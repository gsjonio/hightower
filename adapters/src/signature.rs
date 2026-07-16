//! Windows implementation of [`SignatureVerifier`] backed by Authenticode
//! (`WinVerifyTrust`).
//!
//! This asks Windows the same question Explorer's "Digital Signatures" tab does:
//! is this file signed, and does its signature chain to a trusted root? We map
//! the answer onto [`SignatureStatus`]. Every `unsafe` block carries a
//! `// SAFETY:` comment, enforced by the crate-level
//! `#![deny(clippy::undocumented_unsafe_blocks)]`.
//!
//! When the signature is trusted we also read the signer's display name out of
//! the certificate and return it as the publisher (best-effort -- any failure
//! falls back to `publisher: None`, never to a worse trust verdict).
//!
//! **Security:** that publisher name is the certificate *subject*, which is
//! attacker-controlled text. We only read it *after* `WinVerifyTrust` has
//! confirmed the chain to a trusted root, so it names a real, validated signer --
//! but it is still a display label, never a trust input. No rule in `core`
//! should branch on it.
//!
//! Known limitation: only *embedded* Authenticode signatures are checked. Many
//! Windows system binaries are instead signed via a security *catalog* (`.cat`),
//! which this file-based check reports as `Unsigned`. That is mitigated at the
//! rule layer: the unsigned-binary rule skips processes already vouched for by
//! the known-process database, so catalog-signed system files are not
//! mislabelled. Catalog verification is a possible future enhancement (see the
//! project's follow-up issues).

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
    CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT, CERT_FIND_SUBJECT_CERT,
    CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE,
    CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

use hightower_core::ports::SignatureVerifier;
use hightower_core::process::SignatureStatus;

// Authenticode / trust result codes returned by WinVerifyTrust, as i32 (they are
// HRESULTs). Defined locally to avoid pulling in extra crate features just for a
// handful of constants.
const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;
const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = 0x800B0004u32 as i32;
const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B0111u32 as i32;
const CERT_E_UNTRUSTEDROOT: i32 = 0x800B0109u32 as i32;
const CERT_E_CHAINING: i32 = 0x800B010Au32 as i32;
const CRYPT_E_SECURITY_SETTINGS: i32 = 0x80092026u32 as i32;

/// Verifies Authenticode signatures via `WinVerifyTrust`.
///
/// Zero-sized: it holds no state, it is just the concrete Windows implementation
/// of the [`SignatureVerifier`] port.
pub struct AuthenticodeVerifier;

impl SignatureVerifier for AuthenticodeVerifier {
    fn verify(&self, executable_path: &Path) -> SignatureStatus {
        // WinVerifyTrust wants a wide, NUL-terminated path.
        let wide_path: Vec<u16> = executable_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide_path.as_ptr()),
            ..Default::default()
        };

        let mut trust_data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            ..Default::default()
        };

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // SAFETY: `action` is a valid GUID; the third argument points to a fully
        // initialized WINTRUST_DATA whose pFile borrows `file_info`, which borrows
        // `wide_path` -- all outlive the call. A null HWND plus WTD_UI_NONE means
        // "no UI".
        let status = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut trust_data as *mut WINTRUST_DATA as *mut c_void,
            )
        };

        // We must call again with STATEACTION_CLOSE so WinVerifyTrust frees the
        // state it allocated during verification. The fresh &mut borrow below is
        // also what makes the field write here a real (not dead) store.
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: same WINTRUST_DATA, now releasing the state allocated above.
        unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut trust_data as *mut WINTRUST_DATA as *mut c_void,
            );
        }

        match classify_trust_status(status) {
            // Trusted: the file has a validated embedded signature, so it is worth
            // opening the certificate to name the signer. Best-effort.
            SignatureStatus::Signed { .. } => SignatureStatus::Signed {
                publisher: extract_publisher(executable_path),
            },
            other => other,
        }
    }
}

/// Maps a `WinVerifyTrust` result code onto a [`SignatureStatus`].
fn classify_trust_status(status: i32) -> SignatureStatus {
    match status {
        // ERROR_SUCCESS: signed and chains to a trusted root.
        0 => SignatureStatus::Signed { publisher: None },
        // No signature present at all.
        TRUST_E_NOSIGNATURE => SignatureStatus::Unsigned,
        // A signature exists but is not trusted.
        TRUST_E_SUBJECT_NOT_TRUSTED
        | TRUST_E_EXPLICIT_DISTRUST
        | CERT_E_UNTRUSTEDROOT
        | CERT_E_CHAINING
        | CRYPT_E_SECURITY_SETTINGS => SignatureStatus::Untrusted,
        // Anything else (unsupported file type, provider errors, access issues):
        // we genuinely could not determine it.
        _ => SignatureStatus::Unknown,
    }
}

/// Best-effort extraction of the signer's display name from an embedded
/// Authenticode signature. Returns `None` on any failure -- it must never turn a
/// trusted verdict into a worse one.
///
/// Only ever called after `WinVerifyTrust` reports trust, so the file has a valid
/// embedded PKCS#7 signature and the certificate names a validated signer (see
/// the module-level security note about treating that name as a display label).
fn extract_publisher(executable_path: &Path) -> Option<String> {
    let wide_path: Vec<u16> = executable_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Load the embedded PKCS#7 signature: a certificate store plus the signed
    // message that references the signing certificate. (The message handle has no
    // named type in the windows crate -- it is a raw `*mut c_void`.)
    let mut store = HCERTSTORE::default();
    let mut message: *mut c_void = std::ptr::null_mut();
    // SAFETY: pvObject points to the NUL-terminated wide path; the two out-params
    // are handles we own and release via the RAII guards below. Everything else is
    // a plain flag. A failure returns Err, which becomes None.
    unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut message),
            None,
        )
    }
    .ok()?;
    let store = CertStore(store);
    let message = CryptMsg(message);

    // Read the signer info: its issuer + serial number identify the signing cert.
    // First call sizes the buffer, second call fills it.
    let mut size = 0u32;
    // SAFETY: `message.0` is a live crypto-message handle; a null data pointer asks
    // only for the required size, written into `size`.
    unsafe {
        CryptMsgGetParam(
            message.0 as *const c_void,
            CMSG_SIGNER_INFO_PARAM,
            0,
            None,
            &mut size,
        )
    }
    .ok()?;
    let mut buffer = vec![0u8; size as usize];
    // SAFETY: `buffer` is exactly `size` bytes, the length the sizing call reported.
    unsafe {
        CryptMsgGetParam(
            message.0 as *const c_void,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut size,
        )
    }
    .ok()?;
    // SAFETY: on success CryptMsgGetParam wrote a CMSG_SIGNER_INFO into `buffer`,
    // which outlives `signer` and the CertFind call that reads its issuer/serial
    // blobs (those blobs point back into `buffer`).
    let signer = unsafe { &*(buffer.as_ptr() as *const CMSG_SIGNER_INFO) };

    // Find the signer's certificate in the store by issuer + serial number.
    let cert_info = CERT_INFO {
        Issuer: signer.Issuer,
        SerialNumber: signer.SerialNumber,
        ..Default::default()
    };
    let encoding = CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0);
    // SAFETY: `store` is live; pvFindPara points to a CERT_INFO whose issuer/serial
    // blobs borrow `buffer`, still alive here. Returns null (not Err) on no match.
    let cert = unsafe {
        CertFindCertificateInStore(
            store.0,
            encoding,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&cert_info as *const CERT_INFO as *const c_void),
            None,
        )
    };
    if cert.is_null() {
        return None;
    }
    let cert = CertContext(cert);

    // Ask for the certificate's simple display name: once with no buffer for the
    // length (in u16s, including the NUL terminator), then once to fill it.
    // SAFETY: `cert.0` is a live CERT_CONTEXT; a `None` buffer asks only for the
    // required length.
    let length =
        unsafe { CertGetNameStringW(cert.0, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
    if length <= 1 {
        return None; // 1 == just the terminator (an empty name)
    }
    let mut name = vec![0u16; length as usize];
    // SAFETY: `cert.0` is live; the API writes at most `name.len()` u16s into the
    // slice and returns how many (including the terminator) it wrote.
    let written = unsafe {
        CertGetNameStringW(
            cert.0,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name),
        )
    };
    if written <= 1 {
        return None;
    }
    // Drop the trailing NUL before converting.
    let text = String::from_utf16_lossy(&name[..written as usize - 1]);
    (!text.is_empty()).then_some(text)
}

/// RAII guard that closes a certificate store from `CryptQueryObject` on drop.
struct CertStore(HCERTSTORE);

impl Drop for CertStore {
    fn drop(&mut self) {
        // SAFETY: self.0 was returned by CryptQueryObject and is closed exactly
        // once, here.
        unsafe {
            let _ = CertCloseStore(self.0, 0);
        }
    }
}

/// RAII guard that closes a crypto message from `CryptQueryObject` on drop. The
/// message handle has no named type in the windows crate; it is a `*mut c_void`.
struct CryptMsg(*mut c_void);

impl Drop for CryptMsg {
    fn drop(&mut self) {
        // SAFETY: self.0 was returned by CryptQueryObject and is closed exactly
        // once, here.
        unsafe {
            let _ = CryptMsgClose(Some(self.0 as *const c_void));
        }
    }
}

/// RAII guard that frees a certificate context from `CertFindCertificateInStore`.
struct CertContext(*const CERT_CONTEXT);

impl Drop for CertContext {
    fn drop(&mut self) {
        // SAFETY: self.0 was returned by CertFindCertificateInStore and is freed
        // exactly once, here.
        unsafe {
            let _ = CertFreeCertificateContext(Some(self.0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_codes_map_to_expected_status() {
        assert_eq!(
            classify_trust_status(0),
            SignatureStatus::Signed { publisher: None }
        );
        assert_eq!(
            classify_trust_status(TRUST_E_NOSIGNATURE),
            SignatureStatus::Unsigned
        );
        assert_eq!(
            classify_trust_status(CERT_E_UNTRUSTEDROOT),
            SignatureStatus::Untrusted
        );
        assert_eq!(classify_trust_status(0x7FFF_FFFF), SignatureStatus::Unknown);
    }

    /// Real end-to-end check of the FFI path: the test binary itself is not
    /// Authenticode-signed, so it must come back `Unsigned`.
    #[test]
    fn unsigned_binary_is_detected() {
        let own_exe = std::env::current_exe().expect("current exe path");
        assert_eq!(
            AuthenticodeVerifier.verify(&own_exe),
            SignatureStatus::Unsigned
        );
    }

    /// Verifying a real system file must return *some* status without panicking
    /// (many are catalog-signed and read as Unsigned, which is fine here).
    #[test]
    fn verifying_a_system_file_does_not_panic() {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let kernel32 = std::path::PathBuf::from(system_root)
            .join("System32")
            .join("kernel32.dll");
        if kernel32.exists() {
            let _ = AuthenticodeVerifier.verify(&kernel32);
        }
    }

    /// The fall-back path: a file with no embedded signature yields no publisher,
    /// never a panic.
    #[test]
    fn extract_publisher_is_none_for_unsigned() {
        let own_exe = std::env::current_exe().expect("current exe path");
        assert_eq!(extract_publisher(&own_exe), None);
    }

    /// Real end-to-end check on an embedded-signed system binary: if it verifies
    /// as Signed, we should have read a non-empty publisher name out of the cert.
    /// Lenient about the input -- on SKUs where explorer.exe is catalog-signed it
    /// comes back Unsigned, which is a different code path, so we simply skip.
    #[test]
    fn signed_binary_names_its_publisher() {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let explorer = std::path::PathBuf::from(system_root).join("explorer.exe");
        if !explorer.exists() {
            return;
        }
        if let SignatureStatus::Signed { publisher } = AuthenticodeVerifier.verify(&explorer) {
            assert!(
                publisher.as_deref().is_some_and(|name| !name.is_empty()),
                "a signed binary should name its publisher, got {publisher:?}"
            );
        }
    }
}
