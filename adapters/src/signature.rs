//! Windows implementation of [`SignatureVerifier`] backed by Authenticode
//! (`WinVerifyTrust`).
//!
//! This asks Windows the same question Explorer's "Digital Signatures" tab does:
//! is this file signed, and does its signature chain to a trusted root? We map
//! the answer onto [`SignatureStatus`]. Every `unsafe` block carries a
//! `// SAFETY:` comment, enforced by the crate-level
//! `#![deny(clippy::undocumented_unsafe_blocks)]`.
//!
//! Scope and known limitations:
//!
//! - Trust *status* only. Reading the publisher's name out of the signing
//!   certificate is a larger, more fragile piece of certificate parsing and is
//!   deferred -- [`SignatureStatus::Signed`] carries `publisher: None` here.
//! - Only *embedded* Authenticode signatures are checked. Many Windows system
//!   binaries are instead signed via a security *catalog* (`.cat`), which this
//!   file-based check reports as `Unsigned`. That is mitigated at the rule
//!   layer: the unsigned-binary rule skips processes already vouched for by the
//!   known-process database, so catalog-signed system files are not mislabelled.
//!   Catalog verification is a possible future enhancement.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
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

        classify_trust_status(status)
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
}
