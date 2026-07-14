//! Windows implementation of [`ProcessLister`] backed by the ToolHelp32 API.
//!
//! This is the first place in the project that calls the operating system, so it
//! is also the first place with `unsafe`. Every `unsafe` block below is preceded
//! by a `// SAFETY:` comment stating the invariant we uphold by hand -- the
//! `#![deny(clippy::undocumented_unsafe_blocks)]` in this crate's `lib.rs` turns
//! a missing one into a build error.
//!
//! ## `unsafe`, for a Python dev
//!
//! `unsafe` does not mean "this code is wrong". It means "the compiler cannot
//! verify these invariants for me, so I am promising to uphold them myself".
//! Calling a raw C API (which is what the Win32 functions are) is inherently
//! unverifiable to Rust, so it must be wrapped in `unsafe`. Python has no
//! equivalent because it never lets you touch raw pointers or OS handles
//! directly like this -- the nearest cousin is a `ctypes`/FFI call, which is
//! exactly as unchecked, just without a keyword forcing you to mark it.

use std::mem::size_of;
use std::path::PathBuf;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

use hightower_core::error::HightowerError;
use hightower_core::ports::ProcessLister;
use hightower_core::process::{ProcessInfo, SignatureStatus};

/// Lists running processes by walking a ToolHelp32 snapshot of the whole system.
///
/// Zero-sized: it holds no state, it is just the concrete type that carries the
/// Windows implementation of the [`ProcessLister`] port.
pub struct ToolHelpProcessLister;

impl ProcessLister for ToolHelpProcessLister {
    fn list(&self) -> Result<Vec<ProcessInfo>, HightowerError> {
        // Take a snapshot of every process on the system. This is the one call
        // whose failure aborts the whole listing (hence the `?`); a single
        // process we cannot describe later is handled far more gently.
        //
        // SAFETY: CreateToolhelp32Snapshot has no pointer arguments and no
        // preconditions on the caller here; we pass a valid flag and pid 0
        // ("all processes") and check the returned Result.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|source| HightowerError::ProcessEnumeration(source.to_string()))?;

        // Wrap the raw handle so it is closed exactly once when this function
        // returns, on every path (Python bridge: like a `with` block / context
        // manager, but tied to the value's scope instead of an indent level).
        let snapshot = SnapshotHandle(snapshot);

        // The API requires dwSize to be set to the struct size before the first
        // call, so it can tell which version of the struct it is filling in.
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        // Fetch the first process. An Err here means "no processes at all",
        // which we treat as an empty list rather than a failure.
        //
        // SAFETY: snapshot.0 is a live handle from CreateToolhelp32Snapshot; we
        // pass a pointer to a properly sized PROCESSENTRY32W with dwSize set as
        // the API demands.
        if unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_err() {
            return Ok(Vec::new());
        }

        let mut processes = Vec::new();
        loop {
            processes.push(process_info_from_entry(&entry));

            // Advance to the next process. Iteration ends when this returns Err
            // (ERROR_NO_MORE_FILES), which is the normal, expected stop.
            //
            // SAFETY: same invariants as the Process32FirstW call above; `entry`
            // is re-filled in place on each successful step.
            if unsafe { Process32NextW(snapshot.0, &mut entry) }.is_err() {
                break;
            }
        }

        Ok(processes)
    }
}

/// Builds a [`ProcessInfo`] from one snapshot entry, resolving the full
/// executable path when the OS allows it.
fn process_info_from_entry(entry: &PROCESSENTRY32W) -> ProcessInfo {
    let pid = entry.th32ProcessID;
    let name = wide_nul_to_string(&entry.szExeFile);
    let (executable_path, restricted) = full_process_path(pid);

    ProcessInfo {
        pid,
        name,
        executable_path,
        // A process whose full path the OS refused to reveal is still listed --
        // just flagged restricted, never dropped or turned into an error.
        restricted,
        // The (relatively expensive) signature check runs in a later step; a
        // freshly listed process is always Unchecked here.
        signature: SignatureStatus::Unchecked,
    }
}

/// Resolves the full on-disk path of a process by pid.
///
/// Returns `(Some(path), false)` on success and `(None, true)` when the process
/// is protected or otherwise refuses access -- the boolean is the `restricted`
/// flag. It never returns an error: one inaccessible process must not abort the
/// scan.
fn full_process_path(pid: u32) -> (Option<PathBuf>, bool) {
    // PROCESS_QUERY_LIMITED_INFORMATION is the least-privileged right that still
    // allows reading the image path, so we ask for exactly that and no more.
    //
    // SAFETY: OpenProcess takes no caller-supplied pointers; it returns a Result
    // we handle. An Err means access denied / protected process -> restricted.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => handle,
        Err(_) => return (None, true),
    };
    let handle = ProcessHandle(handle);

    // A generous buffer: Windows paths can in theory reach ~32k UTF-16 code
    // units, and QueryFullProcessImageNameW writes the length back into `size`.
    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;

    // SAFETY: handle.0 is a live process handle; buffer is a valid, writable
    // slice of `size` u16s, and `size` is an in/out length the API updates. We
    // read only the `size` code units it reports as written.
    let queried = unsafe {
        QueryFullProcessImageNameW(
            handle.0,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    };

    match queried {
        Ok(()) => {
            let path = String::from_utf16_lossy(&buffer[..size as usize]);
            (Some(PathBuf::from(path)), false)
        }
        // Could not read the path even though we opened the process: describe it
        // as restricted rather than inventing a path or failing the whole scan.
        Err(_) => (None, true),
    }
}

/// Converts a fixed-size, NUL-terminated UTF-16 buffer (as Win32 fills
/// `szExeFile`) into a Rust `String`, stopping at the first NUL.
fn wide_nul_to_string(wide: &[u16]) -> String {
    let end = wide
        .iter()
        .position(|&code_unit| code_unit == 0)
        .unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

/// RAII guard that closes a ToolHelp32 snapshot handle on drop.
struct SnapshotHandle(HANDLE);

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        // SAFETY: self.0 was returned by CreateToolhelp32Snapshot and is closed
        // exactly once, here, and nowhere else -- upholding CloseHandle's
        // requirement of a valid, not-already-closed handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// RAII guard that closes a process handle from OpenProcess on drop.
struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: self.0 was returned by OpenProcess and is closed exactly once,
        // here, upholding the same valid-handle invariant as above.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_nul_to_string_stops_at_first_nul() {
        // "hi" then a NUL then trailing junk, as Win32 leaves the tail of a
        // fixed-size buffer -- we should read only up to the NUL.
        let buffer = [b'h' as u16, b'i' as u16, 0, b'x' as u16];
        assert_eq!(wide_nul_to_string(&buffer), "hi");
    }

    #[test]
    fn wide_nul_to_string_without_nul_reads_everything() {
        let buffer = [b'a' as u16, b'b' as u16];
        assert_eq!(wide_nul_to_string(&buffer), "ab");
    }

    /// Smoke test that exercises the real ToolHelp32 walk end to end: the
    /// snapshot must contain the test process itself.
    #[test]
    fn lists_running_processes_including_this_test() {
        let processes = ToolHelpProcessLister
            .list()
            .expect("listing running processes should succeed");
        assert!(
            !processes.is_empty(),
            "there is always at least one running process"
        );

        let own_pid = std::process::id();
        assert!(
            processes.iter().any(|process| process.pid == own_pid),
            "the snapshot should include the test process itself (pid {own_pid})"
        );
    }
}
