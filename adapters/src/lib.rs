//! # hightower-adapters -- the driven ring
//!
//! Concrete implementations of the ports defined in `hightower-core`. This is
//! the only place in the workspace allowed to touch the operating system:
//! enumerating processes through the Windows ToolHelp32 API, verifying
//! Authenticode signatures, and loading the embedded known-process database.
//!
//! For a Python dev: if `core` is the `abc.ABC` contract, this crate is the
//! concrete subclass that actually calls out to the OS. Keeping it separate is
//! what lets the domain be tested with fakes instead of real syscalls.

// Every `unsafe` block in this crate must be preceded by a `// SAFETY:` comment
// explaining the invariant we uphold by hand -- this lint makes that a build
// error, not just a convention. The Windows syscalls that need it arrive in
// v0.2.0; the guard is in place from day one.
#![deny(clippy::undocumented_unsafe_blocks)]

// The known-process database is pure JSON parsing, no OS calls, so it builds
// everywhere -- no cfg gate.
pub mod knowledge;

// The process lister talks to the Windows API, so it only exists on Windows.
// Gating the module (not just the dependency) keeps a non-Windows build of this
// crate from trying to compile code against a `windows` crate that is not there.
#[cfg(windows)]
pub mod procinfo;
