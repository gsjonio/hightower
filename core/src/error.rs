//! The one error type the domain can return.
//!
//! ## `Result<T, E>` vs Python exceptions
//!
//! Rust has no exceptions. A function that can fail returns
//! `Result<T, HightowerError>` -- literally "either a `T` on success or a
//! `HightowerError` on failure" -- and the caller is forced by the compiler to
//! handle both arms. It is the difference between `def list(self) -> list[...]`
//! that might raise, and a signature that spells the failure out in the return
//! type so it can never be forgotten.
//!
//! `thiserror`'s `#[derive(Error)]` is the ergonomic way to define such an error
//! type: it generates the `Display` / `std::error::Error` boilerplate from the
//! `#[error("...")]` messages, the same role a custom `class MyError(Exception)`
//! plays in Python, minus the hand-written `__str__`.
//!
//! Note what is *not* here: "I could not fully describe this one process" is not
//! an error. Per the design, a protected process the OS refuses to detail is
//! still returned in the list (marked restricted), never turned into an `Err`.
//! This type is reserved for genuinely unrecoverable failures.

use thiserror::Error;

/// A failure the domain considers unrecoverable for the whole operation.
///
/// Kept deliberately small: new variants are added only when a real call site
/// needs to distinguish a new failure mode, never speculatively.
#[derive(Debug, Error)]
pub enum HightowerError {
    /// The process enumeration itself could not be started or completed (for
    /// example the OS snapshot call failed). A single process that cannot be
    /// described does *not* produce this -- only a failure of the whole listing.
    #[error("failed to enumerate running processes: {0}")]
    ProcessEnumeration(String),

    /// The known-process database could not be loaded or parsed. Because the
    /// database is embedded in the binary at build time, this generally signals
    /// a programming error (malformed embedded JSON), not bad user input.
    #[error("could not load the known-process database: {0}")]
    KnowledgeDatabase(String),
}
