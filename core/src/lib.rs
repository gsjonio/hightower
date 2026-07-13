//! # hightower-core -- the domain ring
//!
//! The pure center of the hexagon: the process model, the risk heuristics, and
//! the *ports* (traits) that describe what the outer rings must provide. Nothing
//! here touches the operating system -- no syscalls, no file reads, no `windows`
//! crate.
//!
//! ## Ports & adapters, for a Python dev
//!
//! A *port* is a trait: an abstract contract, like an `abc.ABC` with
//! `@abstractmethod`. It says *what* a capability does, never *how*. An
//! *adapter* is a concrete `impl` of that trait living in the `adapters` crate
//! (e.g. listing processes via Windows ToolHelp32).
//!
//! Why bother? So the risk rules can be tested against fake, in-memory adapters
//! -- no real Windows machine required. In Python that "domain must not import
//! infrastructure" rule lives only in your head or a linter. Here the Cargo
//! workspace enforces it for real: this crate does not depend on the `windows`
//! crate, so `use windows::...` inside `core` simply *fails to compile*. The
//! compiler is the reviewer.

// Force every public item to carry a doc comment. For a Python dev learning
// Rust, those docs double as a running explanation of the type system, so we
// make them non-optional at the crate level.
#![warn(missing_docs)]

pub mod error;

// Re-exported at the crate root because nearly every fallible call in the
// workspace mentions it: `use hightower_core::HightowerError;` reads better than
// the full module path.
pub use error::HightowerError;
