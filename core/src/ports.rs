//! Ports: the boundary between the pure domain and the outside world.
//!
//! If you come from Python, read each trait here as an abstract base class
//! (`abc.ABC` with `@abstractmethod`): it describes *what* a capability does,
//! never *how*. The difference from Python's duck typing is that the compiler
//! checks, at compile time, that anything claiming to implement a port really
//! provides every method with the exact signature -- there is no "works most of
//! the time" here.
//!
//! The real implementations (adapters) live in the `hightower-adapters` crate.
//! The domain depends only on these traits, never on the concrete types, which
//! is what lets the classifier be tested with fake, in-memory adapters instead
//! of a live Windows machine.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::HightowerError;
use crate::process::{ProcessCategory, ProcessInfo, RiskFinding, SignatureStatus};

/// Enumerates the processes currently running on the machine.
///
/// There is only one real implementation (Windows, in `hightower-adapters`), but
/// the domain depends on this trait rather than that type. That indirection is
/// what makes it possible to test the classifier with a hand-written fake list
/// of processes.
pub trait ProcessLister {
    /// Returns every process visible to this user account. A process the OS
    /// refuses to describe (a protected process, no elevated terminal) must
    /// still appear in the list with [`ProcessInfo::restricted`] set to `true`,
    /// rather than being silently dropped or turned into an `Err`. `Err` is
    /// reserved for a failure of the whole enumeration.
    fn list(&self) -> Result<Vec<ProcessInfo>, HightowerError>;
}

/// Checks the digital signature of an executable on disk.
///
/// Signature checks are comparatively expensive, so in the CLI they run in
/// parallel across processes; the result is then stored on
/// [`ProcessInfo::signature`].
pub trait SignatureVerifier {
    /// Returns what could be determined about the executable's signature. A file
    /// that cannot be read yields [`SignatureStatus::Unknown`] -- never an
    /// `Err` -- so one unreadable binary never aborts a whole scan.
    fn verify(&self, executable_path: &Path) -> SignatureStatus;
}

/// One entry in the curated database of well-known Windows processes.
///
/// This is the shape of each object in the embedded JSON database (see the
/// `adapters` crate). Field names are mapped to the JSON's camelCase keys via
/// serde, with the two description fields renamed explicitly because their JSON
/// keys end in uppercase (`descriptionEN` / `descriptionPT`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownProcess {
    /// The executable's base name, e.g. `"svchost.exe"`.
    pub process_name: String,
    /// Directories the process is legitimately expected to run from. Entries may
    /// contain environment placeholders such as `%SystemRoot%\\System32`.
    pub expected_directories: Vec<String>,
    /// The expected publisher, e.g. `"Microsoft Windows"`.
    pub publisher: String,
    /// The category this process belongs to.
    pub category: ProcessCategory,
    /// Plain-language description in English.
    #[serde(rename = "descriptionEN")]
    pub description_en: String,
    /// Plain-language description in Portuguese.
    #[serde(rename = "descriptionPT")]
    pub description_pt: String,
}

/// Looks up what is known about a process by name.
///
/// (Repository pattern: it hides where the known-process data comes from --
/// today an embedded JSON file, tomorrow perhaps something else -- behind a
/// single lookup method.)
pub trait ProcessKnowledgeRepository {
    /// Returns the database entry for `process_name`, or `None` when the process
    /// is not in the curated list. The lookup should be case-insensitive on the
    /// name, since Windows process names are not case-sensitive.
    fn lookup(&self, process_name: &str) -> Option<KnownProcess>;
}

/// A single risk heuristic: looks at one process and optionally raises a finding.
///
/// Each concrete rule (path masquerading, unsigned binary, unknown process) is a
/// small struct implementing this trait -- the Strategy pattern. The classifier
/// holds a `Vec<Box<dyn RiskRule>>` and runs each one, so adding a heuristic is
/// adding a struct, not editing a giant `match`.
pub trait RiskRule {
    /// Evaluates one process, returning `Some(finding)` when the rule has a
    /// concern and `None` when it has nothing to say. The `knowledge` repository
    /// is passed in so rules can compare against expected paths, publishers, and
    /// so on.
    fn evaluate(
        &self,
        process: &ProcessInfo,
        knowledge: &dyn ProcessKnowledgeRepository,
    ) -> Option<RiskFinding>;
}
