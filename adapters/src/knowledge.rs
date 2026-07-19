//! The embedded known-Windows-process database and its repository.
//!
//! This is a *driven adapter* -- it implements the
//! [`ProcessKnowledgeRepository`] port -- but unlike the process lister it does
//! not touch the operating system: it just parses a JSON file that is baked into
//! the binary. Keeping it in `adapters` (not `core`) follows the hexagonal rule
//! that "where the data comes from" is an outer-ring concern; `core` only knows
//! the trait.
//!
//! (Python bridge: `include_str!` is a compile-time `open(...).read()` -- the
//! file's contents become a `&'static str` constant embedded in the executable,
//! so there is no file to ship alongside it or lose at runtime.)

use hightower_core::error::HightowerError;
use hightower_core::ports::{KnownProcess, ProcessKnowledgeRepository};

/// The curated database, embedded at compile time. See `known_processes.json`
/// and the wiki's "Known-Process Database Format" page for the schema.
const EMBEDDED_DATABASE: &str = include_str!("known_processes.json");

/// A [`ProcessKnowledgeRepository`] backed by the embedded JSON database.
pub struct EmbeddedKnowledgeRepository {
    entries: Vec<KnownProcess>,
}

impl EmbeddedKnowledgeRepository {
    /// Parses the embedded database.
    ///
    /// Returns [`HightowerError::KnowledgeDatabase`] if the JSON is malformed.
    /// Because the data is embedded at build time, that error signals a bug in
    /// the database file itself, not bad user input -- so it surfaces once, at
    /// start-up, with a clear message instead of panicking deep in a lookup.
    pub fn new() -> Result<Self, HightowerError> {
        let entries: Vec<KnownProcess> = serde_json::from_str(EMBEDDED_DATABASE)
            .map_err(|error| HightowerError::KnowledgeDatabase(error.to_string()))?;
        Ok(Self { entries })
    }
}

impl ProcessKnowledgeRepository for EmbeddedKnowledgeRepository {
    fn lookup(&self, process_name: &str) -> Option<KnownProcess> {
        // Windows process names are not case-sensitive, so neither is the
        // lookup. The list is short (a curated set), so a linear scan is plenty.
        self.entries
            .iter()
            .find(|entry| entry.process_name.eq_ignore_ascii_case(process_name))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hightower_core::process::ProcessCategory;

    fn repository() -> EmbeddedKnowledgeRepository {
        // A parse failure here means the embedded JSON is malformed -- exactly
        // what this test is meant to catch.
        EmbeddedKnowledgeRepository::new().expect("embedded database should parse")
    }

    #[test]
    fn embedded_database_parses_and_is_not_empty() {
        assert!(!repository().entries.is_empty());
    }

    #[test]
    fn looks_up_a_known_process() {
        let entry = repository()
            .lookup("svchost.exe")
            .expect("svchost is known");
        assert_eq!(entry.category, ProcessCategory::CoreWindows);
        assert_eq!(entry.publisher, "Microsoft Windows");
        assert!(!entry.description_en.is_empty());
        assert!(!entry.description_pt.is_empty());
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let repository = repository();
        assert!(repository.lookup("SVCHOST.EXE").is_some());
        assert!(repository.lookup("SvcHost.Exe").is_some());
    }

    #[test]
    fn unknown_process_is_none() {
        assert!(repository().lookup("definitely-not-real.exe").is_none());
    }

    #[test]
    fn database_covers_common_core_processes() {
        let repository = repository();
        assert!(
            repository.entries.len() >= 20,
            "the curated database should have grown"
        );
        for name in ["dwm.exe", "conhost.exe", "WmiPrvSE.exe", "taskmgr.exe"] {
            assert!(repository.lookup(name).is_some(), "{name} should be known");
        }
    }

    /// Security invariant: every entry is a trust assertion, so it must carry an
    /// expected directory + publisher (never a bare name) and both descriptions.
    /// This guards future contributions as much as the current data.
    #[test]
    fn every_entry_is_well_formed() {
        for entry in &repository().entries {
            let name = &entry.process_name;
            assert!(!name.trim().is_empty(), "an entry has an empty name");
            assert!(
                !entry.publisher.trim().is_empty(),
                "{name} has no publisher"
            );
            assert!(
                !entry.expected_directories.is_empty(),
                "{name} has no expected directory"
            );
            assert!(
                !entry.description_en.is_empty() && !entry.description_pt.is_empty(),
                "{name} is missing a description"
            );
        }
    }
}
