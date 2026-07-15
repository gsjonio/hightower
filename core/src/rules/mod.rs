//! The risk heuristics: one small [`RiskRule`](crate::ports::RiskRule) per
//! concern, combined by the [`Classifier`](crate::classify::Classifier).
//!
//! This is the Strategy pattern. Each rule is an independent struct that looks
//! at a process and optionally raises a finding; adding a heuristic means adding
//! a struct here, not editing a giant `match`. All of them are pure -- they read
//! a [`ProcessInfo`](crate::process::ProcessInfo) and the knowledge repository,
//! and never touch the OS -- so they are tested with a fake repository below.
//!
//! **A word on false positives.** These heuristics are intentionally simple and
//! err toward *flagging for review* rather than staying silent. A finding is a
//! prompt for a human to look, never a verdict of "malware". Each rule's doc
//! comment notes where it can be wrong.

mod masquerading;
mod unknown;
mod unsigned;

pub use masquerading::PathMasqueradingRule;
pub use unknown::UnknownProcessRule;
pub use unsigned::UnsignedBinaryRule;

use crate::ports::RiskRule;

/// The standard set of rules, in the order the classifier runs them.
///
/// A convenience for the composition root so it does not have to name every
/// rule; callers that want a custom set can still build the `Vec` by hand.
pub fn default_rules() -> Vec<Box<dyn RiskRule>> {
    vec![
        Box::new(PathMasqueradingRule),
        Box::new(UnsignedBinaryRule),
        Box::new(UnknownProcessRule),
    ]
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Hand-written fakes for testing rules and the classifier without any OS
    //! access -- the Rust equivalent of a small stub object in Python, no
    //! mocking library involved.

    use crate::ports::{KnownProcess, ProcessKnowledgeRepository};
    use crate::process::ProcessCategory;

    /// An in-memory [`ProcessKnowledgeRepository`] seeded with fixed entries.
    pub struct FakeKnowledge {
        pub entries: Vec<KnownProcess>,
    }

    impl FakeKnowledge {
        /// A repository that knows nothing -- every lookup returns `None`.
        pub fn empty() -> Self {
            Self {
                entries: Vec::new(),
            }
        }
    }

    impl ProcessKnowledgeRepository for FakeKnowledge {
        fn lookup(&self, process_name: &str) -> Option<KnownProcess> {
            self.entries
                .iter()
                .find(|entry| entry.process_name.eq_ignore_ascii_case(process_name))
                .cloned()
        }
    }

    /// Builds a `KnownProcess` for tests. Directories are given as plain literal
    /// paths (no `%SystemRoot%` placeholders) so path comparisons do not depend
    /// on environment variables, keeping these tests cross-platform.
    pub fn known(process_name: &str, expected_directories: &[&str]) -> KnownProcess {
        KnownProcess {
            process_name: process_name.to_string(),
            expected_directories: expected_directories.iter().map(|d| d.to_string()).collect(),
            publisher: "Microsoft Windows".to_string(),
            category: ProcessCategory::CoreWindows,
            description_en: "test".to_string(),
            description_pt: "teste".to_string(),
        }
    }
}
