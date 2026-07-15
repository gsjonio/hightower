//! The classifier: runs every risk rule over a process and turns the findings,
//! plus the known-process lookup, into a single [`ProcessVerdict`].

use crate::ports::{KnownProcess, ProcessKnowledgeRepository, RiskRule};
use crate::process::{ProcessCategory, ProcessInfo, ProcessVerdict, RiskFinding, SignatureStatus};

/// Holds the rule set and the knowledge repository, and produces a verdict for
/// each process.
///
/// This is the dependency-injection seam: it depends only on the `RiskRule` and
/// `ProcessKnowledgeRepository` traits (via `Box<dyn ...>`), never on concrete
/// types, so tests build it from fakes and the real binary builds it from the
/// Windows adapters -- same code path.
pub struct Classifier {
    rules: Vec<Box<dyn RiskRule>>,
    knowledge: Box<dyn ProcessKnowledgeRepository>,
}

impl Classifier {
    /// Builds a classifier from a set of rules and a knowledge repository.
    pub fn new(
        rules: Vec<Box<dyn RiskRule>>,
        knowledge: Box<dyn ProcessKnowledgeRepository>,
    ) -> Self {
        Self { rules, knowledge }
    }

    /// Classifies one process: runs each rule, then packages the findings with
    /// the process's category and publisher into a [`ProcessVerdict`]. The
    /// overall risk level is derived by `ProcessVerdict::new` (the worst finding
    /// wins).
    ///
    /// Python equivalent of the rule loop:
    ///   `findings = [f for rule in self.rules if (f := rule.evaluate(...))]`
    pub fn classify(&self, process: &ProcessInfo) -> ProcessVerdict {
        let mut findings: Vec<RiskFinding> = Vec::new();
        for rule in &self.rules {
            if let Some(finding) = rule.evaluate(process, self.knowledge.as_ref()) {
                findings.push(finding);
            }
        }

        let known = self.knowledge.lookup(&process.name);
        let category = known
            .as_ref()
            .map(|entry| entry.category)
            .unwrap_or(ProcessCategory::Unknown);
        let publisher = resolve_publisher(known.as_ref(), &process.signature);

        ProcessVerdict::new(process.clone(), category, publisher, findings)
    }
}

/// Picks the best publisher we can name: a validly signed publisher if the
/// signature provides one, otherwise the expected publisher from the database.
fn resolve_publisher(known: Option<&KnownProcess>, signature: &SignatureStatus) -> Option<String> {
    if let SignatureStatus::Signed {
        publisher: Some(publisher),
    } = signature
    {
        return Some(publisher.clone());
    }
    known.map(|entry| entry.publisher.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::RiskLevel;
    use crate::rules::{
        default_rules,
        test_support::{known, FakeKnowledge},
    };

    fn process(name: &str, path: &str) -> ProcessInfo {
        ProcessInfo {
            pid: 100,
            name: name.to_string(),
            executable_path: Some(std::path::PathBuf::from(path)),
            restricted: false,
            signature: SignatureStatus::Unchecked,
        }
    }

    fn classifier() -> Classifier {
        let knowledge = FakeKnowledge {
            entries: vec![known("svchost.exe", &[r"C:\Windows\System32"])],
        };
        Classifier::new(default_rules(), Box::new(knowledge))
    }

    #[test]
    fn known_process_in_place_is_trusted() {
        let verdict =
            classifier().classify(&process("svchost.exe", r"C:\Windows\System32\svchost.exe"));
        assert_eq!(verdict.risk, RiskLevel::Trusted);
        assert_eq!(verdict.category, ProcessCategory::CoreWindows);
        assert_eq!(verdict.publisher.as_deref(), Some("Microsoft Windows"));
        assert!(verdict.findings.is_empty());
    }

    #[test]
    fn masquerading_process_is_suspicious() {
        // A known name in the wrong place: masquerading (suspicious) wins over
        // any lower-severity finding.
        let verdict = classifier().classify(&process(
            "svchost.exe",
            r"C:\Users\me\Downloads\svchost.exe",
        ));
        assert_eq!(verdict.risk, RiskLevel::Suspicious);
    }

    #[test]
    fn unknown_process_is_review_and_categorised_unknown() {
        let verdict = classifier().classify(&process("mystery.exe", r"C:\apps\mystery.exe"));
        assert_eq!(verdict.risk, RiskLevel::Review);
        assert_eq!(verdict.category, ProcessCategory::Unknown);
    }
}
