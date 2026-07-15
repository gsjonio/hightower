//! Unknown-process heuristic.

use crate::ports::{ProcessKnowledgeRepository, RiskRule};
use crate::process::{ProcessInfo, RiskFinding, RiskLevel, SignatureStatus};

/// Flags a process that is neither in the known-process database nor backed by a
/// recognized (validly signed) publisher -- reported as "review manually", never
/// as a categorical "this is malware".
///
/// ## When it can be wrong
///
/// - Most third-party software is legitimately "unknown" to hightower's small
///   curated database, so this fires often and is only `review`. Once a
///   signature verifier populates a trusted publisher, those processes stop
///   being flagged.
pub struct UnknownProcessRule;

impl RiskRule for UnknownProcessRule {
    fn evaluate(
        &self,
        process: &ProcessInfo,
        knowledge: &dyn ProcessKnowledgeRepository,
    ) -> Option<RiskFinding> {
        // In the database -> known, nothing to say.
        if knowledge.lookup(&process.name).is_some() {
            return None;
        }

        // Not in the database, but a trusted digital signature is itself a form
        // of recognition (it chains to a trusted root), so do not flag it -- even
        // when we did not extract the publisher's name.
        if let SignatureStatus::Signed { .. } = &process.signature {
            return None;
        }

        let summary = format!(
            "'{}' is not in hightower's list of known programs and has no recognized publisher. \
             This is common for third-party apps -- review it manually if you do not recognize it.",
            process.name
        );
        Some(RiskFinding::new(RiskLevel::Review, summary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::{known, FakeKnowledge};

    fn process(name: &str, signature: SignatureStatus) -> ProcessInfo {
        ProcessInfo {
            pid: 100,
            name: name.to_string(),
            executable_path: Some(std::path::PathBuf::from(format!(r"C:\apps\{name}"))),
            restricted: false,
            signature,
        }
    }

    fn knowledge() -> FakeKnowledge {
        FakeKnowledge {
            entries: vec![known("svchost.exe", &[r"C:\Windows\System32"])],
        }
    }

    #[test]
    fn known_process_is_not_flagged() {
        let finding = UnknownProcessRule.evaluate(
            &process("svchost.exe", SignatureStatus::Unchecked),
            &knowledge(),
        );
        assert!(finding.is_none());
    }

    #[test]
    fn unknown_and_unchecked_is_review() {
        let finding = UnknownProcessRule
            .evaluate(
                &process("mystery.exe", SignatureStatus::Unchecked),
                &knowledge(),
            )
            .expect("unknown process should be flagged");
        assert_eq!(finding.severity, RiskLevel::Review);
    }

    #[test]
    fn unknown_but_validly_signed_is_not_flagged() {
        let signed = SignatureStatus::Signed {
            publisher: Some("Google LLC".to_string()),
        };
        let finding = UnknownProcessRule.evaluate(&process("chrome.exe", signed), &knowledge());
        assert!(finding.is_none());
    }
}
