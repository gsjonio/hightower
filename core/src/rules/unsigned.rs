//! Unsigned / untrusted-signature heuristic.

use crate::ports::{ProcessKnowledgeRepository, RiskRule};
use crate::process::{ProcessInfo, RiskFinding, RiskLevel, SignatureStatus};

/// Flags a process whose executable is unsigned, or whose signature is present
/// but not trusted.
///
/// ## When it can be wrong
///
/// - Plenty of legitimate small tools and in-house software are unsigned, so an
///   unsigned finding is only `review`, not `suspicious`.
/// - It relies on [`ProcessInfo::signature`] having been filled in by a
///   signature verifier. Until that step runs the status is `Unchecked`, and
///   this rule stays silent -- it never penalises a process for a check that has
///   not happened yet.
pub struct UnsignedBinaryRule;

impl RiskRule for UnsignedBinaryRule {
    fn evaluate(
        &self,
        process: &ProcessInfo,
        _knowledge: &dyn ProcessKnowledgeRepository,
    ) -> Option<RiskFinding> {
        match &process.signature {
            SignatureStatus::Unsigned => Some(RiskFinding::new(
                RiskLevel::Review,
                "This program has no digital signature, so its publisher cannot be verified.",
            )),
            SignatureStatus::Untrusted => Some(RiskFinding::new(
                RiskLevel::Suspicious,
                "This program's digital signature is present but not trusted -- it may have been \
                 tampered with or self-signed.",
            )),
            // Signed is fine; Unchecked/Unknown mean "we did not (or could not)
            // look", which is not the process's fault -- stay silent.
            SignatureStatus::Signed { .. }
            | SignatureStatus::Unchecked
            | SignatureStatus::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::FakeKnowledge;

    fn process_with(signature: SignatureStatus) -> ProcessInfo {
        ProcessInfo {
            pid: 100,
            name: "example.exe".to_string(),
            executable_path: Some(std::path::PathBuf::from(r"C:\Users\me\example.exe")),
            restricted: false,
            signature,
        }
    }

    #[test]
    fn signature_status_maps_to_expected_finding() {
        // Table-driven: (signature, expected finding severity or None).
        let cases = [
            (SignatureStatus::Unsigned, Some(RiskLevel::Review)),
            (SignatureStatus::Untrusted, Some(RiskLevel::Suspicious)),
            (
                SignatureStatus::Signed {
                    publisher: Some("Acme".to_string()),
                },
                None,
            ),
            (SignatureStatus::Unchecked, None),
            (SignatureStatus::Unknown, None),
        ];

        for (signature, expected) in cases {
            let finding =
                UnsignedBinaryRule.evaluate(&process_with(signature), &FakeKnowledge::empty());
            assert_eq!(finding.map(|f| f.severity), expected);
        }
    }
}
