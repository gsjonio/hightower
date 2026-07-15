//! Path-masquerading heuristic.

use crate::ports::{ProcessKnowledgeRepository, RiskRule};
use crate::process::{ProcessInfo, RiskFinding, RiskLevel};

/// Flags a **known** Windows process name running from an **unexpected**
/// directory -- a classic disguise (e.g. a `svchost.exe` in `Downloads` instead
/// of `System32`).
///
/// ## When it can be wrong
///
/// - It only fires for names in the known-process database, so it says nothing
///   about third-party software.
/// - It cannot judge a process whose real path the OS withheld (restricted); it
///   stays silent rather than guess.
pub struct PathMasqueradingRule;

impl RiskRule for PathMasqueradingRule {
    fn evaluate(
        &self,
        process: &ProcessInfo,
        knowledge: &dyn ProcessKnowledgeRepository,
    ) -> Option<RiskFinding> {
        // No path (restricted) -> we cannot judge location. Stay silent.
        let executable_path = process.executable_path.as_ref()?;
        // Only known system names have an "expected" home to compare against.
        let known = knowledge.lookup(&process.name)?;

        let path_text = executable_path.to_string_lossy();
        let actual_directory = normalize_directory(parent_directory(&path_text)?);

        // If the process sits in any of its expected directories, all is well.
        for expected in &known.expected_directories {
            let expected_directory = normalize_directory(&expand_env_placeholders(expected));
            if actual_directory == expected_directory {
                return None;
            }
        }

        // Known name, wrong place.
        let expected_display: Vec<String> = known
            .expected_directories
            .iter()
            .map(|directory| expand_env_placeholders(directory))
            .collect();
        let summary = format!(
            "'{}' normally runs from {}, but this copy is in {}. A trusted system \
             name in an unexpected folder is a common malware disguise.",
            process.name,
            expected_display.join(" or "),
            parent_directory(&path_text).unwrap_or(&path_text)
        );
        Some(RiskFinding::new(RiskLevel::Suspicious, summary))
    }
}

/// Returns the directory part of a path string, splitting on either `\` or `/`.
///
/// Done on the string (not `std::path::Path`) on purpose: these are Windows
/// paths handled as data, and `Path` would not treat `\` as a separator on
/// non-Windows, which would make the risk rules behave differently under test on
/// Linux. String logic behaves identically everywhere.
fn parent_directory(path: &str) -> Option<&str> {
    let last_separator = path.rfind(['\\', '/'])?;
    Some(&path[..last_separator])
}

/// Lower-cases and unifies separators so two Windows directories can be compared
/// (Windows paths are case-insensitive and may mix `\` and `/`).
fn normalize_directory(directory: &str) -> String {
    directory
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

/// Expands `%VAR%` placeholders using environment variables, leaving unknown
/// ones untouched. On real Windows, `%SystemRoot%\System32` becomes
/// `C:\Windows\System32`; in tests (which use literal paths) it is a no-op.
fn expand_env_placeholders(path: &str) -> String {
    let mut result = String::new();
    let mut rest = path;
    while let Some(start) = rest.find('%') {
        result.push_str(&rest[..start]);
        let after_open = &rest[start + 1..];
        match after_open.find('%') {
            Some(end) => {
                let name = &after_open[..end];
                match std::env::var(name) {
                    Ok(value) => result.push_str(&value),
                    // Unknown variable: keep the literal %NAME% so nothing breaks.
                    Err(_) => {
                        result.push('%');
                        result.push_str(name);
                        result.push('%');
                    }
                }
                rest = &after_open[end + 1..];
            }
            // A lone '%' with no closing pair: keep the remainder verbatim.
            None => {
                result.push('%');
                result.push_str(after_open);
                rest = "";
            }
        }
    }
    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::SignatureStatus;
    use crate::rules::test_support::{known, FakeKnowledge};

    fn process_at(name: &str, path: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid: 100,
            name: name.to_string(),
            executable_path: path.map(std::path::PathBuf::from),
            restricted: path.is_none(),
            signature: SignatureStatus::Unchecked,
        }
    }

    fn knowledge() -> FakeKnowledge {
        FakeKnowledge {
            entries: vec![known("svchost.exe", &[r"C:\Windows\System32"])],
        }
    }

    #[test]
    fn known_process_in_expected_directory_is_fine() {
        let finding = PathMasqueradingRule.evaluate(
            &process_at("svchost.exe", Some(r"C:\Windows\System32\svchost.exe")),
            &knowledge(),
        );
        assert!(finding.is_none());
    }

    #[test]
    fn comparison_ignores_case() {
        let finding = PathMasqueradingRule.evaluate(
            &process_at("svchost.exe", Some(r"C:\WINDOWS\system32\svchost.exe")),
            &knowledge(),
        );
        assert!(finding.is_none());
    }

    #[test]
    fn known_process_in_wrong_directory_is_suspicious() {
        let finding = PathMasqueradingRule
            .evaluate(
                &process_at("svchost.exe", Some(r"C:\Users\me\Downloads\svchost.exe")),
                &knowledge(),
            )
            .expect("masquerading should be flagged");
        assert_eq!(finding.severity, RiskLevel::Suspicious);
    }

    #[test]
    fn unknown_process_is_not_this_rules_concern() {
        let finding = PathMasqueradingRule.evaluate(
            &process_at("random.exe", Some(r"C:\Users\me\Downloads\random.exe")),
            &knowledge(),
        );
        assert!(finding.is_none());
    }

    #[test]
    fn restricted_process_is_not_judged() {
        let finding = PathMasqueradingRule.evaluate(&process_at("svchost.exe", None), &knowledge());
        assert!(finding.is_none());
    }

    #[test]
    fn empty_knowledge_flags_nothing() {
        let finding = PathMasqueradingRule.evaluate(
            &process_at("svchost.exe", Some(r"C:\Users\me\Downloads\svchost.exe")),
            &FakeKnowledge::empty(),
        );
        assert!(finding.is_none());
    }
}
