//! Turns classified processes into plain, aligned text for the terminal.
//!
//! Hand-rolled on purpose: computing a few column widths with `format!` is a few
//! lines, so a table crate would be more dependency than the job needs (YAGNI).
//! The renderer returns a `String` instead of printing, keeping it a pure
//! function that is easy to unit-test without capturing stdout.

use hightower_core::process::{ProcessCategory, ProcessVerdict, RiskLevel};

/// Renders the verdicts as an aligned table (RISK / PID / NAME / CATEGORY /
/// PATH) and returns it as a single string ending in a newline.
///
/// Callers are expected to sort worst-first before calling, so the flagged
/// processes appear at the top.
pub fn render_verdict_table(verdicts: &[ProcessVerdict]) -> String {
    const RISK: &str = "RISK";
    const PID: &str = "PID";
    const NAME: &str = "NAME";
    const CATEGORY: &str = "CATEGORY";
    const PATH: &str = "PATH";

    // Build every cell's display string once, so width calculation and rendering
    // see identical values.
    let mut rows: Vec<[String; 5]> = Vec::new();
    for verdict in verdicts {
        let path = match &verdict.process.executable_path {
            Some(path) => path.display().to_string(),
            None => "(restricted)".to_string(),
        };
        rows.push([
            risk_label(verdict.risk).to_string(),
            verdict.process.pid.to_string(),
            verdict.process.name.clone(),
            category_label(verdict.category).to_string(),
            path,
        ]);
    }

    // Each column is as wide as the widest of its header and its cells. PATH is
    // last, so it never needs padding.
    let mut risk_width = RISK.len();
    let mut pid_width = PID.len();
    let mut name_width = NAME.len();
    let mut category_width = CATEGORY.len();
    for [risk, pid, name, category, _path] in &rows {
        risk_width = risk_width.max(risk.len());
        pid_width = pid_width.max(pid.len());
        name_width = name_width.max(name.len());
        category_width = category_width.max(category.len());
    }

    let mut output = String::new();
    // PID is a number, so it reads better right-aligned; text is left-aligned.
    output.push_str(&format!(
        "{RISK:<risk_width$}  {PID:>pid_width$}  {NAME:<name_width$}  \
         {CATEGORY:<category_width$}  {PATH}\n"
    ));
    for [risk, pid, name, category, path] in &rows {
        output.push_str(&format!(
            "{risk:<risk_width$}  {pid:>pid_width$}  {name:<name_width$}  \
             {category:<category_width$}  {path}\n"
        ));
    }
    output
}

/// The plain-text label for a risk level, as shown in the table.
fn risk_label(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Trusted => "trusted",
        RiskLevel::Review => "review",
        RiskLevel::Suspicious => "suspicious",
    }
}

/// The plain-text label for a process category, as shown in the table.
fn category_label(category: ProcessCategory) -> &'static str {
    match category {
        ProcessCategory::CoreWindows => "core-windows",
        ProcessCategory::Driver => "driver",
        ProcessCategory::ThirdPartyKnown => "third-party-known",
        ProcessCategory::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hightower_core::process::{ProcessInfo, SignatureStatus};
    use std::path::PathBuf;

    fn verdict(
        pid: u32,
        name: &str,
        path: Option<&str>,
        category: ProcessCategory,
        risk: RiskLevel,
    ) -> ProcessVerdict {
        ProcessVerdict {
            process: ProcessInfo {
                pid,
                name: name.to_string(),
                executable_path: path.map(PathBuf::from),
                restricted: path.is_none(),
                signature: SignatureStatus::Unchecked,
            },
            category,
            publisher: None,
            risk,
            findings: Vec::new(),
        }
    }

    #[test]
    fn renders_header_labels_and_restricted() {
        let verdicts = [
            verdict(
                4,
                "System",
                None,
                ProcessCategory::Unknown,
                RiskLevel::Review,
            ),
            verdict(
                1234,
                "explorer.exe",
                Some(r"C:\Windows\explorer.exe"),
                ProcessCategory::CoreWindows,
                RiskLevel::Trusted,
            ),
        ];
        let table = render_verdict_table(&verdicts);

        for header in ["RISK", "PID", "NAME", "CATEGORY", "PATH"] {
            assert!(table.contains(header), "missing header {header}");
        }
        assert!(table.contains("trusted"));
        assert!(table.contains("review"));
        assert!(table.contains("core-windows"));
        assert!(table.contains("(restricted)"));
        assert!(table.contains(r"C:\Windows\explorer.exe"));
    }

    #[test]
    fn columns_are_aligned() {
        let verdicts = [
            verdict(
                1,
                "a",
                Some("p1"),
                ProcessCategory::Unknown,
                RiskLevel::Trusted,
            ),
            verdict(
                2,
                "much-longer-name.exe",
                Some("p2"),
                ProcessCategory::Unknown,
                RiskLevel::Trusted,
            ),
        ];
        let table = render_verdict_table(&verdicts);
        let lines: Vec<&str> = table.lines().collect();

        let short_row = lines.iter().find(|line| line.contains("p1")).unwrap();
        let long_row = lines.iter().find(|line| line.contains("p2")).unwrap();
        // Different NAME widths must still line PATH up at the same offset.
        assert_eq!(short_row.find("p1"), long_row.find("p2"));
    }
}
