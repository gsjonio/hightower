//! `hightower explain <name|pid>`: a plain-language write-up of a single
//! process (or every instance sharing a name).

use std::fmt::Write as _;
use std::process::ExitCode;

use hightower_adapters::knowledge::EmbeddedKnowledgeRepository;
use hightower_adapters::procinfo::ToolHelpProcessLister;
use hightower_core::ports::{KnownProcess, ProcessKnowledgeRepository, ProcessLister};
use hightower_core::process::{ProcessInfo, ProcessVerdict, SignatureStatus};

use crate::render::{category_label, paint, risk_label, risk_style, RenderStyle};
use crate::{build_classifier, verify_signatures_in_parallel};

/// Entry point for the `explain` subcommand. `target` is either a numeric PID or
/// a process name (matched case-insensitively).
pub fn run_explain(target: &str, style: RenderStyle) -> ExitCode {
    let all_processes = match ToolHelpProcessLister.list() {
        Ok(processes) => processes,
        Err(error) => {
            eprintln!("hightower: {error}");
            return ExitCode::FAILURE;
        }
    };

    // A purely numeric target is a PID; anything else is a name.
    let mut matches: Vec<ProcessInfo> = match target.parse::<u32>() {
        Ok(pid) => all_processes.into_iter().filter(|p| p.pid == pid).collect(),
        Err(_) => all_processes
            .into_iter()
            .filter(|p| p.name.eq_ignore_ascii_case(target))
            .collect(),
    };

    let knowledge = match EmbeddedKnowledgeRepository::new() {
        Ok(knowledge) => knowledge,
        Err(error) => {
            eprintln!("hightower: {error}");
            return ExitCode::FAILURE;
        }
    };

    if matches.is_empty() {
        // Not running -- but if the name is one we know, still say what it is.
        if let Some(known) = knowledge.lookup(target) {
            anstream::println!("No process named '{target}' is running right now.\n");
            anstream::println!("What it is:\n  {}\n", known.description_en);
        } else {
            anstream::println!("No running process matches '{target}'.");
            anstream::println!("Try `hightower scan --all` to see what is running.");
        }
        return ExitCode::SUCCESS;
    }

    // Fill in signatures (only for the matches) and classify them.
    verify_signatures_in_parallel(&mut matches);
    let classifier = match build_classifier() {
        Ok(classifier) => classifier,
        Err(code) => return code,
    };

    let output = if matches.len() > 1 {
        let verdicts: Vec<ProcessVerdict> = matches
            .iter()
            .map(|process| classifier.classify(process))
            .collect();
        let known = knowledge.lookup(&matches[0].name);
        render_instances(&matches[0].name, &verdicts, known.as_ref(), style)
    } else {
        let verdict = classifier.classify(&matches[0]);
        let known = knowledge.lookup(&matches[0].name);
        render_detail(&verdict, known.as_ref(), style)
    };

    anstream::print!("{output}");
    ExitCode::SUCCESS
}

/// Renders the full detail block for a single process.
fn render_detail(
    verdict: &ProcessVerdict,
    known: Option<&KnownProcess>,
    style: RenderStyle,
) -> String {
    let process = &verdict.process;
    let mut out = String::new();

    let _ = writeln!(out, "{} — PID {}", process.name, process.pid);
    let _ = writeln!(out, "  Risk:      {}", painted_risk(verdict, style));
    let _ = writeln!(out, "  Category:  {}", category_label(verdict.category));
    let _ = writeln!(
        out,
        "  Publisher: {}",
        verdict.publisher.as_deref().unwrap_or("unknown")
    );
    let _ = writeln!(out, "  Signature: {}", signature_label(&process.signature));
    let _ = writeln!(out, "  Path:      {}", path_display(process));
    if let Some(known) = known {
        let _ = writeln!(
            out,
            "  Expected:  {}",
            known.expected_directories.join(" or ")
        );
    }

    out.push_str("\n  What it is:\n");
    match known {
        Some(known) => {
            let _ = writeln!(out, "    {}", known.description_en);
        }
        None => {
            out.push_str(
                "    This process is not in hightower's list of known programs. That is\n",
            );
            out.push_str("    common for third-party software; it is not by itself a problem.\n");
        }
    }

    out.push('\n');
    if verdict.findings.is_empty() {
        out.push_str("  Nothing stood out.\n");
    } else {
        out.push_str("  What hightower noticed:\n");
        for finding in &verdict.findings {
            // Colour each bullet by its own severity.
            let bullet = format!("    - {}", finding.summary);
            let _ = writeln!(
                out,
                "{}",
                paint(&bullet, risk_style(finding.severity), style.color)
            );
        }
    }

    out.push('\n');
    out.push_str(&guidance());
    out
}

/// Renders the summary for several instances that share a name: a shared "what
/// it is", then one coloured risk/path line per instance.
fn render_instances(
    name: &str,
    verdicts: &[ProcessVerdict],
    known: Option<&KnownProcess>,
    style: RenderStyle,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} instances of '{name}' are running.\n",
        verdicts.len()
    );
    match known {
        Some(known) => {
            let _ = writeln!(out, "What it is:\n  {}\n", known.description_en);
        }
        None => out.push_str("This name is not in hightower's known-process list.\n\n"),
    }

    out.push_str("Each instance:\n");
    for verdict in verdicts {
        // Pad the *plain* label to width, then paint: ANSI escapes must not be
        // counted as column width, or the colour would throw the alignment off.
        let risk = paint(
            &format!("{:<10}", risk_label(verdict.risk)),
            risk_style(verdict.risk),
            style.color,
        );
        let _ = writeln!(
            out,
            "  PID {:<6} {risk} {}",
            verdict.process.pid,
            path_display(&verdict.process)
        );
    }
    out.push('\n');
    out.push_str(&guidance());
    out
}

/// The risk label, coloured by its level when the style allows it.
///
/// Note the field-width padding in callers is applied to the *plain* label
/// before painting, because ANSI escapes would otherwise be counted as width and
/// throw the alignment off.
fn painted_risk(verdict: &ProcessVerdict, style: RenderStyle) -> String {
    paint(
        risk_label(verdict.risk),
        risk_style(verdict.risk),
        style.color,
    )
}

/// The standard "what to do" footer -- deliberately cautious.
fn guidance() -> String {
    let mut out = String::new();
    out.push_str("  If it looks suspicious:\n");
    out.push_str(
        "    - Never kill or delete a process unless you are sure -- stopping the wrong\n",
    );
    out.push_str("      one can break Windows or make it restart.\n");
    out.push_str("    - Check the path above is where this program should live.\n");
    out.push_str("    - Research the name online, or ask someone you trust. hightower is a\n");
    out.push_str("      helper, not an antivirus.\n");
    out
}

fn path_display(process: &ProcessInfo) -> String {
    match &process.executable_path {
        Some(path) => path.display().to_string(),
        None => "(restricted — run as administrator for details)".to_string(),
    }
}

fn signature_label(signature: &SignatureStatus) -> &'static str {
    match signature {
        SignatureStatus::Unchecked => "not checked",
        SignatureStatus::Signed { .. } => "signed",
        SignatureStatus::Untrusted => "present but not trusted",
        SignatureStatus::Unsigned => "no signature",
        SignatureStatus::Unknown => "could not be determined",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hightower_core::process::{ProcessCategory, RiskFinding, RiskLevel};
    use std::path::PathBuf;

    fn verdict(name: &str, risk: RiskLevel, findings_text: &[&str]) -> ProcessVerdict {
        let findings = findings_text
            .iter()
            .map(|text| RiskFinding::new(risk, *text))
            .collect();
        ProcessVerdict {
            process: ProcessInfo {
                pid: 4321,
                name: name.to_string(),
                executable_path: Some(PathBuf::from(r"C:\Windows\System32\svchost.exe")),
                restricted: false,
                signature: SignatureStatus::Signed { publisher: None },
            },
            category: ProcessCategory::CoreWindows,
            publisher: Some("Microsoft Windows".to_string()),
            risk,
            findings,
        }
    }

    #[test]
    fn detail_includes_core_fields_and_guidance() {
        let detail = render_detail(
            &verdict("svchost.exe", RiskLevel::Trusted, &[]),
            None,
            RenderStyle::plain(),
        );
        assert!(detail.contains("svchost.exe — PID 4321"));
        assert!(detail.contains("Risk:      trusted"));
        assert!(detail.contains("Publisher: Microsoft Windows"));
        assert!(detail.contains("Nothing stood out."));
        assert!(detail.contains("not an antivirus"));
    }

    #[test]
    fn detail_lists_findings_when_present() {
        let detail = render_detail(
            &verdict("mystery.exe", RiskLevel::Review, &["not in known list"]),
            None,
            RenderStyle::plain(),
        );
        assert!(detail.contains("What hightower noticed:"));
        assert!(detail.contains("- not in known list"));
    }

    #[test]
    fn plain_detail_has_no_escape_sequences() {
        let detail = render_detail(
            &verdict("svchost.exe", RiskLevel::Suspicious, &["bad path"]),
            None,
            RenderStyle::plain(),
        );
        assert!(!detail.contains('\x1b'));
    }

    #[test]
    fn coloured_detail_paints_the_risk() {
        let style = RenderStyle {
            color: true,
            max_width: None,
        };
        let detail = render_detail(
            &verdict("svchost.exe", RiskLevel::Suspicious, &[]),
            None,
            style,
        );
        assert!(detail.contains('\x1b'));
    }
}
