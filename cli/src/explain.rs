//! `hightower explain <name|pid>`: a plain-language write-up of a single
//! process (or every instance sharing a name).

use std::fmt::Write as _;
use std::process::ExitCode;

use hightower_adapters::knowledge::EmbeddedKnowledgeRepository;
use hightower_adapters::procinfo::ToolHelpProcessLister;
use hightower_core::ports::{KnownProcess, ProcessKnowledgeRepository, ProcessLister};
use hightower_core::process::{
    ProcessCategory, ProcessInfo, ProcessVerdict, RiskLevel, SignatureStatus,
};

use crate::{build_classifier, verify_signatures_in_parallel};

/// Entry point for the `explain` subcommand. `target` is either a numeric PID or
/// a process name (matched case-insensitively).
pub fn run_explain(target: &str) -> ExitCode {
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
            println!("No process named '{target}' is running right now.\n");
            println!("What it is:\n  {}\n", known.description_en);
        } else {
            println!("No running process matches '{target}'.");
            println!("Try `hightower scan --all` to see what is running.");
        }
        return ExitCode::SUCCESS;
    }

    // Fill in signatures (only for the matches) and classify them.
    verify_signatures_in_parallel(&mut matches);
    let classifier = match build_classifier() {
        Ok(classifier) => classifier,
        Err(code) => return code,
    };

    let instance_count = matches.len();
    if instance_count > 1 {
        let display_name = matches[0].name.clone();
        println!("{instance_count} instances of '{display_name}' are running.\n");
        if let Some(known) = knowledge.lookup(&display_name) {
            println!("What it is:\n  {}\n", known.description_en);
        } else {
            println!("This name is not in hightower's known-process list.\n");
        }
        println!("Each instance:");
        for process in &matches {
            let verdict = classifier.classify(process);
            println!(
                "  PID {:<6} {:<10} {}",
                process.pid,
                risk_label(verdict.risk),
                path_display(process)
            );
        }
        println!();
        print!("{}", guidance());
    } else {
        let verdict = classifier.classify(&matches[0]);
        let known = knowledge.lookup(&matches[0].name);
        print!("{}", render_detail(&verdict, known.as_ref()));
    }

    ExitCode::SUCCESS
}

/// Renders the full detail block for a single process.
fn render_detail(verdict: &ProcessVerdict, known: Option<&KnownProcess>) -> String {
    let process = &verdict.process;
    let mut out = String::new();

    let _ = writeln!(out, "{} — PID {}", process.name, process.pid);
    let _ = writeln!(out, "  Risk:      {}", risk_label(verdict.risk));
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
            let _ = writeln!(out, "    - {}", finding.summary);
        }
    }

    out.push('\n');
    out.push_str(&guidance());
    out
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

fn risk_label(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Trusted => "trusted",
        RiskLevel::Review => "review",
        RiskLevel::Suspicious => "suspicious",
    }
}

fn category_label(category: ProcessCategory) -> &'static str {
    match category {
        ProcessCategory::CoreWindows => "core-windows",
        ProcessCategory::Driver => "driver",
        ProcessCategory::ThirdPartyKnown => "third-party-known",
        ProcessCategory::Unknown => "unknown",
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
    use std::path::PathBuf;

    fn verdict(name: &str, risk: RiskLevel, findings_text: &[&str]) -> ProcessVerdict {
        let findings = findings_text
            .iter()
            .map(|text| hightower_core::process::RiskFinding::new(risk, *text))
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
        let detail = render_detail(&verdict("svchost.exe", RiskLevel::Trusted, &[]), None);
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
        );
        assert!(detail.contains("What hightower noticed:"));
        assert!(detail.contains("- not in known list"));
    }
}
