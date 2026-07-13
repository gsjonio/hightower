//! The domain model: what hightower knows about a running process, and the
//! verdict it reaches about that process.
//!
//! Everything here is plain data plus a little logic to aggregate risk. None of
//! it touches the operating system; the fields are *filled in* by the adapters
//! (process listing, signature checks) and by the classifier.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// How trustworthy a process looks, from best to worst.
///
/// The variants are declared in ascending order of concern, which is what makes
/// the derived `Ord` do the right thing: `Suspicious > Review > Trusted`. That
/// ordering is used to aggregate many findings into one overall verdict by
/// simply taking the maximum.
///
/// (Python bridge: like an `enum.IntEnum` where a larger value means "worse",
/// except the compiler derives the comparison for us from the declaration
/// order.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskLevel {
    /// Recognized and in its expected place -- nothing stood out.
    Trusted,
    /// Nothing alarming, but something is worth a human glance.
    Review,
    /// One or more strong warning signs (e.g. masquerading). Not a malware
    /// verdict -- a strong prompt to investigate.
    Suspicious,
}

/// The bucket a process falls into, used for grouping and plain-language output.
///
/// Derives `Deserialize` because it is also read back from the embedded
/// known-process database, where the JSON spells the values in kebab-case
/// (`"core-windows"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessCategory {
    /// A core part of Windows itself (e.g. `svchost.exe`, `csrss.exe`).
    CoreWindows,
    /// A device driver / kernel-level component.
    Driver,
    /// Third-party software we recognize from the known-process database.
    ThirdPartyKnown,
    /// Not in the database and not otherwise identifiable -- review manually.
    Unknown,
}

/// What we could determine about an executable's digital signature.
///
/// A signature that could not be read (file gone, access denied) is *not* an
/// error: it is simply `Unknown`. Only failures of a whole operation use
/// [`crate::HightowerError`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureStatus {
    /// Not looked at yet. This is the value a freshly listed process carries
    /// before the (relatively expensive) signature check runs.
    Unchecked,
    /// Validly signed and trusted; carries the signer/publisher name when the
    /// certificate exposes one.
    Signed {
        /// The publisher taken from the signing certificate, when available.
        publisher: Option<String>,
    },
    /// A signature is present but not trusted (broken chain, self-signed,
    /// revoked, expired).
    Untrusted,
    /// No signature at all.
    Unsigned,
    /// The signature could not be determined (e.g. the file could not be read).
    Unknown,
}

/// Everything hightower knows about one running process.
///
/// Think of this as progressively enriched: the process lister fills in
/// [`pid`](Self::pid), [`name`](Self::name), [`executable_path`](Self::executable_path)
/// and [`restricted`](Self::restricted); the signature verifier later fills in
/// [`signature`](Self::signature). The risk rules read the finished value.
///
/// (Python bridge: an ordinary data record, like a `@dataclass`. The `derive`
/// line hands us the equivalents of `__repr__` (`Debug`), value equality
/// (`PartialEq`), copying (`Clone`), and JSON output (`Serialize`) for free.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessInfo {
    /// The operating-system process id.
    pub pid: u32,
    /// The image/base name as the OS reports it, e.g. `"svchost.exe"`.
    pub name: String,
    /// Full path to the executable on disk. `None` when the OS refused to reveal
    /// it (a protected process without an elevated terminal).
    pub executable_path: Option<PathBuf>,
    /// `true` when the OS denied full details for this process. Such a process
    /// is still listed -- never dropped, never a panic -- just with less known
    /// about it.
    pub restricted: bool,
    /// Result of the digital-signature check, or [`SignatureStatus::Unchecked`]
    /// before that step has run.
    pub signature: SignatureStatus,
}

/// A single thing a risk rule noticed about a process.
///
/// Rules return `Option<RiskFinding>`: `None` when the rule has nothing to say,
/// `Some(finding)` when it does. Aggregating these is how a verdict is reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskFinding {
    /// How serious this particular observation is on its own.
    pub severity: RiskLevel,
    /// A short, plain-language explanation aimed at a non-technical reader.
    pub summary: String,
}

impl RiskFinding {
    /// Convenience constructor so rules can write
    /// `RiskFinding::new(RiskLevel::Suspicious, "...")` instead of the struct
    /// literal.
    pub fn new(severity: RiskLevel, summary: impl Into<String>) -> Self {
        Self {
            severity,
            summary: summary.into(),
        }
    }
}

/// The classifier's conclusion about one process: its category, publisher, an
/// overall [`RiskLevel`], and the findings that justify it.
///
/// This is the shape the CLI renders (as a table row or as JSON), so it derives
/// `Serialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessVerdict {
    /// The process this verdict is about.
    pub process: ProcessInfo,
    /// Which bucket the process was placed in.
    pub category: ProcessCategory,
    /// The recognized publisher, if any (from the signature or the database).
    pub publisher: Option<String>,
    /// The overall risk level: the worst severity among the findings.
    pub risk: RiskLevel,
    /// The individual observations behind the verdict; empty means "nothing was
    /// flagged".
    pub findings: Vec<RiskFinding>,
}

impl ProcessVerdict {
    /// Builds a verdict, deriving the overall [`risk`](Self::risk) from the
    /// findings: the worst severity present, or [`RiskLevel::Trusted`] when
    /// there is nothing to flag.
    pub fn new(
        process: ProcessInfo,
        category: ProcessCategory,
        publisher: Option<String>,
        findings: Vec<RiskFinding>,
    ) -> Self {
        // Python equivalent:
        //   risk = max((f.severity for f in findings), default=RiskLevel.Trusted)
        // Written as an explicit loop so the "take the worst finding" intent is
        // obvious without leaning on Rust iterator idioms.
        let mut risk = RiskLevel::Trusted;
        for finding in &findings {
            if finding.severity > risk {
                risk = finding.severity;
            }
        }

        Self {
            process,
            category,
            publisher,
            risk,
            findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ProcessInfo so tests can focus on verdict aggregation.
    fn sample_process() -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            name: "example.exe".to_string(),
            executable_path: None,
            restricted: false,
            signature: SignatureStatus::Unchecked,
        }
    }

    #[test]
    fn no_findings_is_trusted() {
        let verdict =
            ProcessVerdict::new(sample_process(), ProcessCategory::CoreWindows, None, vec![]);
        assert_eq!(verdict.risk, RiskLevel::Trusted);
    }

    #[test]
    fn overall_risk_is_the_worst_finding() {
        // Table-driven: each row is (finding severities, expected overall risk).
        let cases = [
            (vec![RiskLevel::Review], RiskLevel::Review),
            (
                vec![RiskLevel::Review, RiskLevel::Suspicious],
                RiskLevel::Suspicious,
            ),
            (
                vec![RiskLevel::Suspicious, RiskLevel::Review, RiskLevel::Trusted],
                RiskLevel::Suspicious,
            ),
            (vec![RiskLevel::Trusted], RiskLevel::Trusted),
        ];

        for (severities, expected) in cases {
            let findings = severities
                .into_iter()
                .map(|severity| RiskFinding::new(severity, "test"))
                .collect();
            let verdict =
                ProcessVerdict::new(sample_process(), ProcessCategory::Unknown, None, findings);
            assert_eq!(verdict.risk, expected);
        }
    }

    #[test]
    fn risk_levels_order_worst_last() {
        assert!(RiskLevel::Suspicious > RiskLevel::Review);
        assert!(RiskLevel::Review > RiskLevel::Trusted);
    }
}
