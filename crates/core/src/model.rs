use serde::Serialize;

use crate::ScanLimits;

/// Version of the JSON report layout. Incremented on incompatible changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Overall outcome of a scan.
///
/// `Error` means the scan could not run at all. `scan_directory` returns an
/// error value in that case instead of a [`Report`], so a [`Report`] never has
/// this status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// Every required inspection completed and nothing was detected.
    Clean,
    /// Every required inspection completed and at least one rule matched.
    Findings,
    /// At least one required inspection could not complete.
    Incomplete,
    /// The scan could not run.
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
}

/// A rule match, with the evidence needed to review it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    /// Path relative to the scan root, using `/` separators.
    pub file: String,
    /// 1-based line number, if known.
    pub line: Option<usize>,
    /// Position within the file, for example `jobs.build.permissions`.
    pub location: String,
    pub message: String,
    /// The source text that matched, sanitized for display.
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteKind {
    Unreadable,
    NotRegularFile,
    OutsideRoot,
    FileTooLarge,
    InvalidUtf8,
    InvalidYaml,
    UnsupportedYaml,
    LimitExceeded,
    Timeout,
    /// The workflow uses a construct the rules cannot analyze reliably.
    AnalysisLimit,
}

/// An inspection that could not be completed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Incomplete {
    /// Path relative to the scan root, or `None` if the problem is not tied to a file.
    pub path: Option<String>,
    pub kind: IncompleteKind,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScannerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RulesetInfo {
    pub id: String,
    pub version: String,
    pub rules: Vec<String>,
}

/// Git revision of the scanned directory, read without running Git.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Revision {
    /// Commit hash, if it could be determined.
    pub commit: Option<String>,
    /// Checked-out reference such as `refs/heads/main`, if any.
    pub reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Target {
    /// Canonical absolute path of the scan root.
    pub path: String,
    /// `None` when the directory is not a Git checkout or the revision could not be read.
    pub revision: Option<Revision>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub files_inspected: usize,
    pub findings: usize,
    pub incomplete: usize,
}

/// Result of a completed scan. Contains no timestamps, so identical input
/// produces identical output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub scanner: ScannerInfo,
    pub ruleset: RulesetInfo,
    pub limits: LimitsInfo,
    pub target: Target,
    pub status: ScanStatus,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub incomplete: Vec<Incomplete>,
}

/// The limits in force, recorded so a report can be interpreted later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LimitsInfo {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_entries: usize,
    pub max_yaml_depth: usize,
    pub timeout_seconds: u64,
}

impl From<&ScanLimits> for LimitsInfo {
    fn from(l: &ScanLimits) -> Self {
        Self {
            max_file_bytes: l.max_file_bytes,
            max_total_bytes: l.max_total_bytes,
            max_entries: l.max_entries,
            max_yaml_depth: l.max_yaml_depth,
            timeout_seconds: l.timeout.as_secs(),
        }
    }
}

impl Report {
    /// Builds a report, ordering findings and incomplete entries so the output
    /// does not depend on discovery order, and deriving the status.
    ///
    /// Any incomplete inspection makes the status `Incomplete`, even when
    /// findings are also present. The findings are still listed.
    pub fn assemble(
        ruleset: RulesetInfo,
        limits: &ScanLimits,
        target: Target,
        files_inspected: usize,
        mut findings: Vec<Finding>,
        mut incomplete: Vec<Incomplete>,
    ) -> Self {
        findings.sort();
        findings.dedup();
        incomplete.sort();
        incomplete.dedup();
        let status = if !incomplete.is_empty() {
            ScanStatus::Incomplete
        } else if !findings.is_empty() {
            ScanStatus::Findings
        } else {
            ScanStatus::Clean
        };
        Self {
            schema_version: SCHEMA_VERSION,
            scanner: ScannerInfo {
                name: "mergelatch-core".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            ruleset,
            limits: limits.into(),
            target,
            status,
            summary: Summary {
                files_inspected,
                findings: findings.len(),
                incomplete: incomplete.len(),
            },
            findings,
            incomplete,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serialization cannot fail")
    }
}

/// JSON body emitted when a scan could not run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorReport {
    pub schema_version: u32,
    pub status: ScanStatus,
    pub message: String,
}

impl ErrorReport {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            status: ScanStatus::Error,
            message: message.into(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("error report serialization cannot fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ruleset() -> RulesetInfo {
        RulesetInfo {
            id: "test".into(),
            version: "1".into(),
            rules: vec![],
        }
    }

    fn target() -> Target {
        Target {
            path: "/repo".into(),
            revision: None,
        }
    }

    fn finding(file: &str, line: usize) -> Finding {
        Finding {
            rule_id: "R1".into(),
            severity: Severity::Medium,
            title: "t".into(),
            file: file.into(),
            line: Some(line),
            location: "permissions".into(),
            message: "m".into(),
            evidence: "e".into(),
            remediation: "r".into(),
        }
    }

    fn incomplete() -> Incomplete {
        Incomplete {
            path: Some("a.yml".into()),
            kind: IncompleteKind::InvalidYaml,
            detail: "d".into(),
        }
    }

    fn assemble(findings: Vec<Finding>, incomplete: Vec<Incomplete>) -> Report {
        Report::assemble(
            ruleset(),
            &ScanLimits::default(),
            target(),
            1,
            findings,
            incomplete,
        )
    }

    #[test]
    fn no_findings_and_no_gaps_is_clean() {
        assert_eq!(assemble(vec![], vec![]).status, ScanStatus::Clean);
    }

    #[test]
    fn findings_without_gaps_is_findings() {
        assert_eq!(
            assemble(vec![finding("a", 1)], vec![]).status,
            ScanStatus::Findings
        );
    }

    #[test]
    fn any_gap_is_incomplete_even_with_findings() {
        let report = assemble(vec![finding("a", 1)], vec![incomplete()]);
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn findings_are_sorted_regardless_of_input_order() {
        let a = assemble(vec![finding("b.yml", 2), finding("a.yml", 9)], vec![]);
        let b = assemble(vec![finding("a.yml", 9), finding("b.yml", 2)], vec![]);
        assert_eq!(a, b);
        assert_eq!(a.findings[0].file, "a.yml");
        assert_eq!(a.to_json(), b.to_json());
    }

    #[test]
    fn json_uses_snake_case_statuses_and_schema_version() {
        let json = assemble(vec![], vec![incomplete()]).to_json();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["status"], "incomplete");
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["incomplete"][0]["kind"], "invalid_yaml");
    }

    #[test]
    fn error_report_has_error_status() {
        let value: serde_json::Value =
            serde_json::from_str(&ErrorReport::new("boom").to_json()).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["message"], "boom");
    }
}
