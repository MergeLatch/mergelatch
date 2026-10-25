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

/// Bounds that keep a report small enough for its consumers.
///
/// The Action refuses a report over 5 MiB, so the scanner must not emit one.
/// The bounds are fixed and are not recorded in the report's `limits` object,
/// so that the report of a scan below them is exactly what it was before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReportCaps {
    /// Findings listed in one report.
    pub max_findings: usize,
    /// Serialized size of the listed findings, measured as pretty-printed JSON.
    pub max_finding_bytes: usize,
    /// Incomplete entries listed in one report.
    pub max_incomplete: usize,
    /// Serialized size of the listed incomplete entries.
    pub max_incomplete_bytes: usize,
    /// Characters kept in one free-text finding field.
    pub max_field_chars: usize,
}

impl Default for ReportCaps {
    fn default() -> Self {
        Self {
            max_findings: 1000,
            max_finding_bytes: 2 * 1024 * 1024,
            max_incomplete: 500,
            max_incomplete_bytes: 512 * 1024,
            max_field_chars: 1024,
        }
    }
}

/// Entries kept free for the notes that say something was left out.
const RESERVED_NOTES: usize = 2;

/// Size of one value when it is an element of the pretty-printed report,
/// rounded up: its own pretty form, four more spaces of indentation on every
/// line, and the separator.
fn listed_size<T: Serialize>(value: &T) -> usize {
    let text = serde_json::to_string_pretty(value).expect("report serialization cannot fail");
    text.len() + 4 * (text.matches('\n').count() + 1) + 2
}

fn shorten(text: &mut String, max_chars: usize) {
    if let Some((cut, _)) = text.char_indices().nth(max_chars) {
        text.truncate(cut);
        text.push_str("...");
    }
}

/// Indexes of the entries to keep, in their original order.
///
/// Entries are taken in `order` until the next one would pass either bound.
fn choose<T: Serialize>(
    items: &[T],
    order: impl Iterator<Item = usize>,
    max_count: usize,
    max_bytes: usize,
) -> Vec<usize> {
    let mut kept = Vec::new();
    let mut bytes = 0usize;
    for index in order {
        let cost = listed_size(&items[index]);
        if kept.len() >= max_count || bytes.saturating_add(cost) > max_bytes {
            break;
        }
        bytes += cost;
        kept.push(index);
    }
    kept.sort_unstable();
    kept
}

fn keep<T>(items: Vec<T>, indexes: &[usize]) -> Vec<T> {
    let mut wanted = indexes.iter().copied().peekable();
    items
        .into_iter()
        .enumerate()
        .filter(|(i, _)| {
            if wanted.peek() == Some(i) {
                wanted.next();
                true
            } else {
                false
            }
        })
        .map(|(_, item)| item)
        .collect()
}

impl Report {
    /// Builds a report, ordering findings and incomplete entries so the output
    /// does not depend on discovery order, and deriving the status.
    ///
    /// Any incomplete inspection makes the status `Incomplete`, even when
    /// findings are also present. The findings are still listed.
    ///
    /// A report has bounded size (see [`ReportCaps`]). If the findings do not
    /// fit, the highest-severity ones are kept, in their normal order, and an
    /// `Incomplete` entry of kind `limit_exceeded` says how many were left
    /// out. `summary.findings` and `summary.incomplete` always equal the
    /// lengths of the lists in the report, so they count what is listed.
    pub fn assemble(
        ruleset: RulesetInfo,
        limits: &ScanLimits,
        target: Target,
        files_inspected: usize,
        findings: Vec<Finding>,
        incomplete: Vec<Incomplete>,
    ) -> Self {
        Self::assemble_with(
            ReportCaps::default(),
            ruleset,
            limits,
            target,
            files_inspected,
            findings,
            incomplete,
        )
    }

    pub(crate) fn assemble_with(
        caps: ReportCaps,
        ruleset: RulesetInfo,
        limits: &ScanLimits,
        target: Target,
        files_inspected: usize,
        mut findings: Vec<Finding>,
        mut incomplete: Vec<Incomplete>,
    ) -> Self {
        for f in &mut findings {
            for text in [
                &mut f.title,
                &mut f.location,
                &mut f.message,
                &mut f.evidence,
                &mut f.remediation,
            ] {
                shorten(text, caps.max_field_chars);
            }
        }
        findings.sort();
        findings.dedup();
        incomplete.sort();
        incomplete.dedup();

        let mut notes = Vec::new();

        let limit = caps.max_incomplete.saturating_sub(RESERVED_NOTES);
        let fits = incomplete.len() <= limit
            && incomplete.iter().map(listed_size).sum::<usize>() <= caps.max_incomplete_bytes;
        if !fits {
            let kept = choose(
                &incomplete,
                0..incomplete.len(),
                limit,
                caps.max_incomplete_bytes,
            );
            let left_out = incomplete.len() - kept.len();
            incomplete = keep(incomplete, &kept);
            notes.push(Incomplete {
                path: None,
                kind: IncompleteKind::LimitExceeded,
                detail: format!(
                    "the report lists {} incomplete inspections; {left_out} more were left out to keep it a bounded size",
                    kept.len()
                ),
            });
        }

        let fits = findings.len() <= caps.max_findings
            && findings.iter().map(listed_size).sum::<usize>() <= caps.max_finding_bytes;
        if !fits {
            let mut order: Vec<usize> = (0..findings.len()).collect();
            // Highest severity first; ties keep the report order.
            order.sort_by_key(|&i| (std::cmp::Reverse(findings[i].severity), i));
            let kept = choose(
                &findings,
                order.into_iter(),
                caps.max_findings,
                caps.max_finding_bytes,
            );
            let left_out = findings.len() - kept.len();
            findings = keep(findings, &kept);
            notes.push(Incomplete {
                path: None,
                kind: IncompleteKind::LimitExceeded,
                detail: format!(
                    "the report lists {} findings, the highest severity first; {left_out} more were left out to keep it a bounded size",
                    kept.len()
                ),
            });
        }

        incomplete.extend(notes);
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

    fn sev_finding(severity: Severity, file: &str, line: usize) -> Finding {
        Finding {
            severity,
            ..finding(file, line)
        }
    }

    fn caps(max_findings: usize) -> ReportCaps {
        ReportCaps {
            max_findings,
            ..ReportCaps::default()
        }
    }

    fn assemble_capped(caps: ReportCaps, findings: Vec<Finding>, gaps: Vec<Incomplete>) -> Report {
        Report::assemble_with(
            caps,
            ruleset(),
            &ScanLimits::default(),
            target(),
            1,
            findings,
            gaps,
        )
    }

    fn many(n: usize) -> Vec<Finding> {
        (1..=n).map(|i| finding("a.yml", i)).collect()
    }

    fn omission(report: &Report) -> Vec<&Incomplete> {
        report
            .incomplete
            .iter()
            .filter(|i| i.kind == IncompleteKind::LimitExceeded)
            .collect()
    }

    #[test]
    fn below_the_limit_is_unchanged() {
        let report = assemble_capped(caps(10), many(9), vec![]);
        assert_eq!(report.status, ScanStatus::Findings);
        assert_eq!(report.findings.len(), 9);
        assert!(report.incomplete.is_empty());
    }

    #[test]
    fn exactly_at_the_limit_is_unchanged() {
        let report = assemble_capped(caps(10), many(10), vec![]);
        assert_eq!(report.status, ScanStatus::Findings);
        assert_eq!(report.findings.len(), 10);
        assert!(report.incomplete.is_empty());
        assert_eq!(report.summary.findings, 10);
    }

    #[test]
    fn one_over_the_limit_is_incomplete_and_says_how_many_were_left_out() {
        let report = assemble_capped(caps(10), many(11), vec![]);
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(report.findings.len(), 10);
        assert_eq!(report.summary.findings, 10);
        assert_eq!(report.summary.incomplete, 1);
        let notes = omission(&report);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].path.is_none());
        assert!(
            notes[0].detail.contains("lists 10 findings"),
            "{}",
            notes[0].detail
        );
        assert!(
            notes[0].detail.contains("1 more were left out"),
            "{}",
            notes[0].detail
        );
    }

    #[test]
    fn the_highest_severities_are_kept_and_the_order_is_unchanged() {
        let mut input = vec![
            sev_finding(Severity::Low, "a.yml", 1),
            sev_finding(Severity::High, "a.yml", 2),
            sev_finding(Severity::Medium, "a.yml", 3),
            sev_finding(Severity::High, "a.yml", 4),
            sev_finding(Severity::Low, "a.yml", 5),
        ];
        let report = assemble_capped(caps(3), input.clone(), vec![]);
        // Report order is the normal sort order, not severity order.
        let kept: Vec<_> = report
            .findings
            .iter()
            .map(|f| (f.severity, f.line))
            .collect();
        assert_eq!(
            kept,
            vec![
                (Severity::Medium, Some(3)),
                (Severity::High, Some(2)),
                (Severity::High, Some(4)),
            ]
        );
        input.reverse();
        assert_eq!(report, assemble_capped(caps(3), input, vec![]));
    }

    #[test]
    fn findings_with_other_incomplete_inspections_keep_both() {
        let report = assemble_capped(caps(2), many(5), vec![incomplete()]);
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.summary.incomplete, 2);
        assert!(
            report
                .incomplete
                .iter()
                .any(|i| i.kind == IncompleteKind::InvalidYaml)
        );
        assert_eq!(omission(&report).len(), 1);
    }

    #[test]
    fn duplicates_do_not_count_against_the_limit() {
        let mut input = many(10);
        input.extend(many(10));
        let report = assemble_capped(caps(10), input, vec![]);
        assert_eq!(report.status, ScanStatus::Findings);
        assert_eq!(report.findings.len(), 10);
    }

    #[test]
    fn a_size_bound_alone_also_makes_the_report_incomplete() {
        let cost = listed_size(&finding("a.yml", 1));
        let report = assemble_capped(
            ReportCaps {
                max_finding_bytes: cost * 3 + cost / 2,
                ..ReportCaps::default()
            },
            many(10),
            vec![],
        );
        assert_eq!(report.findings.len(), 3);
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert!(omission(&report)[0].detail.contains("7 more were left out"));
    }

    #[test]
    fn exactly_at_the_size_bound_is_unchanged() {
        let cost = listed_size(&finding("a.yml", 1));
        let report = assemble_capped(
            ReportCaps {
                max_finding_bytes: cost * 4,
                ..ReportCaps::default()
            },
            many(4),
            vec![],
        );
        assert_eq!(report.status, ScanStatus::Findings);
        assert_eq!(report.findings.len(), 4);
    }

    #[test]
    fn long_fields_are_shortened_and_do_not_by_themselves_make_it_incomplete() {
        let mut f = finding("a.yml", 1);
        f.evidence = "é".repeat(100_000);
        f.location = "l".repeat(100_000);
        let report = assemble_capped(ReportCaps::default(), vec![f], vec![]);
        assert_eq!(report.status, ScanStatus::Findings);
        assert_eq!(report.findings[0].evidence.chars().count(), 1024 + 3);
        assert!(report.findings[0].evidence.ends_with("..."));
        assert!(report.to_json().len() < 16 * 1024);
    }

    #[test]
    fn findings_that_differ_only_past_the_field_limit_become_one() {
        let mut a = finding("a.yml", 1);
        let mut b = finding("a.yml", 1);
        a.evidence = format!("{}x", "e".repeat(5000));
        b.evidence = format!("{}y", "e".repeat(5000));
        let report = assemble_capped(ReportCaps::default(), vec![a, b], vec![]);
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn a_flood_of_incomplete_entries_is_bounded_and_still_incomplete() {
        let gaps: Vec<_> = (0..2000)
            .map(|i| Incomplete {
                path: Some(format!("w{i:04}.yml")),
                kind: IncompleteKind::InvalidYaml,
                detail: "d".into(),
            })
            .collect();
        let report = assemble_capped(ReportCaps::default(), vec![], gaps);
        assert_eq!(report.status, ScanStatus::Incomplete);
        // 498 kept entries plus the note, inside the 500 allowed.
        assert_eq!(report.incomplete.len(), 499);
        assert_eq!(report.summary.incomplete, 499);
        assert_eq!(omission(&report).len(), 1);
        assert!(omission(&report)[0].detail.contains("1502 more"));
    }

    #[test]
    fn the_old_ten_thousand_finding_report_is_now_bounded() {
        let input: Vec<_> = (1..=10_000)
            .map(|i| Finding {
                rule_id: "MLA001".into(),
                severity: Severity::Medium,
                title: "Action is not pinned to a full commit SHA".into(),
                file: ".github/workflows/ci.yml".into(),
                line: Some(i),
                location: format!("jobs.b.steps[{i}].uses"),
                message: "m".repeat(200),
                evidence: "uses: actions/checkout@v1".into(),
                remediation: "r".repeat(250),
            })
            .collect();
        let report = assemble_capped(ReportCaps::default(), input.clone(), vec![]);
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(report.findings.len(), 1000);
        assert!(
            omission(&report)[0]
                .detail
                .contains("9000 more were left out")
        );
        assert!(report.to_json().len() < 5 * 1024 * 1024);
        let again = assemble_capped(ReportCaps::default(), input, vec![]);
        assert_eq!(report.to_json(), again.to_json());
    }

    #[test]
    fn the_worst_case_report_stays_inside_the_five_mebibyte_limit() {
        // Maximum-size fields of 4-byte characters, a long path, and more
        // entries than the bounds allow, for findings and for gaps alike.
        let wide = "\u{1F600}".repeat(5000);
        let findings: Vec<_> = (1..=3000)
            .map(|i| Finding {
                rule_id: "MLA001".into(),
                severity: Severity::High,
                title: wide.clone(),
                file: "f".repeat(4096),
                line: Some(i),
                location: wide.clone(),
                message: wide.clone(),
                evidence: wide.clone(),
                remediation: wide.clone(),
            })
            .collect();
        let gaps: Vec<_> = (0..3000)
            .map(|i| Incomplete {
                path: Some(format!("{i}{}", "p".repeat(4096))),
                kind: IncompleteKind::InvalidYaml,
                detail: "d".repeat(300),
            })
            .collect();
        let report = Report::assemble(
            ruleset(),
            &ScanLimits::default(),
            Target {
                path: "t".repeat(4096),
                revision: None,
            },
            1000,
            findings,
            gaps,
        );
        let size = report.to_json().len();
        assert!(size <= 3 * 1024 * 1024, "{size}");
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(report.summary.findings, report.findings.len());
        assert_eq!(report.summary.incomplete, report.incomplete.len());
    }

    #[test]
    fn error_report_has_error_status() {
        let value: serde_json::Value =
            serde_json::from_str(&ErrorReport::new("boom").to_json()).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["message"], "boom");
    }
}
