use std::fmt::Write;

use mergelatch_core::{Report, RuleInfo, ScanStatus, sanitize_text};

/// Process exit codes. `1` and `2` are both non-passing: a gate must not treat
/// an incomplete scan as success.
pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_FINDINGS: i32 = 1;
pub const EXIT_INCOMPLETE: i32 = 2;
pub const EXIT_ERROR: i32 = 3;

pub fn exit_code(status: ScanStatus) -> i32 {
    match status {
        ScanStatus::Clean => EXIT_CLEAN,
        ScanStatus::Findings => EXIT_FINDINGS,
        ScanStatus::Incomplete => EXIT_INCOMPLETE,
        ScanStatus::Error => EXIT_ERROR,
    }
}

pub fn human_report(report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "MergeLatch {} (ruleset {} {})",
        report.scanner.version, report.ruleset.id, report.ruleset.version
    );
    let _ = writeln!(out, "Target: {}", sanitize_text(&report.target.path, 500));
    let _ = match &report.target.revision {
        Some(rev) => writeln!(
            out,
            "Revision: {}{}",
            rev.commit.as_deref().unwrap_or("unknown commit"),
            rev.reference
                .as_deref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default()
        ),
        None => writeln!(out, "Revision: not available"),
    };
    let _ = writeln!(
        out,
        "Workflow files inspected: {}",
        report.summary.files_inspected
    );

    if !report.findings.is_empty() {
        let _ = writeln!(out, "\nFindings ({}):", report.findings.len());
        for f in &report.findings {
            let at = match f.line {
                Some(line) => format!("{}:{line}", f.file),
                None => f.file.clone(),
            };
            let _ = writeln!(out, "\n  {} [{:?}] {at}", f.rule_id, f.severity);
            let _ = writeln!(out, "    {}", f.title);
            let _ = writeln!(out, "    Location: {}", f.location);
            let _ = writeln!(out, "    Evidence: {}", f.evidence);
            let _ = writeln!(out, "    Why: {}", f.message);
            let _ = writeln!(out, "    Fix: {}", f.remediation);
        }
    }

    if !report.incomplete.is_empty() {
        let _ = writeln!(
            out,
            "\nIncomplete inspections ({}):",
            report.incomplete.len()
        );
        for gap in &report.incomplete {
            let _ = writeln!(
                out,
                "  {}: {:?}: {}",
                gap.path.as_deref().unwrap_or("(scan)"),
                gap.kind,
                gap.detail
            );
        }
    }

    let summary = match report.status {
        ScanStatus::Clean => "clean (no findings; all required inspections completed)",
        ScanStatus::Findings => "findings (review the findings above)",
        ScanStatus::Incomplete => {
            "incomplete (some inspections did not finish; this is not a pass)"
        }
        ScanStatus::Error => "error",
    };
    let _ = writeln!(
        out,
        "\nResult: {summary}\nExit code: {}",
        exit_code(report.status)
    );
    out
}

pub fn human_rules(rules: &[RuleInfo]) -> String {
    let mut out = String::new();
    for rule in rules {
        let _ = writeln!(out, "{} [{:?}]", rule.id, rule.severity);
        let _ = writeln!(out, "  {}", rule.title);
        let _ = writeln!(out, "  {}", rule.description);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_distinguish_every_outcome() {
        assert_eq!(exit_code(ScanStatus::Clean), 0);
        assert_eq!(exit_code(ScanStatus::Findings), 1);
        assert_eq!(exit_code(ScanStatus::Incomplete), 2);
        assert_eq!(exit_code(ScanStatus::Error), 3);
    }
}
