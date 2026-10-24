//! Behavior of rule ML-GHA-001 on harmless fixtures.

use std::fs;
use std::path::{Path, PathBuf};

use mergelatch_core::{
    IncompleteKind, RULE_PRIVILEGED_PR_CODE, RULE_SCRIPT_INJECTION, RULE_UNPINNED, RULE_WRITE_ALL,
    Report, ScanLimits, ScanStatus, scan_directory,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/gha-permissions")
        .join(name)
}

fn scan_fixture(name: &str) -> Report {
    scan_directory(&fixture(name), &ScanLimits::default()).expect("scan should run")
}

/// Scans a temporary repository containing one workflow with the given text.
fn scan_text(yaml: &str) -> Report {
    let dir = tempfile::tempdir().unwrap();
    let wf = dir.path().join(".github/workflows");
    fs::create_dir_all(&wf).unwrap();
    fs::write(wf.join("ci.yml"), yaml).unwrap();
    scan_directory(dir.path(), &ScanLimits::default()).expect("scan should run")
}

#[test]
fn read_only_workflow_is_clean() {
    let report = scan_fixture("safe-read-only");
    assert_eq!(report.status, ScanStatus::Clean);
    assert_eq!(report.summary.files_inspected, 1);
    assert!(report.findings.is_empty());
}

#[test]
fn read_all_is_not_flagged() {
    assert_eq!(scan_fixture("safe-read-all").status, ScanStatus::Clean);
}

#[test]
fn workflow_level_write_all_is_detected() {
    let report = scan_fixture("workflow-write-all");
    assert_eq!(report.status, ScanStatus::Findings);
    assert_eq!(report.findings.len(), 1);
    let f = &report.findings[0];
    assert_eq!(f.rule_id, RULE_WRITE_ALL);
    assert_eq!(f.file, ".github/workflows/ci.yml");
    assert_eq!(f.line, Some(3));
    assert_eq!(f.location, "permissions");
    assert_eq!(f.evidence, "permissions: write-all");
    assert!(!f.remediation.is_empty());
}

#[test]
fn job_level_write_all_is_detected_and_names_the_job() {
    let report = scan_fixture("job-write-all");
    assert_eq!(report.status, ScanStatus::Findings);
    assert_eq!(report.findings.len(), 1);
    let f = &report.findings[0];
    assert_eq!(f.location, "jobs.publish.permissions");
    assert_eq!(f.line, Some(12));
    assert!(f.message.contains("publish"));
}

#[test]
fn comments_strings_and_unrelated_keys_are_not_flagged() {
    let report = scan_fixture("misleading-text");
    assert_eq!(report.status, ScanStatus::Clean, "{:#?}", report.findings);
}

#[test]
fn malformed_yaml_is_incomplete_not_clean() {
    let report = scan_fixture("malformed");
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(report.incomplete.len(), 1);
    assert_eq!(report.incomplete[0].kind, IncompleteKind::InvalidYaml);
    assert_eq!(
        report.incomplete[0].path.as_deref(),
        Some(".github/workflows/ci.yml")
    );
}

#[test]
fn quoted_value_is_still_a_real_setting() {
    let report = scan_text("on: push\npermissions: \"write-all\"\njobs: {}\n");
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn flow_style_mapping_is_detected() {
    let report = scan_text("on: push\njobs: {a: {permissions: write-all, runs-on: x}}\n");
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].location, "jobs.a.permissions");
}

#[test]
fn every_occurrence_is_reported_in_order() {
    let report = scan_text(
        "on: push\npermissions: write-all\njobs:\n  b:\n    permissions: write-all\n  a:\n    permissions: write-all\n",
    );
    let locations: Vec<_> = report
        .findings
        .iter()
        .map(|f| f.location.as_str())
        .collect();
    assert_eq!(
        locations,
        ["permissions", "jobs.b.permissions", "jobs.a.permissions"]
    );
}

#[test]
fn permission_maps_with_write_scopes_are_out_of_scope() {
    let report = scan_text("on: push\npermissions:\n  contents: write\njobs: {}\n");
    assert_eq!(report.status, ScanStatus::Clean);
}

#[test]
fn scalar_alias_to_write_all_is_detected_at_the_use_site() {
    let report = scan_text("on: push\nx-level: &lvl write-all\npermissions: *lvl\njobs: {}\n");
    assert_eq!(report.findings.len(), 1);
    let f = &report.findings[0];
    assert_eq!(f.line, Some(3), "should point at the permissions setting");
    assert_eq!(f.location, "permissions");
    assert_eq!(
        f.evidence,
        "permissions: write-all (alias; value defined on line 2)"
    );
}

#[test]
fn multiple_aliases_each_point_at_their_own_setting() {
    let report = scan_text(
        "on: push\n\
         x-level: &lvl write-all\n\
         permissions: *lvl\n\
         jobs:\n\
         \x20 a:\n\
         \x20   permissions: *lvl\n\
         \x20 b:\n\
         \x20   permissions: *lvl\n",
    );
    let found: Vec<_> = report
        .findings
        .iter()
        .map(|f| (f.location.as_str(), f.line.unwrap()))
        .collect();
    assert_eq!(
        found,
        [
            ("permissions", 3),
            ("jobs.a.permissions", 6),
            ("jobs.b.permissions", 8)
        ]
    );
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.evidence.ends_with("line 2)"))
    );
}

#[test]
fn alias_to_a_safe_value_is_not_flagged() {
    let report = scan_text(
        "on: push\nx-safe: &safe read-all\nx-bad: &bad write-all\npermissions: *safe\njobs: {}\n",
    );
    assert_eq!(report.status, ScanStatus::Clean, "{:#?}", report.findings);
}

#[test]
fn unused_anchor_with_write_all_is_not_a_setting() {
    let report = scan_text("on: push\nx-level: &lvl write-all\npermissions: read-all\njobs: {}\n");
    assert_eq!(report.status, ScanStatus::Clean);
}

#[test]
fn collection_alias_and_merge_keys_make_the_scan_incomplete() {
    let alias = scan_text("on: push\nbase: &b {runs-on: x}\njobs:\n  a: *b\n");
    assert_eq!(alias.status, ScanStatus::Incomplete);
    assert_eq!(alias.incomplete[0].kind, IncompleteKind::UnsupportedYaml);

    let merge = scan_text("on: push\nbase: &b {permissions: write-all}\njobs:\n  a:\n    <<: *b\n");
    assert_eq!(merge.status, ScanStatus::Incomplete);
}

#[test]
fn non_mapping_workflow_is_incomplete() {
    assert_eq!(scan_text("- a\n- b\n").status, ScanStatus::Incomplete);
}

#[test]
fn findings_and_gaps_together_report_incomplete_with_findings_listed() {
    let dir = tempfile::tempdir().unwrap();
    let wf = dir.path().join(".github/workflows");
    fs::create_dir_all(&wf).unwrap();
    fs::write(wf.join("a.yml"), "permissions: write-all\n").unwrap();
    fs::write(wf.join("b.yml"), "permissions: [\n").unwrap();
    let report = scan_directory(dir.path(), &ScanLimits::default()).unwrap();
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.incomplete.len(), 1);
}

#[test]
fn report_records_scanner_ruleset_and_target() {
    let report = scan_fixture("safe-read-only");
    assert_eq!(report.scanner.name, "mergelatch-core");
    assert_eq!(report.scanner.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        report.ruleset.rules,
        [
            RULE_WRITE_ALL,
            RULE_UNPINNED,
            RULE_SCRIPT_INJECTION,
            RULE_PRIVILEGED_PR_CODE
        ]
    );
    assert!(Path::new(&report.target.path).is_absolute());
}

const MARKER: &str = "MERGELATCH_TEST_SECRET";

#[test]
fn evidence_does_not_copy_unrelated_text_from_the_line() {
    let report = scan_text(&format!(
        "on: push\n\
         env: {{API_KEY: {MARKER}_ENV}}\n\
         permissions: write-all # token={MARKER}_COMMENT\n\
         jobs: {{a: {{permissions: write-all, env: {{TOKEN: {MARKER}_FLOW}}}}}}\n"
    ));
    assert_eq!(report.findings.len(), 2);
    let evidence: Vec<_> = report
        .findings
        .iter()
        .map(|f| f.evidence.as_str())
        .collect();
    assert_eq!(
        evidence,
        ["permissions: write-all", "permissions: write-all"]
    );
    let json = report.to_json();
    assert!(!json.contains(MARKER), "marker leaked into JSON:\n{json}");
}

#[test]
fn evidence_still_identifies_the_setting() {
    let report = scan_fixture("job-write-all");
    let f = &report.findings[0];
    assert_eq!(f.evidence, "permissions: write-all");
    assert_eq!(f.location, "jobs.publish.permissions");
    assert_eq!(f.line, Some(12));
}
