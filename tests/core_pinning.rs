//! Behavior of rule ML-GHA-002 (unpinned external references).

use std::fs;
use std::path::{Path, PathBuf};

use mergelatch_core::{
    IncompleteKind, RULE_UNPINNED, Report, ScanLimits, ScanStatus, scan_directory,
};

const SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/gha-pinning")
        .join(name)
}

fn scan_fixture(name: &str) -> Report {
    scan_directory(&fixture(name), &ScanLimits::default()).expect("scan should run")
}

fn scan_text(yaml: &str) -> Report {
    let dir = tempfile::tempdir().unwrap();
    let wf = dir.path().join(".github/workflows");
    fs::create_dir_all(&wf).unwrap();
    fs::write(wf.join("ci.yml"), yaml).unwrap();
    scan_directory(dir.path(), &ScanLimits::default()).expect("scan should run")
}

fn only(report: &Report) -> &mergelatch_core::Finding {
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    &report.findings[0]
}

#[test]
fn sha_pinned_local_and_digest_references_are_clean() {
    let report = scan_fixture("pinned");
    assert_eq!(report.status, ScanStatus::Clean, "{:#?}", report.findings);
}

#[test]
fn mutable_tag_is_flagged_with_location_and_evidence() {
    let report = scan_fixture("unpinned-tag");
    assert_eq!(report.status, ScanStatus::Findings);
    let f = only(&report);
    assert_eq!(f.rule_id, RULE_UNPINNED);
    assert_eq!(f.location, "jobs.build.steps[0].uses");
    assert_eq!(f.line, Some(7));
    assert_eq!(f.evidence, "uses: actions/checkout@v4");
    assert!(f.message.contains("actions/checkout"));
    assert!(f.remediation.contains("full commit SHA"));
    assert!(f.remediation.contains("does not make the pinned code safe"));
}

#[test]
fn branch_and_action_subpath_references_are_flagged_in_order() {
    let report = scan_fixture("unpinned-branch-and-subpath");
    let found: Vec<_> = report
        .findings
        .iter()
        .map(|f| (f.location.as_str(), f.evidence.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            ("jobs.build.steps[0].uses", "uses: owner/repo@main"),
            ("jobs.build.steps[1].uses", "uses: owner/repo/sub/path@v2"),
        ]
    );
}

#[test]
fn docker_images_and_reusable_workflows_are_handled_separately() {
    let report = scan_fixture("docker-and-reusable");
    assert_eq!(report.findings.len(), 2);
    let docker = report
        .findings
        .iter()
        .find(|f| f.location.contains("steps"))
        .unwrap();
    assert!(docker.message.contains("Docker image"));
    assert!(!docker.message.contains("tag or branch"));
    let reusable = report
        .findings
        .iter()
        .find(|f| f.location == "jobs.call.uses")
        .unwrap();
    assert!(reusable.message.contains("reusable workflow"));
    assert_eq!(
        reusable.evidence,
        "uses: owner/repo/.github/workflows/reusable.yml@v1"
    );
}

#[test]
fn dynamic_reference_is_an_analysis_limit_not_a_pass() {
    let report = scan_fixture("dynamic-reference");
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert!(report.findings.is_empty());
    assert_eq!(report.incomplete[0].kind, IncompleteKind::AnalysisLimit);
    assert!(
        report.incomplete[0]
            .detail
            .contains("jobs.build.steps[0].uses")
    );
}

#[test]
fn comments_strings_and_unrelated_keys_are_not_flagged() {
    let report = scan_fixture("misleading-text");
    assert_eq!(report.status, ScanStatus::Clean, "{:#?}", report.findings);
}

#[test]
fn flow_style_mappings_are_analyzed() {
    let report = scan_text(
        "on: push\njobs: {a: {runs-on: x, steps: [{uses: 'owner/repo@v1'}, {uses: \"owner/repo@main\"}]}}\n",
    );
    let locations: Vec<_> = report
        .findings
        .iter()
        .map(|f| f.location.as_str())
        .collect();
    assert_eq!(locations, ["jobs.a.steps[0].uses", "jobs.a.steps[1].uses"]);
}

#[test]
fn scalar_alias_is_reported_at_the_use_site() {
    let report = scan_text(&format!(
        "on: push\nx-action: &a owner/repo@v1\njobs:\n  a:\n    steps:\n      - uses: *a\n      - uses: owner/repo@{SHA}\n"
    ));
    let f = only(&report);
    assert_eq!(f.line, Some(6));
    assert_eq!(
        f.evidence,
        "uses: owner/repo@v1 (alias; value defined on line 2)"
    );
}

#[test]
fn aliased_steps_and_merge_keys_are_incomplete() {
    let alias =
        scan_text("on: push\nx: &s {uses: 'owner/repo@v1'}\njobs:\n  a:\n    steps:\n      - *x\n");
    assert_eq!(alias.status, ScanStatus::Incomplete);
    let merge = scan_text(
        "on: push\nx: &s {uses: 'owner/repo@v1'}\njobs:\n  a:\n    steps:\n      - <<: *s\n",
    );
    assert_eq!(merge.status, ScanStatus::Incomplete);
    assert!(merge.findings.is_empty());
}

#[test]
fn non_string_uses_is_an_analysis_limit() {
    let report = scan_text("on: push\njobs:\n  a:\n    steps:\n      - uses: [owner/repo@v1]\n");
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(report.incomplete[0].kind, IncompleteKind::AnalysisLimit);
}

#[test]
fn malformed_references_are_analysis_limits_not_pins() {
    for value in ["owner", "owner/repo", "owner/repo@", "a b/c@v1"] {
        let report = scan_text(&format!(
            "on: push\njobs:\n  a:\n    steps:\n      - uses: '{value}'\n"
        ));
        assert_eq!(report.status, ScanStatus::Incomplete, "{value}");
    }
}

#[test]
fn duplicate_uses_keys_cannot_hide_an_unpinned_reference() {
    let report = scan_text(&format!(
        "on: push\njobs:\n  a:\n    steps:\n      - uses: owner/repo@v1\n        uses: owner/repo@{SHA}\n"
    ));
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn multiple_findings_in_one_workflow_are_deterministic() {
    let yaml = "on: push\npermissions: write-all\njobs:\n  b:\n    steps:\n      - uses: owner/b@v1\n  a:\n    steps:\n      - uses: owner/a@v1\n";
    let first = scan_text(yaml);
    let second = scan_text(yaml);
    let strip = |r: &Report| r.to_json().replace(&r.target.path, "<root>");
    assert_eq!(strip(&first), strip(&second));
    let ids: Vec<_> = first
        .findings
        .iter()
        .map(|f| (f.rule_id.as_str(), f.line))
        .collect();
    assert_eq!(
        ids,
        [
            ("ML-GHA-001", Some(2)),
            ("ML-GHA-002", Some(6)),
            ("ML-GHA-002", Some(9))
        ]
    );
}

#[test]
fn evidence_does_not_leak_neighboring_text() {
    let report = scan_text(
        "on: push\njobs:\n  a:\n    steps:\n      - uses: owner/repo@v1 # SECRET_COMMENT_MARKER\n        env: {TOKEN: SECRET_ENV_MARKER}\n",
    );
    let json = report.to_json();
    assert!(!json.contains("SECRET_"), "{json}");
    assert_eq!(report.findings.len(), 1);
}
