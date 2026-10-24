//! Behavior of rule ML-GHA-004 (pull request code run in a pull_request_target
//! workflow). All inputs are harmless text; nothing here is ever executed.

use std::fs;
use std::path::{Path, PathBuf};

use mergelatch_core::{
    Finding, IncompleteKind, RULE_PRIVILEGED_PR_CODE, Report, ScanLimits, ScanStatus, Severity,
    scan_directory,
};

const SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/gha-privileged")
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

fn rule(report: &Report) -> Vec<&Finding> {
    report
        .findings
        .iter()
        .filter(|f| f.rule_id == RULE_PRIVILEGED_PR_CODE)
        .collect()
}

#[test]
fn head_checkout_followed_by_npm_is_flagged() {
    let report = scan_fixture("pr-head-then-npm");
    let found = rule(&report);
    assert_eq!(found.len(), 1);
    let f = found[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.location, "jobs.build.steps[0].with.ref");
    assert_eq!(f.line, Some(11));
    assert_eq!(
        f.evidence,
        "ref: ${{ github.event.pull_request.head.sha }}; step 1 runs npm"
    );
    assert!(f.message.contains("pull_request_target"));
    assert!(f.message.contains("step 1"));
    assert!(f.message.contains("1 more step"));
    assert!(f.message.contains("No explicit write permission"));
    assert!(f.remediation.contains("`pull_request` workflow"));
    assert_eq!(report.status, ScanStatus::Findings);
}

#[test]
fn pull_request_target_alone_is_not_a_finding() {
    for name in ["base-checkout-only", "base-ref-explicit"] {
        let report = scan_fixture(name);
        assert!(rule(&report).is_empty(), "{name}");
        assert_eq!(report.status, ScanStatus::Clean, "{name}");
    }
}

#[test]
fn head_checkout_without_execution_is_not_flagged() {
    let report = scan_fixture("head-checkout-no-exec");
    assert_eq!(report.status, ScanStatus::Clean, "{:#?}", report);
}

#[test]
fn fork_repository_checkout_reports_write_permission_and_secrets() {
    let report = scan_fixture("fork-repository");
    let found = rule(&report);
    assert_eq!(found.len(), 1);
    let f = found[0];
    assert!(f.location.ends_with(".with.repository"), "{}", f.location);
    assert!(
        f.message
            .contains("The token permissions include write access.")
    );
    assert!(f.message.contains("The job references secrets."));
}

#[test]
fn refs_pull_merge_checkout_is_flagged() {
    let report = scan_fixture("refs-pull-merge");
    assert_eq!(rule(&report).len(), 1);
    assert!(rule(&report)[0].evidence.starts_with("ref: refs/pull/"));
}

#[test]
fn gh_pr_checkout_and_script_execution_is_flagged() {
    let report = scan_fixture("gh-pr-checkout");
    let found = rule(&report);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].location, "jobs.test.steps[0].run");
    assert!(
        found[0]
            .evidence
            .starts_with("gh pr checkout; step 0 runs ./scripts/build.sh")
    );
}

#[test]
fn git_fetch_of_a_pull_ref_followed_by_cargo_is_flagged() {
    let report = scan_fixture("git-fetch-pull");
    let found = rule(&report);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].location, "jobs.test.steps[0].run");
    assert!(found[0].evidence.contains("git fetch"));
    assert!(found[0].evidence.contains("step 2 runs cargo"));
}

#[test]
fn local_action_after_head_checkout_is_flagged() {
    let report = scan_fixture("local-action-after-head");
    let found = rule(&report);
    assert_eq!(found.len(), 1);
    assert!(
        found[0]
            .evidence
            .contains("local action ./.github/actions/setup")
    );
}

#[test]
fn jobs_do_not_share_a_workspace() {
    let report = scan_fixture("separate-jobs");
    assert!(rule(&report).is_empty());
    assert_eq!(report.status, ScanStatus::Clean);
}

#[test]
fn the_same_steps_under_pull_request_are_not_flagged() {
    let report = scan_fixture("pull-request-trigger");
    assert_eq!(report.status, ScanStatus::Clean);
}

#[test]
fn workflow_run_is_not_analyzed_yet() {
    // Documented false negative: workflow_run has a similar risk but this rule
    // only analyzes pull_request_target. If workflow_run support is added, this
    // test must change together with the documentation.
    let report = scan_fixture("workflow-run-not-analyzed");
    assert!(rule(&report).is_empty());
    assert_eq!(report.status, ScanStatus::Clean);
}

#[test]
fn unresolvable_checkout_ref_is_an_analysis_limit() {
    let report = scan_fixture("dynamic-ref");
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(report.incomplete[0].kind, IncompleteKind::AnalysisLimit);
    assert!(report.incomplete[0].detail.contains("matrix.ref"));
}

#[test]
fn unrecognized_command_after_head_checkout_is_an_analysis_limit() {
    let report = scan_fixture("unknown-command");
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert!(rule(&report).is_empty());
    assert!(report.incomplete[0].detail.contains("frobnicate"));
}

#[test]
fn comments_names_and_quoted_text_are_not_flagged() {
    let report = scan_fixture("misleading-text");
    assert_eq!(report.status, ScanStatus::Clean, "{:#?}", report);
}

#[test]
fn trigger_forms_are_all_recognized() {
    let steps = format!(
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA}\n        with: {{ref: '${{{{ github.head_ref }}}}'}}\n      - run: make\n"
    );
    for on in [
        "on: pull_request_target\n",
        "on: [push, pull_request_target]\n",
        "on:\n  push:\n  pull_request_target:\n    branches: [main]\n",
        "'on': {pull_request_target: {}}\n",
        "on: PULL_REQUEST_TARGET\n",
    ] {
        let report = scan_text(&format!("{on}{steps}"));
        assert_eq!(rule(&report).len(), 1, "{on}");
    }
    for on in [
        "on: push\n",
        "on: [push, pull_request]\n",
        "on:\n  workflow_dispatch:\n",
    ] {
        let report = scan_text(&format!("{on}{steps}"));
        assert!(rule(&report).is_empty(), "{on}");
    }
}

#[test]
fn alias_for_the_trigger_list_is_incomplete() {
    let report = scan_text(&format!(
        "x: &t [pull_request_target]\non: *t\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA}\n"
    ));
    assert_eq!(report.status, ScanStatus::Incomplete);
}

#[test]
fn execution_before_the_checkout_does_not_count() {
    let report = scan_text(&format!(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - run: npm --version\n      - uses: actions/checkout@{SHA}\n        with:\n          ref: ${{{{ github.event.pull_request.head.sha }}}}\n      - run: ls\n"
    ));
    assert!(rule(&report).is_empty());
    assert_eq!(report.status, ScanStatus::Clean);
}

#[test]
fn checkout_and_execution_in_one_script_are_ordered() {
    let flagged = scan_text(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - run: gh pr checkout 5 && make\n",
    );
    assert_eq!(rule(&flagged).len(), 1);
    let before = scan_text(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - run: make && gh pr checkout 5\n",
    );
    assert!(rule(&before).is_empty());
}

#[test]
fn flow_style_and_aliased_checkout_inputs_are_handled() {
    let report = scan_text(&format!(
        "on: pull_request_target\nx-ref: &r ${{{{ github.event.pull_request.head.sha }}}}\njobs: {{a: {{steps: [{{uses: 'actions/checkout@{SHA}', with: {{ref: *r}}}}, {{run: npm test}}]}}}}\n"
    ));
    let found = rule(&report);
    assert_eq!(found.len(), 1);
    assert!(
        found[0]
            .evidence
            .contains("(alias; value defined on line 2)"),
        "{}",
        found[0].evidence
    );
}

#[test]
fn checkout_name_matching_is_case_insensitive_but_exact() {
    let upper = scan_text(&format!(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: Actions/Checkout@{SHA}\n        with: {{ref: '${{{{ github.head_ref }}}}'}}\n      - run: make\n"
    ));
    assert_eq!(rule(&upper).len(), 1);
    let other = scan_text(&format!(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout-fork@{SHA}\n        with: {{ref: '${{{{ github.head_ref }}}}'}}\n      - run: make\n"
    ));
    assert!(rule(&other).is_empty());
}

#[test]
fn reusable_workflow_jobs_without_steps_are_skipped() {
    let report = scan_text(&format!(
        "on: pull_request_target\njobs:\n  call:\n    uses: owner/repo/.github/workflows/x.yml@{SHA}\n"
    ));
    assert_eq!(report.status, ScanStatus::Clean);
}

#[test]
fn evidence_does_not_leak_neighboring_text() {
    let report = scan_text(&format!(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA} # SECRET_COMMENT_MARKER\n        with:\n          ref: ${{{{ github.head_ref }}}}\n          token: SECRET_TOKEN_MARKER\n      - run: |\n          make --token SECRET_ARG_MARKER\n"
    ));
    assert_eq!(rule(&report).len(), 1);
    let json = report.to_json();
    assert!(!json.contains("SECRET_"), "{json}");
}

#[test]
fn reports_are_deterministic() {
    let a = scan_fixture("fork-repository");
    let b = scan_fixture("fork-repository");
    assert_eq!(a.to_json(), b.to_json());
}
