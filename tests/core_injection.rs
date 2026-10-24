//! Behavior of rule ML-GHA-003 (attacker-controllable values in `run:` scripts).
//! All inputs are harmless text; nothing here is ever executed.

use std::fs;
use std::path::{Path, PathBuf};

use mergelatch_core::{
    Finding, IncompleteKind, RULE_SCRIPT_INJECTION, Report, ScanLimits, ScanStatus, Severity,
    scan_directory,
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/gha-injection")
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

fn summary(report: &Report) -> Vec<(&str, usize, &str)> {
    report
        .findings
        .iter()
        .map(|f: &Finding| (f.location.as_str(), f.line.unwrap(), f.evidence.as_str()))
        .collect()
}

#[test]
fn direct_interpolation_is_flagged_at_the_expression_line() {
    let report = scan_fixture("direct-title");
    assert_eq!(report.status, ScanStatus::Findings);
    assert_eq!(report.findings.len(), 1);
    let f = &report.findings[0];
    assert_eq!(f.rule_id, RULE_SCRIPT_INJECTION);
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.location, "jobs.greet.steps[0].run");
    assert_eq!(f.line, Some(12), "line of the expression inside the block");
    assert_eq!(f.evidence, "${{ github.event.pull_request.title }}");
    assert!(f.message.contains("github.event.pull_request.title"));
    assert!(f.message.contains("depends on the workflow's trigger"));
    assert!(f.remediation.contains("environment variable"));
    assert!(f.remediation.contains("Quoting"));
}

#[test]
fn evidence_is_the_expression_only() {
    let report = scan_fixture("direct-title");
    let f = &report.findings[0];
    assert!(!f.evidence.contains("echo"));
    assert!(!f.evidence.contains("Title:"));
}

#[test]
fn passing_the_value_through_env_is_not_flagged() {
    let report = scan_fixture("env-safe");
    assert_eq!(report.status, ScanStatus::Clean, "{:#?}", report.findings);
}

#[test]
fn many_sources_in_single_line_and_multiline_scripts() {
    let report = scan_fixture("many-sources");
    assert_eq!(
        summary(&report),
        [
            ("jobs.a.steps[0].run", 7, "${{ github.event.issue.body }}"),
            ("jobs.a.steps[0].run", 7, "${{ github.event.issue.title }}"),
            ("jobs.a.steps[1].run", 9, "${{ github.head_ref }}"),
            (
                "jobs.a.steps[1].run",
                10,
                "${{ github.event.comment.body }}"
            ),
            (
                "jobs.a.steps[1].run",
                11,
                "${{ github.event.commits[0].message }}"
            ),
            (
                "jobs.a.steps[1].run",
                11,
                "${{ github.event.head_commit.message }}"
            ),
            (
                "jobs.b.steps[0].run",
                15,
                "${{ github.event.pull_request.head.ref }}"
            ),
        ]
    );
}

#[test]
fn equivalent_context_syntax_is_recognized() {
    let report = scan_fixture("context-syntax-variants");
    assert_eq!(report.findings.len(), 6, "{:#?}", summary(&report));
    let whole = report
        .findings
        .iter()
        .find(|f| f.evidence.contains("toJSON"))
        .unwrap();
    assert!(whole.message.contains("an object that includes"));
}

#[test]
fn harmless_context_values_are_not_flagged() {
    let report = scan_fixture("harmless-values");
    assert_eq!(report.status, ScanStatus::Clean, "{:#?}", report.findings);
}

#[test]
fn boolean_only_expressions_are_not_flagged() {
    let report = scan_fixture("boolean-only");
    assert_eq!(report.status, ScanStatus::Clean, "{:#?}", report.findings);
}

#[test]
fn comments_names_env_and_other_keys_are_not_flagged() {
    // The `script:` input of actions/github-script is also not analyzed. That
    // is a documented limitation, so it appears here as an accepted false negative.
    let report = scan_fixture("misleading-text");
    assert_eq!(report.status, ScanStatus::Clean, "{:#?}", report.findings);
}

#[test]
fn an_expression_inside_a_shell_comment_is_still_expanded_and_flagged() {
    // GitHub substitutes expressions before the shell parses the script, so a
    // `#` comment does not protect against a value that contains a newline.
    let report = scan_text(
        "on: push\njobs:\n  a:\n    steps:\n      - run: |\n          # ${{ github.head_ref }}\n          echo ok\n",
    );
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].line, Some(6));
}

#[test]
fn computed_property_access_is_an_analysis_limit() {
    let report = scan_fixture("computed-access");
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(report.incomplete[0].kind, IncompleteKind::AnalysisLimit);
    assert!(
        report.incomplete[0]
            .detail
            .contains("computed property access")
    );
}

#[test]
fn computed_access_on_an_unrelated_object_is_not_a_limit() {
    let report =
        scan_text("on: push\njobs:\n  a:\n    steps:\n      - run: echo ${{ matrix[inputs.k] }}\n");
    assert_eq!(report.status, ScanStatus::Clean);
}

#[test]
fn unterminated_expression_is_an_analysis_limit() {
    let report = scan_fixture("unterminated");
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(report.incomplete[0].kind, IncompleteKind::AnalysisLimit);
}

#[test]
fn braces_inside_string_literals_do_not_end_the_expression() {
    let report = scan_text(
        "on: push\njobs:\n  a:\n    steps:\n      - run: echo ${{ format('}} {0}', github.head_ref) }}\n",
    );
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn quoting_around_the_expression_does_not_make_it_safe() {
    let report = scan_text(
        "on: push\njobs:\n  a:\n    steps:\n      - run: |\n          echo \"${{ github.head_ref }}\"\n          echo '${{ github.head_ref }}'\n",
    );
    assert_eq!(report.findings.len(), 2);
}

#[test]
fn flow_style_step_and_plain_multiline_run_use_the_scalar_line() {
    let flow = scan_text("on: push\njobs: {a: {steps: [{run: 'echo ${{ github.head_ref }}'}]}}\n");
    assert_eq!(flow.findings.len(), 1);
    assert_eq!(flow.findings[0].location, "jobs.a.steps[0].run");

    let folded = scan_text(
        "on: push\njobs:\n  a:\n    steps:\n      - run: >\n          echo one\n          echo ${{ github.head_ref }}\n",
    );
    assert_eq!(folded.findings.len(), 1);
    assert!(folded.findings[0].line.is_some());
}

#[test]
fn aliased_run_script_is_reported_at_the_use_site() {
    let report = scan_text(
        "on: push\nx-run: &r echo ${{ github.head_ref }}\njobs:\n  a:\n    steps:\n      - run: *r\n",
    );
    assert_eq!(report.findings.len(), 1);
    let f = &report.findings[0];
    assert_eq!(f.line, Some(6));
    assert!(
        f.evidence.ends_with("(alias; value defined on line 2)"),
        "{}",
        f.evidence
    );
}

#[test]
fn non_string_run_and_aliased_steps_are_incomplete() {
    let seq = scan_text("on: push\njobs:\n  a:\n    steps:\n      - run: [echo, hi]\n");
    assert_eq!(seq.status, ScanStatus::Incomplete);
    let alias = scan_text(
        "on: push\nx: &s {run: 'echo ${{ github.head_ref }}'}\njobs:\n  a:\n    steps:\n      - *x\n",
    );
    assert_eq!(alias.status, ScanStatus::Incomplete);
    assert!(alias.findings.is_empty());
}

#[test]
fn duplicate_run_keys_cannot_hide_an_injection() {
    let report = scan_text(
        "on: push\njobs:\n  a:\n    steps:\n      - run: echo safe\n        run: echo ${{ github.head_ref }}\n",
    );
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn secret_like_text_near_an_expression_is_not_copied() {
    let report = scan_text(
        "on: push\njobs:\n  a:\n    steps:\n      - run: |\n          curl -H 'Authorization: SECRET_LINE_MARKER' ${{ github.head_ref }} # SECRET_TAIL_MARKER\n        env: {T: SECRET_ENV_MARKER}\n",
    );
    assert_eq!(report.findings.len(), 1);
    assert!(
        !report.to_json().contains("SECRET_"),
        "{}",
        report.to_json()
    );
}

#[test]
fn reports_are_deterministic() {
    let a = scan_fixture("many-sources");
    let b = scan_fixture("many-sources");
    assert_eq!(a.to_json(), b.to_json());
}
