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

// ---- Checkout repository and ref trust ---------------------------------------

/// A pull_request_target workflow with one checkout configured by `with`
/// lines, followed by a build step.
fn checkout(with: &str) -> Report {
    scan_text(&format!(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA}\n        with:\n{with}      - run: npm test\n"
    ))
}

fn gap_details(report: &Report) -> String {
    report
        .incomplete
        .iter()
        .map(|i| i.detail.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn literal_external_repository_is_not_assumed_to_be_the_base_repository() {
    let report = checkout("          repository: some-owner/some-repo\n");
    assert!(rule(&report).is_empty());
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(report.incomplete[0].kind, IncompleteKind::AnalysisLimit);
    assert!(
        gap_details(&report).contains("literal repository"),
        "{}",
        gap_details(&report)
    );
    assert!(gap_details(&report).contains("with.repository"));
}

#[test]
fn expressions_naming_the_workflows_own_repository_are_trusted() {
    for value in [
        "${{ github.repository }}",
        "${{ github.event.repository.full_name }}",
        "${{ github.event.pull_request.base.repo.full_name }}",
        "${{GITHUB.REPOSITORY}}",
    ] {
        let report = checkout(&format!("          repository: {value}\n"));
        assert_eq!(report.status, ScanStatus::Clean, "{value}: {:#?}", report);
    }
}

#[test]
fn no_repository_input_means_the_base_repository() {
    let report = checkout("          fetch-depth: 0\n");
    assert_eq!(report.status, ScanStatus::Clean);
}

#[test]
fn pull_request_head_repository_is_flagged_in_every_spelling() {
    for value in [
        "${{ github.event.pull_request.head.repo.full_name }}",
        "${{ github.event.pull_request.head.repo.clone_url }}",
        "${{ github['event']['pull_request']['head']['repo']['full_name'] }}",
        "${{ github.event.pull_request.head.repo.full_name }}-suffix",
    ] {
        let report = checkout(&format!("          repository: {value}\n"));
        let found = rule(&report);
        assert_eq!(found.len(), 1, "{value}");
        assert!(found[0].location.ends_with(".with.repository"));
        assert!(found[0].evidence.starts_with("repository: "));
    }
}

#[test]
fn dynamic_or_ambiguous_repository_values_are_analysis_limits() {
    for value in [
        "${{ matrix.repo }}",
        "${{ inputs.repository }}",
        "${{ env.REPO }}",
        "${{ vars.UPSTREAM }}",
        "${{ github.repository_owner }}/tools",
        "${{ github.repository }}-fork",
        "${{ github.event[matrix.key] }}",
        "${{ github.repository || 'owner/repo' }}",
        "''",
        "${{ github.repository",
    ] {
        let report = checkout(&format!("          repository: {value}\n"));
        assert_eq!(report.status, ScanStatus::Incomplete, "{value}");
        assert_eq!(
            report.incomplete[0].kind,
            IncompleteKind::AnalysisLimit,
            "{value}"
        );
        assert!(rule(&report).is_empty(), "{value}");
    }
}

#[test]
fn repository_text_is_not_copied_into_a_limit_message_unboundedly() {
    let report = checkout("          repository: owner/SECRET_REPO_MARKER\n");
    // The location and reason are reported; the literal value is not repeated.
    assert!(!report.to_json().contains("SECRET_REPO_MARKER"));
}

#[test]
fn literal_branch_refs_stay_trusted_and_pull_refs_are_flagged() {
    assert_eq!(checkout("          ref: main\n").status, ScanStatus::Clean);
    assert_eq!(
        checkout("          ref: refs/heads/release\n").status,
        ScanStatus::Clean
    );
    for value in [
        "refs/pull/5/head",
        "refs/pull/5/merge",
        "pull/5/head",
        "pull/5/merge",
    ] {
        let report = checkout(&format!("          ref: {value}\n"));
        assert_eq!(rule(&report).len(), 1, "{value}");
    }
    assert_eq!(
        checkout("          ref: ''\n").status,
        ScanStatus::Incomplete
    );
}

#[test]
fn trusted_repository_with_head_ref_is_flagged_at_the_ref() {
    let report = checkout(
        "          repository: ${{ github.repository }}\n          ref: ${{ github.event.pull_request.head.sha }}\n",
    );
    let found = rule(&report);
    assert_eq!(found.len(), 1);
    assert!(found[0].location.ends_with(".with.ref"));
}

#[test]
fn unresolved_repository_with_head_ref_reports_both_the_finding_and_the_limit() {
    let report = checkout(
        "          repository: owner/other\n          ref: ${{ github.event.pull_request.head.sha }}\n",
    );
    assert_eq!(rule(&report).len(), 1);
    assert_eq!(report.status, ScanStatus::Incomplete);
}

// ---- Commands that look safe but can run programs ---------------------------

/// A head checkout followed by one `run:` line.
fn after_head_checkout(command: &str) -> Report {
    scan_text(&format!(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA}\n        with:\n          ref: ${{{{ github.event.pull_request.head.sha }}}}\n      - run: {command}\n"
    ))
}

#[test]
fn git_alias_execution_after_a_head_checkout_is_flagged() {
    // These were previously classified as safe because the command name was `git`.
    for command in [
        "\"git -c alias.t='!npm test' t\"",
        "\"git config alias.t '!make' && git t\"",
        "\"git rebase --exec make main\"",
        "\"git bisect run ./check\"",
        "\"git submodule foreach make\"",
    ] {
        let report = after_head_checkout(command);
        assert_eq!(rule(&report).len(), 1, "{command}: {:#?}", report);
    }
}

#[test]
fn other_programs_that_run_commands_are_flagged() {
    for command in [
        "\"sed 's/a/b/e' file\"",
        "\"awk 'BEGIN{system(\\\"make\\\")}'\"",
        "\"gh alias set t '!npm test'\"",
        "\"tar -xf a.tar --to-command=sh\"",
        "\"env -S 'npm test'\"",
    ] {
        let report = after_head_checkout(command);
        assert_eq!(rule(&report).len(), 1, "{command}: {:#?}", report);
    }
}

#[test]
fn ordinary_commands_after_a_head_checkout_stay_clean() {
    for command in [
        "\"git diff --stat origin/main...HEAD\"",
        "\"git log --oneline -n 5\"",
        "\"gh pr comment 1 --body ok\"",
        "\"sed -n '1,5p' README.md\"",
        "\"awk '{print $1}' README.md\"",
        "\"tar -cf out.tar README.md\"",
        "\"command -v npm\"",
    ] {
        let report = after_head_checkout(command);
        assert_eq!(report.status, ScanStatus::Clean, "{command}: {:#?}", report);
    }
}

#[test]
fn ambiguous_command_forms_after_a_head_checkout_are_analysis_limits() {
    for command in [
        "\"git mycommand\"",
        "\"sed -f script.sed file\"",
        "\"awk -f prog.awk file\"",
        "\"gh some-extension\"",
        "\"alias t='npm test'\"",
    ] {
        let report = after_head_checkout(command);
        assert_eq!(report.status, ScanStatus::Incomplete, "{command}");
        assert_eq!(
            report.incomplete[0].kind,
            IncompleteKind::AnalysisLimit,
            "{command}"
        );
        assert!(rule(&report).is_empty(), "{command}");
    }
}

#[test]
fn the_same_commands_before_any_pull_request_checkout_are_not_analyzed() {
    let report = scan_text(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - run: git -c alias.t='!npm test' t\n",
    );
    assert_eq!(report.status, ScanStatus::Clean);
}

// ---- Workspace state across several checkouts in one job ----------------------

fn job(steps: &str) -> Report {
    scan_text(&format!(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n{steps}"
    ))
}

fn head_checkout(extra: &str) -> String {
    format!(
        "      - uses: actions/checkout@{SHA}\n        with:\n          ref: ${{{{ github.event.pull_request.head.sha }}}}\n{extra}"
    )
}

fn base_checkout(extra: &str) -> String {
    format!("      - uses: actions/checkout@{SHA}\n{extra}")
}

#[test]
fn a_later_trusted_checkout_does_not_clear_an_earlier_untrusted_one() {
    // The base checkout may or may not remove the earlier files, depending on
    // the `path` and `clean` inputs. The rule does not assume it does.
    let report = job(&format!(
        "{}{}      - run: npm test\n",
        head_checkout(""),
        base_checkout("")
    ));
    assert_eq!(rule(&report).len(), 1, "{:#?}", report);
}

#[test]
fn a_trusted_checkout_followed_by_an_untrusted_one_is_flagged() {
    let report = job(&format!(
        "{}{}      - run: make\n",
        base_checkout(""),
        head_checkout("")
    ));
    let found = rule(&report);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].location, "jobs.a.steps[1].with.ref");
}

#[test]
fn execution_before_the_untrusted_checkout_is_not_attributed_to_it() {
    let report = job(&format!(
        "{}      - run: npm ci\n{}      - run: ls\n",
        base_checkout(""),
        head_checkout("")
    ));
    assert!(rule(&report).is_empty());
    assert_eq!(report.status, ScanStatus::Clean);
}

#[test]
fn a_checkout_into_another_directory_is_still_treated_as_present_in_the_workspace() {
    // `path: pr` puts the head code in a subdirectory, and the later command
    // may well run only in the trusted checkout. The rule cannot tell which
    // directory a command works in, so it reports. This is a known false positive.
    let report = job(&format!(
        "{}{}      - run: npm test\n",
        base_checkout(""),
        head_checkout("          path: pr\n")
    ));
    assert_eq!(rule(&report).len(), 1);
}

#[test]
fn working_directory_does_not_clear_the_finding() {
    let report = job(&format!(
        "{}      - run: npm test\n        working-directory: trusted\n",
        head_checkout("          path: pr\n")
    ));
    assert_eq!(rule(&report).len(), 1);
}

#[test]
fn several_untrusted_checkouts_give_one_finding_for_the_first() {
    let report = job(&format!(
        "{}{}      - run: npm ci\n      - run: npm test\n",
        head_checkout("          path: one\n"),
        head_checkout("          path: two\n"),
    ));
    let found = rule(&report);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].location, "jobs.a.steps[0].with.ref");
    assert!(found[0].message.contains("1 more step"));
}

#[test]
fn an_unresolved_checkout_alongside_an_untrusted_one_reports_both() {
    let report = job(&format!(
        "{}      - uses: actions/checkout@{SHA}\n        with:\n          repository: owner/other\n          path: other\n      - run: make\n",
        head_checkout("")
    ));
    assert_eq!(rule(&report).len(), 1);
    assert_eq!(report.status, ScanStatus::Incomplete);
}

#[test]
fn a_trusted_only_job_with_several_checkouts_is_clean() {
    let report = job(&format!(
        "{}{}      - run: npm test\n",
        base_checkout(""),
        base_checkout("        with:\n          path: again\n")
    ));
    assert_eq!(report.status, ScanStatus::Clean);
}

// ---- Global options before checkout commands, and here-documents ---------------

/// A trusted base checkout followed by one multi-line `run:` script. Any pull
/// request code must therefore come from the script itself.
fn base_then_script(script: &str) -> Report {
    let body: String = script.lines().map(|l| format!("          {l}\n")).collect();
    scan_text(&format!(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA}\n      - run: |\n{body}"
    ))
}

/// An untrusted head checkout followed by one multi-line `run:` script.
fn head_then_script(script: &str) -> Report {
    let body: String = script.lines().map(|l| format!("          {l}\n")).collect();
    scan_text(&format!(
        "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA}\n        with:\n          ref: ${{{{ github.event.pull_request.head.sha }}}}\n      - run: |\n{body}"
    ))
}

#[test]
fn a_here_document_marker_inside_quotes_does_not_hide_later_commands() {
    // The quoted text is not a here-document, so `npm test` still runs.
    for script in [
        "echo \"<<NOT_A_HEREDOC\"\nnpm test",
        "echo '<<NOT_A_HEREDOC'\nnpm test",
        "echo \"<<X\"\ngh pr checkout 12\nnpm test",
        "# cat <<EOF\nnpm test",
        "echo hi # <<EOF\nnpm test",
        "echo \\<<EOF\nnpm test",
    ] {
        let report = head_then_script(script);
        assert_eq!(rule(&report).len(), 1, "{script}: {:#?}", report);
    }
    let report = base_then_script("echo \"<<X\"\ngh pr checkout 12\nnpm test");
    assert_eq!(rule(&report).len(), 1);
}

#[test]
fn real_here_document_bodies_are_data_and_commands_after_them_are_not() {
    let clean = head_then_script("cat <<EOF\nnpm test\nmake\nEOF\necho done");
    assert_eq!(clean.status, ScanStatus::Clean, "{:#?}", clean);

    for script in [
        "cat <<EOF\ntext\nEOF\nnpm test",
        "cat <<'EOF'\ntext\nEOF\nnpm test",
        "cat <<\"EOF\"\ntext\nEOF\nnpm test",
        "cat <<\\EOF\ntext\nEOF\nnpm test",
        "cat <<-EOF\n\ttext\n\tEOF\nnpm test",
        "cat <<A <<B\nfirst\nA\nsecond\nB\nnpm test",
        "cat <<EOF | tee out\ntext\nEOF\nnpm test",
    ] {
        let report = head_then_script(script);
        assert_eq!(rule(&report).len(), 1, "{script}: {:#?}", report);
    }
}

#[test]
fn a_here_string_is_not_a_here_document() {
    let report = head_then_script("cat <<< \"text\"\nnpm test");
    assert_eq!(rule(&report).len(), 1);
}

#[test]
fn a_here_document_without_a_terminator_is_an_analysis_limit_and_is_not_skipped() {
    let report = head_then_script("cat <<EOF\ntext\nnpm test");
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert!(
        report
            .incomplete
            .iter()
            .any(|i| i.detail.contains("here-document")),
        "{:#?}",
        report.incomplete
    );
    // The lines after the marker were still analyzed.
    assert_eq!(rule(&report).len(), 1);
}

#[test]
fn a_command_fed_by_a_here_document_is_still_classified() {
    let report = head_then_script("bash <<EOF\nnpm test\nEOF");
    assert_eq!(rule(&report).len(), 1);
}
