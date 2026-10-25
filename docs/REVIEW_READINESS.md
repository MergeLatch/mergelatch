# Security review readiness: advisory GitHub Action

**Date prepared:** 2026-10-24. **Recommendation:** conditionally ready to hand to an independent reviewer; **not ready for a release candidate tag** until the blockers in [Outstanding release blockers](#outstanding-release-blockers) are closed. **Independent human sign-off: pending.**

This document prepares MergeLatch's first advisory GitHub Action for independent security review. It records what is being asked to be reviewed, what was checked, what was found, and what has not been checked.

**Provenance of this analysis.** It was produced by an AI coding agent (Claude Code) working for the maintainer, who also directed the earlier implementation. It is a preliminary technical review by the same author side, not an independent review and not human approval. Findings that were not found here are not shown to be absent. Nothing in this document certifies the Action as secure.

## Contents

1. [Reviewed source](#reviewed-source)
2. [Scope](#scope)
3. [Trust boundaries](#trust-boundaries)
4. [Threat assumptions](#threat-assumptions)
5. [Security controls implemented](#security-controls-implemented)
6. [Known limitations](#known-limitations)
7. [Verification evidence](#verification-evidence)
8. [What this audit covered and did not cover](#what-this-audit-covered-and-did-not-cover)
9. [Audit findings and dispositions](#audit-findings-and-dispositions)
10. [Dependency and build risks](#dependency-and-build-risks)
11. [Outstanding release blockers](#outstanding-release-blockers)
12. [Reviewer checklist](#reviewer-checklist)
13. [Release recommendation](#release-recommendation)
14. [Sign-off](#sign-off)

## Reviewed source

| Item | Value |
| --- | --- |
| Repository | https://github.com/MergeLatch/mergelatch |
| Implementation commit that was run as a pinned Action | `afc7e65d6723029c22935f82c7fc9562d5831565` (merge commit of pull request #9) |
| `main` when this review was prepared | `4af8f9aa9340fee38abb7c9f3b554c53ad645d64` (merge commit of pull request #10) |
| Relationship | Every implementation path has the same git object ID in both commits. Only workflows, tests, and documentation differ. This is identity of files, not a new test of the newer SHA |

Object IDs of the implementation paths, identical at both commits (`git rev-parse <commit>:<path>`):

| Path | Git object ID |
| --- | --- |
| `action.yml` | `d8a00d9deab8dc02834a775eb190632de6c60d36` |
| `action/mergelatch_action.py` | `8ca73271791ac038225d88d75d9be8fc9e1744fc` |
| `action/build.sh` | `b8cb2ab8bd0953d7c1a554843bd19354b34cad53` |
| `Cargo.toml` | `0773c99973e285c8ab4f6c792c3fc48032d705e0` |
| `Cargo.lock` | `8c3be7c77eb89871f46a76c610a227c35fe08dfa` |
| `rust-toolchain.toml` | `58eef2ccd48f957feeada49b17ad1e3fd667bf8c` |
| `crates/` (tree) | `83aa9f02a753b9fae97de84d11dc6c6c3fd44bb5` |

A reviewer should recompute these rather than trust this table. The documentation commits of the review-readiness change add only files outside these paths, plus one test file (`action/tests/test_real_scanner.py`), which is not part of what runs in a consumer's job.

## Scope

**In scope (the trusted computing base of a consumer's job):**

- `action.yml`, `action/mergelatch_action.py`, `action/build.sh`
- `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`
- The Rust scanner: `crates/core` (discovery, confined filesystem access, YAML layer, rules, report) and `crates/cli`
- The dependencies and toolchain that the build downloads
- The example consumer workflow `docs/examples/pull-request-scan.yml`, because it is what consumers copy

**Also reviewed because they hold or exercise the above:**

- `.github/workflows/*.yml` (this repository's CI and trials; they are not part of what a consumer runs)
- `action/tests/` and the Rust tests, as evidence of what is checked

**Out of scope:**

- Windows Sentinel, Agent Guard, dependency or malware scanning, merge enforcement. None of them exist
- GitHub itself, the runner image, `actions/checkout`, rustup, the Rust distribution servers, crates.io
- Anything about a consumer's own workflow beyond the guidance in the example

## Trust boundaries

```
 GitHub
  |  pull_request event; runner context (github.sha, github.action_ref, ...)   TRUSTED, supplied by GitHub
  v
 Consumer job (ubuntu-24.04, GitHub-hosted, contents: read, no secrets)
  |
  |-- actions/checkout @ pinned SHA ------------> workspace: pull request content      UNTRUSTED (data)
  |
  `-- MergeLatch/mergelatch @ pinned SHA --------> _actions/.../<sha>/                  TRUSTED (pinned code)
        1 prepare  python3 -I   validate runner, event, inputs, checkout
        2 build    python3 -I -> bash build.sh -> rustup, cargo --locked      <-- downloads: static.rust-lang.org, crates.io
        3 scan     python3 -I -> mergelatch scan --format json <workspace dir>   (minimal fixed environment)
        4 report   python3 -I   validate JSON, escape, write outputs + summary

 The scanned directory is only ever a path argument to the finished scanner.
 The caller's workflow file is NOT inside the boundary: the pull request can edit it.
```

| | Trusted | Untrusted |
| --- | --- | --- |
| Code that runs | The Action checkout at the pinned SHA, the downloaded toolchain and locked crates, the runner's system Python and bash, `~/.cargo/bin` | Nothing from the pull request |
| Data that is read | GitHub context values (validated by pattern before use) | Workflow files in the scanned directory, their names and contents, the scanner's report derived from them, `.git` files in the checkout |

## Threat assumptions

The review assumes:

1. **The contributor** can change any file in their pull request, including the caller's workflow, file names, symlinks, and the contents of workflow files. They cannot change the Action's pinned code, the runner image, or repository settings, and cannot read secrets (none are present).
2. **The workflow author** (a maintainer or someone with write access) is trusted to write a sound workflow: they set the Action's SHA, the permissions, and the steps around it. The Action defends against honest misconfiguration (inherited `BASH_ENV`, `CARGO_HOME`, `LD_PRELOAD`) but not against a workflow author who wants it to lie.
3. **GitHub, the runner image, `actions/checkout`, rustup, the Rust distribution servers, and crates.io** behave as documented and are not compromised.
4. **A job runs the Action before any step that executes pull request content.** Otherwise the same-user code could alter the runner's files and the Action's state.
5. **The scanner is advisory.** No decision depends on its result without a human.

Not assumed: that the Action blocks anything, that a green check means a pull request is safe, or that the rules find every attack.

## Security controls implemented

| Control | Where | Evidence |
| --- | --- | --- |
| Trusted code is separated from scanned content. The scanner is built from the Action's own checkout; the scanned directory is a path argument | `action/build.sh`, `prepare`/`scan` in the helper | `scanner-source=action-checkout` asserted on GitHub; mocked and simulated tests |
| No step runs under bash; every step is `/usr/bin/python3 -I` | `action.yml` | Static tests; GitHub run with a hostile `BASH_ENV` and a bash positive control |
| Child processes get an environment built from fixed values; `HOME` from the account database | `trusted_environment` | Tests including real `cargo`, `rustup`, compiler; GitHub run with hostile settings |
| `LD_*` and `GCONV_PATH` cause a hard failure | `check_inherited_environment` | Unit tests; GitHub run that must fail |
| Only GitHub-hosted Ubuntu x86-64 Linux runners | `check_runner` | Unit tests |
| Only `pull_request` is accepted; all other event names fail preparation (decision D-1, implemented after the review; not in `afc7e65…`) | `prepare`, `SUPPORTED_EVENTS` | Tests that follow 26 event values through prepare, scan and report. Not run on GitHub. See finding F-01 |
| `scan-directory` must be relative, free of `..`, resolve inside the workspace, and exist; a missing `.git` is an error | `resolve_scan_directory`, `prepare` | Unit tests |
| Scanner opens files relative to a directory handle with `cap-std`; symlinks, pipes, and devices are not followed or read | `crates/core/src/discover.rs`, `fsaccess.rs` | Deterministic swap tests and concurrent stress tests (Linux) |
| The scanner never runs scanned content, Git, or the network | `crates/` | Safety tests with inert fixtures |
| Report validation: schema, enums, counts, status/list consistency, size cap, duplicate keys, non-standard numbers | `parse_report` | Unit tests; oversize and truncation tests |
| Exit code must match the report; any unknown exit, timeout, or crash is `error` | `evaluate` | Unit tests |
| Fail closed: scan error, wrong revision, untrusted report, build failure all fail the step | `evaluate`, `report_command` | Unit tests, GitHub negative runs |
| Output values restricted to a token pattern; summary text escaped; nothing from the report in the log | `write_output`, `md`, `report_command` | Unit tests with hostile strings |
| Revision check compares the checkout's recorded commit with the trusted event context | `check_revision` | Unit tests; GitHub runs for `matches-merge`, `matches-head`, `mismatch` |
| Scanner time limit (30 s detected), helper timeout (300 s scan, 1500 s build), output size limit (16 MiB file size) | scanner, helper | Unit tests with fakes |
| Workflows: read-only token, no secrets, SHA-pinned external Actions, `persist-credentials: false`, no privileged triggers | `.github/workflows/` | Static tests |
| Full pinned SHA is shown in the rendered summary (a code span, because GitHub shortens it in ordinary text) | `_action_revision_label` | Browser inspection of the rendered summary on GitHub |

## Known limitations

These are accepted design limits, documented in [ACTION.md](ACTION.md) and the [threat model](THREAT_MODEL.md):

- **Advisory, not enforcement.** A pull request edits the caller's workflow and can remove or neutralize the step. SHA pinning protects the Action's code, not the caller's workflow. Findings and incomplete scans leave the step green.
- **Narrow detection.** Four rules, on `.github/workflows/*.yml|yaml` at the root of the scanned directory only. No malware scanning, no source or diff analysis. A clean result is not proof of safety.
- **Linux x86-64 GitHub-hosted only.** Windows and macOS are refused. The `cap-std` fallback for kernels without `openat2` is untested.
- **The toolchain download and locked crates are trusted** and are built on the runner for every job.
- **Revision check** reads the commit from the scanned directory's `.git`, or from the workspace root's detached `HEAD` for a subdirectory; on a `pull_request` an unreadable commit or missing expected commits is an error (D-2, implemented on a branch, not yet verified as a pinned Action). It checks the commit and not the files, and is not an identity.
- **Detection, not neutralization,** for loader variables, and unknown settings that affect the already-running Python are not enumerated.
- **Escaping cannot stop look-alike (confusable) characters** from misleading a reader.
- **The runner's own files** (`~/.cargo`, `~/.rustup`, system Python and bash) and the files that carry state between steps are trusted; a prior step that runs pull request code can change them.
- Windows Sentinel and Agent Guard are not implemented. There is no official published release.

## Verification evidence

### GitHub-hosted runs

| What | Run | Result |
| --- | --- | --- |
| In-repository SHA-pinned trial of `afc7e65…`, first run, rendered summary inspected | [40096959695](https://github.com/MergeLatch/mergelatch/actions/runs/40096959695) | success |
| Same trial on the final head of pull request #10 | [40097235383](https://github.com/MergeLatch/mergelatch/actions/runs/40097235383) | success |
| Action checks (lint, unit tests, smoke test with `uses: ./`) on that head | [40097235333](https://github.com/MergeLatch/mergelatch/actions/runs/40097235333) | success |
| Rust checks (`fmt, clippy, test`, the required check) on that head | [40097235402](https://github.com/MergeLatch/mergelatch/actions/runs/40097235402) | success |
| Separate consumer repository, pinned `afc7e65…` | [40099476256](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40099476256) | success |
| First-time external fork pull request, after maintainer approval (attempt 2; attempt 1 was `action_required`) | [40100818227](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40100818227) | success |

Evidence for the **corrected implementation** `2a1a514…` (strict event allowlist, D-1). The rows above tested `afc7e65…` and are kept as history:

| What | Run | Result |
| --- | --- | --- |
| In-repository trial pinned at `2a1a514…`, rendered summaries inspected | [40106718920](https://github.com/MergeLatch/mergelatch/actions/runs/40106718920) | success |
| Separate consumer repository pinned at `2a1a514…` (consumer PR #3, not merged) | [40106918299](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40106918299) | success |
| `workflow_dispatch` rejected-event test: the Action step failed as intended and the assertion job passed (consumer PR #4 workflow, dispatched by the maintainer) | [40108606160](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40108606160) | success |
| First-time external fork PR #6 against `2a1a514b94754b146a690cf98ef59bc649d423ff`, README-only edit, approved by maintainer after `action_required`; closed unmerged | [40112702817](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40112702817) (attempt 2) | success: full pinned SHA, `action-checkout`, `matches-merge`, clean repository, one fixture finding, one incomplete fixture |

D-2 fail-closed revision evidence for the **new** pinned Action implementation `95bad26bc731caa913861e95f75bf2c4de3dc6b4` (merged PR #18), separate from D-1 history:

| What | Run | Result |
| --- | --- | --- |
| Source SHA-pinned trial (PR #19, merged) | [40119258974](https://github.com/MergeLatch/mergelatch/actions/runs/40119258974) | Success. Full pinned SHA downloaded; downloaded file SHA-256 assertions passed; clean, findings, incomplete, merge/head, stale, hostile settings, and deliberately unverified nested revisions behaved as asserted |
| Separate SHA-pinned consumer trial (consumer PR #7, merged) | [40120225597](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40120225597) | Success. Two deliberately unverifiable nested checkout steps **failed** with `error`/`unavailable` and blank scanned revisions; the finding count remained one; normal fixture subdirectories matched the merge SHA |
| New D-2 fork run | Not performed | Earlier README-only fork trial used D-1 |
| Independent qualified human review | Pending | Maintainer-led tests do not count as independent sign-off |

The D-2 logs and test assertions were inspected; the rendered job summaries were not separately viewed in a browser.

### F-08 SHA-pinned GitHub verification (`c5296cef5fd3ffc36f1b8f0649e6491050606275`)

| What | Run | Result |
| --- | --- | --- |
| Source pinned Action in merged PR #22 | [40125146676](https://github.com/MergeLatch/mergelatch/actions/runs/40125146676) | **Success**. SHA-pinned download and helper hash verified; two-second fake Cargo timeout stopped child and grandchild and reaped the script; normal exit codes, early-error cleanup, and D-2 tests passed |
| External consumer in merged consumer PR #8 | [40126418768](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40126418768) | **Success**. Same pinned SHA and hash; fake timeout and early-failure cleanup probes, and D-2 negative tests passed |
| Failed consumer first attempt | [40126234617](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40126234617) | **Failed test harness:** copied fake PID marker used `$` instead of `$$`. Corrected by consumer commit `dab002e`, then the final run above passed |
| Rendered summaries, F-08 fork and independent human review | Not visually inspected / not performed / pending | These are maintainer-led verification results, not release or enforcement approval |


The checks for the review-readiness pull request itself appear on that pull request and are reported with it; they run the implementation as `uses: ./` and are therefore not tests of a pinned Action.

### Local checks (2026-10-24, this machine, Linux x86-64, Rust 1.99.1)

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | clean |
| `cargo test --workspace --locked` | 266 passed, 0 failed |
| `cargo audit --deny warnings` | exit 0 (78 lock entries, 1,352 advisories loaded) |
| Python Action tests (`MERGELATCH_TEST_BIN` set to the release binary) | 139 passed, 0 failed (138 before this change; one regression test added) |
| `actionlint` 1.7.12 on all workflows and the example | clean |
| `shellcheck` 0.11.0 on `action/build.sh` | clean |

These are local results. The GitHub-hosted counterparts are the runs above. `cargo audit` was run only locally.

### Reproductions made for this review

Black-box checks against the release binary and the real helper (inert files only, every command under a timeout):

- **Event names (before D-1).** `prepare` was run on 17 event names. Only `pull_request_target` and `workflow_run` were refused (finding F-01).
- **Revision check.** The repository root reports `matches-merge`; a subdirectory of the same repository reports `unavailable` and a clean status (F-02).
- **Report size.** One 370 KB workflow with 10,000 unpinned steps produced a 9.5 MB report. The helper turned it into `error` (F-03). Fixed in the scanner: the same input now gives a 0.9 MB `incomplete` report (D-3, below).
- **Pathological input.** Fourteen stress workflows (20,000-deep command substitution, brace and expression nesting; quote storms; 5,000 heredocs; 60,000-long `&&` and pipe chains; 10,000 steps; 5,000 jobs) and eight YAML files (60,000 keys, a 1 MB scalar, 60,000 alias uses, nested collection aliases, an 80,000-entry flow map, nesting at the depth limit, 30,000 tagged values). Every scan finished in at most 0.33 s. For the YAML set, peak memory was at most about 20 MB (memory was not measured for the first set). The 30,000-tag file exceeded the 1 MiB file limit and was reported incomplete as `file_too_large` without being parsed. No super-linear behavior was observed. This samples inputs; it does not prove a bound.
- **CLI output errors.** `mergelatch scan … > /dev/full` still returns the scan's exit code (F-09).

## What this audit covered and did not cover

**Read in full this phase:** `action.yml`; `action/mergelatch_action.py` (all of it); `action/build.sh`; `rust-toolchain.toml`; the three consumer-facing and CI workflows' triggers, permissions, pins, and downloads; `crates/cli/src/main.rs`; `crates/core/src/scan.rs`; `crates/core/src/yaml.rs`; `Cargo.lock` structure (sources, checksums, build scripts).

**Not re-read line by line this phase:** `discover.rs`, `fsaccess.rs`, `revision.rs`, `expr.rs`, `text.rs`, `model.rs`, and the rule files (`rules/*.rs`, including the 1,588-line shell reader). They were written and reviewed in earlier phases by the same agent, are exercised by 266 Rust tests, and were exercised here only by the black-box probes above. An independent reviewer should read them.

**Not done:** fuzzing, coverage measurement, a review of the third-party crates' source, a reproducible-build check, an examination of GitHub's runner internals, a test of the Action under a privileged event on GitHub, or a test of a pull request that edits the workflow.

## Audit findings and dispositions

**No confirmed security defect was found in the trusted implementation.** Nothing was changed in it, so the previously verified commit still describes the implementation. The items below are behaviors, design limitations, and unverified hypotheses, kept distinct on purpose.

Severity scale used here: **Low** means limited effect or requires the workflow author's cooperation; **Informational** means documentation or a note with no demonstrated security effect. A **confirmed defect** would be a behavior that contradicts a documented guarantee. None was found.

| ID | Type | Component | Summary | Severity | Reproduced | Disposition |
| --- | --- | --- | --- | --- | --- | --- |
| F-01 | Confirmed behavior; documentation was inconsistent | `prepare`, `PRIVILEGED_EVENTS` (as reviewed) | Event guard was a refusal list of two names, not an allowlist | Informational (docs); Low (hardening) | Yes | Docs corrected. **D-1 implemented (merged as `2a1a514…`) and verified as a pinned Action; not independently reviewed, not released** |
| F-02 | Design limitation (as reviewed) | `check_revision`, scanner revision reader | No revision check for subdirectory scans or non-`pull_request` events; result stayed green | Low | Yes | Documented, then **D-2 merged at `95bad26bc731caa913861e95f75bf2c4de3dc6b4` in PR #18 and verified with source and consumer pinned GitHub runs (40119258974, 40120225597). Not independently reviewed or released** |
| F-03 | Confirmed behavior; **fixed in the scanner (pull request #26), awaiting independent review** | scanner report assembly, `parse_report` | A small workflow could produce a report over the 5 MiB limit; the step failed with `error` and showed no findings. Now the report is bounded and `incomplete` | Low | Yes, before and after on GitHub (run [40160323975](https://github.com/MergeLatch/mergelatch/actions/runs/40160323975)) | Regression tests in the scanner and with the real binary. D-3 implemented |
| F-04 | Design limitation | consumer workflow | A pull request can edit or remove the caller's step | High if used as a gate; none as advisory | Documented; fork trial did not try it | Documented and prohibited as a required check |
| F-05 | **Confirmed behavior; architectural limitation** (was documented but not reproduced) | job composition | A prior same-job step (or a process it leaves running) runs as the same user, with passwordless `sudo` on GitHub-hosted runners, so it can change the Rust installation, the workspace, the state files, and the scanner the Action runs. Planted `GITHUB_ENV` settings and `GITHUB_PATH` entries are neutralized | High if the Action followed a step that runs pull request code and were used as a gate; none as advisory run first | Yes, on a GitHub-hosted runner with harmless stand-ins (run [40129287435](https://github.com/MergeLatch/mergelatch/actions/runs/40129287435)) | No change to the Action: no in-job fix can be a boundary. Documented; own-job guidance strengthened; a trusted enforcement design is needed for any gate |
| F-06 | Accepted risk | `build.sh`, `Cargo.lock` | The build runs the code of 13 build scripts and proc-macros from crates.io and downloads a toolchain, with no verification beyond rustup and cargo's own | Medium (supply chain) | n/a | Reviewer decision D-4 |
| F-07 | **Characterized**: partly confirmed protection, confirmed limitation, remaining hypotheses | helper start-up | Inherited settings that act before or while `/usr/bin/python3 -I` starts. `PYTHON*` and the working directory are ignored; `LD_*` loads code before any Action code runs and is only detected; the five `GLIBC_TUNABLES` sets and the other non-loader settings tried here did not run the marker library or change the result (observed scope only, see the F-07 section) | Low | Yes, with marker files on a GitHub-hosted runner (run [40132358637](https://github.com/MergeLatch/mergelatch/actions/runs/40132358637)) | No production change. Loader variables stay refused (detection, not prevention); `GLIBC_TUNABLES` is not refused. Tests pin the boundary. Not independently reviewed |
| F-08 | **Confirmed behavior** (was an unverified hypothesis) | `build()` | On the 1,500 s build timeout only the direct `bash` child was killed; `cargo`/`rustc` and other descendants kept running | Low | Yes, with fake tools and a 2 s timeout | The step already failed closed. **Fixed and merged at `c5296cef5fd3ffc36f1b8f0649e6491050606275` in PR #21; verified by pinned source (40125146676) and consumer (40126418768) GitHub runs; not independently reviewed or released** |
| F-09 | Confirmed behavior | `crates/cli/src/main.rs` | Errors writing the report to stdout are ignored; exit code still reflects the scan | Informational | Yes | Documented; the Action rejects a truncated report |
| F-10 | Limitation | scanner deadline | The 30 s limit is detected, not enforced mid-operation; 300 s helper timeout bounds it | Low | Probed, not proven | Documented |
| F-11 | Limitation | escaping | Look-alike characters can mislead a reader | Low | n/a | Documented |
| F-12 | Limitation | platform | Linux x86-64 only; `cap-std` fallback untested | Low | n/a | Documented |

### F-01. Event guard

- **Affected (as reviewed at `afc7e65…` and `4af8f9a…`):** `PRIVILEGED_EVENTS = ("pull_request_target", "workflow_run")` and its check in `prepare`. The text below records the finding as it was; the current behavior is in the disposition.
- **Behavior (reproduced):** exactly those two names are refused. `push`, `schedule`, `workflow_dispatch`, `issue_comment`, `pull_request_review`, `pull_request_review_comment`, `repository_dispatch`, `merge_group`, `issues`, `workflow_call`, `release`, `fork`, and unrecognized names run normally with `revision-check=not-applicable`. Matching is exact: `Pull_Request` and a trailing-space variant also run.
- **Threat:** a maintainer who believes the Action accepts only `pull_request` runs it under an event such as `issue_comment` (which runs the default branch's workflow and can have secrets and a write-capable token) in a job that also checks out pull request code. The Action does not make that job unsafe: it uses no secrets, builds and runs the scanner in an environment assembled from fixed values, and never executes the scanned content. The danger lies in the rest of that job, which the refusal would not have prevented even for the two refused events.
- **Attacker capability required:** none beyond what the workflow author already grants; a contributor cannot choose the event.
- **Severity:** Informational as a documentation inconsistency. No demonstrated vulnerability, so none is claimed.
- **Disposition:** the documentation was first corrected to state the actual behavior. The maintainer then decided D-1 and the guard was replaced by an exact allowlist, `SUPPORTED_EVENTS = ("pull_request",)`, with no normalization; every other name fails preparation with a fixed message, skips build and scan, and ends in status `error`. This is a hardening change, not the fix for a defect. It changes `action/mergelatch_action.py`, so `afc7e65…` no longer represents the current implementation and the targeted re-verification in [RELEASE_PLAN.md](RELEASE_PLAN.md) is required. Status: implemented and merged as `2a1a514…`; verified as a pinned Action in this repository, in the separate consumer repository, and under a real `workflow_dispatch` event; **not independently reviewed, not released**. A first-time README-only fork PR subsequently ran against it ([40112702817](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40112702817)); a workflow-editing fork was not tested.

### F-02. Revision check scope

- **Behavior (reproduced with the real scanner):** the revision is read from `.git` in the scanned directory. For `scan-directory: sub` there is none, so `revision-check` is `unavailable`, the status is unchanged, and the step is green. For events other than `pull_request` the result is `not-applicable`.
- **Threat:** a stale or wrong checkout is not detected in those configurations, so the scan may describe other content than the pull request. The effect is a wrong advisory result, not code execution.
- **Attacker capability required:** control over what is checked out, which belongs to the workflow author (or to code run earlier in the job).
- **Disposition:** first documented. Then, as part of the maintainer-led hardening, D-2 was implemented in the helper only (the scanner and `action.yml` are unchanged): on `pull_request`, `unavailable` and missing expected commits are `error`, and for an ordinary subdirectory the workspace root's `.git/HEAD` is used when it is a detached lowercase commit ID no longer than 256 bytes, read through no-follow, directory-relative opens. The fallback is skipped for a nested checkout (any `.git` entry between the scanned directory and the root). Both properties were added after maintainer review of the first version of this change. A branch checkout combined with a subdirectory scan, and a `.git` file, now fail (compatibility is described in [ACTION.md](ACTION.md#what-revision-is-scanned)). `afc7e65…` and `2a1a514…` do not contain this change. Status: **merged as `95bad26bc731caa913861e95f75bf2c4de3dc6b4` and verified with a pinned Action in source [run 40119258974](https://github.com/MergeLatch/mergelatch/actions/runs/40119258974) and consumer [run 40120225597](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40120225597).** Independent security sign-off and release remain pending; future implementation changes require the targeted re-verification in [RELEASE_PLAN.md](RELEASE_PLAN.md).

### F-03. Oversized reports

- **Behavior before (reproduced):** the scanner reported every finding; the helper accepts at most 5 MiB. 10,000 findings from a 370 KB file gave a 9,486,330-byte report, scanner exit 1, and the step ended in `error` with no findings shown. `RLIMIT_FSIZE` is 16 MiB, so an even larger report would stop or truncate the scanner's output; validation of a truncated report was tested, but a scanner stopped by that limit was not reproduced.
- **Change (D-3, scanner only; the helper, `action.yml` and `build.sh` are unchanged):**
  - A report lists at most 1000 findings and about 2 MiB of findings (measured as the pretty-printed JSON), and at most 500 incomplete entries and 512 KiB of them. Free-text finding fields are cut at 1024 characters, after distinct findings have been told apart on their full text. If the cut makes two distinct findings identical, they are listed once and an incomplete entry says how many were merged, so the status is `incomplete` (a review correction; the first version merged them silently). The shipped rules already keep every field well under 1024 characters (job IDs are cut at 100), so this guards the model and is not a case the current rules reach; the regression is a unit test.
  - If findings do not fit, the highest severities are kept (ties in the normal report order), the list keeps its normal order, and an incomplete entry of kind `limit_exceeded` and no path says how many were left out. The status is therefore `incomplete` and the scanner exits 2. It is never `findings` or `clean`. Other incomplete inspections are kept. Slots for omission notes are reserved only when a note is written (a review correction; the first version always reserved two): 498, 499 and 500 ordinary incomplete entries are all kept without a note, and 501 gives 499 entries plus one note. With a findings note, 499 entries fit, and 500 give 498 entries and two notes.
  - The scan stops analyzing more files once more than 20,000 distinct findings are held in memory, and says how many files were not analyzed. One file is always analyzed in full, so memory is bounded by that threshold plus one file (at most 1 MiB of workflow text).
  - `files-inspected` counts the workflow files discovered and read, as it did before (including after a timeout). When analysis stops early, the files not analyzed are still counted there and the incomplete entry says how many were skipped; the field is not a count of completed analyses.
  - Counts: schema version 1 is unchanged. `summary.findings` and `summary.incomplete` equal the lengths of the lists in the report, which is what the helper already checks, so they count what is listed. The number left out is in the detail text only. A consumer reading `findings-count` alone must not treat it as the total.
  - A scan below the bounds gives the same report as before. The exception is a free-text field longer than 1024 characters, which is now cut.
- **Worst case:** a unit test builds 3000 maximum-size findings (4-byte characters in every free-text field, 4096-byte paths) and 3000 incomplete entries with a 4096-byte target path, and checks that the report is under 3 MiB, inside the helper's 5 MiB limit.
- **After (reproduced):** the 10,000-step fixture gives a 945,518-byte report, status `incomplete`, 1000 findings, one `limit_exceeded` entry ("9000 more were left out"), exit 2. On GitHub (run [40160323975](https://github.com/MergeLatch/mergelatch/actions/runs/40160323975)), with the Action pinned to `5231aa0bb2f84ea2f0e3a888548e97cee750b4f5`: 100 steps gave `findings` 100/0; exactly 1000 gave `findings` 1000/0; 1001 gave `incomplete` 1000/1; 10,000 gave `incomplete` 1000/1; 1500 plus a broken workflow gave `incomplete` 1000/2; 499, 500 and 501 invalid workflow files gave `incomplete` with 499, 500 and 500 entries (the last includes a note). The earlier run [40157894509](https://github.com/MergeLatch/mergelatch/actions/runs/40157894509) pinned `46ebc37…` (before the two review corrections) and gave the same results for the first five. The control job with the commit before the change (`34b6957…`) gave the old `error`, step failure and 0 findings.
- **Threat:** a contributor could make the advisory check fail on their own pull request and hide the findings. Now they get an incomplete result that lists findings, so the check cannot be turned green or hidden this way. They can still fill the 1000 slots with findings of the highest severity they can produce, so which findings are listed is influenced by the contributor; the status is `incomplete`, not `findings` or `clean`.
- **Remaining limits:** rules shorten some text themselves before the scanner builds the report (for example job IDs at 100 characters), so two findings that differ only beyond that point are already one finding earlier; this predates D-3 and is not changed here. The caps are fixed constants and are not recorded in the report's `limits`; a consumer sees them only in the omission entry. An `incomplete` result from this cause is not a pass, and a reader must open the job summary to see the partial list. The helper still fails closed on a report over 5 MiB, a truncated report or an inconsistent one (those tests are unchanged). The new bounds were not independently reviewed.
- **Disposition:** fixed (D-3), advisory only. The scanner changed, so the previously verified commit `afc7e65…` no longer represents it, and the targeted re-verification in [RELEASE_PLAN.md](RELEASE_PLAN.md) is required for the merged commit.

### F-04 to F-12

See the table. F-04 and F-05 are the main reasons the Action must not be used as an enforcement gate. F-05 and F-07 were reproduced on GitHub-hosted runners (see their sections below); F-07 leaves some hypotheses open.

### F-05. Earlier steps in the same job

Scope: only what a step that ran earlier in the **same job** can do to the Action. The caller removing the step (F-04), the toolchain supply chain (F-06) and inherited-variable hypotheses (F-07) are separate. Evidence: [`action-f05-trial.yml`](../.github/workflows/action-f05-trial.yml), [run 40129287435](https://github.com/MergeLatch/mergelatch/actions/runs/40129287435) on a GitHub-hosted `ubuntu-24.04` runner, the Action loaded by full SHA `bac74ac9aacfa6068035526e5ed91fe557e34a70` (`action.yml`, the helper, `build.sh`, `Cargo.lock` and the crates are byte-identical to the F-08 revision `c5296cef…`; only a test constant differs). The earlier steps are written by the maintainers, run only harmless stand-ins that write marker files, and execute no pull request code.

**Confirmed (reproduced on GitHub):**

- **Same user, with `sudo`.** Steps run as `runner` (uid 1001) with passwordless `sudo`. `~/.cargo/bin/cargo`, `~/.rustup` and `$RUNNER_TEMP` are writable by that user; `/usr/bin/python3` is root-owned (replacing it needs `sudo`, which is available; the replacement itself was not attempted). Any code a step runs can therefore reach everything the Action trusts.
- **Settings and `PATH` planted through `GITHUB_ENV` / `GITHUB_PATH` are neutralized.** `BASH_ENV`, `ENV`, `CARGO_HOME`, `RUSTUP_HOME`, `RUSTC_WRAPPER`, `PYTHONPATH`, `PYTHONSTARTUP` and `PYTHONHOME` all took effect in ordinary later steps and were reported by the Action as ignored (8). Fake `python3`, `python`, `git`, `cargo`, `rustup` and `rustc` first in `PATH` were never run; no `sitecustomize`/`usercustomize` ran; no shell started by the Action read `BASH_ENV`. On the runner, attempts to set `RUNNER_TEMP`, `RUNNER_OS`, `GITHUB_WORKSPACE`, `GITHUB_OUTPUT`, `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_STEP_SUMMARY`, `GITHUB_SHA`, `GITHUB_EVENT_NAME` and `NODE_OPTIONS` did not take effect (observed, not a documented guarantee); `HOME` and `MLA_SCAN_TIMEOUT` did.
- **A modified Rust installation runs.** A wrapper placed at `~/.cargo/bin/cargo` ran inside the Action's build (it passes the `command -v` check, which compares only the path) and the build and scan still succeeded.
- **The scanned files are whatever the earlier steps left.** Removing the only workflow file after checkout gave status `clean`, 0 files inspected and `revision-check` = `matches-merge`, because the check reads the commit, not the files (already documented in F-02).
- **A same-user process that outlives its step can rewrite the result.** A background process (`nohup setsid`) waited for the Action's state directory and replaced `binary-path.txt` with a stand-in scanner. With a real finding present, the Action reported `clean`, 0 findings, `revision-check` = `matches-merge`, `action-pinned` = `true` and the correct Action SHA. The only visible difference was the stand-in's version string, which a reader can notice but a script cannot be relied on to.
- **A fixed target directory is reused (reproduced locally, not on GitHub).** After building the scanner into a directory, replacing `release/mergelatch` with a script and running the same `cargo build --locked --release` again took 3.7 s, did not rebuild, and left the script in place (it printed its marker). The Action builds into `$RUNNER_TEMP/mergelatch-cargo-target`, a fixed name that a prior step can create or reuse, so a pre-placed binary is run without being rebuilt.

**Architectural limitation (cannot be fixed inside the Action):** every item above needs only code execution as the runner user. Whatever state the Action keeps (state directory, `binary-path.txt`, report files, outputs), whatever it executes (`~/.cargo`, `~/.rustup`, the system tools) and the files it reads all lie within that user's reach, and the Action cannot prove its own integrity from inside the compromised context. A check run by the same job, by the same user, against the same files can be forged by the same actor. This is why F-04 and F-05 are both reasons not to gate on the Action.

**Unverified hypotheses (not tested):**

- Replacing `/usr/bin/python3` or `/usr/bin/bash` through `sudo` (expected to work; not attempted).
- Variables other than those above, including kernel and glibc settings, are F-07 (characterized below).
- Whether a process started with a new session survives to a later step on a runner image other than `ubuntu-24.04`. The behavior is the runner's, not the Action's.
- A same-user process poisoning `~/.cargo/registry` sources; not tried, same class as the wrapper.
- `MLA_SCAN_TIMEOUT` can come from the job environment. It was only observed to be accepted by the runner; its effect is covered by an existing unit test (a short value makes the scan an `error`). A long value could only keep the step running until the job's own timeout. It cannot make a failed scan look clean.

**What could be mitigated in the current advisory Action:** nothing that changes the boundary. A fresh per-run target directory inside the 0700 state directory would stop a *pre-placed* binary from being reused, at the cost of a rebuild for every invocation (about 13 s of crate compilation per invocation in the GitHub-hosted trials, on top of the toolchain install the first time), but a same-user actor can instead wrap `cargo` or race the state directory, as shown, so it would add cost without a guarantee. It was therefore **not implemented**; the maintainer may still choose it as defence in depth. Detecting tampering from inside the job is equally forgeable. No change was made to `action.yml` or the helper; the `pull_request` trigger, read-only token, SHA pinning, and the D-1, D-2 and F-08 behavior are unchanged.

**What needs a separate, trusted enforcement architecture:** a gate must run where the pull request cannot reach: a separate job (a fresh runner) or workflow that never runs pull request code and receives only the commit to inspect; the pull request's workflow file must not decide whether the check runs (an organization ruleset or required workflow, not a step in the pull request's own workflow); the result must be bound to the exact commit; and the scanner must be a verified artifact rather than built in the same job. That design is outside this audit (see the threat model and the release plan).

**Safeguards for consumers today:**

- Put the Action in **its own job**, with only `actions/checkout` before it, and run no pull request code in that job. A separate job gets a fresh runner, so nothing from other jobs reaches it. `needs:` and outputs stay under the workflow author's control.
- If it shares a job, run it **immediately after checkout**, before any step that installs, builds or tests pull request code. Steps after it cannot change an earlier step's recorded outputs, but background processes started earlier can still intervene.
- Do not use the Action to evaluate a checkout that an earlier step in the same job modified.
- Never make the result a required check or an input to automatic merging.

- **Disposition:** confirmed as an architectural limitation of an in-job advisory check. **No code change.** Documentation updated ([ACTION.md](ACTION.md#what-the-action-can-and-cannot-protect), [THREAT_MODEL.md](THREAT_MODEL.md), the example workflow) and the trial added as evidence. Awaiting independent review; not released.

### F-07. Inherited start-up environment

Scope: environment settings present when the runner starts one of the Action's steps (`/usr/bin/python3 -I`) that can act **before** the helper's first line runs, while the interpreter starts, or later in the helper's children. Settings written by an earlier step (F-05) and the caller's own `env:` (F-04) are the same trust level and are not separate attackers. Evidence: [`action-f07-trial.yml`](../.github/workflows/action-f07-trial.yml), [run 40132358637](https://github.com/MergeLatch/mergelatch/actions/runs/40132358637) on a GitHub-hosted `ubuntu-24.04` runner (glibc 2.39-0ubuntu8.9), the Action loaded by full SHA `e099dcda2ff957b8dbe8c2dc70080880bab1cde2`; the trial only observes markers and flags and runs no pull request code. The trial runs only for a pull request that changes it. A first run of the Python job failed because of a bug in the trial script (a control that is meant to fail ran under `bash -e`), not because of behaviour; it was fixed and the job passed.

**The start-up boundary, in order.**

1. *The dynamic loader (before Python exists).* `LD_*` and `GCONV_PATH` are read by the loader or C library and can load code into the process. Python's isolated mode cannot affect this.
2. *Python start-up.* `-I` implies `-E` and `-s`, ignores `PYTHON*` and the user site, and does not put the working directory or script directory on `sys.path`.
3. *The helper.* It runs `check_inherited_environment()`, which can only see what already happened.
4. *Children (build, scanner).* Their environment is built from fixed values, so nothing inherited reaches them.

**Confirmed protections (reproduced).**

| Setting | Expected | Actual | Evidence |
|---|---|---|---|
| `PYTHONPATH` with a `sitecustomize` and `usercustomize` | plain Python runs them, `-I` does not | plain: ran; `-I`: did not run | Python job summary |
| module in the working directory | plain `python3 -c` imports it, `-I` does not | plain: ran; `-I`: did not run | same |
| `PYTHONHOME=<nonexistent>` | stops plain Python, ignored by `-I` | plain exit 1; `-I` exit 0 | same |
| `PYTHONHASHSEED=0`, `PYTHONDONTWRITEBYTECODE`, `PYTHONWARNINGS=error`, `PYTHONUTF8=1` | change flags in plain Python, no effect under `-I` | plain: 0 / true / `["error"]` / 1; `-I`: 1 / false / `[]` / 0 | same |
| `LD_PRELOAD`, `LD_LIBRARY_PATH`, `GCONV_PATH` given to the Action | step fails, status `error`, no scan | `failure` / `error`, `scanner-source` `unknown`, `revision-check` `not-checked` | loader job |
| `GLIBC_TUNABLES` (five sets: allocator, heap check and tagging, `rtld`, CPU and threading, malformed) | real result unchanged or a failed step | all five: step success, `findings`, 1 finding (the control gave the same). A malformed value only prints an `ld.so` warning in the log | tunables job |
| locale, `LOCPATH`, `NLSPATH`, `TZ`, `TZDIR`, `MALLOC_*`, `TMPDIR`, `HOME`, `HOSTALIASES`, `RES_OPTIONS`, TLS and `XDG_*` settings, plus `PYTHONPATH`/`PYTHONHOME` | real result unchanged | success, `findings`, 1, `matches-merge`; 2 settings reported as ignored | other-settings job |

Unit tests that pin the boundary without GitHub: `test_ld_preload_runs_even_inside_python_isolated_mode` (the positive control), `test_loader_variables_are_a_hard_error`, `test_the_environment_is_exactly_the_fixed_values_plus_what_is_asked_for`, `test_loader_variables_do_not_reach_the_build_children`, and the new `StartUpSettings` tests, including `test_selected_start_up_settings_do_not_load_probe_library`.

**Confirmed limitations.**

- **`LD_PRELOAD` acts first.** A marker library named by `LD_PRELOAD` created its marker file in a plain `python3 -I` run, and in the Action's own interpreters: two marker files (at least the preparation and report steps) existed after the Action refused. The refusal is therefore **detection that stops the scan, not prevention** of the start-up effect, and an in-process check cannot claim otherwise. Whoever can set `LD_PRELOAD` already controls the workflow (F-04) and, by an earlier step, the job (F-05).
- **`GLIBC_TUNABLES` is parsed by the loader.** `ld.so --list-tunables` reports the parsed values. A malformed value only produces an `ld.so` warning on stderr.
- **Observed scope of the tunables evidence.** The 41 tunables listed by glibc 2.39 on this image are allocator, CPU, threading, elision, `rtld` limits, `gmon` and tagging parameters. A name scan found none that is an obvious direct selector of a path, library, audit module or preload, and the trial fails if a later image lists one. The name scan is a heuristic, not an audit of glibc tunables. In the runs, the five chosen sets did not invoke the marker library or change the finding count. That covers those five value sets on this image, nothing more: other values, malformed inputs beyond the one tried, parser defects, other glibc versions and other vulnerability classes are outside the evidence. (As history only, CVE-2023-4911 was a flaw in how an older glibc loader parsed `GLIBC_TUNABLES`; nothing here shows this package is affected, and nothing here shows it is not.)

**Unverified hypotheses (not tested).**

- Whether `GCONV_PATH` would load a gconv module during Python start-up. The Action refuses it regardless, so this was not needed; it is not claimed either way.
- Other `GLIBC_TUNABLES` values, malformed inputs beyond the one tried, and loader parsing defects.
- Behaviour on glibc versions other than 2.39 or runner images other than `ubuntu-24.04`. The Action refuses other images.
- Parsing of a corrupt locale file named by `LOCPATH`, and kernel-level settings (`ptrace`, `seccomp`, `ulimit`). A same-user actor can do more directly (F-05).
- Settings read by tools the helper does not start, or by future Python or glibc versions.

**Accepted risks.**

- `GLIBC_TUNABLES` and the non-loader settings above are not refused, on the strength of the observations above and not of a proof of safety. A refusal would reject legitimate configurations and prevent nothing, because the loader has already read them before any check.
- Anyone who can set the environment for the Action's steps can also edit or remove the step (F-04) or run code in the job (F-05). Environment control is not a separate privilege.
- `MLA_SCAN_TIMEOUT` can be inherited (F-05) and can only make a scan fail.

**What could be mitigated in the present Action.** Nothing that is not already done: children already get a fixed environment, `PYTHON*` is already neutralized by `-I`, and loader variables are already refused. No `action.yml` or helper change was made; D-1, D-2, F-08 and F-05 behaviour is unchanged, and the F-05 limits still apply. A stronger guarantee would need the check to run where the pull request cannot set the environment (a separate trusted workflow), which is outside this audit.

- **Disposition:** characterized; no defect found that an in-Action change can fix. Documentation and tests only. Awaiting independent review; not released.

### F-08. Build timeout left descendants running

- **Affected (as reviewed):** `build()` ran the build script with `subprocess.run(..., timeout=BUILD_TIMEOUT_SECONDS)`.
- **Reproduction (maintainer-led, harmless):** fake `rustup` and `cargo` in a temporary home; the fake `cargo` started a child and a grandchild (`sleep 300`) and waited; the timeout was set to 2 s. The helper raised "the scanner build exceeded its time limit" after 2.0 s, and immediately afterwards the fake `cargo`, its child and its grandchild were all still alive. The leftover processes were killed by hand. No real Cargo build was run or stalled.
- **Threat:** after the Action had already reported a failed build, `cargo`, `rustc`, a linker or a build script, and anything they started, could keep running on the runner and keep writing files or using the network, for the rest of the job. The step still failed closed, so no result was misreported. The effect is leftover execution in the job, and only for a build that has exceeded 25 minutes.
- **Attacker capability required:** none from a contributor: the build uses only the Action's own pinned source and the locked crates. It needs a stalled or hostile toolchain, registry or crate, which is the supply-chain risk in F-06.
- **Severity:** Low.
- **Disposition:** fixed in the helper only. The build script now runs in its own session and process group. On timeout the group receives `SIGKILL` before the script is reaped (so the group ID cannot be reused), the script is then reaped, and the existing time-limit error is raised. The build script, arguments, working directory, controlled environment, timeout value and fail-closed behavior are unchanged. Regression tests (fake tools, 1 to 1.5 s timeout) cover cleanup of the child and grandchild, a descendant that ignores `SIGTERM`, reaping, group isolation, exact exit codes, in-time completion and a launch failure. Three of them fail against the previous code.
- **Remaining limits:** a descendant that deliberately leaves the group (its own `setsid`) is not stopped; the process group is killed with an immediate `SIGKILL`, so nothing gets to clean up; the scanner run (`scan()`) is a single process and was not changed. Status: **merged in PR #21 at `c5296cef5fd3ffc36f1b8f0649e6491050606275` and SHA-pinned source and consumer trials passed** ([40125146676](https://github.com/MergeLatch/mergelatch/actions/runs/40125146676), [40126418768](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40126418768)). Rendered F-08 job summaries were not separately inspected in a browser; no new F-08 fork trial or independent security sign-off. The eventual release-candidate commit will require targeted re-verification under [RELEASE_PLAN.md](RELEASE_PLAN.md).

### Decisions for the maintainers and reviewer

| ID | Question | Recommendation of this review | Cost |
| --- | --- | --- | --- |
| D-1 | Accept only `pull_request`? | Yes, before `v0.1.0-rc.1`: it makes the code match the documentation and removes the ambiguity in F-01. **Decided, implemented and verified as a pinned Action; awaiting independent review** | Changes `mergelatch_action.py`; new SHA; targeted re-verification |
| D-2 | Treat `unavailable` as an error on `pull_request`, or read `.git` from the workspace root? | Both: merged as `95bad26bc731caa913861e95f75bf2c4de3dc6b4` in PR #18 and verified by source and separate consumer pinned GitHub runs; independent human review and release still pending | Changed the helper only; re-verification |
| D-3 | Cap findings in the scanner? | Yes. **Implemented in pull request #26 and verified with a pinned Action on GitHub; awaiting independent review** | Changed the scanner; re-verification |
| D-4 | Is building from crates.io and rustup on every run acceptable for a first release, or should a checksummed prebuilt binary be released? | Reviewer's judgment; this review accepts it for an advisory trial | Release engineering |

Any of D-1 to D-3 changes a trusted implementation file. If one is made, the previously verified SHA `afc7e65…` no longer represents the corrected implementation, and the targeted re-verification in [RELEASE_PLAN.md](RELEASE_PLAN.md) is required for the new commit.

## Dependency and build risks

- **Source:** 76 registry crates in `Cargo.lock`, all from `registry+https://github.com/rust-lang/crates.io-index`, all with checksums, no git or path dependencies. `Cargo.lock` is used with `--locked`, so the build fails if it would change.
- **What the Action compiles:** 44 registry crates (`cargo tree -p mergelatch-cli --edges normal,build` on x86-64 Linux). The other 32 lock entries are Windows-only crates and development dependencies, not built by the Action.
- **Code that runs at build time:** 13 of those 44 run a build script or are proc-macros: `cap-primitives`, `cap-std`, `clap_derive`, `io-extras`, `io-lifetimes`, `proc-macro2`, `quote`, `rustix`, `serde`, `serde_core`, `serde_derive`, `serde_json`, `zmij`. Each is code from crates.io executed on the runner during the build, in an environment with `HOME` and the Rust paths but no job secrets.
- **Direct runtime dependencies of the scanner:** `cap-std`, `rustix`, `serde`, `serde_json`, `yaml-rust2` (and `clap` in the CLI). The YAML parser handles attacker-controlled text; a panic is caught, a hang or memory exhaustion is bounded only by input limits and the helper's 300 s timeout.
- **Toolchain:** `rustup toolchain install` fetches Rust 1.99.1 from the Rust distribution server over HTTPS. rustup verifies what it downloads against the channel manifest; MergeLatch adds no separate checksum or signature check.
- **Advisories:** `cargo audit --deny warnings` passed on 2026-10-24 against the advisory database cached on the review machine. It is not run in CI.
- **Reproducibility:** not checked. A consumer cannot compare the built scanner with a published checksum, because none is published.
- **Network at run time:** GitHub (Action download), `static.rust-lang.org`, `crates.io`. A runner without them cannot build, and the step fails with `error`.
- **CI-only downloads:** `actionlint` and `shellcheck` are downloaded with pinned SHA-256 values in `.github/workflows/action-checks.yml`. They are not part of a consumer's job.

## Outstanding release blockers

A release candidate tag must not be created until all of these are closed:

1. **Independent human review is recorded** (see [Sign-off](#sign-off)). Currently pending.
2. **D-1 has independent review.** It is decided, implemented and verified as a pinned Action (see the evidence table), but has had no independent review. A README-only external fork run against the corrected SHA has now passed; it does not cover a contributor modifying the calling workflow.
3. **A consumer-trial run exists for the exact commit to be tagged,** unless the tag is placed on `afc7e65…` itself (see [RELEASE_PLAN.md](RELEASE_PLAN.md) for why that is not recommended).
4. **F-05 and F-07 are independently reviewed** (both were characterized and documented without a production change; F-08 was confirmed, fixed, merged, and verified in source and consumer SHA-pinned trials; independent review remains pending).
5. **The reviewer's checklist items below are answered** and any resulting defect is fixed through the private vulnerability process if it is exploitable.

Not blockers, but should be tracked: further D-2 verification if the implementation changes, independent review of D-3, D-4, `cargo audit` in CI, and a test of a pull request that edits the workflow.

## Reviewer checklist

Mark each item with the commit SHA reviewed and the result.

**Trust separation**

- [ ] `action.yml`: every step is `shell: /usr/bin/python3 -I {0}`; no step uses bash or interpolates untrusted context into code.
- [ ] Inputs and context reach the helper only through `env:`; no `${{ }}` appears inside a script body.
- [ ] `build()` and `scan()`: the scanned directory is never an argument to `cargo`, `rustup`, or a shell; only the finished binary receives it.
- [ ] `build.sh`: it `cd`s into the Action directory before `rustup` and `cargo`; `--locked`; no path from the workspace.

**Environment**

- [ ] `trusted_environment()` builds from nothing; confirm no variable from the caller reaches children except the listed ones.
- [ ] `check_inherited_environment()` and the documented gap for variables that affect the running interpreter (F-07).
- [ ] `trusted_home()` and the PATH order: is `~/.cargo/bin` first appropriate on the hosted image?
- [ ] `check_runner()`: is the runner context a sufficient basis?

**Filesystem**

- [ ] `resolve_scan_directory()`: realpath and the "inside the workspace" test, including symlinks and `..`.
- [ ] `discover.rs` and `fsaccess.rs`: handle-relative opens; behavior on symlinks, pipes, devices; `openat2` use and the fallback.
- [ ] `revision.rs`: `.git` handling through the same mechanism.
- [ ] The tests in `tests/core_confinement.rs`: are the swap points complete?

**Parsing, rules, report**

- [ ] `yaml.rs`: depth, alias handling, deadline checks, and the use of `catch_unwind`.
- [ ] Rules `ML-GHA-001` to `004`, in particular the shell reader (`rules/shell.rs`), for false negatives that matter and for any input that panics or is super-linear.
- [ ] `parse_report()`: schema and consistency checks; size and duplicate-key handling.
- [ ] `evaluate()`: every path that can produce `clean` or `findings`; confirm none is reachable after a failure.
- [ ] `md()` and `write_output()`: injection through the summary and `GITHUB_OUTPUT`; confusable characters (F-11).

**Event, revision, provenance**

- [ ] The event guard (F-01) and decision D-1.
- [ ] `check_revision()` and F-02, D-2.
- [ ] `action-revision` and `action-pinned` come from `github.action_ref` and `github.action_repository`; confirm that is the runner's own value.

**Supply chain**

- [ ] `Cargo.lock`: sources, checksums, versions; review the 13 build-time crates (F-06, D-4).
- [ ] `rust-toolchain.toml`: the channel, profile, and components that `rustup toolchain install` fetches.
- [ ] CI workflows: permissions, SHA pins, `persist-credentials: false`, and the pinned tool downloads.

**Process**

- [ ] The release plan: is a tag the right unit, and is the consumer-pinning guidance correct?
- [ ] The vulnerability reporting path in `SECURITY.md` works (private reporting is enabled).

## Release recommendation

**Conditionally ready for independent review; blocked for a release candidate tag.**

- Ready to hand to a reviewer: the scope, trust boundaries, controls, limitations, evidence, and findings are written down; local checks pass; the Action has run in-repository, in a separate consumer, under an intentionally rejected event, and from a README-only external fork; no confirmed defect was found.
- Blocked for `v0.1.0-rc.1`: no independent human has reviewed the code, three hypotheses are unconfirmed, and the implemented hardening decision (D-1) changed the trusted helper, which has been verified as a pinned Action but not independently reviewed.
- Whatever happens, the Action stays advisory: it must not be a required check, and no enforcement is claimed.

## Sign-off

| Role | Name | Date | Commit SHA reviewed | Result |
| --- | --- | --- | --- | --- |
| Independent security reviewer | **pending** | | | |
| Maintainer decision on D-1 to D-4 | **pending** | | | |
| Maintainer approval of the release plan | **pending** | | | |

A reviewer's identity, the SHA they examined, and their conclusions go here when a qualified person has actually examined the implementation and recorded a review. Until then every row stays **pending**.
