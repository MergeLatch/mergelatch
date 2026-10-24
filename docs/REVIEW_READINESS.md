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
- **Revision check** reads `.git` from the scanned directory: not applicable to subdirectory scans or events other than `pull_request`, checks the commit and not the files, and is not an identity.
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
| `workflow_dispatch` rejected-event test (consumer PR #4) | not run | **pending maintainer merge and manual dispatch** |
| Fork pull request against `2a1a514…` | not run | not performed |

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
- **Report size.** One 370 KB workflow with 10,000 unpinned steps produced a 9.5 MB report. The helper turned it into `error` (F-03).
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
| F-01 | Confirmed behavior; documentation was inconsistent | `prepare`, `PRIVILEGED_EVENTS` (as reviewed) | Event guard was a refusal list of two names, not an allowlist | Informational (docs); Low (hardening) | Yes | Docs corrected. **D-1 implemented on branch `fix/action-pull-request-event-allowlist`; not independently reviewed, not released, not yet verified as a pinned Action** |
| F-02 | Design limitation | `check_revision`, scanner revision reader | No revision check for subdirectory scans or non-`pull_request` events; result stays green | Low | Yes | Documented. Decision D-2 |
| F-03 | Confirmed behavior; fail-closed | scanner (no findings cap), `parse_report` | A small workflow can produce a report over the 5 MiB limit; the step fails with `error` | Low | Yes | Regression test added. Accepted; decision D-3 |
| F-04 | Design limitation | consumer workflow | A pull request can edit or remove the caller's step | High if used as a gate; none as advisory | Documented; fork trial did not try it | Documented and prohibited as a required check |
| F-05 | Design limitation | job composition | A prior same-job step running pull request code can alter state files, the target directory, `GITHUB_ENV`, `GITHUB_PATH`, or the runner's Rust installation | Medium if misused | Not reproduced this phase | Documented: run before any such step |
| F-06 | Accepted risk | `build.sh`, `Cargo.lock` | The build runs the code of 13 build scripts and proc-macros from crates.io and downloads a toolchain, with no verification beyond rustup and cargo's own | Medium (supply chain) | n/a | Reviewer decision D-4 |
| F-07 | Unverified hypothesis | helper start-up | Inherited variables other than those listed (for example glibc tunables) could affect the already-running Python | Low | No | Needs workflow-author control; documented as unknown |
| F-08 | Unverified hypothesis | `build()` | On the 1,500 s build timeout only the direct `bash` child is killed; `cargo`/`rustc` may linger | Low | No (needs a 25-minute build) | Step still fails closed; reviewer to confirm |
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
- **Disposition:** the documentation was first corrected to state the actual behavior. The maintainer then decided D-1 and the guard was replaced by an exact allowlist, `SUPPORTED_EVENTS = ("pull_request",)`, with no normalization; every other name fails preparation with a fixed message, skips build and scan, and ends in status `error`. This is a hardening change, not the fix for a defect. It changes `action/mergelatch_action.py`, so `afc7e65…` no longer represents the current implementation and the targeted re-verification in [RELEASE_PLAN.md](RELEASE_PLAN.md) is required. Status: implemented on the branch, **not independently reviewed, not released, not yet verified as a pinned Action**.

### F-02. Revision check scope

- **Behavior (reproduced with the real scanner):** the revision is read from `.git` in the scanned directory. For `scan-directory: sub` there is none, so `revision-check` is `unavailable`, the status is unchanged, and the step is green. For events other than `pull_request` the result is `not-applicable`.
- **Threat:** a stale or wrong checkout is not detected in those configurations, so the scan may describe other content than the pull request. The effect is a wrong advisory result, not code execution.
- **Attacker capability required:** control over what is checked out, which belongs to the workflow author (or to code run earlier in the job).
- **Disposition:** documented, including that consumers can scan the root or assert `revision-check`. D-2: whether `unavailable` on `pull_request` should fail, or whether the Action should read `.git` from the workspace root.

### F-03. Oversized reports

- **Behavior (reproduced):** the scanner reports every finding; the helper accepts at most 5 MiB. 10,000 findings from a 370 KB file gave a 9.5 MB report. `RLIMIT_FSIZE` is 16 MiB, so an even larger report would stop or truncate the scanner's output; validation of a truncated report was tested, but a scanner stopped by that limit was not reproduced. Each of these paths ends in status `error` and a failed step. A regression test (`test_a_report_larger_than_the_limit_fails_closed`) pins this and fails if the limit is removed.
- **Threat:** a contributor can make the advisory check fail on their own pull request. That is fail-closed (the result is visible and red, not clean). It also hides the actual findings behind an error.
- **Attacker capability required:** ability to submit a pull request; they could already delete the step.
- **Disposition:** accepted. D-3: cap findings in the scanner and add an incomplete entry, which would change the scanner.

### F-04 to F-12

See the table. F-04 and F-05 are the main reasons the Action must not be used as an enforcement gate. F-05 and F-07 to F-08 are stated as hypotheses or limitations because they were not reproduced, and should be confirmed or dismissed by the reviewer.

### Decisions for the maintainers and reviewer

| ID | Question | Recommendation of this review | Cost |
| --- | --- | --- | --- |
| D-1 | Accept only `pull_request`? | Yes, before `v0.1.0-rc.1`: it makes the code match the documentation and removes the ambiguity in F-01. **Decided and implemented; awaiting independent review and pinned-SHA verification** | Changes `mergelatch_action.py`; new SHA; targeted re-verification |
| D-2 | Treat `unavailable` as an error on `pull_request`, or read `.git` from the workspace root? | Decide with the reviewer; the current documented behavior is acceptable for an advisory Action | Changes the helper or the scanner; re-verification |
| D-3 | Cap findings in the scanner? | Optional | Changes the scanner; re-verification |
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
2. **D-1 is verified.** It is decided and implemented, but the corrected implementation has not run as a pinned Action, has had no independent review, and needs the targeted re-verification in [RELEASE_PLAN.md](RELEASE_PLAN.md).
3. **A consumer-trial run exists for the exact commit to be tagged,** unless the tag is placed on `afc7e65…` itself (see [RELEASE_PLAN.md](RELEASE_PLAN.md) for why that is not recommended).
4. **F-05, F-07, F-08 are confirmed or dismissed** by the reviewer.
5. **The reviewer's checklist items below are answered** and any resulting defect is fixed through the private vulnerability process if it is exploitable.

Not blockers, but should be tracked: D-2, D-3, D-4, `cargo audit` in CI, and a test of a pull request that edits the workflow.

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

- Ready to hand to a reviewer: the scope, trust boundaries, controls, limitations, evidence, and findings are written down; local checks pass; the Action has run from three contexts on GitHub; no confirmed defect was found.
- Blocked for `v0.1.0-rc.1`: no independent human has reviewed the code, three hypotheses are unconfirmed, and the implemented hardening decision (D-1) changed the trusted helper, so the corrected implementation still needs pinned-SHA verification.
- Whatever happens, the Action stays advisory: it must not be a required check, and no enforcement is claimed.

## Sign-off

| Role | Name | Date | Commit SHA reviewed | Result |
| --- | --- | --- | --- | --- |
| Independent security reviewer | **pending** | | | |
| Maintainer decision on D-1 to D-4 | **pending** | | | |
| Maintainer approval of the release plan | **pending** | | | |

A reviewer's identity, the SHA they examined, and their conclusions go here when a qualified person has actually examined the implementation and recorded a review. Until then every row stays **pending**.
