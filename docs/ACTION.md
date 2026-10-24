# MergeLatch advisory GitHub Action

**Status:** implemented and merged, **advisory only**, and **not released**. The Action implementation at commit `afc7e65d6723029c22935f82c7fc9562d5831565` has been run as a SHA-pinned Action on GitHub in this repository, and its rendered job summary showing the full pinned SHA has been inspected (see [Verification status](#verification-status)). It has also been run from a separate consumer repository and from a pull request by a first-time external fork contributor (see [EXTERNAL_TRIAL.md](EXTERNAL_TRIAL.md)). Being referenceable by SHA does not make it an official release, and no independent human review has been recorded yet. This Action is not a merge gate and must not be made a required check (see [Why this is not a merge gate](#why-this-is-not-a-merge-gate)).

## What it does

On a `pull_request` run, the Action scans the GitHub workflow files in a directory that an earlier step has already checked out, using the MergeLatch scanner and rules ML-GHA-001 to ML-GHA-004 (see [RULES.md](RULES.md)). It writes a job summary, sets outputs, and fails the step only when the scan itself cannot be trusted.

It does **not** scan source code for malware, does not look at the Git diff, does not read pull request text, and does not comment on pull requests. It reads `.github/workflows/*.yml` and `*.yaml` at the root of the scanned directory and nothing else.

## Architecture and trust boundaries

```
 consumer workflow (pull_request, contents: read, no secrets)
   |
   +-- actions/checkout (SHA-pinned, persist-credentials: false)
   |     -> pull request content, UNTRUSTED, read as data only
   |
   +-- MergeLatch/mergelatch@<full SHA>   (the Action)
         -> Action checkout, TRUSTED: scanner source, rules, helper
            1. prepare: validate inputs and the checkout  (Python, stdlib only)
            2. build:   cargo build --locked from the Action directory
            3. scan:    run the scanner on the validated directory
            4. report:  validate the JSON, write summary and outputs
```

| | Trusted | Untrusted |
| --- | --- | --- |
| Source | The Action checkout at the pinned SHA | The pull request checkout |
| Used for | Scanner source, rules, `rust-toolchain.toml`, `Cargo.lock`, the Python helper | A directory path passed to the scanner |
| Treatment | Built and run | Only read and parsed. Never built, installed, tested, or executed |

How the separation is kept:

- The scanner is built with `cd` into the Action directory first, so `rustup` reads the Action's `rust-toolchain.toml` and `cargo` reads the Action's configuration. The build is `--locked`.
- **No step runs under bash.** Every step runs as `/usr/bin/python3 -I` (an absolute path, so a changed `PATH` cannot substitute it). Bash reads `BASH_ENV` before the first line of any script, even with `--noprofile --norc`, so a `BASH_ENV` pointing into the checkout would run before the Action's own code. Python's isolated mode ignores the `PYTHON*` variables and the working directory. The only bash is `build.sh`, started by the helper with `--noprofile --norc` in a fresh environment.
- **Child processes get an environment built from scratch, not a filtered copy.** The build and the scanner receive only `PATH` (the runner's `~/.cargo/bin` first, then system directories), `HOME`, `CARGO_HOME`, `RUSTUP_HOME`, `LANG`, and the few variables the build script needs. `HOME` comes from the account database, not from the `HOME` variable. Nothing else is carried over, so unknown or future Cargo, rustup, compiler, linker, and shell settings (`CARGO_HOME`, `CARGO_TARGET_<triple>_LINKER`, `RUSTC_WRAPPER`, `RUSTUP_DIST_SERVER`, `BASH_ENV`, and so on) cannot reach them. The build also requires `rustup` and `cargo` to be found in `~/.cargo/bin` and fails with a clear error if they are not.
- The summary lists the names (never the values) of inherited build settings that were present and ignored, and the `ignored-environment-count` output gives their number.
- **Loader variables are refused.** `LD_PRELOAD`, `LD_LIBRARY_PATH`, other `LD_*` variables, and `GCONV_PATH` make the loader run code in every process, including the Action's own Python, before any of its code runs. They cannot be undone from inside the Action, so the Action stops with an error naming the variable instead of continuing.
- The scanned directory is only ever an argument to the finished binary. It is validated first: it must be a relative path without `..`, must resolve (after symlinks) inside the workspace, and must exist. A workspace without a `.git` entry is an error, so a forgotten checkout cannot produce an empty "clean" result.
- The scanner runs with the same minimal fixed environment as the build (`PATH`, `HOME`, `CARGO_HOME`, `RUSTUP_HOME`, `LANG`; no tokens, no `GITHUB_*` values, nothing from the workflow), from a private state directory, with a time limit and an output size limit.
- Inputs and GitHub context reach the scripts only through environment variables, never inside a shell command. Pull request titles, bodies, branch names, and file names are not used for anything executable.
- Everything in the scanner's report is treated as untrusted. It is validated against the report schema (types, enums, counts, and consistency between the status and the lists), then truncated and Markdown/HTML-escaped before it enters the job summary. Control and bidirectional-format characters are shown as `\u{..}`. Nothing from the report is written to the workflow log.
- **Only the `pull_request` event is accepted.** Preparation checks the event name against an exact allowlist; every other name, including `pull_request_target` and `workflow_run` (which give workflows secrets or a write-capable token), is rejected. See [Events](#events). This is decision D-1. It has run as a pinned Action at `2a1a514…`, including a real rejected event (see [Corrected implementation](#corrected-implementation-2a1a514b94754b146a690cf98ef59bc649d423ff)); the commit `afc7e65…` tested below used a refusal list of two names.
- **Runner restrictions are enforced, not only documented.** The Action stops with an error unless the runner is Linux (`runner.os`), GitHub-hosted (`runner.environment`), x86-64 (`runner.arch`), and its image reports `ID=ubuntu` in `/etc/os-release`. Self-hosted runners and ARM runners are refused because the scanner's file confinement has only been verified on x86-64 Linux. These values come from the runner context and the image, so they are checked at run time; a self-hosted runner that misreports them is outside what the Action can detect.
- If the Action is loaded from the scanned workspace itself (`uses: ./`), the summary and the `scanner-source` output say so: in that case the scanner code comes from the pull request and is **not** an independent release. The repository's own smoke test works this way.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `scan-directory` | `.` | Directory to scan, relative to the workspace. A checkout must already exist. |
| `max-findings-in-summary` | `25` | How many findings and incomplete entries to list in the summary (1 to 100). Counts are always exact. |

There is deliberately no input that makes findings fail the job. That would imply enforcement this version cannot provide.

## Outputs

| Output | Meaning |
| --- | --- |
| `status` | `clean`, `findings`, `incomplete`, or `error` |
| `findings-count`, `incomplete-count`, `files-inspected` | Counts from the report |
| `scanner-exit-code` | The scanner's own exit code, unchanged (`0` clean, `1` findings, `2` incomplete, `3` error; anything else means it failed) |
| `revision-check` | `matches-merge`, `matches-head`, `mismatch`, `unavailable`, `not-applicable`, or `not-checked` (the run failed before there was a result to compare) |
| `scanned-revision` | The commit the checkout recorded, if readable |
| `scanner-version`, `ruleset` | What produced the report |
| `scanner-source` | `action-checkout`, `workspace` (the Action was loaded from the scanned workspace), or `unknown` (the preparation step did not finish) |
| `action-pinned` | `true` only when the Action was referenced by a full 40-character commit SHA |
| `action-revision` | The full commit SHA the runner loaded the Action from, or empty when the Action was not referenced by a full SHA |
| `ignored-environment-count` | How many inherited build settings (for example `CARGO_HOME`, `BASH_ENV`) were present and ignored |

## Events

The Action accepts exactly one event, `pull_request`, by an exact string comparison in the preparation step. No name is normalized: `Pull_Request`, `pull_request ` (padded), an empty or missing name, and every other event (`pull_request_target`, `workflow_run`, `push`, `schedule`, `workflow_dispatch`, `repository_dispatch`, `issue_comment`, `issues`, `pull_request_review`, `pull_request_review_comment`, `merge_group`, `workflow_call`, `release`, `fork`, and unrecognized names) are rejected.

For a rejected event the preparation step records a fixed error message (it does not repeat the event value), the build and scan steps are skipped, no repository content is read, the report step produces status `error` with `revision-check` = `not-checked`, and the Action step fails. It is never reported as clean. This is covered by tests that follow 26 event values through preparation, scan, and report ([`RejectedEvent`](../action/tests/test_prepare_scan.py)) and a static test that `action.yml` skips build and scan unless preparation succeeded.

History. Until decision D-1, the helper refused only `pull_request_target` and `workflow_run` and let every other event run with `revision-check` = `not-applicable` (finding F-01 in [REVIEW_READINESS.md](REVIEW_READINESS.md#audit-findings-and-dispositions)). That was reproduced on 17 event names and was a documentation inconsistency, not a demonstrated vulnerability. The commit `afc7e65…` and its recorded trials have that earlier behavior.

The allowlist reduces accidental unsupported use. It is not a security boundary: a workflow that runs under a privileged event can check out and execute pull request code with its own steps whether or not this Action runs, and the Action cannot see how the rest of the job is built. Only the `pull_request` event has an expected revision, so only it can report `matches-merge`, `matches-head`, or `mismatch`. GitHub documents that a reusable workflow sees the caller's event name; that was not tested here. The new behavior was exercised under a real `workflow_dispatch` event on GitHub as a pinned Action; see [Corrected implementation](#corrected-implementation-2a1a514b94754b146a690cf98ef59bc649d423ff). It has not been exercised under other events or in a fork run, and it has had no independent review.

## What revision is scanned

Whatever the earlier checkout step put in the directory. With `actions/checkout` on `pull_request` and no `ref`, that is the merge result of the pull request and its base (`github.sha`). Setting `ref: ${{ github.event.pull_request.head.sha }}` on the checkout scans the pull request head instead. The Action reads the checked-out commit from `.git`, without running Git, and compares it with the expected merge commit and head commit from the trusted event context:

- `matches-merge` or `matches-head`: reported as that one revision. The summary never claims both were scanned.
- `mismatch`: the checkout is neither (for example a stale or wrong ref). The job **fails** with status `error`.
- `unavailable`: the scanned directory has no readable `.git`. **When `scan-directory` is a subdirectory, this is always the case, because the revision is read from `.git` in the scanned directory itself.** The scan runs, the step stays green, and the summary says the revision could not be checked, so no protection against a wrong checkout applies. Scan the workspace root, or assert `revision-check` in a later step, if that matters to you.
- `not-applicable`: the event has no expected revision (for example `push`).

The revision comes from `.git` files in the checkout, which are what the checkout claims, not a verified identity. It identifies the commit that was checked out, not the content of the files: a step that changes files after the checkout is not detected, which is another reason to run this Action before any other step that touches the workspace.

## Meaning of the results and how they appear

| Status | Meaning | Step result | Summary |
| --- | --- | --- | --- |
| `clean` | The supported checks completed and found nothing | success | "No findings in the supported checks", plus a reminder that this is not proof of safety. If `files-inspected` is 0 it says nothing was checked |
| `findings` | At least one rule matched | success (advisory) | "Findings require review", a table of matched rules and findings, and a warning annotation |
| `incomplete` | An inspection could not finish, or a rule hit an analysis limit | success (advisory) | "Incomplete: this is not a pass", with each reason, and a warning annotation |
| `error` | The scanner could not run, crashed, timed out, produced output that cannot be trusted, exited with a code that does not match its report, or the checkout is the wrong revision | **failure** | "Error: results cannot be trusted" |

A green check means only that the job ran. It is never evidence that a pull request is safe.

## Permissions and supported platforms

The Action needs no token permissions of its own. Use `permissions: contents: read` (the minimum for `actions/checkout`) and no secrets. It runs only on the `pull_request` event. It supports GitHub-hosted Ubuntu runners on x86-64 only (`ubuntu-24.04` is the one tested), because the scanner's race-resistant file access is verified only there. The Action enforces this at run time and refuses self-hosted, non-Linux, non-Ubuntu, and ARM runners. It never uses the network for anything except downloading the pinned Rust toolchain and the locked crates.

The build downloads the pinned Rust toolchain and the locked crates, which takes a few minutes on a cold runner and needs network access to `static.rust-lang.org` and `crates.io`.

## Fork pull requests

On `pull_request` from a fork the token is read-only and secrets are not available, which suits this Action. GitHub may require approval before workflows run for some first-time contributors. In the trial, a first-time external contributor's run waited with `action_required` until a maintainer approved it, and the approved run showed `Contents: read` and no secret source. Approve a run only after reading what the pull request changes under `.github/`; a pull request can edit the workflow that calls this Action. Because nothing is written back to the pull request, results appear only in the job summary and annotations of that run.

## Why this is not a merge gate

- A `pull_request` workflow runs the version of the workflow file from the pull request. The contribution being checked can edit or delete the MergeLatch step, change its inputs, or add `continue-on-error`.
- Pinning the Action to a full commit SHA protects the **Action's implementation** from tag or branch movement. It does not protect the **caller's workflow** from being edited by the pull request.
- The scanner and rules are trusted only if the pinned Action is. A `uses: ./` run, like this repository's smoke test, uses code from the pull request.
- A passing scan is not enough evidence to merge automatically: the supported checks are narrow, have false negatives, and stop at analysis limits.

Real enforcement needs a separately trusted workflow or service that the pull request cannot modify, fresh revision checks, and branch-protection integration. That is future work. **Do not add this Action's check to the required checks of a ruleset.** The `fmt, clippy, test` check is unchanged.

## Testing

| Kind | What it covers |
| --- | --- |
| Mocked | Environment assembly, the build step's calls to fake `rustup` and `cargo` (including their complete environment), report validation, exit-code consistency, truncated and malformed output, large reports, escaping of hostile strings, input validation, scanner invocation with a fake binary, the build script with fake `rustup` and `cargo`, output-writing failures |
| Real processes, simulated GitHub | Real `python3 -I`, `bash`, `cargo`, `rustup`, and a C compiler: positive controls showing that `BASH_ENV`, a `CARGO_HOME` config, a `CARGO_TARGET_<triple>_LINKER`, and `LD_PRELOAD` do run marker scripts when honored, and builds of a small stand-in workspace showing the same settings are neutralized. The GitHub environment is plain files |
| Real scanner, simulated GitHub | The same steps against the real `mergelatch` binary on fixtures, including unusual file names, a hostile-build-files fixture, stale revisions, and an invalid target. The GitHub environment is plain files |
| Static | `action.yml` and every workflow: read-only tokens, no secrets, no privileged triggers, SHA-pinned external Actions, `persist-credentials: false`, no expressions in `run:` text |
| GitHub-hosted run | `.github/workflows/action-checks.yml` runs the composite Action with `uses: ./` on a hosted runner, including a first run with hostile `BASH_ENV`, `CARGO_HOME`, linker, wrapper, and rustup settings, a positive-control bash step, and a run with `LD_PRELOAD` that must fail. This executes the unreviewed implementation and is read-only, with no secrets and no enforcement role. It does not prove that consumers using a released, SHA-pinned Action are protected |

The case of a separately checked-out Action directory (`scanner-source: action-checkout`) is covered by the mocked and simulated tests, and was observed on GitHub for `afc7e65…` in this repository and in a separate consumer repository (see [Verification status](#verification-status)).

## Verification status

### Historical verification: `afc7e65d6723029c22935f82c7fc9562d5831565`

| Item | Status |
| --- | --- |
| Source reviewed | `afc7e65d6723029c22935f82c7fc9562d5831565`, the merge commit of pull request #9 |
| SHA-pinned trial tested | Yes: GitHub downloaded and ran exactly that commit (run 40096959695) |
| Rendered full SHA verified | **Yes**, by reading the Action's own rendered job summaries of that run. Every summary shows ``MergeLatch/mergelatch@afc7e65d6723029c22935f82c7fc9562d5831565`` in full |
| External consumer tested | **Yes**, in the separate repository `MergeLatch/mergelatch-consumer-trial`: clean passed, the unsafe-permissions fixture gave one finding, the malformed fixture gave incomplete, and the Action came from the separate pinned download (run 40099476256) |
| Fork pull request tested | **Yes, in a limited way.** A first-time external account (association `NONE`) opened pull request #2 from a fork. The first attempt was `action_required` and ran no jobs. After a maintainer approved it, the run succeeded (run 40100818227) with the full pinned SHA, `scanner-source` = `action-checkout`, and `revision-check` = `matches-merge`. The fork's change was a README edit only; a fork that edits the workflow was not tried |
| Independent human review | **Pending.** Nothing has been recorded by a qualified reviewer |
| Published release | None. No tag and no GitHub release exist |

Details, caveats, and what these runs do not show are in [EXTERNAL_TRIAL.md](EXTERNAL_TRIAL.md).

### Corrected implementation: `2a1a514b94754b146a690cf98ef59bc649d423ff`

The table above is the evidence for `afc7e65…`, whose helper accepted every event except `pull_request_target` and `workflow_run`. Decision D-1 (pull request #12, merge commit `2a1a514…`) changed the helper to accept only `pull_request`. That is a different implementation, so it is verified separately and the old results are kept, not reused:

| Item | Status |
| --- | --- |
| Unit and simulated tests | Pass (local, 143 Python tests; see [REVIEW_READINESS.md](REVIEW_READINESS.md)) |
| Pinned in this repository, `pull_request` | **Yes**, run [40106718920](https://github.com/MergeLatch/mergelatch/actions/runs/40106718920) (pull request #13). The log shows `Download action repository 'MergeLatch/mergelatch@2a1a514…'`; the scanner compiled from `_actions/MergeLatch/mergelatch/2a1a514…/crates/core`; the workflow's SHA-256 checks of `action.yml`, the helper, `build.sh` and `Cargo.lock` (computed with `git show 2a1a514…:<path>`) passed, and only the helper's hash differs from `afc7e65…`. Clean, findings, incomplete, missing-directory, no-checkout, `LD_PRELOAD`, head, merge and stale-revision scenarios behaved as before. The rendered summaries, read in a browser, show ``MergeLatch/mergelatch@2a1a514b94754b146a690cf98ef59bc649d423ff`` in full in every scenario |
| Separate consumer repository, `pull_request` | **Yes**, run [40106918299](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40106918299) (consumer pull request #3, not merged): pinned download of `2a1a514…`, assertions passed (clean, one finding, incomplete, `action-checkout`, full-SHA `action-revision`, `matches-merge`) |
| Rejected event on GitHub (`workflow_dispatch`) | **Yes**, run [40108606160](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40108606160), dispatched manually by the maintainer from `main` of the consumer repository (workflow from consumer pull request #4). The job passed because the Action step failed as intended. The log shows the pinned download of `MergeLatch/mergelatch@2a1a514…`; the Action's own steps: `prepare` succeeded (it records the rejection), `build` skipped, `scan` skipped, `report` failed with "The scan did not produce a trustworthy result", and there is no compile or `rustup` output. The final assertion step passed: outcome `failure`, `status=error`, `revision-check=not-checked`, 0 findings, 0 incomplete, no scanner exit code or scanned revision, `action-pinned=true`, full-SHA `action-revision`, and a state directory containing only `state.json` with no build directory. Only the `workflow_dispatch` event was exercised. The setup log lists `Contents: read` and `Secret source: Actions`; the repository defines no secrets |
| Fork pull request with the new implementation | **Not performed.** The earlier fork run tested `afc7e65…` |
| Independent human review | **Pending** |
| Published release | None |

The example workflow, `TRIAL_TESTED_SHA`, and the "tested" wording elsewhere still name `afc7e65…`. They were not moved as part of recording this evidence; moving them is a separate maintainer decision, to be taken with the pending review and the fork question.

### Which commit was tested

The Action implementation is `action.yml`, `action/mergelatch_action.py`, `action/build.sh`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, and `crates/`. A consumer who pins a commit receives the whole repository at that commit, but only these paths are built or run.

Two commits have been run as SHA-pinned Actions on GitHub: `afc7e65d6723029c22935f82c7fc9562d5831565` (historical helper behavior) and `2a1a514b94754b146a690cf98ef59bc649d423ff` (corrected D-1 event allowlist). The separate run links and results are documented above. A different commit SHA is not considered tested merely because its implementation files match; GitHub must actually load that exact reference in a recorded trial. As of the review-readiness work (main at `4af8f9aa9340fee38abb7c9f3b554c53ad645d64`), every path above had the same git object ID as at `afc7e65…` (checked with `git rev-parse <commit>:<path>`), so the implementation was byte-identical. The event-allowlist change (decision D-1) then changed `action/mergelatch_action.py`, so commits from that change onward are **not** the implementation that `afc7e65…` verified. That is a statement about identical files, not a new test. The check to repeat for any later commit is:

```
git diff --quiet afc7e65d6723029c22935f82c7fc9562d5831565 <commit> -- \
  action.yml action/mergelatch_action.py action/build.sh Cargo.toml Cargo.lock rust-toolchain.toml crates
```

Re-verification of the Action as a pinned reference is needed if that diff is not empty or a defect is found in the implementation. For a first release, the plan in [RELEASE_PLAN.md](RELEASE_PLAN.md) runs the consumer trial against the exact release commit before it is tagged.

## Historical trial results: `afc7e65d6723029c22935f82c7fc9562d5831565`

Earlier, `.github/workflows/action-trial.yml` ran the Action as `MergeLatch/mergelatch@afc7e65d6723029c22935f82c7fc9562d5831565` (never `uses: ./`) on a GitHub-hosted `ubuntu-24.04` runner, in this repository, on pull request #10. Run [40096959695](https://github.com/MergeLatch/mergelatch/actions/runs/40096959695) succeeded. The expected hashes in the workflow were computed from the files at that commit with `git show`; `action.yml`, `build.sh`, `Cargo.lock`, and `rust-toolchain.toml` are byte-identical to the previous pin and only the helper differs. **This subsection records the historical run, not the workflow's current pin.** The current trial workflow pins `2a1a514b94754b146a690cf98ef59bc649d423ff`; its evidence is recorded under [Corrected implementation](#corrected-implementation-2a1a514b94754b146a690cf98ef59bc649d423ff).

What was observed on GitHub (real execution, not mocks). Summary text was read from the rendered job summaries; outputs were asserted by the workflow:

| Check | Result |
| --- | --- |
| Separate download | `Download action repository 'MergeLatch/mergelatch@afc7e65…' (SHA:afc7e65…)`. The trial finds it at `_actions/MergeLatch/mergelatch/<sha>`, outside the workspace, and the SHA-256 of `action.yml`, the helper, `build.sh`, and `Cargo.lock` match the reviewed files. |
| Scanner built from that directory | `Compiling mergelatch-core … (/home/runner/work/_actions/MergeLatch/mergelatch/afc7e65…/crates/core)`; rustup reports the toolchain is "overridden by" that directory's `rust-toolchain.toml`. |
| Rendered Action revision row | `Action revision` shows ``MergeLatch/mergelatch@afc7e65d6723029c22935f82c7fc9562d5831565`` in full in every scenario's summary. The trial's separate demonstration table still shows that GitHub shortens the same text in ordinary text to `@afc7e65`, which is why the row is a code span. |
| Outputs | `action-revision` = the full 40-character SHA, `action-pinned` = `true`, `scanner-source` = `action-checkout`, scanner `0.1.0`, ruleset `mergelatch-builtin-1`. |
| Clean | Merge checkout: exit 0, step succeeded, "not proof of safety", `matches-merge`. |
| Findings | The `write-all` fixture: 1 finding, exit 1 preserved, "Findings require review", step succeeded. |
| Incomplete | The malformed fixture: exit 2 preserved, "Incomplete: this is not a pass", step succeeded. |
| Errors | A missing directory and a run with no checkout: step failed, status `error`, `revision-check` = `not-checked`. An `LD_PRELOAD` in the environment: step failed, `scanner-source` = `unknown` ("not determined"), `revision-check` = `not-checked`, `action-revision` still the full SHA. |
| Revision | Pull request head checkout: `matches-head`. Base-commit checkout: `mismatch`, step failed. |
| Hostile input | Inert build files were scanned as data. With hostile `BASH_ENV`, `CARGO_HOME`, linker, compiler-wrapper, and rustup settings in the step environment, the build succeeded, the Action listed them as ignored, and no `HOSTILE_*` marker appeared. A control bash step with `BASH_ENV` did run its marker. |

Measured on that run (one fresh cold runner): total run 34 s, trial job 30 s, no-checkout job 3 s. The scanner build took 20.4 s (about 9 s to install the pinned toolchain and 13.1 s to download and compile the locked crates in release mode); later builds in the same job reuse the target directory. These are single measurements; earlier cold runs took 27.3 s for the same build, so expect variation.

Not verified, and not measured:

- **A contributor who edits the calling workflow,** in a fork or otherwise. The external fork pull request changed a README line only ([EXTERNAL_TRIAL.md](EXTERNAL_TRIAL.md)).
- **Event restrictions in the historical run.** The old refusal of `pull_request_target` and `workflow_run` was covered by unit tests; that particular run did not exercise those events. The later D-1 implementation was exercised under real `workflow_dispatch` in [run 40108606160](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40108606160), but no GitHub run has specifically exercised `pull_request_target` or `workflow_run`.
- **GitHub being unable to download the Action.** Not simulated. The job would fail at setup before any step runs.
- **A cold build failure on GitHub** (for example an unreachable Rust distribution server). Covered only by mocked tests, which report status `error` and fail the step.
- Network dependencies, from the logs: GitHub (the Action download), the Rust distribution server (the pinned toolchain), and the crates registry (the locked crates).

History. The first pinned trial, of `0d3ef392b1f18f264ea96d2d8f4796eead4857cc` (run 40091227897), found that the summary did not print the pinned SHA, that an error before any scan said "no expected revision for this event", and that a failed early preparation described the scanner source as pinned. The second, of `cf89c21dad24ad95121fd7d8ce47fe1b6b5f80e5` (run 40095282996), fixed those but found that GitHub shortened the SHA in the rendered row. `afc7e65…` fixes that and is the first commit for which every item above holds.

## Release candidate review

This is a review of the Action as it stands, not a release. No tag, release page, download, or certification exists. Any version label here is a proposal.

| Item | State |
| --- | --- |
| Inputs and outputs | `scan-directory`, `max-findings-in-summary`; outputs listed above. Summary wording is for people and is not a stable interface |
| Scanner and ruleset identity | Reported as `scanner-version` and `ruleset`; both appear in the summary. Report schema version `1`, validated by the helper |
| Runners | GitHub-hosted Ubuntu on x86-64, enforced at run time. `ubuntu-24.04` is the one tested |
| Installation | Pin `MergeLatch/mergelatch@<full 40-character SHA>`; see the example workflow. Tags and branches are not supported and are reported as "NOT a full commit SHA" |
| Build integrity | `cargo build --locked` from `Cargo.lock` and a pinned `rust-toolchain.toml`. Bit-for-bit reproducibility was not checked. rustup and cargo verify what they download against their own metadata; MergeLatch adds no separate verification of the toolchain or crates |
| Network dependencies | GitHub, the Rust distribution server, the crates registry. A runner without access to them cannot build the scanner and the step fails with status `error` |
| License | Apache-2.0, see `LICENSE`; dependencies keep their own licenses |
| Reporting vulnerabilities | Through GitHub private vulnerability reporting, see `SECURITY.md` |
| False positives and negatives | See [RULES.md](RULES.md); the Action adds none of its own beyond the revision check |
| Incomplete and failed scans | `incomplete` keeps the step green but is "not a pass"; a failure to run, build, or parse, or a wrong revision, fails the step |
| Updating | Review the newer commit, then change the whole SHA in the workflow. Do not follow a branch or tag |
| Breaking changes | A change to an input or output name or meaning, to the set of statuses, to which statuses fail the step, to the supported runners, or to the permissions required. Summary wording and the order of summary rows are not part of the interface |
| Proposed first label | `v0.1.0-rc.1` is proposed for a first candidate, only after the open items below are closed. It does not exist |

Open items before a first controlled public release candidate:

1. Independent human review of the Action, helper, workflows, and build ([REVIEW_READINESS.md](REVIEW_READINESS.md)). Pending.
2. Independent review of the D-1 `pull_request`-only allowlist (implemented and trial-tested at `2a1a514b94754b146a690cf98ef59bc649d423ff`) and maintainer dispositions for D-2 through D-4 in [REVIEW_READINESS.md](REVIEW_READINESS.md#audit-findings-and-dispositions).
3. A consumer-trial run pinned to the **exact candidate release commit**, even if its implementation is byte-identical to the tested `2a1a514b94754b146a690cf98ef59bc649d423ff` implementation ([RELEASE_PLAN.md](RELEASE_PLAN.md)).

Verified for the historical `afc7e65…` implementation: the in-repository trial including its rendered full SHA, separate consumer trial, and first-time external fork PR (README-only). Verified separately for `2a1a514b94754b146a690cf98ef59bc649d423ff`: in-repository and separate consumer trials, plus the manually dispatched unsupported-event rejection. A fork run pinned to `2a1a514b94754b146a690cf98ef59bc649d423ff` has not been performed.

## Known limitations

- Narrow coverage: four rules on workflow files only. See [RULES.md](RULES.md) for false positives and negatives.
- **Very large reports fail the step.** The scanner caps neither the number of findings nor the size of its report. The helper rejects reports over 5 MiB, so a workflow of a few hundred kilobytes with thousands of findings (reproduced with 7,000 unpinned steps, about 9.5 MB) produces status `error` and a failed step instead of a list of findings. This is fail-closed and is pinned by a test, but it means such a pull request gets no finding list.
- Escaping removes markup and control characters but cannot stop look-alike (confusable) characters in file names from misleading a reader.
- The revision check trusts the checkout's `.git` files, checks a commit and not file content, and does not apply to subdirectory scans or to events other than `pull_request`.
- The command-line scanner ignores errors writing its report to standard output (for example a full disk) and still returns the scan's exit code, so a redirected report can be truncated while the exit code is correct. The Action detects this because a truncated report fails validation.
- Filesystem and platform limits of the scanner (Linux only, residual races) apply. See the threat model.
- The Python helper, the build, and the downloaded toolchain and crates are part of the trusted computing base.
- The runner's own Rust installation (`~/.cargo/bin`, `~/.rustup`, and any `config.toml` in `~/.cargo`) and the system Python and bash are trusted. A previous step that runs untrusted code in the same job could modify them or the files the runner uses to carry settings between steps (`GITHUB_ENV`, `GITHUB_PATH`); run this Action before any step that executes pull request code, and do not add such steps to the same job.
- `LD_*` and `GCONV_PATH` are detected, not neutralized: by the time the Action can see them, the loader has already acted on them. The Action fails closed instead of continuing.
- Settings are removed by building the child environment from fixed values. Settings that change how the already-running Python behaves, other than `PYTHON*` (ignored by `-I`) and the loader variables above, are not known and are not checked.
- The runner restrictions rely on the runner context and `/etc/os-release`. They stop honest misconfiguration, not a self-hosted runner built to lie.

## Release and SHA-pinning process (not yet done)

1. Independent review of this change, including the helper and the workflows.
2. Merge. Run the smoke test and a controlled advisory trial in a repository that is not otherwise protected by it. (The historical `afc7e65…` implementation has in-repository, separate consumer, and fork evidence; `2a1a514b94754b146a690cf98ef59bc649d423ff` has in-repository, separate consumer, and `workflow_dispatch` rejection evidence, but no fork run.)
3. Cut a release from a reviewed commit and record its **full 40-character SHA**. Verify the SHA against the repository before publishing it.
4. Consumers pin that SHA and nothing else. The example currently names the verified commit `afc7e65…`, not a release. Updates are made by reviewing a newer commit and changing the whole SHA, never by following a branch or tag.
5. Optionally extract `action.yml`, `action/`, and the scanner source (or checksummed release binaries) into a separate `mergelatch-action` repository after the above. The extraction must keep `Cargo.lock` and `rust-toolchain.toml` with the source it builds, and must repeat the review and the SHA pinning for the new location. That repository does not exist yet.
