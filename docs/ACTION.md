# MergeLatch advisory GitHub Action

**Status:** implemented and merged, **advisory only**, and **not released**. Its merge commit `0d3ef392b1f18f264ea96d2d8f4796eead4857cc` has been trial-tested as a SHA-pinned Action in this repository (see [Trial results](#trial-results)). Being referenceable by SHA does not make it an official release, and it has not been tried in a separate consumer repository. This Action is not a merge gate and must not be made a required check (see [Why this is not a merge gate](#why-this-is-not-a-merge-gate)).

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
- The scanner runs with an empty environment (no tokens, no `GITHUB_*` values), from a private state directory, with a time limit and an output size limit.
- Inputs and GitHub context reach the scripts only through environment variables, never inside a shell command. Pull request titles, bodies, branch names, and file names are not used for anything executable.
- Everything in the scanner's report is treated as untrusted. It is validated against the report schema (types, enums, counts, and consistency between the status and the lists), then truncated and Markdown/HTML-escaped before it enters the job summary. Control and bidirectional-format characters are shown as `\u{..}`. Nothing from the report is written to the workflow log.
- The Action refuses to run on `pull_request_target` and `workflow_run`, which give workflows secrets or a write-capable token.
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
| `revision-check` | `matches-merge`, `matches-head`, `mismatch`, `unavailable`, or `not-applicable` |
| `scanned-revision` | The commit the checkout recorded, if readable |
| `scanner-version`, `ruleset` | What produced the report |
| `scanner-source` | `action-checkout` or `workspace` |
| `action-pinned` | `true` only when the Action was referenced by a full 40-character commit SHA |
| `ignored-environment-count` | How many inherited build settings (for example `CARGO_HOME`, `BASH_ENV`) were present and ignored |

## What revision is scanned

Whatever the earlier checkout step put in the directory. With `actions/checkout` on `pull_request` and no `ref`, that is the merge result of the pull request and its base (`github.sha`). Setting `ref: ${{ github.event.pull_request.head.sha }}` on the checkout scans the pull request head instead. The Action reads the checked-out commit from `.git`, without running Git, and compares it with the expected merge commit and head commit from the trusted event context:

- `matches-merge` or `matches-head`: reported as that one revision. The summary never claims both were scanned.
- `mismatch`: the checkout is neither (for example a stale or wrong ref). The job **fails** with status `error`.
- `unavailable`: the scanned directory has no readable `.git` (for example a subdirectory). The scan runs and the summary says the revision could not be checked.
- `not-applicable`: the event has no expected revision (for example `push`).

The revision comes from `.git` files in the checkout, which are what the checkout claims, not a verified identity.

## Meaning of the results and how they appear

| Status | Meaning | Step result | Summary |
| --- | --- | --- | --- |
| `clean` | The supported checks completed and found nothing | success | "No findings in the supported checks", plus a reminder that this is not proof of safety. If `files-inspected` is 0 it says nothing was checked |
| `findings` | At least one rule matched | success (advisory) | "Findings require review", a table of matched rules and findings, and a warning annotation |
| `incomplete` | An inspection could not finish, or a rule hit an analysis limit | success (advisory) | "Incomplete: this is not a pass", with each reason, and a warning annotation |
| `error` | The scanner could not run, crashed, timed out, produced output that cannot be trusted, exited with a code that does not match its report, or the checkout is the wrong revision | **failure** | "Error: results cannot be trusted" |

A green check means only that the job ran. It is never evidence that a pull request is safe.

## Permissions and supported platforms

The Action needs no token permissions of its own. Use `permissions: contents: read` (the minimum for `actions/checkout`) and no secrets. It supports GitHub-hosted Ubuntu runners on x86-64 only (`ubuntu-24.04` is the one tested), because the scanner's race-resistant file access is verified only there. The Action enforces this at run time and refuses self-hosted, non-Linux, non-Ubuntu, and ARM runners. It never uses the network for anything except downloading the pinned Rust toolchain and the locked crates.

The build downloads the pinned Rust toolchain and the locked crates, which takes a few minutes on a cold runner and needs network access to `static.rust-lang.org` and `crates.io`.

## Fork pull requests

On `pull_request` from a fork the token is read-only and secrets are not available, which suits this Action. GitHub may require approval before workflows run for some first-time contributors. Because nothing is written back to the pull request, results appear only in the job summary and annotations of that run.

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

The case of a separately checked-out Action directory (`scanner-source: action-checkout`) is covered by the mocked and simulated tests only. Verifying it on GitHub needs a real pinned reference, which does not exist yet.

## Trial results

`.github/workflows/action-trial.yml` runs the Action as `MergeLatch/mergelatch@0d3ef392b1f18f264ea96d2d8f4796eead4857cc` (never `uses: ./`) on a GitHub-hosted `ubuntu-24.04` runner, in this repository, on pull request #8 (run 40091227897). The terms used below:

- **Verified source commit:** `0d3ef392b1f18f264ea96d2d8f4796eead4857cc`, the merge commit of the reviewed Action. It contains `action.yml`, the helper, the Rust source, and `Cargo.lock`.
- **Trial-tested commit:** the same commit, as GitHub downloaded and ran it.
- **Published release:** none.

What was observed on GitHub (real execution, not mocks):

| Check | Result |
| --- | --- |
| Separate download | The runner log shows `Download action repository 'MergeLatch/mergelatch@0d3ef39…' (SHA:0d3ef39…)`. The trial step finds it at `_actions/MergeLatch/mergelatch/<sha>`, outside the workspace, and the SHA-256 of `action.yml`, the helper, `build.sh`, and `Cargo.lock` match the reviewed files. |
| Scanner built from that directory | `Compiling mergelatch-core … (/home/runner/work/_actions/MergeLatch/mergelatch/0d3ef39…/crates/core)`, and `rustup` reports the toolchain is "overridden by" that directory's `rust-toolchain.toml`. |
| Provenance outputs | `scanner-source` = `action-checkout`, `action-pinned` = `true`, scanner version `0.1.0`, ruleset `mergelatch-builtin-1`. |
| Clean | Scanning the pull request checkout: status `clean`, exit code 0, step succeeded, summary says it is not proof of safety, revision matched the merge commit. |
| Findings | The `write-all` fixture: 1 finding, exit code 1 preserved, step succeeded, finding listed in the summary. |
| Incomplete | The malformed fixture: exit code 2 preserved, step succeeded, summary says "Incomplete: this is not a pass". |
| Error | A missing directory, and a run with no checkout at all: the step failed, status `error`. |
| Revision | A checkout of the pull request head reported `matches-head`; a checkout of the base commit reported `mismatch` and the step failed. |
| Hostile input | A fixture of inert build files was scanned as data. With hostile `BASH_ENV`, `CARGO_HOME`, linker, compiler-wrapper, and rustup settings in the step's environment the build still succeeded, the Action reported them as ignored, and no `HOSTILE_*` marker appeared. A control bash step with `BASH_ENV` did run its marker, so the check is meaningful. |

Measured on that run (one cold runner): total run 46 s, trial job 41 s, the job with no checkout 5 s. The first Action invocation took 27.0 s to build the scanner on a cold runner, which includes about 8 s to install the pinned toolchain (5 components) and 18.4 s to download and compile the locked crates in release mode; later builds in the same job took about 0.2 s because the target directory was reused. A scan itself took about 0.05 s. These are single measurements, not averages.

Gaps found by reading the real summaries, fixed in a later commit but **not** present in the trial-tested commit:

- The summary said the Action was pinned but did not print the SHA. It now prints `repository@sha` and sets an `action-revision` output.
- An error before any scan said "no expected revision for this event". It now reports `not-checked`.
- A run whose preparation failed early described the scanner source as pinned. It now reports `unknown`.

These are verified for the local Action in the smoke test. Verifying them for a pinned Action needs a newer reviewed commit to pin.

Not verified, and not measured:

- Use from a separate consumer repository. Only this repository has been tried.
- A pull request from a fork. GitHub's approval policy for workflow runs from forks applies and was not exercised.
- Behavior when GitHub cannot download the Action (for example an outage). The job would fail at setup before any step runs; this was not simulated.
- A build that fails on a cold runner (for example if the Rust distribution server is unreachable). The failure path is covered by mocked tests, which report status `error` and fail the step, but was not triggered on GitHub.
- Network dependencies, from the logs: GitHub (the Action download), the Rust distribution server (the pinned toolchain), and the crates registry (the locked crates).

## Known limitations

- Narrow coverage: four rules on workflow files only. See [RULES.md](RULES.md) for false positives and negatives.
- Escaping removes markup and control characters but cannot stop look-alike (confusable) characters in file names from misleading a reader.
- The revision check trusts the checkout's `.git` files.
- Filesystem and platform limits of the scanner (Linux only, residual races) apply. See the threat model.
- The Python helper, the build, and the downloaded toolchain and crates are part of the trusted computing base.
- The runner's own Rust installation (`~/.cargo/bin`, `~/.rustup`, and any `config.toml` in `~/.cargo`) and the system Python and bash are trusted. A previous step that runs untrusted code in the same job could modify them or the files the runner uses to carry settings between steps (`GITHUB_ENV`, `GITHUB_PATH`); run this Action before any step that executes pull request code, and do not add such steps to the same job.
- `LD_*` and `GCONV_PATH` are detected, not neutralized: by the time the Action can see them, the loader has already acted on them. The Action fails closed instead of continuing.
- Settings are removed by building the child environment from fixed values. Settings that change how the already-running Python behaves, other than `PYTHON*` (ignored by `-I`) and the loader variables above, are not known and are not checked.
- The runner restrictions rely on the runner context and `/etc/os-release`. They stop honest misconfiguration, not a self-hosted runner built to lie.

## Release and SHA-pinning process (not yet done)

1. Independent review of this change, including the helper and the workflows.
2. Merge. Run the smoke test and a controlled advisory trial in a repository that is not otherwise protected by it.
3. Cut a release from a reviewed commit and record its **full 40-character SHA**. Verify the SHA against the repository before publishing it.
4. Consumers pin that SHA and nothing else. The example currently names the trial-tested merge commit, not a release. Updates are made by reviewing a newer commit and changing the whole SHA, never by following a branch or tag.
5. Optionally extract `action.yml`, `action/`, and the scanner source (or checksummed release binaries) into a separate `mergelatch-action` repository after the above. The extraction must keep `Cargo.lock` and `rust-toolchain.toml` with the source it builds, and must repeat the review and the SHA pinning for the new location. That repository does not exist yet.
