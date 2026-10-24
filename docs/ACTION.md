# MergeLatch advisory GitHub Action

**Status:** implemented in this repository, not yet released, and **advisory only**. There is no reviewed commit to pin yet, so the example workflow in `docs/examples/pull-request-scan.yml` is not runnable. It is a placeholder to be completed after a reviewed release. This Action is not a merge gate and must not be made a required check (see [Why this is not a merge gate](#why-this-is-not-a-merge-gate)).

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

- The scanner is built with `cd` into the Action directory first, so `rustup` reads the Action's `rust-toolchain.toml` and `cargo` reads the Action's configuration. Variables that could redirect the toolchain or build (`RUSTUP_TOOLCHAIN`, `RUSTFLAGS`, `RUSTC_WRAPPER`, `CARGO_TARGET_DIR` and similar) are cleared. The build is `--locked`.
- The scanned directory is only ever an argument to the finished binary. It is validated first: it must be a relative path without `..`, must resolve (after symlinks) inside the workspace, and must exist. A workspace without a `.git` entry is an error, so a forgotten checkout cannot produce an empty "clean" result.
- The scanner runs with an empty environment (no tokens, no `GITHUB_*` values), from a private state directory, with a time limit and an output size limit.
- Inputs and GitHub context reach the scripts only through environment variables, never inside a shell command. Pull request titles, bodies, branch names, and file names are not used for anything executable.
- Everything in the scanner's report is treated as untrusted. It is validated against the report schema (types, enums, counts, and consistency between the status and the lists), then truncated and Markdown/HTML-escaped before it enters the job summary. Control and bidirectional-format characters are shown as `\u{..}`. Nothing from the report is written to the workflow log.
- The Action refuses to run on `pull_request_target` and `workflow_run`, which give workflows secrets or a write-capable token.
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

The Action needs no token permissions of its own. Use `permissions: contents: read` (the minimum for `actions/checkout`) and no secrets. It supports GitHub-hosted `ubuntu-24.04` runners only, because the scanner's race-resistant file access is verified only on Linux. Other runners are not supported and the scanner refuses to run on other platforms.

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
| Mocked | Report validation, exit-code consistency, truncated and malformed output, large reports, escaping of hostile strings, input validation, scanner invocation with a fake binary, the build script with fake `rustup` and `cargo`, output-writing failures |
| Real scanner, simulated GitHub | The same steps against the real `mergelatch` binary on fixtures, including unusual file names, a hostile-build-files fixture, stale revisions, and an invalid target. The GitHub environment is plain files |
| Static | `action.yml` and every workflow: read-only tokens, no secrets, no privileged triggers, SHA-pinned external Actions, `persist-credentials: false`, no expressions in `run:` text |
| GitHub-hosted run | `.github/workflows/action-checks.yml` runs the composite Action with `uses: ./` on a hosted runner. This executes the unreviewed implementation and is read-only, with no secrets and no enforcement role. It does not prove that consumers using a released, SHA-pinned Action are protected |

The case of a separately checked-out Action directory (`scanner-source: action-checkout`) is covered by the mocked and simulated tests only. Verifying it on GitHub needs a real pinned reference, which does not exist yet.

## Known limitations

- Narrow coverage: four rules on workflow files only. See [RULES.md](RULES.md) for false positives and negatives.
- Escaping removes markup and control characters but cannot stop look-alike (confusable) characters in file names from misleading a reader.
- The revision check trusts the checkout's `.git` files.
- Filesystem and platform limits of the scanner (Linux only, residual races) apply. See the threat model.
- The Python helper, the build, and the downloaded toolchain and crates are part of the trusted computing base.

## Release and SHA-pinning process (not yet done)

1. Independent review of this change, including the helper and the workflows.
2. Merge. Run the smoke test and a controlled advisory trial in a repository that is not otherwise protected by it.
3. Cut a release from a reviewed commit and record its **full 40-character SHA**. Verify the SHA against the repository before publishing it.
4. Consumers replace the placeholder in the example with that SHA and nothing else. Updates are made by reviewing and changing the SHA, never by following a branch or tag.
5. Optionally extract `action.yml`, `action/`, and the scanner source (or checksummed release binaries) into a separate `mergelatch-action` repository after the above. The extraction must keep `Cargo.lock` and `rust-toolchain.toml` with the source it builds, and must repeat the review and the SHA pinning for the new location. That repository does not exist yet.
