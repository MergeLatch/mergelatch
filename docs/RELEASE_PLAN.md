# Proposed release plan: `v0.1.0-rc.1`

**Status: proposal. Nothing in this plan has been executed.** No tag, GitHub release, or pre-release exists in this repository or in `mergelatch-consumer-trial` (checked on 2026-10-24: zero tags, zero releases). Creating one needs the maintainer's explicit approval at the step marked below, after the blockers in [REVIEW_READINESS.md](REVIEW_READINESS.md#outstanding-release-blockers) are closed.

The Action stays **advisory** in this release: it is not a merge gate and must not be a required check.

## What would be released

A source tag for the repository, whose `action.yml` consumers reference by full commit SHA. There are no binaries, packages, or installers. The scanner is built from source on the consumer's runner, so there is nothing to checksum except the source itself. `v0.1.0-rc.1` would be a label for a commit. The commit SHA is what a consumer pins.

The scanner reports its version as `0.1.0` (from `Cargo.toml`), not `0.1.0-rc.1`. Changing that would change `Cargo.toml` and `Cargo.lock`, which are part of the trusted implementation, for a cosmetic reason, so this plan leaves them alone. The release notes must say so.

## The commit to tag

### What has been tested

| Commit | Role | Run as a pinned Action on GitHub |
| --- | --- | --- |
| `afc7e65d6723029c22935f82c7fc9562d5831565` | Implementation tested: in this repository, in `mergelatch-consumer-trial`, and on a first-time external fork pull request | **Yes** (runs listed in [REVIEW_READINESS.md](REVIEW_READINESS.md#verification-evidence)) |
| `4af8f9aa9340fee38abb7c9f3b554c53ad645d64` | `main` when the review package was prepared | **No.** No run pinned this SHA |
| `2a1a514b94754b146a690cf98ef59bc649d423ff` | Corrected D-1 event allowlist: in-repository, external consumer, rejected event, and first-time external fork PR (README only) | **Yes** ([verification evidence](REVIEW_READINESS.md#verification-evidence), including [fork run 40112702817](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40112702817)) |
| Earlier review-readiness commits (apart from the separately verified D-1 SHA above) | Documentation and tests | **Not recorded as separately pinned** |

### Differences from the tested commit

Between `afc7e65…` and `4af8f9a…` six files changed: `.github/workflows/action-trial.yml`, `README.md`, `action/tests/test_static.py`, `docs/ACTION.md`, `docs/EXTERNAL_TRIAL.md`, and `docs/examples/pull-request-scan.yml`. The review-readiness change adds documentation and `action/tests/test_real_scanner.py`.

None of these paths is built or run by a consumer's job. The seven implementation paths (`action.yml`, `action/mergelatch_action.py`, `action/build.sh`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `crates/`) have identical git object IDs at both commits. **So the differences do not touch the trusted implementation.** This is a property of identical files that anyone can recheck:

```
git diff --quiet afc7e65d6723029c22935f82c7fc9562d5831565 <candidate> -- \
  action.yml action/mergelatch_action.py action/build.sh Cargo.toml Cargo.lock rust-toolchain.toml crates \
  && echo "implementation identical"
```

It does not make the candidate SHA a tested immutable Action. A SHA is a distinct reference, and GitHub downloads, resolves, and reports it separately. The plan therefore runs the consumer trial against the candidate's own SHA before tagging (step 6). It does not rely on the identity of files alone.

### Options

| Option | Commit | Assessment |
| --- | --- | --- |
| A | Tag `afc7e65…` itself | Exactly the tested SHA. But that commit's README, `SECURITY.md`, and threat model still say the scanner and Action do not exist, and its docs say no external trial happened. A release that carries those statements misleads. Not recommended |
| B (recommended) | A later commit on `main`, after the review and the decisions D-1 to D-4 | Correct docs. If the implementation paths are unchanged, the Action is byte-identical to the tested one, and step 6 gives the candidate SHA its own run. If any implementation path changed, the commit is a new implementation and the full re-verification below applies |

The exact candidate is chosen when the blockers close. It is not named here because it does not exist yet, and this document does not claim otherwise.

### The implementation has changed (D-1)

Decision D-1 has been implemented: `action/mergelatch_action.py` now accepts only the `pull_request` event. Any commit that contains it is a new implementation. The procedure below therefore applies to the candidate; `afc7e65…` remains the evidence for the earlier implementation only. Status of those checks for `2a1a514b94754b146a690cf98ef59bc649d423ff` (merge of #12): steps 1 and 2 are done (in-repository run 40106718920 and consumer run 40106918299, both on GitHub and inspected); the `workflow_dispatch` rejected-event run in step 3 is **done** (run [40108606160](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40108606160): the Action failed as intended and the assertions passed); step 4 (README-only external fork) is **done** ([consumer PR #6](https://github.com/MergeLatch/mergelatch-consumer-trial/pull/6), [run 40112702817](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40112702817), after maintainer approval; workflow-editing fork not tested); step 6 is done in [ACTION.md](ACTION.md#verification-status). Independent review and a release remain pending; this evidence does not make the Action release-ready.

### If an implementation path changes

The previously verified SHA `afc7e65…` then no longer represents the corrected implementation. Targeted re-verification, for the new commit `N`, before it is tagged:

1. Re-pin `.github/workflows/action-trial.yml` to `N`, recompute the file hashes with `git show N:<path>` (never from a working copy), and run it in this repository. Read the rendered summary: the full `MergeLatch/mergelatch@N` must be visible.
2. Run the separate consumer repository pinned to `N` and confirm the same assertions as for `afc7e65…` (clean, one finding, incomplete, `action-checkout`, full SHA, `matches-merge`).
3. Add tests for the change, and for a changed event guard, a GitHub run that proves a refused event is refused (for example a `workflow_dispatch` run if the guard becomes an allowlist). Unit tests alone are not enough for that claim.
4. A fork pull request is repeated only if the change touches what a fork run depends on (event handling, token use, or the trigger). Otherwise the recorded fork run remains evidence for the unchanged parts and is described as such.
5. Do not rerun unchanged parts repeatedly.
6. Update [ACTION.md](ACTION.md) and [REVIEW_READINESS.md](REVIEW_READINESS.md) with the new SHA, hashes, and run links, and keep the `afc7e65…` history.

If the change fixes an exploitable defect, use the private process in [Vulnerability reporting](#vulnerability-reporting-and-rollback) and do not describe the defect publicly before the fix is available.

## Required approvals

All of these, recorded in [REVIEW_READINESS.md](REVIEW_READINESS.md#sign-off), before step 7:

- An **independent human reviewer**, qualified to review GitHub Actions and Rust supply-chain risk, records the SHA they examined and their conclusions. An AI agent's analysis does not count.
- The **maintainer** records decisions D-1 to D-4 and the reasons.
- The **maintainer** approves this plan and the chosen candidate SHA in writing, in a pull request or comment on the repository.
- Findings from the review are closed, or recorded as accepted with a reason. Any exploitable finding is fixed through a private advisory first.

## CI and audit requirements for the candidate commit

- `fmt, clippy, test` (the required check) is green on the candidate.
- `Action checks` (lint, unit tests, smoke test) is green on the candidate.
- Locally or in CI: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo audit --deny warnings` with a freshly updated advisory database on the day of tagging (the audit is not run in CI, so its result is recorded in the release notes with the date), the Python tests with the real binary, `actionlint`, `shellcheck`.
- The repository's security alerts (Dependabot, secret scanning, code scanning if enabled) are read and have no open items that concern the Action's dependencies. The settings themselves are not changed.
- The consumer-trial run for the candidate SHA (step 6) is green.

## Integrity and provenance evidence for the release notes

- The full 40-character candidate SHA, the output of the `git diff` command above, and the git object IDs of the seven implementation paths.
- The SHA-256 of `action.yml`, `action/mergelatch_action.py`, `action/build.sh`, and `Cargo.lock`, computed with `git show <sha>:<path> | sha256sum`, matching the values the trial workflow asserts.
- Links to the runs: the in-repository trial, the consumer repository, the fork pull request, and the candidate's own consumer run. For each, say what it did and did not show.
- The independent review reference and its SHA.
- The `cargo audit` result and date, the pinned toolchain (`rust-toolchain.toml`), and the number of locked crates.
- A signed annotated tag if the maintainer has a signing key (recommended, so GitHub shows it as verified); otherwise an annotated tag. A tag is movable unless protected; the release notes and consumers rely on the SHA, not the tag.
- A statement that bit-for-bit reproducibility of the built scanner was not checked, that no binary is published, and that the build trusts rustup, the Rust distribution servers, and crates.io.

## Consumer SHA-pinning instructions

For the release notes and README, once a release exists. Until then the example in `docs/examples/pull-request-scan.yml` is the only guidance and names the tested commit.

```yaml
# Replace <FULL-40-CHARACTER-SHA> with the commit SHA from the release notes,
# checked against https://github.com/MergeLatch/mergelatch. Do not use a tag or branch.
- uses: MergeLatch/mergelatch@<FULL-40-CHARACTER-SHA>
```

- Pin the **full 40-character SHA**. A tag such as `v0.1.0-rc.1` is a label and can be moved or deleted. The Action reports `action-pinned=false` and labels the run "NOT a full commit SHA" when a tag or branch is used.
- Use the workflow in the example: `pull_request` only, `permissions: contents: read`, no secrets, `ubuntu-24.04`, a SHA-pinned `actions/checkout` with `persist-credentials: false`, the Action before any step that runs pull request code.
- Update by reviewing the newer commit and changing the whole SHA. Do not follow a branch or tag, and be careful with bots that rewrite SHAs unreviewed.
- Do not make the check required. A pull request can edit the workflow that calls it.
- Read `revision-check`, and scan the workspace root if a revision check matters (see [ACTION.md](ACTION.md#events)).

## Supported platforms and known limitations

Supported: GitHub-hosted `ubuntu-24.04`, x86-64, the `pull_request` event, `contents: read`. Refused at run time: other events (D-1), self-hosted, Windows, macOS, and ARM runners. Untested: private-repository behavior and GitHub Enterprise Server.

The full list of limitations is in [REVIEW_READINESS.md](REVIEW_READINESS.md#known-limitations) and [ACTION.md](ACTION.md#known-limitations). The release notes must repeat at least these: advisory only; four narrow rules on workflow files; no malware scanning; findings and incomplete scans do not fail the step; the caller's workflow can be edited by a pull request; the toolchain and crates are downloaded and built on every run; Windows Sentinel and Agent Guard do not exist; this is a pre-release.

## Vulnerability reporting and rollback

**Reporting.** `SECURITY.md` points to GitHub private vulnerability reporting (enabled when this was checked). Reporters are asked for the full commit SHA. The release notes link to it.

**If a defect is found after a tag exists:**

1. Do not move, re-point, or delete the tag to hide the history. A consumer pinned to a SHA is unaffected by tag changes, and moving a tag only misleads consumers who rely on it.
2. Mark the release as withdrawn in its notes (edit the notes and keep it marked pre-release) and say which commit SHAs are affected.
3. For an exploitable defect, work in a private security advisory and its temporary private fork, publish the advisory with the fix, and name the fixed commit SHA and affected SHAs.
4. Cut the fix as a new commit and, if wanted, a new candidate tag (`v0.1.0-rc.2`), after the targeted re-verification above.
5. Tell consumers to replace their pinned SHA. Nothing can update them, and a SHA cannot be revoked by the project, so they remain pinned to the vulnerable code until they change it.

**Rollback for a consumer** is changing the pinned SHA to an earlier reviewed one, or removing the step. Because the Action is advisory, removing it changes no protection that was enforced.

## Execution steps (not executed)

Each step is a separate decision for the maintainer. Stop at the first failure.

1. Close the blockers in [REVIEW_READINESS.md](REVIEW_READINESS.md#outstanding-release-blockers) and record the sign-offs.
2. Decide D-1 to D-4. Implement any chosen change through a normal pull request and a private advisory if it is a security fix.
3. Choose the candidate commit on `main`. Record its SHA and run the `git diff` command above.
4. Run the CI and audit requirements for that SHA.
5. Update the documentation to name the candidate SHA only where it is true. Do not claim that the candidate was run as a pinned Action yet.
6. Run the consumer trial against the candidate SHA (the procedure in [EXTERNAL_TRIAL.md](EXTERNAL_TRIAL.md)) and record the run. If the implementation changed, do the targeted re-verification as well.
7. **Maintainer approval to create the tag.** Create a signed annotated tag `v0.1.0-rc.1` on the candidate SHA, and a GitHub **pre-release** with the notes above. Not auto-generated, not auto-published.
8. Verify from outside: the tag resolves to the SHA; the notes' hashes match `git show`; the example snippet names the same SHA.
9. Update `README.md` and `docs/examples/pull-request-scan.yml` to name the released SHA, in a separate pull request.

Nothing in this plan changes repository settings, rulesets, required checks, or auto-merge. Branch and tag protection are the maintainers' decisions and are not made here.
