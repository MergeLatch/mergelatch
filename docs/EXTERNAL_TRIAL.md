# External consumer and fork trial

**Status: performed on 2026-10-24** for the Action commit `afc7e65d6723029c22935f82c7fc9562d5831565`, in the separate repository `MergeLatch/mergelatch-consumer-trial`. Results are below, with what they do not show. The procedure that follows the results is kept so the trial can be repeated for a later commit.

This was a trial of one commit in one disposable repository with one external account. It is evidence that the SHA-pinned Action works from outside the MergeLatch repository and that GitHub gated a first-time fork contributor's run. It is not a release test and not a security audit.

## Results

All facts below were checked against GitHub's own records (the runs, pull requests, job logs, and repository settings through the API) when this document was written.

### The repository

| Item | Observed |
| --- | --- |
| Repository | https://github.com/MergeLatch/mergelatch-consumer-trial, public, not a fork, not archived |
| Contents | A `pull_request` workflow (`.github/workflows/mergelatch.yml`) and inert fixtures under `fixtures/`. The workflow requests `permissions: contents: read`, runs on `ubuntu-24.04`, uses `actions/checkout` pinned by SHA with `persist-credentials: false`, and uses `MergeLatch/mergelatch@afc7e65d6723029c22935f82c7fc9562d5831565` four times |
| Settings | Default workflow permissions are read-only, no secrets, no rulesets, no branch protection. No setting was changed for this trial |
| Collaborators | One (the maintainer). The fork account is not a collaborator |

### Consumer run (same organization, not a fork)

Run [40099476256](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40099476256): event `pull_request`, pull request #1 (opened by the maintainer, a member of the organization; later merged by them into this disposable repository), head `3bca17d165c9fbd5c632ac38419dfe45d83968e2`. Conclusion: success.

| Check | Result |
| --- | --- |
| Separate download | The log shows `Download action repository 'MergeLatch/mergelatch@afc7e65d6723029c22935f82c7fc9562d5831565'` |
| Real repository checkout | `clean`, scanner exit 0, `revision-check` = `matches-merge`, `scanned-revision` equal to `github.sha` |
| Clean fixture | `clean`, exit 0 |
| Unsafe-permissions fixture (`permissions: write-all`) | `findings`, exactly 1 finding, exit 1, the step itself succeeded (advisory) |
| Malformed fixture | `incomplete`, exactly 1 incomplete entry, exit 2, the step itself succeeded |
| Provenance, all four invocations | `scanner-source` = `action-checkout`, `action-revision` = the full 40-character SHA, `action-pinned` = `true` |

These were asserted by a workflow step that fails the job on any mismatch; the step passed.

### Fork pull request

| Item | Observed |
| --- | --- |
| Pull request | [#2](https://github.com/MergeLatch/mergelatch-consumer-trial/pull/2), from the fork `ZeePearl56/mergelatch-consumer-trial`, branch `test/external-fork-pr`, head `029956056918effe39d0d032e67db74ac6f7fcdb` |
| Contributor | `ZeePearl56`. GitHub records the author association as `NONE`: not a member, collaborator, or previous contributor |
| What it changed | `README.md` only, two added lines. It did not touch `.github/` |
| First attempt | Run [40100818227](https://github.com/MergeLatch/mergelatch-consumer-trial/actions/runs/40100818227), attempt 1: conclusion `action_required`, triggered by the contributor, **no jobs ran**. The workflow waited for a maintainer |
| After approval | Attempt 2, triggered by the maintainer, ran on the proposed merge commit and succeeded. The log shows the same `Download action repository 'MergeLatch/mergelatch@afc7e65…'` line and the workflow's assertions passed: `scanner-source` = `action-checkout`, `action-revision` = the full SHA, `revision-check` = `matches-merge`, findings and incomplete outcomes as above |
| Token | The setup log shows `Contents: read`, `Metadata: read`, `Secret source: None` |
| Outcome | The pull request was closed without merging. The fork and the trial repository were not deleted or archived when this was checked |

### What these runs do not show

- **A contributor who edits the workflow.** The fork pull request changed only a README line, so it did not try to remove, weaken, or redirect the MergeLatch step. That bypass is a known design limit (see [ACTION.md](ACTION.md#why-this-is-not-a-merge-gate)) and was not exercised on GitHub.
- **Who reviewed what before approval.** GitHub records that the second attempt was triggered by the maintainer. It does not record that the contributed files were read first. The pull request's file list (checked afterwards) shows only a README change.
- **GitHub's fork-approval setting.** GitHub's API does not expose it for public repositories, so the exact policy in force was not read. The observed behavior (`action_required` for an author association of `NONE`) is consistent with the default for first-time contributors. Other contributor histories, private repositories, and organization-level policies may behave differently.
- **The rendered job summary of the external runs.** The summaries were not re-read in a browser for these runs. The full-SHA rendering was verified for the in-repository trial ([ACTION.md](ACTION.md#verification-status)); in the external runs the same values were asserted from outputs.
- **A different runner image, other events, or failures.** Only `ubuntu-24.04`, only `pull_request`, no GitHub-side download failure, and no failed cold build.
- **The new commit.** Later commits of MergeLatch were not run as an external Action. See "Which commit was tested" in [ACTION.md](ACTION.md#verification-status).

## Procedure for repeating the trial

Use this for a later commit, or to check a changed GitHub policy.

### What to set up

- **Repository.** A public, disposable repository that holds nothing else. Creating it and deciding who owns it is a maintainer decision.
- **Permissions.** Actions enabled with the default read-only workflow permissions. No secrets, no deploy keys, no environments. Do not change the fork-workflow approval settings; the point is to see the defaults.
- **SHA.** The full commit being tried. Check it against the MergeLatch repository before use.
- **Second account for the fork test.** A GitHub account that is not a collaborator on the trial repository, owned by someone willing to take part. Note whether it has a history in the repository or is a first-time contributor, because GitHub's approval policy differs.

### Minimal workflow

Copy `docs/examples/pull-request-scan.yml` to `.github/workflows/mergelatch.yml` on the default branch. It names a full SHA, `pull_request`, `permissions: contents: read`, `ubuntu-24.04`, and a pinned `actions/checkout` with `persist-credentials: false`. For the trial, use the Action step several times with different `scan-directory` values (see the fixtures below), keep `continue-on-error` off, and add a final step that reads the outputs through `env`, never inside a script, and fails on any mismatch.

### Harmless fixtures

Put the fixtures in sub-directories of the default branch, so that GitHub never runs them as workflows (it only runs workflow files at the repository root):

| Directory | Contents | Expected advisory result |
| --- | --- | --- |
| `fixtures/clean/.github/workflows/ci.yml` | `on: pull_request`, `permissions: {contents: read}`, one job with `run: echo hello` | `clean`, exit 0, step green |
| `fixtures/finding/.github/workflows/ci.yml` | the same, but `permissions: write-all` | `findings`, 1 finding (ML-GHA-001), exit 1, step green |
| `fixtures/incomplete/.github/workflows/ci.yml` | malformed YAML, for example `permissions: [write-all` | `incomplete`, exit 2, step green, "this is not a pass" |

The pull requests themselves should change only a README line, so the fork test stays harmless. To test a contributor who edits the workflow, do it in a separate, clearly labelled pull request on the disposable repository, and record that the result is the expected bypass.

### What to check on each run

1. The log shows `Download action repository 'MergeLatch/mergelatch@<sha>'` for the full SHA, and the scanner is compiled from `_actions/MergeLatch/mergelatch/<sha>/`, not from the trial repository.
2. The rendered job summary shows `MergeLatch/mergelatch@<full sha>` in full, `Scanner source` as pinned at the full commit SHA, and the expected merge commit and head commit.
3. Outputs: `status`, `findings-count`, `scanner-source` (`action-checkout`), `action-pinned` (`true`), `action-revision` (the full SHA), and `revision-check` (`matches-merge`).
4. The token is read-only and no secrets are present (the setup log lists the token permissions).

### Fork pull request

1. From the second account, fork the trial repository and open an ordinary pull request that changes a README line.
2. Record, without changing any setting: whether the workflow started or waited for approval and what GitHub showed; who approved it; that the changes to `.github/` were read before approving; whether the Action downloaded and ran; the revision check; and that the token was read-only with no secrets.
3. If approval is not possible or the workflow does not run, record that as the result. Do not approve a run before reading what the pull request changes in `.github/`.

### Recording the result

Write down the repository, the run URLs, the SHA, the date, who took part, and exactly what was observed, including anything that went wrong and anything not checked. Add it to [ACTION.md](ACTION.md) only after it has happened.

### Cleanup

Close the trial pull requests, ask the second account to delete its fork, and archive or delete the trial repository when it is no longer needed. Nothing here should remain as a template for others to copy blindly.
