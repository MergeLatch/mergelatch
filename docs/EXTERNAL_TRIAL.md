# External consumer trial procedure

**Status: not performed.** No separate repository has been designated or authorized for this trial. This document is a procedure for a maintainer to follow once one is. A run inside the MergeLatch repository does not count as an external consumer test, and neither does a repository used for another project.

The aim is to show that a repository that does not contain MergeLatch can run the advisory Action by its full commit SHA, and to observe what GitHub does with a pull request from a fork.

## What to set up

- **Repository.** A new, public, disposable repository that holds nothing else. Proposed name: `mergelatch-consumer-trial`, owned by the maintainer or the MergeLatch organization. It has not been created. Creating it is a maintainer decision.
- **Permissions.** Actions enabled with the default read-only workflow permissions. No secrets, no deploy keys, no environments, no branch protection changes elsewhere. Do not change the fork-workflow approval settings; the point is to see the defaults.
- **SHA.** The full commit that is being tried, currently `afc7e65d6723029c22935f82c7fc9562d5831565`. Check it against the MergeLatch repository before use.
- **Second account for the fork test.** A GitHub account that is not a collaborator on the trial repository, owned by someone willing to take part. Note whether it is a person with a history in the repository or a first-time contributor, because GitHub's approval policy differs.

## Minimal workflow

Add `.github/workflows/mergelatch.yml` to the trial repository's default branch, copied from `docs/examples/pull-request-scan.yml` in MergeLatch. It already names the verified full SHA, `pull_request`, `permissions: contents: read`, `ubuntu-24.04`, and a pinned `actions/checkout` with `persist-credentials: false`. For the trial, copy the Action step three times with different `scan-directory` values (see the next section), keeping `continue-on-error` off.

## Harmless fixtures

Put the fixtures in sub-directories of the default branch, so that GitHub never runs them as workflows (it only runs workflow files at the repository root):

| Directory | Contents | Expected advisory result |
| --- | --- | --- |
| `fixtures/clean/.github/workflows/ci.yml` | `on: pull_request`, `permissions: {contents: read}`, one job with `run: echo hello` | `clean`, exit 0, step green |
| `fixtures/finding/.github/workflows/ci.yml` | the same, but `permissions: write-all` | `findings`, 1 finding (ML-GHA-001), exit 1, step green, "Findings require review" |
| `fixtures/incomplete/.github/workflows/ci.yml` | malformed YAML, for example `permissions: [write-all` | `incomplete`, exit 2, step green, "this is not a pass" |

The pull requests themselves change only a README line, so the fork test stays harmless.

## What to check on each run

1. The log shows `Download action repository 'MergeLatch/mergelatch@<sha>'` for the full SHA, and the scanner is compiled from `_actions/MergeLatch/mergelatch/<sha>/`, not from the trial repository.
2. The rendered job summary shows `MergeLatch/mergelatch@<full sha>` in full, `Scanner source` as pinned at the full commit SHA, and the expected merge commit and head commit.
3. Outputs, if the example's last step is kept: `status`, `findings-count`. For a deeper check, add a step that prints `scanner-source` (`action-checkout`), `action-pinned` (`true`), `action-revision` (the full SHA), and `revision-check` (`matches-merge`) through `env`, never inside a script.
4. The token is read-only and no secrets are present (the workflow defines none).

## Fork pull request

1. From the second account, fork the trial repository and open an ordinary pull request that changes a README line. Harmless changes only. If you also want to see a finding from fork content, change `fixtures/finding` in the fork's pull request and point a step at it.
2. Record, without changing any setting:
   - whether the workflow started automatically or waited for approval, and the text GitHub showed;
   - who approved it, and that the contributed workflow file was reviewed before approving;
   - whether the Action downloaded and ran, and whether the summary shows the fork's merge commit as `matches-merge`;
   - that the token was read-only and that no secrets were available;
   - that a finding leaves the step green and is labelled "Findings require review".
3. If approval is not possible or the workflow does not run, record that as the result. Do not approve a run before reading what the pull request changes in `.github/`.

Distinguish a fork opened by an existing trusted contributor from one opened by a genuinely external account: GitHub's approval rules can differ between them, and one does not stand in for the other.

## Recording the result

Write down the repository, the run URLs, the SHA used, the date, who took part, and exactly what was observed, including anything that went wrong. Add it to `docs/ACTION.md` under "Verification status" only after it has actually happened.

## Cleanup

Close the trial pull requests, delete the trial branches and fixtures, ask the second account to delete its fork, and archive or delete the trial repository. Nothing here should remain as a template for others to copy blindly.
