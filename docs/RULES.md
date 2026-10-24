# MergeLatch rules

This document describes each rule in the built-in ruleset: what it detects, what it does not, how to read a finding, and where it can be wrong. The rules inspect `.github/workflows/*.yml` and `*.yaml` at the root of the scanned directory by parsing the YAML. They read text only and never run anything.

None of these rules proves that a workflow is vulnerable or that anyone has attacked it. A finding is a configuration worth reviewing. A clean result means these specific checks found nothing, not that the workflow is safe. MergeLatch is not an antivirus and is not a complete GitHub Actions security scanner.

Run `mergelatch rules` to list the rules in the version you have.

| ID | Severity | Summary |
| --- | --- | --- |
| ML-GHA-001 | medium | Explicit `permissions: write-all` |
| ML-GHA-002 | medium | External action, reusable workflow, or Docker image not pinned to an immutable revision |
| ML-GHA-003 | high | Attacker-controllable value expanded directly into a `run:` script |
| ML-GHA-004 | high | Pull request code checked out and run in a `pull_request_target` job |

Severity reflects how much damage the pattern could allow if it is exploitable. It is not a measure of how likely exploitation is.

## When a scan is incomplete

A rule never treats something it cannot analyze as safe. These cases make the scan `incomplete` (exit code 2) instead of clean:

- YAML that is malformed, has more than one document, uses merge keys (`<<`), or uses an alias to a mapping or list in a place a rule needs to read.
- An `analysis_limit` entry: a construct that is valid but that the rules cannot resolve statically. The report names the location and the reason. Examples are a `uses:` value containing an expression, a computed property access such as `github.event[matrix.field]`, an unterminated `${{`, and, in `pull_request_target` workflows, a checkout `ref` whose value cannot be determined or a command after a pull request checkout that is not recognized.

An incomplete scan is not a pass, even when it also lists findings.

## ML-GHA-001: write-all permissions

**Purpose.** `permissions: write-all` gives the `GITHUB_TOKEN` write access to every scope. If any step runs compromised or untrusted code, it can use that access.

**Detects.** The scalar value `write-all` under `permissions` at the workflow level or on a job. Quoted values and values supplied through a scalar alias are detected.

**Example.**

```text
ML-GHA-001 [medium] .github/workflows/ci.yml:3
  Location: permissions
  Evidence: permissions: write-all
```

**Remediation.** Remove `write-all`. Set workflow-level permissions to the minimum needed, for example `contents: read`, and grant individual write scopes only to the jobs that need them.

**Not covered.** Individual write scopes such as `contents: write` are not flagged. A workflow with no `permissions` key inherits the repository default, which this rule does not read.

**False-positive risk.** Low. A workflow that really needs broad write access and runs only trusted code will still be flagged.

## ML-GHA-002: unpinned external references

**Purpose.** A tag or branch such as `owner/repo@v4` or `@main` can be moved by whoever controls the repository. The code that runs in your workflow can then change without any change to your repository. Pinning to a full commit SHA stops that substitution. It does not make the pinned code safe: you still have to trust, or review, the code at that commit.

**Detects.**

- `jobs.<id>.steps[*].uses` of the form `owner/repo@ref` or `owner/repo/path@ref` where `ref` is not a full 40-character (or 64-character) hexadecimal commit SHA.
- `jobs.<id>.uses` for reusable workflows with a non-SHA ref.
- `docker://image` references without an `@sha256:` digest. These are reported with a separate message, because a Docker tag is not a Git ref.

Local references (`./path`) are ignored. Text in comments, `run:` scripts, `name:` fields, and `with:` inputs is not read as a reference.

**Analysis limits.** A `uses:` value that contains an expression, is not a string, or is not in a recognized form (for example `owner/repo` with no `@ref`) is reported as an analysis limit. It is not treated as pinned.

**Example.**

```text
ML-GHA-002 [medium] .github/workflows/ci.yml:7
  Location: jobs.build.steps[0].uses
  Evidence: uses: actions/checkout@v4
```

**Remediation.** Pin to the full commit SHA of a release you have reviewed and keep the version in a trailing comment, for example `uses: owner/repo@<40-character sha> # v1.2.3`. Update pins with a tool such as Dependabot.

**Not covered.** The rule does not evaluate repository or organization policies that require SHA pinning, or any workflow dependency lock mechanism GitHub may provide, so a reference it flags may already be restricted elsewhere, and one it accepts is not made safe by pinning. It does not check whether a SHA belongs to the named repository (a SHA from a fork can be referenced), whether the action is trustworthy, or actions that are fetched at run time by other actions.

**False-positive risk.** Moderate. Every non-SHA reference is flagged, including actions published by GitHub itself. There is no allow list yet.

## ML-GHA-003: attacker-controllable values in scripts

**Purpose.** GitHub replaces `${{ ... }}` expressions in a `run:` script with their values before the shell parses the script. If a value is text chosen by someone outside the project, such as a pull request title or a branch name, it can add shell commands. The usual fix is to pass the value in an environment variable and read it as `"$NAME"`.

**Detects.** Expressions in `run:` fields, including multiline `|` blocks, that reference documented attacker-controllable fields, including:

- `github.event.pull_request.title`, `.body`, `.head.ref`, `.head.label`, `.head.repo.default_branch`
- `github.event.issue.title` and `.body`
- `github.event.comment.body`, `github.event.review.body`, `github.event.review_comment.body`
- `github.event.discussion.title` and `.body`
- `github.event.commits.*.message`, `.author.email`, `.author.name`, and the `head_commit` equivalents
- `github.event.workflow_run.head_branch` and `head_commit.*`
- `github.event.pages.*.page_name`
- `github.head_ref`

Expressions are read statically; no value is ever computed. Matching ignores case and accepts bracket forms such as `github['event']['pull_request'].title`, numeric indexes such as `commits[0]`, and `*`. An expression that refers to a whole object that contains one of these fields, such as `toJSON(github.event.pull_request)`, is flagged with a message saying so. Quoting around an expression is not treated as protection, and neither is a shell comment, because the substitution happens first.

**Not flagged.** Values passed through `env:` and used as shell variables. Expressions that can only produce true or false: a comparison, a negation, or a single `contains`, `startsWith`, or `endsWith` call. Fields not in the list, such as `github.event.pull_request.number` or `github.sha`.

**Analysis limits.** A computed property access that could select one of the listed fields (for example `github.event[matrix.field]`) and an unterminated `${{` make the scan incomplete.

**Example.**

```text
ML-GHA-003 [high] .github/workflows/ci.yml:12
  Location: jobs.greet.steps[0].run
  Evidence: ${{ github.event.pull_request.title }}
```

The line number is exact inside `|` blocks. For other scalar styles it is the line where the scalar starts. Evidence is the expression only, not the surrounding script line.

**Remediation.** Set `env: NAME: ${{ ... }}` on the step and use `"$NAME"` in the script.

**Not covered.** Expressions in places other than `run:`, including the `script:` input of `actions/github-script` and other action inputs. Values reaching a script indirectly through `env`, `steps.*.outputs`, `inputs`, or `matrix`. Fields not on the list, for example `github.ref_name`. Whether the workflow's trigger lets an outsider supply the value.

**False-positive risk.** Moderate. A flagged expression is not necessarily exploitable: it depends on the trigger and on who can start the workflow. Boolean-looking expressions combined with `&&` or `||` are conservatively flagged.

## ML-GHA-004: pull request code run in a pull_request_target job

**Purpose.** `pull_request_target` runs a workflow in the context of the base repository, with its secrets available and a token that may have write access, even for pull requests from forks. That is safe only while the workflow does not run code from the pull request. Checking out the pull request and then building or testing it hands that privilege to the code's author.

**Detects.** In a workflow triggered by `pull_request_target` (as a string, list, or mapping under `on`), a job that does both of the following, in order:

1. Brings pull request code into the workspace by one of:
   - `actions/checkout` with `ref` or `repository` that refers to the pull request head (`github.event.pull_request.head.*`, `github.head_ref`, `github.event.pull_request.merge_commit_sha`) or contains `refs/pull/`;
   - `gh pr checkout` in a `run:` step;
   - `git fetch`, `pull`, `checkout`, `switch`, `merge`, `cherry-pick`, `reset`, `rebase`, `am`, or `apply` with a `pull/N/head`, `pull/N/merge`, or `refs/pull/` ref or a head-branch expression.
2. Afterwards runs a package manager, build tool, test runner, interpreter, shell, a relative script path such as `./build.sh`, a container build, or a local action (`uses: ./...`).

The message notes whether the job has explicit write permissions or references secrets.

**Not flagged.** `pull_request_target` by itself. A checkout with no `repository` and no `ref` (the base repository's default branch), a literal branch or tag `ref` in the base repository, or a `ref` known to select the base (`github.sha`, `github.base_ref`, `github.event.pull_request.base.*`, and similar). A pull request checkout followed only by commands that do not run repository code, such as `git diff`, `echo`, or `gh pr comment`. Steps in other jobs, since each job has its own workspace. Execution before the checkout. Other triggers such as `pull_request`.

**Checkout repository.** `actions/checkout` can fetch any repository, so `with.repository` is judged separately from `with.ref`. It is trusted only when the whole value is one plain expression naming the workflow's own repository (`github.repository`, `github.event.repository.full_name`, or `github.event.pull_request.base.repo.full_name`). A pull request head repository (`github.event.pull_request.head.repo.*`) is untrusted. Anything else, including a literal such as `owner/repo`, an empty value, a mixed value such as `${{ github.repository_owner }}/tools`, or `matrix`, `inputs`, `env`, or `vars` values, cannot be shown to be the base repository and is an analysis limit. Workflows that check out a separate, fixed repository therefore return an incomplete result and need review by hand.

**Analysis limits.** In a `pull_request_target` workflow, a checkout `ref` whose value is not known to select the base repository (for example `${{ matrix.ref }}` or `${{ inputs.ref }}`), a `repository` that cannot be resolved as described above, and, after a pull request checkout, a command that is not on the lists of known-safe or known-executing commands, make the scan incomplete.

**Example.**

```text
ML-GHA-004 [high] .github/workflows/ci.yml:11
  Location: jobs.build.steps[0].with.ref
  Evidence: ref: ${{ github.event.pull_request.head.sha }}; step 1 runs npm
```

**Remediation.** Do not run pull request code in a `pull_request_target` workflow. Build and test untrusted changes in a `pull_request` workflow, which runs without secrets and with a read-only token for forks. If a privileged follow-up step is needed, put it in a separate job or workflow that treats the build output as data and never checks out or runs pull request code, and set `permissions` to the minimum required.

**Not covered.** `workflow_run` workflows have a similar risk (they run with privileges after another workflow, and often check out `github.event.workflow_run.head_sha`). This rule does not analyze them yet; the test suite records this as a known false negative. Also not covered: data flow through `env`, `GITHUB_ENV`, or step outputs into a checkout ref; executing pull request code through an external action (for example one that runs a script from the workspace); shell constructs the command reader does not understand; and checkouts through other means. Detection of execution is based on a fixed list of command names.

**False-positive risk.** Moderate. A job that checks out the head and then runs a command on the executing list may be doing so in a way that is safe, for example a lint tool run in a sandbox. Review the finding.
