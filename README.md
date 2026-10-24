# MergeLatch

**Protect the contribution before it becomes part of the project.**

> **Project status: early development.** MergeLatch has a working command-line scanner with four narrow detection rules for GitHub Actions workflows, and an advisory GitHub Action built on it (see below). The Action is not a merge gate. There is no published release, no desktop application, and no installer. Everything under "Planned" below describes intended features, not capabilities available today.

MergeLatch is an open-source project for checking security-sensitive changes in Git repositories. It is designed for maintainers reviewing pull requests and developers working with code cloned onto their computers.

The aim is simple: help people understand what changed, what might be dangerous, and whether a contribution is ready for review or merging.

## What works today

| Capability | Status |
| --- | --- |
| `mergelatch scan` CLI with human-readable and JSON output | Implemented |
| Rules ML-GHA-001 to ML-GHA-004 for GitHub Actions workflows (see [Detection coverage](#detection-coverage)) | Implemented |
| Local scanning with no network access, hosted service, or AI model | Implemented |
| Advisory GitHub Action for pull requests (Linux runners, job summary; trial-tested by SHA in this repository, in a separate consumer repository, and on a fork pull request; no independent review; not a release, see [docs/ACTION.md](docs/ACTION.md)) | Implemented and merged, not released |
| Sentinel desktop app, Agent Guard, dependency and malware checks, merge enforcement | Not implemented |

### Build and run

Requires Rust. The repository pins toolchain 1.99.1 in `rust-toolchain.toml`; `rustup` installs it on request.

```bash
rustup toolchain install   # installs the pinned toolchain
cargo build --release
./target/release/mergelatch scan path/to/checkout
```

Other commands:

```bash
mergelatch scan <PATH> --format json   # machine-readable report
mergelatch rules                       # list built-in rules (add --format json for JSON)
mergelatch --help
```

Example, scanning a harmless fixture from this repository:

```text
$ mergelatch scan fixtures/gha-permissions/workflow-write-all
MergeLatch 0.1.0 (ruleset mergelatch-builtin 1)
Target: /path/to/mergelatch/fixtures/gha-permissions/workflow-write-all
Revision: not available
Workflow files inspected: 1

Findings (1):

  ML-GHA-001 [medium] .github/workflows/ci.yml:3
    Workflow grants write-all permissions to GITHUB_TOKEN
    Location: permissions
    Evidence: permissions: write-all
    Why: The workflow sets `permissions: write-all`, which gives the GITHUB_TOKEN write access to every permission scope. Any step that runs compromised or untrusted code can use that access.
    Fix: Remove `write-all`. Set workflow-level permissions to the minimum needed, for example `contents: read`, and grant individual write scopes only to the jobs that need them.

Result: findings (review the findings above)
Exit code: 1
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The scan completed and detected nothing. |
| 1 | The scan completed and found one or more issues. |
| 2 | The scan is incomplete: a file could not be read or parsed, or a limit was reached. This is not a pass. |
| 3 | Error: the target is invalid or the command was used incorrectly. The scan did not run. |

Use the exit code, not the absence of output, to decide whether a scan passed. If a scan has both findings and incomplete inspections, the status is `incomplete` and the findings are still listed.

### Interpreting results

- **clean**: every `.github/workflows/*.yml` and `*.yaml` file was read and parsed, and no rule matched. It does not mean the repository is safe.
- **findings**: a rule matched. Each finding shows the file, line, YAML location, short evidence taken from the matching setting or expression (not the whole source line), an explanation, and a suggested fix. A finding is a configuration to review, not proof of malicious intent.
- **incomplete**: at least one inspection did not finish. The report lists each file and the reason: unreadable, not a regular file, outside the scan root, too large, invalid UTF-8, invalid or unsupported YAML, a construct the rules cannot analyze (`analysis_limit`), a resource limit, or a timeout.
- **error**: the scan could not start.

JSON reports include a `schema_version`, the scanner version, the ruleset identity, the limits in force, the target path, and the Git commit when it can be read from `.git`. They contain no timestamps, so the same input produces the same report.

### Detection coverage

| Rule | Severity | Detects |
| --- | --- | --- |
| ML-GHA-001 | medium | Explicit `permissions: write-all` at the workflow or job level. |
| ML-GHA-002 | medium | External actions, reusable workflows, and Docker images referenced by a mutable tag or branch instead of a full commit SHA or digest. |
| ML-GHA-003 | high | Attacker-controllable context values (pull request and issue titles and bodies, comment bodies, commit messages, branch names) expanded directly inside `run:` scripts. |
| ML-GHA-004 | high | A `pull_request_target` job that checks out pull request code and then builds, installs, tests, or runs it. |

Each rule's coverage, example finding, remediation, false-positive risks, and unsupported cases are in [docs/RULES.md](docs/RULES.md). These are focused checks for specific patterns. They do not detect malicious workflows in general, and MergeLatch is not an antivirus or a complete malware detector.

### Known limitations

- Only four narrow rules exist. MergeLatch does not detect malicious workflows in general, individual write scopes such as `contents: write`, `workflow_run` risks, script injection outside `run:` steps, dependency problems, secrets, or malware. Rules can produce false positives and miss variations; see [docs/RULES.md](docs/RULES.md) for each rule's unsupported cases.
- Where a rule cannot analyze a construct (an expression in `uses:`, a computed property access, a checkout ref that cannot be resolved), the scan is reported as incomplete instead of clean. Some ordinary workflows will therefore return exit code 2 until the construct is simplified.
- Only the repository root `.github/workflows` directory is read. Composite actions, reusable workflows in other repositories, and files in subdirectories are not analyzed.
- YAML merge keys (`<<`) and aliases that point to mappings are not expanded. They make the scan incomplete rather than being ignored.
- Files with more than one YAML document are reported as incomplete.
- Symlinks: a relative link is followed only if it stays inside the scan root. A link that leaves the root, an absolute link (even one pointing back inside the root), a dangling link, or a link loop is reported as incomplete and is not read. Directory links such as `.github/workflows` follow the same rule.
- Default limits: 1 MiB per file, 16 MiB total, 1000 directory entries, 64 levels of YAML nesting, and a 30 second time limit. The limits are not yet configurable from the command line.
- The time limit is detected, not strictly enforced. It is checked between files and during YAML parsing, but a single blocking read is not interrupted. A scan that finishes after the limit is reported as incomplete, never clean.
- **Confined file access, verified on Linux only.** Files are opened relative to a handle on the scan root using `cap-std`, so a symlink, rename, or directory swap made during the scan cannot redirect a read outside the root. See "Filesystem confinement" below for what this does and does not cover. Platforms other than Linux are refused with an error, because confinement has not been verified there.
- Revision information is read from `.git` files without running Git, through the same confined access. It is what the scanned directory claims, not a verified identity: anyone who controls the directory controls those files. If it cannot be read safely, it is omitted. Worktrees and other layouts where `.git` is not a directory report no revision.
- Only the local directory contents are analyzed. Pull request metadata and diffs are not. The GitHub Action scans whatever the earlier checkout step provides, nothing more.
- Supported and tested platform: Linux (kernel 7.0 on x86-64 was used for the tests). Windows and macOS return an unsupported-platform error and are untested.

### GitHub Action (advisory, trial-tested, not released)

The repository contains a composite GitHub Action (`action.yml`) that runs the scanner on a checked-out pull request and writes a job summary and outputs. It is **advisory**: it is not a merge gate, a green check does not mean a pull request is safe, and it must not be added as a required check. It scans only the workflow files at the root of the scanned directory with rules ML-GHA-001 to ML-GHA-004. It does not scan source code for malware or the Git diff.

- It supports GitHub-hosted Ubuntu x86-64 runners, `pull_request` triggers, `contents: read`, and no secrets. It enforces the runner and trigger restrictions at run time and refuses `pull_request_target`, `workflow_run`, self-hosted and non-Ubuntu runners, and environments that preload code (`LD_PRELOAD` and similar).
- Steps do not run under bash, and the scanner is built in an environment assembled from fixed values, so `BASH_ENV`, `CARGO_HOME`, linker and compiler overrides, and rustup settings inherited from the workflow are ignored.
- The scanner is built from the Action's own, separately checked-out source with a locked build. The pull request content is only passed to it as a directory to read.
- Results: `clean`, `findings`, `incomplete`, and `error`. Findings and incomplete scans leave the step green but say so prominently in the summary. A scanner failure or an untrustworthy report fails the step.
- The example in [docs/examples/pull-request-scan.yml](docs/examples/pull-request-scan.yml) pins the verified merge commit `afc7e65d6723029c22935f82c7fc9562d5831565`. That commit has been run as a SHA-pinned Action on GitHub in this repository (its rendered summary shows the full SHA), in a separate consumer repository, and on a pull request from a first-time external fork contributor, whose run waited for maintainer approval. The fork's change was a README edit only. [docs/EXTERNAL_TRIAL.md](docs/EXTERNAL_TRIAL.md) records what those runs do and do not show. The commit has had no independent human review, it is not a published release, and a commit that can be referenced by SHA is not thereby an official release.

Architecture, inputs and outputs, what revision is scanned, why a pull request can bypass the check, the tests, and the release process are in [docs/ACTION.md](docs/ACTION.md).

### Filesystem confinement

The scan root is opened once. Every later path is resolved relative to that handle by the operating system (on Linux, `openat2` with `RESOLVE_BENEATH` when the kernel provides it, otherwise a component-by-component walk inside `cap-std`), so it cannot lead outside the root. File type and size are read from the opened handle, files are opened non-blocking so a named pipe cannot stall the scan, and special files are never read. Reads are bounded by the size and total-byte limits.

What the tests demonstrate (on Linux): swapping a workflow file, the `workflows` directory, or `.github` for an outside-root symlink at each step of discovery, including between listing and opening, never reads the outside file; links in `.git` metadata cannot supply a revision from outside; named pipes and devices are not read; and concurrent modification stress runs against full scans never leaked an outside marker. The earlier canonicalize-then-open design is kept as a positive control in the unit tests, which shows it loses the same race.

What this does not cover:

- The path passed on the command line is trusted. It is opened once, and the displayed target path comes from a separate lookup, so it is informational and could differ if that path was changed at that moment.
- A directory inside the root can be swapped for another directory inside the root during a scan, so a scan can mix files from both. Nothing outside the root is read.
- Mount points and hard links inside the tree are not detected. A mount or hard link placed inside the root can expose other content to a read.
- The guarantees rely on the kernel, filesystem, and `cap-std`. The `cap-std` fallback used on kernels without `openat2` was not exercised by these tests.
- Time limits remain detection only (see above).

Do not rely on MergeLatch as an enforcement gate or in Sentinel until the remaining requirements in the [threat model](docs/THREAT_MODEL.md#10-known-implementation-gaps) are met.

### Offline behavior and safety

The scanner makes no network requests, needs no account, and does not use an AI model. It reads files as text, never executes scanned content, and does not run Git, so hooks, scripts, and repository configuration in the scanned directory do not run. Text taken from scanned files is escaped before display so it cannot inject terminal control sequences. Automated tests check these properties against inert fixtures; see [the threat model](docs/THREAT_MODEL.md) for the broader design goals.

### Tests and checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The test suites live in `crates/*/src` (unit tests) and `tests/` (integration tests). Fixtures in `fixtures/` are harmless text files and are only read, never run. The pull request workflow `.github/workflows/rust.yml` runs the same three commands with a read-only token. That workflow runs contributed code and is not a security gate.

## Who is it for?

- **Maintainers:** review security findings on pull requests and use GitHub branch protection to prevent merges when required checks fail.
- **Contributors:** scan a local working tree before opening a pull request.
- **Developers:** monitor selected Git project folders on a laptop and receive notifications about new suspicious changes.
- **Teams using coding agents:** run the same checks before submitting agent-generated changes. AI is optional.

## Planned components

| Component | Purpose | Where it runs |
| --- | --- | --- |
| MergeLatch Core | Scan source files, scripts, dependencies, GitHub workflows, and policy changes | Locally or in CI |
| MergeLatch CLI | Run scans and produce evidence-backed JSON and SARIF reports | Your computer or CI |
| MergeLatch GitHub Action | Run unprivileged PR checks and publish results to GitHub | GitHub Actions |
| MergeLatch Sentinel | Discover and monitor Git repositories in approved folders; show desktop warnings | Your laptop |
| MergeLatch Agent Guard | Let supported coding agents request preflight scans without granting them enforcement privileges | Local integration |
| Stellar/Soroban Adapter | Check domain-specific contract and release integrity risks | Core engine |

These components will be delivered progressively. Not every planned integration will be included in the first release.

## Will I need localhost or a server?

**No, not to use the finished desktop application.** The intended Windows app will be packaged as an installer. It will open as a normal desktop program with its interface bundled inside the app. You will not need to install Node.js, use the terminal, start localhost, or deploy a website.

Development builds may use a local frontend development server. That is for contributors building MergeLatch, not end users.

The GitHub Action will run on GitHub-hosted runners. Repository owners must add the workflow and configure the relevant branch-protection rules. MergeLatch does not need a paid hosted backend for the planned first release.

## Planned: using MergeLatch Sentinel

*This is the expected user flow after the installer is released, not an installation procedure that works today.*

1. Download the official installer from the project's GitHub Releases page.
2. Verify the release information and install the application.
3. Open MergeLatch Sentinel.
4. Choose which directories it may scan. Development folders are the recommended default.
5. Run an initial scan to discover repositories and create a local baseline.
6. Turn on monitoring and notifications if you want ongoing alerts.
7. Open a finding to see the affected file, detection evidence, risk category, and recommended action.
8. Review or dismiss findings with a recorded reason. Suspicious files will not be deleted automatically.

Sentinel will need to be running to monitor file changes. If your laptop is off, it cannot detect new activity; the application should reconcile relevant changes on its next start.

## Planned: protecting pull requests on GitHub

*An advisory-only Action exists (see [GitHub Action](#github-action-advisory-trial-tested-not-released)). The enforcement workflow below, with an official version-pinned snippet and a required status check, is planned and not available. An official installation snippet will be published only with a release.*

1. Add the official version-pinned MergeLatch workflow to your repository.
2. Run it against test pull requests, including safe and intentionally suspicious fixtures.
3. Review the results and tune documented policies.
4. Configure the MergeLatch gate as a required GitHub status check under branch protection.
5. Require normal project tests and suitable human approvals as well.
6. Optionally enable GitHub's native auto-merge. GitHub will merge only after the repository's configured requirements are satisfied.

**Important:** A security scan passing does not mean a pull request is correct or completely safe. A scan is not a substitute for tests or human review. Automated merging will be opt-in, and security-sensitive changes should require human approval.

## Local CLI

The first CLI is described under [What works today](#what-works-today). Planned additions include scanning a Git diff and more detection rules. Commands are documented here only after they are implemented and tested.

## How findings will work

Every finding should include:

- A clear name and severity or confidence category.
- The relevant file and location, if available.
- The rule that triggered and observable evidence.
- Why the behavior may be risky.
- A suggested investigation or remediation step.
- The scanner version, policy version, and analyzed Git revision.

Not every warning means malware is present. A benign script can resemble a suspicious one, and novel attacks may escape detection. The software will not claim to guarantee a malware-free repository.

## Privacy and permissions

MergeLatch is being designed to process local source files on the user's device by default. It should not upload private repositories or secrets to an external AI service without explicit, informed consent. Repository discovery will apply only to folders authorized by the user.

The desktop scanner should not require GitHub access. The GitHub PR scanner should run with minimal read permissions. Merge permissions, if introduced for optional automation, must be isolated from untrusted PR scanning.

## AI integration

No AI account is required for ordinary security scanning. Optional integrations may let supported coding agents explain findings or suggest fixes. Existing chat subscriptions do not necessarily authorize third-party model access. Agent output must never be the sole authority for passing checks or merging code.

## Cost

The first release is designed for **no mandatory paid hosting, domain, or AI API**. Local resources are supplied by the user. GitHub-hosted Actions have provider-enforced resource and usage limits even when standard runners are free for public repositories.

## Development roadmap

See [the implementation playbook](docs/BUILD_PLAN.md) for the steps from repository setup through the first release, including acceptance tests and the documentation checklist.

## How to help

The project is in early development. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose changes and [the threat model](docs/THREAT_MODEL.md) for the risks the design is meant to address. Issue templates will be added later. Please do not submit real malware samples or secrets to public issues.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability in MergeLatch itself. Do not disclose exploit details or credentials in a public issue.

## License

MergeLatch is licensed under the [Apache License 2.0](LICENSE).

---

**Current status:** early development; four rules and an advisory Action implemented, no release. Installation links, release badges, version numbers, performance claims, and coverage statistics will be added only after they are verified.
