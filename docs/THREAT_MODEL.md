# MergeLatch Threat Model

**Status:** design document with a first implementation. MergeLatch currently provides a command-line scanner with four narrow rules for GitHub Actions workflows (ML-GHA-001 to ML-GHA-004, described in `docs/RULES.md`): explicit `write-all` permissions, unpinned external references, attacker-controllable values in `run:` scripts, and pull request code run in `pull_request_target` jobs. It also provides an advisory GitHub Action that builds and runs that scanner on a pull request checkout (`docs/ACTION.md`). The Action is not a merge gate and has no published release. Nothing else described below is implemented: there is no desktop application (Sentinel), Agent Guard, dependency or malware checking, or merge enforcement. This document describes the threats the project intends to address and the requirements its design must meet. It does not claim that protections beyond those four rules exist, and the rules themselves cover only specific patterns. See the README for what the scanner covers today and section 10 for known gaps in the current implementation. Each section should be revised as components are built and tested.

## 1. Purpose

MergeLatch aims to help maintainers and developers notice security-sensitive changes in Git repositories before they are merged or run. This document defines what is in scope, what is not, how trust is divided between components, and which properties must always hold.

## 2. Scope

### In scope (intended)

- Malicious or compromised pull requests, including changes to scripts, build files, and policy files.
- Dependency and supply-chain changes in common manifests and lockfiles.
- Dangerous GitHub Actions workflow configurations.
- Suspicious content in locally cloned repositories, as seen by the local scanner.
- Code produced by AI coding agents, treated as untrusted input like any other contribution.
- Failures of MergeLatch itself: crashes, bad policy, stale rules, and tampering with its own configuration.

### Out of scope

- Compromise of a maintainer's account, device, or GitHub organization. MergeLatch can reduce exposure but cannot defend against an attacker holding maintainer credentials.
- Vulnerabilities in GitHub, the operating system, Git, or the Rust toolchain.
- Runtime behavior of software after it is merged and deployed.
- Confirming that a change is functionally correct. A passing scan is not a substitute for tests or human review.
- Detecting every novel attack. MergeLatch makes no guarantee of a malware-free repository.
- Social engineering of reviewers outside what is visible in repository content.
- Network-level attacks on end-user machines.

## 3. Assets

- The integrity of protected branches and release artifacts.
- Repository secrets and tokens available to CI.
- Maintainer and contributor machines that clone or scan code.
- The integrity of MergeLatch rules, policies, and scan results.
- Private repository contents processed locally.

## 4. Threats

### 4.1 Malicious pull requests

- Install hooks, build scripts, or test code that run attacker commands when a maintainer or CI builds the change.
- Obfuscated or encoded payloads, and logic that is only active under certain conditions.
- Changes that weaken security controls, such as editing the scanner policy, CODEOWNERS, or branch rules in the same PR that needs to pass them.
- Large or noisy diffs that hide a small malicious change.
- Misleading PR titles, descriptions, branch names, and file names, including attacker-controlled text intended to manipulate a scanner, a reviewer, or an AI agent.
- Binary files, symlinks, and unusual file modes that conceal content or point outside the repository.

### 4.2 Dependency and supply-chain attacks

- Newly added or version-changed dependencies, including typosquatted or recently published packages.
- Lockfile changes that do not match manifest changes, or that point to unexpected registries or Git sources.
- Install-time scripts in dependencies.
- Unpinned or mutable references, such as floating tags or branches.
- Tampering with scanner rules, vulnerability data, or release artifacts of MergeLatch itself.

### 4.3 Dangerous GitHub Actions configurations

- `pull_request_target` or `workflow_run` workflows that check out or execute untrusted PR code with elevated permissions or secrets.
- Overbroad `permissions`, or missing explicit permissions.
- Untrusted values (titles, branch names, issue bodies) interpolated into shell commands or scripts.
- Third-party actions referenced by mutable tags instead of commit SHAs.
- Self-hosted runners exposed to untrusted code.
- Secrets exposed to forked pull requests, or written to logs and artifacts.
- Workflow changes made in the same PR whose checks they control.

Implemented (partially) by `ML-GHA-001` to `ML-GHA-004`: write-all permissions, mutable action references, direct interpolation of attacker-controllable values into `run:` scripts, and pull request code checked out and run under `pull_request_target`. Other items in this list, such as self-hosted runners, secret exposure to forked pull requests in general, `workflow_run` privilege escalation, and workflow changes in the same PR as their checks, are not detected.

### 4.4 Local repository threats

- Git hooks and filters that run commands on checkout, commit, or merge once they are enabled on a machine. Hooks are not transferred by `git clone`, but a repository can ship hook scripts, a hook-manager configuration, or setup instructions that install them or point `core.hooksPath` at them. `.gitattributes` filters only run if a matching filter driver is configured locally.
- Editor, task runner, and IDE configuration that runs commands when a folder is opened.
- Build scripts and package manager lifecycle scripts invoked by routine developer commands.
- Path traversal, symlink, and archive-extraction tricks aimed at the scanner itself.
- Files crafted to cause resource exhaustion in the scanner, such as very large files or deeply nested structures.

### 4.5 AI-agent-generated code risks

- Agent output may contain insecure code, invented dependencies, or malicious content introduced through prompt injection from repository text.
- An agent may attempt to alter its own checks, policies, or workflow files.
- Agent-supplied claims that checks passed cannot be trusted. Results must come from an independent run.
- Agents must not be granted enforcement, merge, or secret-access privileges.

## 5. Trust boundaries and permission separation

| Boundary | Trusted side | Untrusted side |
| --- | --- | --- |
| Repository content | MergeLatch engine and base-branch policy | PR files, branch names, titles, bodies, and filenames |
| CI scanning | Workflow definitions on the protected base branch | Code from the PR head, including forks |
| Reporting | A separate reporting step with narrowly scoped write access | The scanning step that processes untrusted input |
| Advisory GitHub Action (see `docs/ACTION.md`) | The Action checkout at a pinned commit: scanner source, rules, helper | The pull request checkout, the caller's workflow file, and every string in the scanner's report |
| Merge authority | Branch protection, required human reviews, and GitHub's own merge controls | Scan results alone, and any agent claims |
| Local scanning | User-approved directories | Everything inside them |
| Rules and policy | Signed or verified releases and the base-branch policy | Policy changes proposed in a PR |

Design principles:

- The scanner reads untrusted content as data. It never executes it.
- The scanning job has read-only permissions and no secrets. Any job that needs write access runs separately and does not process untrusted content.
- Policy and workflow files are evaluated from the trusted base revision, not from the PR under review.
- Merge permission is never held by the same component that parses untrusted input.
- Changes to workflows, policy, CODEOWNERS, and release configuration require human approval.

## 6. False positives, missed detections, and scanner failures

- **False positives:** legitimate scripts can resemble malicious ones. Findings must show evidence and the triggering rule so a reviewer can judge them. Dismissals should require a recorded reason.
- **Missed detections:** rule-based scanning will miss some attacks, especially new or heavily obfuscated ones. Documentation must not imply complete coverage. Detection quality should be measured on test fixtures before any claim is made.
- **Scanner failures:** a crash, timeout, invalid policy, unreadable file, or unavailable mandatory data must produce an explicit "review required" or failing result. It must never be reported as a clean pass.
- **Stale data:** rule and vulnerability data have an age. The result must show the ruleset version, and stale data must be visible to the user.
- **Evasion:** an attacker who can read the rules can try to avoid them. Rules should be treated as one layer, not the only control.

## 7. Privacy and offline behavior

- Scanning of local repositories happens on the user's device by default.
- The local scanner and the GitHub-hosted CI scan are different privacy contexts. The local scanner processes files on the user's device. A CI scan runs on GitHub-hosted runners, so the repository content it reads is processed on GitHub's infrastructure, which is the same place the repository is already hosted. For private repositories, enabling the CI scan means GitHub Actions processes private code under the repository owner's GitHub terms and settings. Documentation must make this distinction clear.
- CI scan results, such as logs, annotations, and uploaded artifacts, may be visible to anyone who can read the repository or its workflow runs. For public repositories they are public, so they must not contain secrets.
- Source code, file paths, and findings are not uploaded without explicit, informed consent.
- The local scanner works offline. When it cannot refresh rules or data, it reports the age of what it is using and does not silently skip checks.
- Repository discovery is limited to folders the user has authorized.
- The desktop scanner does not require GitHub access.
- Any optional AI integration is off by default and must state what data it would send before sending it.
- Logs and reports must not contain secrets that the scanner encountered.

## 8. Security invariants

These properties must hold in every release. Each must have at least one automated acceptance test before MergeLatch claims it.

1. **Untrusted content is never executed** by the scanner, in any mode.
2. **No clean pass on failure.** Any scanner error, timeout, invalid policy, or missing mandatory input yields a non-passing result.
3. **Least privilege in CI.** The scanning job has read-only repository permission and no access to secrets. Write and merge permissions are never available to code that parses untrusted PR content.
4. **Trusted policy source.** Policy, rules, and workflow definitions used for a gate come from the protected base, not from the PR being evaluated.
5. **Self-protection.** A PR that modifies workflows, policy, CODEOWNERS, or release configuration cannot pass the gate without human approval.
6. **Scan never grants merge authority.** A passing scan is one input to branch protection, not a replacement for required reviews or tests.
7. **Reproducible, attributable results.** Each result records the scanner version, ruleset identity, policy hash, and analyzed revision.
8. **Local-first privacy.** No repository content leaves the device without explicit consent.
9. **Bounded resources.** The scanner enforces limits on file size, depth, and time, and reports when a limit was hit.
10. **No destructive actions.** The scanner reports findings. It does not delete or modify files on its own.

## 9. Acceptance-test requirements

Before a component is described as protecting against a threat in this document, the project must provide:

- A positive fixture that the scanner flags, and a negative fixture that it does not flag, for each rule.
- Tests for each invariant in section 8, including failure injection: crashes, timeouts, malformed input, and unreadable files must not produce a pass.
- Tests that confirm fixtures are inert and are never executed.
- Tests that confirm untrusted PR input cannot alter the policy or workflow used for the gate.
- Workflow tests that confirm minimum permissions and that no secrets are available to the scanning job.
- Resource-limit tests with oversized, deeply nested, and adversarial inputs.
- Offline-mode tests that confirm behavior with stale or unavailable data.
- Published false-positive and detection results for the fixture set, with the set's limitations described.

## 10. Known implementation gaps

These are limitations of the current scanner. They are recorded here so they are resolved deliberately and not forgotten.

- **Filesystem access: confined on Linux, partly verified.** The scanner opens the scan root once and resolves every path relative to that handle with `cap-std` (`openat2` with `RESOLVE_BENEATH` where available). Symlink, rename, and directory swaps during a scan cannot redirect a read outside the root; the unit tests in `crates/core/src/discover.rs` and `revision.rs` demonstrate this at each step, and `tests/core_confinement.rs` runs stress scans against a modifying thread. Absolute symlinks and links that climb above the root are refused. `.git` metadata is read through the same mechanism and is never treated as verified identity. Remaining gaps:
  - Verified on Linux only (kernel with `openat2`). Other platforms return an unsupported-platform error. Windows and macOS need their own verified backend and adversarial tests before they are described as protected.
  - The `cap-std` fallback for kernels without `openat2` has not been exercised by our tests.
  - The command-line root path is trusted and opened once; the displayed path comes from a separate lookup.
  - A directory inside the root can be swapped for another inside the root mid-scan, mixing content from both. Mounts and hard links inside the tree are not detected.
  - The tests cannot prove the absence of every race. Stress runs sample interleavings, and the deterministic tests cover the swap points that exist today.
  - **Before Sentinel or an enforcement gate:** add the Windows and macOS backends with tests, exercise the fallback path, decide how to treat mounts and hard links, and have the access layer independently reviewed.
- **Time limit is detection, not cancellation.** The deadline is checked between files and during YAML parsing. A single blocking filesystem operation is not interrupted, so a scan can overrun its limit. An overrun is reported as incomplete, never clean. Strict enforcement would require running the scan in a separate process that can be terminated.
- **Parser trust.** YAML is parsed with a third-party library. A panic is caught and reported as incomplete, but a parser that hangs or exhausts memory within the input size limit is not otherwise contained.
- **Narrow coverage.** Only four rules exist, each limited to specific patterns. See `docs/RULES.md` for what each does and does not cover.
- **Rule-level false negatives.** Known examples: `workflow_run` workflows are not analyzed (a similar privileged-execution risk); script injection is only checked in `run:` steps and for a fixed list of context fields; data flow through `env`, step outputs, and `GITHUB_ENV` is not tracked; execution of pull request code is recognized by fixed command lists, argument checks for a few tools (`git`, `gh`, `sed`, `awk`, `tar`), and local actions, so other ways of running code are missed; pinning is judged by syntax and does not consider repository policies or whether the pinned code is trustworthy.
- **Rule-level false positives.** Every non-SHA reference is flagged (including GitHub-owned actions); a flagged expression may not be exploitable for the workflow's trigger; some safe uses of listed commands after a pull request checkout will be flagged, and after any pull request checkout the rule assumes the workspace still holds that code (a later trusted checkout, a `path:` subdirectory, or a `working-directory:` does not clear the finding).
- **Fail-closed analysis limits.** Constructs the rules cannot resolve make the scan incomplete (exit code 2) instead of clean, which can make ordinary workflows non-passing until they are simplified. This is deliberate.

- **The advisory Action is not an independent control.** A `pull_request` workflow runs the workflow file from the pull request, so the contribution can edit or remove the MergeLatch step. Pinning the Action to a commit protects the Action's code, not the caller's workflow. The Action also builds and runs the scanner on the runner, which makes the helper, the Rust toolchain download, and the locked crates part of the trusted computing base. Before any enforcement use it needs a separately trusted workflow or service the pull request cannot change, fresh revision checks, branch-protection integration, and an independent review. Until then its result must not be a required check or an input to automatic merging. The Action keeps inherited environment settings out of its own steps (no bash, an absolute Python shell, a child environment built from fixed values, refusal of `LD_*` and unsupported runners), planted `GITHUB_ENV` settings and `GITHUB_PATH` entries are ignored (reproduced on GitHub-hosted runners, finding F-05), but a job that runs untrusted code before it, or leaves a process running, executes as the same user with passwordless `sudo` and was shown to be able to run its own `cargo` in the Action's build and to rewrite the Action's recorded scanner so that a real finding is reported as `clean`. Nothing inside the job can prevent that; the Action belongs in a job of its own. Its revision check relies on `.git` files in the checkout and, on a `pull_request`, treats an unreadable commit or missing expected commits as an error (earlier versions reported them green; the change is not yet verified as a pinned Action), and its escaping cannot prevent look-alike characters in file names from misleading a reader. Its event guard accepts only `pull_request` by exact match and rejects every other name (earlier versions refused only `pull_request_target` and `workflow_run`); it reduces accidental unsupported use and is not a boundary, and the new behavior has run as a pinned Action, including under a real `workflow_dispatch` event, but has had no independent review. A report larger than the helper's limit fails the step rather than being summarized. The independent review required above has not happened; see `docs/REVIEW_READINESS.md`.

## 11. Open questions

- Whether a standalone GitHub Action can serve as a sufficiently independent control if a PR can alter files related to its own checks, or whether a separate trusted service is needed. See the build plan for the current position.
- Which third-party data sources and tools to rely on, and how to verify their integrity.
- How to distribute and verify rule updates without a hosted backend.

## 12. Maintenance

Review this document whenever a component is added, a trust boundary changes, or a security incident occurs. Changes to it are security-sensitive and need additional review as described in [CONTRIBUTING.md](../CONTRIBUTING.md).
