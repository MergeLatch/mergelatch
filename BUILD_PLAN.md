# MergeLatch: From an Empty GitHub Organization to a Verified Release

**Status:** implementation playbook, not a claim of completed work.  
**Design baseline:** local-first, free to use, no paid backend required, no localhost for end users, AI optional, secure PR checks, and human-controlled merge authorization.

## Product decisions

1. Start with one main public monorepo named `mergelatch`. Create a second public repository, `mergelatch-action`, when the scanner is tested and the Action is ready for integration.
2. Share one Rust scanning engine between the CLI, GitHub integration, and desktop application.
3. Use Tauri with a bundled static frontend for the Windows desktop release. Do not use the optional localhost plugin in production.
4. Keep local records in SQLite; treat source files, PR bodies, branch names, and rule inputs as untrusted data.
5. Make GitHub scanning read-only and independent of optional AI. Do not execute untrusted PR scripts in a privileged context.
6. Use required GitHub status checks and built-in auto-merge for the initial merge workflow. A scan success alone never grants merge authority.
7. Treat missed scans, invalid policy, tool crashes, and unavailable mandatory security intelligence as a review-required result, not as a clean pass.
8. Measure scan quality, false positives, performance, and failure modes before claiming protection.

## Stage 1: Create the project

### 1. Confirm the project name

- Search GitHub for existing organization and repository names.
- Check domain and trademark risk before publishing a permanent brand. The working name `MergeLatch` is not yet cleared.
- Select an organization owner account with 2FA enabled and set up at least one secure recovery method.

**Done when:** the organization name has been chosen and ownership/recovery responsibilities are clear.

### 2. Create the GitHub organization and main repository

1. In GitHub, create the organization using the accepted project name.
2. Create a **public** repository called `mergelatch` with `main` as the default branch.
3. Add a real license (Apache-2.0 is a candidate; decide before distributing code), `.gitignore`, and the verified initial README.
4. Copy this plan to `docs/BUILD_PLAN.md`.
5. Add `.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, and `docs/THREAT_MODEL.md` as each document is written. Do not add links to nonexistent documents.
6. Turn on private vulnerability reporting if available.
7. Restrict who can modify workflows, releases, security policies, and protected branches.

**Done when:** the repository is public, ownership is clear, and baseline documentation exists without fabricated badges or claims.

### 3. Configure protective GitHub settings

1. Go to **Settings > General > Pull Requests**; select the merge methods intended for the repository. Keep automated merging disabled until its gates are verified.
2. Go to **Settings > Branches** or **Rules > Rulesets**, depending on repository settings.
3. Protect `main`: require PRs; block force-push and deletion; request at least one appropriate review; enable stale-review dismissal and conversation resolution when possible.
4. Create CODEOWNERS entries for `.github/workflows/`, `rules/`, release metadata, and merge-policy files. Require code owner reviews for those sensitive paths where available.
5. Once CI actually publishes its check names, add **those exact checks** as required checks. A check cannot be meaningfully selected before it has reported.
6. Set the repository's default `GITHUB_TOKEN` permissions to read-only and explicitly allow writes only in tightly constrained, separate workflows that truly need them.

**Done when:** a test PR cannot merge if its required review/check is missing or failing. Validate this rather than relying on a settings screenshot.

## Stage 2: Threat model and foundation

### 4. Write the threat model

Create `docs/THREAT_MODEL.md` defining:

- In-scope: malicious PR changes, hostile workflow modifications, dependency poisoning, credential access, unexpected release changes, harmful agent-generated edits, and local files introduced by clone/pull/install.
- Out-of-scope for v1: guaranteed prevention of arbitrary OS malware execution, proving all code benign, monitoring unapproved user folders, stopping a laptop while powered off, or unlimited third-party cloud usage.
- Trust boundaries: untrusted repository content, local scanner process, trusted release binaries, optional AI, GitHub workflows, and merge-authorizing components.
- Failure cases: interrupted scan, stale Git SHA, base change, poisoned cache, malicious file names, oversized files, nested repos, symlink loops, offline threat databases, forged reports, changed workflows, and GitHub downtime.
- Privacy policy: local-only processing by default, opt-in outbound traffic, secret redaction, logs retention, and safe telemetry defaults.

**Done when:** every planned feature maps to a threat and a concrete acceptance test.

### 5. Scaffold Rust and frontend workspaces

Suggested structure:

```
mergelatch/
  crates/
    core/
    cli/
    policy/
    reports/
    git-inspection/
  apps/
    sentinel/
      src/
      src-tauri/
  integrations/
    agents/
  rules/
  fixtures/
  tests/
  docs/
  .github/
    workflows/
  Cargo.toml
  README.md
```

Install the currently supported Rust toolchain, Node.js, pnpm, and Tauri prerequisites on developer machines. Pin verified compatible versions in toolchain and package files rather than assuming today's latest versions work together.

Initial developer commands, **once the workspace exists**:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For the desktop UI, create a Tauri + React/TypeScript app following the current official Tauri guide, then connect its Rust commands to the shared scanning crates. Developers may use Vite localhost during development only.

**Done when:** a clean checkout builds, tests, and runs on a documented development machine, with CI reproducing the checks.

### 6. Define scanner APIs before adding rules

Implement typed interfaces for `ScanTarget`, `Finding`, `Evidence`, `ScanLimits`, `PolicyDecision`, `ScanStatus`, `RevisionIdentity`, and `Report`. Distinguish:

- `clean`: required inspections completed; no configured blocking finding.
- `findings`: inspections completed with one or more detections.
- `incomplete`: one or more required inspections could not complete.
- `error`: scanner malfunction, invalid policy, or corrupted report.

Use a machine-readable schema with versioning, stable rule identifiers, and deterministic output ordering. Store hashes for inspected inputs and policy versions. Never treat `incomplete` or `error` as a passing security gate.

**Done when:** unit tests cover serialization, invalid input, exit codes, policy precedence, and output determinism.

## Stage 3: Scanning and detection

### 7. Build deterministic security rules

Add independent, explainable detectors for risky GitHub Actions permissions, privileged execution of untrusted PR content, unexpected changes to release scripts, sensitive file paths, executable script introduction, and credential-like patterns. Do not claim that a heuristic proves malicious intent.

Implement strict size/time limits, safe archive handling, symlink controls, path normalization, nested repository behavior, and exclusion rules. Do not execute scanned files.

**Done when:** every detector has a documented benign test and a documented dangerous-pattern test, with reproducible evidence.

### 8. Integrate dependency and malware intelligence

Evaluate compatible tools such as OSV-Scanner and YARA-X, including licenses, executable distribution, update authenticity, platform support, resource costs, and offline behavior. Treat third-party detections as findings with provenance, not blanket proof of malware.

Ensure rule updates have integrity verification and rollback. Keep threat data outside untrusted repository control. Use safe defaults when databases are stale.

**Done when:** known test samples are detected, ordinary projects do not produce unacceptable false positives, and offline behavior is documented.

### 9. Implement revision-bound policy decisions

- Capture repository, PR/base/head identities, relevant tree/diff information, engine version, policy hash, and ruleset identity.
- Revalidate on new commits and material changes to the base branch.
- Keep waivers narrow, auditable, expiring where appropriate, and unavailable to untrusted PR authors.
- Use a dedicated, nonskippable gate job that reports success only when required checks actually completed.

**Done when:** pushing a new commit invalidates the former evidence and stale findings cannot authorize merging.

## Stage 4: GitHub integration

### 10. Create `mergelatch-action`

After the engine and reports are stable:

1. Create a separate public GitHub repository `mergelatch-action`.
2. Publish a versioned composite or JavaScript Action that invokes a verified scanner release.
3. Pin downloaded binaries by signed release or strong digest verification, and pin dependencies by full commit SHA where appropriate.
4. Provide a working sample workflow tested on `pull_request`. Add `merge_group` only where merge queues are supported and configured.
5. Apply minimal token permissions such as `contents: read` for read-only scanning. Do not pass write-capable secrets to untrusted PR analysis.
6. Avoid `pull_request_target` for untrusted code execution; never run `npm install`, `make`, test scripts, or downloaded PR binaries with privileged credentials before inspection.
7. Require a stable final gate job with verified `success`, never success by default when scans are skipped, neutral, cancelled, or incomplete.

**Done when:** external public test repositories can install the Action at a pinned version and reproduce good, blocked, and incomplete scans.

### 11. Add protected auto-merge

1. Confirm required GitHub checks and human review are enforced.
2. Enable **Allow auto-merge** in the consuming repository's GitHub settings.
3. Default to maintainer-initiated auto-merge. Let GitHub complete it when requirements pass.
4. Keep sensitive-path PRs and security-policy modifications under mandatory human review.
5. Add opt-in policy-based auto-merge only after separate authorization and race-condition tests.
6. Never mix read-only PR scanning and a write-enabled merge actor in one trust domain.
7. Test stale SHAs, changes from fork authors, updates during scan, base-branch changes, and outages.

**Done when:** authorized low-risk PRs merge only after verified requirements; malicious, incomplete, stale, or unapproved changes do not.

**Caution:** a standalone GitHub Action cannot be treated as an unforgeable external security authority if an attacker can alter workflows or policy files in the same PR. Protect those files with CODEOWNERS and stronger repository policy, and document residual risks. Reassess whether a separate trusted service/App is justified before offering full hands-free auto-merge.

## Stage 5: Desktop release

### 12. Build Windows Sentinel as a packaged application

Implement in the Tauri project:

- First-run onboarding and explicit folder permissions.
- Repository discovery inside approved directories.
- Scans scheduled by the user and incremental filesystem watching.
- Scan queue, resource caps, caching, offline mode, and reconciliation after resume.
- Local SQLite history, findings, rule versions, and dismissals.
- Tray icon, optional startup-at-login, OS notifications, scan history, and manual rescans.
- View evidence safely, without automatically executing suspicious files or deleting project data.
- Secure update verification, clear permission controls, and an uninstall path.

Use bundled frontend assets. Do **not** include the Tauri localhost plugin in production. Windows end users must not need a terminal, a Vite server, Git, Node.js, pnpm, or a cloud account just to scan folders.

**Done when:** a non-developer can install a Windows release, pick a folder, scan it, receive a notification, and uninstall the app on a fresh test machine.

### 13. Add local dashboards and notifications

Provide clear views for:

- Protected and unprotected repositories.
- Last successful and incomplete scan.
- Findings with severity, confidence, evidence, and file location.
- Ruleset age and last update.
- Decisions, dismissals, exceptions, and audit history.
- CPU/resource use and pause controls.

Explain limitations and avoid messages that sound like a guarantee of safety. Support keyboard navigation, accessible contrast, and light/dark themes.

**Done when:** users can distinguish a clean scan from an incomplete scan without reading logs.

## Stage 6: Optional ecosystem integrations

### 14. Add Agent Guard

Provide a local CLI or MCP-compatible interface for supported coding agents to run checks and read findings. Agents may propose fixes but must not rewrite policy silently, approve their own changes, access high-privilege merge credentials, or turn findings into a clean result.

No model account, API subscription, or AI usage must be required for the scanner's core features. Support official sign-in flows only where the provider authorizes third-party integration.

**Done when:** the local scanner works identically with AI enabled, AI disabled, or an AI service unavailable.

### 15. Add Stellar/Soroban checks

Introduce contract release-artifact integrity, network configuration changes, authorization-sensitive diffs, and CI signing/release risks. Prefer verifiable properties (hashes, permissions, paths, config values). Flag semantics requiring human review rather than inventing a full security proof.

**Done when:** documented real-world Stellar/Soroban test repositories produce accurate, reproducible results.

## Stage 7: Independent validation and publication

### 16. Build a security benchmark and failure test suite

Test, at minimum:

- Known dangerous-pattern fixtures and representative benign fixtures.
- New/updated/deleted files; symlinks; huge and binary files; unusual names; nested repos.
- Changed PR SHA, rebases, updated base branches, cancelled jobs, skipped jobs, and merge queues.
- Github API/action timeouts and rate-limit responses.
- Scanner crashes, bad policy, stale threat database, and failed rule downloads.
- Desktop restarts, system sleep, slow disks, offline runs, and locked folders.
- Protected policy-file modifications, attempts to forge status-check success, and untrusted workflow execution.
- Signed/digest-verified release update and installation/uninstallation tests.

Publish test methodology and results. Do not invent detection rates or claim zero false negatives.

### 17. Create trustworthy builds and releases

1. Configure independent Linux, macOS, and Windows CI as the implementation reaches those platforms; ship Windows first.
2. Pin dependencies, enable vulnerability audits, and generate an SBOM and release checksums.
3. Build an installable Windows artifact on a verified Windows runner.
4. Verify clean-machine installation. Note that unsigned installers may produce Windows SmartScreen warnings; do not tell users to ignore security warnings blindly.
5. Publish GitHub Releases with full changelog, release assets, checksums, compatibility requirements, and honest limitations.
6. Add documentation with real screenshots from the actual app and a tested GitHub Action snippet.
7. Perform external pilot testing with consenting maintainers and collect false-positive and usability reports.

**Done when:** a first-time user can install and use the release using only the published README, and a maintainer can install the Action into a public test repository and safely demonstrate a blocked PR.

## Publication checklist

- [ ] Organization and name verified
- [ ] License selected
- [ ] Ownership and recovery secured
- [ ] Security threat model and private disclosure path published
- [ ] GitHub branches and sensitive files protected
- [ ] Core scanner functional with documented limitations
- [ ] Safe test corpus and benchmark results published
- [ ] Engine report schema and failure states tested
- [ ] GitHub Action uses least privilege and verified artifacts
- [ ] Required merge check genuinely enforced
- [ ] Auto-merge remains opt-in and does not bypass human review where required
- [ ] Windows installer works without localhost or development tools
- [ ] Desktop folders require user permission
- [ ] Local data and optional outbound traffic documented
- [ ] Offline behavior and update integrity tested
- [ ] README and user documentation match the released product
- [ ] No invented badges, adoption counts, malware detection rates, or claims of complete safety

## Practical scope for the first public release

**V1 required:** usable Rust scanner, safe reports, reproducible rules/tests, unprivileged GitHub Action, required merge gate, maintainer-initiated GitHub native auto-merge, Windows desktop installer, local folder monitoring, and clear documentation.

**V1.1 candidates:** optional AI/MCP integration, deeper Stellar/Soroban adapter, more advanced automated merge policies, Linux/macOS packaged support, more threat intelligence sources.

This sequencing reduces scope risk while preserving the long-term product idea. Avoid opening large numbers of speculative issues before the architecture and first acceptance tests are proven.

## Official references

- [Tauri frontend configuration](https://v2.tauri.app/start/frontend/)
- [Tauri localhost plugin security warning](https://v2.tauri.app/plugin/localhost/)
- [GitHub auto-merge](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/automatically-merging-a-pull-request)
- [GitHub protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [GitHub Actions safe PR execution](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [GitHub composite Actions](https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action)
