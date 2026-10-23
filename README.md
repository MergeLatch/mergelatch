# MergeLatch

**Protect the contribution before it becomes part of the project.**

> **Project status: Design and implementation planning.** MergeLatch has not yet published a working scanner, GitHub Action, or desktop installer. The features below describe the intended product, not capabilities available today.

MergeLatch is an open-source project for checking security-sensitive changes in Git repositories. It is designed for maintainers reviewing pull requests and developers working with code cloned onto their computers.

The aim is simple: help people understand what changed, what might be dangerous, and whether a contribution is ready for review or merging.

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

*The Action and its verified installation snippet will be published after implementation and security testing.*

1. Add the official version-pinned MergeLatch workflow to your repository.
2. Run it against test pull requests, including safe and intentionally suspicious fixtures.
3. Review the results and tune documented policies.
4. Configure the MergeLatch gate as a required GitHub status check under branch protection.
5. Require normal project tests and suitable human approvals as well.
6. Optionally enable GitHub's native auto-merge. GitHub will merge only after the repository's configured requirements are satisfied.

**Important:** A security scan passing does not mean a pull request is correct or completely safe. A scan is not a substitute for tests or human review. Automated merging will be opt-in, and security-sensitive changes should require human approval.

## Planned: local CLI

The final CLI will support operations such as scanning a directory, scanning a Git diff, listing enabled rules, and exporting machine-readable findings. Exact command syntax will be documented and tested before publication. We do not publish placeholder commands as if they already work.

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

The project is in planning. Once the source repositories are created, we will publish a contribution guide, issue templates, a security disclosure process, and repeatable tests. Please do not submit real malware samples or secrets to public issues.

## Security

If you believe you have found a vulnerability in MergeLatch itself, use the private vulnerability-reporting mechanism documented in the repository once it is configured. Do not disclose exploit details or credentials in a public issue.

## License

A repository license will be selected and committed before code is published. Until then, this planning document should not be treated as a grant of software-use rights.

---

**Current status:** proposal and build plan only. Installation links, release badges, version numbers, performance claims, and coverage statistics will be added only after they are verified.
