# Contributing to MergeLatch

Thank you for your interest. MergeLatch is in the design and planning stage, so the most useful contributions right now are documentation review, threat-model feedback, and discussion of the [build plan](docs/BUILD_PLAN.md).

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).

## Proposing a change

1. For anything beyond a typo or small correction, open an issue first and describe the problem and the proposed approach.
2. Fork the repository, or create a branch if you have write access.
3. Make your change on a dedicated branch. Do not commit directly to `main`.
4. Open a pull request using the pull request template and complete every section.

## Branches and commits

- Use short, descriptive branch names such as `docs/threat-model-update` or `fix/readme-link`.
- Each commit should be one meaningful, self-contained unit of work with an accurate message. Prefer a form such as `docs: clarify trust boundaries`.
- Do not split work into artificial commits, and do not rewrite shared history or force-push to branches others are using.
- Do not commit generated files, credentials, or unrelated formatting changes.

## Testing

- Describe in the pull request what you did to check your change, and include the actual results.
- Once code exists, new behavior needs tests, and security rules need both a positive fixture (should be detected) and a negative fixture (should not be flagged).
- For documentation, check that links resolve and that Markdown renders correctly.
- Do not claim a capability, test result, or security property that has not been implemented and verified.

## Pull request expectations

- Keep pull requests small and focused on one purpose.
- Explain the security implications of the change, even if the answer is "none".
- Describe remaining risks and known limitations honestly.
- A maintainer must approve before merge. Authors do not merge their own pull requests unless the project has recorded an exception.
- Be prepared to revise. Maintainers may ask for changes or decline a proposal.

## Security-sensitive changes

The following require additional review by a maintainer who did not write the change, and the pull request description must explain the security impact:

- Anything under `.github/`, including workflows, actions, and CODEOWNERS.
- Authentication, tokens, permissions, or secrets handling.
- Detection rules, policies, severity levels, and allow-lists.
- Release, signing, packaging, and update processes.
- Dependency additions or version changes.

Workflow changes must follow these rules:

- Declare the minimum `permissions` for each workflow and job.
- Do not run untrusted pull request code with write permissions or access to secrets. Treat `pull_request_target` and `workflow_run` as dangerous and justify any use.
- Do not interpolate untrusted values, such as branch names, titles, or bodies, directly into shell commands.
- Pin third-party actions to a full commit SHA.

## Reporting vulnerabilities and sharing samples

Do not report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md). Never post real malware, credentials, or exploit details in issues or pull requests.

## Use of AI tools

You may use AI tools, but you are responsible for every line you submit. Review, understand, and test generated content before opening a pull request, and do not submit fabricated results or claims. Disclose substantial AI assistance in the pull request description.

## Conduct

Be respectful and constructive. Assume good faith, and keep discussion focused on the work.
