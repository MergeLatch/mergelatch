# Contributing to MergeLatch

Thank you for your interest. MergeLatch is in early development: a command-line scanner with four narrow rules and an advisory GitHub Action exist, and everything else is planned. The most useful contributions right now are security review of the existing code, documentation review, threat-model feedback, and discussion of the [build plan](docs/BUILD_PLAN.md).

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
- Where a second reviewer is available, a maintainer other than the author must approve before merge. See "Sole-maintainer period" below for the temporary procedure.
- Be prepared to revise. Maintainers may ask for changes or decline a proposal.

## Security-sensitive changes

The following require independent review by a maintainer who did not write the change where one is available, and the pull request description must explain the security impact:

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

### Sole-maintainer period

The project currently has one maintainer, so independent review is not always possible. Until a second reviewer exists, the following temporary procedure applies. It is not equivalent to independent approval and must not be described as such.

1. The owner opens a pull request for every change, including their own. Direct pushes to `main` are not used.
2. The owner reviews their own diff after a pause, using the pull request template, and records in the pull request that this was an owner review and not an independent approval.
3. For security-sensitive changes, the owner states the security impact, the checks performed, and the remaining risks, and marks the pull request as "owner-reviewed, not independently reviewed".
4. The owner requests outside review where practical, for example by asking a trusted contributor to comment, and records the outcome.
5. The owner merges manually. Automatic merging is not enabled for security-sensitive changes, and is not used for any change until suitable protections, such as branch rules and required checks, are in place and documented.
6. When a second maintainer joins, security-sensitive paths move to independent review, and this section should be removed or updated.

## Reporting vulnerabilities and sharing samples

Do not report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md). Never post real malware, credentials, or exploit details in issues or pull requests.

## Use of AI tools

You may use AI tools, but you are responsible for every line you submit. Review, understand, and test generated content before opening a pull request, and do not submit fabricated results or claims. Disclose substantial AI assistance in the pull request description.

## Conduct

Be respectful and constructive. Assume good faith, and keep discussion focused on the work.
