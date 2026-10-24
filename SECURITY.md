# Security Policy

MergeLatch is in early development. The repository contains a command-line scanner and an advisory GitHub Action. There is no published release or installer. This policy covers the repository contents and, later, the released software.

## Reporting a vulnerability

Do not report vulnerabilities in public issues, pull requests, or discussions.

Use GitHub's private vulnerability reporting form:

https://github.com/MergeLatch/mergelatch/security/advisories/new

You can also reach it from the **Security** tab of the repository by choosing **Report a vulnerability**. Reports submitted this way are visible only to you and the repository maintainers.

## What to include in a report

- The affected file, component, or version. For the GitHub Action, give the full 40-character commit SHA you reference.
- The impact and who could be affected.
- Steps to reproduce, kept as small as possible.
- Whether you plan to disclose the issue publicly, and when.

## What not to submit publicly

Do not post any of the following in public issues, pull requests, or comments:

- Real malware samples or live malicious payloads.
- Credentials, tokens, private keys, or other secrets, including expired ones that reveal how a system is configured.
- Working exploit details for an unfixed vulnerability.
- Private repository contents or personal data.

If you need to share a detection test case, use a harmless, clearly labelled fixture that reproduces the pattern without being functional malware.

## Scope

In scope:

- Flaws in MergeLatch's own code, build, release, and workflow configuration.
- Ways to make a scan pass, hide a finding, or disable a check without the maintainers' knowledge.
- Ways for untrusted repository content to execute code or escape the intended permissions.

Out of scope:

- Vulnerabilities in third-party software that MergeLatch only reports on.
- A missed detection of a novel attack. These are valuable and can be reported as ordinary issues, but MergeLatch does not guarantee detecting every threat. See [the threat model](docs/THREAT_MODEL.md).

## Response expectations

MergeLatch is maintained by volunteers. There is no service-level commitment. The maintainers aim to acknowledge reports promptly, work with the reporter on a fix, and credit reporters who want credit.

## Supported versions

No versions have been released, so there is no supported-version list. Until a release exists, fixes are made on `main`. Anyone who references the Action by commit SHA must review a newer commit and change the whole SHA to receive a fix; nothing updates automatically.
