# Security Policy

Thank you for helping keep this repository and its users safe. If you've found a security issue in any script, policy template, or deployment artifact in this repo, please follow the disclosure process below.

## What counts as a security issue

- A script that could leak credentials, tokens, or tenant-specific secrets
- A Conditional Access or compliance policy template that, if deployed as-is, weakens rather than strengthens tenant security
- A deployment script that grants unintended or excessive Microsoft Graph permissions
- Any artifact that could cause data loss, account lockout beyond documented behavior, or privilege escalation

Configuration preferences, naming debates, or suggestions to add new content are **not** security issues — open a regular GitHub issue for those.

## How to report

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately via one of the following:

- **Email:** `derek.morgan@cloudharborconsulting.cloud` with subject line beginning `[SECURITY]`
- **GitHub private advisory:** Use the [Report a vulnerability](https://github.com/dmorgan-chc/M365-Security-Frameworks/security/advisories/new) button in the repo's Security tab

Please include:
- A description of the issue and which artifact is affected
- Steps to reproduce or demonstrate the impact
- Your assessment of severity (low / medium / high / critical)
- Any suggested remediation

## What to expect

| Timeframe | What happens |
|-----------|--------------|
| Within 3 business days | Acknowledgment of your report |
| Within 14 business days | Initial triage and preliminary remediation plan |
| Coordinated | Public disclosure after a fix is published, with credit to the reporter (unless anonymity is requested) |

## Scope

This policy covers artifacts published in this repository. It does **not** cover:

- Vulnerabilities in Microsoft Entra ID, Intune, or any Microsoft product — report those via [Microsoft Security Response Center (MSRC)](https://msrc.microsoft.com/)
- Issues in third-party tools referenced in the frameworks — report to the respective maintainer

## Thank you

Responsible disclosure is how the Microsoft security community keeps tenants safe. If you've taken the time to report something here, I appreciate it.
