# Changelog

All notable changes to **M365-Security-Frameworks** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Planned for v1.1 of the **Conditional Access Baseline**:

- Repo hygiene: issue templates, PR template, `CODEOWNERS`, GitHub Project board
- Report-only telemetry script to quantify impact before enforcement
- Workload Identities persona and baseline policy
- External Guests (B2B) persona and baseline policy
- Explicit documented Emergency Access exclusion policy template

---

## [1.0.0] — 2026-04-22

First public release of the **Conditional Access Baseline** framework.

### Added

- **Framework landing page** at `Frameworks/Conditional-Access-Baseline/README.md` — scope, principles, six-policy table, prerequisites, and deployment workflow.
- **Design document** (`Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md`) — four defensible-baseline principles, principle-coded naming convention, persona model, exclusion strategy, staged rollout sequence, and per-policy design specifications.
- **Six Conditional Access policy templates** in `Frameworks/Conditional-Access-Baseline/Policies/`, all shipped in report-only (`enabledForReportingButNotEnforced`):
  - `CA-COV001-AllUsers-BlockLegacyAuth.json`
  - `CA-COV002-AllUsers-RequireMFA.json`
  - `CA-SIG001-SensApps-RequireCompliantDevice.json`
  - `CA-AUT001-PrivAccounts-RequirePhishResistantMFA.json`
  - `CA-AUT002-PrivRoles-RequirePhishResistantMFA.json`
  - `CA-SIG002-AllUsers-RequireStepUpOnRisk.json`
- **Deployment script** `Frameworks/Conditional-Access-Baseline/Scripts/Deploy-CABaseline.ps1` — PowerShell 7, Microsoft Graph SDK 2.x, placeholder resolution, `-WhatIf` support, report-only default, confirmation-gated `-Enforce` switch.
- **Scripts usage guide** (`Frameworks/Conditional-Access-Baseline/Scripts/README.md`) — prerequisites, usage examples, expected output, troubleshooting.
- **Executive ROI document** (`Frameworks/Conditional-Access-Baseline/Business-Case/ROI-CONDITIONAL-ACCESS.md`) — business risk framing, investment model, risk reduction narrative, and compliance mapping (SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST SP 800-53).

### Added (repository foundation)

- Top-level `README.md` with Frameworks roadmap table.
- MIT `LICENSE`.
- `CONTRIBUTING.md` and `SECURITY.md`.
- `.gitignore` covering secrets, PowerShell artifacts, editor noise, and logs.
- `.markdownlint.json` disabling MD013, MD033, MD041, and MD060 for pragmatic Markdown style.
- Roadmap stub READMEs for:
  - Intune Compliance Baseline (Q3 2026)
  - Entra ID Governance Toolkit (Q4 2026)
  - Defender XDR Detection Rules (Q1 2027)

### Security

- All CA policy templates ship in report-only by default. Operators must explicitly opt in to enforcement via the `-Enforce` switch on the deployment script.
- Private vulnerability reporting enabled on the repository.
- Emergency access group exclusion placeholder documented across all applicable policies.

### Acknowledgments

This framework was shaped by the public work of Joey Verlinden, Daniel Chronlund, and Claus Jespersen on Conditional Access design patterns.

---

[Unreleased]: https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/releases/tag/v1.0.0
