# Changelog

All notable changes to **M365-Security-Frameworks** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Scripts/Get-CABaselineImpact.ps1 — report-only telemetry tool: analyzes sign-in logs and summarizes what each report-only CA policy would have done if enforced.
- Scripts/README.md — documentation and promotion rubric for Get-CABaselineImpact.ps1.
- .github/ISSUE_TEMPLATE/ — bug report, policy request, and documentation fix issue templates.
- .github/pull_request_template.md — PR checklist aligned to the four design principles.
- .github/CODEOWNERS — auto-review routing on every PR.
- Frameworks/Conditional-Access-Baseline/Policies/CA-EXC001-EmergencyAccess-Exclusion.md — written contract documenting that every CA-* policy excludes the Emergency Access persona, plus the operational runbook (alerting, monthly attestation, quarterly recovery drill, rotation).
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG003-Guests-RequireMFA.json — requires MFA for all external users (B2B collaboration guests, direct-connect users, internal guests, service providers, and other external users) on all applications. Honors CA-EXC001 by excluding the Emergency Access persona.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV003-WorkloadIdentities-TrustedLocations.json — blocks service principal sign-ins from outside a tenant-defined Trusted IPs named location. Requires Microsoft Entra Workload Identities Premium SKU; CAE does not apply to workload identity tokens.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV003-WorkloadIdentities.md — design doc covering hard prerequisites (Workload Identities Premium, Trusted IPs named location), per-SPN exclusion model (distinct from user-targeted CA-EXC001), SPN discovery query, and CAE limitations for workload identities.

### Changed

- Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md — documented section 6.7 (`CA-COV003-WorkloadIdentities-TrustedLocations`) and section 6.8 (`CA-SIG003-Guests-RequireMFA`) per-policy specs; added rollout-sequence rows 7 and 8; added `CA-EXC001` reference under section 4.1; updated section 6 intro count from "six" to "eight" starter policies.
- Frameworks/Conditional-Access-Baseline/Business-Case/ROI-CONDITIONAL-ACCESS.md — updated executive summary, "What the baseline delivers" table, "Risk reduction framing" table, licensing section, implementation prerequisites, and quarterly cadence to cover `CA-COV003` (workload identities — trusted locations) and `CA-SIG003` (guests — require MFA). Policy count changed from "six" to "eight". Workload Identities Premium add-on noted as a licensing line item. Quarterly operational estimate updated from ~32 hours to ~40 hours per year.

### Fixed

- Get-CABaselineImpact.ps1 — StrictMode-safe check for `@odata.nextLink` so the script doesn't error on the final page of sign-in results.
- Get-CABaselineImpact.ps1 — force array semantics around `.Count` accesses so the script works when 0 or 1 sign-ins / records / unique users exist (StrictMode correctness).

### Planned for v1.1 of the **Conditional Access Baseline**

- Repo hygiene: issue templates, PR template, `CODEOWNERS`, GitHub Project board
- Report-only telemetry script to quantify impact before enforcement
- Workload Identities persona and baseline policy
- External Guests (B2B) persona and baseline policy
- Explicit documented Emergency Access exclusion policy template
- `Write-Status` function hardened with `[AllowEmptyString()]` to prevent future regressions

---

## [1.0.1] — 2026-04-23

Stability and accuracy fixes for the **Conditional Access Baseline**.

### Fixed

- **Deploy-CABaseline.ps1** — script no longer terminates with `Cannot bind argument to parameter 'Message' because it is an empty string` after a successful deployment. Replaced the empty-string `Write-Status ""` call before the summary table with a direct `Write-Host ""` for visual spacing.
- **Deploy-CABaseline.ps1** — added `Application.Read.All` to the required Graph scopes. Without it, `CA-SIG001-SensApps-RequireCompliantDevice` could not resolve the Azure Management application reference and policy creation failed. Updated the connection guidance, prerequisite check, and inline error messages to reflect the additional scope.
- **Deploy-CABaseline.ps1** — corrected the authentication strength Graph endpoint: `authenticationStrengths` (plural) → `authenticationStrength` (singular). This fixes `Resolve-AuthStrengthId` failing to return the tenant's `Phishing-resistant MFA` policy ID for the CA-AUT001 and CA-AUT002 templates.
- **Frameworks/Conditional-Access-Baseline/Scripts/README.md** — same Graph endpoint typo corrected in the documentation so the README matches the working script.

### Changed

- **Frameworks/Conditional-Access-Baseline/README.md** — updated component statuses from `Planned` to `Released` to reflect v1.0.0 availability.
- **.markdownlint.json** — added `MD040` (fenced-code-language) to the disabled-rules list so code blocks without language identifiers (commit message examples, shell prompts) no longer trigger warnings.

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
