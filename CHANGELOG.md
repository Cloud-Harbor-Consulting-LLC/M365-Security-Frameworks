# Changelog

All notable changes to **M365-Security-Frameworks** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Frameworks/Conditional-Access-Baseline/Policies/CA-EXC002-ServiceAccounts-Exclusion.md — written contract documenting that every human-targeted CA-* policy excludes the ServiceAccounts persona via `users.excludeGroups`, and that the persona is the inclusion target for the v1.2 compensating control (CA-COV010-ServiceAccounts-BlockUntrustedLocations). Defines persona membership rules, monthly attestation, quarterly sign-in review, and credential rotation procedure. Parallel in structure to CA-EXC001-EmergencyAccess-Exclusion.md.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/ — new folder for tenant-scoped artifacts that CA policy templates depend on (custom authentication strengths, named locations). Includes a README documenting the schema and how `Deploy-CABaseline.ps1` will resolve placeholder IDs against the tenant.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/CA-AUTH-STRENGTH-StandardAuth.json — custom authentication strength: Windows Hello for Business, FIDO2, or password + Microsoft Authenticator push. Default strength for general user populations during the rollout to phishing-resistant credentials.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/CA-AUTH-STRENGTH-StrongAuth.json — custom authentication strength: Windows Hello for Business or FIDO2. Phishing-resistant only.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/CA-AUTH-STRENGTH-AdminAuth.json — custom authentication strength: FIDO2 only. Narrowest strength in the baseline; for privileged accounts and admin roles.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/CA-LOCATION-TrustedCountries.json — country-based named location template (`countryNamedLocation`). Default scope: US, `clientIpAddress` lookup, unknown countries excluded. Adopters customize the `countriesAndRegions` list to match their organization's trust posture before bootstrapping.
- Frameworks/Conditional-Access-Baseline/Scripts/Deploy-CABaseline.ps1 — added `Resolve-NamedLocationId` resolver, new `-SupportingArtifactsPath` and `-TrustedCountriesLocationName` parameters, and a new `REPLACE_WITH_TRUSTED_COUNTRIES_LOCATION_ID` substitution. The deployer now resolves named-location placeholders against `/identity/conditionalAccess/namedLocations` by display name.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/README.md — added named-locations section and a bootstrapping-artifacts section with the Graph API calls operators run once per tenant to provision custom authentication strengths and named locations before deployment.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV004-Global-NoPersistentBrowserSession.json — Global persona session-hardening policy. Disables persistent browser sessions (`persistentBrowser.mode=never`) and enforces a 4-hour browser sign-in frequency for all users. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts personas per CA-EXC001 and CA-EXC002. Scoped to `clientAppTypes=["browser"]`; excludes iOS and Android platforms where OS-level session handling makes the control redundant. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV005-Global-BlockDeviceCodeFlow.json — Global persona auth-flow policy. Blocks sign-ins that use OAuth 2.0 device code flow (`conditions.authenticationFlows.transferMethods="deviceCodeFlow"`) for all users on all applications. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Closes a phishing-friendly grant flow rarely used outside legitimate device-pairing scenarios. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV006-Global-BlockAuthenticationTransfer.json — Global persona auth-flow policy. Blocks Authentication Transfer (cross-device authentication initiated on one device and completed on another, `conditions.authenticationFlows.transferMethods="authenticationTransfer"`) for all users on all applications. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV007-Global-BlockUnknownPlatforms.json — Global persona platform-hygiene policy. Blocks sign-ins from device platforms not in the named set (`includePlatforms=["all"]`, `excludePlatforms=["windows","macOS","iOS","android","linux","windowsPhone"]`) for all users on all applications. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Catches sign-ins from spoofed, headless, or obsolete device platforms that fall outside the tenant's supported fleet. Ships in report-only.

### Fixed

- Top-level `README.md` — Frameworks table status for the Conditional Access Baseline updated from `v1.0.0` to `v1.1.0` to match the v1.1.0 release. Documentation-only correction; missed during the v1.1.0 release prep.

---

## [1.1.0] — 2026-05-01

Operational maturity and persona completeness release for the **Conditional Access Baseline**. Adds the External Guests and Workload Identities personas, a written Emergency Access exclusion contract, a report-only telemetry script, repo governance scaffolding, and a hardened deployer.

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

- Deploy-CABaseline.ps1 — hardened `Write-Status` against empty-string messages by adding `[AllowEmptyString()]` to the `$Message` parameter. Prevents the StrictMode regression that surfaced in v1.0.1 where `Write-Status ""` (used for blank-line spacing) threw a parameter validation error.
- Get-CABaselineImpact.ps1 — StrictMode-safe check for `@odata.nextLink` so the script doesn't error on the final page of sign-in results.
- Get-CABaselineImpact.ps1 — force array semantics around `.Count` accesses so the script works when 0 or 1 sign-ins / records / unique users exist (StrictMode correctness).

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
[Unreleased] : <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.1.0...HEAD>

[1.1.0] : <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.0.1...v1.1.0>

[1.0.1] : <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.0.0...v1.0.1>

[1.0.0] : <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/releases/tag/v1.0.0>
