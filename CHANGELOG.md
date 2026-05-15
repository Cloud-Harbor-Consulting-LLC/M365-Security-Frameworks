# Changelog

All notable changes to **M365-Security-Frameworks** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.2.0] - 2026-05-15

### Added

- Frameworks/Intune-Compliance-Baseline/Policies/ICB-WIN001-Baseline-DefenderAndBitLocker.json — first ICB Windows 10/11 compliance template. Reproduces the 9 active settings from the May 12 source-of-truth export (BitLocker, storage encryption, firewall, TPM, antivirus, Defender enabled, signature freshness at 1 day, real-time protection, Defender for Endpoint MTD at medium). Includes the graduated-response scheduledActionsForRule block — notify at 0 days, mark noncompliant at 7 days; no retire on corporate Windows per POLICY-DESIGN section 5. Assigns to the ICB-Persona-CorpWindows persona group.
- Frameworks/Intune-Compliance-Baseline/Policies/README.md — folder README documenting the week-1 manual import model (Microsoft Graph PowerShell and Intune portal paths), placeholder substitution, post-import validation steps, and the template inventory. Notes that the deployer script is deferred per POLICY-DESIGN section 4.
- Frameworks/Intune-Compliance-Baseline/Design/POLICY-DESIGN.md — Intune Compliance Baseline design specification. Establishes four framework design principles (1.1 Platform-led scope, 1.2 Verify don't enforce, 1.3 Compliance as a graded scale, 1.4 Signal-clean handoff to Conditional Access), platform-led naming convention (ICB-WIN###, ICB-MAC###, ICB-IOS###, ICB-AND###, ICB-LIN###), device persona model (CorpWindows, CorpMac, CorpMobile, BYODMobile, CorpLinux), out-of-scope device classes, action-for-noncompliance graduated-response defaults (notify at 0, block at 7 days, retire at 30 days for BYOD only), signal-handoff-to-CA mapping table (deviceComplianceState → compliantDevice grant), rollout sequence, and per-template design specifications. Includes the ICB-WIN001-Baseline-DefenderAndBitLocker per-template spec (9 settings reproducing the production source-of-truth export from May 12, 2026: bitLockerEnabled, storageRequireEncryption, activeFirewallRequired, tpmRequired, antivirusRequired, defenderEnabled, signatureOutOfDate, rtpEnabled, deviceThreatProtectionEnabled with required security level medium) and the ICB-WIN002 through ICB-WIN007 hardening roadmap (Secure Boot, Code Integrity / HVCI, OS version floor, password / PIN complexity, EALAM driver, Device Health Attestation).
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG008-Internal-TokenProtection.json — Internal persona session-hardening policy. Enables Token Protection (`sessionControls.secureSignInSession.isEnabled=true`) for Windows sign-ins to the Office 365 application bundle. Cryptographically binds refresh tokens and Primary Refresh Tokens to the issuing device's TPM-protected key, blocking redemption of stolen tokens from any other device. This is the only policy in the baseline that operates at token-redemption time rather than sign-in time. Scoped to `platforms.includePlatforms=["windows"]` and `clientAppTypes=["all"]`. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG008-Internal-TokenProtection.md — paired design doc covering the post-MFA token-replay threat surface (AiTM session-token capture, infostealer token theft, cookie redemption replay), how Token Protection layers with Continuous Access Evaluation (CAE) without redundancy, current coverage seams (Windows-only, Exchange Online + SharePoint Online sign-in paths within the Office365 bundle, modern-auth-only, client-version dependency), the rollout-sequence position 9 slot, and the 14-day report-only validation procedure including the non-supporting-client inventory step.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV010-ServiceAccounts-BlockUntrustedLocations.json — ServiceAccounts persona compensating control. Blocks service-account sign-ins originating outside the CA-LOCATION-TrustedCountries named-location set (`locations.includeLocations=["All"]`, `locations.excludeLocations=["REPLACE_WITH_TRUSTED_COUNTRIES_LOCATION_ID"]`). Closes the coverage gap created by CA-EXC002, which exempts the ServiceAccounts persona from every human-targeted CA policy. Inverse of the standard pattern: ServiceAccounts is the inclusion target; only EmergencyAccess and WorkloadIdentities are excluded (WorkloadIdentities sit on the separate CA-COV003 code path). `clientAppTypes=["all"]` to capture varied service-account authentication paths. Ships in report-only; adopters use the 14-day soak to inventory legitimate service-account sign-in geographies before enforcement.
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG007-Guests-BlockNonGuestAppAccess.json — Guests persona application-scope policy. Blocks guest sign-ins to any application outside the Microsoft 365 collaboration set (`includeApplications=["All"]`, `excludeApplications=["Office365"]`). Closes the gap where a B2B guest token issued for a collaboration app could be re-used against unrelated registered applications in the tenant. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Adopters extend `excludeApplications` with their own guest-shared line-of-business apps during the report-only soak. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG006-Admins-BlockMediumAndHighSignInRisk.json — Admins persona ID Protection sign-in risk policy. Blocks admin sign-ins (`grantControls.builtInControls=["block"]`, `operator=OR`) when `signInRiskLevels=["medium","high"]`. Scope mirrors CA-AUT005 (PR 11): `CA-Persona-GlobalAdmins` plus the 14 highly-privileged Entra ID directory roles by template ID. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Distinct from CA-SIG002 (all-users; MFA step-up fallback): SIG006 hard-blocks because admin credentials in a risk-flagged session do not get a re-challenge path. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-AUT005-Admins-RequireAdminAuthOnAdminPortals.json — Admins persona app-scoped authentication-strength policy. Requires the AdminAuth custom authentication strength (FIDO2 only) for sign-ins from the admin scope (`CA-Persona-GlobalAdmins` plus the 14 highly-privileged Entra ID directory roles by template ID) when accessing Microsoft Azure Management (`797f4846-ba00-4fd7-ba43-dac1f8f63013`) or Microsoft Admin Portals (`MicrosoftAdminPortals`). Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Layers on top of CA-AUT001 / CA-AUT002 (StrongAuth = WHfB or FIDO2) by narrowing to FIDO2-only on the highest-value admin surfaces. Auth-strength ID resolved at deploy time via `REPLACE_WITH_ADMIN_AUTH_STRENGTH_ID`. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV009-Internal-RequireCompliantDeviceOnDesktops.json — Internal persona desktop-platform policy. Requires compliant device or hybrid Azure AD joined device (`grantControls.builtInControls=["compliantDevice","domainJoinedDevice"]`, `operator=OR`) for sign-ins from Windows, macOS, and Linux platforms. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Scoped to `clientAppTypes=["browser","mobileAppsAndDesktopClients"]`. Mobile platforms (iOS, Android) are handled separately and out of scope for this policy. Closes the desktop-side gap where Internal users could sign in from unmanaged devices. Ships in report-only.
- Intune Compliance Baseline (ICB) framework skeleton: framework README at Frameworks/Intune-Compliance-Baseline/README.md, platform-led naming convention (ICB-WIN###, ICB-MAC###, ICB-IOS###, ICB-AND###, ICB-LIN###), scope, and roadmap. POLICY-DESIGN.md and the first Windows 10/11 compliance template land in subsequent PRs this week, with the v0.1.0-preview tag scheduled for Fri May 15, 2026.
- CA-SIG004-Global-MediumUserRisk: graduated medium User Risk response requiring StandardAuth and a password change, with sign-in frequency set to every time. Global persona with the standard Emergency Access / Workload Identities / Service Accounts excludes.
- CA-SIG005-Global-MediumSignInRisk: graduated medium Sign-In Risk response requiring StandardAuth, with sign-in frequency set to every time. Global persona with the standard Emergency Access / Workload Identities / Service Accounts excludes.
- CA-AUT003-Global-RegisterDevice policy template (Global persona; userAction urn:user:registerdevice; requires StandardAuth authentication strength; report-only on first deployment; excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts groups).
- CA-AUT004-Global-RegisterSecurityInfo policy template (Global persona; userAction urn:user:registersecurityinfo; requires StandardAuth authentication strength; report-only on first deployment; excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts groups).
- CA-COV008-Global-BlockByLocation policy template (Global persona; blocks sign-ins from locations outside the CA-LOCATION-TrustedCountries named-location set; report-only on first deployment; excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts groups).
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

### Changed

- Frameworks/Conditional-Access-Baseline/Business-Case/ROI-CONDITIONAL-ACCESS.md — folded the v1.2 slate into the executive ROI document. Policy count changed from "eight" to "twenty-three". Five-persona model (Global, Internal, Admins, Guests, ServiceAccounts) noted in the executive summary alongside the workload-identity policy. Expanded "What the baseline delivers" table with 15 new rows covering the v1.2 policies (CA-AUT003, CA-AUT004, CA-COV004 through CA-COV010, CA-SIG004 through CA-SIG008), grouped by persona segment. Expanded "Risk reduction framing" table to mirror. Added Token Protection client-version note and ServiceAccounts operational note to the licensing section. Added Trusted Countries named-location provisioning, three custom authentication strength provisioning steps (StandardAuth, StrongAuth, AdminAuth), and the ServiceAccounts persona group to the implementation prerequisites. Quarterly operational estimate updated from approximately 40 hours to approximately 52 hours per year to cover ServiceAccounts geography review, admin-context risk review, and expanded risk-detection tuning. Recommended investment approach Phase 3 window extended from weeks 9 to 12 to weeks 9 to 14 to accommodate the larger enforcement surface.
- Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md — documented sections 6.9 through 6.23 (`CA-COV004`, `CA-COV005`, `CA-COV006`, `CA-COV007`, `CA-AUT003`, `CA-AUT004`, `CA-COV008`, `CA-COV009`, `CA-SIG004`, `CA-SIG005`, `CA-AUT005`, `CA-SIG006`, `CA-SIG007`, `CA-COV010`, `CA-SIG008`) per-policy specs; added rollout-sequence rows 9 through 23; added the Service Accounts persona row to section 3 and the `CA-EXC002` reference under section 4.1 (permanent exclusions count updated from 2 to 3); added section 1.5 (v1.2 design refinements) and section 1.6 (Global and Admins scope definitions); updated section 6 intro count from "eight" to "twenty-three" starter policies.
  
### Fixed

- Top-level `README.md` — Frameworks table status for the Conditional Access Baseline updated from `v1.0.0` to `v1.1.0` to match the v1.1.0 release. Documentation-only correction; missed during the v1.1.0 release prep.

### Note on Intune Compliance Baseline timing

The original repo roadmap targeted the Intune Compliance Baseline at Q3 2026 for framework completion. The MVP Strategy publishing calendar (Month 2 Week 2, May 2026) calls for the first Intune compliance policy templates earlier. This release reconciles the two: the framework skeleton and first Windows 10/11 template ship now under the v0.1.0-preview tag (2026-05-15); full framework completion (macOS, iOS, Android, Linux templates, Deploy-ICBaseline.ps1, cross-framework integration doc with the Conditional Access Baseline) remains targeted at Q3 2026.

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
[Unreleased] : <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.2.0...HEAD>

[1.2.0] : <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.1.0...v1.2.0>

[1.1.0] : <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.0.1...v1.1.0>

[1.0.1] : <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.0.0...v1.0.1>

[1.0.0] : <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/releases/tag/v1.0.0>
