# Conditional Access Baseline

A defensible-baseline framework for Microsoft Entra ID Conditional Access. Twenty-three policies across five personas plus workload identities, scoped to the access paths attackers exploit most frequently, with every policy shipped in report-only by default so adopters validate impact before enforcement. Companion reading: [Why Entra ID Conditional Access Fails in Practice (And How to Fix It)](https://www.cloudharborconsulting.cloud/post/why-entra-id-conditional-access-fails-in-practice-and-how-to-fix-it).

**Status:** 🟢 Released — v1.2.0

---

## Why a baseline first

Conditional Access is Microsoft's Zero Trust policy engine, not a collection of feature toggles. Most tenants accumulate Conditional Access policies the way attics accumulate boxes: one at a time, each with a forgotten owner and a half-remembered justification. The result is a policy set that is broad in count and narrow in coverage, with exclusions that no one reviews and signals that no one tunes.

A baseline reverses that pattern. Until a defensible baseline exists, adding more Conditional Access policies increases complexity without materially reducing risk. This framework establishes the floor.

---

## What a defensible baseline looks like

Four principles anchor every design decision in this framework:

1. **Identity-wide coverage.** No orphaned identities, applications, or legacy protocols authenticate outside the scope of Conditional Access. Every user, every guest, every workload identity, and every cloud app is covered by at least one evaluated policy.
2. **No standing exclusions.** Exclusions are a common attack path. Only two exclusion groups are permanent (emergency access accounts and workload identities, each governed by a hardened separate policy set). All other exclusions are time-bound, auditable, and reviewed.
3. **Layered signals.** Strong security emerges from combining signals (identity risk, device state, location, application sensitivity), not from any single control. Every signal-driven policy in this baseline evaluates two or more signals in combination.
4. **Authentication Strengths.** Not all MFA is equal. SMS and voice-call MFA are phishable via adversary-in-the-middle proxies; FIDO2, Windows Hello for Business, and certificate-based authentication are not. Privileged identities and high-value workloads in this baseline are protected by phishing-resistant methods.

The four principles are specified, with rationale and per-policy implementation notes, in [Design/POLICY-DESIGN.md](Design/POLICY-DESIGN.md).

---

## Naming convention

Every policy in this baseline follows the format:

`CA-[PrinciplePrefix][Number]-[Persona]-[Action]`

| Prefix | Principle | Use when the policy primarily enforces... |
|--------|-----------|-------------------------------------------|
| COV | Identity-wide coverage | Blanket coverage of users, apps, or protocols |
| EXC | No standing exclusions | Time-bound access paths, documented permanent exclusions |
| SIG | Layered signals | Device, location, or risk signals shaping access decisions |
| AUT | Authentication Strengths | Phishing-resistant MFA requirements |

File names mirror policy names. The JSON template for `CA-COV001-AllUsers-BlockLegacyAuth` is `CA-COV001-AllUsers-BlockLegacyAuth.json`.

---

## The twenty-four starter policies

All twenty-four policies ship in report-only on first deployment. Operators opt in to enforcement explicitly via the `-Enforce` switch on the deployer.

### Global persona (13)

| Policy | Intent |
|--------|--------|
| CA-COV001-AllUsers-BlockLegacyAuth | Block authentication paths that cannot enforce MFA. |
| CA-COV002-AllUsers-RequireMFA | Require MFA for every interactive sign-in. |
| CA-COV004-Global-NoPersistentBrowserSession | Disable persistent browser sessions; enforce 4-hour browser sign-in frequency. |
| CA-COV005-Global-BlockDeviceCodeFlow | Block OAuth 2.0 device code flow. |
| CA-COV006-Global-BlockAuthenticationTransfer | Block cross-device Authentication Transfer. |
| CA-COV007-Global-BlockUnknownPlatforms | Block sign-ins from device platforms outside the named fleet. |
| CA-COV008-Global-BlockByLocation | Block sign-ins from outside the Trusted Countries named-location set. |
| CA-AUT003-Global-RegisterDevice | Require StandardAuth for the device-registration user action. |
| CA-AUT004-Global-RegisterSecurityInfo | Require StandardAuth for the security-info registration user action. |
| CA-SIG004-Global-MediumUserRisk | Graduated response to medium User Risk: StandardAuth plus password change, SignInFreq every time. |
| CA-SIG005-Global-MediumSignInRisk | Graduated response to medium Sign-In Risk: StandardAuth, SignInFreq every time. |
| CA-SIG009-AllUsers-BlockHighUserRisk | Block all users on high user risk (excludes break-glass accounts). |
| CA-SIG010-AllUsers-BlockHighSignInRisk | Block all users on high sign-in risk (excludes break-glass accounts). |

### Internal persona (2)

| Policy | Intent |
|--------|--------|
| CA-COV009-Internal-RequireCompliantDeviceOnDesktops | Require compliant or hybrid-joined device on Windows, macOS, and Linux. |
| CA-SIG008-Internal-TokenProtection | Cryptographically bind refresh tokens to the issuing Windows device's TPM-protected key. |

### Admins persona (4)

| Policy | Intent |
|--------|--------|
| CA-AUT001-PrivAccounts-RequirePhishResistantMFA | Require phishing-resistant MFA (StrongAuth) for privileged account sign-ins. |
| CA-AUT002-PrivRoles-RequirePhishResistantMFA | Require phishing-resistant MFA at PIM activation for privileged directory roles. |
| CA-AUT005-Admins-RequireAdminAuthOnAdminPortals | Require AdminAuth (FIDO2 only) on Azure Service Management and Microsoft Admin Portals. |
| CA-SIG006-Admins-BlockMediumAndHighSignInRisk | Hard-block admin sign-ins at medium and high sign-in risk (no re-challenge path). |

### Guests persona (2)

| Policy | Intent |
|--------|--------|
| CA-SIG003-Guests-RequireMFA | Require MFA for every interactive guest sign-in. |
| CA-SIG007-Guests-BlockNonGuestAppAccess | Block guest sign-ins to any application outside the Microsoft 365 collaboration set. |

### ServiceAccounts persona (1)

| Policy | Intent |
|--------|--------|
| CA-COV010-ServiceAccounts-BlockUntrustedLocations | Block service-account sign-ins originating outside the Trusted Countries named-location set. |

### Workload identities (1)

| Policy | Intent |
|--------|--------|
| CA-COV003-WorkloadIdentities-TrustedLocations | Restrict service-principal sign-ins to a defined egress (requires Workload Identities Premium). |

### Sensitive applications (1)

| Policy | Intent |
|--------|--------|
| CA-SIG001-SensApps-RequireCompliantDevice | Require compliant or hybrid-joined device for sensitive-app access. |

Per-policy design specs (intent, principle mapping, scope, conditions, controls, license requirements, validation steps) are in [Design/POLICY-DESIGN.md](Design/POLICY-DESIGN.md). Continuous Access Evaluation (CAE) layers on top of every grant policy in this baseline without a redundant configuration step; the post-MFA token-replay threat surface is documented in [Policies/CA-SIG008-Internal-TokenProtection.md](Policies/CA-SIG008-Internal-TokenProtection.md).

---

## What's included in this framework

| Artifact | Path | Purpose |
|----------|------|---------|
| Design specification | `Design/POLICY-DESIGN.md` | Principles, naming, persona model, exclusion strategy, rollout sequence, and per-policy design specs. |
| Policy templates | `Policies/CA-*.json` | One JSON template per policy. All ship in report-only. |
| Exclusion contracts | `Policies/CA-EXC001-EmergencyAccess-Exclusion.md`, `Policies/CA-EXC002-ServiceAccounts-Exclusion.md` | Written contracts for the two permanent exclusion personas, with attestation and review cadence. |
| Supporting artifacts | `Supporting-Artifacts/CA-AUTH-STRENGTH-*.json`, `Supporting-Artifacts/CA-LOCATION-*.json` | Tenant-scoped custom authentication strengths (StandardAuth, StrongAuth, AdminAuth) and named locations (Trusted Countries) referenced by the policy templates. |
| Deployer | `Scripts/Deploy-CABaseline.ps1` | PowerShell 7 + Microsoft Graph SDK 2.x. Placeholder resolution for groups, applications, named locations, and authentication strengths. `-WhatIf` supported. Report-only by default. |
| Telemetry | `Scripts/Get-CABaselineImpact.ps1` | Report-only analyzer that summarizes what each policy would have done if enforced. |
| Business case | `Business-Case/ROI-CONDITIONAL-ACCESS.md` | Plain-language ROI document for executive and board-level audiences. |

---

## Personas covered

- Global and Privileged Administrators (`CA-Persona-GlobalAdmins`)
- Privileged Roles (PIM-activated, dynamic via directory roles)
- Internal Users (`CA-Persona-InternalUsers`)
- Guest Users (`CA-Persona-GuestUsers`)
- Service Accounts (`CA-Persona-ServiceAccounts`)
- Workload Identities (`CA-Persona-WorkloadIdentities`)
- Emergency Access Accounts (`CA-Persona-EmergencyAccess`, monitored by alert rule, never members of any other group)

---

## Prerequisites

- Microsoft Entra ID P1 (minimum). P2 unlocks Identity Protection (required for `CA-SIG004`, `CA-SIG005`, `CA-SIG006`, `CA-SIG009`, `CA-SIG010`) and Privileged Identity Management (required for `CA-AUT002`).
- Microsoft Entra Workload Identities Premium (required for `CA-COV003`).
- Microsoft Intune (required for `CA-SIG001` and `CA-COV009`; hybrid Azure AD join is an accepted alternative for both).
- PowerShell 7 and the Microsoft Graph SDK 2.x for the deployer.
- Persona groups created in Entra ID and populated before deployment.
- Two emergency-access accounts provisioned per `Policies/CA-EXC001-EmergencyAccess-Exclusion.md`.
- ServiceAccounts persona group populated per `Policies/CA-EXC002-ServiceAccounts-Exclusion.md`.
- Three custom authentication strengths (StandardAuth, StrongAuth, AdminAuth) created in the tenant from the templates in `Supporting-Artifacts/`.
- Trusted Countries named location created in the tenant from the template in `Supporting-Artifacts/CA-LOCATION-TrustedCountries.json` and tailored to the organization's approved geographies.

---

## Deployment workflow

1. Review `Design/POLICY-DESIGN.md` end to end.
2. Create the persona groups and populate them.
3. Provision the two emergency-access accounts; populate the `CA-Persona-EmergencyAccess` group; configure the sign-in alert rule.
4. Provision the ServiceAccounts persona group; complete the attestation in `CA-EXC002-ServiceAccounts-Exclusion.md`.
5. Create the three custom authentication strengths and the Trusted Countries named location in the tenant from the templates in `Supporting-Artifacts/`.
6. Open every policy template in `Policies/` and replace the `REPLACE_WITH_*_OBJECT_ID` placeholders with the actual object IDs from your tenant. The deployer resolves group, application, named-location, and authentication-strength placeholders automatically if the corresponding artifacts exist with matching display names.
7. Run the deployer in report-only mode:

    ```powershell
    Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","Policy.Read.All","Group.Read.All","Application.Read.All","Policy.ReadWrite.AuthenticationMethod"
    ./Scripts/Deploy-CABaseline.ps1 -WhatIf
    ./Scripts/Deploy-CABaseline.ps1
    ```

8. Soak each policy in report-only for the minimum duration specified in `Design/POLICY-DESIGN.md` section 5. Use `Scripts/Get-CABaselineImpact.ps1` to summarize what each policy would have done if enforced.
9. Promote policies to enforcement in the documented rollout sequence, one at a time, after the soak window closes and the impact analysis is clean.

---

## Roadmap

### v1.0 — shipped (2026-04-22)

- [x] Six starter policies (CA-COV001, CA-COV002, CA-AUT001, CA-AUT002, CA-SIG001, CA-SIG002)
- [x] Design specification (POLICY-DESIGN.md)
- [x] Deployer (`Deploy-CABaseline.ps1`)
- [x] Business case (ROI-CONDITIONAL-ACCESS.md)
- [x] Repository foundation (LICENSE, CONTRIBUTING, SECURITY, root README)

### v1.1 — shipped (2026-05-01)

- [x] CA-SIG003 Guests-RequireMFA
- [x] CA-COV003 WorkloadIdentities-TrustedLocations
- [x] CA-EXC001 EmergencyAccess written exclusion contract
- [x] `Get-CABaselineImpact.ps1` report-only telemetry
- [x] Repo governance (issue templates, PR template, CODEOWNERS)
- [x] POLICY-DESIGN.md and ROI-CONDITIONAL-ACCESS.md persona and workload rollups

### v1.2 — shipped (2026-05-15)

- [x] 15 new policies (Global, Internal, Admins, Guests, ServiceAccounts)
- [x] CA-EXC002 ServiceAccounts written exclusion contract
- [x] Three custom authentication-strength templates (StandardAuth, StrongAuth, AdminAuth)
- [x] CA-LOCATION-TrustedCountries named-location template
- [x] Supporting-Artifacts folder with bootstrapping README
- [x] Deployer extended with named-location resolver
- [x] POLICY-DESIGN.md v1.2 rollup (23 policies, five active personas, expanded rollout sequence)
- [x] ROI-CONDITIONAL-ACCESS.md v1.2 rollup (23-policy ROI framing, ~40 hours/year operational cost)
- [x] CAE and Token Protection layering note (CA-SIG008 paired design doc)

### v1.3 — Candidates (not committed)

- [ ] Terms-of-Use enforcement for B2B guests (Entra ID Premium ToU feature)
- [ ] CAE and Token Protection layering doc for post-baseline environments (deeper-than-CA-SIG008 treatment, covering EXO + SPO + Teams client matrix and replay-resistance trade-offs)
- [ ] Workload identity IP allow-listing patterns and CI/CD examples (Workload Identities Premium SKU)
- [ ] Cross-framework integration doc (CA "require compliant device" plus Intune Compliance Baseline signal handoff)

---

## References

- Microsoft Learn. [Conditional Access architecture](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies).
- Microsoft Learn. [Authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths).
- Microsoft Learn. [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation).
- Cloud Harbor Consulting. [Why Entra ID Conditional Access Fails in Practice (And How to Fix It)](https://www.cloudharborconsulting.cloud/post/why-entra-id-conditional-access-fails-in-practice-and-how-to-fix-it).

---

## License

MIT. See [LICENSE](../../LICENSE).
