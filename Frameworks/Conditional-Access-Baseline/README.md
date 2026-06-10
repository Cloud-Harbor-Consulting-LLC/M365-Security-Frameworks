# Conditional Access Baseline

A defensible-baseline framework for Microsoft Entra ID Conditional Access. Twenty-eight policies covering eight identity personas, scoped to the access paths attackers exploit most frequently, with every policy shipped in report-only by default so adopters validate impact before enforcement. Companion reading: [Why Entra ID Conditional Access Fails in Practice (And How to Fix It)](https://www.cloudharborconsulting.cloud/post/why-entra-id-conditional-access-fails-in-practice-and-how-to-fix-it).

**Status:** 🟢 Released — v1.4.0

> **Beta endpoint:** This framework targets `https://graph.microsoft.com/beta/identity/conditionalAccess/policies` for all 28 policies. Three policies use Microsoft Graph beta-only features as of May 2026 (`CA-SIG003` and `CA-SIG004` use `signInFrequency.frequencyInterval: "everyTime"`; `CA-COV011` uses the Microsoft Agent ID condition family). See the Prerequisites section and `Design/AGENTS-PERSONA-MODEL.md` for the GA promotion tracking commitment.

---

## Why a baseline first

Conditional Access is Microsoft's Zero Trust policy engine, not a collection of feature toggles. Most tenants accumulate Conditional Access policies the way attics accumulate boxes: one at a time, each with a forgotten owner and a half-remembered justification. The result is a policy set that is broad in count and narrow in coverage, with exclusions that no one reviews and signals that no one tunes.

A baseline reverses that pattern. Until a defensible baseline exists, adding more Conditional Access policies increases complexity without materially reducing risk. This framework establishes the floor.

---

## What a defensible baseline looks like

Four principles anchor every design decision in this framework:

1. **Identity-wide coverage.** No orphaned identities, applications, or legacy protocols authenticate outside the scope of Conditional Access. Every user, every guest, every workload identity, every service account, every agent, and every cloud app is covered by at least one evaluated policy.
2. **No standing exclusions.** Exclusions are a common attack path. Only two exclusion groups are permanent (emergency access accounts governed by CA-EXC001, and service accounts governed by CA-EXC002). All other exclusions are per-policy, justified, and documented in `Design/POLICY-DESIGN.md` Section 6.
3. **Layered signals.** Strong security emerges from combining signals (identity risk, device state, location, application sensitivity, authentication flow). Risk policies combine authentication strength with sign-in frequency and risk remediation. Token Protection layers application and platform scope.
4. **Authentication Strengths.** Not all MFA is equal. SMS and voice-call MFA are phishable via adversary-in-the-middle proxies; FIDO2 and Windows Hello for Business are not. Admin portals require AdminAuth (FIDO2 only). Risk-elevated sessions require StrongAuth (WHfB or FIDO2). All user actions require at minimum StandardAuth.

The four principles are specified, with rationale and per-policy implementation notes, in [Design/POLICY-DESIGN.md](Design/POLICY-DESIGN.md).

---

## Naming convention

Every policy in this baseline follows the format:

`CA-[PrinciplePrefix][Number]-[Persona]-[Action]`

| Prefix | Principle | Use when the policy primarily enforces... |
|---|---|---|
| AUT | Authentication Strengths | Phishing-resistant MFA requirements |
| COV | Identity-wide coverage | Blanket coverage of users, apps, or protocols |
| EXC | No standing exclusions | Written exclusion contracts and persona governance |
| SIG | Layered signals | Device, location, or risk signals shaping access decisions |

File names mirror policy names. The JSON template for `CA-COV001-AllUsers-BlockLegacyAuth` is `CA-COV001-AllUsers-BlockLegacyAuth.json`.

---

## The 28 starter policies

All 28 policies ship in report-only on first deployment. Operators opt in to enforcement explicitly via the `-Enforce` switch on the deployer.

### Global scope (9)

| Policy | Intent |
|---|---|
| CA-COV001-AllUsers-BlockLegacyAuth | Block authentication paths that cannot enforce MFA. |
| CA-COV002-AllUsers-RequireMFA | Require MFA for every interactive sign-in. |
| CA-COV003-Global-NoPersistentBrowserSessionOnNonCorpDevices | Disable persistent browser sessions on non-corp devices; enforce 4-hour sign-in frequency. |
| CA-COV004-Global-BlockDeviceCodeFlow | Block OAuth 2.0 device code flow. |
| CA-COV005-Global-BlockAuthenticationTransfer | Block cross-device Authentication Transfer. |
| CA-COV006-Global-BlockUnknownPlatforms | Block sign-ins from device platforms outside the named fleet. |
| CA-COV007-Global-BlockByLocation | Block sign-ins from outside the Trusted Countries named-location set. |
| CA-SIG008-AllUsers-BlockHighUserRisk | Block all users on high user risk. |
| CA-SIG009-AllUsers-BlockHighSignInRisk | Block all users on high sign-in risk. |

### User-action (registration) scope (2)

| Policy | Intent |
|---|---|
| CA-AUT001-Global-RegisterDevice | Require StandardAuth for the device-registration user action. |
| CA-AUT002-Global-RegisterSecurityInfo | Require StandardAuth for the security-info registration user action. |

### Internal persona (2)

| Policy | Intent |
|---|---|
| CA-COV008-Internal-RequireCompliantDeviceOnDesktops | Require compliant or hybrid-joined device on Windows, macOS, and Linux. |
| CA-SIG007-Internal-TokenProtection | Cryptographically bind refresh tokens to the issuing Windows device's TPM-protected key. |

### Admins persona (2)

| Policy | Intent |
|---|---|
| CA-AUT003-Admins-RequireAdminAuthOnAdminPortals | Require AdminAuth (FIDO2 only) on Azure Service Management and Microsoft Admin Portals. |
| CA-SIG005-Admins-BlockMediumAndHighSignInRisk | Hard-block admin sign-ins at medium and high sign-in risk. |

### Guests persona (4)

| Policy | Intent |
|---|---|
| CA-SIG002-Guests-RequireMFA | Require MFA for every interactive guest sign-in. |
| CA-SIG003-Global-MediumUserRisk | Graduated response to medium user risk: StrongAuth + risk remediation + SignInFreq every time. |
| CA-SIG010-Guests-RequireToU | Require B2B guests to accept a tenant-defined Terms of Use before access is granted. |
| CA-SIG006-Guests-BlockNonGuestAppAccess | Block guest sign-ins to any application outside the Microsoft 365 collaboration set. |

> Note: CA-SIG003 is scoped globally and appears in the Guests section because the `everyTime` frequency interval is a beta-only condition primarily relevant to the guest and risk-elevated sign-in population. See POLICY-DESIGN.md section 6.17 for the full scope specification.

### Risk scope (1)

| Policy | Intent |
|---|---|
| CA-SIG004-Global-MediumSignInRisk | Graduated response to medium sign-in risk: StrongAuth + SignInFreq every time. |

### ServiceAccounts persona (1)

| Policy | Intent |
|---|---|
| CA-COV009-ServiceAccounts-BlockUntrustedLocations | Block service-account sign-ins originating outside the Trusted Countries named-location set. |

### WorkloadIdentities persona (1)

| Policy | Intent |
|---|---|
| CA-COV010-WorkloadIdentities-TrustedLocations | Restrict service-principal sign-ins to a defined egress (requires Workload Identities Premium). |

### Agents persona (2)

| Policy | Intent |
|---|---|
| CA-COV011-Agents-BlockMediumAndHighRisk | Block Agent ID authentication when Microsoft Identity Protection detects medium or high agent risk. |
| CA-COV012-Agents-AllowOnlyApprovedAgents | Block every agent identity except an approved set (include all agents, exclude the approved set, block). |

### AgentUsers persona (3)

The AgentUsers persona covers the agent user account identity sub-class (Pattern 3: agent acting as a user / digital worker), distinct from the agent identity covered by the Agents persona. All 3 ship report-only. See `Policies/CA-EXC003-Agents-Persona.md`.

| Policy | Intent |
|---|---|
| CA-COV013-AgentUsers-BlockMediumAndHighRisk | Block agent user account sign-ins when Microsoft Identity Protection detects medium or high agent risk. |
| CA-COV014-AgentUsers-RequireCompliantDevice | Require a compliant device for agent user account sign-ins (Intune-managed Windows 365 Cloud PCs for Agents). |
| CA-COV015-AgentUsers-BlockNonCompliantNetwork | Block agent user account sign-ins from outside the compliant network (all locations except the Microsoft Entra Global Secure Access compliant-network named location). |

### Sensitive-applications scope (1)

| Policy | Intent |
|---|---|
| CA-SIG001-SensitiveApps-RequireCompliantDevice | Require compliant or hybrid-joined device for Azure Service Management access by Internal users. |

Per-policy design specs (intent, principle mapping, scope, conditions, controls, license requirements, validation steps, exclusion rationale) are in [Design/POLICY-DESIGN.md](Design/POLICY-DESIGN.md).

---

## What's included in this framework

| Artifact | Path | Purpose |
|---|---|---|
| Design specification | `Design/POLICY-DESIGN.md` | Principles, naming, persona model, exclusion strategy, rollout sequence, per-policy design specs. |
| Agents persona model | `Design/AGENTS-PERSONA-MODEL.md` | Microsoft Agent ID technical overview, risk signal model, policy mechanics, beta endpoint commitment. |
| Policy templates | `Policies/CA-*.json` | One JSON template per policy. All ship in report-only. |
| Exclusion contracts | `Policies/CA-EXC001-EmergencyAccess-Exclusion.md` | Emergency access exclusion governance: key custody, alert rule, recovery drill cadence. |
| | `Policies/CA-EXC002-ServiceAccounts-Exclusion.md` | ServiceAccounts exclusion governance: persona membership, attestation, sign-in review. |
| | `Policies/CA-EXC003-Agents-Persona.md` | Agents persona contract: Agent ID inventory, monthly risk review, incident runbook. |
| Supporting artifacts | `Supporting-Artifacts/CA-AUTH-STRENGTH-*.json` | Tenant-scoped custom authentication strengths (StandardAuth, StrongAuth, AdminAuth). |
| | `Supporting-Artifacts/CA-LOCATION-TrustedCountries.json` | Trusted Countries named location template. |
| Deployer | `Scripts/Deploy-CABaseline.ps1` | PowerShell 7 + `Microsoft.Graph.Authentication` module only. Placeholder resolution at runtime. `-WhatIf` and `-Enforce` supported. Targets beta endpoint. Report-only by default. |
| Telemetry | `Scripts/Get-CABaselineImpact.ps1` | Report-only analyzer: summarizes what each policy would have done if enforced. Targets beta sign-in log endpoint. |
| Business case | `Business-Case/ROI-CONDITIONAL-ACCESS.md` | Plain-language ROI document for executive and board-level audiences. |

---

## Personas covered

- **Global** — all users in the tenant (every interactive sign-in)
- **Internal** — member users (`CA-Persona-InternalUsers`)
- **Admins** — 14 highly-privileged Entra ID directory roles by template ID
- **Guests** — B2B collaboration guests and external users
- **ServiceAccounts** — non-interactive user-type identities (`CA-Persona-ServiceAccounts`, governed by CA-EXC002)
- **WorkloadIdentities** — service principals (governed by CA-COV010 on the service-principal authentication path)
- **Agents** — Microsoft Agent IDs (governed by CA-EXC003, CA-COV011, and CA-COV012)
- **AgentUsers** — agent user accounts, the agent-acting-as-a-user sub-class (governed by CA-EXC003 and CA-COV013 through CA-COV015)
- **EmergencyAccess** — break-glass accounts (`CA-Persona-EmergencyAccess`, governed by CA-EXC001, monitored by alert rule, never members of any other group)

---

## Prerequisites

- **Entra ID P1** (minimum). Required by all policies.
- **Entra ID P2** (Identity Protection). Required by CA-SIG003, CA-SIG004, CA-SIG005, CA-SIG008, CA-SIG009.
- **Entra ID P2** (Terms of Use feature). Required by CA-SIG010. Covers guest users at the 1:5 ratio (one P2 license covers five guest users). See <https://learn.microsoft.com/en-us/entra/identity/conditional-access/terms-of-use>.
- **Microsoft Entra Workload Identities Premium**. Required by CA-COV010. Separate SKU from Entra ID P1/P2.
- **Microsoft Intune**. Required for `compliantDevice` grant control (CA-COV008, CA-SIG001). Hybrid Azure AD join is an accepted alternative.
- **Microsoft Entra ID P1 or P2 plus a Microsoft Agent 365 license per user**. Required by CA-COV011 for Conditional Access for agents. Risk-based enforcement through Identity Protection requires P2. Microsoft describes enforcement of the Agent 365 licensing requirement as coming soon.
- **Microsoft Entra Internet Access**. Required for agent network controls. The compliant-network grant relies on the Global Secure Access client on the endpoint.
- **Conditional Access Administrator role**. Required to create and manage agent policies. The custom-security-attribute targeting method also requires the Attribute Assignment Reader role.
- **Microsoft Graph beta endpoint**. Required by all 28 policies. The deployer targets `https://graph.microsoft.com/beta/identity/conditionalAccess/policies`. Three policies use beta-only features (`CA-SIG003`, `CA-SIG004` use `frequencyInterval: "everyTime"`; `CA-COV011` uses the Agent ID condition family).
- **PowerShell 7.0 or later** and the **`Microsoft.Graph.Authentication` module** for the deployer.
- **Persona groups** created in Entra ID and populated before deployment.
- **Two emergency-access accounts** provisioned per `Policies/CA-EXC001-EmergencyAccess-Exclusion.md`.
- **ServiceAccounts persona group** populated per `Policies/CA-EXC002-ServiceAccounts-Exclusion.md`.
- **Three custom authentication strengths** (StandardAuth, StrongAuth, AdminAuth) created in the tenant from the templates in `Supporting-Artifacts/`.
- **Trusted Countries named location** created in the tenant from `Supporting-Artifacts/CA-LOCATION-TrustedCountries.json` and tailored to the organization's approved geographies.

---

## Deployment workflow

1. Review `Design/POLICY-DESIGN.md` end to end.
2. Create the persona groups and populate them per the persona model in POLICY-DESIGN.md Section 3.
3. Provision emergency-access accounts; populate `CA-Persona-EmergencyAccess`; configure the sign-in alert rule per `Policies/CA-EXC001-EmergencyAccess-Exclusion.md`.
4. Populate the ServiceAccounts persona group; complete the attestation in `Policies/CA-EXC002-ServiceAccounts-Exclusion.md`.
5. Review `Policies/CA-EXC003-Agents-Persona.md` and run an Agent ID inventory before adopting the Agents persona.
6. Create the three custom authentication strengths and the Trusted Countries named location in the tenant from the templates in `Supporting-Artifacts/`.
7. Run the deployer in report-only mode:

   ```powershell
   Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","Policy.Read.All","Group.Read.All","Application.Read.All","Policy.ReadWrite.AuthenticationMethod"
   .\Scripts\Deploy-CABaseline.ps1 -WhatIf
   .\Scripts\Deploy-CABaseline.ps1
   ```

8. Soak each policy in report-only for the minimum duration in `Design/POLICY-DESIGN.md` Section 5. Use `Scripts/Get-CABaselineImpact.ps1` to summarize what each policy would have done if enforced.
9. Promote policies to enforcement in the documented rollout sequence, one at a time, after the soak window closes and the impact analysis is clean.

---

## Roadmap

### v1.0 — Released (2026-04-22)

- [x] Six starter policies (CA-COV001, CA-COV002, CA-AUT001/002, CA-SIG001, CA-SIG002)
- [x] Design specification (POLICY-DESIGN.md)
- [x] Deployer (`Deploy-CABaseline.ps1`)
- [x] Business case (ROI-CONDITIONAL-ACCESS.md)
- [x] Repository foundation (LICENSE, CONTRIBUTING, SECURITY, root README)

### v1.1 — Released (2026-05-01)

- [x] CA-SIG003 Guests-RequireMFA
- [x] CA-COV003 WorkloadIdentities-TrustedLocations
- [x] CA-EXC001 EmergencyAccess written exclusion contract
- [x] `Get-CABaselineImpact.ps1` report-only telemetry
- [x] Repo governance (issue templates, PR template, CODEOWNERS)

### v1.2 — Released (2026-05-15)

- [x] 15 new policies (Global, Internal, Admins, Guests, ServiceAccounts)
- [x] CA-EXC002 ServiceAccounts written exclusion contract
- [x] Three custom authentication-strength templates (StandardAuth, StrongAuth, AdminAuth)
- [x] CA-LOCATION-TrustedCountries named-location template
- [x] Supporting-Artifacts folder with bootstrapping README
- [x] POLICY-DESIGN.md v1.2 rollup
- [x] ROI-CONDITIONAL-ACCESS.md v1.2 rollup
- [x] CAE and Token Protection layering note (CA-SIG007 paired design doc)

### v1.3 — Shipped (2026-05-28)

- [x] 24-policy baseline sourced from prod tenant restructure
- [x] All-beta endpoint architecture (`Microsoft.Graph.Authentication` only, `Invoke-MgGraphRequest` deployer)
- [x] Agents persona as first-class identity class (CA-EXC003, CA-COV011, AGENTS-PERSONA-MODEL.md)
- [x] CA-COV010 WorkloadIdentities-TrustedLocations retained and renumbered from CA-COV003
- [x] Wholesale rewrite of POLICY-DESIGN.md (v1.3 stack)
- [x] Wholesale rewrite of Deploy-CABaseline.ps1 (single module dependency)
- [x] Per-policy exclusion judgment with documented rationale
- [x] CA-SIG010 Guests-RequireToU — Terms of Use gate for all 6 B2B guest user types; paired contract doc; deployer `Resolve-TermsOfUseId` helper
- [x] CAE and Token Protection layering deep-dive design doc (Design/CAE-TOKEN-PROTECTION-LAYERING.md) — threat model, signal models, client matrix, replay-resistance trade-offs, layering order, 14-day soak procedure
- [x] Workload identity IP allow-listing patterns and CI/CD examples (Design/WORKLOAD-IDENTITY-IP-PATTERNS.md) — SPN per-pipeline scoping, Trusted IPs refresh cadence per runner class, rollback procedure, GitHub Actions and Azure DevOps examples
- [x] CA-ICB cross-framework integration doc (Design/CA-ICB-INTEGRATION.md) — signal flow narrative with Mermaid diagram, per-policy ICB requirements for CA-COV008, CA-SIG001, and CA-SIG007, failure-mode matrix, CA-to-ICB rollout sequence, 5-test verification procedure, and out-of-scope disclosure
- [x] ROI-CONDITIONAL-ACCESS.md v1.3 wholesale rewrite; CHANGELOG v1.3.0 promotion; root README and framework README sync (this PR)

### v1.4 — Released (2026-06-10)

- [x] CA-COV012 Agents-AllowOnlyApprovedAgents — allow-only-approved-agents governance via the `agentIdServicePrincipalFilter` custom security attribute exclude
- [x] AgentUsers persona for the agent user account sub-class — CA-COV013 (block medium and high agent risk), CA-COV014 (require compliant device on Windows 365 Cloud PCs for Agents), CA-COV015 (block non-compliant network)
- [x] Three Microsoft agent access patterns documented (on-behalf-of, application-only, agent acting as a user)
- [x] Agent field shapes grounded in verified Microsoft Graph beta JSON; CA-COV015 deployer compliant-network location resolver
- [x] POLICY-DESIGN.md sections 6.14a and 6a per-policy specs; CA-EXC003 limitations and report-only rollout sections
- [x] ROI-CONDITIONAL-ACCESS.md v1.4 rollup; CHANGELOG v1.4.0 promotion; root README and framework README sync (this PR)

### v1.5 — Candidates (not committed)

- [ ] Microsoft Agent ID v1.0 schema migration once Microsoft completes GA promotion of the Agent ID condition family
- [ ] `signInFrequency: everyTime` v1.0 migration once Microsoft promotes `frequencyInterval: "everyTime"` to the v1.0 endpoint
- [ ] Mobile platform Token Protection coverage once Microsoft ships support for iOS and Android token binding
- [ ] Named-location refresh utility script in Scripts/ if adopter demand warrants

---

## References

- Microsoft Learn. [Conditional Access architecture](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies).
- Microsoft Learn. [Authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths).
- Microsoft Learn. [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation).
- Microsoft Learn. [Conditional Access API reference (beta)](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-beta).
- Cloud Harbor Consulting. [Why Entra ID Conditional Access Fails in Practice (And How to Fix It)](https://www.cloudharborconsulting.cloud/post/why-entra-id-conditional-access-fails-in-practice-and-how-to-fix-it).

---

## License

MIT. See [LICENSE](../../LICENSE).
