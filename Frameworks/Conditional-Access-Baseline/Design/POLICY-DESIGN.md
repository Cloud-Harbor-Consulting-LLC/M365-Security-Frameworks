# Conditional Access Baseline — Policy Design

This document specifies the design philosophy, naming convention, persona model, and exclusion strategy for the Conditional Access Baseline framework. It is the prerequisite reading for anyone deploying, extending, or auditing the baseline.

The per-policy design specifications (one subsection for each starter policy) are appended in the following section of this document.

---

## 1. Design philosophy

Conditional Access is Microsoft's Zero Trust policy engine, not a collection of feature toggles. This baseline is built around the thesis that **until a defensible baseline exists, adding more Conditional Access policies increases complexity without materially reducing risk.**

Four principles anchor every design decision in this framework:

### 1.1 Identity-wide coverage

**What it means:** No orphaned identities, applications, or legacy protocols should be able to authenticate outside the scope of Conditional Access. Every user, every guest, every workload identity, and every cloud app must be covered by at least one evaluated policy.

**How this baseline implements it:** Policies `CA-COV001` (Block legacy authentication) and `CA-COV002` (Require MFA for all users) are scoped to "All users" and "All cloud apps" — with controlled exclusions for emergency access accounts and workload identities that have their own hardened paths. `CA-COV003` (Workload Identities — Trusted Locations) closes the workload-identity coverage gap by restricting service-principal sign-ins to a defined egress.

### 1.2 No standing exclusions

**What it means:** Exclusions are a common attack path. An exclusion group that persists indefinitely becomes a backdoor — one compromised member, and the entire baseline can be bypassed. Exclusions must be time-bound, auditable, and reviewed.

**How this baseline implements it:** Only two exclusion groups are considered permanent: emergency access accounts (two total, monitored by alert) and workload identities governed by a separate workload-identity policy set. All other exclusions are temporary, tracked by owner and expiration date, and reviewed quarterly. The operational specification for the emergency access exclusion is `CA-EXC001-EmergencyAccess-Exclusion.md`.

### 1.3 Layered signals

**What it means:** Strong security emerges from combining signals — identity risk, device state, location, application sensitivity — not from any single control. A policy that evaluates only one signal is a single point of failure.

**How this baseline implements it:** Policies in the `CA-SIG` series evaluate multiple signals in combination. `CA-SIG001` layers application sensitivity with device compliance; `CA-SIG004` layers medium user-risk with authentication strength and password change; `CA-SIG003` layers user-type (guest) with the MFA control. This is the difference between "require MFA" and "require MFA *because we detected risk*."

### 1.4 Authentication Strengths

**What it means:** Not all MFA is equal. SMS and voice-call MFA are phishable via AiTM (adversary-in-the-middle) proxies; FIDO2, Windows Hello for Business, and certificate-based authentication are not. Privileged identities and high-value workloads must be protected by phishing-resistant methods.

**How this baseline implements it:** Policies in the `CA-AUT` series use Entra ID Authentication Strengths to require phishing-resistant MFA for privileged accounts (`CA-AUT001`) and privileged role activations (`CA-AUT002`). No privileged action clears the baseline without a phishing-resistant credential.

### 1.5 v1.2 design refinements

The v1.2 slate refines each of the four anchoring principles without replacing any of them. The refinements are grouped here so they are visible at one glance; the per-policy specs in Section 6 carry the implementation detail.

#### Refinements of 1.1 Identity-wide coverage

- **Auth-flow surface-area block trio.** `CA-COV005` (BlockDeviceCodeFlow), `CA-COV006` (BlockAuthenticationTransfer), and `CA-COV007` (BlockUnknownPlatforms) close auth-flow side channels commonly abused for token theft and phishing-resistance bypass. Adopters ship the trio together; partial deployment leaves a known gap.
- **userAction carve-out.** `CA-AUT003` (RegisterDevice) and `CA-AUT004` (RegisterSecurityInfo) target the `userAction` condition rather than sign-in. They live on the Global scope but operate on the registration ceremony itself, not the sign-in path.
- **Internal desktop coverage closure.** `CA-COV009` requires compliant or hybrid-joined device for Windows / macOS / Linux Internal sign-ins. Mobile platforms are handled separately and remain out of scope for this policy.
- **Global location closure.** `CA-COV008` blocks Global sign-ins from any location outside `CA-LOCATION-TrustedCountries`.

#### Refinements of 1.2 No standing exclusions

- **ServiceAccounts as a first-class persona, not a standing exclusion.** Non-interactive identities get their own persona, their own exclusion contract (`CA-EXC002`), and their own compensating control (`CA-COV010`). Treating service accounts as a residual exclusion was operationally brittle; making them a first-class persona makes the design explicit and auditable.

#### Refinements of 1.3 Layered signals

- **Graduated medium-risk response.** Medium user-risk (`CA-SIG004`) layers StandardAuth + password change + `signInFrequency=everyTime`. Medium sign-in risk (`CA-SIG005`) layers StandardAuth + `signInFrequency=everyTime`. High-risk hard-blocks via `CA-SIG009` (user risk) and `CA-SIG010` (sign-in risk). Rationale: hard-blocking medium risk produces too many false-positive lockouts; the graduated control catches the threat without breaking legitimate sign-ins.
- **Token Protection on Windows desktop.** `CA-SIG008` enables `secureSignInSession=true` for Internal Windows sign-ins to the Office 365 application bundle. The control operates at token-redemption time, layering with Continuous Access Evaluation (CAE) without redundancy.
- **Trusted-countries location pattern.** `CA-LOCATION-TrustedCountries` is one named location with two policy roles: exclusion target for `CA-COV008` (everyone else allowed only from those countries) and inclusion target for `CA-COV010` (service accounts only allowed from those countries).
- **Hard-block on admin-context medium risk.** `CA-SIG006` hard-blocks medium and high sign-in risk for the Admins scope. Admin credentials in a risk-flagged session do not get the MFA step-up path that `CA-SIG002` extends to general users.
- **Guest application scope.** `CA-SIG007` blocks guest sign-ins to any application outside the Microsoft 365 collaboration set. Closes the gap where a B2B guest token issued for a collaboration app could be re-used against unrelated registered applications.

#### Refinements of 1.4 Authentication Strengths

- **Auth-strength tiering.** Three reusable named authentication strengths replace per-policy bespoke strength configuration: `CA-AUTH-STRENGTH-StandardAuth` (WHfB + FIDO2 + password + Authenticator push), `CA-AUTH-STRENGTH-StrongAuth` (WHfB + FIDO2), `CA-AUTH-STRENGTH-AdminAuth` (FIDO2 only). Centralizing strengths keeps the templates uniform and gives adopters one place to revise the floor.
- **Admin layering on admin app surfaces.** `CA-AUT005` applies the AdminAuth strength specifically to Microsoft Azure Management + Microsoft Admin Portals, on top of (not replacing) `CA-AUT001` and `CA-AUT002`. The highest-privilege admin actions warrant phishing-resistant-only auth, but applying that floor to every admin app surface would block legitimate non-portal admin tooling.

### 1.6 Global scope and Admins scope

Two scope segments appear in v1.2 policy names that are not separate personas in the table below: **Global** means "all users in the tenant" (the broadest baseline scope, the v1.2 successor to the `AllUsers` segment used by v1.1 policies) and **Admins** means "the 14 highly-privileged Entra ID directory roles by template ID" (the scope used by `CA-AUT005` and `CA-SIG006`). Both scope segments inherit the standard EmergencyAccess + WorkloadIdentities + ServiceAccounts exclusion contract.

---

## 2. Naming convention

Every policy in this baseline follows the format:

```
CA-[PrinciplePrefix][Number]-[Persona]-[Action]
```

### 2.1 Principle prefixes

| Prefix | Principle | Use when the policy primarily enforces... |
|--------|-----------|-------------------------------------------|
| `COV` | Identity-wide coverage | Blanket coverage of users, apps, or protocols |
| `EXC` | No standing exclusions | Time-bound access paths, JIT elevation, guest lifecycle, documented permanent exclusions |
| `SIG` | Layered signals | Device, location, or risk signals shaping access decisions |
| `AUT` | Authentication Strengths | Phishing-resistant MFA requirements |

### 2.2 Rules

- **One prefix per policy.** When a policy could fit two prefixes, use the one that reflects its primary intent. Document the secondary intent in the policy's design spec.
- **Numbers are sequential within a prefix.** `CA-SIG001` comes before `CA-SIG002`; retired policies keep their number permanently.
- **Persona and action are hyphen-separated.** Use CamelCase within each segment (`PrivAccounts`, `BlockLegacyAuth`) — no spaces, no underscores.
- **File names mirror policy names.** JSON template for `CA-COV001-AllUsers-BlockLegacyAuth` is `CA-COV001-AllUsers-BlockLegacyAuth.json`.

---

## 3. Persona model

This baseline is deployed around the people it protects. Each persona maps to one or more Entra ID groups that serve as scope targets for policies.

| Persona | Included By | Typical Size | Notes |
|---------|------------|--------------|-------|
| Privileged Roles (Directory Roles) | 14 template IDs | Inventory-dependent | Scoped via directory roles, not a static group. Includes roles: Global Admin, Privileged Role Admin, Security Admin, Exchange Admin, SharePoint Admin, Teams Admin, Dynamics Admin, Power Platform Admin, Auth Admin, Compliance Admin, Helpdesk Admin, Attributes Admin, Cloud App Admin, Reports Reader |
| Internal Users | `CA-Persona-InternalUsers` | All employees | Dynamic group based on `userType eq 'Member'` recommended |
| Guest Users | `CA-Persona-GuestUsers` | Varies | Dynamic group based on `userType eq 'Guest'` recommended |
| Workload Identities | Scoped via Workload Identities blade | Inventory-dependent | Not scoped via a user group |
| Emergency Access Accounts | `CA-Persona-EmergencyAccess` | Exactly 2 | Monitored by alert rule; never members of any other group |
| Service Accounts | `EntraID-ConditionalAccess-ServiceAccounts` | Inventory-dependent | Non-interactive identities. Persona is the *inclusion* target for CA-COV010 and the *exclusion* target across every human-targeted policy via CA-EXC002. Not the same as Workload Identities (which sit on the CA-COV003 service-principal code path). |

### 3.1 Persona naming

The `CA-Persona-` prefix on groups is intentional: it makes persona groups sortable, searchable, and unambiguous in the Entra admin center. Avoid reusing existing business groups (e.g., "All Employees") as persona scopes — policy scope and HR scope should not be conflated.

---

## 4. Exclusion group strategy

Exclusions are the single most dangerous element of any Conditional Access baseline. This framework treats them with corresponding rigor.

### 4.1 Permanent exclusions (3 total)

1. **Emergency access accounts** (`CA-Persona-EmergencyAccess`) — excluded from every policy. Two accounts, cloud-only, stored offline in a sealed envelope, monitored by a sign-in alert rule that pages the security team on any use. Operational specification (key custody, alert rule, recovery test cadence): `CA-EXC001-EmergencyAccess-Exclusion.md`.
2. **Workload identities** — excluded from user-scoped policies and governed by a separate workload-identity policy set (see `CA-COV003`).
3. **Service accounts** (`EntraID-ConditionalAccess-ServiceAccounts`) — excluded from every human-targeted policy via the written contract `CA-EXC002-ServiceAccounts-Exclusion.md`. Compensating control is `CA-COV010-ServiceAccounts-BlockUntrustedLocations`. Persona membership, monthly attestation, quarterly sign-in review, and credential rotation procedure are documented in the contract.

### 4.2 Temporary exclusions

All other exclusions are temporary and tracked in a single location (`exclusions.md` in this framework, forthcoming) with:

- **Exclusion owner** — the person who requested it
- **Justification** — the business reason
- **Expiration date** — no longer than 90 days without renewal
- **Reviewer** — who reviews at expiration

Quarterly, the baseline's maintainer audits all temporary exclusions and either renews (with re-justification) or removes them.

### 4.3 Anti-patterns to avoid

- ❌ "Helpdesk exclusion" groups that accumulate members over time
- ❌ Service account exclusions that aren't tied to a hardened workload identity policy
- ❌ Long-lived "pilot" exclusions that outlast the pilot
- ❌ Executive exclusions (executives are the highest-value targets — strengthen, don't exclude)

---

## 5. Rollout sequence

Policies should be staged, enforced, and promoted in the following order. Each step has a minimum soak period in report-only mode.

| Order | Policy | Minimum report-only soak | Why this order |
|-------|--------|-------------------------|----------------|
| 1 | `CA-COV001-AllUsers-BlockLegacyAuth` | 14 days | Highest impact, lowest user-facing friction — establishes the floor |
| 2 | `CA-COV002-AllUsers-RequireMFA` | 14 days | Builds on CA-COV001; flushes out accounts missing MFA registration |
| 3 | `CA-AUT001-PrivAccounts-RequirePhishResistantMFA` | 7 days | Small, high-trust scope — easy to validate |
| 4 | `CA-AUT002-PrivRoles-RequirePhishResistantMFA` | 7 days | PIM-path parallel to CA-AUT001 |
| 5 | `CA-SIG001-SensApps-RequireCompliantDevice` | 14 days | Requires device compliance maturity — soak longer |
| 6 | `CA-COV003-WorkloadIdentities-TrustedLocations` | 14 days | Workload-identity coverage; soak to inventory legitimate egress IPs before enforcement |
| 7 | `CA-SIG003-Guests-RequireMFA` | 7 days | Guest scope is bounded; soak captures cross-tenant B2B sign-in patterns |
| 8 | `CA-COV004-Global-NoPersistentBrowserSession` | 14 days | Session-hardening floor; high reach across the Global scope |
| 9 | `CA-COV005-Global-BlockDeviceCodeFlow` | 14 days | Auth-flow surface-area trio; soak captures legitimate device-pairing exceptions |
| 10 | `CA-COV006-Global-BlockAuthenticationTransfer` | 14 days | Auth-flow surface-area trio; ships paired with CA-COV005 and CA-COV007 |
| 11 | `CA-COV007-Global-BlockUnknownPlatforms` | 14 days | Auth-flow surface-area trio; soak captures sign-ins from spoofed, headless, or obsolete platforms |
| 12 | `CA-AUT003-Global-RegisterDevice` | 14 days | userAction registration flow; soak validates StandardAuth coverage at registration time |
| 13 | `CA-AUT004-Global-RegisterSecurityInfo` | 14 days | userAction registration flow; ships paired with CA-AUT003 |
| 14 | `CA-COV008-Global-BlockByLocation` | 14 days | Depends on `CA-LOCATION-TrustedCountries`; soak inventories legitimate sign-in geographies |
| 15 | `CA-COV009-Internal-RequireCompliantDeviceOnDesktops` | 14 days | Internal desktop coverage closure; depends on Intune compliance maturity |
| 16 | `CA-SIG004-Global-MediumUserRisk` | 14 days | Graduated medium user-risk response; soak captures false-positive volume |
| 17 | `CA-SIG005-Global-MediumSignInRisk` | 14 days | Graduated medium sign-in-risk response; ships paired with CA-SIG004 |
| 18 | `CA-SIG009-AllUsers-BlockHighUserRisk` | 14 days | Requires Entra ID P2 + Identity Protection tuning; hard-block on high user risk |
| 19 | `CA-SIG010-AllUsers-BlockHighSignInRisk` | 14 days | Requires Entra ID P2 + Identity Protection tuning; hard-block on high sign-in risk |
| 20 | `CA-AUT005-Admins-RequireAdminAuthOnAdminPortals` | 7 days | Admin app-scoped FIDO2-only; layers on top of CA-AUT001/002 |
| 21 | `CA-SIG006-Admins-BlockMediumAndHighSignInRisk` | 7 days | Admin-context hard block on risk; admins do not get MFA step-up fallback |
| 22 | `CA-SIG007-Guests-BlockNonGuestAppAccess` | 7 days | Guest application-scope restriction to the Microsoft 365 collaboration set |
| 23 | `CA-COV010-ServiceAccounts-BlockUntrustedLocations` | 14 days | ServiceAccounts compensating control; soak inventories legitimate service-account sign-in geographies |
| 24 | `CA-SIG008-Internal-TokenProtection` | 14 days | Token-redemption-time control; soak inventories non-supporting clients and validates CAE layering |

`CA-EXC001-EmergencyAccess-Exclusion` is a documented permanent exclusion, not a deployable policy, and is not part of the rollout sequence.

**Do not skip report-only.** Every policy must be validated in report-only mode before enforcement, no matter how confident the reviewer is in its scope.

---

## 6. Per-policy design specifications

Each of the twenty-three (23) starter policies is specified below. Every spec follows the same structure: intent, principle mapping, scope, conditions, controls, license requirements, validation steps, and the JSON template path. The standing exclusion specification for emergency access accounts (`CA-EXC001`) is documented separately in `CA-EXC001-EmergencyAccess-Exclusion.md`.

---

### 6.1 `CA-COV001-AllUsers-BlockLegacyAuth`

**Intent:** Block authentication requests using legacy (non-modern) protocols. Legacy authentication — basic auth, POP, IMAP, SMTP AUTH, older Exchange clients — does not support MFA and is the single largest vector for password-spray attacks against Entra ID.

**Principle mapping:** Primary — COV (Identity-wide coverage). This policy establishes the coverage floor by eliminating the authentication paths that would bypass every other policy.

#### Scope

- Included users: All users
- Excluded users: `CA-Persona-EmergencyAccess`
- Included cloud apps: All cloud apps
- Excluded cloud apps: None

#### Conditions

- Client apps: Exchange ActiveSync clients, Other clients
- Device platforms: Any
- Locations: Any
- Sign-in risk: Not evaluated
- User risk: Not evaluated

#### Controls

- Grant: Block access
- Session: None

**License requirements:** Entra ID P1 (minimum)

#### Validation in report-only

- Review sign-in logs filtered by Client app = Exchange ActiveSync and Client app = Other clients to confirm whether these paths are active in your tenant
- Identify any service accounts or legacy applications still using basic auth; migrate to modern auth or scope them under a workload-identity policy BEFORE promoting to enforced
- Confirm zero unexplained sign-in failures during the soak period

**JSON template:** `../Policies/CA-COV001-AllUsers-BlockLegacyAuth.json` (planned)

---

### 6.2 `CA-COV002-AllUsers-RequireMFA`

**Intent:** Require multi-factor authentication for every interactive user sign-in to every cloud app. Establishes MFA as the floor beneath every other policy in the baseline.

**Principle mapping:** Primary — COV (Identity-wide coverage). Layered beneath CA-COV001 to ensure any authentication that clears the legacy-auth block is still MFA-protected.

#### Scope

- Included users: All users
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`
- Included cloud apps: All cloud apps
- Excluded cloud apps: None

#### Conditions

- Client apps: Browser, Mobile apps and desktop clients
- Device platforms: Any
- Locations: Any
- Sign-in risk: Not evaluated
- User risk: Not evaluated

#### Controls

- Grant: Require multifactor authentication
- Session: None

**License requirements:** Entra ID P1 (minimum)

#### Validation in report-only

- Run the "Users registered for MFA" report; ensure every user has at least one MFA method registered before enforcement
- Soak for 14 days to capture low-frequency sign-ins (monthly reports, quarterly tools, dormant accounts)
- Confirm the `CA-Persona-EmergencyAccess` exclusion is intact — if the policy accidentally applies to break-glass accounts, the tenant can be locked out

**JSON template:** `../Policies/CA-COV002-AllUsers-RequireMFA.json` (planned)

---

### 6.3 `CA-AUT001-PrivAccounts-RequirePhishResistantMFA`

**Intent:** Require phishing-resistant MFA (FIDO2, Windows Hello for Business, or certificate-based authentication) for every sign-in by a privileged account. Replaces standard MFA — which can be phished via AiTM proxies — for the accounts attackers target first.

**Principle mapping:** Primary — AUT (Authentication Strengths). Secondary — SIG, because the control is gated on identity-role signal.

#### Scope

- Included users: None
- Excluded users: `CA-Persona-EmergencyAccess`
- Included directory roles: 14 highly-privileged roles (Global Administrator, Privileged Role Administrator, Security Administrator, Exchange Administrator, SharePoint Administrator, Teams Administrator, Dynamics Administrator, Power Platform Administrator, Authentication Administrator, Compliance Administrator, Helpdesk Administrator, Directory Synchronization Administrator, Cloud Application Administrator, Reports Reader)
- Included cloud apps: All cloud apps

#### Conditions

- Client apps: All
- Device platforms: Any
- Locations: Any
- Sign-in risk: Not evaluated
- User risk: Not evaluated

#### Controls

- Grant: Require authentication strength — Phishing-resistant MFA
- Session: None

**License requirements:** Entra ID P1 (Authentication Strengths is a P1 feature)

#### Validation in report-only

- Confirm every user with one of the 14 included directory roles has a registered phishing-resistant credential (FIDO2 key, Windows Hello, or certificate) BEFORE enforcement — lockout risk is highest for privileged roles
- Provision backup FIDO2 keys for each admin; keep one secured offline
- Verify break-glass accounts are NOT assigned any of the 14 included directory roles

**JSON template:** `../Policies/CA-AUT001-PrivAccounts-RequirePhishResistantMFA.json` (planned)

---

### 6.4 `CA-AUT002-PrivRoles-RequirePhishResistantMFA`

**Intent:** Require phishing-resistant MFA at the moment a user activates a privileged directory role through Privileged Identity Management (PIM) or signs in with an already-elevated session. Extends CA-AUT001 to the Just-In-Time activation path where standing admin membership has been replaced by on-demand activation.

**Principle mapping:** Primary — AUT (Authentication Strengths). Secondary — SIG, because the control responds dynamically to the user's effective role at sign-in.

#### Scope

- Included users: All users
- Excluded users: `CA-Persona-EmergencyAccess`
- Included cloud apps: All cloud apps
- Excluded cloud apps: None
- Directory role condition (minimum): Global Administrator, Privileged Role Administrator, Security Administrator, User Administrator, Conditional Access Administrator, Exchange Administrator, SharePoint Administrator, Helpdesk Administrator, Billing Administrator, Application Administrator, Cloud Application Administrator, Authentication Administrator. Expand based on your privileged role inventory.

#### Conditions

- Client apps: All
- Device platforms: Any
- Locations: Any
- Sign-in risk: Not evaluated
- User risk: Not evaluated

#### Controls

- Grant: Require authentication strength — Phishing-resistant MFA
- Session: None

**License requirements:** Entra ID P2 (required for PIM); P1 minimum for Authentication Strengths

#### Validation in report-only

- Inventory all directory roles in use via `Get-MgDirectoryRole` in Microsoft Graph PowerShell; confirm the condition list covers every privileged role you assign
- Validate that any user who might activate a role has a phishing-resistant credential registered
- Test the full PIM activation flow with a pilot user before enforcement

**JSON template:** `../Policies/CA-AUT002-PrivRoles-RequirePhishResistantMFA.json` (planned)

---

### 6.5 `CA-SIG001-SensApps-RequireCompliantDevice`

**Intent:** Require that the sign-in originate from an Intune-compliant or Hybrid Azure AD-joined device when accessing sensitive applications. Ties high-value access to endpoints whose health posture is known and managed.

**Principle mapping:** Primary — SIG (Layered signals). Combines application-sensitivity signal with device-state signal to make access conditional on both identity assurance AND endpoint integrity.

#### Scope

- Included users: `CA-Persona-InternalUsers`
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`
- Included cloud apps: Sensitive Apps set — typically includes Microsoft Admin portals, Azure Management, Microsoft Intune, Microsoft 365 admin center, Exchange Online Admin, SharePoint Admin, and any in-house finance/HR/crown-jewel SaaS
- Excluded cloud apps: None

#### Conditions

- Client apps: Browser, Mobile apps and desktop clients
- Device platforms: Any
- Locations: Any
- Sign-in risk: Not evaluated
- User risk: Not evaluated

#### Controls

- Grant: Require device to be marked as compliant OR Require Hybrid Azure AD joined device (use OR to support mixed modern and legacy compliance postures)
- Session: None

**License requirements:** Entra ID P1 + Microsoft Intune (or Hybrid join via Active Directory)

#### Validation in report-only

- Confirm every user in `CA-Persona-InternalUsers` has at least one device registered and marked compliant in Intune (or Hybrid-joined) BEFORE enforcement
- Run the Intune compliance dashboard; remediate non-compliant devices in the pilot group before tenant-wide rollout
- Validate the sensitive-app scope matches your organization's crown-jewel app list — do not over-scope in the first release

**JSON template:** `../Policies/CA-SIG001-SensApps-RequireCompliantDevice.json` (planned)

---

### 6.6 `CA-SIG009-AllUsers-BlockHighUserRisk`

**Intent:** Hard-block all users when Entra ID Identity Protection evaluates user risk as high. Complements the graduated response on medium user risk (CA-SIG004).

**Principle mapping:** Primary — SIG (Layered signals). Consumes Identity Protection user risk and responds decisively.

#### Scope

- Included users: All users
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`
- Included cloud apps: All cloud apps

#### Conditions

- Client apps: All
- Device platforms: Any
- Locations: Any
- User risk: High

#### Controls

- Grant: Block access

**License requirements:** Entra ID P2 (Identity Protection is a P2 feature)

#### Validation in report-only

- Review Identity Protection user-risk detections for the prior 30 days to understand false-positive volume in your tenant
- Confirm the Risky Users remediation path is in place (password reset, MFA enrollment, or user dismissal)
- Soak for 14 days minimum; user-risk detections surface over time as behavior patterns emerge
- Confirm that high user-risk accounts have a documented remediation process before enforcement

**JSON template:** `../Policies/CA-SIG009-AllUsers-BlockHighUserRisk.json`

---

### 6.7 `CA-SIG010-AllUsers-BlockHighSignInRisk`

**Intent:** Hard-block all users when Entra ID Identity Protection evaluates sign-in risk as high. Replaces the step-up-on-risk control with a zero-tolerance high-risk response.

**Principle mapping:** Primary — SIG (Layered signals). Consumes Identity Protection sign-in risk and responds decisively.

#### Scope

- Included users: All users
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`
- Included cloud apps: All cloud apps

#### Conditions

- Client apps: All
- Device platforms: Any
- Locations: Any
- Sign-in risk: High

#### Controls

- Grant: Block access

**License requirements:** Entra ID P2 (Identity Protection is a P2 feature)

#### Validation in report-only

- Review Identity Protection sign-in-risk detections for the prior 30 days to understand false-positive volume in your tenant
- Soak for 14 days minimum; sign-in-risk detections surface unevenly, and a shorter soak can miss edge cases
- Confirm that high-risk sign-in accounts have a documented remediation path before enforcement
- Monitor for legitimate services that trigger high-risk detections; these may require service-account exclusions

**JSON template:** `../Policies/CA-SIG010-AllUsers-BlockHighSignInRisk.json`

---

### 6.9 `CA-COV003-WorkloadIdentities-TrustedLocations`

**Intent:** Restrict service-principal (workload identity) sign-ins to a defined set of Named Locations representing the organization's approved egress IP ranges. Closes the workload-identity coverage gap left by the user-scoped CA-COV policies, which exclude `CA-Persona-WorkloadIdentities` so that machine sign-ins are not blocked by interactive-user controls.

**Principle mapping:** Primary — COV (Identity-wide coverage). This policy is the workload-side equivalent of CA-COV001/CA-COV002 — it ensures the workload-identity exclusion in the user-scoped policies does not become a coverage hole.

#### Scope

- Included workload identities: `CA-Persona-WorkloadIdentities` (or "All service principals" in tenants with a complete workload-identity inventory)
- Excluded workload identities: None
- Included cloud apps: All cloud apps
- Excluded cloud apps: None

#### Conditions

- Locations: Include All locations; Exclude Trusted Network Locations (one or more Named Locations representing approved egress)
- Client apps: Not applicable (workload identity policies do not evaluate client app)
- Device platforms: Not applicable
- Sign-in risk: Not evaluated (handled separately by Workload Identity Risk if licensed)
- User risk: Not applicable

#### Controls

- Grant: Block access
- Session: None

**License requirements:** Microsoft Entra Workload Identities Premium add-on (required to scope Conditional Access to service principals)

#### Validation in report-only

- Enumerate active service-principal sign-ins for the prior 30 days via `Get-MgAuditLogSignIn` filtered by `signInEventTypes/any(t:t eq 'servicePrincipal')`; record the source IPs
- Confirm every legitimate workload signs in from a known trusted IP range before enforcement; coordinate with platform engineering to register all egress IPs as a Named Location
- Identify any third-party SaaS-to-tenant integrations that authenticate from vendor-owned IP ranges; either add those ranges to the trusted set or scope the service principal under a tighter, vendor-specific policy
- Soak for 14 days minimum to capture low-frequency batch jobs and quarterly automation

**JSON template:** `../Policies/CA-COV003-WorkloadIdentities-TrustedLocations.json`

---

### 6.9 `CA-SIG003-Guests-RequireMFA`

**Intent:** Require MFA for every interactive guest (B2B) sign-in into the tenant. Closes the gap where home-tenant authentication assurance for guest users may be weaker than the resource tenant's standard for internal users.

**Principle mapping:** Primary — SIG (Layered signals). Combines user-type signal (`userType eq 'Guest'`) with the MFA control. Secondary — COV, because it extends the MFA floor established by CA-COV002 to the guest population that is otherwise governed by cross-tenant access settings.

---

### 6.10 `CA-COV004-Global-NoPersistentBrowserSession`

**Intent:** Disable persistent browser sessions and enforce a 4-hour browser sign-in frequency. Closes the "keep me signed in" path that materially extends the post-MFA token lifetime on shared and unmanaged browsers.

**Principle mapping:** Primary — COV (Identity-wide coverage). Secondary — SIG, because the control modifies the session signal.

#### Scope

- Included users: All users (Global scope)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: All cloud apps
- Excluded cloud apps: None

#### Conditions

- Client apps: Browser
- Device platforms: Include any; exclude iOS, Android (OS-level session handling makes the control redundant on mobile)

#### Controls

- Session: Persistent browser session — never; Sign-in frequency — 4 hours

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-COV004-Global-NoPersistentBrowserSession.json`

---

### 6.11 `CA-COV005-Global-BlockDeviceCodeFlow`

**Intent:** Block OAuth 2.0 device code flow. Device code flow is a phishing-friendly grant flow that is rarely used outside legitimate device-pairing scenarios; closing it materially reduces consent-phishing attack surface.

**Principle mapping:** Primary — COV (Identity-wide coverage). Ships as part of the auth-flow surface-area block trio (CA-COV005 / CA-COV006 / CA-COV007).

#### Scope

- Included users: All users (Global scope)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: All cloud apps

#### Conditions

- Authentication flows: Device code flow

#### Controls

- Grant: Block access

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-COV005-Global-BlockDeviceCodeFlow.json`

---

### 6.12 `CA-COV006-Global-BlockAuthenticationTransfer`

**Intent:** Block Authentication Transfer (cross-device authentication initiated on one device and completed on another). Closes the second auth-flow side channel of the v1.2 trio.

**Principle mapping:** Primary — COV. Ships paired with CA-COV005 and CA-COV007.

#### Scope

- Included users: All users (Global scope)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: All cloud apps

#### Conditions

- Authentication flows: Authentication transfer

#### Controls

- Grant: Block access

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-COV006-Global-BlockAuthenticationTransfer.json`

---

### 6.13 `CA-COV007-Global-BlockUnknownPlatforms`

**Intent:** Block sign-ins from device platforms not in the named set. Catches sign-ins from spoofed, headless, or obsolete device platforms that fall outside the tenant's supported fleet.

**Principle mapping:** Primary — COV. Completes the auth-flow surface-area block trio.

#### Scope

- Included users: All users (Global scope)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: All cloud apps

#### Conditions

- Device platforms: Include any; exclude windows, macOS, iOS, android, linux, windowsPhone

#### Controls

- Grant: Block access

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-COV007-Global-BlockUnknownPlatforms.json`

---

### 6.14 `CA-AUT003-Global-RegisterDevice`

**Intent:** Require StandardAuth authentication strength on the registerdevice userAction. Protects the device-registration ceremony itself, ensuring tokens issued at registration are bound to a verified authentication path.

**Principle mapping:** Primary — AUT. Operates on the `userAction` condition, distinct from sign-in policies.

#### Scope

- Included users: All users (Global scope)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- User action: `urn:user:registerdevice`

#### Conditions

- Client apps: All
- Device platforms: Any
- Locations: Any

#### Controls

- Grant: Require authentication strength — `CA-AUTH-STRENGTH-StandardAuth`

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-AUT003-Global-RegisterDevice.json`

---

### 6.15 `CA-AUT004-Global-RegisterSecurityInfo`

**Intent:** Require StandardAuth on the registersecurityinfo userAction. Protects the security-info registration ceremony (MFA method enrollment, SSPR enrollment) from being completed by a weakly-authenticated session.

**Principle mapping:** Primary — AUT. Ships paired with CA-AUT003.

#### Scope

- Included users: All users (Global scope)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- User action: `urn:user:registersecurityinfo`

#### Conditions

- Client apps: All
- Device platforms: Any
- Locations: Any

#### Controls

- Grant: Require authentication strength — `CA-AUTH-STRENGTH-StandardAuth`

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-AUT004-Global-RegisterSecurityInfo.json`

---

### 6.16 `CA-COV008-Global-BlockByLocation`

**Intent:** Block Global sign-ins originating outside the `CA-LOCATION-TrustedCountries` named-location set. Establishes a country-based floor for the entire baseline.

**Principle mapping:** Primary — COV. Combines with `CA-COV010` (the ServiceAccounts inverse) to give the trusted-countries pattern two policy roles.

#### Scope

- Included users: All users (Global scope)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: All cloud apps

#### Conditions

- Locations: Include All locations; Exclude `CA-LOCATION-TrustedCountries`

#### Controls

- Grant: Block access

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-COV008-Global-BlockByLocation.json`

**Supporting artifact:** `../Supporting-Artifacts/CA-LOCATION-TrustedCountries.json`

---

### 6.17 `CA-COV009-Internal-RequireCompliantDeviceOnDesktops`

**Intent:** Require compliant or hybrid Azure AD joined device for Internal sign-ins from desktop platforms (Windows, macOS, Linux). Closes the desktop-side gap where Internal users could sign in from unmanaged devices.

**Principle mapping:** Primary — SIG. Layers device-state signal with platform signal.

#### Scope

- Included users: `CA-Persona-InternalUsers`
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: All cloud apps

#### Conditions

- Client apps: Browser, Mobile apps and desktop clients
- Device platforms: Include windows, macOS, linux
- Locations: Any

#### Controls

- Grant: Require device to be marked as compliant **OR** Require Hybrid Azure AD joined device

**License requirements:** Entra ID P1 + Microsoft Intune (or Hybrid join via Active Directory)

**JSON template:** `../Policies/CA-COV009-Internal-RequireCompliantDeviceOnDesktops.json`

---

### 6.18 `CA-SIG004-Global-MediumUserRisk`

**Intent:** Apply a graduated control to medium user-risk sign-ins: require StandardAuth, require password change, set sign-in frequency to every time. Replaces hard-block-on-medium-risk, which produces too many false-positive lockouts.

**Principle mapping:** Primary — SIG. Pairs with `CA-SIG002` (high-risk hard block) and `CA-SIG005` (medium sign-in-risk).

#### Scope

- Included users: All users (Global scope)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: All cloud apps

#### Conditions

- User risk: Medium

#### Controls

- Grant: Require authentication strength — `CA-AUTH-STRENGTH-StandardAuth`; Require password change
- Session: Sign-in frequency — every time

**License requirements:** Entra ID P2 (user-risk requires Identity Protection)

**JSON template:** `../Policies/CA-SIG004-Global-MediumUserRisk.json`

---

### 6.19 `CA-SIG005-Global-MediumSignInRisk`

**Intent:** Apply a graduated control to medium sign-in-risk sessions: require StandardAuth and set sign-in frequency to every time. Pairs with `CA-SIG002` to give the sign-in-risk axis a hard-block-on-high + graduated-on-medium shape.

**Principle mapping:** Primary — SIG. Ships paired with `CA-SIG004`.

#### Scope

- Included users: All users (Global scope)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: All cloud apps

#### Conditions

- Sign-in risk: Medium

#### Controls

- Grant: Require authentication strength — `CA-AUTH-STRENGTH-StandardAuth`
- Session: Sign-in frequency — every time

**License requirements:** Entra ID P2

**JSON template:** `../Policies/CA-SIG005-Global-MediumSignInRisk.json`

---

### 6.20 `CA-AUT005-Admins-RequireAdminAuthOnAdminPortals`

**Intent:** Require the AdminAuth (FIDO2-only) authentication strength for admin sign-ins to Microsoft Azure Management + Microsoft Admin Portals. The highest-privilege admin surfaces get a phishing-resistant-only floor on top of the broader admin baseline.

**Principle mapping:** Primary — AUT. Layers on top of `CA-AUT001` (StrongAuth on GlobalAdmins) and `CA-AUT002` (StrongAuth on PIM activation).

#### Scope

- Included users: `CA-Persona-GlobalAdmins` plus the 14 highly-privileged Entra ID directory roles by template ID (see CA-AUT002 spec for the role list)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: Microsoft Azure Management (`797f4846-ba00-4fd7-ba43-dac1f8f63013`), Microsoft Admin Portals (`MicrosoftAdminPortals`)
- Excluded cloud apps: None

#### Conditions

- Client apps: All

#### Controls

- Grant: Require authentication strength — `CA-AUTH-STRENGTH-AdminAuth`

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-AUT005-Admins-RequireAdminAuthOnAdminPortals.json`

**Supporting artifact:** `../Supporting-Artifacts/CA-AUTH-STRENGTH-AdminAuth.json`

---

### 6.21 `CA-SIG006-Admins-BlockMediumAndHighSignInRisk`

**Intent:** Hard-block medium and high sign-in-risk sessions for the Admins scope. Admins do not get the MFA step-up fallback that `CA-SIG002` extends to general users — admin credentials in a risk-flagged session do not get a re-challenge path.

**Principle mapping:** Primary — SIG. Distinct from `CA-SIG002` (general-user step-up) and `CA-SIG005` (general-user graduated on medium).

#### Scope

- Included users: Same Admins scope as `CA-AUT005` (CA-Persona-GlobalAdmins + 14 privileged roles)
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: All cloud apps

#### Conditions

- Sign-in risk: Medium, High

#### Controls

- Grant: Block access

**License requirements:** Entra ID P2

**JSON template:** `../Policies/CA-SIG006-Admins-BlockMediumAndHighSignInRisk.json`

---

### 6.22 `CA-SIG007-Guests-BlockNonGuestAppAccess`

**Intent:** Block guest sign-ins to any application outside the Microsoft 365 collaboration set. Closes the gap where a B2B guest token issued for a collaboration app could be re-used against unrelated registered applications in the tenant.

**Principle mapping:** Primary — SIG. Layers user-type (guest) with application-scope.

#### Scope

- Included users: `CA-Persona-GuestUsers`
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: All
- Excluded cloud apps: Office365 (the Microsoft 365 collaboration set)

#### Conditions

- Client apps: All

#### Controls

- Grant: Block access

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-SIG007-Guests-BlockNonGuestAppAccess.json`

---

### 6.23 `CA-COV010-ServiceAccounts-BlockUntrustedLocations`

**Intent:** Block ServiceAccounts persona sign-ins originating outside `CA-LOCATION-TrustedCountries`. The compensating control that closes the gap created by `CA-EXC002` (which exempts ServiceAccounts from every human-targeted policy).

**Principle mapping:** Primary — COV. Inverse-shape of the standard pattern: ServiceAccounts is the *inclusion* target; only EmergencyAccess and WorkloadIdentities are excluded.

#### Scope

- Included users: `EntraID-ConditionalAccess-ServiceAccounts`
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`
- Included cloud apps: All cloud apps

#### Conditions

- Client apps: All
- Locations: Include All locations; Exclude `CA-LOCATION-TrustedCountries`

#### Controls

- Grant: Block access

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-COV010-ServiceAccounts-BlockUntrustedLocations.json`

**Exclusion contract:** `../Policies/CA-EXC002-ServiceAccounts-Exclusion.md`

---

### 6.24 `CA-SIG008-Internal-TokenProtection`

**Intent:** Enable Token Protection (`sessionControls.secureSignInSession.isEnabled=true`) for Internal Windows sign-ins to the Office 365 application bundle. Cryptographically binds refresh tokens and PRTs to the issuing device's TPM-protected key, blocking redemption of stolen tokens from any other device. The only policy in the baseline that operates at token-redemption time rather than sign-in time.

**Principle mapping:** Primary — SIG. Layers with Continuous Access Evaluation (CAE) without redundancy; full layering analysis in the paired design doc.

#### Scope

- Included users: `CA-Persona-InternalUsers`
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`, `EntraID-ConditionalAccess-ServiceAccounts`
- Included cloud apps: Office 365 application bundle (Exchange Online + SharePoint Online sign-in paths)

#### Conditions

- Client apps: All
- Device platforms: Windows

#### Controls

- Session: Token Protection — `secureSignInSession=true`

**License requirements:** Entra ID P1

**JSON template:** `../Policies/CA-SIG008-Internal-TokenProtection.json`

**Paired design doc:** `../Policies/CA-SIG008-Internal-TokenProtection.md` (covers post-MFA token-replay threat surface, CAE layering, coverage seams, 14-day report-only validation procedure)

#### Scope

- Included users: `CA-Persona-GuestUsers`
- Excluded users: `CA-Persona-EmergencyAccess`
- Included cloud apps: All cloud apps
- Excluded cloud apps: None

#### Conditions

- Client apps: Browser, Mobile apps and desktop clients
- Device platforms: Any
- Locations: Any
- Sign-in risk: Not evaluated
- User risk: Not evaluated

#### Controls

- Grant: Require multifactor authentication
- Session: None

**License requirements:** Entra ID P1 (minimum)

#### Validation in report-only

- Inventory all active guest accounts via `Get-MgUser -Filter "userType eq 'Guest'"`; confirm the dynamic membership of `CA-Persona-GuestUsers` matches that inventory
- Configure Cross-Tenant Access Settings to trust home-tenant MFA claims where appropriate; otherwise guests will be challenged on every resource-tenant sign-in
- Soak for 7 days to capture monthly cross-tenant guest sign-ins and any low-frequency external collaborators
- Verify break-glass accounts are NOT members of `CA-Persona-GuestUsers`

