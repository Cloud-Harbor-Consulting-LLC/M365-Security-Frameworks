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

**How this baseline implements it:** Policies in the `CA-SIG` series evaluate multiple signals in combination. `CA-SIG001` layers application sensitivity with device compliance; `CA-SIG002` layers sign-in risk with step-up authentication; `CA-SIG003` layers user-type (guest) with the MFA control. This is the difference between "require MFA" and "require MFA *because we detected risk*."

### 1.4 Authentication Strengths

**What it means:** Not all MFA is equal. SMS and voice-call MFA are phishable via AiTM (adversary-in-the-middle) proxies; FIDO2, Windows Hello for Business, and certificate-based authentication are not. Privileged identities and high-value workloads must be protected by phishing-resistant methods.

**How this baseline implements it:** Policies in the `CA-AUT` series use Entra ID Authentication Strengths to require phishing-resistant MFA for privileged accounts (`CA-AUT001`) and privileged role activations (`CA-AUT002`). No privileged action clears the baseline without a phishing-resistant credential.

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

| Persona | Suggested Entra Group | Typical Size | Notes |
|---------|----------------------|--------------|-------|
| Global & Privileged Administrators | `CA-Persona-GlobalAdmins` | 2–5 members | Break-glass accounts are NOT members |
| Privileged Roles (PIM-activated) | Dynamic, driven by PIM activation | Varies | Scoped via directory roles, not a static group |
| Internal Users | `CA-Persona-InternalUsers` | All employees | Dynamic group based on `userType eq 'Member'` recommended |
| Guest Users | `CA-Persona-GuestUsers` | Varies | Dynamic group based on `userType eq 'Guest'` recommended |
| Workload Identities | `CA-Persona-WorkloadIdentities` | Inventory-dependent | Scoped via the Workload Identities blade, not a user group |
| Emergency Access Accounts | `CA-Persona-EmergencyAccess` | Exactly 2 | Monitored by alert rule; never members of any other group |

### 3.1 Persona naming

The `CA-Persona-` prefix on groups is intentional: it makes persona groups sortable, searchable, and unambiguous in the Entra admin center. Avoid reusing existing business groups (e.g., "All Employees") as persona scopes — policy scope and HR scope should not be conflated.

---

## 4. Exclusion group strategy

Exclusions are the single most dangerous element of any Conditional Access baseline. This framework treats them with corresponding rigor.

### 4.1 Permanent exclusions (2 total)

1. **Emergency access accounts** (`CA-Persona-EmergencyAccess`) — excluded from every policy. Two accounts, cloud-only, stored offline in a sealed envelope, monitored by a sign-in alert rule that pages the security team on any use. Operational specification (key custody, alert rule, recovery test cadence): `CA-EXC001-EmergencyAccess-Exclusion.md`.
2. **Workload identities** — excluded from user-scoped policies and governed by a separate workload-identity policy set (see `CA-COV003`).

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
| 6 | `CA-SIG002-AllUsers-RequireStepUpOnRisk` | 14 days | Requires Entra ID P2 + Identity Protection tuning — soak longer |
| 7 | `CA-COV003-WorkloadIdentities-TrustedLocations` | 14 days | Workload-identity coverage; soak to inventory legitimate egress IPs before enforcement |
| 8 | `CA-SIG003-Guests-RequireMFA` | 7 days | Guest scope is bounded; soak captures cross-tenant B2B sign-in patterns |

`CA-EXC001-EmergencyAccess-Exclusion` is a documented permanent exclusion, not a deployable policy, and is not part of the rollout sequence.

**Do not skip report-only.** Every policy must be validated in report-only mode before enforcement, no matter how confident the reviewer is in its scope.

---

## 6. Per-policy design specifications

Each of the eight starter policies is specified below. Every spec follows the same structure: intent, principle mapping, scope, conditions, controls, license requirements, validation steps, and the JSON template path. The standing exclusion specification for emergency access accounts (`CA-EXC001`) is documented separately in `CA-EXC001-EmergencyAccess-Exclusion.md`.

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

- Included users: `CA-Persona-GlobalAdmins`
- Excluded users: `CA-Persona-EmergencyAccess`
- Included cloud apps: All cloud apps
- Excluded cloud apps: None

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

- Confirm every member of `CA-Persona-GlobalAdmins` has a registered phishing-resistant credential (FIDO2 key, Windows Hello, or certificate) BEFORE enforcement — lockout risk is highest here
- Provision backup FIDO2 keys for each admin; keep one secured offline
- Verify break-glass accounts are NOT members of `CA-Persona-GlobalAdmins`

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

### 6.6 `CA-SIG002-AllUsers-RequireStepUpOnRisk`

**Intent:** Enforce step-up authentication when Entra ID Identity Protection evaluates a sign-in as medium or high risk. Converts risk intelligence into an adaptive control rather than relying on static allow/deny.

**Principle mapping:** Primary — SIG (Layered signals). Consumes Identity Protection sign-in risk and responds dynamically.

#### Scope

- Included users: All users
- Excluded users: `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities`
- Included cloud apps: All cloud apps
- Excluded cloud apps: None

#### Conditions

- Client apps: All
- Device platforms: Any
- Locations: Any
- Sign-in risk: Medium, High
- User risk: Not evaluated here (handled separately in a future CA-SIG policy addressing user-risk remediation)

#### Controls

- Grant: Require authentication strength — Multifactor authentication (consider Phishing-resistant MFA for high-risk sign-ins based on your tenant's false-positive tolerance)
- Session: Sign-in frequency — every time (forces re-auth on risky sessions)

**License requirements:** Entra ID P2 (Identity Protection is a P2 feature)

#### Validation in report-only

- Review Identity Protection risk detections for the prior 30 days to understand false-positive volume in your tenant
- Tune exclusions for known service-account sign-in patterns that legitimately trigger risk detections
- Soak for 14 days minimum; risk detections surface unevenly, and a shorter soak can miss edge cases
- Confirm self-service password reset and MFA registration are both deployed — risky sign-ins must have a remediation path

**JSON template:** `../Policies/CA-SIG002-AllUsers-RequireStepUpOnRisk.json` (planned)

---

### 6.7 `CA-COV003-WorkloadIdentities-TrustedLocations`

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

### 6.8 `CA-SIG003-Guests-RequireMFA`

**Intent:** Require MFA for every interactive guest (B2B) sign-in into the tenant. Closes the gap where home-tenant authentication assurance for guest users may be weaker than the resource tenant's standard for internal users.

**Principle mapping:** Primary — SIG (Layered signals). Combines user-type signal (`userType eq 'Guest'`) with the MFA control. Secondary — COV, because it extends the MFA floor established by CA-COV002 to the guest population that is otherwise governed by cross-tenant access settings.

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
