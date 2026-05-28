# Conditional Access Baseline — Policy Design

This document specifies the design philosophy, naming convention, persona model, exclusion strategy, rollout sequence, and per-policy design specifications for the Conditional Access Baseline framework (v1.3). It is the prerequisite reading for anyone deploying, extending, or auditing the baseline.

---

## 1. Design philosophy

Conditional Access is Microsoft's Zero Trust policy engine, not a collection of feature toggles. This baseline is built around the thesis that **until a defensible baseline exists, adding more Conditional Access policies increases complexity without materially reducing risk.**

Four principles anchor every design decision in this framework:

### 1.1 Identity-wide coverage

**What it means:** No orphaned identities, applications, or legacy protocols should be able to authenticate outside the scope of Conditional Access. Every user, every guest, every workload identity, every service account, every agent, and every cloud app must be covered by at least one evaluated policy.

**How this baseline implements it:** `CA-COV001` (Block legacy authentication) and `CA-COV002` (Require MFA) are scoped to all users and all cloud apps, with controlled exclusions. `CA-COV010` (Workload Identities Trusted Locations) closes the service-principal gap. `CA-COV011` (Agents BlockMediumAndHighRisk) covers the Agent ID identity class. Auth-flow side channels are closed by `CA-COV004` (BlockDeviceCodeFlow) and `CA-COV005` (BlockAuthenticationTransfer). Location and platform gaps are closed by `CA-COV006` and `CA-COV007`.

### 1.2 No standing exclusions

**What it means:** Exclusions are a common attack path. An exclusion group that persists indefinitely becomes a backdoor — one compromised member, and the entire baseline can be bypassed. Exclusions must be governed, auditable, and reviewed.

**How this baseline implements it:** Only two exclusion groups are permanent: emergency access accounts (governed by `CA-EXC001`) and service accounts (governed by `CA-EXC002`). Workload identities are excluded from user-targeted policies because they operate on a separate code path (`CA-COV010`). The Agents persona is handled via positive targeting in `CA-COV011`, not exclusion. Per-policy exclusion rationale is documented in Section 6.

### 1.3 Layered signals

**What it means:** Strong security emerges from combining signals — identity risk, device state, location, application sensitivity, authentication flow — not from any single control. A policy that evaluates only one signal is a single point of failure.

**How this baseline implements it:** Risk policies (`CA-SIG003`, `CA-SIG004`) combine authentication strength with sign-in frequency and risk remediation. The Internal desktop policy (`CA-COV008`) layers platform with device compliance. Token Protection (`CA-SIG007`) layers application scope with platform scope to target the highest-risk token-theft surface. The Agents policy (`CA-COV011`) layers agent identity with agent risk level.

### 1.4 Authentication Strengths

**What it means:** Not all MFA is equal. SMS and voice-call MFA are phishable via AiTM (adversary-in-the-middle) proxies; FIDO2, Windows Hello for Business, and certificate-based authentication are not. Privileged identities and high-value workloads must be protected by phishing-resistant methods.

**How this baseline implements it:** Three named authentication strengths are defined in `Supporting-Artifacts/`: `StandardAuth` (WHfB + FIDO2 + password + Authenticator push), `StrongAuth` (WHfB + FIDO2 only), and `AdminAuth` (FIDO2 only). `CA-AUT001` and `CA-AUT002` require `StandardAuth` for the registration user actions. `CA-AUT003` requires `AdminAuth` on admin portals. Risk policies `CA-SIG003` and `CA-SIG004` require `StrongAuth` as part of their graduated response.

### 1.5 v1.3 design refinements

The v1.3 slate makes the following changes relative to prior Unreleased state. The per-policy specs in Section 6 carry the full implementation detail.

#### Beta endpoint commitment

All 23 policies in this baseline target `https://graph.microsoft.com/beta/identity/conditionalAccess/policies`. Three policies use features that are Microsoft Graph beta-only as of May 2026:

- `CA-SIG003-Global-MediumUserRisk` and `CA-SIG004-Global-MediumSignInRisk` use `signInFrequency.frequencyInterval: "everyTime"`, which is not available in the v1.0 endpoint.
- `CA-COV011-Agents-BlockMediumAndHighRisk` uses `agentIdRiskLevels`, `IncludeAgentIdServicePrincipals`, and `AllAgentIdResources`, all of which are beta-only.

Rather than maintain two endpoint paths, the framework commits all 23 policies to the beta endpoint. When Microsoft completes GA promotion of these fields, the endpoint URL can be flipped in one deployer change without updating any policy template. See `Design/AGENTS-PERSONA-MODEL.md` section 6 for the GA tracking commitment.

#### Agents persona as first-class identity class

`CA-COV011-Agents-BlockMediumAndHighRisk` introduces the Agents persona. Microsoft Agent IDs are not service principals, not managed identities, and not users. They carry their own Identity Protection risk signals via `agentIdRiskLevels`. The persona is documented in `Policies/CA-EXC003-Agents-Persona.md` and fully modeled in `Design/AGENTS-PERSONA-MODEL.md`.

#### Per-policy exclusion judgment replaces blanket exclusion set

The v1.2 architecture excluded EmergencyAccess, WorkloadIdentities, and ServiceAccounts from virtually all policies by default. v1.3 applies exclusions on a per-policy basis with documented rationale. The pattern is stricter: if a persona is excluded, Section 6 records why. If a persona is not excluded, it is in scope by design.

#### Phishing-resistant MFA enforcement model change

The prior Unreleased state included `CA-AUT001-PrivAccounts-RequirePhishResistantMFA` and `CA-AUT002-PrivRoles-RequirePhishResistantMFA` as always-on phishing-resistant MFA policies for privileged accounts. v1.3 replaces this with:

- `CA-AUT003-Admins-RequireAdminAuthOnAdminPortals`: FIDO2-only (`AdminAuth`) on Azure Service Management and Microsoft Admin Portals, targeting the 14 privileged directory roles.
- `CA-SIG003-Global-MediumUserRisk` and `CA-SIG004-Global-MediumSignInRisk`: StrongAuth (WHfB or FIDO2) required when Identity Protection raises medium user or sign-in risk. Risk remediation is required alongside the authentication strength.
- PIM activation: always-on phishing-resistant enforcement for role activation is handled out-of-baseline via Privileged Identity Management configuration.

This model targets the phishing-resistant requirement at the highest-risk surfaces (admin portals) and risk-elevated sessions, rather than enforcing a blanket always-on requirement that generates friction on low-risk internal admin tasks.

### 1.6 Global scope and Admins scope definitions

**Global scope** means all users in the tenant. Policies with `Global` in the name target `users.includeUsers: ["All"]` with the standard exclusion set applied per-policy.

**Admins scope** means the 14 highly-privileged Entra ID directory roles by template ID. These roles are:

| Role | Template ID |
|---|---|
| Global Administrator | `62e90394-69f5-4237-9190-012177145e10` |
| Privileged Role Administrator | `e8611ab8-c189-46e8-94e1-60213ab1f814` |
| Security Administrator | `194ae4cb-b126-40b2-bd5b-6091b380977d` |
| Compliance Administrator | `7be44c8a-adaf-4e2a-84d6-ab2649e08a13` |
| Exchange Administrator | `158c047a-c907-4556-b7ef-446551a6b5f7` |
| SharePoint Administrator | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` |
| Helpdesk Administrator | `fe930be7-5e62-47db-91af-98c3a49a38b1` |
| Authentication Administrator | `966707d0-3269-4727-9be2-8c3a10f19b9d` |
| Cloud Application Administrator | `c4e39bd9-1100-46d3-8c65-fb160da0071f` |
| Directory Synchronization Account | `29232cdf-9323-42fd-ade2-1d097af3e4de` |
| Teams Administrator | `69091246-20e8-4a56-aa4d-066075b2a7a8` |
| Power Platform Administrator | `3a2c62db-5318-420d-8d74-23affee5d9d5` |
| Dynamics Administrator | `f28a1f50-f6e7-4571-818b-6a12f2af6b6c` |
| Reports Reader | `729827e3-9c14-49f7-bb1b-9608f156bbb8` |

Both Global and Admins scope segments inherit the per-policy exclusion contract documented in Section 4 and detailed per-policy in Section 6.

---

## 2. Naming convention

Every policy in this baseline follows the format:

```
CA-[PrinciplePrefix][Number]-[Persona]-[Action]
```

### 2.1 Principle prefixes

| Prefix | Principle | Use when the policy primarily enforces... |
|---|---|---|
| `AUT` | Authentication Strengths | Phishing-resistant MFA requirements |
| `COV` | Identity-wide coverage | Blanket coverage of users, apps, protocols, or flows |
| `EXC` | No standing exclusions | Written exclusion contracts and persona governance |
| `SIG` | Layered signals | Device, location, risk, or application signals shaping decisions |

### 2.2 Rules

- One prefix per policy. When a policy could fit two prefixes, use the one that reflects its primary intent.
- Numbers are sequential within a prefix. Retired policies keep their number permanently.
- Persona and action are hyphen-separated, using CamelCase within each segment.
- File names mirror policy names exactly: `CA-COV001-AllUsers-BlockLegacyAuth.json`.

---

## 3. Persona model

Eight personas are defined in this baseline. Each persona maps to an identity class that authenticates distinctly and requires a distinct CA treatment.

| Persona | How targeted | Permanent exclusion contract | Notes |
|---|---|---|---|
| Global | `users.includeUsers: ["All"]` | Per-policy (EA, SA excluded; WI excluded from user-context policies) | Universal baseline scope. Applies to all users including guests unless overridden. |
| Internal | `users.includeGroups: [CA-Persona-InternalUsers]` | EA, WI, SA excluded per-policy | Member users only. Dynamic group recommended (`userType eq 'Member'`). |
| Admins | `users.includeRoles: [14 template IDs]` | EA, WI, SA excluded per-policy | 14 highly-privileged Entra ID directory roles. Scoped via role template IDs, not a static group. |
| Guests | `users.includeGuestsOrExternalUsers` or `users.includeGroups: [CA-Persona-Guests]` | EA excluded per-policy | B2B collaboration guests, external users, service providers. |
| ServiceAccounts | `users.includeGroups: [CA-Persona-ServiceAccounts]` | EA, WI excluded from CA-COV009 | Positive inclusion target for CA-COV009. Excluded from all human-targeted policies via CA-EXC002. |
| WorkloadIdentities | `clientApplications.includeServicePrincipals: [ServicePrincipalsInMyTenant]` | Not applicable (not a user persona) | Inclusion target for CA-COV010. Excluded from human-targeted user policies by virtue of not being users. |
| Agents | `clientApplications.includeAgentIdServicePrincipals: ["All"]` | Not applicable (not a user persona) | Inclusion target for CA-COV011. Microsoft Agent IDs. Persona governed by CA-EXC003. |
| EmergencyAccess | `users.excludeGroups: [CA-Persona-EmergencyAccess]` | Permanent exclusion from all policies | Exactly 2 accounts. Cloud-only. Governed by CA-EXC001. |

### 3.1 Persona group naming convention

| Group name | Persona | Type |
|---|---|---|
| `CA-Persona-EmergencyAccess` | EmergencyAccess | Static, exactly 2 members |
| `CA-Persona-InternalUsers` | Internal | Dynamic recommended (`userType eq 'Member'`) |
| `CA-Persona-ServiceAccounts` | ServiceAccounts | Static, curated per CA-EXC002 |
| `CA-Persona-WorkloadIdentities` | WorkloadIdentities | Deprecated from user group model; service principals are targeted via `clientApplications` |
| `CA-Persona-Guests` | Guests | Dynamic recommended (`userType eq 'Guest'`) or use `includeGuestsOrExternalUsers` condition |

The Agents persona does not have a corresponding Entra group. Targeting is via application-side CA conditions only. See `Policies/CA-EXC003-Agents-Persona.md` for details.

---

## 4. Exclusion strategy

Exclusions are the single most dangerous element of any Conditional Access baseline. This framework treats them with corresponding rigor.

### 4.1 Permanent exclusions

Two exclusion groups are permanent:

1. **Emergency access accounts** (`CA-Persona-EmergencyAccess`) — excluded from every policy. Two accounts, cloud-only, stored offline, monitored by alert rule. Operational specification: `Policies/CA-EXC001-EmergencyAccess-Exclusion.md`.
2. **Service accounts** (`CA-Persona-ServiceAccounts`) — excluded from every human-targeted policy via the written contract `Policies/CA-EXC002-ServiceAccounts-Exclusion.md`. Compensating control: `CA-COV009-ServiceAccounts-BlockUntrustedLocations`. Persona membership, monthly attestation, quarterly sign-in review, and credential rotation procedure are in the contract.

### 4.2 WorkloadIdentities exclusion pattern

Workload identities (service principals) are excluded from human-targeted policies by design — service principals do not authenticate as users and the user-context conditions do not evaluate against them. `CA-COV010-WorkloadIdentities-TrustedLocations` is the dedicated service-principal policy. The `REPLACE_WITH_WORKLOAD_IDENTITIES_GROUP_OBJECT_ID` group is excluded from human-targeted policies as an explicit guard; it is documented in the deployer so tenants can maintain the group.

### 4.3 Agents exclusion pattern

The Agents persona is **not** an exclusion from human-targeted policies. Agent IDs do not authenticate via the user-context flow. No `excludeGroups` entry for agents is needed in user-targeted policies, and none is present. `CA-COV011` provides positive targeting via `clientApplications.includeAgentIdServicePrincipals` and is the only policy that evaluates Agent ID authentication. See `Policies/CA-EXC003-Agents-Persona.md`.

### 4.4 Per-policy exclusion rationale

Section 6 documents the exclusion rationale for each policy. The pattern:

- **EmergencyAccess** is excluded from every policy. No exceptions.
- **WorkloadIdentities group** is excluded from user-targeted policies where workload identity authentication could be mistakenly caught.
- **ServiceAccounts** is excluded from human-targeted policies where the interactive requirements (MFA, device compliance, auth strength) would block legitimate service account operation.
- **Guests** are excluded where the policy targets a user type that guests do not match.
- **Agents** require no exclusion from user-targeted policies (they do not authenticate via the user path).

---

## 5. Rollout sequence

All 23 policies ship in `enabledForReportingButNotEnforced` state. The table below documents the recommended enforcement sequence. Enforce one policy at a time; validate with `Get-CABaselineImpact.ps1` before promoting the next.

One additional policy is deferred to PR 2: `CA-SIG010-Guests-RequireToU` (Terms of Use enforcement for B2B guests). It will join the baseline when the Entra ID ToU template and paired contract are complete.

| Position | Policy | Min soak (report-only) | Prerequisites |
|---|---|---|---|
| 1 | CA-COV001-AllUsers-BlockLegacyAuth | 7 days | Inventory of legacy auth clients |
| 2 | CA-COV002-AllUsers-RequireMFA | 14 days | MFA registration complete for all users in scope |
| 3 | CA-AUT001-Global-RegisterDevice | 7 days | StandardAuth strength provisioned |
| 4 | CA-AUT002-Global-RegisterSecurityInfo | 7 days | StandardAuth strength provisioned |
| 5 | CA-COV004-Global-BlockDeviceCodeFlow | 7 days | Inventory of legitimate device code flow clients |
| 6 | CA-COV005-Global-BlockAuthenticationTransfer | 7 days | Confirm no legitimate auth transfer flows in use |
| 7 | CA-COV006-Global-BlockUnknownPlatforms | 7 days | Confirm full fleet platform inventory |
| 8 | CA-COV007-Global-BlockByLocation | 14 days | TrustedCountries named location provisioned and validated |
| 9 | CA-COV003-Global-NoPersistentBrowserSessionOnNonCorpDevices | 14 days | Device filter rule validated against fleet |
| 10 | CA-SIG002-Guests-RequireMFA | 7 days | Guest MFA registration confirmed |
| 11 | CA-AUT003-Admins-RequireAdminAuthOnAdminPortals | 14 days | AdminAuth strength provisioned; FIDO2 keys issued to all 14-role holders |
| 12 | CA-SIG005-Admins-BlockMediumAndHighSignInRisk | 7 days | Identity Protection P2 active; review existing risk events |
| 13 | CA-SIG001-SensitiveApps-RequireCompliantDevice | 14 days | Intune compliance policy for internal users active and clean |
| 14 | CA-COV008-Internal-RequireCompliantDeviceOnDesktops | 14 days | Intune compliance policy for internal users active; Hybrid Join validated |
| 15 | CA-COV009-ServiceAccounts-BlockUntrustedLocations | 14 days | ServiceAccounts group membership attested per CA-EXC002; location inventory complete |
| 16 | CA-SIG003-Global-MediumUserRisk | 14 days | StrongAuth strength provisioned; Identity Protection P2 active |
| 17 | CA-SIG004-Global-MediumSignInRisk | 14 days | StrongAuth strength provisioned; Identity Protection P2 active |
| 18 | CA-SIG006-Guests-BlockNonGuestAppAccess | 7 days | Review guest sign-ins to non-Office365 apps; extend excludeApplications if needed |
| 19 | CA-SIG007-Internal-TokenProtection | 14 days | Windows TPM inventory; client version inventory per CA-SIG007-Internal-TokenProtection.md |
| 20 | CA-SIG008-AllUsers-BlockHighUserRisk | 7 days | Identity Protection P2 active; process for risk dismissal established |
| 21 | CA-SIG009-AllUsers-BlockHighSignInRisk | 7 days | Identity Protection P2 active; process for risk dismissal established |
| 22 | CA-COV010-WorkloadIdentities-TrustedLocations | 14 days | Workload Identities Premium; Trusted IPs location provisioned; SPN exclusion list reviewed |
| 23 | CA-COV011-Agents-BlockMediumAndHighRisk | 14 days | Agent ID inventory complete; Identity Protection agent signals active |

---

## 6. Per-policy design specifications

This section provides one subsection per policy. The 23 policies are ordered to match the rollout sequence table above.

---

### 6.1 CA-COV001-AllUsers-BlockLegacyAuth

**Intent:** Block sign-in attempts that use authentication protocols which cannot satisfy MFA challenges. Legacy authentication protocols (Exchange ActiveSync with basic auth, older MAPI/EAS clients, SMTP AUTH, IMAP, POP3) do not support modern authentication and cannot be intercepted by Conditional Access grant controls. Blocking them closes the single most commonly exploited bypass path for identity attacks.

**Principle mapping:** 1.1 Identity-wide coverage. Eliminating an entire authentication category from the sign-in surface.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess]` — WorkloadIdentities and ServiceAccounts are not excluded because the `clientAppTypes` filter to `exchangeActiveSync` and `other` is not applicable to them |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["exchangeActiveSync", "other"]` — the exact values that Microsoft recognizes as legacy auth |

**Grant control:** `block`. No re-challenge path exists; legacy clients cannot satisfy modern authentication controls.

**Session controls:** None.

**License requirements:** Entra ID P1 minimum.

**Validation steps:**

1. Run `Get-CABaselineImpact.ps1 -PolicyNameFilter 'CA-COV001' -Days 14`.
2. Identify every UPN in `WouldBlock`. These are users still using legacy clients.
3. For each UPN, identify the application and client (Exchange Online audit log, `ClientInfoString` field).
4. Work with the user or application owner to migrate to modern auth before enforcement.
5. After enforcement, monitor for `CA-COV001` blocks in the sign-in log for 48 hours.

**Exclusion rationale:** Only EmergencyAccess is excluded. Legacy authentication blocks must be as broad as possible. Service accounts and workload identities that use legacy protocols must be migrated or re-routed before enforcement — the preferred remediation is migration, not exclusion.

---

### 6.2 CA-AUT001-Global-RegisterDevice

**Intent:** Require StandardAuth (phishing-resistant first, with Authenticator push as a fallback) when any user performs the device registration user action (`urn:user:registerdevice`). Device registration is a high-value action — a device registration event binds a device to the tenant and can be used to upgrade a compromised account to device-level access.

**Principle mapping:** 1.4 Authentication Strengths. Authentication-gating the device registration ceremony.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeUserActions: ["urn:user:registerdevice"]` — targets the registration ceremony, not a specific app |
| Client app types | `["all"]` |

**Grant control:** `authenticationStrength.id: REPLACE_WITH_STANDARDAUTH_STRENGTH_ID` with `operator: "OR"`. StandardAuth allows WHfB, FIDO2, or password + Microsoft Authenticator push.

**Session controls:** None.

**License requirements:** Entra ID P1. StandardAuth custom authentication strength must exist in the tenant.

**Validation steps:**

1. Provision StandardAuth in the tenant from `Supporting-Artifacts/CA-AUTH-STRENGTH-StandardAuth.json`.
2. In report-only, confirm that device registration events in the sign-in log show `CA-AUT001` as `reportOnlyInterrupted` (challenge surfaced) or `reportOnlySuccess` (already satisfied).
3. After enforcement, verify that a test device registration from a compliant client (modern auth + Authenticator app) succeeds.

**Exclusion rationale:** Service accounts and workload identities do not register devices; excluding them prevents false positives if a non-user principal triggers this user action.

---

### 6.3 CA-AUT002-Global-RegisterSecurityInfo

**Intent:** Require StandardAuth when any user performs the security information registration user action (`urn:user:registersecurityinfo`). Security info registration adds authentication methods (phone numbers, authenticator apps, FIDO2 keys). An unauthenticated or weak-auth registration event allows an attacker who has stolen a password to add their own MFA methods before the account owner notices.

**Principle mapping:** 1.4 Authentication Strengths. Authentication-gating the security info registration ceremony.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeUserActions: ["urn:user:registersecurityinfo"]` |
| Client app types | `["all"]` |

**Grant control:** `authenticationStrength.id: REPLACE_WITH_STANDARDAUTH_STRENGTH_ID` with `operator: "OR"`.

**Session controls:** None.

**License requirements:** Entra ID P1. StandardAuth custom authentication strength must exist in the tenant.

**Validation steps:** Same pattern as 6.2. Verify that a test security info registration (adding an Authenticator app) from a modern auth client succeeds, while a test from a non-registered device without WHfB or FIDO2 is challenged.

**Exclusion rationale:** Same as CA-AUT001.

---

### 6.4 CA-AUT003-Admins-RequireAdminAuthOnAdminPortals

**Intent:** Require AdminAuth (FIDO2 hardware key only) when users with highly-privileged Entra ID directory roles access Azure Service Management or Microsoft Admin Portals. Admin portals are the highest-value attack surface for a privileged identity compromise. Requiring a hardware-bound, phishing-resistant key for all admin portal access eliminates AiTM and password-based attack paths on the admin surface.

**Principle mapping:** 1.4 Authentication Strengths. Narrowest authentication strength in the baseline applied to the highest-value admin surfaces.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeRoles: [14 privileged directory role template IDs]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["797f4846-ba00-4fd7-ba43-dac1f8f63013", "MicrosoftAdminPortals"]` — Azure Service Management + Microsoft Admin Portals |
| Client app types | `["all"]` |

**Grant control:** `authenticationStrength.id: REPLACE_WITH_ADMINAUTH_STRENGTH_ID` with `operator: "OR"`. AdminAuth allows FIDO2 hardware key only.

**Session controls:** None.

**License requirements:** Entra ID P1. AdminAuth custom authentication strength must exist in the tenant. FIDO2 hardware keys must be issued and registered for all users in the 14 roles before enforcement.

**Validation steps:**

1. Provision AdminAuth in the tenant from `Supporting-Artifacts/CA-AUTH-STRENGTH-AdminAuth.json`.
2. Enumerate all current role holders in the 14 roles. Confirm each has a registered FIDO2 key.
3. In report-only, verify that admin portal sign-ins from 14-role holders show `reportOnlyInterrupted` if using non-FIDO2 methods.
4. After enforcement, verify that a FIDO2 sign-in to the Azure portal succeeds, and that a non-FIDO2 (e.g., Authenticator app) sign-in is blocked.

**Exclusion rationale:** EmergencyAccess accounts may be excluded to retain emergency console access. This is a deliberate risk acceptance — document the decision in the CA-EXC001 contract.

---

### 6.5 CA-COV002-AllUsers-RequireMFA

**Intent:** Require any form of MFA for every interactive sign-in. This is the universal MFA floor — the policy that makes password-only authentication impossible across the tenant. It scopes to browser and rich client (mobileAppsAndDesktopClients) app types, which are the interactive authentication paths.

**Principle mapping:** 1.1 Identity-wide coverage. The most fundamental coverage policy in the baseline.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities]` — ServiceAccounts is **not** excluded here; service accounts that authenticate interactively must satisfy MFA or be moved to the ServiceAccounts persona |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["browser", "mobileAppsAndDesktopClients"]` |

**Grant control:** `builtInControls: ["mfa"]` with `operator: "OR"`. The built-in MFA control accepts any registered MFA method.

**Session controls:** None.

**License requirements:** Entra ID P1 minimum.

**Validation steps:**

1. Run `Get-CABaselineImpact.ps1 -PolicyNameFilter 'CA-COV002' -Days 14`.
2. Review `WouldBlock` — these users have no registered MFA method. Run MFA registration before enforcement.
3. After enforcement, confirm `WouldBlock` count drops to zero or matches your exception documentation.

**Exclusion rationale:** WorkloadIdentities are excluded because service principals don't use the interactive browser/rich-client authentication paths. ServiceAccounts that authenticate interactively should be in scope; if they cannot satisfy MFA, they should be reclassified and move to the ServiceAccounts persona group (which will then be covered by CA-COV009 instead).

---

### 6.6 CA-COV003-Global-NoPersistentBrowserSessionOnNonCorpDevices

**Intent:** Disable persistent browser sessions and enforce a 4-hour sign-in frequency for browser sessions originating from non-corporate devices. On corporate (Entra-joined or hybrid-joined) devices, persistent sessions are acceptable because the device itself provides posture verification. On non-corporate devices, a persistent session represents a residual access path that survives for days after a sign-in without re-verification.

**Principle mapping:** 1.3 Layered signals. Combines platform scope (browser only), platform type (non-mobile), and device state (exclude corporate) to produce a targeted session-hardening policy.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["browser"]` |
| Platforms | `includePlatforms: ["all"]`, `excludePlatforms: ["android", "iOS"]` — mobile platforms excluded because OS-level session management handles persistence on mobile |
| Device filter | `mode: "exclude"`, `rule: "device.isCompliant -eq True -or device.trustType -eq \"ServerAD\""` — corporate devices are excluded; the policy applies only to unmanaged or BYOD devices |

**Grant control:** None — this policy uses session controls only.

**Session controls:** `persistentBrowser.isEnabled: true, mode: "never"` disables persistent sessions. `signInFrequency.authenticationType: "primaryAndSecondaryAuthentication", frequencyInterval: "timeBased", isEnabled: true, type: "hours", value: 4` requires re-authentication every 4 hours.

**License requirements:** Entra ID P1.

**Validation steps:** Validate device filter rule against the fleet. In report-only, confirm the policy is not applying to Entra-joined or hybrid-joined devices. After enforcement, test a browser session from a non-managed device and verify it prompts at the 4-hour mark.

**Exclusion rationale:** Mobile platforms are excluded at the platform level, not via group exclusion. The device filter exclusion is the key scoping mechanism.

---

### 6.7 CA-COV004-Global-BlockDeviceCodeFlow

**Intent:** Block OAuth 2.0 device code flow for all users on all apps. Device code flow is a grant type designed for input-constrained devices (TVs, printers). Attackers have weaponized it for phishing — the "device code phishing" technique generates a real device code and tricks a user into entering it at `login.microsoftonline.com`. The user's session token is delivered to the attacker. Blocking this flow eliminates the attack surface without impacting any legitimate use case in most enterprise tenants.

**Principle mapping:** 1.1 Identity-wide coverage. Closing an authentication flow side channel.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["All"]` |
| Authentication flows | `transferMethods: "deviceCodeFlow"` |
| Client app types | `["all"]` |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`.

**Session controls:** None.

**License requirements:** Entra ID P1.

**Validation steps:** Before enforcement, inventory whether any legitimate workloads use device code flow (rare in modern enterprise environments; common only for IoT devices or headless automation that cannot open a browser). If legitimate use exists, those workloads must be migrated or excluded before enforcement.

**Exclusion rationale:** ServiceAccounts and WorkloadIdentities are excluded as a precaution; if they use device code flow, they should be investigated — this is unusual and potentially suspicious.

---

### 6.8 CA-COV005-Global-BlockAuthenticationTransfer

**Intent:** Block cross-device Authentication Transfer (`authenticationTransfer`). Authentication Transfer is an IETF draft protocol that allows an authentication started on one device to be completed on another device. This is a mechanism for token transfer across device boundaries and has a threat model similar to device code flow phishing. Blocking it prevents a class of cross-device token relay attacks.

**Principle mapping:** 1.1 Identity-wide coverage. Closing an authentication flow side channel.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["All"]` |
| Authentication flows | `transferMethods: "authenticationTransfer"` |
| Client app types | `["all"]` |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`.

**Session controls:** None.

**License requirements:** Entra ID P1.

**Validation steps:** Confirm no business-critical workflows depend on cross-device authentication transfer. This protocol is not widely deployed; blocking it is generally safe.

**Exclusion rationale:** Same as CA-COV004.

---

### 6.9 CA-COV006-Global-BlockUnknownPlatforms

**Intent:** Block sign-ins from device platforms outside the named set (android, iOS, windows, windowsPhone, macOS, linux). This catches sign-ins from spoofed, headless, or obsolete device platforms — browser automation frameworks, custom HTTP clients, test tools, and platforms not in the tenant's supported fleet. The pattern is deny-by-default: include all platforms, then explicitly exclude the approved set.

**Principle mapping:** 1.1 Identity-wide coverage. Enforcing a known, bounded device platform set.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["all"]` |
| Platforms | `includePlatforms: ["all"]`, `excludePlatforms: ["android", "iOS", "windows", "windowsPhone", "macOS", "linux"]` |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`.

**Session controls:** None.

**License requirements:** Entra ID P1.

**Validation steps:** In report-only, review `WouldBlock` for unexpected platform strings. A legacy `Windows Phone` platform string in the logs indicates an old client agent string that would be caught by this policy.

**Exclusion rationale:** ServiceAccounts and WorkloadIdentities may authenticate from platform-unknown infrastructure (cloud VMs, automation pipelines). Excluding them prevents disrupting legitimate automation.

---

### 6.10 CA-COV007-Global-BlockByLocation

**Intent:** Block sign-ins from locations outside the TrustedCountries named location set. This provides country-of-origin geofencing for the entire tenant's user population.

**Principle mapping:** 1.3 Layered signals. Location as a Conditional Access signal combined with universal user scope.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["all"]` |
| Locations | `includeLocations: ["All"]`, `excludeLocations: [REPLACE_WITH_TRUSTED_COUNTRIES_LOCATION_ID]` |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`.

**Session controls:** None.

**License requirements:** Entra ID P1. TrustedCountries named location must be provisioned and accurately populated before enforcement.

**Validation steps:**

1. Provision TrustedCountries from `Supporting-Artifacts/CA-LOCATION-TrustedCountries.json`.
2. Confirm the country list covers all legitimate user locations (business travel should be in scope or handled via Conditional Access Named Location policy for travel).
3. In report-only, check `WouldBlock` for users in countries that should be trusted.
4. After enforcement, notify remote users and travelers of the location enforcement.

**Exclusion rationale:** ServiceAccounts may authenticate from cloud-hosted infrastructure. WorkloadIdentities are on the CA-COV010 code path, not the user path.

---

### 6.11 CA-COV008-Internal-RequireCompliantDeviceOnDesktops

**Intent:** Require compliant device or hybrid Azure AD join for Internal users signing in from desktop platforms (Windows, macOS, Linux). Unmanaged desktop devices can exfiltrate tokens, store credentials in unencrypted browser profiles, and run malware. Device compliance is the strongest posture signal available at sign-in time; requiring it on desktop platforms closes the unmanaged-device gap for the internal user population.

**Principle mapping:** 1.3 Layered signals. Device compliance combined with platform scope and persona scope.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeGroups: [CA-Persona-InternalUsers]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["browser", "mobileAppsAndDesktopClients"]` |
| Platforms | `includePlatforms: ["windows", "macOS", "linux"]` |

**Grant control:** `builtInControls: ["compliantDevice", "domainJoinedDevice"]` with `operator: "OR"`. Either Intune compliance or hybrid Azure AD join satisfies the requirement.

**Session controls:** None.

**License requirements:** Entra ID P1. Microsoft Intune required for compliantDevice signal; hybrid Azure AD join is an accepted alternative.

**Validation steps:**

1. Run `Get-CABaselineImpact.ps1 -PolicyNameFilter 'CA-COV008' -Days 14`.
2. Review `WouldBlock` — these are Internal users on unmanaged desktop devices.
3. Prioritize Intune enrollment for all users in `WouldBlock` before enforcement.
4. After enforcement, monitor for blocked sign-ins from recently enrolled devices (enrollment lag).

**Exclusion rationale:** Mobile platforms (iOS, Android) are excluded at the platform condition level — this policy targets desktop posture. Mobile device compliance is a separate future policy.

---

### 6.12 CA-COV009-ServiceAccounts-BlockUntrustedLocations

**Intent:** Block service account sign-ins from locations outside the TrustedCountries named location set. This is the compensating control for the ServiceAccounts exclusion defined in CA-EXC002. Service accounts are excluded from all human-targeted policies, so this policy provides the only location-based enforcement for the ServiceAccounts persona.

**Principle mapping:** 1.1 Identity-wide coverage. Closing the coverage gap created by CA-EXC002 for the ServiceAccounts persona.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeGroups: [CA-Persona-ServiceAccounts]` — inverse of the exclusion pattern |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["all"]` |
| Locations | `includeLocations: ["All"]`, `excludeLocations: [REPLACE_WITH_TRUSTED_COUNTRIES_LOCATION_ID]` |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`. Service accounts cannot satisfy MFA or interactive controls; block is the only meaningful enforcement.

**Session controls:** None.

**License requirements:** Entra ID P1. ServiceAccounts group populated per CA-EXC002.

**Validation steps:**

1. Complete CA-EXC002 attestation before deploying CA-COV009.
2. Inventory service account sign-in geography from the prior 14 days.
3. Confirm that all expected sign-in geographies are within TrustedCountries.
4. In report-only, verify no `WouldBlock` results from expected source locations.

**Exclusion rationale:** WorkloadIdentities are excluded because they are on the CA-COV010 service-principal code path, not the user path.

---

### 6.13 CA-COV010-WorkloadIdentities-TrustedLocations

**Intent:** Restrict service-principal sign-ins to a defined trusted IP egress. Workload identities cannot satisfy MFA or interactive controls; the only available enforcement mechanism for service principals is location-based blocking. This policy closes the workload identity coverage gap.

**Principle mapping:** 1.1 Identity-wide coverage. Service-principal code path, separate from the user path.

**Scope:**

| Dimension | Value |
|---|---|
| Service principals | `includeServicePrincipals: ["ServicePrincipalsInMyTenant"]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["all"]` |
| Locations | `includeLocations: ["All"]`, `excludeLocations: [REPLACE_WITH_TRUSTED_IPS_LOCATION_ID]` — Note: this uses Trusted IPs (IP ranges), not TrustedCountries (country list). Workload identities authenticate from specific infrastructure; IP-range restriction is more precise than country filtering. |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`.

**Session controls:** None.

**License requirements:** Microsoft Entra Workload Identities Premium. Separate SKU from Entra ID P1/P2.

**Validation steps:** See full pre-flight and validation procedure in `Policies/CA-COV010-WorkloadIdentities.md`.

**Exclusion rationale:** This policy targets service principals exclusively via the `clientApplications` condition. No user group exclusions are needed.

---

### 6.14 CA-COV011-Agents-BlockMediumAndHighRisk

**Intent:** Block Agent ID authentication flows when Microsoft Identity Protection detects medium or high risk for the agent. This is the Conditional Access enforcement layer for the Microsoft Agent ID identity class — the only policy in the baseline that evaluates the `agentIdRiskLevels` condition.

**Principle mapping:** 1.1 Identity-wide coverage (Agents persona) and 1.3 Layered signals (agent identity + risk signal).

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["None"]` — Agents do not authenticate as users |
| Agent ID principals | `clientApplications.includeAgentIdServicePrincipals: ["All"]` |
| Applications | `includeApplications: ["AllAgentIdResources"]` |
| Client app types | `["all"]` |
| Agent risk | `agentIdRiskLevels: "medium,high"` |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`. Agent IDs cannot satisfy interactive grant controls.

**Session controls:** None.

**License requirements:** Microsoft Agent ID feature availability (requires Microsoft 365 Copilot or Azure AI Entra integration). Identity Protection for Agent IDs (Entra ID P2). Microsoft Graph beta endpoint (all Agent ID fields are beta-only as of May 2026).

**Validation steps:** See `Policies/CA-EXC003-Agents-Persona.md` and `Design/AGENTS-PERSONA-MODEL.md` section 5 for the full rollout recommendation.

**Exclusion rationale:** No user group exclusions are needed. The policy does not evaluate user authentication flows. See `Policies/CA-EXC003-Agents-Persona.md` for the full exclusion model.

---

### 6.15 CA-SIG001-SensitiveApps-RequireCompliantDevice

**Intent:** Require compliant device or hybrid Azure AD join for Internal users accessing Azure Service Management (`797f4846-ba00-4fd7-ba43-dac1f8f63013`). Azure Service Management is the highest-value sensitive application in most Microsoft 365 tenants — it controls Azure subscription access, resource provisioning, and policy changes. Requiring device compliance for this application ensures that Azure management operations cannot originate from unmanaged or compromised devices.

**Principle mapping:** 1.3 Layered signals. Application sensitivity combined with device compliance and persona scope.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeGroups: [CA-Persona-InternalUsers]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities]` |
| Applications | `includeApplications: ["797f4846-ba00-4fd7-ba43-dac1f8f63013"]` — Azure Service Management |
| Client app types | `["browser", "mobileAppsAndDesktopClients"]` |

**Grant control:** `builtInControls: ["compliantDevice", "domainJoinedDevice"]` with `operator: "OR"`.

**Session controls:** None.

**License requirements:** Entra ID P1. Microsoft Intune or hybrid Azure AD join.

**Validation steps:**

1. In report-only, run impact with `-PolicyNameFilter 'CA-SIG001'`.
2. Identify Internal users who access Azure Service Management from non-compliant devices.
3. Enroll those devices in Intune before enforcement.

**Exclusion rationale:** ServiceAccounts is not excluded from CA-SIG001 because ServiceAccounts should not have interactive Azure Service Management access; if they do, that warrants investigation. WorkloadIdentities is excluded as a precaution.

---

### 6.16 CA-SIG002-Guests-RequireMFA

**Intent:** Require MFA for every interactive guest sign-in across all applications. Guests are external users with B2B collaboration access; they do not inherit the tenant's baseline MFA policies unless explicitly targeted. This policy closes the gap.

**Principle mapping:** 1.1 Identity-wide coverage. Guest identity class coverage.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeGuestsOrExternalUsers` — covers internalGuest, b2bCollaborationGuest, b2bCollaborationMember, b2bDirectConnectUser, otherExternalUser, serviceProvider |
| External tenant scope | `membershipKind: "all"` |
| Exclusions | `excludeGroups: [EmergencyAccess]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["all"]` |

**Grant control:** `builtInControls: ["mfa"]` with `operator: "OR"`.

**Session controls:** None.

**License requirements:** Entra ID P1.

**Validation steps:**

1. Review guest MFA registration status in the Entra admin center.
2. In report-only, confirm that `WouldBlock` includes only guests who have never registered MFA — these need outreach before enforcement.
3. After enforcement, verify that a guest sign-in triggers an MFA prompt.

**Exclusion rationale:** Only EmergencyAccess is excluded. Guests who cannot satisfy MFA cannot access the tenant after enforcement; this is intentional.

---

### 6.17 CA-SIG003-Global-MediumUserRisk

**Intent:** Provide a graduated response to medium user risk: require StrongAuth (phishing-resistant: WHfB or FIDO2) combined with password change as a risk remediation step, and enforce sign-in frequency to `everyTime` so the re-authentication is required at every new token request. This stops the risk from compounding and gives the user a clear remediation path.

**Principle mapping:** 1.3 Layered signals (risk signal + auth strength + frequency), 1.4 Authentication Strengths (StrongAuth on risk).

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, ServiceAccounts, WorkloadIdentities]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["all"]` |
| Risk | `userRiskLevels: ["medium"]` |

**Grant control:** `authenticationStrength.id: REPLACE_WITH_STRONGAUTH_STRENGTH_ID`, `builtInControls: ["riskRemediation"]`, `operator: "AND"`. Both must be satisfied: a phishing-resistant credential AND the remediation step (password change).

**Session controls:** `signInFrequency.authenticationType: "primaryAndSecondaryAuthentication", frequencyInterval: "everyTime", isEnabled: true`. The `everyTime` interval is a Microsoft Graph beta-only value as of May 2026.

**License requirements:** Entra ID P2 (Identity Protection user risk). StrongAuth custom authentication strength must exist in the tenant.

**Validation steps:**

1. Provision StrongAuth from `Supporting-Artifacts/CA-AUTH-STRENGTH-StrongAuth.json`.
2. Verify Identity Protection is generating user risk signals.
3. In report-only, confirm that `WouldChallenge` entries correspond to users with medium user risk.
4. Before enforcement, confirm all user in scope have WHfB or FIDO2 registered, or are enrolled in a rollout that will complete before enforcement.

**Exclusion rationale:** ServiceAccounts cannot satisfy StrongAuth or password change; they are excluded. WorkloadIdentities are excluded as they are not users.

---

### 6.18 CA-SIG004-Global-MediumSignInRisk

**Intent:** Require StrongAuth when a sign-in triggers a medium sign-in risk detection, and enforce `signInFrequency: everyTime`. Unlike user risk (which persists until remediated), sign-in risk is session-specific. The StrongAuth requirement forces a phishing-resistant credential for the risky session; the `everyTime` frequency prevents token reuse until the risk resolves.

**Principle mapping:** 1.3 Layered signals (sign-in risk + auth strength + frequency), 1.4 Authentication Strengths.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["all"]` |
| Risk | `signInRiskLevels: ["medium"]` |

**Grant control:** `authenticationStrength.id: REPLACE_WITH_STRONGAUTH_STRENGTH_ID`, `operator: "OR"`. Note: operator is OR here (not AND), because sign-in risk does not require the additional `riskRemediation` step that user risk does. The auth strength alone satisfies the requirement.

**Session controls:** Same as CA-SIG003: `frequencyInterval: "everyTime"` (beta-only).

**License requirements:** Entra ID P2. StrongAuth custom authentication strength.

**Validation steps:** Same pattern as CA-SIG003. Confirm sign-in risk detections are active before enforcement.

**Exclusion rationale:** Same as CA-SIG003.

---

### 6.19 CA-SIG005-Admins-BlockMediumAndHighSignInRisk

**Intent:** Hard-block admin sign-ins when Identity Protection detects medium or high sign-in risk for a 14-role holder. Admin accounts in risk-flagged sessions do not receive a re-challenge path — blocking is the only appropriate response because an admin credential being used in a risky session indicates a high likelihood of compromise.

**Principle mapping:** 1.3 Layered signals (sign-in risk + admin scope). Intentionally stricter than the Global medium sign-in risk policy because of the elevated blast radius of admin credential misuse.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeRoles: [14 privileged directory role template IDs]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["all"]` |
| Risk | `signInRiskLevels: ["high", "medium"]` |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`. No re-challenge path; the session is hard-blocked.

**Session controls:** None.

**License requirements:** Entra ID P2 (Identity Protection sign-in risk).

**Validation steps:** Verify that all 14-role holders are aware that any sign-in flagged at medium or high risk will be blocked without a challenge option. Establish a process for admins to contact security operations if they are unexpectedly blocked during a legitimate session.

**Exclusion rationale:** EmergencyAccess may need to be excluded if the emergency sign-in itself triggers a risk detection. This is a risk acceptance; document in CA-EXC001.

---

### 6.20 CA-SIG006-Guests-BlockNonGuestAppAccess

**Intent:** Block guest sign-ins to any application outside the Microsoft 365 collaboration set. A B2B guest token issued for collaboration (Teams, SharePoint, Exchange Online) should not be usable against unrelated registered applications in the tenant. This policy enforces the principle that guests have access to collaboration tools and nothing else unless explicitly granted.

**Principle mapping:** 1.2 No standing exclusions (preventing guest tokens from spanning the tenant's full app surface), 1.3 Layered signals (user type + application scope).

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeGroups: [CA-Persona-Guests]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["All"]`, `excludeApplications: ["Office365"]` |
| Client app types | `["all"]` |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`. Any guest sign-in to a non-Office365 application is blocked.

**Session controls:** None.

**License requirements:** Entra ID P1.

**Validation steps:** Before enforcement, review guest sign-in logs for applications outside the Office365 bundle. If guests legitimately access line-of-business applications, add those application IDs to `excludeApplications` before enforcement.

**Exclusion rationale:** WorkloadIdentities and ServiceAccounts are excluded because they are not guest users; the `includeGroups` condition already limits scope to the Guests persona.

---

### 6.21 CA-SIG007-Internal-TokenProtection

**Intent:** Enable Token Protection (`secureSignInSession: isEnabled: true`) for Internal users on Windows devices accessing the Office365 application bundle. Token Protection cryptographically binds the refresh token and PRT to the issuing device's TPM key. A stolen token cannot be replayed from attacker infrastructure.

**Principle mapping:** 1.3 Layered signals. Application scope (Office365) + platform scope (Windows) + persona scope (Internal) + session control (token binding).

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeGroups: [CA-Persona-InternalUsers]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities, ServiceAccounts]` |
| Applications | `includeApplications: ["Office365"]` — Exchange Online + SharePoint Online sign-in paths |
| Client app types | `["all"]` |
| Platforms | `includePlatforms: ["windows"]` — macOS, iOS, Android do not yet issue device-bound tokens |

**Grant control:** None — Token Protection is a session control, not a grant control.

**Session controls:** `secureSignInSession.isEnabled: true`.

**License requirements:** Entra ID P1. Windows 10/11 with TPM. Modern auth clients. See `Policies/CA-SIG007-Internal-TokenProtection.md` for full coverage seam documentation.

**Validation steps:** See `Policies/CA-SIG007-Internal-TokenProtection.md` section 6 for the full 14-day validation procedure.

**Exclusion rationale:** Non-Windows platforms are excluded at the platform condition level. ServiceAccounts and WorkloadIdentities do not authenticate as Internal users on Windows devices.

---

### 6.22 CA-SIG008-AllUsers-BlockHighUserRisk

**Intent:** Hard-block all sign-ins when Identity Protection detects high user risk. High user risk indicates a strong likelihood of account compromise (credential leak, confirmed attack, high-confidence anomaly). At high risk, there is no safe re-challenge path — the account must be blocked until the risk is remediated.

**Principle mapping:** 1.3 Layered signals (user risk). Zero-tolerance high-risk response.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities]` — ServiceAccounts is not excluded; a high-risk service account warrants immediate investigation |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["all"]` |
| Risk | `userRiskLevels: ["high"]` |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`.

**Session controls:** None.

**License requirements:** Entra ID P2 (Identity Protection user risk).

**Validation steps:** Establish a risk dismissal process in Identity Protection before enforcement. When CA-SIG008 blocks a user, the security operations team must review the risk detection and either remediate (password reset, investigate) or dismiss (false positive).

**Exclusion rationale:** ServiceAccounts intentionally remain in scope; a high-risk service account signals a potential credential theft or lateral movement event and should be blocked pending investigation.

---

### 6.23 CA-SIG009-AllUsers-BlockHighSignInRisk

**Intent:** Hard-block all sign-ins when Identity Protection detects high sign-in risk. High sign-in risk at the session level — impossible travel, mass sign-in attacks, anomalous infrastructure — warrants an immediate hard block with no re-challenge path.

**Principle mapping:** 1.3 Layered signals. Zero-tolerance high-risk response for sign-in signals.

**Scope:**

| Dimension | Value |
|---|---|
| Users | `includeUsers: ["All"]` |
| Exclusions | `excludeGroups: [EmergencyAccess, WorkloadIdentities]` |
| Applications | `includeApplications: ["All"]` |
| Client app types | `["all"]` |
| Risk | `signInRiskLevels: ["high"]` |

**Grant control:** `builtInControls: ["block"]` with `operator: "OR"`.

**Session controls:** None.

**License requirements:** Entra ID P2 (Identity Protection sign-in risk).

**Validation steps:** Same risk dismissal process as CA-SIG008. Test by reviewing sign-in logs for any high sign-in risk events before enforcement.

**Exclusion rationale:** WorkloadIdentities are excluded because service principals surface via `servicePrincipalRiskLevels`, not `signInRiskLevels`. ServiceAccounts remain in scope for the same reason as CA-SIG008.
