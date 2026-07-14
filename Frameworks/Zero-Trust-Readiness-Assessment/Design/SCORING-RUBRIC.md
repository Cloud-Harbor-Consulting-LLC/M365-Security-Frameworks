# ZTRA Scoring Rubric

**Framework:** Zero Trust Readiness Assessment Framework (ZTRA)  
**Maturity scale:** CISA ZTMM v2.0 (April 2023) — 4 stages  
**Control citations:** NIST SP 800-207 tenets T1–T7  
**Pillar weighting:** Equal (16.67% per pillar) — aligned with CISA ZTMM v2.0 horizontal progress design

---

## How to score

1. Work through each pillar section below.
2. For each control, read the stage descriptions and identify which best matches your tenant's current configuration.
3. Assign the control a stage score (1–4).
4. Compute the **pillar stage** as the median of all control scores within that pillar. Round down on ties.
5. Compute the **overall tenant stage** as the median of the 6 pillar scores. Round down on ties.

This rubric is usable without the collector script. The collector script (`Scripts/Get-ZTReadinessScore.ps1`) automates evidence gathering for the M365 Signal field of each control.

---

## Maturity stage definitions

| Stage | Label | Summary |
|---|---|---|
| 1 | Traditional | Manual configurations, static policies, no cross-pillar visibility. Reactive posture. |
| 2 | Initial | Automation starting. Some cross-pillar telemetry. Initial risk-based access decisions emerging. Some lifecycle management still manual. |
| 3 | Advanced | Automated lifecycles. Centralized visibility and analytics. Dynamic risk-based access decisions. Cross-pillar integration active. |
| 4 | Optimal | Fully automated JIT and dynamic least privilege. Continuous monitoring with automated response. Complete cross-pillar integration. Policy updated continuously from live telemetry. |

---

## NIST SP 800-207 tenet reference

| ID | Tenet |
|---|---|
| T1 | All data sources and computing services are considered resources |
| T2 | All communication is secured regardless of network location |
| T3 | Access to individual enterprise resources is granted on a per-session basis |
| T4 | Access to resources is determined by dynamic policy |
| T5 | The enterprise monitors and measures the integrity and security posture of all owned assets |
| T6 | All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| T7 | The enterprise collects as much information as possible about assets and uses it to improve its security posture |

---

## Pillar 1 — Identities

*CISA ZTMM v2.0 equivalent: Identity*

### ID-01: MFA enrollment and coverage

**NIST Tenets:** T4, T6  
**Repo X-Ref:** CA-COV001–009, CA-SIG001

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No MFA policy. Users authenticate with password only. Legacy authentication enabled org-wide. |
| 2 — Initial | MFA enabled via Security Defaults or per-user MFA. CA policies not enforcing MFA for all users. Some legacy authentication still permitted. |
| 3 — Advanced | CA policies enforce MFA for all users via a coverage set in enforced mode. Legacy authentication blocked via CA. |
| 4 — Optimal | Phishing-resistant MFA (FIDO2 / Windows Hello for Business) enforced for all users. Passwordless is the primary authentication method. Per-session reauthentication enforced for sensitive resources. |

**M365 Signal:** CA policy set includes a legacy auth block policy and MFA grant-control policies covering all users. Check `conditions.clientAppTypes` for legacy auth block and `grantControls.builtInControls` for `mfa` or `authenticationStrength` on coverage policies.

---

### ID-02: Admin MFA and privileged identity protection

**NIST Tenets:** T3, T4, T6  
**Repo X-Ref:** CA-AUT001–003, CA-SIG005

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Admins use the same MFA (or no MFA) as regular users. No separation of admin sign-in treatment. Admin roles permanently assigned. |
| 2 — Initial | Admin MFA required but not phishing-resistant. No risk-based CA for admin personas. PIM licensed but few or no eligible assignments. |
| 3 — Advanced | Phishing-resistant MFA enforced for admins via dedicated CA policy. Sign-in risk CA targets admin personas. PIM deployed with eligible assignments for most admin roles. |
| 4 — Optimal | All admin roles in PIM eligible — zero permanent assignments except break-glass. JIT activation requires approval and justification. Dedicated admin accounts separate from daily-use accounts. Real-time risk response automated. |

**M365 Signal:** CA policy targeting admin role set with phishing-resistant auth strength in enforced mode. PIM eligible assignment count via `GET /roleManagement/directory/roleEligibilityScheduleInstances`; permanent standing assignment count via `GET /roleManagement/directory/roleAssignmentScheduleInstances` filtered to `assignmentType eq 'Assigned'` with a null `endDateTime`.

---

### ID-03: Block legacy authentication

**NIST Tenets:** T2, T6  
**Repo X-Ref:** CA-SIG001

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Legacy authentication (Basic Auth, Exchange ActiveSync, NTLM via proxy) permitted without restriction. No CA policy targeting legacy clients. |
| 2 — Initial | CA policy targets legacy authentication in report-only mode. Some legacy protocols disabled at the app level (e.g., SMTP AUTH on mailboxes). |
| 3 — Advanced | CA policy blocking legacy authentication is in enforced mode. Monitoring in place for legacy auth sign-in attempts. |
| 4 — Optimal | Legacy authentication blocked at the CA layer and disabled at the protocol and app layer. Zero successful legacy auth sign-ins in logs. Automated alert on any legacy auth attempt. |

**M365 Signal:** CA policy with `conditions.clientAppTypes: ['exchangeActiveSync', 'other']` and `grantControls.operator: 'OR'` / `builtInControls: ['block']` in enforced mode. Sign-in log legacy auth success rate via `GET /auditLogs/signIns`.

---

### ID-04: Sign-in risk — CA enforcement

**NIST Tenets:** T4, T5, T7  
**Repo X-Ref:** CA-SIG005–007

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No risk-based CA. Sign-in risk scores generated by Entra ID Protection but not acted on. |
| 2 — Initial | Entra ID Protection licensed and sign-in risk scores generated. Risk-based CA policy exists but in report-only mode. |
| 3 — Advanced | Sign-in risk CA in enforced mode for medium and high risk. MFA step-up automated for medium risk. High-risk sign-ins blocked or require immediate remediation. |
| 4 — Optimal | All risk levels addressed via CA. Risk signals from Defender for Identity and third-party feeds integrated. Real-time risk score acts on sign-ins continuously. Automated remediation for confirmed compromises. |

**M365 Signal:** CA policies with `conditions.signInRiskLevels` targeting medium and high in enforced mode. Entra ID Protection risky sign-in count and remediation rate.

---

### ID-05: User risk — CA enforcement

**NIST Tenets:** T4, T5, T7  
**Repo X-Ref:** CA-SIG008–010

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No user risk policy. Compromised accounts not automatically remediated. Risky users identified manually if at all. |
| 2 — Initial | User risk CA policy exists in report-only or targeting high risk only. SSPR not required as a remediation grant. |
| 3 — Advanced | User risk CA in enforced mode for high risk (block or require password change). Medium-risk users challenged with MFA. SSPR registration enforced. |
| 4 — Optimal | All user risk levels addressed via CA. Self-service password reset integrated as CA grant control for medium risk. SSPR coverage for all users. Risky user remediation automated — zero confirmed compromised accounts left unaddressed. |

**M365 Signal:** CA policies with `conditions.userRiskLevels` in enforced mode. SSPR registration rate via `GET /reports/authenticationMethods/userRegistrationDetails`. Risky user count via `GET /identityProtection/riskyUsers`.

---

### ID-06: Privileged identity management — JIT access

**NIST Tenets:** T3, T4, T5  
**Repo X-Ref:** EIG-AR002

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Admin roles permanently assigned. No activation workflow. No audit trail for privileged role use beyond basic audit logs. |
| 2 — Initial | PIM licensed. Some eligible assignments created but permanent assignments still dominate for most roles. Activation requires justification but no approval. |
| 3 — Advanced | Majority of admin roles eligible via PIM. Activation requires approval for high-impact roles (Global Admin, Privileged Role Admin, Security Admin). PIM audit logs reviewed regularly. Emergency access accounts exist and are monitored. |
| 4 — Optimal | Zero permanent admin assignments except documented break-glass accounts. All role activations time-limited. Activation triggers automated alert. PIM access reviews run on all eligible assignments. Break-glass account usage monitored continuously. |

**M365 Signal:** `GET /roleManagement/directory/roleEligibilityScheduleInstances` and `GET /roleManagement/directory/roleAssignmentScheduleInstances` — eligible vs. permanent standing assignment ratio (permanent = `assignmentType eq 'Assigned'` with null `endDateTime`). PIM role settings requiring approval via `GET /policies/roleManagementPolicyAssignments`.

---

### ID-07: External identity lifecycle governance

**NIST Tenets:** T4, T5  
**Repo X-Ref:** EIG-AR001

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Guest accounts created ad hoc with no lifecycle management. Stale guests accumulate. No restriction on who can invite guests. |
| 2 — Initial | Guest invitation policy restricts who can invite (not all users). Guest accounts reviewed manually on an ad hoc basis. No automated review schedule. |
| 3 — Advanced | Access reviews scheduled and run for guest accounts. Inactive guests flagged and removed. Entitlement management controls which resources guests can access. |
| 4 — Optimal | Access reviews automated and run at least quarterly. Guests auto-removed on review denial. Guest lifecycle tied to sponsoring user status. Entitlement management governs all external access with time-limited access packages. |

**M365 Signal:** Entra ID guest invitation policy (`GET /policies/authorizationPolicy`). Entra ID Governance access review policies for guest accounts (`GET /identityGovernance/accessReviews/definitions`). Inactive guest count (last sign-in > 90 days).

---

### ID-08: SSO coverage for sanctioned applications

**NIST Tenets:** T3, T6  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Applications use separate credentials. No SSO. Password sharing and app passwords common. |
| 2 — Initial | SSO deployed for Microsoft 365 native apps. Third-party app SSO partial. App passwords still permitted for some apps. |
| 3 — Advanced | SSO via SAML or OIDC deployed for all sanctioned third-party apps registered in Entra ID app gallery. App passwords disabled. All user-facing apps authenticate through Entra ID. |
| 4 — Optimal | SSO covers all sanctioned apps including on-premises apps (Entra Application Proxy or Global Secure Access). App inventory complete. All apps without SSO are identified and on a remediation roadmap with target dates. |

**M365 Signal:** `GET /servicePrincipals` — enterprise app count with SSO configured (`preferredSingleSignOnMode` not null). App password policy state. Application Proxy connector count.

---

## Pillar 2 — Endpoints

*CISA ZTMM v2.0 equivalent: Devices*

### EP-01: Device registration with cloud identity

**NIST Tenets:** T1, T5  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Devices domain-joined only (on-premises AD). No Entra ID join or registration. Device identity not available as a CA signal. |
| 2 — Initial | Corporate devices Entra Hybrid Joined or Entra Joined. BYOD devices not registered. Device inventory incomplete in Entra ID. |
| 3 — Advanced | All corporate devices Entra Joined or Hybrid Joined. BYOD devices Entra registered with Intune enrollment. Device inventory near-complete. |
| 4 — Optimal | All corporate and BYOD devices registered. Device registration required before first access to corporate resources. Unknown device access blocked at CA layer. Stale device records cleaned up automatically on a schedule. |

**M365 Signal:** `GET /devices` — registered device count, join type distribution (`azureADJoined`, `hybridAzureADJoined`, `registered`). Stale device count (approximate last activity > 90 days).

---

### EP-02: Device compliance policies

**NIST Tenets:** T4, T5  
**Repo X-Ref:** Intune Compliance Baseline (when deployed)

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No Intune compliance policies. Device health not assessed. No compliance baseline applied to any platform. |
| 2 — Initial | Intune deployed. Compliance policies exist for at least one platform (Windows). Noncompliant devices not blocked — CA not integrated with compliance state. |
| 3 — Advanced | Compliance policies deployed for all managed platforms (Windows, macOS, iOS, Android). Noncompliant devices trigger remediation notifications and actions. Compliance baselines applied. |
| 4 — Optimal | Compliance policies cover all platforms and device types (corporate and BYOD). Compliance state enforced via CA. Remediation automated where Intune supports it. Compliance posture reviewed and tuned regularly. |

**M365 Signal:** `GET /deviceManagement/deviceCompliancePolicies` — policy count and platform coverage. Noncompliant device percentage across enrolled device population.

---

### EP-03: CA enforcement of device compliance

**NIST Tenets:** T3, T4, T6  
**Repo X-Ref:** CA-AUT003

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No CA policy requiring a compliant device. Any registered or unregistered device can access corporate resources. |
| 2 — Initial | CA policy requiring compliant device exists in report-only. Compliant device required for a subset of apps only. |
| 3 — Advanced | CA requires compliant device for all corporate app access. Report-only graduated to enforced mode for the majority of the user population. |
| 4 — Optimal | Compliant device required for all resource access. No exceptions except documented break-glass. Compliance posture is a continuous per-session CA signal. Non-compliant devices receive guided remediation. |

**M365 Signal:** CA policies with `grantControls.builtInControls: ['compliantDevice']` in enforced mode. App target coverage of the compliant-device policy set.

---

### EP-04: App protection policies (BYOD / MAM)

**NIST Tenets:** T1, T4  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No Intune app protection policies. Corporate data accessible in unmanaged apps. No restriction on copy-paste between corporate and personal apps. |
| 2 — Initial | App protection policies deployed for Microsoft 365 mobile apps on iOS and Android (MAM-WE). PIN required for app access. No coverage for Windows or macOS. |
| 3 — Advanced | App protection policies cover all supported platforms and corporate apps. Data transfer restrictions enforced between managed and unmanaged apps. Selective wipe capability on unenrollment. |
| 4 — Optimal | App protection policies cover all platforms including MAM for unenrolled devices. Policy targets all corporate apps — not only M365 first-party apps. Remote selective wipe tested and documented. Data can be wiped from any managed app without wiping the device. |

**M365 Signal:** `GET /deviceAppManagement/managedAppPolicies` — policy count and platform coverage. Assignment coverage across users and apps.

---

### EP-05: Security baselines and configuration enforcement

**NIST Tenets:** T5, T7  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No security baselines applied. Devices configured manually with inconsistent settings. No visibility into configuration drift. |
| 2 — Initial | Intune security baselines deployed for Windows (MDM Security Baseline or Microsoft 365 Apps baseline). Partial coverage of device population. No active drift monitoring. |
| 3 — Advanced | Security baselines deployed and enforced for Windows and macOS. Configuration compliance monitored via Intune. Drift detected and triggers remediation. |
| 4 — Optimal | Security baselines cover all managed platforms. Baseline compliance monitored in real time. Configuration drift auto-remediated where Intune supports it. CIS or Microsoft security benchmark applied and tracked against a defined target compliance rate. |

**M365 Signal:** `GET /deviceManagement/templates` — baseline profile deployment count. `GET /deviceManagement/deviceConfigurationDeviceStatuses` — configuration compliance rate per platform.

---

### EP-06: Device encryption

**NIST Tenets:** T1, T2  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Disk encryption not enforced on managed devices. Corporate data at rest on endpoints unprotected. |
| 2 — Initial | BitLocker enforced on corporate Windows devices via Intune. Recovery keys escrowed to Entra ID. macOS, iOS, and Android not covered by policy. |
| 3 — Advanced | Encryption enforced via Intune for all managed platforms (Windows BitLocker, macOS FileVault, iOS and Android device encryption). Recovery key escrow centralized. |
| 4 — Optimal | Encryption enforced on all corporate and BYOD devices as a compliance requirement. Encryption compliance is a CA enforcement signal. Encryption key management centralized and audited. Personal Data Encryption deployed for Windows high-sensitivity data. |

**M365 Signal:** `GET /deviceManagement/deviceCompliancePolicies` — BitLocker and FileVault requirements per policy. Device encryption compliance rate across enrolled population.

---

### EP-07: Endpoint threat detection

**NIST Tenets:** T5, T7  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No EDR deployed. Signature-based antivirus only. No visibility into endpoint-level behavioral threats. |
| 2 — Initial | Microsoft Defender for Endpoint deployed on Windows devices. Basic threat detection active. No integration with Intune or CA. |
| 3 — Advanced | Defender for Endpoint deployed on all managed platforms. MDE-Intune integration active — device risk level flows into Intune compliance state. CA blocks access for devices at high risk. |
| 4 — Optimal | Defender for Endpoint covers all platforms. Device risk level is a real-time CA signal. Threat response automated (isolate, remediate). SOC integration via Microsoft Sentinel. IoT/OT coverage via Defender for IoT where applicable. |

**M365 Signal:** `GET /deviceManagement/managedDevices` — Defender onboarding state and device risk level distribution. MDE-Intune connector state. Sentinel workspace with MDE data connector active.

---

## Pillar 3 — Applications

*CISA ZTMM v2.0 equivalent: Applications & Workloads (partial)*

### AP-01: Shadow IT discovery

**NIST Tenets:** T5, T7  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No visibility into non-sanctioned app usage. Cloud Discovery not configured. Unknown apps in use across the organization. |
| 2 — Initial | Defender for Cloud Apps licensed. Cloud Discovery configured with at least one log source (firewall or MDE integration). Discovery running but app usage not actively reviewed or actioned. |
| 3 — Advanced | Cloud Discovery active with MDE integration for continuous endpoint-based discovery. Discovered app usage reviewed regularly. Risk scoring applied. Unsanctioned high-risk apps blocked at proxy or endpoint. |
| 4 — Optimal | Continuous app discovery via MDE covering all managed endpoints. All discovered apps reviewed and classified (sanctioned, monitored, or unsanctioned). Unsanctioned apps automatically blocked. New app discoveries alert the SOC in real time. |

**M365 Signal:** Defender for Cloud Apps Cloud Discovery configuration state. MDE stream integration status. Discovered app count and classification rate.

---

### AP-02: OAuth consent governance

**NIST Tenets:** T4, T5  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | OAuth consent unrestricted — users can grant consent to any app requesting any permission. No visibility into OAuth grants. Risky OAuth grants not reviewed. |
| 2 — Initial | Admin consent workflow enabled for high-risk permission scopes. OAuth app review performed ad hoc. Admin consent required for some permissions. |
| 3 — Advanced | Admin consent required for all apps requesting sensitive permissions. OAuth app permission review scheduled. Risky OAuth grants revoked. App inventory of high-privilege grants maintained. |
| 4 — Optimal | Consent policies block risky permission scopes automatically. OAuth app anomaly detection active in Defender for Cloud Apps. Risky grants trigger automated alert and revocation workflow. Zero unreviewed high-privilege OAuth grants. |

**M365 Signal:** Entra ID admin consent policy configuration (`GET /policies/adminConsentRequestPolicy`). `GET /oauth2PermissionGrants` — high-privilege OAuth grant count. Defender for Cloud Apps OAuth app governance state.

---

### AP-03: Conditional Access App Control (session controls)

**NIST Tenets:** T3, T4  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No session-level controls. Once authenticated, users have unrestricted app access for the full session duration regardless of risk changes. |
| 2 — Initial | CAAC deployed for one or more critical apps via Defender for Cloud Apps. Basic session policies (block download on unmanaged device) for those apps. |
| 3 — Advanced | CAAC deployed for all critical and sensitive apps. Session policies enforce data protection on unmanaged devices (no download, no copy-paste, content inspection). Real-time session monitoring active. |
| 4 — Optimal | CAAC covers all user-facing apps including connected third-party SaaS. Session controls dynamically adapt based on device compliance and user risk. Session anomalies trigger real-time response. |

**M365 Signal:** CA policies with `sessionControls.cloudAppSecurity` configured. Defender for Cloud Apps — connected app count with session control active.

---

### AP-04: Application DLP

**NIST Tenets:** T4, T5  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No DLP policies across M365 services. Sensitive data sharable via Teams, SharePoint, OneDrive, and email without restriction. |
| 2 — Initial | DLP policies deployed for Exchange email (audit mode). SharePoint and OneDrive not covered or in audit-only mode. |
| 3 — Advanced | DLP policies in enforced mode across Exchange, SharePoint, OneDrive, and Teams. Policies aligned to sensitivity label taxonomy. DLP alerts reviewed and tuned. |
| 4 — Optimal | DLP coverage includes non-Microsoft cloud apps via Defender for Cloud Apps integration. Endpoint DLP covers Windows 10/11 and macOS. Policies auto-enforce based on sensitivity label. DLP alerts feed Insider Risk Management correlation. |

**M365 Signal:** Microsoft Purview DLP policy count and mode (audit vs. enforce) per workload. Endpoint DLP policy deployment state. DLP policy match count in last 30 days.

---

### AP-05: UEBA and anomaly detection

**NIST Tenets:** T5, T7  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No behavioral analytics. Threats detected only through signature-based rules. No baseline of normal user or app behavior. |
| 2 — Initial | Defender for Cloud Apps anomaly detection policies enabled with default settings. Alerts exist but are reviewed manually and reactively. |
| 3 — Advanced | UEBA active in Defender for Cloud Apps. Anomaly detection policies tuned. Alerts integrated into SOC triage workflow. Impossible travel, suspicious inbox rules, and risky OAuth policies all active and enforced. |
| 4 — Optimal | Full UEBA coverage via Defender for Cloud Apps and Microsoft Sentinel. ML-based behavioral baselines established. Automated response playbooks triggered on high-confidence anomalies. Cross-pillar signal correlation (identity + app + endpoint). |

**M365 Signal:** Defender for Cloud Apps anomaly detection policy count and enablement state. UEBA enrollment state. Sentinel data connector for Defender for Cloud Apps active.

---

### AP-06: App-level access permissions and entitlement governance

**NIST Tenets:** T3, T4  
**Repo X-Ref:** EIG-AR001, EIG-AR002

| Stage | Configuration state |
|---|---|
| 1 — Traditional | App permissions not reviewed. Users have excessive permissions (Owner, Full Control) across SharePoint, Teams, and Exchange. No entitlement review for app access. |
| 2 — Initial | App role assignments reviewed ad hoc. Some apps have defined access policies. SharePoint site permissions reviewed occasionally. |
| 3 — Advanced | App access permissions scoped to least privilege by default. Entitlement Management controls which apps users can request access to. Access package policies define who gets access and under what conditions. |
| 4 — Optimal | All sanctioned app access governed via Entitlement Management or scoped RBAC. Zero standing access to sensitive apps where Entitlement Management supports it. Access package lifecycle managed end-to-end. Periodic access reviews confirm continued need. |

**M365 Signal:** `GET /identityGovernance/entitlementManagement/accessPackages` — access package count. Access review definitions for app-level access. SharePoint site external sharing state.

---

## Pillar 4 — Data

*CISA ZTMM v2.0 equivalent: Data*

### DA-01: Data classification framework and sensitivity label taxonomy

**NIST Tenets:** T1, T5  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No data classification. No sensitivity labels. Data protection relies entirely on perimeter and access controls. |
| 2 — Initial | Sensitivity label taxonomy defined and labels configured in Microsoft Purview. Labels available but not yet deployed via policy. No auto-labeling. |
| 3 — Advanced | Sensitivity labels published and available to users across Office apps. Auto-labeling configured for known sensitive information types. Labels applied to the majority of documents in SharePoint and OneDrive. |
| 4 — Optimal | Labels cover all data classifications (Public, Internal, Confidential, Highly Confidential). Mandatory labeling enforced for Office apps and email. Auto-labeling covers all supported workloads. Label coverage metrics tracked continuously. |

**M365 Signal:** `GET /informationProtection/sensitivityLabels` — label count and policy publication state. Auto-labeling policy count and workload coverage. Purview Content Explorer — labeled item percentage.

---

### DA-02: Information protection — encryption and rights management

**NIST Tenets:** T1, T2, T4  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No encryption applied to corporate documents at rest. Sensitive files stored and shared without protection. Rights management not in use. |
| 2 — Initial | Sensitivity labels configured with encryption for the highest classification level (Highly Confidential). Encryption applied manually to select documents only. |
| 3 — Advanced | Encryption enforced automatically via sensitivity labels for Confidential and above. Rights management controls (view-only, no-print, no-forward) applied consistently. Encryption persists when data leaves M365. |
| 4 — Optimal | All sensitive data encrypted with label-enforced encryption. Co-authoring and AIP-enlightened app support in place. Encryption key management centralized. Revocation capability documented and tested. |

**M365 Signal:** Sensitivity label policies with encryption configured. Purview Information Protection scanner deployment state. Label analytics — percentage of documents with encryption-enforcing labels applied.

---

### DA-03: Container-level data protection (Teams, M365 Groups, SharePoint)

**NIST Tenets:** T3, T4  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Teams, M365 Groups, and SharePoint sites created with default permissions. External sharing unrestricted at the tenant level. No container-level classification. |
| 2 — Initial | External sharing restricted at the tenant level. Sensitivity labels applied to some Teams and SharePoint sites (container labels). Guest access reviewed ad hoc. |
| 3 — Advanced | Container sensitivity labels mandatory for all new Teams and SharePoint sites. External sharing policies enforced per label. CA app-enforced restrictions active for SharePoint. |
| 4 — Optimal | All Teams, M365 Groups, and SharePoint sites have a container label applied. External sharing dynamically controlled by label. New site creation gated by label application. Access reviews enforced on all high-sensitivity containers on a regular schedule. |

**M365 Signal:** Container label deployment state via Microsoft Purview. Tenant external sharing setting (`GET /admin/sharepoint/settings`). Teams creation policy — label required flag.

---

### DA-04: Data Loss Prevention policy coverage and maturity

**NIST Tenets:** T4, T5  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No DLP policies. No visibility into sensitive data movement or external sharing. |
| 2 — Initial | DLP policies deployed for Exchange in audit mode. Sensitive information types defined. No enforcement across SharePoint, OneDrive, or Teams. |
| 3 — Advanced | DLP policies in enforced mode across Exchange, SharePoint, OneDrive, Teams, and Windows endpoints. Policies aligned to the sensitivity label taxonomy. DLP alerts integrated into compliance workflows. |
| 4 — Optimal | DLP coverage includes non-Microsoft cloud apps (Defender for Cloud Apps). Endpoint DLP covers Windows 10/11 and macOS. Policy tuning ongoing — false positive rate actively managed. DLP alerts feed Insider Risk Management correlation signals. |

**M365 Signal:** Microsoft Purview DLP policy count and mode per workload. Endpoint DLP policy deployment state. DLP alert volume and false-positive review state.

---

### DA-05: Insider Risk Management

**NIST Tenets:** T5, T7  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No insider risk program. Data exfiltration by insiders not detectable until after a breach occurs. |
| 2 — Initial | Microsoft Purview Insider Risk Management (IRM) licensed. IRM policies created but not tuned. No integration with HR data sources or DLP signals. |
| 3 — Advanced | IRM policies active for high-risk scenarios (data theft by departing employees, general data leaks). Alerts reviewed by designated reviewers. IRM cases managed within the Purview compliance portal. |
| 4 — Optimal | IRM policies cover all major risk scenarios. HR connector feeds resignation and termination events as risk indicators. DLP and Defender XDR signals correlated in IRM. Investigation workflow semi-automated. Privacy protection controls in place for all investigative data. |

**M365 Signal:** Microsoft Purview IRM policy count and enablement state. Active alert count. HR data connector configuration state.

---

### DA-06: Data lifecycle and records management

**NIST Tenets:** T5  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No retention policies. Data retained indefinitely or deleted inconsistently. No records management program. |
| 2 — Initial | M365 retention policies applied to Exchange and Teams. No SharePoint or OneDrive coverage. No records management. |
| 3 — Advanced | Retention policies cover all M365 workloads. Retention labels deployed for records. Disposition reviews scheduled. Sensitive data minimized when no longer needed per policy. |
| 4 — Optimal | Complete data lifecycle management. Retention labels auto-applied to sensitive records. Disposition review automated where supported. Regulatory compliance labels (GDPR, SEC, FINRA as applicable) deployed. Data minimization reduces sensitive data exposure continuously. |

**M365 Signal:** Microsoft Purview retention policy count and workload coverage. Records management label count. Disposition review schedule and completion rate.

---

### DA-07: Data discovery and content inventory

**NIST Tenets:** T1, T5  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No data inventory. Sensitive data location unknown. Discovery performed only in response to a specific legal or compliance event. |
| 2 — Initial | Microsoft Purview Content Search used ad hoc. Some sensitive information types defined. No automated or continuous discovery across the data estate. |
| 3 — Advanced | Microsoft Purview Content Explorer active. Sensitive data discovered and inventoried across Exchange, SharePoint, OneDrive, and Teams. Data estate partially classified with coverage tracked. |
| 4 — Optimal | Continuous data discovery across all M365 workloads. Content Explorer provides a real-time view of sensitive data by label and location. On-premises scanner deployed for file shares. Data estate classified to above 80% coverage across all workloads. |

**M365 Signal:** Microsoft Purview Content Explorer — labeled item count by workload. Sensitive information type match count. On-premises scanner deployment and scan schedule state.

---

## Pillar 5 — Infrastructure

*CISA ZTMM v2.0 equivalent: Applications & Workloads (partial)*

> **Scope note:** This pillar includes Azure-scoped controls. For organizations running M365-only with minimal Azure footprint, several controls in this pillar may have limited applicability or may be scored at Stage 1 by default. The collector script surfaces what is available via Microsoft Graph; controls requiring Azure Management API signals are marked.

### IN-01: JIT privileged access for Azure resource roles

**NIST Tenets:** T3, T4, T5  
**Repo X-Ref:** EIG-AR002

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Azure resource roles permanently assigned. No JIT. Owner and Contributor access granted broadly at the subscription level. |
| 2 — Initial | Entra PIM deployed for Entra directory roles. Azure resource roles not yet in PIM or only partially covered. Some eligible assignments for directory roles. |
| 3 — Advanced | PIM covers both Entra directory roles and Azure resource roles for key subscriptions. Activation requires justification and MFA. High-impact role activations require approval. Time-bound access enforced. |
| 4 — Optimal | Zero permanent assignments for Azure resource roles except documented break-glass. All activations time-limited. Activation triggers automated alert. Azure resource role usage audited continuously. Emergency access process documented and tested. |

**M365 Signal:** Eligible vs. permanent ratio for Azure resource roles is an Azure Resource Manager signal (`Microsoft.Authorization/roleEligibilityScheduleInstances` and `roleAssignmentScheduleInstances`), not available via Microsoft Graph — manual review in the Graph-only v0.1.0-preview collector.

---

### IN-02: Workload identity — managed identities vs. secrets

**NIST Tenets:** T1, T6  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Service accounts and automation use passwords or long-lived client secrets. Secrets stored in config files or environment variables. No rotation schedule. Secrets shared across multiple workloads. |
| 2 — Initial | Some workloads use managed identities. Client secrets still in use for apps where managed identities are not supported. No formal secret rotation schedule. |
| 3 — Advanced | Managed identities used for all Azure workloads where supported. Client secrets stored in Azure Key Vault with audited access. Secret rotation automated or formally scheduled. Workload identity federation used for CI/CD pipelines. |
| 4 — Optimal | Zero client secrets stored outside Key Vault. All Azure workloads use managed identities or workload identity federation. Secret expiry monitored with automated rotation. No long-lived credentials for any automated workload. |

**M365 Signal:** `GET /applications` — app registrations with client secret expiry greater than 1 year or no expiry set. Managed identity coverage for Azure resources is an Azure Management API signal.

---

### IN-03: Workload monitoring and threat detection

**NIST Tenets:** T5, T7  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No centralized workload monitoring. Workload logs not collected. Threats detected only via reactive support tickets or end-user reports. |
| 2 — Initial | Microsoft Defender for Cloud enabled. Basic Secure Score visible. Some resource-level alerts configured. No SIEM integration. |
| 3 — Advanced | Defender for Cloud plans enabled for key resource types (Servers, Storage, Containers, SQL). Alerts triaged by SOC. Secure Score tracked against a defined organizational baseline. Microsoft Sentinel deployed with key data connectors active. |
| 4 — Optimal | Full Defender for Cloud coverage across all subscriptions and resource types. All workload alert types connected to Sentinel. SOAR playbooks automate response for high-confidence alerts. Secure Score improvement tracked as an organizational metric. |

**M365 Signal:** Defender for Cloud enablement and Secure Score are Azure Management API signals. Sentinel workspace existence and connected data connector count via `GET /operationalInsights/workspaces` (requires `Log Analytics Reader` scope, outside Graph-only collector scope for v0.1.0-preview).

---

### IN-04: RBAC for subscriptions and resources

**NIST Tenets:** T4, T6  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Subscription Owner or Contributor access granted broadly. No resource-group level scoping. Access not reviewed. Implicit trust within subscription boundary. |
| 2 — Initial | RBAC applied at subscription level. Some custom roles defined. Owner assignments exist but not reviewed or minimized. |
| 3 — Advanced | Least-privilege RBAC applied at resource group level. Owner role usage minimized. RBAC assignments reviewed quarterly. Custom roles documented and scoped tightly. |
| 4 — Optimal | Least privilege enforced at resource and resource-group level. No standing Owner or Contributor access except for automation identities managed via PIM. RBAC assignments reviewed automatically. Privileged resource assignments gated by PIM activation. |

**M365 Signal:** Azure RBAC Owner and Contributor assignment count at subscription level is an Azure Management API signal. PIM coverage for Azure resource roles is an Azure Resource Manager signal (`Microsoft.Authorization/roleEligibilityScheduleInstances`), not available via Microsoft Graph.

---

### IN-05: Vulnerability management

**NIST Tenets:** T5, T7  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No vulnerability scanning. Patch management manual and inconsistent. Known vulnerabilities untracked across infrastructure. |
| 2 — Initial | Defender for Servers or a partner vulnerability scanner deployed on some VMs. Vulnerabilities visible in Defender for Cloud but not formally tracked to remediation SLAs. |
| 3 — Advanced | Vulnerability management active across all servers and containers. Critical and high vulnerabilities tracked to SLA-based remediation. Defender for Cloud Secure Score includes vulnerability findings. |
| 4 — Optimal | Continuous vulnerability scanning across all infrastructure. Vulnerabilities auto-prioritized by risk score and exposure. Critical CVEs older than 30 days auto-escalated. Vulnerability trends tracked as an organizational metric. |

**M365 Signal:** Defender for Cloud vulnerability assessment coverage and critical/high vulnerability count are Azure Management API signals. Secure Score vulnerability-related recommendation status is an Azure Management API signal.

---

### IN-06: Deployment governance and configuration policy

**NIST Tenets:** T4, T5  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Resources deployed manually via the portal. No infrastructure-as-code. No compliance guardrails enforced at deployment time. |
| 2 — Initial | Azure Policy assigned for some compliance requirements (region restrictions, required tags). Some ARM or Bicep templates in use. No blueprint-level guardrails. |
| 3 — Advanced | Azure Policy enforces compliance requirements across all subscriptions. Non-compliant resources flagged and tracked. IaC (ARM, Bicep, or Terraform) used for all new resource deployments. |
| 4 — Optimal | Policy-as-code — all Azure Policies version-controlled and deployed via pipeline. Unauthorized resource types blocked at deployment. Azure Policy compliance rate above 95%. Deployment pipelines gate on policy compliance before merge. |

**M365 Signal:** Azure Policy compliance state and assignment count are Azure Management API signals. IaC adoption rate is assessed manually.

---

## Pillar 6 — Networks

*CISA ZTMM v2.0 equivalent: Networks*

### NW-01: Legacy VPN displacement / private access

**NIST Tenets:** T2, T3  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | All remote access via traditional VPN. Full-network tunnel granted — no microsegmentation. VPN credentials are high-value targets for attackers. |
| 2 — Initial | Microsoft Entra Private Access evaluated or piloted for one or more private app segments. Traditional VPN still primary for most users. |
| 3 — Advanced | Entra Private Access deployed for the majority of private app access. App-specific tunnels replace broad VPN access for covered application segments. GSA client deployed on managed devices. |
| 4 — Optimal | Traditional VPN fully replaced by Entra Private Access for all private app access. App-specific tunnels only — no full-network VPN. GSA client deployed on all managed and BYOD devices. |

**M365 Signal:** Entra Private Access connector group count and application segment count via Microsoft Entra admin center. GSA client deployment state via Intune device configuration profile count targeting GSA.

---

### NW-02: Internet access security (Entra Internet Access / SWG)

**NIST Tenets:** T2, T4  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Internet traffic unfiltered or filtered only at an on-premises proxy. No cloud-based Secure Web Gateway. No identity context applied to web filtering decisions. |
| 2 — Initial | Microsoft Entra Internet Access or a third-party SWG deployed in pilot. Basic web category filtering. No integration with identity risk signals. |
| 3 — Advanced | Entra Internet Access deployed for managed devices. Web category filtering enforced. Threat-intelligence-based URL filtering active. Microsoft 365 traffic profile enforced through GSA. |
| 4 — Optimal | Entra Internet Access covers all managed and BYOD devices. Web filtering integrates user risk level as a dynamic filtering signal. Tenant restrictions v2 enforced to block access to non-corporate tenants. Internet Access traffic logs fed to Sentinel. |

**M365 Signal:** Entra Internet Access forwarding profile configuration state. Web category filtering policy state. Tenant restrictions v2 policy configuration.

---

### NW-03: Compliant network CA enforcement (GSA)

**NIST Tenets:** T3, T4  
**Repo X-Ref:** CA-COV015

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No network-based CA condition. Device location and network path are not CA signals. |
| 2 — Initial | Named locations defined in CA using IP ranges. Some CA policies restrict access to known corporate IP ranges. GSA not deployed. |
| 3 — Advanced | GSA deployed. The "All Compliant Network" named location is configured in Entra ID. CA policies require compliant network for sensitive resources. |
| 4 — Optimal | All sensitive resource access requires a compliant network via CA. GSA client on all managed and BYOD devices. Non-compliant network access blocked for high-sensitivity resources in enforced mode. |

**M365 Signal:** Named locations — presence of GSA "All Compliant Network" system location (requires beta namedLocations endpoint). CA policies with compliant network condition in enforced mode.

---

### NW-04: Network segmentation

**NIST Tenets:** T2, T4  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Flat network. No microsegmentation. Lateral movement unrestricted once inside the perimeter. Single breach equals full network access. |
| 2 — Initial | Basic network segmentation via VLANs or Azure VNets. NSG rules applied to key resources. No workload-level microsegmentation. |
| 3 — Advanced | VNet-level segmentation with NSG rules enforced. Application Security Groups used for workload-level segmentation. Azure Firewall deployed for east-west traffic inspection between segments. |
| 4 — Optimal | Microsegmentation at workload level — default deny, explicit allow between all workloads. All east-west traffic inspected. Lateral movement detected in real time via Sentinel network analytics rules. |

**M365 Signal:** Azure VNet, NSG, and Azure Firewall counts are Azure Management API signals. Microsegmentation policy count is an Azure Management API signal.

---

### NW-05: Encryption in transit

**NIST Tenets:** T2  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | Internal traffic not consistently encrypted. HTTP used for some internal services. TLS version enforcement absent. |
| 2 — Initial | HTTPS enforced for external-facing services. TLS 1.2+ required for M365 service endpoints. Internal service-to-service communication not consistently encrypted. |
| 3 — Advanced | TLS 1.2+ enforced for all external and internal services. TLS 1.0 and 1.1 disabled. Certificate lifecycle managed — expiry monitoring in place and auto-renewal configured where supported. |
| 4 — Optimal | TLS 1.3 preferred everywhere. Mutual TLS (mTLS) enforced for service-to-service communication in high-sensitivity workloads. Certificate inventory automated. Zero expired certificates. TLS inspection active for egress traffic via Entra Internet Access. |

**M365 Signal:** Entra Internet Access TLS inspection policy state. M365 service TLS enforcement policy (via Microsoft 365 admin center). Certificate expiry monitoring state is environment-specific.

---

### NW-06: Network traffic monitoring and analytics

**NIST Tenets:** T5, T7  
**Repo X-Ref:** —

| Stage | Configuration state |
|---|---|
| 1 — Traditional | No network traffic logging. Threat detection reactive. No visibility into east-west or egress traffic. |
| 2 — Initial | NSG flow logs enabled for key VNets. Basic alerting on anomalous traffic volumes. No SIEM integration. |
| 3 — Advanced | NSG flow logs and Azure Firewall logs collected in a Log Analytics workspace. Sentinel analytics rules active for network-based threats. SOC reviews network alerts. |
| 4 — Optimal | Full network telemetry — NSG flow logs, Firewall logs, Entra Internet Access traffic logs, and Defender for Endpoint network events — all in Sentinel. ML-based anomaly detection on network traffic patterns. Automated response on high-confidence network threats. |

**M365 Signal:** NSG flow log enablement is an Azure Management API signal. Sentinel data connectors for network sources (Azure Firewall, NSG). Entra Internet Access traffic log forwarding state.

---

*End of rubric — 40 controls across 6 pillars*

*Collector script: `Scripts/Get-ZTReadinessScore.ps1` | Formatter: `Scripts/Format-ZTReadinessReport.ps1`*
