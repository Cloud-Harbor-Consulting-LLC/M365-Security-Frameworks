# ZTRA Sample Reports — Contoso Ltd

> **Note:** All data in this document is fictional. Contoso Ltd is a made-up organization
> used to illustrate the three ZTRA output shapes. No real tenant data is represented.

**Fictional tenant profile:**

| Pillar | Stage | Key configuration state |
|---|---|---|
| Identities | Stage 2 — Initial | MFA enabled via Security Defaults; no CA coverage set in enforced mode; sign-in risk CA in report-only; PIM licensed with no eligible assignments |
| Endpoints | Stage 2 — Initial | Intune deployed; Windows compliance policy exists but not CA-linked; Defender for Endpoint onboarded on Windows only |
| Applications | Stage 2 — Initial | Defender for Cloud Apps licensed; Cloud Discovery active with firewall log source; admin consent workflow enabled |
| Data | Stage 2 — Initial | 4 sensitivity labels published (Public, Internal, Confidential, Highly Confidential); no auto-labeling; no DLP enforcement |
| Infrastructure | Stage 1 — Traditional | Azure resource role assignments require manual portal review; app registrations have long-lived secrets (9 of 14 affected); no Defender for Cloud plans enabled |
| Networks | Stage 1 — Traditional | All remote access via legacy VPN; no Entra Private Access; named locations defined by IP range only |
| **Overall** | **Stage 2 — Initial** | Median of [1, 1, 2, 2, 2, 2] pillars, round down on ties |

---

# Technical Report — Contoso Ltd

**Tenant:** Contoso Ltd  
**Assessment date:** 2026-07-15  
**Collector version:** v0.1.0-preview  
**Overall stage:** Stage 2 — Initial  
**Manual review controls:** 27 of 40  

---

## Pillar summary

| Pillar | Stage | Automated | Manual review |
|---|---|---|---|
| Identities | Stage 2 — Initial | 7 | 1 |
| Endpoints | Stage 2 — Initial | 2 | 5 |
| Applications | Stage 2 — Initial | 3 | 3 |
| Data | Stage 2 — Initial | 1 | 6 |
| Infrastructure | Stage 1 — Traditional | 1 | 5 |
| Networks | Stage 1 — Traditional | 1 | 5 |

---

## Identities — Stage 2 — Initial

| Control | Stage | NIST Tenets | Repo X-Ref | Manual Review |
|---|---|---|---|---|
| **ID-01** MFA enrollment and coverage | Stage 2 — Initial | T4, T6 | CA-COV001-009, CA-SIG001 | No |
| **ID-02** Admin MFA and privileged identity protection | Stage 2 — Initial | T3, T4, T6 | CA-AUT001-003, CA-SIG005 | No |
| **ID-03** Block legacy authentication | Stage 2 — Initial | T2, T6 | CA-SIG001 | No |
| **ID-04** Sign-in risk CA enforcement | Stage 2 — Initial | T4, T5, T7 | CA-SIG005-007 | No |
| **ID-05** User risk CA enforcement | Stage 2 — Initial | T4, T5, T7 | CA-SIG008-010 | No |
| **ID-06** Privileged identity management JIT access | Stage 2 — Initial | T3, T4, T5 | EIG-AR002 | No |
| **ID-07** External identity lifecycle governance | Stage 2 — Initial | T4, T5 | EIG-AR001 | No |
| **ID-08** SSO coverage for sanctioned applications | — | T3, T6 | — | Yes |

> **ID-01 signals observed:** LegacyAuthBlocked = False, MfaCoverageEnforced = False (Security Defaults active — CA coverage set not deployed), PhishResistantEnforced = False → Stage 2

> **ID-02 signals observed:** AdminMfaEnforced = False, PimData: Eligible = 0, Permanent = 12 → Stage 2 (admin MFA partially covered via Security Defaults; PIM licensed but no eligible assignments)

> **ID-03 signals observed:** LegacyBlockEnforced = False, LegacyBlockReportOnly = False → Stage 2 (Security Defaults blocks some legacy auth at the service level but no CA policy in enforced mode)

> **ID-04 signals observed:** SignInRiskEnforced = False, SignInRiskReportOnly = True → Stage 2

> **ID-05 signals observed:** UserRiskHighEnforced = False, UserRiskMedEnforced = False, RiskyUserCount = 3 → Stage 2

> **ID-06 signals observed:** PimData: Eligible = 0, Permanent = 12 → Stage 2 (PIM licensed; no eligible assignments configured; all permanent)

> **ID-07 signals observed:** GuestInvitePolicy = adminsAndGuestInviters, AccessReviewsExist = False → Stage 2

> **ID-08 — Manual review required:** SSO coverage requires Application.Read.All, outside v0.1.0-preview scope.

---

## Endpoints — Stage 2 — Initial

| Control | Stage | NIST Tenets | Repo X-Ref | Manual Review |
|---|---|---|---|---|
| **EP-01** Device registration with cloud identity | Stage 3 — Advanced | T1, T5 | — | No |
| **EP-02** Device compliance policies | — | T4, T5 | — | Yes |
| **EP-03** CA enforcement of device compliance | Stage 1 — Traditional | T3, T4, T6 | CA-AUT003 | No |
| **EP-04** App protection policies BYOD MAM | — | T1, T4 | — | Yes |
| **EP-05** Security baselines and configuration enforcement | — | T5, T7 | — | Yes |
| **EP-06** Device encryption | — | T1, T2 | — | Yes |
| **EP-07** Endpoint threat detection | — | T5, T7 | — | Yes |

> **EP-01 signals observed:** TotalDevices = 210, JoinedDevices = 201, RegisteredDevices = 5 → Stage 3 (96% of devices are Entra Joined or Hybrid Joined)

> **EP-03 signals observed:** CompliantDeviceEnforced = False, CompliantDeviceReportOnly = False → Stage 1 (no CA policy requiring compliant device in any mode)

*Pillar stage = median of [3, 1] (scored controls) = Stage 1 raised by manual review gap — practitioners should review EP-02 compliance policy state to confirm pillar stage.*

---

## Applications — Stage 2 — Initial

| Control | Stage | NIST Tenets | Manual Review |
|---|---|---|---|
| **AP-01** Shadow IT discovery | — | T5, T7 | Yes |
| **AP-02** OAuth consent governance | Stage 3 — Advanced | T4, T5 | No |
| **AP-03** Conditional Access App Control session controls | Stage 1 — Traditional | T3, T4 | No |
| **AP-04** Application DLP | — | T4, T5 | Yes |
| **AP-05** UEBA and anomaly detection | — | T5, T7 | Yes |
| **AP-06** App-level access permissions and entitlement governance | Stage 2 — Initial | T3, T4 | No |

> **AP-02 signals observed:** AdminConsentEnabled = True, HighPrivilegeGrantCount = 7 → Stage 3

> **AP-03 signals observed:** CaacEnabled = False → Stage 1

> **AP-06 signals observed:** AccessPackageCount = 2 → Stage 2

---

## Data — Stage 2 — Initial

| Control | Stage | NIST Tenets | Manual Review |
|---|---|---|---|
| **DA-01** Data classification framework and sensitivity label taxonomy | Stage 2 — Initial | T1, T5 | Yes (partial) |
| **DA-02** Information protection encryption and rights management | — | T1, T2, T4 | Yes |
| **DA-03** Container-level data protection | — | T3, T4 | Yes |
| **DA-04** Data Loss Prevention policy coverage and maturity | — | T4, T5 | Yes |
| **DA-05** Insider Risk Management | — | T5, T7 | Yes |
| **DA-06** Data lifecycle and records management | — | T5 | Yes |
| **DA-07** Data discovery and content inventory | — | T1, T5 | Yes |

> **DA-01 signals observed:** SensitivityLabelCount = 4 → Stage 2 (labels published; auto-labeling and enforcement state requires Purview portal review)

---

## Infrastructure — Stage 1 — Traditional

| Control | Stage | NIST Tenets | Manual Review |
|---|---|---|---|
| **IN-01** JIT privileged access for Azure resource roles | — | T3, T4, T5 | Yes |
| **IN-02** Workload identity managed identities vs. secrets | Stage 1 — Traditional | T1, T6 | Yes (partial) |
| **IN-03** Workload monitoring and threat detection | — | T5, T7 | Yes |
| **IN-04** RBAC for subscriptions and resources | — | T4, T6 | Yes |
| **IN-05** Vulnerability management | — | T5, T7 | Yes |
| **IN-06** Deployment governance and configuration policy | — | T4, T5 | Yes |

> **IN-01 — Manual review required:** Azure PIM for resource roles requires the Azure Resource Manager API, outside v0.1.0-preview Graph scope. Navigate to: Azure portal > Entra ID > Privileged Identity Management > Azure Resources.

> **IN-02 signals observed:** AppRegistrationCount = 14, AppsWithStaleSecrets = 9 → Stage 1 (64% of app registrations have secrets expiring in more than 1 year or with no expiry)

---

## Networks — Stage 1 — Traditional

| Control | Stage | NIST Tenets | Manual Review |
|---|---|---|---|
| **NW-01** Legacy VPN displacement private access | — | T2, T3 | Yes |
| **NW-02** Internet access security Entra Internet Access SWG | — | T2, T4 | Yes |
| **NW-03** Compliant network CA enforcement GSA | Stage 1 — Traditional | T3, T4 | No |
| **NW-04** Network segmentation | — | T2, T4 | Yes |
| **NW-05** Encryption in transit | — | T2 | Yes |
| **NW-06** Network traffic monitoring and analytics | — | T5, T7 | Yes |

> **NW-03 signals observed:** GsaLocationFound = False, NamedLocationCount = 3, CompliantNetworkCA = False → Stage 1 (named locations defined by IP range; no GSA compliant network location; no compliant network CA)

---

*Report generated by ZTRA Collector v0.1.0-preview — Cloud Harbor Consulting LLC*

---
---

# Executive Summary — Contoso Ltd

**Tenant:** Contoso Ltd  
**Assessment date:** 2026-07-15  
**Overall maturity stage:** Stage 2 — Initial  

> Automation starting. Initial risk-based access decisions emerging. Some lifecycle management still manual.

---

## Per-pillar maturity

| Pillar | Stage | Top gaps |
|---|---|---|
| **Identities** | Stage 2 — Initial | ID-01, ID-02, ID-06 |
| **Endpoints** | Stage 2 — Initial | EP-03, EP-02, EP-07 |
| **Applications** | Stage 2 — Initial | AP-03, AP-01, AP-05 |
| **Data** | Stage 2 — Initial | DA-01, DA-04, DA-02 |
| **Infrastructure** | Stage 1 — Traditional | IN-01, IN-03, IN-04 |
| **Networks** | Stage 1 — Traditional | NW-03, NW-01, NW-02 |

---

## Recommended next actions

### Identities — Stage 2 — Initial

- Advance ID-01 (MFA enrollment and coverage) from Stage 2 to Stage 3: deploy a CA coverage set in enforced mode with a legacy authentication block policy.
- Advance ID-06 (PIM JIT access) from Stage 2 to Stage 3: configure PIM eligible assignments for high-impact admin roles (Global Admin, Privileged Role Admin, Security Admin) with approval required.
- Advance ID-04 (Sign-in risk CA) from Stage 2 to Stage 3: move sign-in risk CA from report-only to enforced mode for medium and high risk.

### Endpoints — Stage 2 — Initial

- Advance EP-03 (CA enforcement of device compliance) from Stage 1 to Stage 3: create a CA policy requiring compliant device for all corporate app access, graduate from report-only to enforced.
- Complete manual review for EP-02 (device compliance policies), EP-04 (MAM), EP-05 (security baselines), and EP-07 (MDE onboarding) to confirm full pillar stage.

### Applications — Stage 2 — Initial

- Advance AP-03 (CAAC session controls) from Stage 1 to Stage 3: configure at least one CAAC session policy in Defender for Cloud Apps for critical apps.
- Complete manual review for AP-01 (Shadow IT discovery) and AP-05 (UEBA) to confirm cloud app visibility baseline.

### Data — Stage 2 — Initial

- Complete manual review for DA-02 through DA-07 to establish Data pillar baseline; prioritize DLP (DA-04) and label enforcement (DA-02) as the highest-impact gap.

### Infrastructure — Stage 1 — Traditional

- Advance IN-02 (workload identity): rotate or sunset long-lived app secrets (9 of 14 registrations affected); move to managed identities for eligible Azure workloads.
- Complete manual review for IN-01 (Azure resource PIM), IN-03 (Defender for Cloud), IN-04 (RBAC), and IN-05 (vulnerability management) to establish remediation plan.

### Networks — Stage 1 — Traditional

- Evaluate Entra Private Access deployment (NW-01) as replacement for legacy VPN; pilot one application segment.
- Deploy GSA compliant network named location and CA policy (NW-03) once Private Access is operational.

---

## Manual review items

27 controls require portal-based assessment. Review each control's `ManualReviewNote` in the technical
report for exact portal navigation. The highest-priority manual reviews are: EP-02 (device compliance
policies), EP-07 (MDE onboarding), DA-04 (DLP policy coverage), and IN-03 (Defender for Cloud).

---

*Report generated by ZTRA Collector v0.1.0-preview — Cloud Harbor Consulting LLC*

---
---

# Board Summary — Contoso Ltd

**Organization:** Contoso Ltd  
**Assessment date:** 2026-07-15  
**Assessment framework:** CISA Zero Trust Maturity Model v2.0  

---

## Overall maturity

**Stage 2 — Initial**

Automation is starting. Some initial risk-based access decisions are in place, but lifecycle
management for privileged accounts and devices remains largely manual. The organization has
not yet achieved consistent, policy-enforced access control across all 6 pillars.

| Pillar | Maturity stage |
|---|---|
| Identities | Stage 2 — Initial |
| Endpoints | Stage 2 — Initial |
| Applications | Stage 2 — Initial |
| Data | Stage 2 — Initial |
| Infrastructure | Stage 1 — Traditional |
| Networks | Stage 1 — Traditional |

---

## Strengths

- **Identities**: Multi-factor authentication is enabled for all users, and an admin consent workflow is in place for third-party app permissions. This reduces the risk of the most common initial access vector — phishing and credential theft.
- **Endpoints**: 96% of corporate devices are registered with Entra ID, providing device identity visibility across the estate. Defender for Endpoint is onboarded on Windows devices.
- **Applications**: The OAuth consent workflow is configured, preventing users from granting excessive permissions to third-party apps without administrator approval.

---

## Top priorities

- **Infrastructure** is currently at Stage 1 (Traditional). 9 of 14 application registrations use long-lived secrets with no rotation schedule. Privileged Azure resource roles have no time-limited access controls. This creates standing access risk — a compromised credential retains full access indefinitely.
- **Networks** is currently at Stage 1 (Traditional). All remote access is via legacy VPN with no microsegmentation. A compromised endpoint with VPN access has unrestricted reach to all internal resources.
- **Identities** has 12 permanently assigned admin roles with no JIT activation requirement. Administrative sessions are not time-limited or approval-gated, increasing the impact of an admin account compromise.

---

## Business risk context

Contoso's current Stage 2 posture means the most common attack paths remain open. Phishing and
credential theft are the top initial access vectors in M365 environments. Without a compliant
device CA policy and enforced MFA coverage set, an attacker who obtains a valid password can
access corporate resources from any device.

The IBM Cost of a Data Breach 2024 report places the average breach cost at $4.88M globally
($9.36M in the United States). Organizations with a mature Zero Trust program average $1.76M
less per breach than organizations without one. A Stage 2 organization typically falls into the
higher-cost breach category.

---

## Path forward

Advancing to Stage 3 (Advanced) across all pillars is the recommended next objective.
The highest-impact changes are: deploying a CA coverage set with legacy auth block (Identities),
linking device compliance to Conditional Access (Endpoints), and rotating long-lived app secrets
with a move to managed identities (Infrastructure). These 3 changes close the most common
initial access paths and reduce breach likelihood significantly. Targeted remediation at this
stage typically requires 3–6 months.

The executive summary and technical report identify specific configuration changes required
at the control level, prioritized by pillar stage gap.

---

*Assessment: ZTRA v0.1.0-preview | Framework: CISA ZTMM v2.0 | Methodology: NIST SP 800-207 | Delivered by Cloud Harbor Consulting LLC*
