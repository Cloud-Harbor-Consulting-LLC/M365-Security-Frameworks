# Entra ID P2 — Business Case

A standalone business case for organizations evaluating or defending a Microsoft Entra ID P2 investment to executive stakeholders. No other repo context required to use this document.

## Executive summary

Microsoft Entra ID ships in 3 commercial tiers: Free, P1, and P2. Most organizations running Microsoft 365 Business Premium or E3 already have P1. The gap between P1 and P2 covers 3 capabilities that directly reduce breach probability and audit preparation time: Identity Protection risk policies, Privileged Identity Management, and automated Access Reviews.

This repo's frameworks — the Conditional Access Baseline and the Entra ID Governance Toolkit — are designed to use all 3 P2 capabilities. Organizations running this repo's frameworks on P1-only tenants are missing the controls that drive the highest-value risk reduction.

The ask of executive leadership is to confirm or fund Entra ID P2 for all in-scope users. At $10.00 per user per month (standalone, annual commitment) or bundled in Microsoft 365 E5 at $60.00 per user per month, P2 is the licensing tier that closes the largest remaining gaps in this repo's control coverage.

## What Entra ID P2 adds

| Feature | P1 | P2 | Notes |
|---|---|---|---|
| Conditional Access policies | Yes | Yes | P2 adds risk-based conditions (user risk, sign-in risk) |
| Identity Protection — risk detection and reporting | Limited | Full | P1 shows only medium and high risky users with no detail drawer or risk history, and no risk detail on risky sign-ins |
| Identity Protection — risky user and sign-in policies | No | Yes | Risk policies are P2 only. Free and P1 are both "No" in the Microsoft licensing table |
| Privileged Identity Management (PIM) | No | Yes | Just-in-time activation, time-bound assignments, approval workflows. Also available via Entra ID Governance |
| Access Reviews | No | Yes | P2 covers the access review capabilities previously generally available in P2. Newer capabilities require Entra ID Governance (see note below) |
| Entitlement Management | No | Partial | Full Entitlement Management requires the Entra ID Governance add-on |
| Lifecycle Workflows | No | No | Requires the Entra ID Governance add-on |

Source: Microsoft Learn, [Microsoft Entra ID Governance licensing fundamentals](https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals) and [What is Microsoft Entra ID Protection](https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection). Verify at <https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing> before distributing.

### Two licensing notes that affect budget

**Access Reviews is not a single line item.** P2 covers the access review capabilities that were generally available in P2. The following require an Entra ID Governance subscription, not P2: machine-learning assisted access certifications, reviews scoped to inactive users only, PIM for Groups reviews, and catalog access reviews. Confirm which capabilities your review design depends on before sizing the P2 purchase.

**Guest users are billed differently.** Identity Governance features for guests use monthly active user (MAU) billing and require an Azure subscription with guest billing enabled. This is separate from per-user P2 licensing. It applies directly to EIG-AR001, which reviews B2B guests. Budget for both.

**Forward-looking note.** Microsoft states that all currently generally available features in Entra ID P2 will remain, but no new identity governance features or capabilities will be added to the P2 SKU. New governance capability ships under Entra ID Governance and Entra Suite. Factor this into a multi-year licensing plan.

## P2-exclusive features used in this repo

| Feature | Framework | Control | Business value |
|---|---|---|---|
| Identity Protection — user risk policy | Conditional Access Baseline | CA-SIG003 (medium user risk, require secure password change), CA-SIG008 (block high user risk) | Stops compromised credentials from authorizing new sessions without analyst intervention |
| Identity Protection — sign-in risk policy | Conditional Access Baseline | CA-SIG004 (medium sign-in risk, require strong authentication), CA-SIG009 (block high sign-in risk) | Forces re-authentication on anomalous sign-in patterns before the session is granted |
| Identity Protection — Agent ID risk | Conditional Access Baseline | CA-COV011 (block medium and high risk Agent ID sign-ins) | Extends risk-based enforcement to AI agent identities; requires P2 Identity Protection signals |
| Privileged Identity Management | Entra ID Governance Toolkit | PIM integration is future scope; not yet shipped in this repo | Just-in-time activation for the 39 privileged roles in the CA Baseline Admins persona; eliminates standing admin access |
| Access Reviews | Entra ID Governance Toolkit | EIG-AR001 (quarterly guest review), EIG-AR002 (dormant admin role review) | Automates the review cycle that manually takes 3 to 8 hours per quarter per admin; produces auditable evidence for SOC 2 CC6.3 and ISO 27001:2013 A.9.2.5 (consolidated into A.5.18 in the 2022 revision) |

**All 5 Conditional Access risk policies above ship in report-only mode** (`enabledForReportingButNotEnforced`). They generate evaluation data but do not enforce until an operator promotes them to On. The analyst-time savings in the next section are only realized after that promotion. Validate with report-only and policy impact analysis first.

## Licensing tiers and per-user cost

| SKU | Per-user/month | Includes P2 | Notes |
|---|---|---|---|
| Entra ID P2 (standalone) | $10.00 | Yes | Covers Identity Protection, PIM, Access Reviews |
| Microsoft 365 E3 + Entra ID P2 add-on | $49.00 (computed: $39.00 + $10.00) | Yes | Option for orgs on E3 who need P2 without full E5. Microsoft does not publish this as a single bundled SKU; the figure is the sum of the 2 list prices |
| Microsoft 365 E5 | $60.00 | Yes | Bundles P2 plus Defender XDR, Purview, and Sentinel data connectors |
| Microsoft 365 E3 | $39.00 | No | Includes Entra ID P1 only; P2 must be added separately |
| Microsoft 365 Business Premium | No P2 | No | Includes P1 only; P2 must be added separately |

Pricing verified from the Microsoft Entra pricing page and the Microsoft 365 enterprise plans and pricing page as of 2026-08-07. Prices are USD, per user, per month at list price, paid yearly with an annual commitment. Volume and EA pricing varies.

**Do not confuse Office 365 E5 with Microsoft 365 E5.** Office 365 E5 (list $41.00) does not include Entra ID P2. Only Microsoft 365 E5 (list $60.00) includes it. This is a common and expensive procurement error.

## Operational cost estimates

These estimates are based on manual baseline observations from organizations running Microsoft 365 tenants with equivalent user populations. Replace with organization-specific figures where available.

### Access Reviews (EIG-AR001 and EIG-AR002)

| Task | Manual time (quarterly) | Automated time (EIG scripts) | Annual hours saved per 100 users |
|---|---|---|---|
| Guest access review | 3 to 5 hours | 30 minutes (review output, approve/deny) | 10 to 18 hours |
| Dormant admin role review | 1 to 3 hours | 20 minutes (review output, approve/deny) | 3 to 10 hours |

### Identity Protection (CA-SIG003, CA-SIG004, CA-SIG008, CA-SIG009, CA-COV011)

Manual equivalent: analysts triaging and acting on risky user reports in the Entra admin center without automated CA enforcement. Estimated 30 to 90 minutes per risky user event without automated enforcement, versus no analyst time for events handled by an enforcing risk policy.

| Scenario | Without P2 enforcement | With P2 enforcement (policies promoted to On) |
|---|---|---|
| Medium risk user detected | Analyst opens portal, reviews event, manually disables account or resets password (30 to 60 min) | CA-SIG003 requires a secure password change at next sign-in; no analyst action for medium-risk events |
| Medium risk sign-in detected | Analyst reviews the sign-in log entry and decides whether to act (15 to 30 min) | CA-SIG004 requires strong authentication before the session is granted |
| High risk user detected | Analyst opens portal, reviews event, escalates (60 to 90 min) | CA-SIG008 blocks sign-in immediately; analyst reviews closed event (10 to 15 min) |
| High risk sign-in detected | Analyst opens portal, reviews event, escalates (60 to 90 min) | CA-SIG009 blocks the sign-in immediately |

These savings assume the policies have been promoted out of report-only mode. In report-only they produce evaluation data for tuning, which has planning value but does not reduce analyst workload.

### PIM (future scope — included for planning)

Just-in-time admin activation removes standing privilege from the 39 roles in the CA Baseline Admins persona. Standing privilege is the condition where an attacker who compromises an admin account has immediate, persistent access to those roles. With PIM, the window of exposure collapses to the activation window (typically 1 to 4 hours).

PIM requires Entra ID P2 or Entra ID Governance. Licenses are needed for users with eligible or time-bound assignments, users who approve activation requests, users assigned to an access review, and users who perform access reviews.

---

## Compliance mapping

Entra ID P2 controls directly satisfy requirements in 3 frameworks. The controls listed here are in scope because they are implemented by artifacts in this repo or are the stated licensing prerequisite for those artifacts.

### SOC 2 Trust Services Criteria

| CC control | Description | What P2 provides |
|---|---|---|
| CC6.1 | Logical access controls restrict access to authorized users based on authorized user roles | PIM provides just-in-time role activation with approval workflows; eliminates standing admin privilege |
| CC6.3 | Access is restricted to authorized users, internal and external, based on their role | EIG-AR001 (quarterly guest review) and EIG-AR002 (dormant admin role review) produce auditable recertification evidence; Access Reviews require P2 |
| CC6.6 | Logical access security measures protect against threats from sources outside the entity's system boundaries | Identity Protection risk policies (CA-SIG003, CA-SIG004, CA-SIG008, CA-SIG009) block access when Entra ID detects active credential compromise or anomalous sign-in risk; risk-based access restriction against external threats requires P2 |
| CC7.2 | System components are monitored for anomalies indicative of malicious acts; anomalies are analyzed to determine whether they represent security events | Identity Protection risk detections (compromised credentials, anomalous sign-ins, Agent ID risk) are the P2-exclusive detection signal that feeds the CA risk policies |
| CC7.4 | Security incidents are contained, and the effects remediated | CA-SIG008 and CA-SIG009 block sign-in immediately on high risk, reducing the breach window without analyst intervention; enforcement requires P2 |

Note: all CA risk policies (CA-SIG003, CA-SIG004, CA-SIG008, CA-SIG009, CA-COV011) ship in report-only mode. CC6.6 and CC7.4 credit is realized only after policies are promoted to enforcement.

### ISO 27001:2022

Control numbers follow the 2022 revision. For reference, the 2013 equivalents are noted in parentheses.

| Control | Description | What P2 provides |
|---|---|---|
| A.5.15 (was A.9.1.1, A.9.1.2) | Access control | Conditional Access risk policies restrict access at the authentication level based on identity risk; risk-based conditions require P2 |
| A.5.18 (was A.9.2.2, A.9.2.5, A.9.2.6) | Access rights — management of privileged access rights | EIG-AR001 and EIG-AR002 review and remove excess access rights on a defined cadence; PIM enforces time-bound privileged role assignments |
| A.5.25 (was A.16.1.4) | Assessment and decision on information security events | Identity Protection risk detections are the identity-layer events requiring assessment; the CA risk policies automate the response decision for medium and high events |
| A.5.26 (was A.16.1.5) | Response to information security incidents | CA-SIG008 and CA-SIG009 block high-risk sign-ins immediately; enforcing policies constitute automated incident response for credential-compromise events |
| A.8.15 (was A.12.4.1, A.12.4.2, A.12.4.3) | Logging | Entra ID sign-in and audit logs, including Identity Protection risk event logs, are the evidence source for all identity controls; P2 exposes the full risk detail drawer and risk history |
| A.8.16 (no 2013 equivalent — introduced in the 2022 revision) | Monitoring activities | Identity Protection continuous monitoring is the P2 capability that detects compromised credentials, anomalous sign-ins, and Agent ID risk events |

### NIST SP 800-53 Rev 5

| Control | Description | What P2 provides |
|---|---|---|
| AC-2 | Account management | Access Reviews (EIG-AR001, EIG-AR002) automate the periodic account review and disable process required by AC-2(3) |
| AC-6 | Least privilege | PIM enforces time-bound, just-in-time role activation for the 39 admin roles in the CA Baseline Admins persona; standing privilege is eliminated for covered roles |
| AU-2 | Event logging | Identity Protection risk events, PIM activation events, and Access Review decisions are logged in Entra ID audit logs and retained per the tenant's log retention policy |
| IA-4 | Identifier management | Access Reviews (EIG-AR001) enforce guest identity lifecycle by recertifying and removing access for guests who no longer need it |
| RA-3 | Risk assessment | Identity Protection risk detections constitute automated risk identification for credential and sign-in events; P2 enables policy-driven risk response |

---

## CFO-ready summary

**The investment.** Entra ID P2 costs $10.00 per user per month (standalone, annual commitment). For organizations on Microsoft 365 E5 ($60.00 per user per month), P2 is already included. For organizations on Microsoft 365 E3 ($39.00), P2 can be added for $10.00 per user per month.

**What P2 buys.** 3 capabilities that reduce breach probability and audit preparation time: Identity Protection risk policies (stops compromised credentials from authorizing new sessions), Privileged Identity Management (removes standing admin access from 39 privileged roles), and Access Reviews (automates quarterly guest and admin role recertification).

**The savings.** The primary savings are analyst time recovered through Access Review automation (10 to 28 hours per year per 100 users across both EIG scripts) and analyst time recovered through risk-based CA enforcement once policies are promoted to On (30 to 90 minutes per avoided manual remediation event). The primary risk reduction is the removal of standing admin privilege and the automatic containment of compromised credentials.

**The licensing path.** Entra ID P2 is the right starting point for organizations that need Identity Protection, PIM, and Access Reviews now. Microsoft will not add new identity governance capabilities to the P2 SKU. Organizations planning beyond 2 years should evaluate Entra ID Governance as the next step — it adds Lifecycle Workflows, ML-assisted access certifications, PIM for Groups reviews, and continued governance investment. Budget for the upgrade in a 3-year plan.

**Guest billing note.** Identity Governance features for B2B guests use monthly active user (MAU) billing via Azure, separate from per-user P2 licensing. Any organization running EIG-AR001 (quarterly guest review) must budget for guest MAU charges in addition to the P2 per-user cost.

---

## Cross-references

This business case is one of 3 in this repo that together cover the full investment case for the CA Baseline and Entra ID Governance Toolkit.

- `Frameworks/Conditional-Access-Baseline/Business-Case/ROI-CONDITIONAL-ACCESS.md` — business case for the CA Baseline. Covers the risk policies (CA-SIG003, CA-SIG004, CA-SIG008, CA-SIG009, CA-COV011) that are the enforcement layer on top of P2 Identity Protection detections. CFOs evaluating P2 should read both documents: the P2 doc covers the license, this doc covers the policy configuration.
- `Frameworks/Entra-ID-Governance-Toolkit/Business-Case/ROI-ENTRA-GOVERNANCE.md` — business case for the EIG Toolkit. Covers the Access Reviews automation (EIG-AR001, EIG-AR002) in depth, including per-script operational savings, reviewer chain design, and audit evidence retention. The EIG doc covers the operational layer; this doc covers the P2 license that makes it possible.
