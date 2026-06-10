# Conditional Access Baseline — Business Case and ROI

> A plain-language business case for security architects defending Conditional Access investment to executive leaders, the C-suite, and board members.

## Executive summary

Identity is the modern enterprise perimeter. Over the last five years, industry data from Verizon's annual *Data Breach Investigations Report (DBIR)*, IBM's annual *Cost of a Data Breach Report*, and the *Microsoft Digital Defense Report* consistently ranks stolen or misused credentials as the leading initial access vector for enterprise breaches. Organizations that deploy a mature Conditional Access baseline materially reduce the probability of credential-driven incidents, without adding meaningful user friction when scoped correctly.

This v1.4 baseline delivers twenty-eight Conditional Access policies across eight personas — Global, Internal, Admins, Guests, ServiceAccounts, WorkloadIdentities, Agents, and AgentUsers — plus a Sensitive-Applications scope. Every policy ships in report-only by default. Operators promote to enforcement on a documented soak schedule, with a minimum of seven to fourteen days of impact validation per policy before any enforcement decision is made.

Four developments define this baseline's executive narrative:

**The Agents persona.** Microsoft Agent ID is a distinct identity class in Microsoft Entra ID for AI agents and Copilot agents. Agent IDs cannot be governed by user-targeted Conditional Access policies. Without a dedicated Agents lane, agentic AI workloads run completely outside the Conditional Access policy surface — even in tenants that have otherwise deployed a mature identity baseline. The v1.3 baseline introduces CA-COV011, which covers Agent ID sign-ins via Microsoft Identity Protection signals, making this one of the first community Conditional Access baselines to include native Agent ID coverage as of 2026.

**Microsoft Graph beta endpoint commitment.** Seven policies require the beta endpoint because Microsoft has not yet completed general availability promotion of specific features: the `signInFrequency: everyTime` interval used in the risk policies, and the Microsoft agent condition family used across the Agents and AgentUsers persona policies. For operational simplicity, all twenty-eight policies target the beta endpoint consistently, with a documented migration path when Microsoft completes GA promotion.

**A graduated authentication strength model.** The v1.3 model replaces the v1.2 framing of always-on phishing-resistant MFA for privileged accounts with three distinct authentication strength tiers, applied at the moment and context where each tier adds the most coverage: StandardAuth at registration time for all users, AdminAuth (FIDO2 only) on admin portal surfaces for privileged roles, and StrongAuth (FIDO2 or Windows Hello for Business) on risk-elevated sessions for any user.

**Expanded agent governance (v1.4).** v1.3 covered the agent surface with a single risk-based policy on the agent identity (CA-COV011). v1.4 extends that to a four-policy agent surface across two personas. The Agents persona gains CA-COV012, an allow-only-approved-agents control that blocks every agent identity in the tenant except an approved set, turning the agent surface from open-by-default into a governed allow-list. A new AgentUsers persona covers the agent user account, the identity Microsoft uses when an agent acts as a user (the digital worker pattern), which is a distinct identity from the agent itself: CA-COV013 blocks risky agent user sign-ins, CA-COV014 requires a compliant device, and CA-COV015 blocks sign-ins from outside the compliant network. Most community baselines still address neither the agent identity nor the agent user account as of 2026.

The ask of executive leadership is threefold:

1. **Endorse a phased deployment** that runs each policy in report-only mode for seven to fourteen days before enforcement.
2. **Fund or confirm** Entra ID P1 (minimum) or P2 (recommended) licensing for all in-scope users, plus Microsoft Entra Workload Identities Premium for the workload-identity policy, a per-user Microsoft Agent 365 license for the Agents persona policy, and Microsoft Entra Internet Access if network-based agent controls are in scope.
3. **Authorize a quarterly review cadence** for the baseline, led jointly by Security and IT Operations.

In return, the organization gets a defensible, auditable identity security posture that addresses the single highest-probability breach vector in contemporary incident data, extends coverage to the agentic AI workload surface that most frameworks ignore, and aligns with SOC 2, ISO 27001, HIPAA, PCI-DSS, and NIST SP 800-53 access control requirements. This baseline pairs with the Intune Compliance Baseline to deliver end-to-end device-health signal integration (see `Design/CA-ICB-INTEGRATION.md`).

## The business risk this addresses

### Identity compromise is the dominant breach vector

Every year since the Verizon DBIR began tracking credential-based attacks as a distinct category, stolen or misused credentials have ranked among the top initial access vectors across industries and organization sizes. Phishing, password spray, adversary-in-the-middle token theft, and reuse of credentials exposed in third-party breaches all converge on the same point of failure: an identity that authenticates successfully with insufficient verification.

The risk surface has grown. In 2026, the identity surface includes not only human users and service principals, but also AI agents operating under delegated permissions in Microsoft 365. Most identity security frameworks were designed before this identity class existed at scale. The v1.4 baseline is designed for the current attack surface, not the 2022 one.

### The financial exposure is substantial

IBM's *Cost of a Data Breach Report* consistently finds that breaches involving stolen or compromised credentials take longer to identify and contain than the average breach — and that the per-breach cost is measured in millions of US dollars. For organizations in regulated industries (healthcare, financial services, critical infrastructure), the per-breach cost is materially higher.

For this baseline's ROI calculation, the organization should reference its own most recent cyber-insurance questionnaire, internal risk register, or the latest published figures from IBM and Verizon to populate:

- [INSERT: ORGANIZATION'S ESTIMATED ANNUAL BREACH-RISK EXPOSURE]
- [INSERT: ORGANIZATION'S CURRENT CYBER-INSURANCE PREMIUM]
- [INSERT: INDUSTRY AVERAGE BREACH COST FROM LATEST IBM REPORT]

### Legacy MFA does not close the gap alone

MFA is necessary but no longer sufficient as the sole authentication defense. Attackers using adversary-in-the-middle proxy kits can phish a valid MFA-protected session token in minutes and replay it to the target service without ever seeing the password. Microsoft's own guidance has shifted toward phishing-resistant methods (FIDO2 security keys, Windows Hello for Business) for privileged identities and high-value workloads. This baseline enforces that shift at the contexts where it matters most — admin portal access and risk-elevated sessions — and layers token binding to defeat replay even when phishing-resistant MFA was not in play on the original session.

## What the baseline delivers

Twenty-eight policies, each addressing a specific business risk. Policies are grouped below by the persona segment they target. Columns: Policy ID, Persona, Intent, License floor, Business outcome.

### AUT series — Authentication Strength policies

| Policy ID | Persona | Intent | License floor | Business outcome |
|---|---|---|---|---|
| CA-AUT001 | Global (user action) | Require StandardAuth for device registration | Entra ID P1 | Every user reaches a phishing-resistant-capable posture at device enrollment time |
| CA-AUT002 | Global (user action) | Require StandardAuth for security info registration | Entra ID P1 | Prevents attackers who phished a password from swapping in their own MFA method |
| CA-AUT003 | Admins (14 directory roles) | Require AdminAuth (FIDO2 only) when accessing Azure Service Management or Microsoft Admin Portals | Entra ID P1 | Admin portal access — the highest-value attack surface in Microsoft 365 — requires a hardware security key |

### COV series — Identity-wide Coverage policies

| Policy ID | Persona | Intent | License floor | Business outcome |
|---|---|---|---|---|
| CA-COV001 | Global | Block legacy authentication protocols | Entra ID P1 | Eliminates the password-spray attack surface entirely |
| CA-COV002 | Global | Require MFA for every interactive sign-in | Entra ID P1 | No identity authenticates with a password alone |
| CA-COV003 | Global | Disable persistent browser sessions; enforce 4-hour sign-in frequency on non-corp devices | Entra ID P1 | Stolen browser cookies expire within hours |
| CA-COV004 | Global | Block OAuth 2.0 device code flow | Entra ID P1 | Removes a phishing-friendly grant flow attackers use to extract tokens from users |
| CA-COV005 | Global | Block cross-device Authentication Transfer | Entra ID P1 | Eliminates a social-engineering vector where attackers redirect authentication to their device |
| CA-COV006 | Global | Block sign-ins from unknown device platforms | Entra ID P1 | Catches spoofed, headless, or obsolete clients outside the supported fleet |
| CA-COV007 | Global | Block sign-ins from outside the Trusted Countries named location | Entra ID P1 | Removes geographies the business does not operate in from the attack surface |
| CA-COV008 | Internal | Require compliant or hybrid-joined device on Windows, macOS, and Linux | Entra ID P1 + Intune | Internal users sign in to all apps only from organization-managed, healthy desktops |
| CA-COV009 | ServiceAccounts | Block service-account sign-ins from outside the Trusted Countries named location | Entra ID P1 | Closes the coverage gap created by the ServiceAccounts persona exclusion from human-targeted policies |
| CA-COV010 | WorkloadIdentities | Restrict service-principal sign-ins to a defined egress | Workload Identities Premium | Closes the workload-identity coverage gap left by user-scoped policies |
| CA-COV011 | Agents | Block Agent ID sign-ins at medium or high agent risk per Identity Protection | Entra ID P2 + Agent 365 (per user) | Covers the agentic AI workload surface; most community baselines ignore Agent IDs entirely |
| CA-COV012 | Agents | Block every agent identity except an approved set (allow-only-approved-agents) | Entra ID P1 + Agent 365 (per user) | Turns the agent surface into a governed allow-list; only sanctioned agents operate |
| CA-COV013 | AgentUsers | Block agent user account sign-ins at medium or high agent risk | Entra ID P2 + Agent 365 (per user) | Extends risk-based blocking to the agent-acting-as-a-user identity that user-targeted policies do not reach |
| CA-COV014 | AgentUsers | Require a compliant device for agent user account sign-ins | Entra ID P1 + Agent 365 + Intune | Agent user work runs only from Intune-managed Windows 365 Cloud PCs for Agents |
| CA-COV015 | AgentUsers | Block agent user account sign-ins from outside the compliant network | Entra ID P1 + Agent 365 + Entra Internet Access | Confines agent user sessions to the trusted corporate network via Global Secure Access |

### SIG series — Layered Signal policies

| Policy ID | Persona | Intent | License floor | Business outcome |
|---|---|---|---|---|
| CA-SIG001 | Sensitive-Applications | Require compliant or hybrid-joined device for Azure Service Management access by Internal users | Entra ID P1 + Intune | Sensitive admin surfaces reachable only from managed endpoints |
| CA-SIG002 | Guests | Require MFA for every interactive guest sign-in | Entra ID P1 | Establishes a resource-tenant authentication floor independent of the guest's home-tenant posture |
| CA-SIG003 | Global (risk) | Graduated response to medium user risk: StrongAuth plus risk remediation plus SignInFreq every time | Entra ID P2 | Forces phishing-resistant step-up and password change when account-level compromise indicators surface |
| CA-SIG004 | Global (risk) | Graduated response to medium sign-in risk: StrongAuth plus SignInFreq every time | Entra ID P2 | Challenges anomalous sessions before they proceed; forces phishing-resistant re-authentication |
| CA-SIG005 | Admins (14 directory roles) | Hard-block admin sign-ins at medium and high sign-in risk | Entra ID P2 | Privileged sessions at elevated risk do not get a re-challenge path; they are blocked outright |
| CA-SIG006 | Guests | Block guest sign-ins to any application outside the Microsoft 365 collaboration set | Entra ID P1 | Constrains B2B authorization scope to the apps that were shared |
| CA-SIG007 | Internal | Cryptographically bind refresh tokens to the issuing Windows device's TPM-protected key | Entra ID P1 | Stolen tokens cannot be replayed from any other device; defeats infostealer token theft |
| CA-SIG008 | Global | Block all users on high user risk | Entra ID P2 | Zero tolerance for high-confidence account compromise indicators |
| CA-SIG009 | Global | Block all users on high sign-in risk | Entra ID P2 | Zero tolerance for high-confidence session anomaly indicators |
| CA-SIG010 | Guests | Require B2B guests to accept a Terms of Use before access is granted | Entra ID P2 | Documented consent gate for every B2B guest; supports contractual disclosure requirements |

## Risk reduction framing

The baseline does not eliminate breach risk. No single control does. It materially reduces the probability of the highest-frequency attack paths. The threat categories the baseline addresses:

**Credential theft and phishing.** CA-AUT003 requires phishing-resistant hardware keys (FIDO2) when accessing the Azure portal and Microsoft admin portals — the targets attackers prioritize in credential phishing campaigns against privileged identities. CA-SIG003, CA-SIG004, and CA-SIG005 enforce StrongAuth or hard-block on risk-elevated sessions for users and admins. CA-SIG008 and CA-SIG009 hard-block on high user and sign-in risk signals from Identity Protection. The combination removes the most common paths through which credential attacks succeed against a Microsoft Entra ID tenant.

**Post-MFA token theft.** CA-SIG007 (Token Protection) cryptographically binds refresh tokens and Primary Refresh Tokens to the issuing device's TPM-protected key, defeating post-MFA token replay attacks — including adversary-in-the-middle session-token capture, infostealer token theft, and browser cookie redemption. Stolen tokens are mathematically non-portable to any other device. The full interaction with Continuous Access Evaluation is documented in `Design/CAE-TOKEN-PROTECTION-LAYERING.md`.

**B2B guest data exposure.** CA-SIG002 gates every guest sign-in behind MFA at the resource-tenant level, independent of the guest's home-tenant MFA posture. CA-SIG006 constrains guest token authorization to only the applications that were explicitly shared. CA-SIG010 adds a Terms of Use consent gate that creates a documented record of guest acknowledgment and supports regulatory and contractual disclosure requirements.

**Workload identity abuse.** CA-COV010 restricts service-principal sign-ins to a defined egress IP set, closing the workload-identity gap that user-scoped policies leave open. CA-COV009 extends parallel geography-based coverage to the ServiceAccounts persona. Operational patterns for named-location refresh, per-pipeline SPN scoping, and CI/CD runner egress management are documented in `Design/WORKLOAD-IDENTITY-IP-PATTERNS.md`.

**Agentic AI workload abuse.** CA-COV011 blocks Agent ID sign-ins when Microsoft Identity Protection detects medium or high agent risk. Without this policy, agentic workloads operating through Microsoft Agent IDs can authenticate to tenant resources with no Conditional Access evaluation, even in tenants with an otherwise mature identity baseline. The design rationale, risk signal model, and operational runbook are in `Design/AGENTS-PERSONA-MODEL.md`.

**Legacy auth bypass.** CA-COV001 blocks all authentication protocols that cannot enforce MFA, including IMAP, POP, SMTP AUTH, and older Exchange ActiveSync variants. This eliminates the password-spray attack surface entirely for any client still using legacy protocols.

**Sign-in-flow phishing variants.** CA-COV004 blocks OAuth 2.0 device code flow, a grant flow attackers use to phish tokens from users who approve authentication on the wrong endpoint — a phishing variant that bypasses traditional URL-based defenses. CA-COV005 blocks Authentication Transfer, a cross-device authentication flow that can be social-engineered into authorizing on an attacker-controlled device.

## Authentication strength enforcement model

The v1.3 baseline introduces a graduated authentication strength model that replaces the v1.2 approach of always-on phishing-resistant MFA for all privileged accounts. The model applies three distinct authentication strength tiers at the moment and context where each tier provides the most coverage.

**StandardAuth** (Windows Hello for Business, FIDO2, or password plus Microsoft Authenticator push) is required on the two user-action registration policies — CA-AUT001 (register device) and CA-AUT002 (register security info). These are the two moments where an attacker who has phished a password can do the most lasting damage: enrolling a new device or swapping in an MFA method they control. StandardAuth at these moments ensures that every user reaches a phishing-resistant-capable posture before they can modify their authentication surface.

**AdminAuth** (FIDO2 only) is required by CA-AUT003 when the fourteen highly-privileged Entra ID directory roles access Azure Service Management or Microsoft Admin Portals. This narrows the two highest-value admin surfaces to phishing-resistant hardware keys, while not imposing FIDO2 on routine admin work outside those application scopes, where CA-COV002 (RequireMFA) provides the authentication floor.

**StrongAuth** (Windows Hello for Business or FIDO2) is required by CA-SIG003 (medium user risk) and CA-SIG004 (medium sign-in risk) when Identity Protection signals elevate session risk. Risk-elevated sessions must clear a phishing-resistant bar before proceeding or receiving risk remediation credit.

**PIM activation** is assumed to enforce always-on phishing-resistant MFA at role activation time, outside the Conditional Access baseline's scope. Adopters who have not deployed PIM should extend CA-AUT003 to cover all admin sign-ins rather than only admin portal access until PIM is in place.

The model is intentionally lighter on routine admin work outside the admin portals application, where AdminAuth would impose FIDO2 on every admin sign-in regardless of destination. This reduces friction for organizations that have not yet completed a full FIDO2 hardware key rollout across their admin population, while still enforcing FIDO2 on the highest-risk admin surfaces.

## The Agents persona business case

### What Agent IDs are

Microsoft Agent ID is a distinct identity class in Microsoft Entra ID. When an organization deploys a Microsoft 365 Copilot agent, an Azure AI-integrated workflow, or a custom agentic application, Entra provisions a corresponding Agent ID in the tenant. Each Agent ID operates as a non-human identity with its own authentication path and delegated permissions to Microsoft 365 resources. Agent IDs are not service principals in the traditional sense; they form a dedicated identity class with their own condition family in the Microsoft Graph Conditional Access API.

### Why Agent IDs need a dedicated Conditional Access lane

Agent IDs do not authenticate via the user-context flow. They cannot be included or excluded by user-targeted Conditional Access policies in the way human users can. Without an Agents-specific policy lane, Agent ID sign-ins are evaluated under the most permissive available policy for their authentication path — or not evaluated by Conditional Access at all.

This gap is growing in business significance. As organizations expand their use of Copilot agents and AI-integrated workflows, the Agent ID population in the tenant grows. Each Agent ID carries delegated permissions to Microsoft 365 resources. An Agent ID with elevated permissions that is not gated by Conditional Access represents a potential lateral movement surface if an AI workflow is compromised, misconfigured, or abused.

### What CA-COV011 does

CA-COV011 blocks Agent ID sign-ins when Microsoft Identity Protection detects medium or high agent risk. The policy operates at the application-side filter: it targets all Agent ID service principals across all Agent ID resources, independently of user-targeted policy scope. The policy ships in report-only by default, following the same soak model as every other policy in the baseline.

Operationally, CA-COV011 requires a monthly Agent ID risk-event review to ensure the Agents persona is current with the tenant's deployed agent inventory and to catch risk signals that warrant investigation. This cadence is included in the operational cost estimate in the Operational cost estimate section.

### What CA-COV012 does (allow-only-approved agents)

CA-COV011 blocks an agent only when it turns risky. CA-COV012 closes the prior question: should this agent be operating at all? It establishes an allow-only posture. The policy includes every agent identity in the tenant, excludes an approved set selected by a custom security attribute, and blocks. The net effect is that only sanctioned agents operate; any new, unknown, or shadow agent is blocked until it is reviewed and added to the approved set. This converts the agent surface from open-by-default, where any provisioned agent can authenticate, into a governed allow-list with a named owner and an approval gate.

For the business, this is the difference between knowing which agents are risky and knowing which agents are authorized. As Copilot agents and AI-integrated workflows proliferate inside the tenant, the approved-agent allow-list is the control that keeps the agent population from growing faster than governance can track. CA-COV011 and CA-COV012 are complementary layers, not duplicates: one blocks sanctioned agents that go bad, the other blocks unsanctioned agents outright.

### Covering the agent user account (AgentUsers persona)

Microsoft describes three agent access patterns, and they do not all use the same identity. An agent can act on behalf of a user (the user is the subject, and existing user-targeted policies already cover it), it can act on its own (the agent identity is the subject, covered by CA-COV011 and CA-COV012), or it can act as a user, a digital worker with its own agent user account as the subject. The agent user account is a distinct identity. A policy that targets all users does not include it, and a policy that targets agent identities does not apply to it. Left uncovered, the digital-worker pattern is a coverage seam that sits between the human and agent identity lanes.

The AgentUsers persona closes that seam with three policies. CA-COV013 blocks agent user account sign-ins at medium and high agent risk, the same risk-based control CA-COV011 provides for the agent identity. CA-COV014 requires a compliant device, scoped so it applies only to endpoint-initiated agent user sessions on Intune-managed Windows 365 Cloud PCs for Agents, so cloud-native agents with no device are not blocked with no path to compliance. CA-COV015 blocks agent user account sign-ins from outside the compliant network, confining digital-worker sessions to the trusted corporate network. All three ship report-only so adopters validate impact before enforcement.

### The competitive positioning point

As of 2026, few community Conditional Access baselines include explicit coverage of Microsoft Agent IDs. Most frameworks were designed before the Agent ID identity class existed at scale and have not been updated to address the agentic AI identity surface. This baseline treats Agents as a first-class persona with a dedicated policy lane, a written exclusion contract (CA-EXC003), and a full design document covering the technical risk model and operational runbook (`Design/AGENTS-PERSONA-MODEL.md`). Adopters who deploy this baseline are covered on the agentic workload surface that most other published frameworks currently leave unaddressed.

### Licensing dependency

Covering agents with Conditional Access carries the following cost lines the organization should budget for. They back all four agent policies (CA-COV012 on the agent identity, and CA-COV013 through CA-COV015 on the agent user account), not just the v1.3 risk policy:

- **A Microsoft Agent 365 license for each user.** Conditional Access for agents requires Microsoft Entra ID P1 or P2 plus a Microsoft Agent 365 license per user. This is a per-user subscription cost on top of the existing Entra ID license, and it applies to every agent policy in the baseline. Microsoft has said it will begin enforcing the Agent 365 licensing requirement soon, so the organization should confirm this entitlement is purchased and assigned before it depends on the Agents or AgentUsers personas for protection. Risk-based blocking, the mechanism behind CA-COV011 and CA-COV013, requires the P2 tier of Entra ID; the allow-list (CA-COV012) and the device and network controls (CA-COV014, CA-COV015) work at P1.
- **Microsoft Intune for the compliant-device control.** CA-COV014 requires a compliant device for agent user sessions and evaluates that signal only on Intune-managed Windows 365 Cloud PCs for Agents. Budget for the Intune entitlement and the Cloud PC for Agents footprint where the digital-worker pattern is in use.
- **Microsoft Entra Internet Access for network controls.** CA-COV015 blocks agent user account sign-ins from outside the compliant network. That control requires the Microsoft Entra Internet Access subscription, and the Global Secure Access client must be installed on the endpoints in scope. This is a separate subscription and a software rollout, so plan for both the license cost and the deployment effort before committing to network-based agent controls.

## Beta endpoint commitment

The framework targets the Microsoft Graph beta endpoint for all twenty-eight policies. This is a deliberate architectural decision.

Seven policies require the beta endpoint because Microsoft has not yet completed general availability promotion of specific features:

- **CA-SIG003** (medium user risk) and **CA-SIG004** (medium sign-in risk) use `signInFrequency.frequencyInterval: "everyTime"` — a condition that enforces sign-in frequency on every session rather than on a fixed time interval. This parameter has not yet been promoted to the Microsoft Graph v1.0 endpoint.
- **CA-COV011** and **CA-COV012** (Agents persona) and **CA-COV013** through **CA-COV015** (AgentUsers persona) use the Microsoft agent condition family (the agent identity selectors, the agent user account subject, the agent execution-environments condition, and the agent risk levels) — condition types that exist only in the beta endpoint as of 2026.

For operational simplicity, all twenty-eight policies target the beta endpoint consistently rather than maintaining a split deployment with twenty-one policies at v1.0 and seven at beta. A split-endpoint deployment increases operational surface without a proportional security benefit; a single endpoint target is simpler to operate, audit, and maintain.

Microsoft Graph beta is designed to be production-capable. The documented caveat is that beta features may change before GA promotion. This framework commits to publishing a future migration to the v1.0 endpoint when Microsoft completes GA promotion of `signInFrequency: everyTime` and the agent condition family. Adopters should monitor the Microsoft Graph changelog and this repository for migration guidance.

For executive audiences: targeting the beta endpoint is not the same as running pre-release software in production. Microsoft Graph beta is the delivery channel Microsoft uses to make real, production-deployed features available before the formal GA promotion is complete. The beta-dependent conditions in this baseline are active in Microsoft-operated production environments today.

## Licensing

| Component | Required by | Note |
|---|---|---|
| Microsoft Entra ID P1 | All 28 policies (minimum) | Required for basic Conditional Access, device compliance integration, and named-location controls |
| Microsoft Entra ID P2 — Identity Protection | CA-SIG003, CA-SIG004, CA-SIG005, CA-SIG008, CA-SIG009, CA-COV011, CA-COV013 | User risk, sign-in risk, and agent risk signals; required for the risk-response policy tier on users, agent identities, and agent user accounts |
| Microsoft Entra ID P2 — Privileged Identity Management | Operational model (Section 4) | PIM activation enforces phishing-resistant MFA at role elevation; assumed in the AuthN strength model |
| Microsoft Entra ID P2 — Terms of Use | CA-SIG010 | Terms of Use feature for B2B guest consent gating. The 1:5 guest-licensing ratio applies. |
| Microsoft Entra Workload Identities Premium | CA-COV010 | Separate SKU from Entra ID P1/P2. Required for service-principal Conditional Access. |
| Microsoft Intune | CA-COV008, CA-SIG001, CA-COV014 | Required for `compliantDevice` grant control. Hybrid Azure AD join is an accepted alternative for CA-COV008 and CA-SIG001; CA-COV014 evaluates compliance on Intune-managed Windows 365 Cloud PCs for Agents. |
| Microsoft Agent 365 (per user) | CA-COV011, CA-COV012, CA-COV013, CA-COV014, CA-COV015 | Conditional Access for agents requires Entra ID P1 or P2 plus a Microsoft Agent 365 license per user, across both the Agents and AgentUsers personas. Risk-based enforcement (CA-COV011, CA-COV013) requires P2. Enforcement of the Agent 365 requirement is described as coming soon. |
| Microsoft Entra Internet Access | CA-COV015 | Required for the compliant-network block on agent user account sign-ins. Relies on the Global Secure Access client on the endpoint. Separate subscription from Entra ID P1/P2. |

If P1 is already licensed for all users, the incremental cost of this baseline covers the P2 upgrade for Identity Protection, PIM, and Terms of Use; the Workload Identities Premium SKU; the per-user Microsoft Agent 365 license for agent coverage; and Microsoft Entra Internet Access if network-based agent controls are in scope.

If P2 is not yet in place, calculate the incremental cost against the organization's Microsoft 365 agreement:

- [INSERT: CURRENT USERS AT P1 x COST-PER-USER DELTA FROM P1 TO P2]
- [INSERT: ORGANIZATION'S ESTIMATED ANNUAL BREACH-RISK EXPOSURE]
- [INSERT: ORGANIZATION'S CURRENT CYBER-INSURANCE PREMIUM]
- [INSERT: INDUSTRY AVERAGE BREACH COST FROM LATEST IBM REPORT]

These placeholders convert a directional business case into a quantified ROI specific to the organization. A template with named industry references ages better than one with specific dollar amounts that drift as annual reports are published.

## Implementation prerequisites

Before the first policy is deployed in report-only mode, the following must be in place:

- **Seven persona groups** created in Entra ID and populated: `CA-Persona-EmergencyAccess`, `CA-Persona-InternalUsers`, `CA-Persona-ServiceAccounts`, `CA-Persona-GuestUsers`, `CA-Persona-WorkloadIdentities`, and the Agents persona per `Policies/CA-EXC003-Agents-Persona.md`. Membership rules and attestation owners for each group should be documented before deployment begins.
- **Three emergency-access accounts** provisioned per `Policies/CA-EXC001-EmergencyAccess-Exclusion.md`. The sign-in alerting rule for emergency-access accounts must be configured before any policy is promoted to enforcement.
- **Three custom authentication strengths** — StandardAuth, StrongAuth, and AdminAuth — created in the tenant from the templates in `Supporting-Artifacts/`. These must exist before the AUT-series policies can be deployed.
- **Trusted Countries named location** created and tailored to the organization's approved operating geographies. Required before CA-COV007, CA-COV009, and CA-COV010 can be deployed.
- **Microsoft Entra Terms of Use agreement** published and the agreement ID captured before CA-SIG010 is deployed in report-only mode. The agreement must exist before the policy can resolve the grant control.
- **Agent ID inventory** completed per `Policies/CA-EXC003-Agents-Persona.md` before CA-COV011 is deployed. Understanding which Agent IDs exist and what permissions they hold is a prerequisite for a clean CA-COV011 report-only soak.
- **PowerShell 7.0 or later** and the **`Microsoft.Graph.Authentication` module** installed on the deployer workstation. No other Graph SDK module is required.
- **Intune device compliance baseline** (or hybrid Azure AD join coverage) confirmed before CA-COV008 and CA-SIG001 are promoted to enforcement. The compliant-device grant control requires a device compliance policy in Intune to signal into Conditional Access.

## Operational cost estimate

Annualized hours required to maintain the baseline at steady state after the phased deployment is complete:

| Activity | Frequency | Hours per cycle | Annual total |
|---|---|---|---|
| Persona-group attestation | Quarterly | 4 hours | 16 hours |
| Emergency-access recovery drill | Quarterly | 2 hours | 8 hours |
| ServiceAccounts geography review | Monthly | 1 hour | 12 hours |
| Agents persona Agent ID risk-event review | Monthly | 2 hours | 24 hours |
| Admin-context risk review | Monthly | 1 hour | 12 hours |
| Risk-detection tuning | Quarterly | 4 hours | 16 hours |
| Trusted IPs named-location refresh (CI runner egress changes) | Quarterly | 4 hours where applicable | 16 hours |
| Terms of Use version refresh and re-consent monitoring | Quarterly | 2 hours | 8 hours |

**Total at steady state: approximately 112 hours per year.**

This is up from the v1.2 estimate of approximately 52 hours per year. The increase is driven by three v1.3 additions:

- The **Agents persona monthly risk-event review** (24 hours per year) is new. The v1.2 baseline had no Agents persona and no corresponding review cadence.
- The **Workload Identities Trusted IPs refresh cadence** (16 hours per year) is formalized in v1.3. This operational activity existed informally in v1.2 but was not measured separately in the estimate.
- The **Terms of Use lifecycle management** (8 hours per year) is new with CA-SIG010. Re-consent monitoring and periodic agreement version refresh are non-trivial operational activities once a Terms of Use gate is in production.

For organizations with dedicated security operations, this effort can be absorbed into existing quarterly security review cadences. For smaller organizations, 112 hours represents approximately two to three days of security-architect time per quarter.

## Compliance mapping

This baseline supports the access control requirements in major compliance frameworks. The mapping below reflects the v1.4 policy surface. Organizations should validate specific control numbers against current framework revisions with their audit team.

| Framework | Control | How this baseline supports it |
|---|---|---|
| SOC 2 | CC6.1 (Logical Access Controls) | CA-COV002, CA-COV008, CA-SIG001, CA-SIG008, and CA-SIG009 enforce authentication, authorization, and access restriction based on identity and context |
| SOC 2 | CC6.6 (Boundary Protection) | CA-COV007 (BlockByLocation), CA-COV009 (ServiceAccounts trusted locations), and CA-COV010 (WorkloadIdentities trusted locations) gate access by geography and network boundary |
| SOC 2 | CC6.7 (Privileged Access) | CA-AUT003 requires AdminAuth (FIDO2 only) on admin portals; CA-SIG005 hard-blocks admin sign-ins at medium and high risk |
| ISO 27001 | A.5.16 (Identity management) | CA-AUT001 and CA-AUT002 enforce authentication strength at device and security info registration; CA-COV002 ensures no identity authenticates with a password alone |
| ISO 27001 | A.5.17 (Authentication information) | The graduated strength model (StandardAuth, StrongAuth, AdminAuth) formalizes authentication quality by context and risk level |
| HIPAA | §164.312(a)(2)(i) (Unique user identification) | CA-COV002 and CA-SIG002 enforce MFA for every identity accessing resources, supporting person-level identification assurance |
| PCI-DSS | 8.4.2 (Strong cryptography for non-console admin) | CA-AUT003 requires FIDO2-only (AdminAuth) for admin portal sign-ins — the non-console admin surface in Microsoft 365 |
| NIST SP 800-53 | AC-2 (Account management) | CA-AUT001 and CA-AUT002 apply authentication controls at the account provisioning moments (device enrollment and security info registration) |
| NIST SP 800-53 | IA-2 (Identification and Authentication) | CA-COV002 combined with the graduated authentication strength model satisfies IA-2 requirements for both users and privileged users |

Beyond compliance, this baseline satisfies the identity-related controls that cyber-insurance carriers increasingly require as a precondition for favorable premium pricing or coverage. MFA for all users, phishing-resistant MFA for privileged access, device compliance requirements, and risk-based access controls are among the controls carriers most frequently ask about in underwriting questionnaires.

## Recommended investment approach

### Phase 1 — Foundation (weeks 1 to 4)

Create the seven persona groups and populate them per the membership rules in `Design/POLICY-DESIGN.md` Section 3. Provision three emergency-access accounts and configure the sign-in alerting rule per `Policies/CA-EXC001-EmergencyAccess-Exclusion.md`. Create the three custom authentication strengths (StandardAuth, StrongAuth, AdminAuth) from the templates in `Supporting-Artifacts/`. Create the Trusted Countries named location and tailor it to the organization's approved operating geographies. Publish the Microsoft Entra Terms of Use agreement and capture the agreement ID for CA-SIG010. Run the Agent ID inventory per `Policies/CA-EXC003-Agents-Persona.md` before adopting the Agents persona.

### Phase 2 — Coverage (weeks 5 to 8)

Deploy CA-COV001 through CA-COV007 plus CA-AUT001 and CA-AUT002 in report-only mode. Soak each policy for a minimum of seven to fourteen days. Remediate findings: users without MFA, services using legacy auth, service accounts authenticating from unregistered geographies. Begin the MFA registration campaign for the full user population. Promote Phase 2 policies to enforcement after the soak window closes clean.

### Phase 3 — Persona-specific (weeks 9 to 12)

Deploy persona-specific policies in report-only mode: Internal persona (CA-COV008, CA-SIG007), Admins persona (CA-AUT003, CA-SIG005), Guests persona (CA-SIG002, CA-SIG006, CA-SIG010), ServiceAccounts persona (CA-COV009), WorkloadIdentities persona (CA-COV010), Agents persona (CA-COV011, CA-COV012), and AgentUsers persona (CA-COV013, CA-COV014, CA-COV015). Inventory Token Protection client compatibility — Windows build and modern auth confirmed — before the CA-SIG007 soak. Complete the phishing-resistant method rollout to privileged users before CA-AUT003 enforcement. Soak each policy for a minimum of seven to fourteen days.

### Phase 4 — Risk and Token Protection (weeks 13 to 16)

Deploy the risk policies — CA-SIG003, CA-SIG004, CA-SIG008, CA-SIG009 — and the Sensitive-Applications scope policy CA-SIG001, all in report-only mode. Layer Token Protection per `Design/CAE-TOKEN-PROTECTION-LAYERING.md`. Use `Scripts/Get-CABaselineImpact.ps1` to quantify what each risk policy would have blocked over the soak period. Soak for a minimum of fourteen days before promoting risk policies to enforcement; a longer soak is recommended for CA-SIG008 and CA-SIG009 (the high-risk hard-blocks) to confirm false-positive rates are acceptable.

### Phase 5 — Enforcement promotion (weeks 17 to 20)

Promote all remaining report-only policies to enforcement on the documented soak-completion schedule. Pair with the Intune Compliance Baseline rollout per `Design/CA-ICB-INTEGRATION.md` to ensure that the compliant-device signal that CA-COV008 and CA-SIG001 depend on is clean before enforcement decisions are made. Establish the quarterly review cadence described in the Operational cost estimate section. Declare the v1.4 baseline deployment complete.

Total: a twenty-week phased rollout. Up from the v1.2 estimate of twelve weeks. The extension is driven by the Agents persona soak and Agent ID inventory, the Workload Identities Trusted IPs initial setup and SPN scoping exercise, and the additional enforcement-promotion phase the larger v1.4 surface requires.

## References

- Verizon. *Data Breach Investigations Report* (annual).
- IBM Security. *Cost of a Data Breach Report* (annual).
- Microsoft. *Microsoft Digital Defense Report* (annual).
- Microsoft Learn. [Conditional Access architecture](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies).
- Microsoft Learn. [Authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths).
- Microsoft Learn. [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation).
- Microsoft Learn. [Token Protection](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection).
- Microsoft Learn. [Conditional Access API reference (beta)](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy?view=graph-rest-beta).
- Cloud Harbor Consulting. [Why Entra ID Conditional Access Fails in Practice (And How to Fix It)](https://www.cloudharborconsulting.cloud/post/why-entra-id-conditional-access-fails-in-practice-and-how-to-fix-it).
- Cloud Harbor Consulting. `Design/POLICY-DESIGN.md` — full per-policy design specifications, exclusion rationale, and rollout sequence.
- Cloud Harbor Consulting. `Design/AGENTS-PERSONA-MODEL.md` — Microsoft Agent ID technical overview, risk signal model, CA-COV011 mechanics, and beta endpoint commitment.
- Cloud Harbor Consulting. `Design/CAE-TOKEN-PROTECTION-LAYERING.md` — Continuous Access Evaluation and Token Protection layering analysis, client matrix, and soak procedure.
- Cloud Harbor Consulting. `Design/WORKLOAD-IDENTITY-IP-PATTERNS.md` — workload identity IP allow-listing patterns, CI/CD runner egress management, and rollback procedure.
- Cloud Harbor Consulting. `Design/CA-ICB-INTEGRATION.md` — Conditional Access and Intune Compliance Baseline cross-framework integration: signal flow, failure-mode matrix, and rollout sequence.

## Acknowledgments

This framework was shaped by the public work of Joey Verlinden, Daniel Chronlund, and Claus Jespersen on Conditional Access design patterns. Their published guidance on persona-based scoping, exclusion contract governance, and authentication strength selection provided the conceptual foundation for this baseline.

The v1.3 redirection — including the Agents persona introduction, the all-beta endpoint commitment, the graduated authentication strength enforcement model, and the four new design documents — was developed by the Cloud Harbor Consulting team.
