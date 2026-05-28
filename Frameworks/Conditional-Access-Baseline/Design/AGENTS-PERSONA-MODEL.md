# Agents Persona Model — Design Document

**Framework:** Conditional Access Baseline v1.3
**Status:** Preview — v1.3.0-rc.1
**Endpoint dependency:** Microsoft Graph beta (all Agent ID condition fields; GA promotion tracked below)

---

## 1. Introduction

The Conditional Access Baseline has always distinguished between identity classes. Users, guests, service accounts, workload identities, and emergency access accounts each authenticate differently and carry different risk profiles. The baseline treats each as a distinct persona with its own policy lane.

Agentic AI workloads — Microsoft 365 Copilot agents, Azure AI agents, and custom agents built on the Microsoft Copilot extensibility stack — introduce an identity class that is not a user, not a service principal, and not a managed identity. It is a Microsoft Agent ID: a new principal type that Microsoft introduced alongside its agentic AI platform and that Entra ID now surfaces as a first-class identity.

This document explains why Agent IDs need their own Conditional Access lane, what Microsoft Agent ID is technically, how Microsoft Identity Protection generates risk signals for Agent IDs, how the `CA-COV011-Agents-BlockMediumAndHighRisk` policy works mechanically, and what the framework's commitment is while the feature remains in beta.

---

## 2. Microsoft Agent ID overview

### What it is

Microsoft Agent ID is a principal type provisioned through the Microsoft Agent framework in Entra ID. An Agent ID represents an agentic AI workload — an autonomous software component that can receive instructions, call Microsoft Graph APIs, access Microsoft 365 data, and act on behalf of a tenant without a human present at each step.

Agent IDs are provisioned via the Microsoft Agent framework API or through the Microsoft 365 admin center's Copilot management surface. Once provisioned, an Agent ID appears in the tenant's Entra ID directory and is subject to Conditional Access policies that target the `AllAgentIdResources` application bundle and the `IncludeAgentIdServicePrincipals` condition.

### How it differs from service principals

| Dimension | Service Principal | Microsoft Agent ID |
|---|---|---|
| Provisioning path | App registration or managed identity | Microsoft Agent framework / Copilot admin surface |
| Authentication surface | Client secret, certificate, or managed identity token | Agent framework credentials via Entra |
| Graph API surface | `/servicePrincipals` endpoint | Agent-specific beta endpoints |
| CA targeting condition | `clientApplications.includeServicePrincipals` | `clientApplications.includeAgentIdServicePrincipals` |
| Application scope in CA | App registration ID or `AllApplications` | `AllAgentIdResources` |
| Risk signals | `servicePrincipalRiskLevels` | `agentIdRiskLevels` |
| Group membership model | Standard Entra group | Not exposed via standard group API (as of May 2026) |
| Permissions model | App roles, delegated permissions | Agent-specific permission model |

The key operational implication: you cannot cover Agent IDs by adding them to a service principal exclude group, by targeting them via a `clientApplications` policy that uses `IncludeServicePrincipals`, or by including them in the `CA-Persona-WorkloadIdentities` group. They are a separate principal type that requires their own CA conditions.

### How it differs from managed identities

A managed identity is a system-assigned or user-assigned identity attached to an Azure resource (a virtual machine, a function app, a container instance). It authenticates via the Azure Instance Metadata Service (IMDS) token endpoint. Managed identities are a subtype of service principal and appear in the `servicePrincipals` Graph endpoint.

A Microsoft Agent ID is not attached to an Azure resource. It is provisioned as an agent workload identity in Entra ID and authenticates through the Microsoft Agent framework runtime, not via IMDS. The two are operationally separate even though both represent non-human authentication.

### Why Microsoft introduced it

The introduction of Agent IDs reflects a platform-level design decision by Microsoft: agentic AI workloads require identity governance separate from both human users and traditional automation (service principals, managed identities). Agents operate in a more autonomous, instruction-following mode than traditional automation. They can be directed by user-provided prompts, which creates a prompt injection threat surface that does not exist for traditional service principals. Microsoft has introduced `agentIdRiskLevels` as a risk condition specifically because the threat model for agents — particularly prompt injection and credential misuse — is meaningfully different from the threat model for traditional workload identities.

---

## 3. Identity Protection signal model for Agent IDs

### The `agentIdRiskLevels` condition

`agentIdRiskLevels` is a Conditional Access condition that evaluates the risk level Microsoft Identity Protection has assigned to an Agent ID principal at the time of an authentication request. The condition accepts the same risk level values as `userRiskLevels` and `signInRiskLevels`: `low`, `medium`, `high`, `hidden`, and `none`.

In `CA-COV011`, the condition is set to `"medium,high"` — meaning the policy evaluates when Microsoft Identity Protection has raised the agent's risk level to medium or high. A `none` or `low` risk level results in the policy not applying to that authentication event.

### How Microsoft populates `agentIdRiskLevels`

Microsoft Identity Protection generates agent risk detections based on signals that are specific to agentic workloads:

- **Unusual agent behavior patterns.** An agent that suddenly begins accessing APIs it has never called, or accessing an unusually broad range of mailboxes or SharePoint sites, generates a behavioral anomaly detection.
- **Anomalous authentication origin.** An agent authenticating from an IP or region outside its historical pattern — similar to the impossible-travel detection for users — generates a location-based risk detection.
- **Credential misuse indicators.** Signs that the agent's credentials have been extracted and replayed outside the normal agent runtime generate credential-theft risk detections.
- **Prompt injection indicators.** Where Microsoft can detect that an agent received instructions via injected content (rather than legitimate user prompts), this is surfaced as a risk signal.

Risk detections are available in the Microsoft Entra admin center under Protection → Identity Protection → Risk detections, filtered by principal type. They are also queryable via the Microsoft Graph beta `identityProtection/riskyServicePrincipals` endpoint (noting that Agent IDs surface via this endpoint while the dedicated Agent ID endpoints are in development).

### Risk signal latency

Agent ID risk signals follow the same near-real-time propagation model as user risk signals in Identity Protection. When Microsoft detects a risk event, the `agentIdRiskLevels` value is updated within minutes, and a Conditional Access policy evaluating that condition will reflect the updated risk level on the next authentication from the affected Agent ID.

---

## 4. Policy scope mechanics

### CA-COV011-Agents-BlockMediumAndHighRisk

The policy applies three conditions to scope it to Agent ID authentication:

**`conditions.agentIdRiskLevels: "medium,high"`**

Limits evaluation to authentication events where Microsoft Identity Protection has raised the agent's risk level to medium or high. At `none` or `low`, the policy does not apply and the authentication proceeds subject to other policies (or no policy, if no other policy targets agents).

**`conditions.applications.includeApplications: ["AllAgentIdResources"]`**

`AllAgentIdResources` is an application bundle identifier (similar to `Office365`) that Microsoft has defined to cover all Microsoft services accessible by Agent IDs. Using this bundle ensures the policy covers all Agent ID authentication flows against Microsoft resources without requiring enumeration of individual application IDs.

**`conditions.clientApplications.includeAgentIdServicePrincipals: ["All"]`**

This condition targets all Agent ID principals in the tenant. It is the Agent ID equivalent of `clientApplications.includeServicePrincipals: ["All"]` for service principals. Using `"All"` ensures every provisioned Agent ID is in scope; there is no per-agent inclusion list to maintain.

**`conditions.users.includeUsers: ["None"]`**

Agent IDs do not authenticate as users. Setting `includeUsers` to `["None"]` explicitly excludes the user authentication path from this policy's scope. The policy targets the agent authentication path only, via the `clientApplications.includeAgentIdServicePrincipals` condition. Without this `None` setting, the policy might inadvertently evaluate against user authentications in some edge cases.

**`grantControls.builtInControls: ["block"]`**

When the risk threshold is met, the response is a hard block. Agent IDs cannot satisfy interactive MFA, authentication strength, or device compliance grant controls — they have no human to respond to a challenge. Block is the only enforceable grant control for non-human principals. This mirrors the approach used for service accounts (CA-COV009) and workload identities (CA-COV010).

---

## 5. Rollout recommendation

### Pre-deployment inventory

Before deploying CA-COV011 in any state, inventory the Agent IDs provisioned in the tenant:

```powershell
Connect-MgGraph -Scopes "AgentId.Read.All"
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/agentIds"
```

If the tenant has no Agent IDs, CA-COV011 will evaluate with zero matches in report-only mode. This is safe and produces no user impact, but means the policy is producing no signal — it can be deferred until Agent IDs are provisioned.

If the tenant has Agent IDs, capture the list, confirm ownership for each, and verify that each Agent ID's production behavior is understood before enforcement.

### 14-day report-only soak

Deploy CA-COV011 in `enabledForReportingButNotEnforced` state (the default) for a minimum of 14 days. During the soak:

- Monitor the Entra sign-in logs filtered to Agent ID authentication events and the CA-COV011 policy
- Review any `reportOnlyFailure` results — these are Agent IDs that would have been blocked. Investigate whether the risk detection is accurate before enforcement
- Confirm that no human-targeted sign-ins are inadvertently appearing as CA-COV011 evaluations (the `includeUsers: None` condition should prevent this, but verify)

### False positive handling

Agent ID risk detections are a newer signal class. False positives are possible, particularly in the early adoption period. If a legitimate Agent ID is flagged at medium or high risk:

1. Confirm the detection in the Microsoft Entra admin center
2. If it is a confirmed false positive, dismiss the risk via the Identity Protection console
3. File a report with Microsoft via the Microsoft 365 admin center feedback mechanism
4. Document the false positive in the quarterly Agent ID inventory record

Do not disable CA-COV011 to unblock a falsely flagged Agent ID. Use the Identity Protection dismissal mechanism, which resets the risk level and allows the policy to pass on subsequent authentications.

### Enforcement promotion

After the 14-day soak, if the report-only output shows:

- `reportOnlySuccess` only (no medium/high risk signals): safe to promote, but the policy provides no active protection yet — confirm that Identity Protection is running and generating signals
- `reportOnlyFailure` for a known legitimate Agent ID: investigate before promoting; may indicate a legitimate risk event requiring remediation, or a false positive requiring dismissal
- `reportOnlyFailure` for an unknown or orphaned Agent ID: the Agent ID should be reviewed and potentially disabled before enforcement

---

## 6. Beta endpoint commitment

As of May 2026, all Agent ID condition fields used in CA-COV011 are Microsoft Graph beta-only:

| Field | Status | Source |
|---|---|---|
| `conditions.agentIdRiskLevels` | Beta only | Microsoft Learn v1.0 conditionalAccessConditionSet refresh dated 12/02/2025 |
| `conditions.clientApplications.includeAgentIdServicePrincipals` | Beta only | Same source |
| `conditions.applications.includeApplications: ["AllAgentIdResources"]` | Beta only | Same source |

The baseline framework targets the beta endpoint (`https://graph.microsoft.com/beta/identity/conditionalAccess/policies`) for all 23 policies to avoid conditional endpoint logic in the deployer. Splitting the policy set between v1.0 and beta endpoints would require maintaining two deployer code paths, two sets of test fixtures, and runtime logic to decide which endpoint applies to which policy.

**GA promotion tracking:** When Microsoft promotes `agentIdRiskLevels`, `includeAgentIdServicePrincipals`, and `AllAgentIdResources` to the v1.0 Graph API, this framework will flip the deployer endpoint to v1.0 as a single change. That change will be documented in the CHANGELOG and will not require updates to any policy JSON template — the conditions use the same field names in both beta and v1.0.

Watch the Microsoft Graph Conditional Access API changelog for the GA promotion announcement. The Microsoft Learn conditional access API reference page for `conditionalAccessConditionSet` is the authoritative source.

---

## 7. Trade-offs

### What Agent ID conditional access covers

CA-COV011 provides risk-based enforcement at the medium and high risk threshold. When Microsoft Identity Protection detects that an Agent ID has reached medium or high risk, subsequent authentication from that Agent ID is blocked until the risk is dismissed or remediated.

### What it does not cover

**Below-threshold activity.** Agent IDs operating at `none` or `low` risk are not constrained by CA-COV011. If an agent is engaged in low-level exfiltration that does not trigger a medium risk detection, the policy does not see it. This gap is shared by all risk-based CA policies and is a function of Identity Protection's detection sensitivity.

**Out-of-band communication channels.** An agent that exfiltrates data via a side channel — writing to an external storage account, sending Teams messages to an attacker-controlled external user, using authenticated graph calls that are not surfaced as a risk signal — is outside the scope of this policy. Monitoring those channels requires separate telemetry (Microsoft Purview audit logs, Defender XDR hunt queries, Data Loss Prevention policies).

**Pre-authentication agent provisioning.** The provisioning of an Agent ID — including the assignment of permissions scopes — happens before CA policy evaluation. CA policies cannot prevent an over-privileged Agent ID from being provisioned. Least-privilege Agent ID provisioning is an administrative control, not a Conditional Access control.

**Agents acting under user delegation.** If an agent authenticates under a user's delegated context (OAuth 2.0 On-Behalf-Of flow with a user access token), the sign-in is surfaced as a user sign-in and evaluated against user-targeted CA policies, not CA-COV011. CA-COV011 only evaluates agent authentication flows, not delegated user flows.

---

## 8. Cross-framework future hooks

**Defender XDR Detection Rules framework (planned Q1 2027):** The planned Defender XDR Detection Rules framework will ship hunt queries targeting Agent ID risk signals, including cross-correlation between `agentIdRiskLevels` events and Microsoft Purview audit events for data access patterns. This will provide a detection layer below the CA medium/high threshold — surfacing low-level agent anomalies that Identity Protection has not yet elevated to medium risk. The CA-COV011 policy and the Defender XDR hunt queries will be documented as complementary layers in that framework's cross-framework integration section.

**Workload Identity IP Allow-Listing Patterns (PR 4):** PR 4 of the v1.3 series will add `Design/WORKLOAD-IDENTITY-IP-PATTERNS.md`, documenting egress-based controls for service principals via CA-COV010. That document will include a section on the distinction between workload identity egress controls and agent-specific controls — specifically, why IP-based allow-listing is a useful compensating control for service principals but is less applicable to Agent IDs (which may authenticate from dynamic Microsoft-managed infrastructure rather than customer-controlled egress).

**CA-ICB Integration (PR 5):** PR 5 will add `Design/CA-ICB-INTEGRATION.md`, documenting the signal handoff between the Conditional Access Baseline and the Intune Compliance Baseline. The Agent ID identity class is currently out of scope for device compliance signals (Agent IDs do not have device attributes). This will be documented as an explicit out-of-scope item in the CA-ICB integration document.
