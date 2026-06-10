# Agents Persona Model — Design Document

**Framework:** Conditional Access Baseline v1.4
**Status:** Preview — v1.4.0
**Endpoint dependency:** Microsoft Graph beta (all Agent ID condition fields; GA promotion tracked below)

---

## 1. Introduction

The Conditional Access Baseline has always distinguished between identity classes. Users, guests, service accounts, workload identities, and emergency access accounts each authenticate differently and carry different risk profiles. The baseline treats each as a distinct persona with its own policy lane.

Agentic AI workloads (Microsoft 365 Copilot agents, Azure AI agents, and custom agents built on the Microsoft Copilot extensibility stack) introduce identity behavior that is not a user, not a service principal, and not a managed identity. Microsoft Agent ID is the principal type that Entra ID surfaces for these workloads. An agent does not authenticate one single way, though. Microsoft documents three distinct agent access patterns, and each carries a different token subject and therefore a different Conditional Access targeting model. This document replaces the earlier single-class framing of the Agents persona with that three-pattern model.

This document explains why agents need their own Conditional Access treatment, what Microsoft Agent ID is technically, the three agent access patterns and the token subject each carries, how Microsoft Identity Protection generates risk signals for Agent IDs, how the `CA-COV011-Agents-BlockMediumAndHighRisk` policy works mechanically, and what the framework's commitment is while the feature remains in beta.

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

### The three agent access patterns

An agent does not have one fixed authentication model. Microsoft documents three access patterns, and the difference that matters for Conditional Access is the token subject each one produces. The token subject determines which targeting model reaches the sign-in. An earlier version of this framework treated agents as a single identity class targeted only through agent identity conditions. That framing covered one of the three patterns and left the other two unaddressed. The three patterns are:

**Pattern 1, on-behalf-of (delegated).** A user signs into the agent, and the agent exchanges tokens through the OAuth 2.0 On-Behalf-Of flow to reach downstream resources. The token subject is the user. Conditional Access therefore targets users and groups, not agent identities. A policy that targets the agent identity does not see this flow at all; it is evaluated as a user sign-in against the user-targeted policy set.

**Pattern 2, application-only (client credentials, autonomous).** The agent authenticates with its own identity using the client credentials flow, with no user present. The token subject is the agent identity. Conditional Access targets the agent identity through `includeAgentIdServicePrincipals` together with the agent application bundle. This is the pattern the baseline addresses today, via `CA-COV011-Agents-BlockMediumAndHighRisk`.

**Pattern 3, agent acting as a user (agent user account, digital worker).** The agent is provisioned with its own user account, including a mailbox and group membership, and acts as a distinct digital worker. The token subject is the agent user account, which is a separate identity sub-class from the agent identity. Conditional Access targets agent users through the All agent users target (Preview). Coverage for this sub-class is planned for a later PR in the v1.4 series and is not addressed by `CA-COV011`.

The three patterns map to three token subjects and three targeting models:

| Access pattern | Token subject | Conditional Access targeting |
|---|---|---|
| On-behalf-of (delegated) | User | Users and groups |
| Application-only (autonomous) | Agent identity | `includeAgentIdServicePrincipals` plus the agent application bundle |
| Agent acting as a user (digital worker) | Agent user account | Agent users (All agent users, Preview) |

### Limitations of the targeting models

The three targeting models do not overlap, and Microsoft documents specific gaps that an adopter must account for:

- A policy targeting all users does not include agent user accounts. A broad user policy leaves the agent user account uncovered.
- Agent user accounts cannot be scoped by group membership. The group-based persona pattern used elsewhere in this baseline does not apply to them.
- A policy targeting agent identities does not apply to the agent user account. The application-only targeting model reaches Pattern 2 only.
- Agent identity blueprint targeting covers the agent identity, not the agent user account.

These limitations are the reason the baseline addresses the application-only pattern first and treats the agent user account as a separate coverage item. See <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id>.

### Boundaries and limitations

Beyond the targeting gaps above, Microsoft documents authentication surfaces where Conditional Access for agents does not apply at all. The full set of documented boundaries is:

- A policy targeting all users does not include agent user accounts.
- Agent user accounts cannot be scoped by group membership.
- A policy targeting agent identities does not apply to the agent user account.
- Agent identity blueprint targeting covers the agent identity, not the agent user account.
- Conditional Access does not apply at the Microsoft Entra Token Exchange Endpoint.
- Conditional Access does not apply to blueprint token acquisition for creating agents.
- Conditional Access does not apply when Security Defaults are enabled. Security Defaults disables Conditional Access for agents.
- Conditional Access does not apply to API-key access.

When investigating whether an agent policy applied to a given sign-in, filter the Microsoft Entra sign-in logs on the `agentType` field to isolate agent entries from user and service principal sign-ins. The `agentType` field is confirmed, but its enumerated values are not published, so confirm the value list in-tenant. See <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id>.

---

## 3. Identity Protection signal model for Agent IDs

### The `agentIdRiskLevels` condition

`agentIdRiskLevels` is a Conditional Access condition that evaluates the risk level Microsoft Identity Protection has assigned to an Agent ID principal at the time of an authentication request. The condition accepts the same risk level values as `userRiskLevels` and `signInRiskLevels`: `low`, `medium`, `high`, `hidden`, and `none`.

In `CA-COV011`, the condition is set to `"medium,high"` — meaning the policy evaluates when Microsoft Identity Protection has raised the agent's risk level to medium or high. A `none` or `low` risk level results in the policy not applying to that authentication event.

**Deviation from Microsoft's recommendation.** Microsoft recommends `agentIdRiskLevels = high` for agent-identity policies. CA-COV011 deliberately blocks at `medium,high` instead. This is a stricter-than-recommended CHC posture: blocking at medium catches a compromised or misbehaving agent one risk tier earlier, accepting a higher rate of report-only signals during the soak in exchange for earlier enforcement coverage. The stricter setting is the default. An adopter who prefers to align with Microsoft's recommendation can set `agentIdRiskLevels` to `high` in the CA-COV011 template and rename the policy accordingly.

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

This condition targets all Agent ID principals in the tenant. It is the Agent ID equivalent of `clientApplications.includeServicePrincipals: ["All"]` for service principals. Using `"All"` in CA-COV011 ensures every provisioned Agent ID is in scope. `"All"` is not the only available target, however: Microsoft documents selecting specific agents three ways — the enhanced object picker (tabs All, Agent blueprint principals, and Agent identities), individual agent identities by object ID, and custom security attributes via the `agentIdServicePrincipalFilter` rule (grammar `CustomSecurityAttribute.<Set>_<Attribute> -eq "<value>"`, with `mode` include or exclude). The verified attribute scheme is the `AgentIdAttributes` set with the String attribute `AgentIdApprovedForUse` matched with the `-eq` operator. These selection and exclusion methods are what `CA-COV012-Agents-AllowOnlyApprovedAgents` uses to express an allow-only posture: include all agents, exclude the approved set by filter, block. The enhanced object picker and individual selection require the Conditional Access Administrator role; the custom security attribute method additionally requires the Attribute Assignment Reader role. See `Policies/CA-COV012-Agents-AllowOnlyApprovedAgents.md`.

**`conditions.users.includeUsers: ["None"]`**

Agent IDs do not authenticate as users. Setting `includeUsers` to `["None"]` explicitly excludes the user authentication path from this policy's scope. The policy targets the agent authentication path only, via the `clientApplications.includeAgentIdServicePrincipals` condition. Without this `None` setting, the policy might inadvertently evaluate against user authentications in some edge cases.

**`grantControls.builtInControls: ["block"]`**

When the risk threshold is met, the response is a hard block. Agent IDs cannot satisfy interactive MFA, authentication strength, or device compliance grant controls — they have no human to respond to a challenge. Block is the only enforceable grant control for non-human principals. This mirrors the approach used for service accounts (CA-COV009) and workload identities (CA-COV010).

---

## 5. Rollout recommendation

### Licensing prerequisites

Conditional Access for agents requires Microsoft Entra ID P1 or P2 plus a Microsoft Agent 365 license for each user. Microsoft describes enforcement of the Agent 365 licensing requirement as coming soon, so confirm the per-user Agent 365 entitlement is in place before you rely on this persona. Risk-based enforcement for agents through Microsoft Identity Protection, including the `agentIdRiskLevels` signal that CA-COV011 evaluates, requires Entra ID P2.

Network controls for agents require Microsoft Entra Internet Access. The compliant-network grant relies on the Global Secure Access client being present on the endpoint. License Microsoft Entra Internet Access and deploy the Global Secure Access client before you add a compliant-network condition to an agent policy.

Creating and managing these policies requires the Conditional Access Administrator role. The custom-security-attribute targeting method also requires the Attribute Assignment Reader role so the administrator can read the attribute values used to scope the policy.

See <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id> and <https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-autonomous-agents>.

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

Every agent-specific Conditional Access field is Microsoft Graph beta-only. None is present on the v1.0 endpoint, and each is labelled Preview in the Entra admin center portal. The table below records the verified field set as of the 2026-06-03 Conditional Access for Agents documentation refresh, confirmed against the Microsoft Graph `conditionalAccessConditionSet` and `conditionalAccessClientApplications` reference pages.

| Agent field | JSON property | Beta-only | Portal Preview | Tenant-verified | Source |
|---|---|---|---|---|---|
| Agent identity risk level condition | `conditionalAccessConditionSet.agentIdRiskLevels` | Yes | Yes | Yes | <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id> and the Microsoft Graph `conditionalAccessConditionSet` reference |
| Include agent identity service principals | `conditionalAccessClientApplications.includeAgentIdServicePrincipals` (including the `"All"` value) | Yes | Yes | Yes | Raw Graph beta export (`GET /beta/policies/conditionalAccessPolicies`) and the Microsoft Graph `conditionalAccessClientApplications` reference |
| Exclude agent identity service principals | `conditionalAccessClientApplications.excludeAgentIdServicePrincipals` | Yes | Yes | Yes | Microsoft Graph `conditionalAccessClientApplications` reference |
| Agent identity service principal filter | `conditionalAccessClientApplications.agentIdServicePrincipalFilter` (rule grammar `CustomSecurityAttribute.<Set>_<Attribute> -eq "<value>"`, `mode` include/exclude) | Yes | Yes | Yes | Raw Graph beta export (`GET /beta/policies/conditionalAccessPolicies`) and the Microsoft Graph `conditionalAccessClientApplications` reference |
| Agent user subject | `conditionalAccessConditionSet.agents` (`includeAgentUsers`, `excludeAgentUsers`, `agentFilter`) | Yes | Yes | Yes | Raw Graph beta export (`GET /beta/policies/conditionalAccessPolicies`) |
| Agent execution environments condition | `conditionalAccessConditionSet.agentContext.includeAgentContexts` (value `agentUserSessionsInitiatedFromEndpoints`) | Yes | Yes | Yes | Raw Graph beta export (`GET /beta/policies/conditionalAccessPolicies`) |
| Agent application bundle | `conditions.applications.includeApplications` value `AllAgentIdResources` | Yes | Yes | Yes | Raw Graph beta export (`GET /beta/policies/conditionalAccessPolicies`) |

`agentIdRiskLevels` is the correct property name (it is not `agentRiskLevels`). It is multivalued and accepts `low`, `medium`, `high`, and `unknownFutureValue`. The v1.0 `conditionalAccessConditionSet` has no agent-risk property at all. Microsoft recommends `agentIdRiskLevels = high` for agent-identity policies, and `medium` and `high` for agent-user policies.

**Tenant-verified field shapes.** The shapes above were confirmed against raw Microsoft Graph beta exports (`GET /beta/policies/conditionalAccessPolicies`): the `includeAgentIdServicePrincipals` `"All"` value, the `agentIdServicePrincipalFilter` object and its `CustomSecurityAttribute.<Set>_<Attribute> -eq "<value>"` rule grammar, the `conditions.agents` agent-user subject (`includeAgentUsers`, `excludeAgentUsers`, `agentFilter`), the `conditions.agentContext.includeAgentContexts` execution-environments condition (value `agentUserSessionsInitiatedFromEndpoints`), and the `AllAgentIdResources` application bundle.

**Not yet published in the Graph reference (confirm-in-tenant pending GA):** the following is referenced in the Conditional Access for Agents documentation but is not yet typed in the Microsoft Graph reference, so this framework treats it as a confirm-in-tenant value that an adopter must validate against the live tenant before enforcement:

- Agent identity blueprint targeting.

The baseline framework targets the beta endpoint (`https://graph.microsoft.com/beta/identity/conditionalAccess/policies`) for all 28 policies to avoid conditional endpoint logic in the deployer. Splitting the policy set between v1.0 and beta endpoints would require maintaining two deployer code paths, two sets of test fixtures, and runtime logic to decide which endpoint applies to which policy.

**GA promotion tracking:** When Microsoft promotes the agent fields above to the v1.0 Graph API, this framework will flip the deployer endpoint to v1.0 as a single change. That change will be documented in the CHANGELOG and will not require updates to any policy JSON template, because the conditions use the same field names in both beta and v1.0. The unpublished `AllAgentIdResources` bundle and `includeAgentIdServicePrincipals` `"All"` token will be reconciled against the published reference at that time.

Watch the Microsoft Graph Conditional Access API changelog for the GA promotion announcement. The Microsoft Graph `conditionalAccessConditionSet` and `conditionalAccessClientApplications` reference pages are the authoritative sources, alongside <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id> and <https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-autonomous-agents>.

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
