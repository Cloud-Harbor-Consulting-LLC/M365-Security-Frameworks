# CA-EXC003 — Agents Persona

**Type:** Documentation / operational contract
**Status:** Required for any baseline deployment that includes the Agents persona (tenants with Microsoft Agent ID provisioned)
**Persona:** Agents (Microsoft Agent ID)
**Replaces deployable template:** No — this is a written contract establishing the Agents persona as a first-class identity class in the Conditional Access Baseline. Targeting is enforced via application-side filters in `CA-COV011-Agents-BlockMediumAndHighRisk`.

---

## Purpose

Microsoft Agent ID is a distinct identity class introduced for agentic AI workloads, including Microsoft 365 Copilot agents and custom agents built on the Azure OpenAI or Microsoft Copilot extensibility stack. Agent IDs carry Entra-issued credentials but authenticate differently from both interactive users and traditional service principals or managed identities.

The Agents persona exists in this baseline for three reasons:

**1. Agents cannot be covered by user-targeted policies.** Human-facing policies (CA-COV001 through CA-COV009, CA-SIG001 through CA-SIG006, CA-SIG008, CA-SIG009, CA-AUT001 through CA-AUT003) target users via `includeUsers`, `includeGroups`, or `includeRoles`. Agent IDs do not authenticate as users. Rolling Agents into the user persona set would create unevaluated gaps.

**2. Agents are not equivalent to workload identities.** Service principals and managed identities authenticate against app registrations or system-assigned resource identities. Agent IDs are provisioned separately through the Microsoft Agent framework and surface as a distinct principal type in Microsoft Graph. The `CA-COV010-WorkloadIdentities-TrustedLocations` policy targets service principals via `includeServicePrincipals`; it does not evaluate Agent ID authentication flows.

**3. Agent IDs carry Identity Protection risk signals.** Microsoft exposes `agentIdRiskLevels` as a Conditional Access condition alongside `signInRiskLevels` and `userRiskLevels`. This allows risk-based policy enforcement specific to the Agent ID identity class, independent of user risk or service principal risk signals.

Treating the Agents persona as first-class — rather than attempting to route it through the ServiceAccounts or WorkloadIdentities exclusion paths — produces a cleaner policy set with explicit, auditable coverage.

---

## Persona definition

**What an Agent ID is:** A Microsoft Agent ID is an identity object provisioned by the Microsoft Agent framework in Entra ID. It represents an agentic AI workload — such as a Microsoft 365 Copilot extensibility agent, a custom Copilot Studio agent, or an Azure AI agent — that authenticates to Microsoft 365 resources using Entra-issued credentials.

**How it differs from a service principal:** A service principal is created by an app registration or managed identity and authenticates using a client secret, certificate, or managed identity token. A service principal can be assigned permissions, added to groups, and appears in the `servicePrincipals` Graph API endpoint. An Agent ID is provisioned through the Agent framework rather than app registration, appears in Agent-specific Graph endpoints, and authenticates using the `agentIdServicePrincipalFilter` condition family in Conditional Access — not via `clientApplications.includeServicePrincipals`.

**How it differs from a managed identity:** A managed identity is system-assigned or user-assigned to an Azure resource. It does not require credential management and authenticates via the Azure IMDS token endpoint. An Agent ID is explicitly provisioned for an agentic workload and carries its own risk signals via `agentIdRiskLevels`.

**Membership rules:** Any Agent ID provisioned in the tenant is in scope for this persona. The Agents persona is not defined by group membership. Targeting is via `IncludeApplications: ["AllAgentIdResources"]` and `IncludeAgentIdServicePrincipals: ["All"]` in `CA-COV011`. This means every Agent ID in the tenant is in scope; there is no per-agent exclusion mechanism equivalent to the per-SPN `excludeServicePrincipals` list in CA-COV010.

**The three agent access patterns:** An agent does not authenticate one fixed way. Microsoft documents three access patterns, and each carries a different token subject, which determines the Conditional Access targeting model:

1. **On-behalf-of (delegated).** A user signs into the agent, which exchanges tokens through the OAuth 2.0 On-Behalf-Of flow for downstream resources. The token subject is the user, so Conditional Access targets users and groups, not agent identities.
2. **Application-only (autonomous).** The agent authenticates with its own identity using the client credentials flow. The token subject is the agent identity, so Conditional Access targets the agent identity through `IncludeAgentIdServicePrincipals` plus the agent application bundle. This is the pattern this persona and `CA-COV011` cover today.
3. **Agent acting as a user (digital worker).** The agent has its own user account with a mailbox and group membership. The token subject is the agent user account, so Conditional Access targets agent users through the All agent users target (Preview).

**The agent user account is a distinct identity sub-class from the agent identity.** The agent identity (Pattern 2) and the agent user account (Pattern 3) are not the same principal. A policy targeting agent identities does not apply to the agent user account, and a policy targeting all users does not include agent user accounts. Agent user accounts also cannot be scoped by group membership, and agent identity blueprint targeting covers the agent identity, not the agent user account. `CA-COV011` and `CA-COV012` cover the agent identity (Pattern 2); the agent user account sub-class (Pattern 3) is covered by the three policies in the Agent user accounts coverage section below. See `Design/AGENTS-PERSONA-MODEL.md` section 2 and <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id>.

---

## Agent user accounts coverage

The agent user account is the Pattern 3 identity sub-class: an agent that has its own user account with a mailbox and group membership and authenticates as a digital worker. The token subject is the agent user account, not the user who deployed the agent and not the agent identity. Because this is a distinct sub-class, the user-targeted baseline policies do not reach it, and `CA-COV011` and `CA-COV012` (which target the agent identity) do not reach it either. This section defines the three policies that cover the agent user account sub-class.

### Sub-class definition

An agent user account is an Entra ID user object provisioned for an agent so the agent can act as a user (digital worker). It carries a mailbox, can hold group membership, and authenticates with the agent user account as the token subject. It differs from the agent identity (Pattern 2), which authenticates with the client credentials flow and carries the agent identity as the token subject. A policy that includes all users does not include agent user accounts, and a policy that targets the agent identity does not apply to the agent user account. Agent user accounts also cannot be scoped by group membership, so the targeting token for the sub-class is `conditions.agents.includeAgentUsers` rather than a persona group.

### The three agent user account policies

| Policy | Intent | Grant control | State |
|---|---|---|---|
| `CA-COV013-AgentUsers-BlockMediumAndHighRisk` | Block agent user account sign-ins when Microsoft Identity Protection raises the agent risk level to medium or high | `block` | Report-only |
| `CA-COV014-AgentUsers-RequireCompliantDevice` | Require a compliant device for agent user account sign-ins | `compliantDevice` | Report-only |
| `CA-COV015-AgentUsers-BlockNonCompliantNetwork` | Block agent user account sign-ins from outside the compliant network (all locations except the compliant-network named location) | `block` | Report-only |

All 3 policies ship in `enabledForReportingButNotEnforced`. For the agent user account sub-class Microsoft recommends `agentIdRiskLevels = medium` and `high`, which is distinct from the high-only recommendation for the agent identity policy `CA-COV011`. `CA-COV013` uses `agentIdRiskLevels = "medium,high"` to match that recommendation.

### Verified field shapes

The field shapes in these policies are verified against raw Microsoft Graph beta exports (`GET /beta/policies/conditionalAccessPolicies`):

1. **Agent user subject.** The agent-user sub-class is targeted through `conditions.agents.includeAgentUsers: ["All"]`, with `users.includeUsers: ["None"]` keeping the user authentication path out of scope.
2. **Agent execution environments condition.** `CA-COV014` scopes the device requirement to endpoint-initiated agent user sessions with `conditions.agentContext.includeAgentContexts: ["agentUserSessionsInitiatedFromEndpoints"]` (see the next section).
3. **Compliant-network location exclusion.** `CA-COV015` blocks any agent user sign-in from outside the compliant network by targeting `locations.includeLocations: ["All"]` and excluding the compliant-network named location (`excludeLocations`). The deployer resolves the named location to its id. Require compliant network is not a `builtInControls` value, so the policy uses the location-block pattern instead.

### Agent execution environments condition

The Agent execution environments condition (`conditions.agentContext.includeAgentContexts`, value `agentUserSessionsInitiatedFromEndpoints`) scopes a policy to endpoint-initiated agent user sessions. It is the mechanism that excludes cloud-native agents, which have no device, rather than blocking them with no path to compliance. Device compliance is evaluated only on Intune-managed Windows 365 Cloud PCs for Agents. `CA-COV014` ships with this condition in its JSON so the device requirement applies only to the sessions that can satisfy it.

`CA-COV013` (risk-based block) and `CA-COV015` (compliant-network location block) do not depend on the execution-environments condition, but all 3 ship report-only for a consistent soak.

### Network policy prerequisite

`CA-COV015-AgentUsers-BlockNonCompliantNetwork` requires Microsoft Entra Internet Access so the compliant-network named location is signalled. The compliant-network location relies on the Global Secure Access client being present on the endpoint. License Microsoft Entra Internet Access and deploy the Global Secure Access client, and provision the compliant-network named location, before enforcement. The compliant network is auth-plane GA and data-plane Preview.

See <https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-autonomous-agents> and <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id>.

---

## Limitations

Microsoft documents specific boundaries on where Conditional Access for agents applies. Account for each of these when planning coverage. None of the agent policies in this baseline closes these gaps, because the gaps are in the evaluation surface itself, not in the policy set.

**Targeting gaps between the agent identity and the agent user account:**

- A policy targeting all users does not include agent user accounts. A broad user policy leaves the agent user account uncovered.
- Agent user accounts cannot be scoped by group membership. The group-based persona pattern used elsewhere in this baseline does not apply to them.
- A policy targeting agent identities does not apply to the agent user account. Agent identity targeting reaches the application-only pattern (Pattern 2) only.
- Agent identity blueprint targeting covers the agent identity, not the agent user account.

**Authentication surfaces where Conditional Access does not apply:**

- Conditional Access does not apply at the Microsoft Entra Token Exchange Endpoint.
- Conditional Access does not apply to blueprint token acquisition for creating agents.
- Conditional Access does not apply when Security Defaults are enabled. Security Defaults disables Conditional Access for agents, so a tenant relying on Security Defaults has no agent Conditional Access enforcement regardless of the policies defined.
- Conditional Access does not apply to API-key access.

See <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id>.

---

## Report-only rollout for the agent policies

All 5 agent policies in this baseline ship in report-only (`enabledForReportingButNotEnforced`): `CA-COV011` and `CA-COV012` for the agent identity (Pattern 2), and `CA-COV013`, `CA-COV014`, and `CA-COV015` for the agent user account sub-class (Pattern 3). Validate each with policy impact analysis or report-only mode before moving it to On. Promote one policy at a time and confirm the report-only output before enforcing the next. Provision the compliant-network named location before enforcing `CA-COV015`, as described in the Agent user accounts coverage section above.

---

## Scope of this contract

This contract establishes:

1. The Agents persona is the **inclusion target** for `CA-COV011-Agents-BlockMediumAndHighRisk`. That policy blocks all Agent ID authentication flows where Microsoft Identity Protection has raised the agent risk level to `medium` or `high`.

2. The Agents persona is **not the inclusion target for any human-facing policy** in this baseline. The CA-AUT, CA-COV (001-009), and CA-SIG (001-009) policies target users, guests, service accounts, workload identities, or admin roles. None of them target Agent IDs.

3. **Other policies in the baseline do not exclude Agents** because Agents do not authenticate via the user-context flow. There is no `users.excludeGroups` entry for Agents in any human-targeted policy, and none is needed. The evaluation engine routes Agent ID authentication through Agent-specific conditions, not through user-targeted conditions.

4. The Agents persona **does not have a persona group** in the same sense as EmergencyAccess, WorkloadIdentities, ServiceAccounts, InternalUsers, or Guests. Microsoft does not expose Agent ID assignment groups through the same group-membership API surface. The deployer does not resolve an `AgentPersonaGroupName` parameter.

**What this contract does not govern:** The Agents persona contract does not govern individual agent permissions, app role assignments, or agent-to-user delegation flows. Those are governed by the app registration and permissions model, outside the scope of the Conditional Access Baseline.

---

## Operational requirements

### Quarterly Agent ID inventory

Run a quarterly inventory of all Agent IDs provisioned in the tenant. The Microsoft Graph beta endpoint exposes Agent ID objects. Verify that every Agent ID in the inventory has a known owner, a documented business purpose, and an active review record.

```powershell
Connect-MgGraph -Scopes "AgentId.Read.All"
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/agentIds"
```

The inventory review should confirm:

- No orphaned Agent IDs exist (owner has left the organization or project has ended)
- Every Agent ID's `AllAgentIdResources` access scope is still required
- Risk event counts for each Agent ID are reviewed and understood

### Monthly Agent ID risk event review

Review `agentIdRiskLevels` events monthly. Microsoft Identity Protection surfaces risk detections for Agent IDs via the beta sign-in logs. High-frequency risk detections against a specific Agent ID warrant investigation before the next enforcement decision.

```powershell
Connect-MgGraph -Scopes "IdentityRiskyServicePrincipal.Read.All"
$uri = "https://graph.microsoft.com/beta/identityProtection/riskyServicePrincipals"
Invoke-MgGraphRequest -Method GET -Uri $uri |
    Where-Object { $_.riskLevelAggregated -in "medium","high" }
```

### Incident response runbook for `agentIdRiskLevels: "high"` events

When Microsoft Identity Protection raises an Agent ID risk level to `high`:

1. **Immediate:** Confirm that `CA-COV011-Agents-BlockMediumAndHighRisk` is in `enabled` state (not just `enabledForReportingButNotEnforced`). If still in report-only, the high-risk agent has not been blocked — escalate to an emergency enforcement decision. To confirm whether an agent policy actually applied to the affected sign-ins, open the Microsoft Entra sign-in logs and filter on the `agentType` field, which isolates agent entries from user and service principal sign-ins. The `agentType` field is confirmed, but its enumerated values are not published, so confirm the value list in-tenant. Review the applied and report-only policy results on the filtered entries to see whether `CA-COV011` (or `CA-COV013` for an agent user account event) evaluated and what action it took or would have taken.
2. **Within 1 hour:** Identify the Agent ID object and its owner. Review the risk detection events in the Microsoft Entra admin center under Protection → Identity Protection → Risk detections.
3. **Revocation:** Disable the Agent ID in the tenant. This prevents further authentication regardless of CA policy state. Contact the Agent ID owner to coordinate.
4. **Investigation:** Determine whether the risk signal indicates prompt injection (agent instructed to exfiltrate data or act outside its authorized scope), credential theft (Agent ID credentials extracted and replayed from attacker infrastructure), or a false positive (Microsoft detection error — document and submit feedback to Microsoft).
5. **Remediation:** If credential theft is confirmed, rotate any embedded secrets in the agent configuration. If prompt injection is confirmed, review the agent's system prompt and data access scope. Apply principle of least privilege to the agent's permissions.
6. **Recovery:** Re-enable the Agent ID only after the root cause is resolved and documented. Update the quarterly inventory record.

---

## Licensing prerequisites

The Agents persona and `CA-COV011-Agents-BlockMediumAndHighRisk` depend on features that are per-tenant and per-SKU:

**Conditional Access for agents licensing:** Conditional Access for agents requires Microsoft Entra ID P1 or P2 plus a Microsoft Agent 365 license for each user. Microsoft describes enforcement of the Agent 365 licensing requirement as coming soon, so confirm the per-user Agent 365 entitlement is in place before you rely on this persona. Verify that Agent IDs are provisioned in your tenant before adopting this persona. If no Agent IDs exist, `CA-COV011` will evaluate with zero matches in report-only mode, which is safe but produces no signal. See <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id> and <https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-autonomous-agents>.

**Microsoft Entra Internet Access for network controls:** Network controls for agents require Microsoft Entra Internet Access. The compliant-network grant relies on the Global Secure Access client being present on the endpoint. If you intend to add a compliant-network condition to an agent policy, license Microsoft Entra Internet Access and deploy the Global Secure Access client before enforcement.

**Admin roles:** Creating and managing Conditional Access policies for agents requires the Conditional Access Administrator role. The custom-security-attribute targeting method also requires the Attribute Assignment Reader role so the administrator can read the attribute values used to scope the policy.

**Microsoft Graph beta endpoint:** All Agent ID condition fields — `agentIdRiskLevels`, `IncludeAgentIdServicePrincipals`, and `IncludeApplications: ["AllAgentIdResources"]` — are Microsoft Graph beta-only as of May 2026. The baseline framework targets the beta endpoint for all 28 policies to avoid conditional endpoint logic in the deployer. See `Design/AGENTS-PERSONA-MODEL.md` for the GA promotion tracking commitment.

**Identity Protection for Agent IDs:** Risk-based enforcement in `CA-COV011` requires that Microsoft Identity Protection is generating `agentIdRiskLevels` signals for your tenant's Agent IDs. Identity Protection for Agent IDs is included in Entra ID P2 licensing. Verify that risk detections are appearing before treating the report-only output of CA-COV011 as a complete picture of agent risk.

---

## Naming convention

The Agents persona does not follow the same group-based naming convention used for other personas (CA-Persona-EmergencyAccess, CA-Persona-ServiceAccounts, etc.). Microsoft does not currently expose Agent ID assignment groups through the standard group API. The persona is enforced through policy-side conditions in CA-COV011 rather than through a group membership reference.

If Microsoft introduces a group-based Agent ID management surface in a future release, this contract will be updated to include the corresponding group naming convention. At that point, the deployer will be extended with an `AgentsGroupName` parameter to match.

For documentation and audit purposes, refer to the Agents persona by the label `CA-Persona-Agents` in internal runbooks, incident tickets, and governance records — even though this label does not correspond to an Entra group object.

---

## Cross-references

| Document | Relationship |
|---|---|
| `CA-COV011-Agents-BlockMediumAndHighRisk.json` | The policy this persona contract governs |
| `Design/AGENTS-PERSONA-MODEL.md` | Full design rationale, Microsoft Agent ID technical overview, beta endpoint commitment |
| `CA-EXC001-EmergencyAccess-Exclusion.md` | Permanent exclusion contract — user persona, not applicable to Agent IDs |
| `CA-EXC002-ServiceAccounts-Exclusion.md` | Permanent exclusion contract — service account user persona, not applicable to Agent IDs |
| `CA-COV010-WorkloadIdentities.md` | Paired design doc for workload identity (service principal) coverage — separate from Agent ID coverage |
