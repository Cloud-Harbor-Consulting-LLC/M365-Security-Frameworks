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

1. **Immediate:** Confirm that `CA-COV011-Agents-BlockMediumAndHighRisk` is in `enabled` state (not just `enabledForReportingButNotEnforced`). If still in report-only, the high-risk agent has not been blocked — escalate to an emergency enforcement decision.
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

**Microsoft Graph beta endpoint:** All Agent ID condition fields — `agentIdRiskLevels`, `IncludeAgentIdServicePrincipals`, and `IncludeApplications: ["AllAgentIdResources"]` — are Microsoft Graph beta-only as of May 2026. The baseline framework targets the beta endpoint for all 23 policies to avoid conditional endpoint logic in the deployer. See `Design/AGENTS-PERSONA-MODEL.md` for the GA promotion tracking commitment.

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
