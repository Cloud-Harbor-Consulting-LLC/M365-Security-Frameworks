# CA-COV012 — Agents AllowOnlyApprovedAgents

**Type:** Deployable policy template with paired operational contract
**Status:** Report-only on first deployment (`enabledForReportingButNotEnforced`)
**Persona:** Agents (Microsoft Agent ID)
**Pairs with:** `CA-COV012-Agents-AllowOnlyApprovedAgents.json`

---

## Purpose

`CA-COV012-Agents-AllowOnlyApprovedAgents` establishes an allow-list posture for the
Agents persona. Where `CA-COV011-Agents-BlockMediumAndHighRisk` is a risk-based control
that blocks agent identities only when Microsoft Identity Protection raises the agent risk
level to medium or high, CA-COV012 is a standing allow-only control: every agent identity
in the tenant is blocked unless it is on the approved set. The two policies are
complementary. CA-COV011 governs risk; CA-COV012 governs which agents are sanctioned to
operate at all.

---

## Design: deny by default, allow only the approved set

The policy uses the same deny-by-default-except-approved pattern that
`CA-COV006-Global-BlockUnknownPlatforms` uses for device platforms: include everything,
exclude the approved set, and block. Applied to agent identities, the three conditions are:

| Condition | Value | Effect |
|---|---|---|
| `conditions.applications.includeApplications` | `["All"]` | Targets All resources (the portal labels this "All resources (formerly 'All cloud apps')"). The policy must target All resources; an empty target leaves the allow-list inert because there is no resource for the block to apply against. |
| `conditions.clientApplications.includeAgentIdServicePrincipals` | `["All"]` | Brings every agent identity in the tenant into scope. |
| `conditions.clientApplications.agentIdServicePrincipalFilter` | `{ "mode": "exclude", "rule": "CustomSecurityAttribute.AgentIdAttributes_AgentIdApprovedForUse -eq \"yes\"" }` | Carves the approved agent identities back out by custom security attribute, so they are not blocked. |
| `conditions.users.includeUsers` | `["None"]` | Agents do not authenticate as users; this keeps the user authentication path out of scope. |
| `grantControls.builtInControls` | `["block"]` | Any in-scope agent identity (every agent that is not on the approved set) is blocked. |

The net result: an agent identity that is not on the approved set is blocked, and an agent
identity that is on the approved set is unaffected by this policy. `block` is the only
enforceable grant control for a non-human principal, because an agent identity cannot
satisfy an interactive MFA, authentication strength, or device compliance challenge. This
mirrors the block-only approach taken for service accounts (`CA-COV009`), workload
identities (`CA-COV010`), and the agent risk control (`CA-COV011`).

The approved set is expressed through `agentIdServicePrincipalFilter` rather than an
enumerated object ID list. With `mode` set to `exclude`, the filter rule matches the agent
identities that carry the approval attribute and carves them out of the block. The verified
rule is `CustomSecurityAttribute.AgentIdAttributes_AgentIdApprovedForUse -eq "yes"`: it
matches every agent whose `AgentIdAttributes` custom security attribute set has the
`AgentIdApprovedForUse` String attribute set to `yes`. Assign that attribute value to each
agent your organization has sanctioned before you import or enforce the policy.

---

## Selecting the approved agents

Microsoft documents two methods for selecting the approved agent identities that populate
the exclude set. Both require the Conditional Access Administrator role; the attribute
method additionally requires the Attribute Assignment Reader role.

### Method 1: the enhanced object picker

The Conditional Access agent identity picker presents three tabs:

- **All** — every agent identity in the tenant.
- **Agent blueprint principals** — agents grouped by the blueprint they were provisioned
  from, so an approval can cover all agents built on an approved blueprint.
- **Agent identities** — individual agent identities selected one at a time.

Use this method when the approved set is a known, enumerable list of individual agents or
blueprints. The template ships the attribute method (Method 2) instead, because the filter
rule is the verified wire shape.

### Method 2: custom security attributes

For a larger or attribute-governed fleet, agents are selected by custom security attribute
rather than by enumerating object IDs. This is the method the template uses. The verified
scheme is a single attribute:

- Custom security attribute set **AgentIdAttributes**, attribute **AgentIdApprovedForUse**,
  of type String, with the value `yes` assigned to each sanctioned agent.

Selection uses the `agentIdServicePrincipalFilter` rule with the `-eq` operator. The filter
grammar is `CustomSecurityAttribute.<Set>_<Attribute> -eq "<value>"`, so the approved set is
expressed as
`CustomSecurityAttribute.AgentIdAttributes_AgentIdApprovedForUse -eq "yes"`. With the
filter `mode` set to `exclude`, every agent that matches the rule is carved out of the
block. The attribute method requires the Attribute Assignment Reader role in addition to the
Conditional Access Administrator role, so the administrator can read the attribute values
used to scope the policy.

---

## Roles

| Role | Required for |
|---|---|
| Conditional Access Administrator | Creating and managing the policy, and selecting agents via the enhanced object picker. |
| Attribute Assignment Reader | Reading the custom security attribute values when agents are selected via the attribute method. |

---

## Verified field shapes

Every field in this policy is verified against raw Microsoft Graph beta exports
(`GET /beta/policies/conditionalAccessPolicies`):

1. The `includeAgentIdServicePrincipals` `"All"` value is tenant-verified.
2. The `agentIdServicePrincipalFilter` object and its rule grammar
   (`CustomSecurityAttribute.<Set>_<Attribute> -eq "<value>"`, with `mode` set to `exclude`)
   are tenant-verified. The attribute set `AgentIdAttributes`, the String attribute
   `AgentIdApprovedForUse`, and the value `yes` matched with `-eq` are the verified scheme.

The properties this policy relies on are
`conditionalAccessClientApplications.includeAgentIdServicePrincipals`,
`conditionalAccessClientApplications.agentIdServicePrincipalFilter`,
`conditions.applications.includeApplications` value `"All"` (the policy targets All
resources; an empty target leaves the allow-list inert), `conditions.users.includeUsers`
value `"None"`, and `grantControls.builtInControls` value `"block"`. See
`Design/AGENTS-PERSONA-MODEL.md` section 6 for the full field-status table and the GA
tracking commitment.

---

## Relationship to CA-COV011

CA-COV011 and CA-COV012 are layered, not redundant:

- **CA-COV011-Agents-BlockMediumAndHighRisk** blocks an agent identity when its risk level
  reaches medium or high. It applies to every agent, including approved ones, because an
  approved agent that is compromised should still be blocked on risk.
- **CA-COV012-Agents-AllowOnlyApprovedAgents** blocks every agent identity that is not on the
  approved set, regardless of risk level. It establishes which agents are sanctioned to
  operate at all.

Run both in report-only during the soak. Confirm that CA-COV012 would block only the agents
you intend to keep out (unapproved or unknown agent identities) and that every approved
agent appears in the exclude set before promoting to enforcement.

---

## References

- <https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-autonomous-agents>
- <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id>
- `Policies/CA-EXC003-Agents-Persona.md` — Agents persona contract
- `Policies/CA-COV011-Agents-BlockMediumAndHighRisk.json` — paired risk-based agent control
- `Design/AGENTS-PERSONA-MODEL.md` — full design rationale and beta endpoint commitment
