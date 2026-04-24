# Conditional Access Baseline

A defensible Conditional Access baseline for Microsoft Entra ID — six starter policies that enforce Zero Trust access principles, grounded in the risk-reduction framing published in [Why Entra ID Conditional Access Fails in Practice (And How to Fix It)](https://www.cloudharborconsulting.cloud/post/why-entra-id-conditional-access-fails-in-practice-and-how-to-fix-it).

**Status:** 🟢 Released — v1.0.0

## Why a baseline first

Conditional Access is Microsoft's Zero Trust policy engine, not a feature. Every sign-in is evaluated against identity, device state, location, risk, and application signals — and a decision is made to allow, block, or challenge. Most Conditional Access failures don't stem from the technology; they stem from policies bolted on without a defensible baseline underneath.

**Until a baseline exists, adding more Conditional Access policies increases complexity without materially reducing risk.**

## What a defensible baseline looks like

1. **Identity-wide coverage** — no orphaned identities or applications
2. **No standing exclusions** — only controlled, time-bound access paths
3. **Layered signals** — device, location, and risk aligned to real attack paths
4. **Authentication Strengths** — phishing-resistant MFA for privileged and high-value workloads

## Naming convention

Every policy in this baseline follows a principle-coded naming scheme that ties each policy back to one of the four defensible-baseline principles above:

```
CA-[PrinciplePrefix][Number]-[Persona]-[Action]
```

| Principle | Prefix | Meaning |
|-----------|--------|---------|
| Identity-wide coverage | `COV` | Ensures no orphaned identities, apps, or legacy protocols slip past |
| No standing exclusions | `EXC` | Governs time-bound or controlled access paths (future policies) |
| Layered signals | `SIG` | Uses device, location, or risk signals to shape access decisions |
| Authentication Strengths | `AUT` | Enforces phishing-resistant MFA for privileged and high-value workloads |

**Why this convention:** Every policy name is a micro-reminder of which principle it supports. Admins reading the policy list in Entra see the baseline's thesis reflected in the names themselves, and auditors can trace any policy back to a documented principle in three letters.

## The six starter policies

| Policy Name | Purpose |
|-------------|---------|
| `CA-COV001-AllUsers-BlockLegacyAuth` | Eliminates the single largest unsecured protocol surface in Entra ID |
| `CA-COV002-AllUsers-RequireMFA` | Establishes multi-factor as the floor for every authenticated session |
| `CA-SIG001-SensApps-RequireCompliantDevice` | Ties access to known, healthy endpoints for high-value workloads |
| `CA-AUT001-PrivAccounts-RequirePhishResistantMFA` | Protects the identities attackers target first |
| `CA-AUT002-PrivRoles-RequirePhishResistantMFA` | Enforces strong auth at the role-activation layer (PIM path) |
| `CA-SIG002-AllUsers-RequireStepUpOnRisk` | Responds dynamically to Entra ID Protection signals on medium/high-risk sign-ins |

Environments operating beyond this baseline should layer **Continuous Access Evaluation (CAE)** and **Token Protection** to close the session-token gap that static Conditional Access policies leave open.

## What's included in this framework

| Artifact | Purpose | Status |
|----------|---------|--------|
| [Policy design doc](./Design/POLICY-DESIGN.md) | Baseline philosophy, naming convention, exclusion-group strategy | 🟢 Released |
| [JSON policy templates](./Policies/) | The six importable Conditional Access policies | 🟢 Released |
| [Deployment scripts](./Scripts/) | PowerShell automation via Microsoft Graph | 🟢 Released |
| [Business case](./Business-Case/ROI-CONDITIONAL-ACCESS.md) | ROI, risk reduction, and audit framing | 🟢 Released |

## Personas covered

This baseline is deployed around the people it protects, not around individual technical controls:

- **Global & Privileged Administrators** — highest-trust, most-targeted accounts
- **Privileged Roles (PIM-activated)** — just-in-time elevated identities
- **Internal Users** — standard employee identities
- **Guest Users** — external collaborators via B2B
- **Workload Identities** — service principals and managed identities
- **Emergency Access Accounts** — break-glass accounts (explicitly excluded)

## Prerequisites

- Microsoft Entra ID P1 (P2 recommended for risk-based policy `CA-SIG002`)
- Global Administrator or Conditional Access Administrator role to deploy
- Microsoft Graph PowerShell SDK 2.x installed
- Two emergency access accounts created and excluded from every policy
- A pilot group of users before tenant-wide rollout

## Deployment workflow

> ⚠️ **Do not deploy to production without a pilot.** Conditional Access misconfigurations are the #1 cause of self-inflicted lockouts in Entra ID. Always stage in report-only mode first.

```powershell
# High-level flow (detailed steps publish with v1.0.0)

# 1. Create exclusion groups (emergency access, pilot users)
# 2. Import CA-COV001 through CA-SIG002 in report-only mode
# 3. Monitor sign-in logs for 7–14 days
# 4. Promote policies from report-only to enforced, one at a time
# 5. Tenant-wide rollout
```

## Roadmap

- [ ] Publish policy design doc (persona model, naming convention, exclusion strategy)
- [ ] Publish six core JSON policy templates
- [ ] Publish `Deploy-CABaseline.ps1` with `-WhatIf` and `-ReportOnly` support
- [ ] Publish ROI / business-case document
- [ ] Document CAE and Token Protection layering for post-baseline environments
- [ ] Tag v1.0.0 release

## References

This baseline is grounded in my own consulting experience and the risk-reduction framing from the [Cloud Harbor Consulting blog](https://www.cloudharborconsulting.cloud/post/why-entra-id-conditional-access-fails-in-practice-and-how-to-fix-it). It also acknowledges community prior art:

- Microsoft's [Conditional Access architecture](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies) guidance
- Joey Verlinden's [ConditionalAccessBaseline](https://github.com/j0eyv/ConditionalAccessBaseline)
- Daniel Chronlund's [Conditional Access design baseline](https://danielchronlund.com/)
- Claus Jespersen's Microsoft Conditional Access framework

## License

MIT — see repo root [LICENSE](../../LICENSE).
