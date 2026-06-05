# Entra ID Governance Toolkit — Business Case and ROI

> A plain-language business case for security and IT leaders defending an identity governance investment to the CFO, the board, and security leadership.

## Executive summary

Access that is granted once and never reviewed is how guest sprawl and privilege creep take hold. Every external collaborator added to a Microsoft 365 group, and every administrative role assigned for a one-time project, becomes standing access the moment the work is done — unless something forces a review. In most tenants nothing does. The access stays, the people who approved it move on, and the organization carries an invisible, audit-exposed liability that grows every quarter.

The Entra ID Governance Toolkit (EIG) v0.1.0-preview automates the two recurring access reviews that close the largest standing-access gaps in a Microsoft 365 tenant:

- **EIG-AR001 — Quarterly guest access review.** A recurring quarterly Microsoft Entra access review over B2B guest membership across all Microsoft 365 groups. Decisions default to deny, denied guests are removed automatically, and each guest is routed to its sponsor with a named fallback reviewer where no sponsor is recorded.
- **EIG-AR002 — Monthly dormant admin role review.** A recurring monthly access review over administrative role assignments, using a 30-day inactivity look-back so any role assignment not exercised in the prior 30 days is recommended for denial. Decisions default to deny and denied assignments are removed automatically.

Both controls are built on four principles: time-bound access by default, reviewer accountability with a sign-off trail, recurrence enforced in the review definition rather than in someone's memory, and durable audit evidence retained for every decision. The scripts are PowerShell 7 against the Microsoft Graph Identity Governance API, each paired with a plain-language contract document so an adopter can read exactly what the control commits to before running it.

The ask of leadership is twofold:

1. **Confirm Microsoft Entra ID P2 licensing** for the populations under review. Access Reviews is a P2 feature; without it neither control can be deployed.
2. **Authorize the recurring review cadence** — quarterly for guests, monthly for dormant admin roles — and name the reviewer chain and fallback reviewers before the first review opens.

In return, the organization replaces an irregular, manual, error-prone cleanup with two scheduled controls that close the orphaned-access window without manual remediation, name an accountable reviewer for every decision, and retain the evidence an auditor needs. This directly supports the access-review and least-privilege requirements in SOC 2, ISO 27001, HIPAA, PCI-DSS, and NIST SP 800-53.

## The business risk this addresses

### Standing access is a silent, compounding liability

Two patterns drive most of the standing-access risk in a Microsoft 365 tenant:

**Guest sprawl.** B2B guests are added to Microsoft 365 groups to collaborate on a project, a deal, or a support case. When the work ends, the guest is rarely removed. Over time the tenant accumulates external identities with continued access to documents, conversations, and Teams channels that no current employee can account for. Each one is a path for data to leave the organization through an account it no longer controls.

**Privilege creep.** Administrative roles are assigned for migrations, incident response, or vendor engagements and then left in place. A standing admin assignment that no one is using is pure downside: it adds nothing to operations and everything to the blast radius if the account is compromised. Dormant admin access is exactly what an attacker looks for — high privilege, low scrutiny.

### Manual governance does not scale and does not hold up to audit

The conventional answer is a periodic manual cleanup: export the guest list, chase down who owns each one, decide, and remove. This fails in three predictable ways:

- **It is slow and it slips.** Manual reviews depend on someone remembering to run them. When the quarter gets busy, the review is the first thing to drop, and the standing-access window stays open indefinitely.
- **It is error-prone.** Hand-built lists miss accounts, sponsors are guessed at, and removals are applied inconsistently or not at all. The orphaned-access window stays open even after a review nominally "completed."
- **It is audit-exposed.** A manual cleanup rarely produces a defensible record of who reviewed what, when, and with what outcome. When an auditor asks for evidence, the organization reconstructs it after the fact, if it can at all.

### Deny-by-default plus auto-apply closes the window without manual remediation

EIG inverts the manual model. The review recurs automatically on its defined cadence, so it never depends on memory. Every decision defaults to deny: if a reviewer does not respond before the review closes, access is removed rather than silently retained. And because removals are auto-applied, there is no separate manual remediation step — the orphaned-access window closes as part of the review, not in a follow-up ticket that may never be worked. The result is that standing access is continuously pruned back toward least privilege with no manual cleanup project required.

## What the toolkit delivers

Two Access Reviews automations, each addressing a specific standing-access risk. Columns: Script ID, Control, Cadence, Decision model, Business outcome.

| Script ID | Control | Cadence | Decision model | Business outcome |
|---|---|---|---|---|
| EIG-AR001 | Quarterly guest access review across all Microsoft 365 groups | Quarterly | Deny-by-default; denied guests auto-removed; sponsor reviewer with named fallback | Guest membership is pruned every quarter to only the externals with a current, sponsor-confirmed business need |
| EIG-AR002 | Monthly dormant admin role review with a 30-day inactivity look-back | Monthly | Deny-by-default; denied assignments auto-removed; role owner or delegated reviewer with named fallback | Admin role assignments unused for 30+ days are surfaced and removed every month, shrinking the privileged blast radius |

Both controls retain review decisions and reviewer identity for the audit retention period, so an auditor can reconstruct who reviewed what, when, and with what outcome — without the team reconstructing evidence after the fact.

## Risk reduction framing

The toolkit does not eliminate access risk. It removes the standing-access surface that accumulates when access is granted and never re-examined. The categories it addresses:

**External data exposure through stale guests.** EIG-AR001 reviews B2B guest membership across all Microsoft 365 groups every quarter. Guests whose sponsor does not confirm continued need — or for whom no reviewer responds — are removed automatically. This continuously constrains external access to the collaborators who still have a confirmed business reason for it, closing the path where data leaves through a guest account no one is watching.

**Privileged blast radius from dormant admin access.** EIG-AR002 reviews administrative role assignments monthly with a 30-day inactivity look-back. An assignment that has not been exercised in 30 days is recommended for denial and removed on a deny decision. This keeps the privileged-access footprint matched to actual operational use, removing the dormant high-privilege assignments that attackers prize and that least-privilege audits flag.

**Governance decay from manual processes.** Both controls enforce recurrence in the Access Review definition itself. The cadence does not depend on anyone remembering to run a cleanup, so governance does not silently lapse during a busy quarter.

**Unaccountable and undocumented decisions.** Every review names a responsible reviewer and records the decision, with deny-by-default ensuring non-responses fail safe rather than defaulting to continued access. The retained evidence trail turns each review into defensible audit proof rather than an informal cleanup.

## Licensing

| Component | Required by | Note |
|---|---|---|
| Microsoft Entra ID P2 | EIG-AR001 and EIG-AR002 | Access Reviews is a Microsoft Entra ID P2 feature. Required for both controls; there is no P1 fallback. |
| PowerShell 7 | EIG-AR001 and EIG-AR002 | The scripts target PowerShell 7. No Windows PowerShell 5.1 support. |
| Microsoft.Graph.Authentication module | EIG-AR001 and EIG-AR002 | The only Graph SDK module the scripts depend on. |

Entra ID P2 is the only licensing line item this toolkit introduces. Organizations that have already licensed P2 for Conditional Access Identity Protection, Privileged Identity Management, or risk-based access controls incur no incremental license cost to adopt EIG — the Access Reviews entitlement is already included in the P2 SKU they hold.

If P2 is not yet in place, calculate the incremental cost against the organization's Microsoft 365 agreement:

- [INSERT: CURRENT IN-SCOPE USERS x COST-PER-USER DELTA FROM P1 TO P2]
- [INSERT: ORGANIZATION'S CURRENT COUNT OF B2B GUESTS]
- [INSERT: ORGANIZATION'S CURRENT COUNT OF STANDING ADMIN ROLE ASSIGNMENTS]

These placeholders convert a directional business case into a quantified ROI specific to the organization.

## Implementation prerequisites

Before the first review is created, the following must be in place:

- **Microsoft Entra ID P2 licensing** confirmed for the populations under review. Access Reviews will not function without it.
- **PowerShell 7** and the **`Microsoft.Graph.Authentication` module** installed on the operator workstation. No other Graph SDK module is required.
- **Operator consent** to the required Microsoft Graph scopes: `AccessReview.ReadWrite.All` and `AccessReview.ReadWrite.Membership` for EIG-AR001; the same two plus `RoleManagement.ReadWrite.Directory` for EIG-AR002.
- **A named reviewer chain.** For guests, confirm the sponsor reviewer query in your tenant and supply a named fallback reviewer team for guests with no recorded sponsor. For dormant admin roles, identify the role owner or delegated governance reviewer and supply a named fallback reviewer group.
- **The directory role definition IDs** for the administrative roles you intend to place under review. EIG-AR002 reviews one role per run, so identify which privileged roles belong under review before the first run.

## Operational cost model

The model below is an **illustrative, assumptions-based estimate, not a guarantee**. Every input is an assumption an adopter tunes to their own tenant; the bracketed values are starting points, and every total is computed with the arithmetic shown so the adopter can substitute their own numbers and re-derive the result. The point of the model is the method, not the specific figures.

### Stated assumptions

| Assumption | Illustrative value (tune to your tenant) |
|---|---|
| A1 — Microsoft 365 groups containing at least one guest | [80] groups |
| A2 — Guest memberships requiring a decision per group, per cycle | [5] decisions |
| A3 — Minutes per manual guest decision (locate sponsor, confirm need, record) | [6] minutes |
| A4 — Guest review cadence | Quarterly ([4] cycles/year) |
| A5 — Privileged directory roles placed under review | [8] roles |
| A6 — Dormant assignments per role requiring a decision per cycle | [3] decisions |
| A7 — Minutes per manual dormant-admin decision (check last activation, confirm, record) | [10] minutes |
| A8 — Dormant admin review cadence | Monthly ([12] cycles/year) |
| A9 — Share of decisions resulting in a removal (the rest are renewals) | [20]% |
| A10 — Minutes of manual remediation saved per removed grant when auto-apply performs the removal | [8] minutes |

The manual per-decision figures (A3, A7) decompose into the human decision itself plus the orchestration overhead automation removes — locating the sponsor, building the list, sending reminders, and chasing non-responders. For this model we treat that orchestration overhead as [2] minutes of the [6]-minute guest decision and [4] minutes of the [10]-minute admin decision. Automation removes the orchestration portion (the review pre-routes each item to its reviewer with evidence attached) but not the human judgment, so the automated per-decision time is [4] minutes for guests and [6] minutes for admin roles.

### Manual baseline (today)

Guest decision labor:

    A1 x A2 = 80 x 5 = 400 guest decisions per quarter
    400 decisions x A3 (6 min) x A4 (4 cycles) = 9,600 min/year = 160 hours/year

Dormant admin decision labor:

    A5 x A6 = 8 x 3 = 24 admin decisions per month
    24 decisions x A7 (10 min) x A8 (12 cycles) = 2,880 min/year = 48 hours/year

Manual remediation labor:

    Annual decisions = (400 x 4) + (24 x 12) = 1,600 + 288 = 1,888 decisions/year
    Removals = 1,888 x A9 (20%) = 378 removals/year
    378 removals x A10 (8 min) = 3,024 min/year = ~50 hours/year

    Manual baseline total = 160 + 48 + 50 = ~258 hours/year

### Automated steady state

Guest decision labor (orchestration overhead removed):

    400 decisions x 4 min x 4 cycles = 6,400 min/year = ~107 hours/year

Dormant admin decision labor (orchestration overhead removed):

    24 decisions x 6 min x 12 cycles = 1,728 min/year = ~29 hours/year

Manual remediation labor:

    Auto-apply performs every removal = 0 hours/year

Operator oversight (confirm each cycle ran, spot-check evidence):

    Guest: 1 hour/quarter x 4 = 4 hours/year
    Admin: 0.5 hour/month x 12 = 6 hours/year
    Oversight total = 10 hours/year

    Automated steady-state total = 107 + 29 + 0 + 10 = ~146 hours/year

A one-time setup effort of roughly [4] hours (confirm reviewer queries, resolve role definition IDs, schedule the first runs) is not annualized into the steady-state figure.

### Net result

    Net annual labor reclaimed = 258 - 146 = ~112 hours/year

At a fully-loaded security-administrator labor rate of [INSERT: LOADED HOURLY COST], the reclaimed time converts to [112 x your loaded hourly cost] in recovered staff capacity each year. The larger return is not in the hours line: it is in the standing-access window that closes automatically every cycle instead of staying open until someone remembers to run a cleanup. Tune A1 through A10 to your tenant before presenting any figure as your own.

## Compliance mapping

This toolkit supports the access-review and least-privilege requirements in major compliance frameworks. Organizations should validate specific control numbers against current framework revisions with their audit team.

| Framework | Control | How the toolkit supports it |
|---|---|---|
| SOC 2 | CC6.2 / CC6.3 (Access provisioning and removal) | EIG-AR001 and EIG-AR002 enforce recurring review and automatic removal of access that is no longer justified |
| SOC 2 | CC6.7 (Privileged access) | EIG-AR002 reviews administrative role assignments monthly and removes dormant privileged access |
| ISO 27001 | A.5.18 (Access rights — review and removal) | Both controls provide a recurring, evidenced review of access rights with automatic removal on a deny decision |
| ISO 27001 | A.5.15 / A.8.2 (Access control and privileged access rights) | EIG-AR002 keeps privileged assignments matched to demonstrated use via the 30-day inactivity look-back |
| HIPAA | §164.308(a)(4) (Information access management) | Recurring guest and admin reviews enforce that access to systems holding ePHI is periodically re-authorized |
| PCI-DSS | 7.2.4 (Review user accounts and access privileges) | EIG-AR001 and EIG-AR002 provide the periodic access review the requirement mandates, with retained evidence |
| NIST SP 800-53 | AC-2 (Account management) | Recurring reviews and auto-applied removal support the account review and disabling controls |
| NIST SP 800-53 | AC-6 (Least privilege) | EIG-AR002 removes dormant administrative privilege, directly supporting least-privilege enforcement |

Beyond compliance, recurring access reviews and least-privilege evidence are increasingly named in cyber-insurance underwriting questionnaires as a precondition for favorable premium pricing or coverage.

## Recommended investment approach

### Phase 1 — Prerequisites (week 1)

Confirm Microsoft Entra ID P2 licensing for the populations under review. Install PowerShell 7 and the `Microsoft.Graph.Authentication` module on the operator workstation. Grant the operator the required Graph scopes. Name the reviewer chain — guest sponsors with a fallback reviewer team, and role owners or delegated governance reviewers with a fallback group.

### Phase 2 — Guest access review (week 2)

Confirm the sponsor reviewer query against your tenant and supply the fallback reviewer team object ID. Run EIG-AR001 with `-WhatIf` to preview, then create the quarterly guest access review. Confirm in the Entra admin center that the definition was created with the expected quarterly recurrence and reviewer assignment. Treat the first review instance as a calibration cycle: watch how many guests are routed to the fallback reviewer and tighten sponsor records accordingly.

### Phase 3 — Dormant admin role review (week 3)

Identify the privileged directory roles to place under review and capture their role definition IDs. Confirm the primary reviewer query for role owners or delegated governance reviewers and supply the fallback group object ID. Run EIG-AR002 once per role to create the monthly dormant admin role review with the 30-day inactivity look-back. Confirm in the Entra admin center that each definition was created with the expected monthly recurrence, reviewer assignment, and look-back.

### Phase 4 — Steady state (week 4 onward)

Establish the operator oversight cadence: confirm each cycle ran and spot-check the retained evidence. Tune the assumptions in the operational cost model against the first one or two real review cycles. As demand warrants, extend coverage to additional privileged roles and additional review domains as later EIG releases add Lifecycle Workflows and Privileged Identity Management governance.

## References

- Microsoft Learn. [What are Microsoft Entra access reviews?](https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview)
- Microsoft Learn. [Microsoft Entra ID Governance overview](https://learn.microsoft.com/en-us/entra/id-governance/identity-governance-overview)
- Microsoft Learn. [Create an access review of groups and applications](https://learn.microsoft.com/en-us/entra/id-governance/create-access-review)
- Microsoft Learn. [accessReviewScheduleDefinition resource type (Microsoft Graph)](https://learn.microsoft.com/en-us/graph/api/resources/accessreviewscheduledefinition)
- Microsoft Learn. [Microsoft Entra ID Governance licensing fundamentals](https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals)
- Cloud Harbor Consulting. `Design/POLICY-DESIGN.md` — full framework design specification, persona model, rollout sequence, and per-script design specs.
- Cloud Harbor Consulting. `Scripts/EIG-AR001-QuarterlyGuestAccessReview.md` — paired contract for the quarterly guest access review.
- Cloud Harbor Consulting. `Scripts/EIG-AR002-DormantAdminRoleReview.md` — paired contract for the monthly dormant admin role review.

---

Part of [M365-Security-Frameworks](https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks). Licensed under MIT.
