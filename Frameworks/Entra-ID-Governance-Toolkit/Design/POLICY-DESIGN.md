# Entra ID Governance Toolkit: Policy Design

Status: in development, targeting v0.1.0-preview

This document is the design specification for the Entra ID Governance Toolkit
(EIG). It defines the framework principles, the naming convention, the persona
model, the rollout sequence, and the per-script design specs that the toolkit
scripts implement. Script PRs are reviewed against this document.

## 1. Purpose

EIG gives an Entra ID administrator a small set of self-invoking PowerShell
scripts that enforce recurring identity governance controls through the Microsoft
Graph identity governance endpoints. The toolkit favors time-bound access,
reviewer accountability, enforced recurrence, and durable audit evidence over
one-time manual cleanups.

## 2. Scope

In scope for v0.1.0-preview:

- Access Reviews for B2B guest accounts.
- Access Reviews for dormant administrative role assignments.
- Per-script design specs, prerequisites, and the Graph permission scopes each
  script requires.

Out of scope for v0.1.0-preview (tracked for later versions):

- Lifecycle Workflows automation (EIG-LW domain).
- Privileged Identity Management policy governance (EIG-PIM domain).
- A unified deployer or orchestration runner across scripts. Each script is
  self-invoking at v0.1.0-preview. A unified runner is deferred to v0.2.0 or
  v1.0.0 if adopter demand warrants it.

## 3. Design principles

The toolkit is built on 4 principles. Every script is reviewed against them.

1. Time-bound access by default. Access is granted for a defined period and
   expires unless it is renewed through a review. Scripts do not create standing
   access.
2. Reviewer accountability with a sign-off trail. Every review names a
   responsible reviewer and records the reviewer decision. Reviews are not
   auto-approved silently.
3. Recurrence enforcement at the workflow level. Controls recur on a fixed
   cadence defined in the review definition, not on a reviewer remembering to
   run them. The recurrence lives in the Access Review definition.
4. Evidence retention for audit. Each review retains its decisions and the
   reasoning for a defined retention period so that an auditor can reconstruct
   who reviewed what, when, and with what outcome.

## 4. Naming convention

Scripts and their paired contract documents follow the pattern:

    EIG-[Domain][Number]-[Description]

| Domain | Code | Meaning |
| --- | --- | --- |
| Access Reviews | EIG-AR | Recurring access reviews over guests, roles, and group membership |
| Lifecycle Workflows | EIG-LW | Joiner, mover, leaver automation (deferred past v0.1.0-preview) |
| PIM governance | EIG-PIM | Privileged Identity Management policy controls (deferred past v0.1.0-preview) |

Number is a zero-padded 3-digit sequence within the domain, assigned in delivery
order: EIG-AR001, EIG-AR002, and onward. Description is a short PascalCase phrase.
Each script ships with a paired contract document of the same base name and a .md
extension.

## 5. Persona model

The toolkit is designed around 3 personas.

- Operator. The Entra ID administrator who runs the scripts. The operator holds
  the Graph permission scopes listed per script and is responsible for scheduling
  recurrence and confirming that reviews were created.
- Reviewer. The person accountable for a review decision. For guest reviews the
  reviewer is the guest sponsor where one is set, with a named fallback team where
  no sponsor is recorded. For dormant admin role reviews the reviewer is the role
  owner or a delegated governance reviewer.
- Auditor. The person who reads the retained review evidence after the fact. The
  auditor does not run scripts. The auditor relies on the sign-off trail and the
  evidence retention period to reconstruct decisions.

## 6. Rollout sequence

An adopter brings EIG online in this order:

1. Confirm prerequisites: Entra ID P2 licensing, PowerShell 7, and the
   Microsoft.Graph.Authentication module.
2. Grant the operator the Graph permission scopes for the first script.
3. Run EIG-AR001 to stand up the quarterly guest access review.
4. Run EIG-AR002 to stand up the monthly dormant admin role review.
5. Confirm in the Entra admin center that both review definitions were created
   with the expected recurrence and reviewer assignment.

Scripts are self-invoking and independent. An adopter can run EIG-AR001 without
EIG-AR002. There is no required cross-script order beyond prerequisites.

## 7. Per-script design specifications

### 7.1 EIG-AR001 Quarterly Guest Access Review

- Purpose: create a recurring quarterly Access Review covering all B2B guest
  accounts in the tenant.
- Graph surface: POST to /identityGovernance/accessReviews/definitions.
- Review scope: all B2B guest users.
- Recurrence: quarterly, enforced in the review definition.
- Reviewer assignment: the guest sponsor where a sponsor is recorded on the guest
  account, with a named fallback team where no sponsor is set.
- Decision policy default: deny if the reviewer does not respond before the review
  closes. No silent auto-approve.
- Post-review action on a deny decision: remove the guest from the reviewed group.
- Evidence: review decisions and reviewer identity retained for the defined audit
  retention period.
- Required scopes: AccessReview.ReadWrite.All and AccessReview.ReadWrite.Membership.
- Paired contract document: EIG-AR001-QuarterlyGuestAccessReview.md.

### 7.2 EIG-AR002 Dormant Admin Role Review

- Purpose: create a recurring monthly Access Review covering administrative role
  assignments that have been dormant for 30 or more days.
- Graph surface: POST to /identityGovernance/accessReviews/definitions.
- Review scope: administrative role assignments not activated in the prior 30 days.
- Recurrence: monthly, enforced in the review definition.
- Reviewer assignment: the role owner or a delegated governance reviewer.
- Decision policy default: deny if the reviewer does not respond before the review
  closes. No silent auto-approve.
- Post-review action on a deny decision: remove the dormant role assignment.
- Evidence: review decisions and reviewer identity retained for the defined audit
  retention period.
- Required scopes: AccessReview.ReadWrite.All, AccessReview.ReadWrite.Membership,
  and RoleManagement.ReadWrite.Directory.
- Paired contract document: EIG-AR002-DormantAdminRoleReview.md.

## 8. Prerequisites

- Entra ID P2 licensing, required for Access Reviews.
- PowerShell 7.
- The Microsoft.Graph.Authentication module.
- The operator must consent to the Graph permission scopes listed for each script
  before that script is run.

## 9. Versioning

This design specification tracks the framework toward v0.1.0-preview. Changes to
the principles, naming convention, persona model, or per-script specs are recorded
in the root CHANGELOG under [Unreleased] until the framework is tagged.
