# EIG-AR002 Monthly Dormant Admin Role Review

Paired contract for `EIG-AR002-DormantAdminRoleReview.ps1`. This document is the
plain-language description of what the script configures and the commitments the
control makes. It is reviewed against design spec section 7.2.

## What it does

Creates a recurring monthly Microsoft Entra access review covering administrative
role assignments that have gone dormant. The review applies a 30-day inactivity
look-back so that assignments not exercised in the prior 30 days are recommended
for denial. The review recurs on a fixed monthly cadence defined in the review
definition, so the control does not depend on anyone remembering to run it.

## Scope

- Reviewed population: principals (`/users`) holding an assignment to the named
  administrative directory role.
- Resource scope: a directory role, addressed as
  `/roleManagement/directory/roleDefinitions/{role id}`.
- The Microsoft Graph access reviews API does not expose a single query that
  targets every directory role at once. Each review targets one role definition;
  run the script once per privileged role you want under review. The role
  definition ID is supplied through the
  `REPLACE_WITH_DIRECTORY_ROLE_DEFINITION_ID` placeholder.

## Recurrence

Monthly. The recurrence pattern is `absoluteMonthly` with an interval of 1, on
day 1 of the month, starting on the configured start date and continuing with no
end date.

## Reviewer model

The primary reviewer is the role owner or a delegated governance reviewer. Where
no reviewer is resolvable, a named fallback group reviews the assignment.

CONFIRM-IN-TENANT: the exact reviewer query for the role owner / delegated
governance reviewer was not verified against a live tenant for this preview
release. Directory roles have no single documented "owner" reviewer query the
way a group owner does. The primary reviewer query in the script ships as a
`REPLACE_WITH_VERIFIED_PRIMARY_REVIEWER_QUERY` placeholder. Validate the primary
reviewer query in your own tenant, then replace the placeholder before running.
The fallback reviewer block is verified and ready; supply the fallback group
object ID through the `FallbackReviewerId` parameter. The script refuses to run
while any placeholder is unresolved.

## Decision policy

Decisions default to Deny. If a reviewer does not respond before the review
closes, the assignment is denied by default. There is no silent auto-approve. A
30-day inactivity look-back (`recommendationLookBackDuration` of `P30D`) drives a
deny recommendation for any assignment dormant for 30 or more days.

## Post-review action

Decisions are auto-applied. An assignment that is denied is removed from the
role.

## Evidence retention

Review decisions and reviewer identity are retained for the audit retention
period so an auditor can reconstruct who reviewed what, when, and with what
outcome.

## Required Graph permission scopes

- AccessReview.ReadWrite.All
- AccessReview.ReadWrite.Membership
- RoleManagement.ReadWrite.Directory

## Prerequisites

- Entra ID P2 licensing.
- PowerShell 7.
- The Microsoft.Graph.Authentication module.
- The operator consents to the required scopes before the script is run.

## Placeholders to resolve before running

| Placeholder | Where | Meaning |
| --- | --- | --- |
| REPLACE_WITH_FALLBACK_REVIEWERS_GROUP_OBJECT_ID | `FallbackReviewerId` parameter | Object ID of the named fallback reviewer group. Verified shape. |
| REPLACE_WITH_DIRECTORY_ROLE_DEFINITION_ID | `$roleDefinitionId` in the script | Role definition ID of the administrative role to review. Verified shape; tenant-specific value. |
| REPLACE_WITH_VERIFIED_PRIMARY_REVIEWER_QUERY | `$reviewers` in the script | CONFIRM-IN-TENANT. Reviewer query for the role owner / delegated governance reviewer. Validate in your tenant before replacing. |

## How to run

1. Resolve the placeholders. Set `FallbackReviewerId` to the object ID of the
   fallback reviewer group, replace `REPLACE_WITH_DIRECTORY_ROLE_DEFINITION_ID`
   with the role definition ID of the role you are reviewing, and replace the
   primary reviewer query placeholder with the verified query for your tenant.
2. Create the review definition:

       ./EIG-AR002-DormantAdminRoleReview.ps1 -FallbackReviewerId <object-id>

3. Confirm in the Entra admin center that the review definition was created with
   the expected monthly recurrence, reviewer assignment, and 30-day inactivity
   look-back.

The script supports `-WhatIf`. Note that the run guard throws while any
placeholder is unresolved, so a dry run completes only after the placeholders
are resolved in your tenant.

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| FallbackReviewerId | REPLACE_WITH_FALLBACK_REVIEWERS_GROUP_OBJECT_ID | Object ID of the named fallback reviewer group |
| StartDate | today | First occurrence date in yyyy-MM-dd form |
| InstanceDurationInDays | 25 | Days each review instance stays open |
| DisplayName | EIG-AR002 Monthly Dormant Admin Role Review | Display name for the review definition |
