# EIG-AR001 Quarterly Guest Access Review

Paired contract for `EIG-AR001-QuarterlyGuestAccessReview.ps1`. This document is
the plain-language description of what the script configures and the commitments
the control makes. It is reviewed against design spec section 7.1.

## What it does

Creates a recurring quarterly Microsoft Entra access review covering B2B guest
user membership across all Microsoft 365 groups. The review recurs on a fixed
quarterly cadence defined in the review definition, so the control does not
depend on anyone remembering to run it.

## Scope

- Reviewed population: guest users (`userType eq 'Guest'`) who are members of
  Microsoft 365 (Unified) groups.
- Enumeration scope: all Microsoft 365 groups in the tenant.

## Recurrence

Quarterly. The recurrence pattern is `absoluteMonthly` with an interval of 3,
starting on the configured start date and continuing with no end date.

## Reviewer model

The primary reviewer is the guest sponsor where a sponsor is recorded on the
guest account. Where no sponsor is recorded, a named fallback team reviews the
guest.

CONFIRM-IN-TENANT: the exact reviewer query for guest sponsors was not verified
against a live tenant for this preview release. The sponsor reviewer query in
the script ships as a `REPLACE_WITH_VERIFIED_SPONSOR_REVIEWER_QUERY` placeholder.
Validate the sponsor reviewer query in your own tenant, then replace the
placeholder before running. The fallback reviewer block is verified and ready;
supply the fallback team object ID through the `FallbackReviewerId` parameter.
The script refuses to run while either placeholder is unresolved.

## Decision policy

Decisions default to Deny. If a reviewer does not respond before the review
closes, the guest is denied by default. There is no silent auto-approve.

## Post-review action

Decisions are auto-applied. A guest who is denied is removed from the reviewed
group.

## Evidence retention

Review decisions and reviewer identity are retained for the audit retention
period so an auditor can reconstruct who reviewed what, when, and with what
outcome.

## Required Graph permission scopes

- AccessReview.ReadWrite.All
- AccessReview.ReadWrite.Membership

## Prerequisites

- Entra ID P2 licensing.
- PowerShell 7.
- The Microsoft.Graph.Authentication module.
- The operator consents to the required scopes before the script is run.

## How to run

1. Resolve the placeholders. Set `FallbackReviewerId` to the object ID of the
   fallback reviewer team, and replace the sponsor reviewer query placeholder
   with the verified query for your tenant.
2. Preview without writing:

       ./EIG-AR001-QuarterlyGuestAccessReview.ps1 -FallbackReviewerId <object-id> -WhatIf

3. Create the review definition:

       ./EIG-AR001-QuarterlyGuestAccessReview.ps1 -FallbackReviewerId <object-id>

4. Confirm in the Entra admin center that the review definition was created with
   the expected quarterly recurrence and reviewer assignment.

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| FallbackReviewerId | REPLACE_WITH_FALLBACK_REVIEWERS_GROUP_OBJECT_ID | Object ID of the named fallback reviewer team |
| StartDate | today | First occurrence date in yyyy-MM-dd form |
| InstanceDurationInDays | 25 | Days each review instance stays open |
| DisplayName | EIG-AR001 Quarterly Guest Access Review | Display name for the review definition |
