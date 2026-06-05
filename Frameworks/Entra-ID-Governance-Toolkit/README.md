# Entra ID Governance Toolkit

Practical Microsoft Entra ID Governance automation, starting with Access Reviews and extending to Lifecycle Workflows and Privileged Identity Management governance. Part of the Cloud Harbor Consulting M365 Security Frameworks.

> **Status: Preview (v0.1.0-preview)**

## What this framework does

Standing access that no one reviews is how guest sprawl and privilege creep take hold. This framework automates the recurring governance controls that keep access time-bound and auditable: scheduled Access Reviews with a clear reviewer chain, a deny-by-default decision when no one responds, and a retained evidence trail for audit. The scripts are PowerShell 7 against the Microsoft Graph Identity Governance API, and each one is paired with a plain-language contract doc so an adopter can read what it does before running it.

## Scope

- v0.1.0-preview: Access Reviews automation. 2 starter scripts (quarterly guest access review, dormant admin role review).
- v1.0 target: Lifecycle Workflows and PIM governance scripts.

## Framework principles

1. Time-bound access by default. Access is granted for a window, not in perpetuity, and every grant has a review date.
2. Reviewer accountability with a sign-off trail. Every review names a responsible reviewer and records the decision.
3. Recurrence enforcement at the workflow level. Reviews repeat on a fixed cadence so governance does not depend on someone remembering.
4. Evidence retention for audit. Review outcomes are retained as audit evidence, not discarded when the review closes.

## Naming convention

`EIG-[Domain][Number]-[Description]`

| Prefix | Domain |
|--------|--------|
| EIG-AR | Access Reviews |
| EIG-LW | Lifecycle Workflows |
| EIG-PIM | Privileged Identity Management governance |

## Scripts inventory

| Script | Purpose | Status |
|--------|---------|--------|
| EIG-AR001-QuarterlyGuestAccessReview | Quarterly Access Review of all B2B guests | Available (v0.1.0-preview) |
| EIG-AR002-DormantAdminRoleReview | Monthly review of admin role assignments dormant 30+ days | Available (v0.1.0-preview) |

## Business case

For the executive ROI, risk-reduction, and compliance framing, see [Business-Case/ROI-ENTRA-GOVERNANCE.md](Business-Case/ROI-ENTRA-GOVERNANCE.md).

## Deployment workflow

Each script is self-invoking. There is no unified deployer at v0.1.0-preview. Access Reviews are recurring configurations rather than one-shot deployments, so an adopter tunes the parameters at the top of each script and runs it once to stand the review up in their tenant. A unified runner may follow in a later release if adopter demand warrants.

## Prerequisites

- PowerShell 7 or later.
- The `Microsoft.Graph.Authentication` module.
- A Microsoft Entra ID P2 license (required for Access Reviews and PIM).
- Microsoft Graph scopes: `AccessReview.ReadWrite.All`, `AccessReview.ReadWrite.Membership`, and `RoleManagement.ReadWrite.Directory` for the dormant admin role review.

## Repository

Part of [M365-Security-Frameworks](https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks). Licensed under MIT.
