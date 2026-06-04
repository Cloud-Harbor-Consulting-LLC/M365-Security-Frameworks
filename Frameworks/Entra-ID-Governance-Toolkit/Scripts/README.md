# Entra ID Governance Toolkit: Scripts

This folder holds the self-invoking PowerShell scripts that stand up the Entra ID
Governance Toolkit access review controls. Each script is paired with a contract
document of the same base name that describes, in plain language, what the script
configures and the commitments the control makes.

## Scripts

### EIG-AR001 Quarterly Guest Access Review

- Purpose: stands up a recurring quarterly access review over B2B guest
  membership across all Microsoft 365 groups, with deny-by-default decisions and
  auto-applied removal of denied guests.
- Recurrence: quarterly.
- Required scopes: `AccessReview.ReadWrite.All`, `AccessReview.ReadWrite.Membership`.
- Contract: [EIG-AR001-QuarterlyGuestAccessReview.md](EIG-AR001-QuarterlyGuestAccessReview.md).

### EIG-AR002 Monthly Dormant Admin Role Review

- Purpose: stands up a recurring monthly access review over dormant
  administrative role assignments, using a 30-day inactivity look-back so
  assignments not exercised in the prior 30 days are recommended for denial, with
  deny-by-default decisions and auto-applied removal of denied assignments.
- Recurrence: monthly.
- Required scopes: `AccessReview.ReadWrite.All`, `AccessReview.ReadWrite.Membership`,
  `RoleManagement.ReadWrite.Directory`.
- Contract: [EIG-AR002-DormantAdminRoleReview.md](EIG-AR002-DormantAdminRoleReview.md).

## Shared prerequisites

- Entra ID P2 licensing, required for Access Reviews.
- PowerShell 7.
- The Microsoft.Graph.Authentication module.
- The operator consents to the Graph permission scopes listed for a script before
  that script is run.

## Deployment model

Scripts are self-invoking and independent. There is no unified deployer or
orchestration runner at v0.1.0-preview; each script is run on its own. Before a
script can create anything, the operator resolves the `REPLACE_WITH_*`
placeholders it ships with, which are documented in that script's paired
contract. The run guard refuses to create a review definition while any
placeholder is unresolved.
