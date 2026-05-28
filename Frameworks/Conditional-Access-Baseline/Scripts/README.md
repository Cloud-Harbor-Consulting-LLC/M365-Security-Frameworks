# Scripts

This folder contains deployment automation for the Conditional Access Baseline framework.

| Script | Purpose |
|---|---|
| Deploy-CABaseline.ps1 | Imports all 23 CA policy templates into a Microsoft Entra tenant. Resolves tenant-specific placeholders at runtime. Defaults to report-only state. Supports `-WhatIf` for safe preview without a Graph connection. Targets the Microsoft Graph beta endpoint. |
| Get-CABaselineImpact.ps1 | Analyzes Entra sign-in logs to report what each report-only CA policy would have done if enforced. Use this before promoting any policy from `enabledForReportingButNotEnforced` to `enabled` state. Targets the Microsoft Graph beta sign-in log endpoint. |

## Beta endpoint commitment

Both scripts target `https://graph.microsoft.com/beta/` endpoints. Three policies in the baseline require beta-only features: `CA-SIG003` and `CA-SIG004` use `signInFrequency.frequencyInterval: "everyTime"`, and `CA-COV011` uses the Microsoft Agent ID condition family (`agentIdRiskLevels`, `AllAgentIdResources`, `IncludeAgentIdServicePrincipals`). The framework commits to the beta endpoint for all 23 policies to keep a single deployer code path. See `Design/AGENTS-PERSONA-MODEL.md` section 6 for the GA promotion tracking commitment.

## Prerequisites

Before running any script in this folder, confirm the following are in place in your tenant and on your machine.

### On your machine

- **PowerShell 7.0 or later.** The deployer uses `ConvertFrom-Json -AsHashtable`, which requires PowerShell 7.
- **Microsoft.Graph.Authentication module (version 2.x).** The deployer requires only this one module — not the full Microsoft.Graph SDK. Install with:

  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  ```

### In your tenant

Five persona groups must exist with exact display names, or override the defaults via script parameters:

- `CA-Persona-EmergencyAccess` — exactly 2 members, monitored by alert rule per `Policies/CA-EXC001-EmergencyAccess-Exclusion.md`
- `CA-Persona-WorkloadIdentities` — per `Design/POLICY-DESIGN.md` section 3
- `CA-Persona-InternalUsers` — dynamic group recommended (`userType eq 'Member'`)
- `CA-Persona-ServiceAccounts` — attested per `Policies/CA-EXC002-ServiceAccounts-Exclusion.md`
- `CA-Persona-Guests` — dynamic group recommended (`userType eq 'Guest'`)

**Note on Agents persona:** The Agents persona does not require a persona group. Targeting is via Agent ID-specific filters in `CA-COV011` (`IncludeAgentIdServicePrincipals: ["All"]` and `IncludeApplications: ["AllAgentIdResources"]`). The deployer does not resolve an `AgentsGroupName` parameter. See `Policies/CA-EXC003-Agents-Persona.md` for the full Agents persona governance model.

Additional tenant prerequisites:

- Three custom authentication strengths created from `Supporting-Artifacts/CA-AUTH-STRENGTH-*.json` (StandardAuth, StrongAuth, AdminAuth).
- Trusted Countries named location created from `Supporting-Artifacts/CA-LOCATION-TrustedCountries.json`.
- Trusted IPs named location created for workload identity egress (see `Policies/CA-COV010-WorkloadIdentities.md`).

## Deploy-CABaseline.ps1

### Permissions to connect

Connect to Microsoft Graph with all required scopes before running the script in non-WhatIf mode:

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","Policy.Read.All","Group.Read.All","Application.Read.All","Policy.ReadWrite.AuthenticationMethod"
```

### Usage

#### Preview mode (no Graph connection required)

```powershell
.\Deploy-CABaseline.ps1 -WhatIf
```

Parses every JSON template in the Policies/ folder and reports what it would do. No tenant changes are made and no Graph connection is required. Use this to validate that all templates parse cleanly before connecting to a tenant.

#### Report-only deployment (default, safe)

```powershell
.\Deploy-CABaseline.ps1
```

Creates all 23 policies in `enabledForReportingButNotEnforced` state via the beta endpoint. Policies evaluate every sign-in and log the outcome, but never block or challenge a user.

#### Enforced deployment (requires confirmation)

```powershell
.\Deploy-CABaseline.ps1 -Enforce
```

Creates all 23 policies in `enabled` state. Prompts for confirmation before touching the tenant. Only run this after completing the report-only soak per `Design/POLICY-DESIGN.md` section 5.

#### Custom persona group names

```powershell
.\Deploy-CABaseline.ps1 -EmergencyAccessGroupName 'BreakGlass-Accounts' -InternalUsersGroupName 'Corp-Members'
```

See `Get-Help .\Deploy-CABaseline.ps1 -Full` for the complete parameter list.

#### Stop on first error

```powershell
.\Deploy-CABaseline.ps1 -StopOnError
```

Stops deployment after the first failed policy creation. Default behavior is to continue and report all errors at the end.

### Expected output

Successful report-only deployment produces output similar to:

```
[INFO] Deploy-CABaseline starting
[INFO] Mode: report-only (safe default)
[OK]   Connected tenant: <tenant-id> as <user-upn>
[INFO] Resolving tenant-specific placeholders...
[OK]     REPLACE_WITH_EMERGENCY_ACCESS_GROUP_OBJECT_ID -> <guid>
[OK]     REPLACE_WITH_WORKLOAD_IDENTITIES_GROUP_OBJECT_ID -> <guid>
[OK]     REPLACE_WITH_INTERNAL_USERS_GROUP_OBJECT_ID -> <guid>
[OK]     REPLACE_WITH_SERVICE_ACCOUNTS_GROUP_OBJECT_ID -> <guid>
[OK]     REPLACE_WITH_GUESTS_GROUP_OBJECT_ID -> <guid>
[OK]     REPLACE_WITH_TRUSTED_COUNTRIES_LOCATION_ID -> <guid>
[OK]     REPLACE_WITH_STANDARDAUTH_STRENGTH_ID -> <guid>
[OK]     REPLACE_WITH_STRONGAUTH_STRENGTH_ID -> <guid>
[OK]     REPLACE_WITH_ADMINAUTH_STRENGTH_ID -> <guid>
[OK]   Found 23 policy templates in ../Policies
[INFO] Processing: CA-AUT001-Global-RegisterDevice.json
[OK]     Created: CA-AUT001-Global-RegisterDevice [<guid>]
[INFO] Processing: CA-AUT002-Global-RegisterSecurityInfo.json
... (one entry per template) ...
[INFO] Created: 23  Previewed: 0  Errors: 0
[INFO] Reminder: Policies are in report-only mode. Soak, validate with Get-CABaselineImpact.ps1, and promote per Design/POLICY-DESIGN.md section 5.
```

### Troubleshooting

#### "Group not found in tenant"

A persona group does not exist or is named differently. Verify with:

```powershell
Get-MgGroup -Filter "displayName eq 'CA-Persona-EmergencyAccess'"
```

Create the missing group or override the parameter with your tenant's actual group name.

#### "Authentication strength not found"

A custom authentication strength is missing. Provision it from `Supporting-Artifacts/CA-AUTH-STRENGTH-*.json`. Verify with:

```powershell
Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies" |
    Select-Object -ExpandProperty value | Select-Object id, displayName
```

#### "Named location not found"

The Trusted Countries or Trusted IPs named location is missing. Provision it and retry. See `Supporting-Artifacts/` and `Policies/CA-COV010-WorkloadIdentities.md`.

#### "Unresolved placeholders remain"

A JSON template contains a `REPLACE_WITH_` token that the script's substitution map does not cover. Open an issue in the repo with the template name — this indicates a mismatch between the policy template and the deployer.

#### A policy import fails mid-run

Per-policy errors do not cascade by default. The script logs the failure, continues to the next template, and produces a summary table. Re-run after fixing the underlying issue. Successfully created policies will fail with a duplicate-name error on re-run — either delete them first or filter them from the run.

## Get-CABaselineImpact.ps1

### Permissions to connect

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All","Policy.Read.All"
```

### Usage

#### Default — last 7 days, all CA-* policies

```powershell
.\Get-CABaselineImpact.ps1
```

#### Custom window with CSV export

```powershell
.\Get-CABaselineImpact.ps1 -Days 14 -ExportCsvPath .\impact.csv
```

#### Filter to a specific pillar

```powershell
.\Get-CABaselineImpact.ps1 -PolicyNameFilter 'CA-COV'
```

Swap for `CA-SIG` or `CA-AUT` to target other pillars, or use a full policy name to filter to a single policy.

### Output

Per-policy summary table with:

- **Evaluations** — total times the policy was evaluated in the window
- **UniqueUsers** — distinct users affected
- **WouldBlock** — `reportOnlyFailure` count
- **WouldChallenge** — `reportOnlyInterrupted` count
- **WouldPass** — `reportOnlySuccess` count
- **NotApplied** — conditions did not match the sign-in

Followed by a top-10 list of users by would-block + would-challenge count.

### Promotion rubric

Before promoting a policy from report-only to enabled state:

1. Run with `-Days 14` for a full two-week sample.
2. Confirm **WouldBlock + WouldChallenge** affects only the expected personas.
3. For each user in the top-10 list, confirm they can satisfy the grant controls.
4. Communicate the enforcement date to affected users if the count is non-trivial.
5. Promote the policy and re-run 24 hours later to confirm the enforced result matches the report-only prediction.

## Reference

- `Design/POLICY-DESIGN.md` — baseline philosophy, naming convention, persona model, rollout sequence, per-policy specs
- `Policies/` — the 23 JSON policy templates consumed by Deploy-CABaseline.ps1
- `Design/AGENTS-PERSONA-MODEL.md` — Microsoft Agent ID technical overview and beta endpoint commitment
- Root README — framework overview and deployment workflow
