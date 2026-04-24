# Scripts

This folder contains deployment automation for the Conditional Access Baseline framework.

| Script | Purpose |
|--------|---------|
| Deploy-CABaseline.ps1 | Imports the six CA-COV, CA-SIG, and CA-AUT policy templates into a Microsoft Entra tenant. Resolves tenant-specific placeholders at runtime, defaults to report-only state, and supports -WhatIf for safe preview. |
| Get-CABaselineImpact.ps1 | Analyzes Entra sign-in logs to report what each report-only CA policy would have done if enforced. Use this before promoting any policy from `enabledForReportingButNotEnforced` to `enabled` state. |

## Prerequisites

Before running any script in this folder, confirm the following are in place in your tenant and on your machine. Graph scopes differ per script — see each script's section below.

### On your machine

- **PowerShell 7.0 or later.** The deployer uses ConvertFrom-Json -AsHashtable, which requires PowerShell 7.
- **Microsoft.Graph PowerShell SDK (version 2.x).** Install with:

  ```powershell
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```

### In your tenant

- Four persona groups exist with these exact display names (or override via script parameters):
  - CA-Persona-EmergencyAccess
  - CA-Persona-WorkloadIdentities
  - CA-Persona-GlobalAdmins
  - CA-Persona-InternalUsers
- Emergency access accounts are created, documented, monitored by alert, and members of the CA-Persona-EmergencyAccess group only.
- The built-in Phishing-resistant MFA authentication strength policy exists (this is a default in Entra ID P1+).

## Deploy-CABaseline.ps1

### Permissions to connect

Connect to Microsoft Graph with all three scopes below before running the script:

```powershell
Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess,Group.Read.All,Policy.Read.All,Application.Read.All
```

### Usage

#### Preview mode (no changes made)

```powershell
.\Deploy-CABaseline.ps1 -WhatIf
```

Runs every read operation — group lookups, authentication strength lookup, template parsing, placeholder substitution — but stops before creating any policy. Use this the first time you run the script to validate that all placeholders resolve cleanly in your tenant.

#### Report-only deployment (default, safe)

```powershell
.\Deploy-CABaseline.ps1
```

Creates all six policies in enabledForReportingButNotEnforced state. Policies evaluate every sign-in and log the outcome, but never block or challenge a user. This is the safe default for every first deployment.

#### Enforced deployment (destructive, requires confirmation)

```powershell
.\Deploy-CABaseline.ps1 -Enforce
```

Creates all six policies in enabled state. Prompts once for confirmation before touching the tenant. Only run this after:

1. A full report-only soak period per Policy-Design.md section 5.
2. Validation that every user in scope has the prerequisites for each policy (MFA registration for CA-COV002, phishing-resistant credentials for CA-AUT001/002, device compliance for CA-SIG001).
3. Review and tuning of Entra ID Protection risk detections for CA-SIG002.

#### Custom persona group names

If your tenant uses different display names for the persona groups, override them via parameters:

```powershell
.\Deploy-CABaseline.ps1 -EmergencyAccessGroupName 'BreakGlass-Accounts' -GlobalAdminsGroupName 'Tier0-Admins'
```

See the script's comment-based help (`Get-Help .\Deploy-CABaseline.ps1 -Full`) for the complete parameter list.

### Expected output

Successful report-only deployment produces output similar to:

```
[INFO] Deploy-CABaseline starting
[INFO] Mode: report-only (safe default)
[OK]   Connected tenant: <tenant-id> as <user-upn>
[INFO] Resolving tenant-specific placeholders...
[OK]     REPLACE_WITH_EMERGENCY_ACCESS_GROUP_OBJECT_ID -> <guid>
[OK]     REPLACE_WITH_WORKLOAD_IDENTITIES_GROUP_OBJECT_ID -> <guid>
[OK]     REPLACE_WITH_GLOBAL_ADMINS_GROUP_OBJECT_ID -> <guid>
[OK]     REPLACE_WITH_INTERNAL_USERS_GROUP_OBJECT_ID -> <guid>
[OK]     REPLACE_WITH_PHISHING_RESISTANT_MFA_STRENGTH_ID -> <guid>
[OK]   Found 6 policy templates in ../Policies
[INFO] Processing: CA-AUT001-PrivAccounts-RequirePhishResistantMFA.json
[OK]     Created: CA-AUT001-PrivAccounts-RequirePhishResistantMFA [<guid>]
... (one entry per template) ...
[INFO] Created: 6, Previewed: 0, Errors: 0
[INFO] Reminder: Policies are in report-only mode. Soak, validate, and promote to enforced per Policy-Design.md section 5.
```

### Troubleshooting

#### "Group not found in tenant"

One of the persona groups does not exist or is named differently. Verify with:

```powershell
Get-MgGroup -Filter "displayName eq 'CA-Persona-EmergencyAccess'"
```

Create the missing group or override the parameter with your tenant's actual group name.

#### "Authentication strength not found"

The built-in Phishing-resistant MFA authentication strength is missing or has been renamed. Verify with:

```powershell
Invoke-MgGraphRequest GET 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies'
```

If the built-in is renamed in your tenant, pass the custom name via -AuthStrengthName.

#### "Not connected to Microsoft Graph"

Run Connect-MgGraph with the three required scopes listed above. A session with fewer scopes will be rejected with a clear error.

#### "Unresolved placeholders remain"

A JSON template contains a REPLACE_WITH_ token that the script does not know how to substitute. Open an issue in the repo with the template name — this indicates a bug in the substitution map.

#### A policy import fails mid-run

Per-policy errors do not cascade. The script logs the failure, continues to the next template, and produces a summary table at the end. Re-run after fixing the underlying issue — successfully created policies will attempt to be re-created and fail with a duplicate-name error, which is safe. If you want to retry from a clean state, delete the successful policies in Entra first.

## Get-CABaselineImpact.ps1

### Permissions to connect

Connect to Microsoft Graph with all three scopes below before running the script:

```powershell
Connect-MgGraph -Scopes AuditLog.Read.All,Directory.Read.All,Policy.Read.All
```

### Usage

#### Default — last 7 days, all CA-* policies

```powershell
.\Get-CABaselineImpact.ps1
```

Pulls sign-in logs for the last seven days and summarizes the impact of every policy whose display name contains `CA-`.

#### Custom window with CSV export

```powershell
.\Get-CABaselineImpact.ps1 -Days 14 -ExportCsvPath .\impact.csv
```

Two-week window. Writes one row per (sign-in, policy) evaluation to `impact.csv` for pivoting in Excel.

#### Filter to a specific pillar

```powershell
.\Get-CABaselineImpact.ps1 -PolicyNameFilter 'CA-COV'
```

Only evaluates coverage-pillar policies. Swap for `CA-SIG` or `CA-AUT` to target the other pillars.

#### Explicit start and end dates

```powershell
.\Get-CABaselineImpact.ps1 -StartDate '2026-04-01' -EndDate '2026-04-15'
```

Overrides -Days with an explicit window. Useful for retrospective analysis or reproducing a prior report.

### Output

Per-policy summary table with:

- **Evaluations** — total times the policy was evaluated in the window
- **UniqueUsers** — distinct users affected
- **WouldBlock** — `reportOnlyFailure` count (grant controls would have failed)
- **WouldChallenge** — `reportOnlyInterrupted` count (user would have been prompted — MFA, auth strength)
- **WouldPass** — `reportOnlySuccess` count (user already satisfied grant controls)
- **NotApplied** — conditions did not match the sign-in

Followed by a top-10 list of users by would-block + would-challenge count — useful for identifying accounts that need remediation (enroll MFA, join device to Entra, etc.) before enforcement.

### Promotion rubric

Before promoting a policy from report-only to enabled state:

1. Run with `-Days 14` to get a full two-week sample.
2. Confirm **WouldBlock + WouldChallenge** affects only the expected personas.
3. For each unique user in the top-10 list, confirm they can satisfy the grant controls (MFA registered, device compliant, etc.).
4. Communicate the enforcement date to affected users if the count is non-trivial.
5. Promote the policy and re-run 24 hours later to confirm the enforced result matches the report-only prediction.

### Troubleshooting

#### "No policy evaluations matched filter"

Either the tenant has no sign-ins matching the filter in the window, or the policies haven't been deployed yet. Verify with:

```powershell
Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -like 'CA-*' } | Select-Object DisplayName, State
```

If policies are deployed but the window is quiet, widen it with `-Days 30`.

#### "Not connected to Microsoft Graph" or "missing required scopes"

Run Connect-MgGraph with the three required scopes listed above. A session with fewer scopes will be rejected with a clear error.

#### Slow runs on large tenants

Sign-in log pagination handles page sizes up to 1000 events. Tenants with hundreds of thousands of daily sign-ins can take several minutes. Narrow the window with `-Days` or a specific `-StartDate` / `-EndDate` if needed.

#### CSV export is empty

If no sign-ins matched the filter, no records are written. Check the per-policy summary first — if every count is zero, there's nothing to export.

## Reference

- Policy-Design.md — baseline philosophy, naming convention, persona model, rollout sequence
- Policies/ — the six JSON policy templates consumed by Deploy-CABaseline.ps1
- Repo root README — framework overview and business-case positioning
