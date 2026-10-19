# Intune Compliance Baseline — Scripts

## Deploy-ICBaseline.ps1

Deploys the ICB compliance policy templates in [`../Policies`](../Policies/) to a Microsoft Intune tenant through Microsoft Graph beta. It deploys in **observation mode** unless told otherwise, it is safe to re-run, and it reads back everything it writes.

Read [POLICY-DESIGN.md](../Design/POLICY-DESIGN.md) sections 5 and 7 before the first run.

### Prerequisites

- PowerShell 7 and the Microsoft.Graph.Authentication module: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`
- An account with the Intune Administrator role (or higher).
- Microsoft Graph scopes `DeviceManagementConfiguration.ReadWrite.All` and `Group.Read.All`.
- The persona groups each template targets (POLICY-DESIGN.md section 3). Defaults: `ICB-Persona-CorpWindows`, `ICB-Persona-CorpMac`, `ICB-Persona-CorpMobile`, `ICB-Persona-BYODMobile`, `ICB-Persona-CorpLinux`. Only the groups used by the templates being deployed must exist.
- For `-Enforce` only: an Intune notification message template, default name `ICB - Device noncompliant`.
- The tenant-wide settings in POLICY-DESIGN.md section 7.1. The script checks them and warns; it never changes them.

```powershell
Connect-MgGraph -Scopes DeviceManagementConfiguration.ReadWrite.All, Group.Read.All
```

### Usage

| Goal | Command |
|---|---|
| Preview: read the tenant, write nothing | `.\Deploy-ICBaseline.ps1 -WhatIf` |
| Deploy every template in observation mode | `.\Deploy-ICBaseline.ps1` |
| Deploy one platform | `.\Deploy-ICBaseline.ps1 -Template 'ICB-WIN*'` |
| Promote a template after its observation period | `.\Deploy-ICBaseline.ps1 -Template 'ICB-WIN001*' -Enforce` |
| Return a template to observation mode | `.\Deploy-ICBaseline.ps1 -Template 'ICB-WIN001*'` |
| Overwrite settings changed in the tenant | `.\Deploy-ICBaseline.ps1 -UpdateExisting` |

Group and template names can be overridden with `-CorpWindowsGroupName`, `-CorpMacGroupName`, `-CorpMobileGroupName`, `-BYODMobileGroupName`, `-CorpLinuxGroupName` and `-NotificationTemplateName`. `-StopOnError` stops at the first failing template; `-Force` skips the `-Enforce` confirmation.

### Modes

**Observation (default).** Every policy carries one action: mark the device noncompliant after 365 days, the longest delay Intune allows. No email is sent and no device is added to a retire list. Intune's compliance reports show every failing setting, while Conditional Access treats the device as compliant because it is in its grace period. Intune compliance policies have no report-only state and cannot drop the mark-noncompliant action, so this is the closest equivalent to the Conditional Access Baseline's report-only default.

**Enforce (`-Enforce`).** Each policy gets the schedule designed into its template (POLICY-DESIGN.md section 5.1): an email at 0 hours, mark noncompliant at 0 or 168 hours, and, for personally owned Android, "add to retire list" at 30 days. Once a schedule elapses, any Conditional Access policy that requires a compliant device starts blocking that device.

Switching mode replaces the policy's schedule in place. The policy keeps its ID, assignments and reporting history.

### What a run does

Each template is matched to an existing policy by name:

| In the tenant | Result | Status |
|---|---|---|
| No policy of that name | Created with the mode's schedule, assigned to its persona group, read back | `Created` |
| Present, schedule differs from the mode | Schedule replaced | `Updated` |
| Present, persona group not assigned | Group added; other assignments kept | `Updated` |
| Present, settings differ from the template | Reported and left alone; overwritten with `-UpdateExisting` (classic policies only) | `Drift` |
| Present and matching | Nothing written | `Unchanged` |

After every write the script reads the policy back and compares each template setting, the schedule and the assignment. Anything that did not land as sent fails the template with `Read-back mismatch`. One reason this matters: Graph accepts a Linux (Settings Catalog) policy created with an inline schedule, returns success, and stores its own default, mark noncompliant at 0 hours, instead. The script therefore sets Linux schedules with a separate call after creation and confirms the result.

The run ends with a table and a count of each status. It exits 1 if any template failed.

### Expected output

```text
[INFO] Deploy-ICBaseline starting
[INFO] Mode: observation (mark noncompliant after 8760 hours, no email)
[OK]   Templates: 2 in C:\...\Policies
[OK]   Connected tenant: 00000000-0000-0000-0000-000000000000
[WARN] Tenant setting 'Compliance status validity period' is 30 days. ICB expects 7 or fewer (POLICY-DESIGN.md section 7.1).
[OK]   ICB-LIN001-Baseline-EncryptionAndPassword: Created (created, schedule set, assigned)
[OK]   ICB-WIN001-Baseline-DefenderAndBitLocker: Created (created, assigned)
[INFO] Created: 2  Updated: 0  Unchanged: 0  Drift: 0  WhatIf: 0  Errors: 0
```

### Troubleshooting

| Message | Cause and fix |
|---|---|
| `Group not found in tenant: '…'` | Create the persona group, or pass its name with the matching `-<Persona>GroupName` parameter. |
| `Notification message template not found` | `-Enforce` emails users. Create the template under Endpoint security › Device compliance › Notifications, or pass `-NotificationTemplateName`. |
| `The Graph session lacks …` | Reconnect with both scopes, as above. |
| `… policies in the tenant are named '…'` | Two policies share a template's name. Rename or delete the extra one; the script will not guess. |
| `A policy named '…' exists but is a …` | A policy for another platform already uses the name. |
| `Read-back mismatch after …` | A value did not land as sent. The message names it. Check the policy in the Intune admin center, then re-run. |
| `Drift: …` | Someone changed the policy's settings in the tenant. Re-run with `-UpdateExisting` to restore the template's values, or update the template if the change was intended. |
| `Graph returned 429 …; retrying` | Throttling. The script honours `Retry-After` and retries up to `-MaxRetries` times (default 4). |

### Tests

`Tests/Intune-Compliance-Baseline/Deploy-ICBaseline.Harness.ps1` runs this script against a fake of both Intune compliance APIs built from responses recorded on a live tenant, including the empty response bodies and the Linux schedule behaviour described above. CI runs it on every change.
