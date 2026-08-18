# ZTRA Scripts
This folder contains two scripts for the Zero Trust Readiness Assessment Framework.
- **Get-ZTReadinessScore.ps1** — collector: reads Microsoft Graph and returns a `ZTRAResult` object
- **Format-ZTReadinessReport.ps1** — formatter: converts a `ZTRAResult` into 3 output report shapes (PR D)
---
## Prerequisites
| Requirement | Detail |
|---|---|
| PowerShell | 7.0 or later |
| Module | `Microsoft.Graph.Authentication` — install via `Install-Module Microsoft.Graph.Authentication` |
| Permissions | Global Reader, or a custom role granting the 6 Graph scopes below |
| License | Entra ID P2 required for PIM and ID Protection signals (ID-02, ID-04–ID-06) |
---
## Required Graph scopes
| Scope | Pillar(s) |
|---|---|
| `Policy.Read.All` | Identities, Endpoints, Networks (CA policies, authorization policy) |
| `IdentityRiskyUser.Read.All` | Identities (risky user count) |
| `AuditLog.Read.All` | Cross-pillar (sign-in logs) |
| `Device.Read.All` | Endpoints (device registration and join type) |
| `RoleManagement.Read.Directory` | Identities (directory role assignments; PIM role eligibility/assignment schedule instances) |
| `Reports.Read.All` | Cross-pillar (authentication method registration) |
| `Application.Read.All` | Infrastructure (`applications` — workload identity credential lifetime) |
| `AccessReview.Read.All` | Identities (`identityGovernance/accessReviews/definitions` — ID-07) |
| `EntitlementManagement.Read.All` | Applications (`identityGovernance/entitlementManagement/accessPackages` — AP-06) |
| `DelegatedPermissionGrant.Read.All` | Applications (`oauth2PermissionGrants` — AP-02) |
| `SensitivityLabels.Read.All` | Data (`security/dataSecurityAndGovernance/sensitivityLabels` — DA-01) |

The last four were added after a live run. They were missing while the endpoints were still being called, and the gap was invisible on any workstation that had already consented to them for another tool: the Microsoft Graph PowerShell client carries previously consented scopes forward, so those calls succeeded on a machine that had run the ITPS collector and would have returned `403` on a fresh one.

**Adding scopes means re-consenting.** The first run after this change prompts for the new permissions.

**Sensitivity labels are global-service only.** `GET /security/dataSecurityAndGovernance/sensitivityLabels` is GA in Microsoft Graph v1.0 and returns the tenant's label taxonomy. It is *not* published for US Government L4, US Government L5 (DOD), or China operated by 21Vianet, so in those clouds the call fails and DA-01 falls to manual review with no stage. Note the namespace: the resource sits under `security/dataSecurityAndGovernance`, not `informationProtection` — `informationProtection/sensitivityLabels` and `security/informationProtection/sensitivityLabels` both return HTTP 400. `SensitivityLabel.Read` is the least-privileged delegated alternative, but `SensitivityLabels.Read.All` is what returns the full tenant taxonomy rather than the labels published to the calling user.

---
## Authentication
**Interactive (recommended for initial assessment):**
```powershell
.\Get-ZTReadinessScore.ps1 -TenantId '<your-tenant-id>'
```
A browser sign-in prompt appears. Sign in with an account that holds the scopes above.
**Service principal (unattended / automation):**
```powershell
Connect-MgGraph -TenantId '<tenant-id>' -ClientId '<app-id>' -CertificateThumbprint '<thumbprint>'
.\Get-ZTReadinessScore.ps1 -TenantId '<tenant-id>'
```
Grant the 7 application permissions above to the app registration and obtain admin consent before running.
---
## Collector usage
```powershell
# Basic — interactive auth, result returned to pipeline
$result = .\Get-ZTReadinessScore.ps1 -TenantId '<tenant-id>'
# Export JSON for archiving or sharing
.\Get-ZTReadinessScore.ps1 -TenantId '<tenant-id>' -ExportJson -OutputPath 'C:\Reports'
# Pass result to formatter (PR D)
$result = .\Get-ZTReadinessScore.ps1 -TenantId '<tenant-id>'
.\Format-ZTReadinessReport.ps1 -Result $result -OutputPath 'C:\Reports'
```
### Parameters
| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `TenantId` | String | Yes | — | Entra tenant ID to assess |
| `OutputPath` | String | No | `.` | Directory for JSON export |
| `ExportJson` | Switch | No | Off | Exports result to timestamped JSON file |
---
## Output object shape
```
ZTRAResult
├── TenantId           (string)
├── AssessmentDate     (ISO 8601 string)
├── CollectorVersion   (string)
├── OverallStage       (int 1–4, nullable)
├── ManualReviewCount  (int)
├── GraphScopesUsed    (string[])
└── Pillars[]
    ├── Name           (string)
    ├── Stage          (int 1–4, nullable)
    └── Controls[]
        ├── Id               (string, e.g. "ID-01")
        ├── Name             (string)
        ├── NistTenets       (string[])
        ├── RepoXRef         (string)
        ├── Stage            (int 1–4, nullable — null when ManualReview = true and no partial signal)
        ├── ManualReview     (bool)
        ├── ManualReviewNote (string — portal navigation instructions)
        └── Signal           (hashtable — raw Graph values observed)
```
---
## Manual review guidance
Controls flagged `ManualReview = $true` require portal assessment. Each control's
`ManualReviewNote` field contains exact navigation instructions. The table below
lists all controls requiring manual assessment in v0.1.0-preview and why.
| Control | Reason | Portal location |
|---|---|---|
| ID-08 | Requires `Application.Read.All` | Entra admin center > Enterprise applications |
| EP-02 | Requires `DeviceManagementConfiguration.Read.All` | Intune admin center > Devices > Compliance policies |
| EP-04 | Requires `DeviceManagementApps.Read.All` | Intune admin center > Apps > App protection policies |
| EP-05 | Requires `DeviceManagementConfiguration.Read.All` | Intune admin center > Endpoint security > Security baselines |
| EP-06 | Requires `DeviceManagementConfiguration.Read.All` | Intune admin center > Devices > Compliance policies |
| EP-07 | Requires `DeviceManagementManagedDevices.Read.All` | Defender portal > Settings > Endpoints > Onboarding |
| AP-01 | Defender for Cloud Apps not in Graph | Defender portal > Cloud Apps > Cloud discovery |
| AP-04 | Purview DLP not in Graph | Purview compliance portal > Data loss prevention |
| AP-05 | Defender for Cloud Apps not in Graph | Defender portal > Cloud Apps > Policies |
| DA-01* | Purview auto-labeling / coverage not in Graph | Purview compliance portal > Information protection |
| DA-02 | Purview label encryption not in Graph | Purview compliance portal > Information protection |
| DA-03 | Container labels / SharePoint sharing not in Graph | Purview compliance portal + SharePoint admin center |
| DA-04 | Purview DLP not in Graph | Purview compliance portal > Data loss prevention |
| DA-05 | Purview IRM not in Graph | Purview compliance portal > Insider risk management |
| DA-06 | Purview retention not in Graph | Purview compliance portal > Data lifecycle management |
| DA-07 | Purview Content Explorer not in Graph | Purview compliance portal > Content explorer |
| IN-01 | PIM for Azure resource roles is managed via the Azure Resource Manager APIs, not Microsoft Graph | Entra admin center > PIM > Azure resources |
| IN-02* | Managed identity coverage requires Azure Management API | Azure portal > resource > Identity |
| IN-03 | Defender for Cloud + Sentinel require Azure Management API | Defender for Cloud + Sentinel |
| IN-04 | Azure RBAC requires Azure Management API | Azure portal > Subscriptions > IAM |
| IN-05 | Vulnerability data requires Azure Management API | Defender for Cloud > Recommendations |
| IN-06 | Azure Policy requires Azure Management API | Azure portal > Policy > Compliance |
| NW-01 | GSA Private Access not in standard Graph scopes | Entra admin center > Global Secure Access > Private access |
| NW-02 | GSA Internet Access not in standard Graph scopes | Entra admin center > Global Secure Access > Internet access |
| NW-04 | Azure VNet / NSG / Firewall require Azure Management API | Azure portal > Virtual networks |
| NW-05 | TLS policy details require Azure Management API | Entra admin center > GSA > Internet access > TLS inspection |
| NW-06 | NSG flow logs + Sentinel connectors require Azure Management API | Azure portal > Network Watcher + Sentinel |
*Controls marked * have a partial Graph signal — Stage may be computed for what is available; ManualReview = $true indicates the signal is incomplete.*
---
## How the display name is resolved

`TenantId` is the tenant GUID and is what the collector authenticates with. `TenantName` is presentation only. The formatter resolves the report label in this order:

1. `-TenantName` passed to the formatter (explicit override)
2. `TenantName` carried in the `ZTRAResult` from the collector
3. the tenant GUID

Supplying `-TenantName` on the **collector** is usually enough — the name travels with the result object, so the JSON export is self-describing and the formatter picks it up without repeating it:

```powershell
.\Get-ZTReadinessScore.ps1 -TenantId '<tenant-guid>' -TenantName 'Cloud Harbor Demo' -ExportJson -OutputPath '.eports'
.\Format-ZTReadinessReport.ps1 -InputPath '.eports\ZTRAResult-<timestamp>.json' -OutputPath '.eports'
```

The name also sets the output filenames, so reports read `Cloud-Harbor-Demo-2026-08-18-board.md` rather than a GUID. Result files produced before the collector carried `TenantName` still format correctly and fall back to the GUID.

## Absent, unassessable, and unanswered

The collector distinguishes three outcomes per Graph call, and they are scored differently.

| Outcome | Meaning | Effect |
|---|---|---|
| Call succeeds, records returned | The control exists and can be evaluated | Scored on its merits |
| Call succeeds, **zero records** | The signal is genuinely absent | Scored on that basis |
| Call fails | The control **could not be assessed** | `ManualReview`, with the Graph error recorded |

The middle row is the one that used to break the collector. `$x = try { fn } catch { @() }` yields `$null` when the result is empty, because PowerShell unrolls an empty collection to zero pipeline objects — so a tenant with **zero risky users**, the ideal state, produced the same `$null` as a failed call, and the next line's `.Count` threw under `Set-StrictMode -Version Latest`. All collection calls now route through `Invoke-ZTCollection`, which reports success-with-data, success-but-empty, and failure as distinct outcomes.

The distinction also matters to scoring. ID-05 reaches Stage 4 only when the risky-user call **succeeded** and returned nothing. A failed call returns nothing too, and reading that as a clean tenant would award the top stage for an unanswered question.

## Throttling and paging

Microsoft Graph throttles **per service, not per tenant**, so one endpoint can return `429 TooManyRequests` while every other call in the same run succeeds. The Identity Governance endpoints have tighter limits than most, and repeated assessments of the same tenant within an hour can reach them.

The collector retries transient failures (429, 500, 502, 503, 504) up to `-MaxRetry` times, honouring the `Retry-After` header where Graph sends one and falling back to exponential backoff where it does not, capped at 60 seconds per wait. Each wait prints a line naming the status code, the endpoint, and the retry number, so a pause is never silent:

```
  ! Graph returned 429 for identityGovernance/accessReviews/definitions. Waiting 12s, then retry 1 of 5.
```

Non-transient failures such as `403` are not retried and fail immediately with the status code and the message Graph returned.

Paging is bounded by `-MaxPages` (default 200). Hitting the ceiling is reported rather than passed over, because a silently truncated collection would misstate a stage. The `devices` endpoint is the one most likely to page heavily on a large tenant.

## Scoring logic
**Control stage:** 1–4, assigned by the collector from Graph evidence. Null when
`ManualReview = $true` and no partial signal is available.
**Pillar stage:** median of all non-null control stages within the pillar. Round down on ties.
**Overall stage:** median of the 6 pillar stages. Round down on ties.
**CISA ZTMM v2.0 stage labels:** 1 = Traditional, 2 = Initial, 3 = Advanced, 4 = Optimal.
