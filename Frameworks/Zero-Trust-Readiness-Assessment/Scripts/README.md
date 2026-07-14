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
| Permissions | Global Reader, or a custom role granting the 7 Graph scopes below |
| License | Entra ID P2 required for PIM and ID Protection signals (ID-02, ID-04–ID-06) |
---
## Required Graph scopes
| Scope | Pillar(s) |
|---|---|
| `Policy.Read.All` | Identities, Endpoints, Networks (CA policies, authorization policy) |
| `IdentityRiskyUser.Read.All` | Identities (risky user count) |
| `AuditLog.Read.All` | Cross-pillar (sign-in logs) |
| `Device.Read.All` | Endpoints (device registration and join type) |
| `RoleManagement.Read.Directory` | Identities (directory role assignments) |
| `Reports.Read.All` | Cross-pillar (authentication method registration) |
| `PrivilegedAccess.Read.AzureAD` | Identities, Infrastructure (PIM assignments) |
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
| IN-01* | Azure resource PIM may be inaccessible | Entra admin center > PIM > Azure resources |
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
## Scoring logic
**Control stage:** 1–4, assigned by the collector from Graph evidence. Null when
`ManualReview = $true` and no partial signal is available.
**Pillar stage:** median of all non-null control stages within the pillar. Round down on ties.
**Overall stage:** median of the 6 pillar stages. Round down on ties.
**CISA ZTMM v2.0 stage labels:** 1 = Traditional, 2 = Initial, 3 = Advanced, 4 = Optimal.
