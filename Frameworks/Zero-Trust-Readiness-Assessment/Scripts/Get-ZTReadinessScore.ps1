#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    ZTRA Collector — Zero Trust Readiness Assessment evidence gatherer.
.DESCRIPTION
    Read-only Microsoft Graph assessment across the ZTRA 6-pillar rubric.
    Produces a structured PSCustomObject consumed by Format-ZTReadinessReport.ps1.
    Controls outside Microsoft Graph scope are flagged ManualReview = $true
    with portal navigation instructions.
.PARAMETER TenantId
    The Entra tenant ID to assess.
.PARAMETER OutputPath
    Directory path for JSON export when -ExportJson is specified. Default: current directory.
.PARAMETER ExportJson
    When present, exports the result object to a timestamped JSON file in OutputPath.
.EXAMPLE
    .\Get-ZTReadinessScore.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
.EXAMPLE
    .\Get-ZTReadinessScore.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -ExportJson -OutputPath 'C:\Reports'
.NOTES
    Version:  v0.1.0-preview
    Author:   Cloud Harbor Consulting LLC
    Requires: PowerShell 7+, Microsoft.Graph.Authentication module
    Scopes:   Policy.Read.All, IdentityRiskyUser.Read.All, AuditLog.Read.All,
              Device.Read.All, RoleManagement.Read.Directory, Reports.Read.All,
              PrivilegedAccess.Read.AzureAD
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TenantId,
    [string]$OutputPath = '.',
    [switch]$ExportJson
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$COLLECTOR_VERSION = 'v0.1.0-preview'
$REQUIRED_SCOPES = @(
    'Policy.Read.All',
    'IdentityRiskyUser.Read.All',
    'AuditLog.Read.All',
    'Device.Read.All',
    'RoleManagement.Read.Directory',
    'Reports.Read.All',
    'PrivilegedAccess.Read.AzureAD'
)
# ── Helper functions ──────────────────────────────────────────────────────────
function Write-Status {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Message,
        [ValidateSet('Info','OK','Warn','Skip')][string]$Level = 'Info'
    )
    $prefix = switch ($Level) {
        'Info' { '  →' }
        'OK'   { '  ✓' }
        'Warn' { '  !' }
        'Skip' { '  –' }
    }
    Write-Host "$prefix $Message"
}
function Invoke-ZTGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri,
        [string]$ApiVersion = 'v1.0'
    )
    $base    = "https://graph.microsoft.com/$ApiVersion"
    $fullUri = if ($Uri -match '^https?://') { $Uri } else { "$base/$($Uri.TrimStart('/'))" }
    $results = [System.Collections.Generic.List[object]]::new()
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $fullUri -OutputType PSObject
        if ($null -ne $response.value) {
            $results.AddRange([object[]]($response.value))
        } else {
            return $response
        }
        $fullUri = $response.'@odata.nextLink'
    } while ($fullUri)
    return $results.ToArray()
}
function New-ZTControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Id,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        [string[]]$NistTenets       = @(),
        [string]$RepoXRef           = '',
        [nullable[int]]$Stage,
        [bool]$ManualReview         = $false,
        [string]$ManualReviewNote   = '',
        [hashtable]$Signal          = @{}
    )
    [PSCustomObject]@{
        Id               = $Id
        Name             = $Name
        NistTenets       = $NistTenets
        RepoXRef         = $RepoXRef
        Stage            = $Stage
        ManualReview     = $ManualReview
        ManualReviewNote = $ManualReviewNote
        Signal           = $Signal
    }
}
function Get-PillarStage {
    [CmdletBinding()]
    param([PSCustomObject[]]$Controls)
    $scored = @($Controls | Where-Object { $null -ne $_.Stage } | ForEach-Object { [int]$_.Stage })
    if ($scored.Count -eq 0) { return $null }
    $sorted = $scored | Sort-Object
    $count  = $sorted.Count
    if ($count % 2 -eq 1) {
        return $sorted[($count - 1) / 2]
    } else {
        # Even count: return lower of two middle values (round down on ties)
        return $sorted[($count / 2) - 1]
    }
}
function Get-CAPolicies {
    Write-Status 'Fetching Conditional Access policies (beta endpoint)...'
    # Beta required: preview fields (signInFrequency everyTime, Agent ID conditions)
    Invoke-ZTGraphRequest -Uri 'identity/conditionalAccess/policies' -ApiVersion 'beta'
}
function Test-CAPolicyExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Policies,
        [Parameter(Mandatory)][scriptblock]$Filter,
        [ValidateSet('enabled','enabledForReportingButNotEnforced','disabled')]
        [string]$State = 'enabled'
    )
    $matching = @($Policies | Where-Object { $_.state -eq $State -and (& $Filter $_) })
    return ($matching.Count -gt 0)
}
# ── Connect ───────────────────────────────────────────────────────────────────
Write-Status "Connecting to Microsoft Graph (tenant: $TenantId)..."
Connect-MgGraph -TenantId $TenantId -Scopes $REQUIRED_SCOPES -NoWelcome
Write-Status 'Connected.' -Level OK
# ── Shared data ───────────────────────────────────────────────────────────────
Write-Status 'Loading shared data...'
$caPolicies = Get-CAPolicies
$devices    = Invoke-ZTGraphRequest -Uri 'devices'
$riskyUsers = try { Invoke-ZTGraphRequest -Uri 'identityProtection/riskyUsers' } catch { @() }
Write-Status "Loaded: $($caPolicies.Count) CA policies, $($devices.Count) devices, $($riskyUsers.Count) risky users." -Level OK
# ── Pillar 1 — Identities ─────────────────────────────────────────────────────
Write-Status 'Assessing Pillar 1 — Identities...'
$idControls = [System.Collections.Generic.List[PSCustomObject]]::new()
# ID-01: MFA enrollment and coverage
$legacyAuthBlocked = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ($p.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
     $p.conditions.clientAppTypes -contains 'other') -and
    $p.grantControls.builtInControls -contains 'block'
}
$mfaCoverageEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ($p.grantControls.builtInControls -contains 'mfa' -or
     $null -ne $p.grantControls.authenticationStrength) -and
    ($p.conditions.users.includeUsers -contains 'All' -or
     $p.conditions.users.includeGroups.Count -gt 0)
}
$phishResistantEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $null -ne $p.grantControls.authenticationStrength -and
    ($p.conditions.users.includeUsers -contains 'All' -or
     $p.conditions.users.includeGroups.Count -gt 0)
}
$mfaReportOnly = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $p.grantControls.builtInControls -contains 'mfa' -or
    $null -ne $p.grantControls.authenticationStrength
} -State 'enabledForReportingButNotEnforced'
$id01Stage = if ($phishResistantEnforced -and $legacyAuthBlocked) { 4 }
             elseif ($mfaCoverageEnforced -and $legacyAuthBlocked) { 3 }
             elseif ($mfaCoverageEnforced -or $mfaReportOnly)      { 2 }
             else                                                   { 1 }
$idControls.Add((New-ZTControl -Id 'ID-01' -Name 'MFA enrollment and coverage' `
    -NistTenets @('T4','T6') -RepoXRef 'CA-COV001-009, CA-SIG001' -Stage $id01Stage `
    -Signal @{
        LegacyAuthBlocked      = $legacyAuthBlocked
        MfaCoverageEnforced    = $mfaCoverageEnforced
        PhishResistantEnforced = $phishResistantEnforced
    }))
# ID-02: Admin MFA and privileged identity protection
$adminMfaEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $p.conditions.users.includeRoles.Count -gt 0 -and
    ($null -ne $p.grantControls.authenticationStrength -or
     $p.grantControls.builtInControls -contains 'mfa')
}
$adminSignInRiskCA = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $p.conditions.users.includeRoles.Count -gt 0 -and
    $p.conditions.signInRiskLevels.Count -gt 0
}
$pimData = try {
    $assignments = Invoke-ZTGraphRequest -Uri "privilegedAccess/aadRoles/resources/$TenantId/roleAssignments" -ApiVersion 'beta'
    $eligible  = @($assignments | Where-Object { $_.assignmentState -eq 'Eligible' }).Count
    $permanent = @($assignments | Where-Object { $_.assignmentState -eq 'Active'   }).Count
    @{ Eligible = $eligible; Permanent = $permanent }
} catch {
    Write-Status 'PIM role assignment data unavailable — flagging ManualReview for ID-02 and ID-06.' -Level Warn
    $null
}
$id02Stage = if ($null -eq $pimData) { $null }
             elseif ($adminMfaEnforced -and $adminSignInRiskCA -and $pimData.Permanent -eq 0) { 4 }
             elseif ($adminMfaEnforced -and $pimData.Eligible -gt 0)                          { 3 }
             elseif ($adminMfaEnforced -or $pimData.Eligible -gt 0)                           { 2 }
             else                                                                              { 1 }
$idControls.Add((New-ZTControl -Id 'ID-02' -Name 'Admin MFA and privileged identity protection' `
    -NistTenets @('T3','T4','T6') -RepoXRef 'CA-AUT001-003, CA-SIG005' -Stage $id02Stage `
    -ManualReview ($null -eq $pimData) `
    -ManualReviewNote (if ($null -eq $pimData) { 'PIM role assignment data not returned. Review in Entra admin center > Identity Governance > Privileged Identity Management > Azure AD roles > Assignments.' } else { '' }) `
    -Signal @{ AdminMfaEnforced = $adminMfaEnforced; AdminSignInRiskCA = $adminSignInRiskCA; PimData = $pimData }))
# ID-03: Block legacy authentication
$legacyBlockEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ($p.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
     $p.conditions.clientAppTypes -contains 'other') -and
    $p.grantControls.builtInControls -contains 'block'
}
$legacyBlockReportOnly = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ($p.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
     $p.conditions.clientAppTypes -contains 'other') -and
    $p.grantControls.builtInControls -contains 'block'
} -State 'enabledForReportingButNotEnforced'
$id03Stage = if ($legacyBlockEnforced)      { 3 }
             elseif ($legacyBlockReportOnly) { 2 }
             else                            { 1 }
$idControls.Add((New-ZTControl -Id 'ID-03' -Name 'Block legacy authentication' `
    -NistTenets @('T2','T6') -RepoXRef 'CA-SIG001' -Stage $id03Stage `
    -Signal @{ LegacyBlockEnforced = $legacyBlockEnforced; LegacyBlockReportOnly = $legacyBlockReportOnly }))
# ID-04: Sign-in risk CA enforcement
$signInRiskEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ($p.conditions.signInRiskLevels -contains 'medium' -or
     $p.conditions.signInRiskLevels -contains 'high') -and
    $p.grantControls.builtInControls.Count -gt 0
}
$signInRiskReportOnly = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $p.conditions.signInRiskLevels.Count -gt 0
} -State 'enabledForReportingButNotEnforced'
$id04Stage = if ($signInRiskEnforced)      { 3 }
             elseif ($signInRiskReportOnly) { 2 }
             else                          { 1 }
$idControls.Add((New-ZTControl -Id 'ID-04' -Name 'Sign-in risk CA enforcement' `
    -NistTenets @('T4','T5','T7') -RepoXRef 'CA-SIG005-007' -Stage $id04Stage `
    -Signal @{ SignInRiskEnforced = $signInRiskEnforced; SignInRiskReportOnly = $signInRiskReportOnly }))
# ID-05: User risk CA enforcement
$userRiskHighEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $p.conditions.userRiskLevels -contains 'high' -and
    $p.grantControls.builtInControls.Count -gt 0
}
$userRiskMedEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ($p.conditions.userRiskLevels -contains 'medium' -or
     $p.conditions.userRiskLevels -contains 'high') -and
    $p.grantControls.builtInControls.Count -gt 0
}
$id05Stage = if ($userRiskMedEnforced -and $riskyUsers.Count -eq 0) { 4 }
             elseif ($userRiskHighEnforced -and $userRiskMedEnforced) { 3 }
             elseif ($userRiskHighEnforced)                           { 2 }
             else                                                     { 1 }
$idControls.Add((New-ZTControl -Id 'ID-05' -Name 'User risk CA enforcement' `
    -NistTenets @('T4','T5','T7') -RepoXRef 'CA-SIG008-010' -Stage $id05Stage `
    -Signal @{ UserRiskHighEnforced = $userRiskHighEnforced; UserRiskMedEnforced = $userRiskMedEnforced; RiskyUserCount = $riskyUsers.Count }))
# ID-06: PIM JIT access (reuses $pimData from ID-02)
$id06Stage = if ($null -eq $pimData) { $null }
             elseif ($pimData.Permanent -eq 0 -and $pimData.Eligible -gt 0)               { 4 }
             elseif ($pimData.Eligible -gt 0 -and $pimData.Eligible -ge $pimData.Permanent) { 3 }
             elseif ($pimData.Eligible -gt 0)                                              { 2 }
             else                                                                          { 1 }
$idControls.Add((New-ZTControl -Id 'ID-06' -Name 'Privileged identity management JIT access' `
    -NistTenets @('T3','T4','T5') -RepoXRef 'EIG-AR002' -Stage $id06Stage `
    -ManualReview ($null -eq $pimData) `
    -ManualReviewNote (if ($null -eq $pimData) { 'PIM data unavailable. Review in Entra admin center > Identity Governance > PIM > Azure AD roles > Assignments.' } else { '' }) `
    -Signal @{ PimData = $pimData }))
# ID-07: External identity lifecycle governance
$authPolicy        = try { Invoke-ZTGraphRequest -Uri 'policies/authorizationPolicy' } catch { $null }
$guestInvitePolicy = if ($null -ne $authPolicy) { $authPolicy.allowInvitesFrom } else { 'unknown' }
$guestPolicyStage = switch ($guestInvitePolicy) {
    'none'                          { 4 }
    'adminsAndGuestInviters'        { 3 }
    'adminsGuestInvitersAndMembers' { 2 }
    'everyone'                      { 1 }
    default                         { 1 }
}
$accessReviewsExist = try {
    $reviews = Invoke-ZTGraphRequest -Uri 'identityGovernance/accessReviews/definitions'
    @($reviews | Where-Object { $_.scope.query -match 'guest' -or $_.displayName -match '(?i)guest' }).Count -gt 0
} catch { $false }
$id07Stage = if ($guestPolicyStage -ge 3 -and $accessReviewsExist) { $guestPolicyStage }
             elseif ($guestPolicyStage -ge 2)                       { $guestPolicyStage }
             else                                                    { 1 }
$idControls.Add((New-ZTControl -Id 'ID-07' -Name 'External identity lifecycle governance' `
    -NistTenets @('T4','T5') -RepoXRef 'EIG-AR001' -Stage $id07Stage `
    -Signal @{ GuestInvitePolicy = $guestInvitePolicy; AccessReviewsExist = $accessReviewsExist }))
# ID-08: SSO coverage for sanctioned applications — outside Graph-only scope
$idControls.Add((New-ZTControl -Id 'ID-08' -Name 'SSO coverage for sanctioned applications' `
    -NistTenets @('T3','T6') -Stage $null -ManualReview $true `
    -ManualReviewNote 'SSO coverage requires Application.Read.All, outside v0.1.0-preview scope. Review in Entra admin center > Enterprise applications > All applications — filter by Single sign-on status.' `
    -Signal @{}))
$pillar1Stage = Get-PillarStage -Controls $idControls.ToArray()
Write-Status "Pillar 1 (Identities) stage: $pillar1Stage" -Level OK
# ── Pillar 2 — Endpoints ──────────────────────────────────────────────────────
Write-Status 'Assessing Pillar 2 — Endpoints...'
$epControls = [System.Collections.Generic.List[PSCustomObject]]::new()
# EP-01: Device registration with cloud identity
$joinedCount     = @($devices | Where-Object { $_.trustType -in @('AzureAD','ServerAD') }).Count
$registeredCount = @($devices | Where-Object { $_.trustType -eq 'Workplace' }).Count
$totalCount      = $devices.Count
$ep01Stage = if ($totalCount -eq 0)                                               { 1 }
             elseif (($joinedCount + $registeredCount) -ge ($totalCount * 0.95))  { 4 }
             elseif ($joinedCount -gt 0 -and $registeredCount -gt 0)              { 3 }
             elseif ($joinedCount -gt 0)                                           { 2 }
             else                                                                  { 1 }
$epControls.Add((New-ZTControl -Id 'EP-01' -Name 'Device registration with cloud identity' `
    -NistTenets @('T1','T5') -Stage $ep01Stage `
    -Signal @{ TotalDevices = $totalCount; JoinedDevices = $joinedCount; RegisteredDevices = $registeredCount }))
# EP-02: Device compliance policies — Intune scope required
$epControls.Add((New-ZTControl -Id 'EP-02' -Name 'Device compliance policies' `
    -NistTenets @('T4','T5') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Requires DeviceManagementConfiguration.Read.All, outside v0.1.0-preview scope. Review in Intune admin center > Devices > Compliance policies.' `
    -Signal @{}))
# EP-03: CA enforcement of device compliance
$compliantDeviceEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $p.grantControls.builtInControls -contains 'compliantDevice'
}
$compliantDeviceReportOnly = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $p.grantControls.builtInControls -contains 'compliantDevice'
} -State 'enabledForReportingButNotEnforced'
$ep03Stage = if ($compliantDeviceEnforced)      { 3 }
             elseif ($compliantDeviceReportOnly) { 2 }
             else                               { 1 }
$epControls.Add((New-ZTControl -Id 'EP-03' -Name 'CA enforcement of device compliance' `
    -NistTenets @('T3','T4','T6') -RepoXRef 'CA-AUT003' -Stage $ep03Stage `
    -Signal @{ CompliantDeviceEnforced = $compliantDeviceEnforced; CompliantDeviceReportOnly = $compliantDeviceReportOnly }))
# EP-04 through EP-07 — Intune-scoped, ManualReview
$epControls.Add((New-ZTControl -Id 'EP-04' -Name 'App protection policies BYOD MAM' `
    -NistTenets @('T1','T4') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Requires DeviceManagementApps.Read.All, outside v0.1.0-preview scope. Review in Intune admin center > Apps > App protection policies.' `
    -Signal @{}))
$epControls.Add((New-ZTControl -Id 'EP-05' -Name 'Security baselines and configuration enforcement' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Requires DeviceManagementConfiguration.Read.All, outside v0.1.0-preview scope. Review in Intune admin center > Endpoint security > Security baselines.' `
    -Signal @{}))
$epControls.Add((New-ZTControl -Id 'EP-06' -Name 'Device encryption' `
    -NistTenets @('T1','T2') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Requires DeviceManagementConfiguration.Read.All, outside v0.1.0-preview scope. Review in Intune admin center > Devices > Compliance policies — verify encryption requirement per platform.' `
    -Signal @{}))
$epControls.Add((New-ZTControl -Id 'EP-07' -Name 'Endpoint threat detection' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Requires DeviceManagementManagedDevices.Read.All, outside v0.1.0-preview scope. Review in Defender portal > Settings > Endpoints > Onboarding and Intune admin center > Endpoint security > Microsoft Defender for Endpoint.' `
    -Signal @{}))
$pillar2Stage = Get-PillarStage -Controls $epControls.ToArray()
Write-Status "Pillar 2 (Endpoints) stage: $pillar2Stage" -Level OK
# ── Pillar 3 — Applications ───────────────────────────────────────────────────
Write-Status 'Assessing Pillar 3 — Applications...'
$apControls = [System.Collections.Generic.List[PSCustomObject]]::new()
# AP-01: Shadow IT discovery — Defender for Cloud Apps, not in Graph
$apControls.Add((New-ZTControl -Id 'AP-01' -Name 'Shadow IT discovery' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Defender for Cloud Apps state is not available via Microsoft Graph. Review in Defender portal > Cloud Apps > Cloud discovery > Dashboard — verify log source and MDE stream integration.' `
    -Signal @{}))
# AP-02: OAuth consent governance
$consentPolicy  = try { Invoke-ZTGraphRequest -Uri 'policies/adminConsentRequestPolicy' } catch { $null }
$consentEnabled = if ($null -ne $consentPolicy) { [bool]$consentPolicy.isEnabled } else { $false }
$highPrivGrants = try {
    $grants = Invoke-ZTGraphRequest -Uri 'oauth2PermissionGrants'
    @($grants | Where-Object { $_.scope -match 'Mail\.|Files\.|Directory\.' }).Count
} catch { 0 }
$ap02Stage = if ($consentEnabled -and $highPrivGrants -eq 0) { 4 }
             elseif ($consentEnabled)                         { 3 }
             elseif ($highPrivGrants -lt 10)                  { 2 }
             else                                             { 1 }
$apControls.Add((New-ZTControl -Id 'AP-02' -Name 'OAuth consent governance' `
    -NistTenets @('T4','T5') -Stage $ap02Stage `
    -Signal @{ AdminConsentEnabled = $consentEnabled; HighPrivilegeGrantCount = $highPrivGrants }))
# AP-03: CAAC session controls
$caacEnabled = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $null -ne $p.sessionControls.cloudAppSecurity
}
$ap03Stage = if ($caacEnabled) { 3 } else { 1 }
$apControls.Add((New-ZTControl -Id 'AP-03' -Name 'Conditional Access App Control session controls' `
    -NistTenets @('T3','T4') -Stage $ap03Stage `
    -Signal @{ CaacEnabled = $caacEnabled }))
# AP-04, AP-05 — Purview / Defender for Cloud Apps, ManualReview
$apControls.Add((New-ZTControl -Id 'AP-04' -Name 'Application DLP' `
    -NistTenets @('T4','T5') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Microsoft Purview DLP is not available via Microsoft Graph. Review in Purview compliance portal > Data loss prevention > Policies — verify mode (audit vs. enforce) per workload.' `
    -Signal @{}))
$apControls.Add((New-ZTControl -Id 'AP-05' -Name 'UEBA and anomaly detection' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Defender for Cloud Apps anomaly detection state is not available via Microsoft Graph. Review in Defender portal > Cloud Apps > Policies > Policy management.' `
    -Signal @{}))
# AP-06: Entitlement governance
$accessPackageCount = try {
    $pkgs = Invoke-ZTGraphRequest -Uri 'identityGovernance/entitlementManagement/accessPackages'
    $pkgs.Count
} catch { 0 }
$ap06Stage = if ($accessPackageCount -gt 5)   { 3 }
             elseif ($accessPackageCount -gt 0) { 2 }
             else                               { 1 }
$apControls.Add((New-ZTControl -Id 'AP-06' -Name 'App-level access permissions and entitlement governance' `
    -NistTenets @('T3','T4') -RepoXRef 'EIG-AR001, EIG-AR002' -Stage $ap06Stage `
    -Signal @{ AccessPackageCount = $accessPackageCount }))
$pillar3Stage = Get-PillarStage -Controls $apControls.ToArray()
Write-Status "Pillar 3 (Applications) stage: $pillar3Stage" -Level OK
# ── Pillar 4 — Data ───────────────────────────────────────────────────────────
Write-Status 'Assessing Pillar 4 — Data...'
$daControls  = [System.Collections.Generic.List[PSCustomObject]]::new()
$purviewNote = 'Microsoft Purview signals are not available via Microsoft Graph in v0.1.0-preview. Review in Purview compliance portal'
# DA-01: Sensitivity labels — partial Graph signal available
$labelCount = try {
    $labels = Invoke-ZTGraphRequest -Uri 'informationProtection/sensitivityLabels'
    $labels.Count
} catch { 0 }
$da01Stage = if ($labelCount -gt 0) { 2 } else { 1 }
$daControls.Add((New-ZTControl -Id 'DA-01' -Name 'Data classification framework and sensitivity label taxonomy' `
    -NistTenets @('T1','T5') -Stage $da01Stage -ManualReview $true `
    -ManualReviewNote "$purviewNote > Information protection > Labels — verify publication policy, auto-labeling configuration, and label coverage metrics in Content Explorer." `
    -Signal @{ SensitivityLabelCount = $labelCount }))
# DA-02 through DA-07 — all Purview-scoped, ManualReview
$daControls.Add((New-ZTControl -Id 'DA-02' -Name 'Information protection encryption and rights management' `
    -NistTenets @('T1','T2','T4') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Information protection > Labels — verify encryption is configured on Confidential and Highly Confidential labels." `
    -Signal @{}))
$daControls.Add((New-ZTControl -Id 'DA-03' -Name 'Container-level data protection Teams M365 Groups SharePoint' `
    -NistTenets @('T3','T4') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Information protection — verify container labels applied to Teams and SharePoint sites. Also review SharePoint admin center > Policies > Sharing." `
    -Signal @{}))
$daControls.Add((New-ZTControl -Id 'DA-04' -Name 'Data Loss Prevention policy coverage and maturity' `
    -NistTenets @('T4','T5') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Data loss prevention > Policies — verify mode (audit vs. enforce) and coverage across Exchange, SharePoint, OneDrive, Teams, and Endpoint." `
    -Signal @{}))
$daControls.Add((New-ZTControl -Id 'DA-05' -Name 'Insider Risk Management' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Insider risk management > Policies — verify active policy count, alert review state, and HR connector configuration." `
    -Signal @{}))
$daControls.Add((New-ZTControl -Id 'DA-06' -Name 'Data lifecycle and records management' `
    -NistTenets @('T5') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Data lifecycle management > Retention policies — verify workload coverage and retention label deployment." `
    -Signal @{}))
$daControls.Add((New-ZTControl -Id 'DA-07' -Name 'Data discovery and content inventory' `
    -NistTenets @('T1','T5') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Content explorer — verify labeled item count by workload and on-premises scanner deployment state." `
    -Signal @{}))
$pillar4Stage = Get-PillarStage -Controls $daControls.ToArray()
Write-Status "Pillar 4 (Data) stage: $pillar4Stage" -Level OK
# ── Pillar 5 — Infrastructure ─────────────────────────────────────────────────
Write-Status 'Assessing Pillar 5 — Infrastructure...'
$infraControls = [System.Collections.Generic.List[PSCustomObject]]::new()
$azureNote     = 'Requires Azure Management API signals, outside v0.1.0-preview Graph-only scope.'
# IN-01: JIT privileged access for Azure resource roles
$azureResPim = try {
    $ra = Invoke-ZTGraphRequest -Uri 'privilegedAccess/azureResources/roleAssignments' -ApiVersion 'beta'
    $e  = @($ra | Where-Object { $_.assignmentState -eq 'Eligible' }).Count
    $p  = @($ra | Where-Object { $_.assignmentState -eq 'Active'   }).Count
    @{ Eligible = $e; Permanent = $p }
} catch {
    Write-Status 'Azure resource PIM data unavailable — flagging ManualReview for IN-01.' -Level Warn
    $null
}
$in01Stage = if ($null -eq $azureResPim) { $null }
             elseif ($azureResPim.Permanent -eq 0 -and $azureResPim.Eligible -gt 0) { 4 }
             elseif ($azureResPim.Eligible -ge $azureResPim.Permanent)               { 3 }
             elseif ($azureResPim.Eligible -gt 0)                                    { 2 }
             else                                                                    { 1 }
$infraControls.Add((New-ZTControl -Id 'IN-01' -Name 'JIT privileged access for Azure resource roles' `
    -NistTenets @('T3','T4','T5') -RepoXRef 'EIG-AR002' -Stage $in01Stage `
    -ManualReview ($null -eq $azureResPim) `
    -ManualReviewNote (if ($null -eq $azureResPim) { 'Azure resource PIM data not returned. Review in Entra admin center > Identity Governance > PIM > Azure resources > Assignments.' } else { '' }) `
    -Signal @{ AzureResourcePim = $azureResPim }))
# IN-02: Workload identity — managed identities vs. secrets
$appRegs      = try { Invoke-ZTGraphRequest -Uri 'applications' } catch { @() }
$staleSecrets = @($appRegs | Where-Object {
    @($_.passwordCredentials | Where-Object {
        $null -eq $_.endDateTime -or
        ([datetime]$_.endDateTime - [datetime]::UtcNow).TotalDays -gt 365
    }).Count -gt 0
}).Count
$in02Stage = if ($appRegs.Count -gt 0 -and $staleSecrets -eq 0)                              { 3 }
             elseif ($appRegs.Count -gt 0 -and $staleSecrets -lt ($appRegs.Count * 0.2))     { 2 }
             else                                                                              { 1 }
$infraControls.Add((New-ZTControl -Id 'IN-02' -Name 'Workload identity managed identities vs. secrets' `
    -NistTenets @('T1','T6') -Stage $in02Stage -ManualReview $true `
    -ManualReviewNote "$azureNote For managed identity coverage, review Azure portal > resource > Identity — verify system-assigned or user-assigned managed identity is enabled." `
    -Signal @{ AppRegistrationCount = $appRegs.Count; AppsWithStaleSecrets = $staleSecrets }))
# IN-03 through IN-06 — Azure Management API, all ManualReview
$infraControls.Add((New-ZTControl -Id 'IN-03' -Name 'Workload monitoring and threat detection' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote "$azureNote Review Defender for Cloud > Environment settings — verify plans enabled per resource type. Review Sentinel > Data connectors — verify key workload connectors." `
    -Signal @{}))
$infraControls.Add((New-ZTControl -Id 'IN-04' -Name 'RBAC for subscriptions and resources' `
    -NistTenets @('T4','T6') -Stage $null -ManualReview $true `
    -ManualReviewNote "$azureNote Review Azure portal > Subscriptions > Access control (IAM) — verify Owner and Contributor assignment count and last review date." `
    -Signal @{}))
$infraControls.Add((New-ZTControl -Id 'IN-05' -Name 'Vulnerability management' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote "$azureNote Review Defender for Cloud > Recommendations — verify vulnerability assessment coverage and critical/high CVE count and age." `
    -Signal @{}))
$infraControls.Add((New-ZTControl -Id 'IN-06' -Name 'Deployment governance and configuration policy' `
    -NistTenets @('T4','T5') -Stage $null -ManualReview $true `
    -ManualReviewNote "$azureNote Review Azure portal > Policy > Compliance — verify assigned policy count and overall compliance percentage. Confirm IaC adoption via repository evidence." `
    -Signal @{}))
$pillar5Stage = Get-PillarStage -Controls $infraControls.ToArray()
Write-Status "Pillar 5 (Infrastructure) stage: $pillar5Stage" -Level OK
# ── Pillar 6 — Networks ───────────────────────────────────────────────────────
Write-Status 'Assessing Pillar 6 — Networks...'
$nwControls  = [System.Collections.Generic.List[PSCustomObject]]::new()
$networkNote = 'Requires Azure Management API or GSA-specific Graph scopes, outside v0.1.0-preview scope.'
# NW-01, NW-02 — GSA scopes not in collector scope, ManualReview
$nwControls.Add((New-ZTControl -Id 'NW-01' -Name 'Legacy VPN displacement private access' `
    -NistTenets @('T2','T3') -Stage $null -ManualReview $true `
    -ManualReviewNote "$networkNote Review Entra admin center > Global Secure Access > Connect > Private access — verify connector group count and application segment count." `
    -Signal @{}))
$nwControls.Add((New-ZTControl -Id 'NW-02' -Name 'Internet access security Entra Internet Access SWG' `
    -NistTenets @('T2','T4') -Stage $null -ManualReview $true `
    -ManualReviewNote "$networkNote Review Entra admin center > Global Secure Access > Connect > Internet access — verify forwarding profile state and web category filtering policy." `
    -Signal @{}))
# NW-03: Compliant network CA enforcement — partial Graph signal available
$namedLocations = try {
    Invoke-ZTGraphRequest -Uri 'identity/conditionalAccess/namedLocations' -ApiVersion 'beta'
} catch { @() }
$gsaLocationFound = @($namedLocations | Where-Object {
    $_.displayName -match '(?i)(compliant|GSA|Global Secure)'
}).Count -gt 0
$compliantNetworkCA = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $p.conditions.locations.includeLocations.Count -gt 0
} -State 'enabled'
$nw03Stage = if ($gsaLocationFound -and $compliantNetworkCA) { 3 }
             elseif ($namedLocations.Count -gt 0)             { 2 }
             else                                             { 1 }
$nwControls.Add((New-ZTControl -Id 'NW-03' -Name 'Compliant network CA enforcement GSA' `
    -NistTenets @('T3','T4') -RepoXRef 'CA-COV015' -Stage $nw03Stage `
    -Signal @{ GsaLocationFound = $gsaLocationFound; NamedLocationCount = $namedLocations.Count; CompliantNetworkCA = $compliantNetworkCA }))
# NW-04 through NW-06 — Azure Management API, all ManualReview
$nwControls.Add((New-ZTControl -Id 'NW-04' -Name 'Network segmentation' `
    -NistTenets @('T2','T4') -Stage $null -ManualReview $true `
    -ManualReviewNote "$networkNote Review Azure portal > Virtual networks — verify VNet segmentation, NSG rule coverage per subnet, and Azure Firewall deployment for east-west inspection." `
    -Signal @{}))
$nwControls.Add((New-ZTControl -Id 'NW-05' -Name 'Encryption in transit' `
    -NistTenets @('T2') -Stage $null -ManualReview $true `
    -ManualReviewNote "$networkNote Review Entra admin center > Global Secure Access > Internet access > TLS inspection policy. Also verify TLS version enforcement in Azure App Service and API Management." `
    -Signal @{}))
$nwControls.Add((New-ZTControl -Id 'NW-06' -Name 'Network traffic monitoring and analytics' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote "$networkNote Review Azure portal > Network Watcher > NSG flow logs — verify enablement per VNet. Review Sentinel > Data connectors — verify Azure Firewall and Entra Internet Access connectors." `
    -Signal @{}))
$pillar6Stage = Get-PillarStage -Controls $nwControls.ToArray()
Write-Status "Pillar 6 (Networks) stage: $pillar6Stage" -Level OK
# ── Result assembly ───────────────────────────────────────────────────────────
Write-Status 'Assembling result...'
$allPillarStages = @($pillar1Stage, $pillar2Stage, $pillar3Stage, $pillar4Stage, $pillar5Stage, $pillar6Stage) |
    Where-Object { $null -ne $_ } | Sort-Object
$overallStage = if ($allPillarStages.Count -eq 0) { $null }
               elseif ($allPillarStages.Count % 2 -eq 1) {
                   $allPillarStages[($allPillarStages.Count - 1) / 2]
               } else {
                   $allPillarStages[($allPillarStages.Count / 2) - 1]
               }
$allControls       = @($idControls + $epControls + $apControls + $daControls + $infraControls + $nwControls)
$manualReviewCount = @($allControls | Where-Object { $_.ManualReview -eq $true }).Count
$result = [PSCustomObject]@{
    TenantId          = $TenantId
    AssessmentDate    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
    CollectorVersion  = $COLLECTOR_VERSION
    OverallStage      = $overallStage
    ManualReviewCount = $manualReviewCount
    GraphScopesUsed   = $REQUIRED_SCOPES
    Pillars           = @(
        [PSCustomObject]@{ Name = 'Identities';     Stage = $pillar1Stage; Controls = $idControls.ToArray()    }
        [PSCustomObject]@{ Name = 'Endpoints';      Stage = $pillar2Stage; Controls = $epControls.ToArray()    }
        [PSCustomObject]@{ Name = 'Applications';   Stage = $pillar3Stage; Controls = $apControls.ToArray()    }
        [PSCustomObject]@{ Name = 'Data';           Stage = $pillar4Stage; Controls = $daControls.ToArray()    }
        [PSCustomObject]@{ Name = 'Infrastructure'; Stage = $pillar5Stage; Controls = $infraControls.ToArray() }
        [PSCustomObject]@{ Name = 'Networks';       Stage = $pillar6Stage; Controls = $nwControls.ToArray()    }
    )
}
# ── Summary output ────────────────────────────────────────────────────────────
$stageLabels = @{ 1 = 'Traditional'; 2 = 'Initial'; 3 = 'Advanced'; 4 = 'Optimal' }
Write-Host ''
Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
Write-Host "  ZTRA — Zero Trust Readiness Assessment   $($result.AssessmentDate)"
Write-Host "  Tenant:        $TenantId"
Write-Host "  Collector:     $COLLECTOR_VERSION"
$overallLabel = if ($null -ne $overallStage) { "Stage $overallStage — $($stageLabels[$overallStage])" } else { 'Indeterminate' }
Write-Host "  Overall Stage: $overallLabel"
Write-Host "  Manual Review: $manualReviewCount of 40 controls require manual assessment"
Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
foreach ($pillar in $result.Pillars) {
    $stageStr    = if ($null -ne $pillar.Stage) { "Stage $($pillar.Stage) — $($stageLabels[$pillar.Stage])" } else { 'Manual review required' }
    $manualCount = @($pillar.Controls | Where-Object { $_.ManualReview }).Count
    Write-Host ("  {0,-16} {1,-38} ({2} manual)" -f $pillar.Name, $stageStr, $manualCount)
}
Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
Write-Host ''
Write-Host '  Next step: pipe this result to Format-ZTReadinessReport.ps1'
Write-Host ''
# ── JSON export ───────────────────────────────────────────────────────────────
if ($ExportJson) {
    $timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $exportFile = Join-Path $OutputPath "ZTRAResult-$timestamp.json"
    $result | ConvertTo-Json -Depth 10 | Set-Content -Path $exportFile -Encoding UTF8
    Write-Status "JSON exported: $exportFile" -Level OK
}
# ── Disconnect and return ─────────────────────────────────────────────────────
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
return $result
