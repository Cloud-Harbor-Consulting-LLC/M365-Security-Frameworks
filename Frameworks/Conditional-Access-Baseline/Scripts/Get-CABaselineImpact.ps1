<#
.SYNOPSIS
    Analyzes sign-in logs to report the impact of report-only Conditional Access policies.

.DESCRIPTION
    Get-CABaselineImpact.ps1 pulls Entra sign-in logs over a configurable window and
    summarizes what each report-only CA policy would have done if enforced. Helps
    validate the baseline before promoting policies to enabled state.

    Report outcomes:
    - Would have blocked       (reportOnlyFailure)     — grant controls would have failed the sign-in
    - Would have challenged    (reportOnlyInterrupted) — user would have been prompted (MFA, auth strength)
    - Would have passed        (reportOnlySuccess)     — grant controls already satisfied
    - Not applied              (reportOnlyNotApplied)  — conditions didn't match

.PARAMETER Days
    Look-back window in days. Default: 7. Max practical: 30 (Graph retention limit on most tenants).

.PARAMETER StartDate
    Explicit start datetime (ISO 8601). Overrides -Days if provided.

.PARAMETER EndDate
    Explicit end datetime (ISO 8601). Defaults to now.

.PARAMETER PolicyNameFilter
    Optional substring to filter policies by display name. Default: 'CA-' (matches the baseline).

.PARAMETER ExportCsvPath
    Optional path to export per-sign-in policy evaluations as CSV.

.EXAMPLE
    .\Get-CABaselineImpact.ps1
    Summarize the last 7 days of CA- policy evaluations.

.EXAMPLE
    .\Get-CABaselineImpact.ps1 -Days 14 -ExportCsvPath .\impact.csv
    Two-week window with CSV export for pivoting in Excel.

.EXAMPLE
    .\Get-CABaselineImpact.ps1 -PolicyNameFilter 'CA-COV'
    Only evaluate coverage-pillar policies.

.NOTES
    Requires:
    - PowerShell 7.0 or later
    - Microsoft.Graph PowerShell SDK 2.x
    - Graph scopes: AuditLog.Read.All, Directory.Read.All, Policy.Read.All

    Connect with:
      Connect-MgGraph -Scopes AuditLog.Read.All,Directory.Read.All,Policy.Read.All

    Author: Derek Morgan, Cloud Harbor Consulting
    Repository: https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks
#>

[CmdletBinding()]
param(
    [Parameter()][int]$Days = 7,
    [Parameter()][datetime]$StartDate,
    [Parameter()][datetime]$EndDate = (Get-Date),
    [Parameter()][string]$PolicyNameFilter = 'CA-',
    [Parameter()][string]$ExportCsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers

function Write-Status {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')][string]$Level = 'Info'
    )
    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        default   { 'Cyan' }
    }
    $prefix = switch ($Level) {
        'Success' { '[OK]   ' }
        'Warning' { '[WARN] ' }
        'Error'   { '[ERR]  ' }
        default   { '[INFO] ' }
    }
    Write-Host "$prefix$Message" -ForegroundColor $color
}

function Test-GraphPrerequisites {
    if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        throw "Microsoft.Graph PowerShell SDK is not installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
    }
    $context = Get-MgContext
    if (-not $context) {
        throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes AuditLog.Read.All,Directory.Read.All,Policy.Read.All"
    }
    $required = @('AuditLog.Read.All', 'Directory.Read.All', 'Policy.Read.All')
    $missing = $required | Where-Object { $_ -notin $context.Scopes }
    if ($missing) {
        throw "Graph session is missing required scopes: $($missing -join ', '). Reconnect with all required scopes."
    }
}

function Get-SignInsInWindow {
    param(
        [Parameter(Mandatory)][datetime]$Start,
        [Parameter(Mandatory)][datetime]$End
    )
    $startIso = $Start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $endIso   = $End.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "createdDateTime ge $startIso and createdDateTime le $endIso"
    $encoded = [System.Uri]::EscapeDataString($filter)
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$encoded&`$top=1000"

    $all = [System.Collections.Generic.List[object]]::new()
    $page = 0
    while ($uri) {
        $page++
        Write-Status "  Fetching page $page..."
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        if ($response.value) { $all.AddRange([object[]]$response.value) }
        $uri = $response.'@odata.nextLink'
    }
    return $all
}

#endregion

#region Main

try {
    Write-Status "Get-CABaselineImpact starting"
    Test-GraphPrerequisites
    $tenantContext = Get-MgContext
    Write-Status "Connected tenant: $($tenantContext.TenantId) as $($tenantContext.Account)" -Level Success

    if (-not $StartDate) { $StartDate = $EndDate.AddDays(-$Days) }
    Write-Status "Window: $($StartDate.ToString('u')) -> $($EndDate.ToString('u'))"
    Write-Status "Policy filter: displayName contains '$PolicyNameFilter'"

    Write-Status "Fetching sign-in logs..."
    $signIns = Get-SignInsInWindow -Start $StartDate -End $EndDate
    Write-Status "Retrieved $($signIns.Count) sign-in events" -Level Success

    $records = foreach ($si in $signIns) {
        if (-not $si.appliedConditionalAccessPolicies) { continue }
        foreach ($p in $si.appliedConditionalAccessPolicies) {
            if ($p.displayName -notlike "*$PolicyNameFilter*") { continue }
            [pscustomobject]@{
                SignInId       = $si.id
                CreatedUtc     = $si.createdDateTime
                UserPrincipal  = $si.userPrincipalName
                UserId         = $si.userId
                AppDisplayName = $si.appDisplayName
                PolicyId       = $p.id
                PolicyName     = $p.displayName
                Result         = $p.result
            }
        }
    }

    if (-not $records) {
        Write-Status "No policy evaluations matched filter '$PolicyNameFilter' in this window." -Level Warning
        return
    }

    Write-Status ""
    Write-Status "Per-policy impact summary:"
    $summary = $records | Group-Object PolicyName | ForEach-Object {
        $group = $_.Group
        [pscustomobject]@{
            Policy           = $_.Name
            Evaluations      = $group.Count
            UniqueUsers      = ($group.UserPrincipal | Sort-Object -Unique).Count
            WouldBlock       = @($group | Where-Object { $_.Result -eq 'reportOnlyFailure' }).Count
            WouldChallenge   = @($group | Where-Object { $_.Result -eq 'reportOnlyInterrupted' }).Count
            WouldPass        = @($group | Where-Object { $_.Result -eq 'reportOnlySuccess' }).Count
            NotApplied       = @($group | Where-Object { $_.Result -eq 'reportOnlyNotApplied' }).Count
        }
    } | Sort-Object Policy

    $summary | Format-Table -AutoSize

    $affectedByUser = $records |
        Where-Object { $_.Result -in 'reportOnlyFailure', 'reportOnlyInterrupted' } |
        Group-Object UserPrincipal |
        Sort-Object Count -Descending |
        Select-Object -First 10

    if ($affectedByUser) {
        Write-Status ""
        Write-Status "Top 10 users by would-block + would-challenge:"
        $affectedByUser | ForEach-Object {
            [pscustomobject]@{ User = $_.Name; Count = $_.Count }
        } | Format-Table -AutoSize
    }

    if ($ExportCsvPath) {
        $records | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Status "Exported $($records.Count) records to $ExportCsvPath" -Level Success
    }

    Write-Status ""
    Write-Status "Reminder: review would-block spikes before promoting any policy to enabled state." -Level Info

} catch {
    Write-Status $_ -Level Error
    exit 1
}

#endregion