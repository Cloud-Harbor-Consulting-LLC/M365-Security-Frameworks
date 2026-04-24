<#
.SYNOPSIS
    Deploys the Conditional Access Baseline policies to a Microsoft Entra tenant.

.DESCRIPTION
    Deploy-CABaseline.ps1 imports the six CA-COV, CA-SIG, and CA-AUT policy
    templates in this framework into the target tenant. The script:

    - Resolves tenant-specific placeholders (persona group IDs, authentication
      strength ID) by looking them up in the tenant at runtime
    - Validates every placeholder resolves before submitting any policy
    - Defaults to report-only state (enabledForReportingButNotEnforced); use
      -Enforce to promote to enabled state (requires explicit confirmation)
    - Supports -WhatIf for safe preview before any policy is created

.PARAMETER PolicyPath
    Path to the folder containing the JSON policy templates. Defaults to
    '../Policies' relative to the script's location.

.PARAMETER EmergencyAccessGroupName
    Display name of the emergency access group. Default: CA-Persona-EmergencyAccess.

.PARAMETER WorkloadIdentitiesGroupName
    Display name of the workload identities group. Default: CA-Persona-WorkloadIdentities.

.PARAMETER GlobalAdminsGroupName
    Display name of the global administrators persona group. Default: CA-Persona-GlobalAdmins.

.PARAMETER InternalUsersGroupName
    Display name of the internal users persona group. Default: CA-Persona-InternalUsers.

.PARAMETER AuthStrengthName
    Display name of the authentication strength policy. Default: 'Phishing-resistant MFA'.

.PARAMETER Enforce
    Switch. If specified, policies are created in 'enabled' state instead of
    report-only. Destructive — requires explicit confirmation.

.EXAMPLE
    .\Deploy-CABaseline.ps1 -WhatIf
    Preview the deployment. No changes made to the tenant.

.EXAMPLE
    .\Deploy-CABaseline.ps1
    Deploy all six policies in report-only mode.

.EXAMPLE
    .\Deploy-CABaseline.ps1 -Enforce
    Deploy all six policies in enabled state. Prompts for confirmation.

.NOTES
    Requires:
    - PowerShell 7.0 or later
    - Microsoft.Graph PowerShell SDK 2.x
    - Graph scopes: Policy.ReadWrite.ConditionalAccess, Group.Read.All, Policy.Read.All
    - Persona groups must exist in the tenant before running this script

    Connect with:
      Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess,Group.Read.All,Policy.Read.All

    Author: Derek Morgan, Cloud Harbor Consulting
    Repository: https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [string]$PolicyPath = (Join-Path $PSScriptRoot 'Policies'),

    [Parameter()]
    [string]$EmergencyAccessGroupName = 'CA-Persona-EmergencyAccess',

    [Parameter()]
    [string]$WorkloadIdentitiesGroupName = 'CA-Persona-WorkloadIdentities',

    [Parameter()]
    [string]$GlobalAdminsGroupName = 'CA-Persona-GlobalAdmins',

    [Parameter()]
    [string]$InternalUsersGroupName = 'CA-Persona-InternalUsers',

    [Parameter()]
    [string]$AuthStrengthName = 'Phishing-resistant MFA',

    [Parameter()]
    [switch]$Enforce
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helper functions

function Write-Status {
    param(
        [Parameter(Mandatory)][string]$Message,
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
        throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess,Group.Read.All,Policy.Read.All,Application.Read.All"
    }
    $requiredScopes = @('Policy.ReadWrite.ConditionalAccess', 'Group.Read.All', 'Policy.Read.All', 'Application.Read.All')
    $missing = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
    if ($missing) {
        throw "Graph session is missing required scopes: $($missing -join ', '). Reconnect with all required scopes."
    }
}

function Resolve-GroupId {
    param([Parameter(Mandatory)][string]$DisplayName)
    $escaped = $DisplayName -replace "'", "''"
    $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$escaped'&`$select=id,displayName"
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $groups = @($response.value)
    if ($groups.Count -eq 0) {
        throw "Group not found in tenant: '$DisplayName'. Create it before running this script."
    }
    if ($groups.Count -gt 1) {
        throw "Multiple groups found with displayName '$DisplayName'. Ensure the name is unique."
    }
    return $groups[0].id
}

function Resolve-AuthStrengthId {
    param([Parameter(Mandatory)][string]$DisplayName)
    $response = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies?$select=id,displayName'
    $match = @($response.value | Where-Object { $_.displayName -eq $DisplayName })
    if ($match.Count -eq 0) {
        throw "Authentication strength not found in tenant: '$DisplayName'."
    }
    return $match[0].id
}

function Expand-Placeholders {
    param(
        [Parameter(Mandatory)][string]$JsonContent,
        [Parameter(Mandatory)][hashtable]$Substitutions
    )
    $result = $JsonContent
    foreach ($key in $Substitutions.Keys) {
        $result = $result -replace [regex]::Escape($key), $Substitutions[$key]
    }
    return $result
}

function New-CAPolicy {
    param([Parameter(Mandatory)][hashtable]$Policy)
    $body = $Policy | ConvertTo-Json -Depth 20 -Compress:$false
    return Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' `
        -Body $body -ContentType 'application/json'
}

#endregion

#region Main

try {
    Write-Status "Deploy-CABaseline starting"
    $modeLabel = if ($Enforce) { 'ENFORCE (enabled state)' } else { 'report-only (safe default)' }
    Write-Status "Mode: $modeLabel" -Level $(if ($Enforce) { 'Warning' } else { 'Info' })

    Test-GraphPrerequisites
    $tenantContext = Get-MgContext
    Write-Status "Connected tenant: $($tenantContext.TenantId) as $($tenantContext.Account)" -Level Success

    Write-Status "Resolving tenant-specific placeholders..."
    $substitutions = @{
        'REPLACE_WITH_EMERGENCY_ACCESS_GROUP_OBJECT_ID'     = Resolve-GroupId -DisplayName $EmergencyAccessGroupName
        'REPLACE_WITH_WORKLOAD_IDENTITIES_GROUP_OBJECT_ID'  = Resolve-GroupId -DisplayName $WorkloadIdentitiesGroupName
        'REPLACE_WITH_GLOBAL_ADMINS_GROUP_OBJECT_ID'        = Resolve-GroupId -DisplayName $GlobalAdminsGroupName
        'REPLACE_WITH_INTERNAL_USERS_GROUP_OBJECT_ID'       = Resolve-GroupId -DisplayName $InternalUsersGroupName
        'REPLACE_WITH_PHISHING_RESISTANT_MFA_STRENGTH_ID'   = Resolve-AuthStrengthId -DisplayName $AuthStrengthName
    }
    foreach ($key in $substitutions.Keys) {
        Write-Status "  $key -> $($substitutions[$key])" -Level Success
    }

    $resolvedPolicyPath = Resolve-Path -Path $PolicyPath -ErrorAction SilentlyContinue
    if (-not $resolvedPolicyPath) {
        throw "Policy path not found: $PolicyPath"
    }
    $templates = Get-ChildItem -Path $resolvedPolicyPath -Filter '*.json' -File | Sort-Object Name
    if ($templates.Count -eq 0) {
        throw "No JSON policy templates found in: $resolvedPolicyPath"
    }
    Write-Status "Found $($templates.Count) policy templates in $resolvedPolicyPath" -Level Success

    if ($Enforce) {
        Write-Status "You have specified -Enforce. Policies will be created in 'enabled' state." -Level Warning
        if (-not $PSCmdlet.ShouldContinue(
                "This will enforce $($templates.Count) Conditional Access policies on tenant $($tenantContext.TenantId). Continue?",
                "Confirm enforced deployment"
            )) {
            Write-Status "Deployment cancelled by user." -Level Warning
            return
        }
    }

    $results = @()
    foreach ($template in $templates) {
        Write-Status "Processing: $($template.Name)"
        try {
            $rawJson = Get-Content -Path $template.FullName -Raw
            $expandedJson = Expand-Placeholders -JsonContent $rawJson -Substitutions $substitutions
            if ($expandedJson -match 'REPLACE_WITH_') {
                throw "Unresolved placeholders remain in $($template.Name) after substitution."
            }
            $policy = $expandedJson | ConvertFrom-Json -AsHashtable
            $policy.state = if ($Enforce) { 'enabled' } else { 'enabledForReportingButNotEnforced' }

            if ($PSCmdlet.ShouldProcess($policy.displayName, "Create Conditional Access policy (state=$($policy.state))")) {
                $created = New-CAPolicy -Policy $policy
                Write-Status "  Created: $($created.displayName) [$($created.id)]" -Level Success
                $results += [pscustomobject]@{
                    Template = $template.Name
                    Policy   = $created.displayName
                    Id       = $created.id
                    State    = $created.state
                    Status   = 'Created'
                }
            } else {
                $results += [pscustomobject]@{
                    Template = $template.Name
                    Policy   = $policy.displayName
                    Id       = 'n/a'
                    State    = $policy.state
                    Status   = 'WhatIf'
                }
            }
        } catch {
            Write-Status "  Failed: $($template.Name) - $_" -Level Error
            $results += [pscustomobject]@{
                Template = $template.Name
                Policy   = 'n/a'
                Id       = 'n/a'
                State    = 'n/a'
                Status   = "Error: $_"
            }
        }
    }

    Write-Host ""
    Write-Status "Summary:"
    $results | Format-Table -AutoSize

    $createdCount = @($results | Where-Object { $_.Status -eq 'Created' }).Count
    $whatIfCount  = @($results | Where-Object { $_.Status -eq 'WhatIf' }).Count
    $errorCount   = @($results | Where-Object { $_.Status -like 'Error:*' }).Count

    Write-Status "Created: $createdCount, Previewed: $whatIfCount, Errors: $errorCount"
    if ($errorCount -gt 0) {
        Write-Status "Deployment completed with errors. Review output above." -Level Warning
        exit 1
    }
    if ($createdCount -gt 0 -and -not $Enforce) {
        Write-Status "Reminder: Policies are in report-only mode. Soak, validate, and promote to enforced per Policy-Design.md section 5." -Level Info
    }

} catch {
    Write-Status $_ -Level Error
    exit 1
}

#endregion
