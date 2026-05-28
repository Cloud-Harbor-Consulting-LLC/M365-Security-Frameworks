<#
.SYNOPSIS
    Deploys the Conditional Access Baseline policies to a Microsoft Entra tenant.

.DESCRIPTION
    Deploy-CABaseline.ps1 imports the CA-AUT, CA-COV, and CA-SIG policy templates
    in this framework into the target tenant using a single Microsoft.Graph.Authentication
    module dependency and the Microsoft Graph beta endpoint.

    The script:
    - Resolves tenant-specific placeholders (persona group IDs, named location IDs,
      authentication strength IDs) by looking them up in the tenant at runtime
    - Validates every placeholder resolves before submitting any policy
    - Defaults to report-only state (enabledForReportingButNotEnforced); use
      -Enforce to promote to enabled state (requires explicit confirmation)
    - Supports -WhatIf for safe preview: in WhatIf mode the script connects to
      Microsoft Graph, validates the session, parses every policy template, and
      reports what it would do without making any tenant changes or resolving
      tenant-specific placeholders

    Supporting artifacts (custom authentication strengths, named locations) referenced
    by the policy templates must exist in the tenant before running this script in
    non-WhatIf mode. See Supporting-Artifacts/README.md for provisioning instructions.

.PARAMETER PolicyPath
    Path to the folder containing the JSON policy templates. Defaults to
    the Policies/ folder adjacent to the Scripts/ folder.

.PARAMETER EmergencyAccessGroupName
    Display name of the emergency access group. Default: CA-Persona-EmergencyAccess.

.PARAMETER WorkloadIdentitiesGroupName
    Display name of the workload identities group. Default: CA-Persona-WorkloadIdentities.

.PARAMETER InternalUsersGroupName
    Display name of the internal users persona group. Default: CA-Persona-InternalUsers.

.PARAMETER ServiceAccountsGroupName
    Display name of the service accounts persona group. Default: CA-Persona-ServiceAccounts.

.PARAMETER GuestsGroupName
    Display name of the guests persona group. Default: CA-Persona-Guests.

.PARAMETER TrustedCountriesLocationName
    Display name of the trusted-countries named location. Default: Trusted Countries.

.PARAMETER StandardAuthStrengthName
    Display name of the StandardAuth authentication strength. Default: StandardAuth.

.PARAMETER StrongAuthStrengthName
    Display name of the StrongAuth authentication strength. Default: StrongAuth.

.PARAMETER AdminAuthStrengthName
    Display name of the AdminAuth authentication strength. Default: AdminAuth.

.PARAMETER TermsOfUseName
    Display name of the Terms of Use agreement. Default: CHC Guest Terms of Use.

.PARAMETER Enforce
    Switch. If specified, policies are created in 'enabled' state. Requires explicit
    confirmation. Default is report-only.

.PARAMETER StopOnError
    Switch. If specified, the script stops on the first policy creation failure.
    Default behavior is to continue and report all errors at the end.

.EXAMPLE
    .\Deploy-CABaseline.ps1 -WhatIf
    Preview the deployment. Connects to Graph to validate the session, parses all
    templates, and reports what would be created without making any tenant changes.

.EXAMPLE
    .\Deploy-CABaseline.ps1
    Deploy all policies in report-only mode.

.EXAMPLE
    .\Deploy-CABaseline.ps1 -Enforce
    Deploy all policies in enabled state. Prompts for confirmation.

.NOTES
    Requires:
    - PowerShell 7.0 or later
    - Microsoft.Graph.Authentication module (Install-Module Microsoft.Graph.Authentication)
    - Graph scopes: Policy.ReadWrite.ConditionalAccess, Policy.Read.All,
      Group.Read.All, Application.Read.All, Policy.ReadWrite.AuthenticationMethod
    - Persona groups, authentication strengths, and named locations must exist
      in the tenant before running in non-WhatIf mode

    Endpoint: https://graph.microsoft.com/beta/identity/conditionalAccess/policies
    (beta is required for agentIdRiskLevels and signInFrequency.frequencyInterval=everyTime)

    Author: Derek Morgan, Cloud Harbor Consulting
    Repository: https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [string]$PolicyPath = (Join-Path $PSScriptRoot '\' 'Policies'),

    [Parameter()]
    [string]$EmergencyAccessGroupName = 'CA-Persona-EmergencyAccess',

    [Parameter()]
    [string]$WorkloadIdentitiesGroupName = 'CA-Persona-WorkloadIdentities',

    [Parameter()]
    [string]$InternalUsersGroupName = 'CA-Persona-InternalUsers',

    [Parameter()]
    [string]$ServiceAccountsGroupName = 'CA-Persona-ServiceAccounts',

    [Parameter()]
    [string]$GuestsGroupName = 'CA-Persona-Guests',

    [Parameter()]
    [string]$TrustedCountriesLocationName = 'Trusted Countries',

    [Parameter()]
    [string]$StandardAuthStrengthName = 'StandardAuth',

    [Parameter()]
    [string]$StrongAuthStrengthName = 'StrongAuth',

    [Parameter()]
    [string]$AdminAuthStrengthName = 'AdminAuth',

    [Parameter(Mandatory = $false)]
    [string]$TermsOfUseName = 'Terms of Use for Guest Users',

    [Parameter()]
    [switch]$Enforce,

    [Parameter()]
    [switch]$StopOnError
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
        throw "Microsoft.Graph.Authentication module is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }
    $context = Get-MgContext
    if (-not $context) {
        throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess,Policy.Read.All,Group.Read.All,Application.Read.All,Policy.ReadWrite.AuthenticationMethod,Agreement.Read.All,Agreement.ReadWrite.All"
    }
    $required = @(
        'Policy.ReadWrite.ConditionalAccess',
        'Policy.Read.All',
        'Group.Read.All',
        'Application.Read.All'
    )
    $missing = $required | Where-Object { $_ -notin $context.Scopes }
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
        throw "Authentication strength not found in tenant: '$DisplayName'. Provision it from Supporting-Artifacts/ before running this script."
    }
    return $match[0].id
}

function Resolve-NamedLocationId {
    param([Parameter(Mandatory)][string]$DisplayName)
    $response = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations?$select=id,displayName'
    $match = @($response.value | Where-Object { $_.displayName -eq $DisplayName })
    if ($match.Count -eq 0) {
        throw "Named location not found in tenant: '$DisplayName'. Provision it from Supporting-Artifacts/ before running this script."
    }
    if ($match.Count -gt 1) {
        throw "Multiple named locations found with displayName '$DisplayName'. Ensure the name is unique."
    }
    return $match[0].id
}

function Resolve-TermsOfUseId {
    param([string]$Name)
    Write-Status "Resolving Terms of Use agreement '$Name'..."
    $response = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/identityGovernance/termsOfUse/agreements"
    $tou = $response.value | Where-Object { $_.displayName -eq $Name } | Select-Object -First 1
    if (-not $tou) {
        throw "Terms of Use agreement '$Name' not found in tenant. Create it in Microsoft Entra > External Identities > Terms of use, then re-run."
    }
    Write-Status "Resolved Terms of Use ID: $($tou.id)"
    return $tou.id
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

#endregion

#region Main

try {
    Write-Status "Deploy-CABaseline starting"

    $isWhatIf = $PSBoundParameters.ContainsKey('WhatIf')
    $modeLabel = if ($Enforce) { 'ENFORCE (enabled state)' } else { 'report-only (safe default)' }
    Write-Status "Mode: $modeLabel"
    if ($isWhatIf) { Write-Status "WhatIf: live simulation — prerequisites and placeholders will be validated, no policies will be created" -Level Warning }

    $resolvedPolicyPath = Resolve-Path -Path $PolicyPath -ErrorAction SilentlyContinue
    if (-not $resolvedPolicyPath) {
        throw "Policy path not found: $PolicyPath"
    }

    $templates = Get-ChildItem -Path $resolvedPolicyPath -Filter '*.json' -File | Sort-Object Name
    if ($templates.Count -eq 0) {
        throw "No JSON policy templates found in: $resolvedPolicyPath"
    }
    Write-Status "Found $($templates.Count) policy templates in $resolvedPolicyPath" -Level Success

    $substitutions = @{}

    Test-GraphPrerequisites
    $tenantContext = Get-MgContext
    Write-Status "Connected tenant: $($tenantContext.TenantId) as $($tenantContext.Account)" -Level Success

    Write-Status "Resolving tenant-specific placeholders..."
    $substitutions = @{
        'REPLACE_WITH_EMERGENCY_ACCESS_GROUP_OBJECT_ID'    = Resolve-GroupId -DisplayName $EmergencyAccessGroupName
        'REPLACE_WITH_WORKLOAD_IDENTITIES_GROUP_OBJECT_ID' = Resolve-GroupId -DisplayName $WorkloadIdentitiesGroupName
        'REPLACE_WITH_INTERNAL_USERS_GROUP_OBJECT_ID'      = Resolve-GroupId -DisplayName $InternalUsersGroupName
        'REPLACE_WITH_SERVICE_ACCOUNTS_GROUP_OBJECT_ID'    = Resolve-GroupId -DisplayName $ServiceAccountsGroupName
        'REPLACE_WITH_GUESTS_GROUP_OBJECT_ID'              = Resolve-GroupId -DisplayName $GuestsGroupName
        'REPLACE_WITH_TRUSTED_COUNTRIES_LOCATION_ID'       = Resolve-NamedLocationId -DisplayName $TrustedCountriesLocationName
        'REPLACE_WITH_STANDARDAUTH_STRENGTH_ID'            = Resolve-AuthStrengthId -DisplayName $StandardAuthStrengthName
        'REPLACE_WITH_STRONGAUTH_STRENGTH_ID'              = Resolve-AuthStrengthId -DisplayName $StrongAuthStrengthName
        'REPLACE_WITH_ADMINAUTH_STRENGTH_ID'               = Resolve-AuthStrengthId -DisplayName $AdminAuthStrengthName
    }
    foreach ($key in $substitutions.Keys) {
        Write-Status "  $key -> $($substitutions[$key])" -Level Success
    }

    if (-not $isWhatIf -and $Enforce) {
        Write-Status "You have specified -Enforce. Policies will be created in 'enabled' state." -Level Warning
        if (-not $PSCmdlet.ShouldContinue(
                "This will create $($templates.Count) Conditional Access policies in 'enabled' state on tenant $($tenantContext.TenantId). Continue?",
                "Confirm enforced deployment"
            )) {
            Write-Status "Deployment cancelled by user." -Level Warning
            return
        }
    }

    $script:TermsOfUseId = $null
    $results = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($template in $templates) {
        Write-Status "Processing: $($template.Name)"
        try {
            $rawJson = Get-Content -Path $template.FullName -Raw
            $expandedJson = Expand-Placeholders -JsonContent $rawJson -Substitutions $substitutions
            if ($expandedJson -match 'REPLACE_WITH_TERMS_OF_USE_ID') {
                if (-not $script:TermsOfUseId) {
                    $script:TermsOfUseId = Resolve-TermsOfUseId -Name $TermsOfUseName
                }
                $expandedJson = $expandedJson -replace 'REPLACE_WITH_TERMS_OF_USE_ID', $script:TermsOfUseId
            }
            if ($expandedJson -match 'REPLACE_WITH_') {
                throw "Unresolved placeholders remain in $($template.Name) after substitution."
            }

            $body = $expandedJson | ConvertFrom-Json -AsHashtable
            $body['state'] = if ($Enforce) { 'enabled' } else { 'enabledForReportingButNotEnforced' }

            if ($PSCmdlet.ShouldProcess($body['displayName'], "Create Conditional Access policy (state=$($body['state'])) on beta endpoint")) {
                $bodyJson = $body | ConvertTo-Json -Depth 50 -Compress
                $created = Invoke-MgGraphRequest -Method POST `
                    -Uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' `
                    -Body $bodyJson -ContentType 'application/json'
                Write-Status "  Created: $($created.displayName) [$($created.id)]" -Level Success
                $results.Add([pscustomobject]@{
                    Template = $template.Name
                    Policy   = $created.displayName
                    Id       = $created.id
                    State    = $created.state
                    Status   = 'Created'
                })
            } else {
                $results.Add([pscustomobject]@{
                    Template = $template.Name
                    Policy   = $body['displayName']
                    Id       = 'n/a'
                    State    = $body['state']
                    Status   = 'WhatIf'
                })
            }
        } catch {
            $errMsg = "Failed: $($template.Name) — $_"
            Write-Status $errMsg -Level Error
            $results.Add([pscustomobject]@{
                Template = $template.Name
                Policy   = 'n/a'
                Id       = 'n/a'
                State    = 'n/a'
                Status   = "Error: $_"
            })
            if ($StopOnError) {
                throw "Stopping on first error as requested by -StopOnError. $errMsg"
            }
        }
    }

    Write-Host ''
    Write-Status "Summary:"
    $results | Format-Table -AutoSize

    $createdCount = @($results | Where-Object { $_.Status -eq 'Created' }).Count
    $whatIfCount  = @($results | Where-Object { $_.Status -eq 'WhatIf' }).Count
    $errorCount   = @($results | Where-Object { $_.Status -like 'Error:*' }).Count

    Write-Status "Created: $createdCount  Previewed: $whatIfCount  Errors: $errorCount"

    if ($errorCount -gt 0) {
        Write-Status "Deployment completed with errors. Review output above." -Level Warning
        exit 1
    }
    if ($whatIfCount -gt 0) {
        Write-Status "WhatIf complete. Re-run without -WhatIf to deploy." -Level Info
    }
    if ($createdCount -gt 0 -and -not $Enforce) {
        Write-Status "Reminder: Policies are in report-only mode. Soak, validate with Get-CABaselineImpact.ps1, and promote per Design/POLICY-DESIGN.md section 5." -Level Info
    }

} catch {
    Write-Status "$_" -Level Error
    exit 1
}

#endregion
