#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Deploys the reference Conditional Access policy plans (preview) to a tenant, every rule in report-only.

.DESCRIPTION
    Creates each plan in Plans/ with its rules in a single request (POST /identity/conditionalAccess/plans
    on Microsoft Graph beta), then reads the plan back and checks it against what was sent.

    The script:
      - deploys report-only only. A plan file whose rules are not all enabledForReportingButNotEnforced
        is refused, and there is no switch to enforce. Turn rules on in the Entra admin center after
        validating them (see the folder README).
      - never changes the baseline's standalone policies. Plans apply alongside them.
      - resolves the same placeholders as Deploy-CABaseline.ps1 (persona groups, the AdminAuth
        authentication strength, the guest Terms of Use), only for the plans being deployed, and
        refuses a plan that still carries a placeholder.
      - skips a plan that already exists with the same name. It never updates or replaces one.
      - with -WhatIf, resolves everything and reports what it would create, without writing.

    Policy plans are a Microsoft Entra preview feature and the API is Graph beta.

.PARAMETER PlanPath
    Folder of plan JSON files. Default: the Plans/ folder next to Scripts/.

.PARAMETER Plan
    Names of the plans to deploy (file base names, for example CAB-P6-Guests). Default: all.

.PARAMETER TenantId
    Tenant ID or primary domain to sign in to. Omit to use the current Microsoft Graph session, or
    the account's home tenant if there is none.

.PARAMETER EmergencyAccessGroupName
    Display name of the emergency access group. Default: CA-Persona-EmergencyAccess.

.PARAMETER WorkloadIdentitiesGroupName
    Display name of the workload identities group. Default: CA-Persona-WorkloadIdentities.

.PARAMETER ServiceAccountsGroupName
    Display name of the service accounts group. Default: CA-Persona-ServiceAccounts.

.PARAMETER AdminAuthStrengthName
    Display name of the AdminAuth authentication strength. Default: AdminAuth.

.PARAMETER TermsOfUseName
    Display name of the guest Terms of Use agreement. Default: Terms of Use for Guest Users.

.EXAMPLE
    ./Deploy-CABPolicyPlans.ps1 -TenantId contoso.onmicrosoft.com -WhatIf

.EXAMPLE
    ./Deploy-CABPolicyPlans.ps1 -TenantId contoso.onmicrosoft.com -Plan CAB-P6-Guests -TermsOfUseName 'Contoso guest terms'

.NOTES
    Delegated scopes: Policy.ReadWrite.ConditionalAccess, Policy.Read.All, Group.Read.All,
    Agreement.Read.All. The account needs the Conditional Access Administrator role.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PlanPath = (Join-Path $PSScriptRoot '..' 'Plans'),
    [string[]]$Plan,
    [string]$TenantId,
    [string]$EmergencyAccessGroupName = 'CA-Persona-EmergencyAccess',
    [string]$WorkloadIdentitiesGroupName = 'CA-Persona-WorkloadIdentities',
    [string]$ServiceAccountsGroupName = 'CA-Persona-ServiceAccounts',
    [string]$AdminAuthStrengthName = 'AdminAuth',
    [string]$TermsOfUseName = 'Terms of Use for Guest Users'
)
$ErrorActionPreference = 'Stop'
$beta = 'https://graph.microsoft.com/beta'
$reportOnly = 'enabledForReportingButNotEnforced'

function Write-Status([string]$Message, [string]$Level = 'Info') {
    $color = @{ Info = 'Cyan'; Success = 'Green'; Warning = 'Yellow'; Error = 'Red' }[$Level]
    $prefix = @{ Info = '[INFO] '; Success = '[OK]   '; Warning = '[WARN] '; Error = '[ERR]  ' }[$Level]
    Write-Host "$prefix$Message" -ForegroundColor $color
}
function Get-All([string]$Uri) {
    $items = @()
    while ($Uri) { $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject; $items += @($r.value); $Uri = $r.'@odata.nextLink' }
    $items
}
function Resolve-GroupId([string]$DisplayName) {
    $escaped = $DisplayName -replace "'", "''"
    $groups = @(Get-All "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$escaped'&`$select=id,displayName")
    if ($groups.Count -eq 0) { throw "Group not found in tenant: '$DisplayName'. Create it, or pass its name with the matching -...GroupName parameter." }
    if ($groups.Count -gt 1) { throw "Multiple groups found with displayName '$DisplayName'. Ensure the name is unique." }
    $groups[0].id
}
function Resolve-AuthStrengthId([string]$DisplayName) {
    $match = @(Get-All "$beta/identity/conditionalAccess/authenticationStrength/policies" | Where-Object displayName -eq $DisplayName)
    if ($match.Count -eq 0) { throw "Authentication strength not found in tenant: '$DisplayName'. Provision it from Supporting-Artifacts/ first." }
    $match[0].id
}
function Resolve-TermsOfUseId([string]$DisplayName) {
    $match = @(Get-All "$beta/identityGovernance/termsOfUse/agreements" | Where-Object displayName -eq $DisplayName)
    if ($match.Count -eq 0) { throw "Terms of Use agreement not found in tenant: '$DisplayName'. Pass the agreement's name with -TermsOfUseName." }
    $match[0].id
}

# Flattens an object to path -> sorted unique values, so what was sent and what Graph stored compare regardless of
# order. Nulls, empty arrays and false booleans are dropped: they are defaults, and Graph omits them differently.
# The same function as in Export-CABPolicyPlans.ps1; the harness checks the two copies are identical.
function ConvertTo-Flat($Obj, [string]$Prefix) {
    $h = [ordered]@{}
    if ($null -eq $Obj) { return $h }
    foreach ($p in $Obj.PSObject.Properties) {
        if ($p.Name -like '*@odata*') { continue }
        $path = if ($Prefix) { "$Prefix.$($p.Name)" } else { $p.Name }
        $v = $p.Value
        if ($null -eq $v -or ($v -is [bool] -and -not $v)) { continue }
        if ($v -is [System.Management.Automation.PSCustomObject]) {
            $sub = ConvertTo-Flat $v $path
            foreach ($k in $sub.Keys) { $h[$k] = $sub[$k] }
        } elseif ($v -is [array]) {
            $vals = @($v | Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [System.Management.Automation.PSCustomObject]) { $_ | ConvertTo-Json -Compress -Depth 10 } else { "$_" } })
            if ($vals.Count) { $h[$path] = @($vals | Sort-Object -Unique) }
        } elseif ("$v" -ne '') {
            # Comma-separated enums (guest types, risk levels, transfer methods) compare as sets.
            $h[$path] = if ($path -match '(guestOrExternalUserTypes|RiskLevels|transferMethods)$') { @("$v".Split(',') | ForEach-Object Trim | Sort-Object -Unique) } else { @("$v") }
        }
    }
    $h
}
# Values sent that Graph did not store as sent. Values Graph added on its own are not mismatches.
function Compare-Stored($Sent, $Stored, [string]$Prefix) {
    $want = ConvertTo-Flat $Sent $Prefix
    $got = ConvertTo-Flat $Stored $Prefix
    foreach ($k in $want.Keys) {
        if ((@($want[$k]) -join '|') -ne (@($got[$k]) -join '|')) { "$k sent [$(@($want[$k]) -join ', ')] stored [$(@($got[$k]) -join ', ')]" }
    }
}

$files = @(Get-ChildItem -Path $PlanPath -Filter '*.json' -File | Sort-Object Name)
if ($Plan) {
    $unknown = @($Plan | Where-Object { $_ -notin $files.BaseName })
    if ($unknown) { throw "No plan file for: $($unknown -join ', '). Available: $($files.BaseName -join ', ')." }
    $files = @($files | Where-Object BaseName -in $Plan)
}
if (-not $files) { throw "No plan files found in $PlanPath." }

# Every rule must ship report-only before anything else happens.
$plans = foreach ($f in $files) {
    $raw = Get-Content -Path $f.FullName -Raw
    $obj = $raw | ConvertFrom-Json -Depth 50
    $notReportOnly = @($obj.rules | Where-Object state -ne $reportOnly)
    if ($notReportOnly) { throw "$($f.Name): rule(s) $($notReportOnly.displayName -join ', ') are not $reportOnly. This script deploys report-only only." }
    [pscustomobject]@{ Name = $obj.displayName; File = $f.Name; Raw = $raw }
}
Write-Status "Plans to deploy: $($plans.Name -join ', ')"

$context = Get-MgContext
if ($TenantId -or -not $context) {
    $connect = @{ NoWelcome = $true; Scopes = 'Policy.ReadWrite.ConditionalAccess', 'Policy.Read.All', 'Group.Read.All', 'Agreement.Read.All' }
    if ($TenantId) { $connect.TenantId = $TenantId }
    Connect-MgGraph @connect
    $context = Get-MgContext
}
Write-Status "Tenant $($context.TenantId) as $($context.Account)"

# Resolve only the placeholders the selected plans use.
$resolvers = [ordered]@{
    'REPLACE_WITH_EMERGENCY_ACCESS_GROUP_OBJECT_ID'    = { Resolve-GroupId $EmergencyAccessGroupName }
    'REPLACE_WITH_WORKLOAD_IDENTITIES_GROUP_OBJECT_ID' = { Resolve-GroupId $WorkloadIdentitiesGroupName }
    'REPLACE_WITH_SERVICE_ACCOUNTS_GROUP_OBJECT_ID'    = { Resolve-GroupId $ServiceAccountsGroupName }
    'REPLACE_WITH_ADMINAUTH_STRENGTH_ID'               = { Resolve-AuthStrengthId $AdminAuthStrengthName }
    'REPLACE_WITH_TERMS_OF_USE_ID'                     = { Resolve-TermsOfUseId $TermsOfUseName }
}
$allRaw = $plans.Raw -join "`n"
$values = [ordered]@{}
foreach ($key in $resolvers.Keys) {
    if ($allRaw.Contains($key)) {
        $values[$key] = & $resolvers[$key]
        Write-Status "  $key -> $($values[$key])" 'Success'
    }
}
foreach ($p in $plans) {
    foreach ($key in $values.Keys) { $p.Raw = $p.Raw.Replace($key, $values[$key]) }
    $left = @([regex]::Matches($p.Raw, 'REPLACE_WITH_[A-Z_]+') | ForEach-Object Value | Sort-Object -Unique)
    if ($left) { throw "$($p.File): no resolver for $($left -join ', '). Nothing was deployed." }
}

$existing = @(Get-All "$beta/identity/conditionalAccess/plans")
$failures = 0
foreach ($p in $plans) {
    if ($p.Name -in $existing.displayName) {
        Write-Status "$($p.Name): a plan with this name already exists; skipped. This script never updates or replaces a plan." 'Warning'
        continue
    }
    $body = $p.Raw | ConvertFrom-Json -Depth 50
    if (-not $PSCmdlet.ShouldProcess("plan $($p.Name) with $(@($body.rules).Count) report-only rule(s)", 'Create')) { continue }
    try {
        $created = Invoke-MgGraphRequest -Method POST -Uri "$beta/identity/conditionalAccess/plans" -Body ($p.Raw) -ContentType 'application/json' -OutputType PSObject
        Write-Status "$($p.Name): created, id $($created.id)" 'Success'

        # Read back and compare with what was sent: shared conditions, then each rule by name.
        $stored = Invoke-MgGraphRequest -Method GET -Uri "$beta/identity/conditionalAccess/plans/$($created.id)" -OutputType PSObject
        $storedRules = @(Get-All "$beta/identity/conditionalAccess/plans/$($created.id)/rules")
        $problems = @(Compare-Stored $body.sharedConditions $stored.sharedConditions 'sharedConditions')
        foreach ($rule in $body.rules) {
            $match = @($storedRules | Where-Object displayName -eq $rule.displayName)
            if ($match.Count -ne 1) { $problems += "rule $($rule.displayName): $($match.Count) stored with this name"; continue }
            if ($match[0].state -ne $reportOnly) { $problems += "rule $($rule.displayName): state $($match[0].state)" }
            $problems += @(Compare-Stored ([pscustomobject]@{ conditions = $rule.conditions; controls = $rule.controls }) ([pscustomobject]@{ conditions = $match[0].conditions; controls = $match[0].controls }) $rule.displayName)
        }
        if ($storedRules.Count -ne @($body.rules).Count) { $problems += "$($storedRules.Count) rules stored, $(@($body.rules).Count) sent" }
        if ($problems) {
            $failures++
            Write-Status "$($p.Name): read-back differs from what was sent:" 'Error'
            $problems | ForEach-Object { Write-Status "    $_" 'Error' }
        } else {
            Write-Status "$($p.Name): read-back matches ($($storedRules.Count) rules, all report-only)" 'Success'
        }
    } catch {
        $failures++
        Write-Status "$($p.Name): $($_.Exception.Message)" 'Error'
    }
}
Write-Status "Done. Errors: $failures" $(if ($failures) { 'Error' } else { 'Success' })
if ($failures) { exit 1 }
