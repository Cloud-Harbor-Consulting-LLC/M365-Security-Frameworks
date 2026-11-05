#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Read-only. Exports every Conditional Access policy plan (preview) with its rules, snapshots the
    standalone policies, and compares each rule with the standalone policy of the same name.

.DESCRIPTION
    Policy plans live on their own Graph beta endpoint, /identity/conditionalAccess/plans, with rules
    under /plans/{id}/rules. Tools and backups that read only /policies do not see them. This script:

      1. Saves each plan together with its rules (a rule stores only its own settings, not the plan's
         shared conditions, so a rule alone is incomplete) and a snapshot of all standalone policies.
      2. Compares each rule's effective settings (plan shared conditions + rule) with the standalone
         policy of the same name, which is the name the migration wizard gives each rule. Exclusions and
         other values combine as a union. clientAppTypes must match both the plan and the rule, with
         'all' meaning no restriction (observed in sign-in logs: plan 'all' + rule 'browser' did not
         apply to desktop clients, conditionsNotSatisfied=clientType).
      3. Flags plan-level values that a rule also carries ("duplicated from plan").
      4. Lists Conditional Access audit events that mention plans or rules.

    Nothing is written to the tenant. Policy plans are in preview; the API is Graph beta.

.PARAMETER TenantId
    Tenant ID or primary domain to sign in to. Omit to use the account's home tenant.

.PARAMETER AuditDaysBack
    How many days of Conditional Access audit events to list. Default 7.

.PARAMETER OutDir
    Folder for the JSON export and the log. Default: cab-policy-plans-<tenant>-<time> in the current folder.

.EXAMPLE
    ./Export-CABPolicyPlans.ps1 -TenantId contoso.onmicrosoft.com

.NOTES
    Delegated scopes: Policy.Read.All, Directory.Read.All (to show names for IDs), AuditLog.Read.All.
#>
param(
    [string]$TenantId,
    [int]$AuditDaysBack = 7,
    [string]$OutDir
)
$ErrorActionPreference = 'Stop'
$connect = @{ NoWelcome = $true; Scopes = 'Policy.Read.All', 'Directory.Read.All', 'AuditLog.Read.All' }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect
$tenant = (Get-MgContext).TenantId
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutDir) { $OutDir = Join-Path (Get-Location) "cab-policy-plans-$tenant-$stamp" }
$logFile = Join-Path $OutDir "cab-policy-plans-$tenant-$stamp.log"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$beta = 'https://graph.microsoft.com/beta'
$out = New-Object System.Collections.Generic.List[string]
function Say($Text) { $out.Add("$Text"); Write-Host $Text }
function Get-All([string]$Uri) {
    $items = @()
    while ($Uri) { $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject; $items += @($r.value); $Uri = $r.'@odata.nextLink' }
    $items
}

# Names for the GUIDs that appear in conditions: roles, named locations and authentication strengths up front,
# users and groups on demand.
$names = @{}
Get-All "$beta/directoryRoleTemplates" | ForEach-Object { $names[$_.id] = "role:$($_.displayName)" }
Get-All "$beta/identity/conditionalAccess/namedLocations" | ForEach-Object { $names[$_.id] = "location:$($_.displayName)" }
Get-All "$beta/identity/conditionalAccess/authenticationStrength/policies" | ForEach-Object { $names[$_.id] = "strength:$($_.displayName)" }
function Get-Name([string]$Value) {
    if ($Value -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') { return $Value }
    if (-not $names.ContainsKey($Value)) {
        try {
            $o = Invoke-MgGraphRequest -Method GET -Uri "$beta/directoryObjects/$Value" -OutputType PSObject
            $names[$Value] = "$($o.'@odata.type' -replace '^#microsoft\.graph\.', ''):$($o.displayName)"
        } catch { $names[$Value] = $Value }
    }
    $names[$Value]
}

# Flattens an object to path -> sorted unique values, so a policy and a rule compare regardless of order.
# Nulls, empty arrays and false booleans are dropped: they are defaults, and the two APIs omit them differently.
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
# Grant and session controls in one comparable shape. The policies API expands an authentication strength;
# keep only its id.
function Get-Controls($Grant, $Session) {
    $g = if ($Grant) { $Grant | ConvertTo-Json -Depth 10 | ConvertFrom-Json } else { $null }
    if ($g.authenticationStrength) { $g.authenticationStrength = [pscustomobject]@{ id = $g.authenticationStrength.id } }
    [pscustomobject]@{ grantControls = $g; sessionControls = $Session }
}
# Differences between a standalone policy and a plan rule's effective settings, assuming plan and rule values
# combine as a union ("inclusions and exclusions accumulate"). Exception: clientAppTypes must match both, with
# 'all' meaning no restriction (demo sign-ins 2026-11-03: plan 'all' + rule 'browser' was not satisfied for
# desktop clients, conditionsNotSatisfied=clientType).
function Get-RuleDiff($SharedConditions, $Rule, $Policy) {
    $effective = [ordered]@{}
    $intersect = @('conditions.clientAppTypes')
    foreach ($src in (ConvertTo-Flat $SharedConditions 'conditions'), (ConvertTo-Flat $Rule.conditions 'conditions'), (ConvertTo-Flat (Get-Controls $Rule.controls.grantControls $Rule.controls.sessionControls) '')) {
        foreach ($k in $src.Keys) {
            if ($k -in $intersect -and $effective.Contains($k)) {
                $a = @($effective[$k]); $b = @($src[$k])
                $effective[$k] = if ($a -contains 'all') { $b } elseif ($b -contains 'all') { $a } else { @($a | Where-Object { $_ -in $b }) }
            } else { $effective[$k] = @(@($effective[$k]) + @($src[$k]) | Where-Object { $_ } | Sort-Object -Unique) }
        }
    }
    $want = ConvertTo-Flat $Policy.conditions 'conditions'
    $pc = ConvertTo-Flat (Get-Controls $Policy.grantControls $Policy.sessionControls) ''
    foreach ($k in $pc.Keys) { $want[$k] = $pc[$k] }
    foreach ($k in (@($want.Keys) + @($effective.Keys) | Sort-Object -Unique)) {
        if ((@($want[$k]) -join '|') -ne (@($effective[$k]) -join '|')) { [pscustomobject]@{ Path = $k; Policy = $want[$k]; Effective = $effective[$k] } }
    }
}
function Format-Values($Values) { (@($Values | ForEach-Object { Get-Name $_ }) -join ', ') }

Say "Conditional Access policy plans in tenant $tenant, $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')"
Say "Raw JSON: $OutDir"

$policies = @(Get-All "$beta/identity/conditionalAccess/policies")
$policies | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $OutDir 'policies-snapshot.json') -Encoding utf8
$plans = @(Get-All "$beta/identity/conditionalAccess/plans")
Say "Standalone policies: $($policies.Count). Policy plans: $($plans.Count)."

$rulesTotal = 0
foreach ($plan in ($plans | Sort-Object displayName)) {
    $rules = @(Get-All "$beta/identity/conditionalAccess/plans/$($plan.id)/rules")
    $rulesTotal += $rules.Count
    $file = ($plan.displayName -replace '[^\w.-]+', '_')
    [pscustomobject]@{ plan = $plan; rules = $rules } | ConvertTo-Json -Depth 20 | Set-Content -Path (Join-Path $OutDir "plan-$file.json") -Encoding utf8

    Say ''
    Say ("== Plan: {0} ==" -f $plan.displayName)
    Say ("    id {0}; version {1}; template {2}; created {3}; modified {4}" -f $plan.id, $plan.version, ($plan.templateId ?? 'none'), $plan.createdDateTime, $plan.modifiedDateTime)
    Say ("    owners {0}; tags {1}" -f ((@($plan.owners) | ForEach-Object { Get-Name $_ }) -join ', '), (@($plan.tags) -join ', '))
    $shared = ConvertTo-Flat $plan.sharedConditions 'conditions'
    if (-not $shared.Count) { Say '    shared conditions: (none)' }
    foreach ($k in $shared.Keys) { Say ("    shared {0}: {1}" -f $k, (Format-Values $shared[$k])) }

    foreach ($rule in ($rules | Sort-Object displayName)) {
        Say ''
        Say ("  -- Rule: {0} [{1}]" -f $rule.displayName, $rule.state)
        $own = ConvertTo-Flat $rule.conditions 'conditions'
        $ctl = ConvertTo-Flat (Get-Controls $rule.controls.grantControls $rule.controls.sessionControls) ''
        foreach ($k in $own.Keys) { Say ("     rule {0}: {1}" -f $k, (Format-Values $own[$k])) }
        foreach ($k in $ctl.Keys) { Say ("     rule {0}: {1}" -f $k, (Format-Values $ctl[$k])) }
        # Plan-level values the rule also carries: the duplication plans are meant to remove.
        foreach ($k in $own.Keys) {
            $dup = @($own[$k] | Where-Object { $shared[$k] -contains $_ })
            if ($dup) { Say ("     duplicated from plan {0}: {1}" -f $k, (Format-Values $dup)) }
        }

        $source = @($policies | Where-Object displayName -eq $rule.displayName)
        if (-not $source) { Say '     source policy: none with this name'; continue }
        $p = $source[0]
        $diffs = @(Get-RuleDiff $plan.sharedConditions $rule $p)
        Say ("     source policy {0} [{1}], modified {2}: {3}" -f $p.id, $p.state, $p.modifiedDateTime, $(if ($diffs) { "$($diffs.Count) difference(s)" } else { 'MATCH' }))
        foreach ($d in $diffs) { Say ("       {0}: policy [{1}] vs plan+rule [{2}]" -f $d.Path, (Format-Values $d.Policy), (Format-Values $d.Effective)) }
    }
}

Say ''
Say "== Totals: $($plans.Count) plan(s), $rulesTotal rule(s), $($policies.Count) standalone policies =="

Say ''
Say "== Conditional Access audit events, last $AuditDaysBack days, that mention plans or rules =="
$fromUtc = (Get-Date).ToUniversalTime().AddDays(-$AuditDaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$audits = @(Get-All "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $fromUtc and loggedByService eq 'Conditional Access'" |
        Where-Object { $_.activityDisplayName -match 'plan|rule' -or @($_.targetResources.type) -match 'plan|rule' } | Sort-Object activityDateTime)
if (-not $audits) { Say '(none)' }
foreach ($a in $audits) {
    $who = $a.initiatedBy.user.userPrincipalName ?? $a.initiatedBy.app.displayName
    Say ("{0}  {1}: {2} by {3}" -f $a.activityDateTime, $a.activityDisplayName, ((@($a.targetResources) | ForEach-Object { "$($_.displayName) ($($_.type))" }) -join '; '), $who)
}
$out | Set-Content -Path $logFile -Encoding utf8
Write-Host "`nWritten to $logFile"
