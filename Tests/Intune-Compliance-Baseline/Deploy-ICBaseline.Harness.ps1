#Requires -Version 7.0
# Regression harness for Deploy-ICBaseline.ps1.
#
# Runs the shipped script, unmodified, against a stateful fake of the two Intune compliance APIs.
# The fake reproduces what the demo tenant returned to Probe-ICBDeployerApi.ps1 on 2026-10-12, not
# what the documentation describes. Responses are built from the recordings in Fixtures/Live/, and:
#   - assign, scheduleActionsForRules and setScheduledActions answer 200 with an empty body;
#   - a schedule change replaces the whole schedule and gives every action a new ID;
#   - a Settings Catalog (Linux) create accepts an inline schedule and stores Intune's default
#     (mark noncompliant at 0 hours) instead;
#   - read-backs carry every unset classic property (false, null, deviceDefault, unavailable) and
#     null template references on Settings Catalog settings;
#   - a deleted classic policy answers 404 (not exercised: the deployer never deletes).
#
# Prints PASS/FAIL per assertion and a closing 'passed: N   failed: M' line; exits 1 on any failure.
# -Script runs a mutated copy, to prove the assertions can fail.
param([string]$Script)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
if (-not $Script) { $Script = Join-Path $RepoRoot 'Frameworks/Intune-Compliance-Baseline/Scripts/Deploy-ICBaseline.ps1' }
$Fixtures = Join-Path $PSScriptRoot 'Fixtures'
$Live = Join-Path $Fixtures 'Live'

$Beta = 'https://graph.microsoft.com/beta'
$V1 = 'https://graph.microsoft.com/v1.0'
$ClassicUri = "$Beta/deviceManagement/deviceCompliancePolicies"
$CatalogUri = "$Beta/deviceManagement/compliancePolicies"
$Zero = '00000000-0000-0000-0000-000000000000'
$WinName = 'ZZ-ICB-TEST-WIN-DELETE'
$LinName = 'ZZ-ICB-TEST-LIN-DELETE'
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) "icb-deploy-harness-$PID"

$script:Passed = 0; $script:Failed = 0
function Assert-True($Name, $Condition) {
    if ($Condition) { $script:Passed++; "PASS  $Name" } else { $script:Failed++; "FAIL  $Name" }
}

#region Fake Intune ------------------------------------------------------------------------------

function Read-Live($Name) { Get-Content (Join-Path $Live $Name) -Raw | ConvertFrom-Json -AsHashtable }
function ToJson($o) { ConvertTo-Json -InputObject $o -Depth 40 -Compress }
function New-Id { [guid]::NewGuid().ToString() }

function Reset-Fake {
    $global:Fake = [pscustomobject]@{
        Context          = [pscustomobject]@{ Account = ''; TenantId = '76b87c33-6178-4ff9-94a7-164792c8e4c6'; Scopes = @('DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All', 'User.Read') }
        Groups           = @{ 'ICB-Persona-CorpWindows' = @('grp-win'); 'ICB-Persona-CorpLinux' = @('grp-lin') }
        Templates        = @(@{ id = 'tpl-1'; displayName = 'ICB - Device Noncompliant' })   # live casing
        Settings         = Read-Live 'tenant-settings.json'
        SettingsStatus   = 200
        Classic          = [ordered]@{}
        Catalog          = [ordered]@{}
        PageSize         = 100
        Calls            = [System.Collections.Generic.List[object]]::new()
        Sleeps           = [System.Collections.Generic.List[int]]::new()
        Throttle         = @{}        # "METHOD uri" -> number of 429s to return first
        CatalogIgnoresSet = $false    # simulate setScheduledActions not taking effect
        ClassicDropOnCreate = $null   # property silently dropped on classic create
    }
}

function Add-ClassicPolicy {
    param([string]$Name, [hashtable]$Props = @{}, [object[]]$Actions = @(), [string[]]$Groups = @(), [string]$Type = '#microsoft.graph.windows10CompliancePolicy')
    $id = New-Id
    $p = [ordered]@{ '@odata.type' = $Type; displayName = $Name }
    foreach ($k in $Props.Keys) { $p[$k] = $Props[$k] }
    $global:Fake.Classic[$id] = [pscustomobject]@{ Props = $p; Actions = @($Actions | ForEach-Object { New-Action $_ }); Groups = [System.Collections.Generic.List[string]]$Groups }
    return $id
}
function Add-CatalogPolicy {
    param([string]$Name, [object[]]$Settings = @(), [object[]]$Actions = @(), [string[]]$Groups = @())
    $id = New-Id
    $global:Fake.Catalog[$id] = [pscustomobject]@{ Props = [ordered]@{ name = $Name; platforms = 'linux'; technologies = 'linuxMdm' }; Settings = @($Settings); Actions = @($Actions | ForEach-Object { New-Action $_ }); Groups = [System.Collections.Generic.List[string]]$Groups }
    return $id
}
function New-Action($a) {
    # Index access: strict mode rejects dot-access to a key a hashtable does not have.
    $template = [string]$a['notificationTemplateId']
    [ordered]@{ id = New-Id; gracePeriodHours = [int]$a['gracePeriodHours']; actionType = [string]$a['actionType']
        notificationTemplateId = $(if ($template) { $template } else { $Zero }); notificationMessageCCList = @() }
}
function Get-ActionKeys($actions) { (@($actions | ForEach-Object { '{0}@{1}' -f $_['actionType'], $_['gracePeriodHours'] }) | Sort-Object) -join ',' }

function Add-NullRefs($instance) {
    # Live Settings Catalog read-backs add null template references at every level.
    $copy = [ordered]@{}
    foreach ($k in $instance.Keys) { $copy[$k] = $instance[$k] }
    $copy['settingInstanceTemplateReference'] = $null
    $copy['auditRuleInformation'] = $null
    foreach ($vk in 'choiceSettingValue', 'simpleSettingValue') {
        if ($copy.Contains($vk) -and $copy[$vk]) {
            $v = [ordered]@{}; foreach ($k in $copy[$vk].Keys) { $v[$k] = $copy[$vk][$k] }; $v['settingValueTemplateReference'] = $null; $copy[$vk] = $v
        }
    }
    return $copy
}

function Get-Page($items, $baseUri, $skip) {
    $skip = [int]$skip
    $page = @($items | Select-Object -Skip $skip -First $global:Fake.PageSize)
    $r = [ordered]@{ value = $page }
    if ($skip + $global:Fake.PageSize -lt @($items).Count) { $r['@odata.nextLink'] = "$baseUri&`$skiptoken=$($skip + $global:Fake.PageSize)" }
    return $r
}

function Get-ClassicReadback($id, [switch]$Create) {
    $s = $global:Fake.Classic[$id]
    $base = if ($Create) { Read-Live 'classic-create.json' } else { Read-Live 'classic-readback.json' }
    $r = [ordered]@{}
    foreach ($k in $base.Keys) { if ($k -notlike 'scheduledActionsForRule*') { $r[$k] = $base[$k] } }
    foreach ($k in $s.Props.Keys) { $r[$k] = $s.Props[$k] }
    $r['id'] = $id
    if (-not $Create) {
        $r['scheduledActionsForRule'] = @([ordered]@{ id = $id; ruleName = $null; scheduledActionConfigurations = @($s.Actions) })
    }
    return $r
}

function Invoke-Fake {
    param([string]$Method, [string]$Uri, $Body)
    $F = $global:Fake
    $resp = { param($status, $obj) [pscustomobject]@{ Status = $status; Body = $(if ($null -eq $obj) { '' } else { ToJson $obj }) } }
    $err = { param($status, $msg) [pscustomobject]@{ Status = $status; Body = (ToJson @{ error = @{ code = 'Error'; message = $msg } }) } }

    # Throttling, keyed on method and URI.
    $tk = "$Method $Uri"
    if ($F.Throttle.ContainsKey($tk) -and $F.Throttle[$tk] -gt 0) {
        $F.Throttle[$tk]--
        return [pscustomobject]@{ Status = 429; Body = (ToJson @{ error = @{ code = 'TooManyRequests'; message = 'Too many requests' } }); Headers = @{ 'Retry-After' = @('3') } }
    }

    if ($Method -eq 'GET' -and $Uri -match "^$([regex]::Escape($V1))/groups\?\`$filter=displayName eq '(.+)'&") {
        $name = $Matches[1] -replace "''", "'"
        $ids = if ($F.Groups.ContainsKey($name)) { @($F.Groups[$name]) } else { @() }
        return (& $resp 200 @{ value = @($ids | ForEach-Object { @{ id = $_; displayName = $name } }) })
    }
    if ($Method -eq 'GET' -and $Uri -eq "$Beta/deviceManagement/notificationMessageTemplates") { return (& $resp 200 @{ value = @($F.Templates) }) }
    if ($Method -eq 'GET' -and $Uri -eq "$Beta/deviceManagement/settings") {
        if ($F.SettingsStatus -ne 200) { return (& $err $F.SettingsStatus 'Insufficient privileges') }
        return (& $resp 200 $F.Settings)
    }

    # Lists, with paging through $skiptoken.
    if ($Method -eq 'GET' -and $Uri -match "^$([regex]::Escape($ClassicUri))\?\`$select=id,displayName(&\`$skiptoken=(\d+))?$") {
        $items = @($F.Classic.Keys | ForEach-Object { [ordered]@{ id = $_; displayName = $F.Classic[$_].Props.displayName } })
        return (& $resp 200 (Get-Page $items "$ClassicUri`?`$select=id,displayName" $(if ($Matches[2]) { $Matches[2] } else { 0 })))
    }
    if ($Method -eq 'GET' -and $Uri -match "^$([regex]::Escape($CatalogUri))\?\`$select=id,name(&\`$skiptoken=(\d+))?$") {
        $items = @($F.Catalog.Keys | ForEach-Object { [ordered]@{ id = $_; name = $F.Catalog[$_].Props.name } })
        return (& $resp 200 (Get-Page $items "$CatalogUri`?`$select=id,name" $(if ($Matches[2]) { $Matches[2] } else { 0 })))
    }

    # --- Classic API ---
    if ($Method -eq 'POST' -and $Uri -eq $ClassicUri) {
        $id = New-Id
        $props = [ordered]@{}
        foreach ($k in $Body.Keys) { if ($k -notin 'scheduledActionsForRule', 'assignments') { $props[$k] = $Body[$k] } }
        if ($F.ClassicDropOnCreate) { $props.Remove($F.ClassicDropOnCreate) }
        $actions = @($Body['scheduledActionsForRule'][0]['scheduledActionConfigurations'] | ForEach-Object { New-Action $_ })
        $F.Classic[$id] = [pscustomobject]@{ Props = $props; Actions = $actions; Groups = [System.Collections.Generic.List[string]]::new() }
        return (& $resp 201 (Get-ClassicReadback $id -Create))
    }
    if ($Uri -match "^$([regex]::Escape($ClassicUri))/([^/?]+)(.*)$") {
        $id = $Matches[1]; $rest = $Matches[2]
        if (-not $F.Classic.Contains($id)) { return (& $err 404 'ResourceNotFound') }
        $s = $F.Classic[$id]
        if ($Method -eq 'GET' -and $rest -eq "?`$expand=scheduledActionsForRule(`$expand=scheduledActionConfigurations)") { return (& $resp 200 (Get-ClassicReadback $id)) }
        if ($Method -eq 'GET' -and $rest -eq '/assignments') {
            return (& $resp 200 @{ value = @($s.Groups | ForEach-Object { [ordered]@{ id = "$($id)_$_"; source = 'direct'; sourceId = $id; target = [ordered]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; deviceAndAppManagementAssignmentFilterId = $null; deviceAndAppManagementAssignmentFilterType = 'none'; groupId = $_ } } }) })
        }
        if ($Method -eq 'POST' -and $rest -eq '/assign') {
            $s.Groups = [System.Collections.Generic.List[string]]@($Body['assignments'] | ForEach-Object { [string]$_['target']['groupId'] })
            return (& $resp 200 $null)
        }
        if ($Method -eq 'POST' -and $rest -eq '/scheduleActionsForRules') {
            $s.Actions = @($Body['deviceComplianceScheduledActionForRules'][0]['scheduledActionConfigurations'] | ForEach-Object { New-Action $_ })
            return (& $resp 200 $null)
        }
        if ($Method -eq 'PATCH' -and $rest -eq '') {
            foreach ($k in $Body.Keys) { $s.Props[$k] = $Body[$k] }
            return (& $resp 204 $null)
        }
    }

    # --- Settings Catalog API ---
    if ($Method -eq 'POST' -and $Uri -eq $CatalogUri) {
        $id = New-Id
        $props = [ordered]@{}
        foreach ($k in $Body.Keys) { if ($k -notin 'settings', 'scheduledActionsForRule', 'assignments') { $props[$k] = $Body[$k] } }
        $settings = @($Body['settings'] | ForEach-Object { $_['settingInstance'] })
        # Live: an inline schedule is accepted and replaced by Intune's default.
        $F.Catalog[$id] = [pscustomobject]@{ Props = $props; Settings = $settings; Actions = @(New-Action @{ actionType = 'block'; gracePeriodHours = 0 }); Groups = [System.Collections.Generic.List[string]]::new() }
        $created = Read-Live 'catalog-create.json'; foreach ($k in $props.Keys) { $created[$k] = $props[$k] }; $created['id'] = $id
        return (& $resp 201 $created)
    }
    if ($Uri -match "^$([regex]::Escape($CatalogUri))/([^/?]+)(.*)$") {
        $id = $Matches[1]; $rest = $Matches[2]
        if (-not $F.Catalog.Contains($id)) { return (& $err 400 'An error has occurred') }   # live: 400, not 404
        $s = $F.Catalog[$id]
        if ($Method -eq 'GET' -and $rest -eq '') { $r = Read-Live 'catalog-readback.json'; foreach ($k in $s.Props.Keys) { $r[$k] = $s.Props[$k] }; $r['id'] = $id; return (& $resp 200 $r) }
        if ($Method -eq 'GET' -and $rest -eq '/settings') {
            $i = 0
            return (& $resp 200 @{ '@odata.count' = @($s.Settings).Count; value = @($s.Settings | ForEach-Object { [ordered]@{ id = [string]($i++); settingInstance = (Add-NullRefs $_) } }) })
        }
        if ($Method -eq 'GET' -and $rest -eq "/scheduledActionsForRule?`$expand=scheduledActionConfigurations") {
            return (& $resp 200 @{ value = @([ordered]@{ id = $id; ruleName = $null; scheduledActionConfigurations = @($s.Actions) }) })
        }
        if ($Method -eq 'GET' -and $rest -eq '/assignments') {
            return (& $resp 200 @{ value = @($s.Groups | ForEach-Object { [ordered]@{ id = "$($id)_$_"; source = 'direct'; sourceId = $id; target = [ordered]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; deviceAndAppManagementAssignmentFilterId = $null; deviceAndAppManagementAssignmentFilterType = 'none'; groupId = $_ } } }) })
        }
        if ($Method -eq 'POST' -and $rest -eq '/assign') {
            $s.Groups = [System.Collections.Generic.List[string]]@($Body['assignments'] | ForEach-Object { [string]$_['target']['groupId'] })
            return (& $resp 200 $null)
        }
        if ($Method -eq 'POST' -and $rest -eq '/setScheduledActions') {
            if (-not $F.CatalogIgnoresSet) { $s.Actions = @($Body['scheduledActions'][0]['scheduledActionConfigurations'] | ForEach-Object { New-Action $_ }) }
            return (& $resp 200 $null)
        }
    }
    return (& $err 400 "No OData route exists for $Method $Uri (fake)")
}

function global:Get-MgContext { $global:Fake.Context }
function global:Start-Sleep { param([int]$Seconds) $global:Fake.Sleeps.Add($Seconds) }
function global:Invoke-MgGraphRequest {
    param([string]$Method, [string]$Uri, [string]$OutputType, [switch]$SkipHttpErrorCheck,
          [string]$StatusCodeVariable, [string]$ResponseHeadersVariable, [string]$Body, [string]$ContentType)
    $parsed = if ($Body) { $Body | ConvertFrom-Json -AsHashtable } else { $null }
    $global:Fake.Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $parsed; Raw = $Body })
    $r = Invoke-Fake -Method $Method -Uri $Uri -Body $parsed
    $headers = if ($r.PSObject.Properties['Headers']) { $r.Headers } else { @{} }
    Set-Variable -Name $StatusCodeVariable -Value $r.Status -Scope 1 -WhatIf:$false
    Set-Variable -Name $ResponseHeadersVariable -Value $headers -Scope 1 -WhatIf:$false
    return $r.Body
}

#endregion

#region Runner ------------------------------------------------------------------------------------

$script:RunCount = 0
function Invoke-Deploy {
    param([hashtable]$Params = @{}, [string]$PolicyPath = $Fixtures)
    $script:RunCount++
    $p = @{ PolicyPath = $PolicyPath } + $Params
    $global:LASTEXITCODE = 0
    $global:Fake.Calls.Clear(); $global:Fake.Sleeps.Clear()
    $out = & $Script @p *>&1
    [pscustomobject]@{ Exit = $global:LASTEXITCODE; Text = (($out | ForEach-Object { "$_" }) -join "`n") }
}
function Calls($Method, $Pattern) { , @($global:Fake.Calls | Where-Object { $_.Method -eq $Method -and $_.Uri -like $Pattern }) }
function Writes { , @($global:Fake.Calls | Where-Object { $_.Method -ne 'GET' }) }
function ClassicByName($n) { $id = @($global:Fake.Classic.Keys | Where-Object { $global:Fake.Classic[$_].Props.displayName -eq $n }); if ($id.Count -eq 1) { $global:Fake.Classic[$id[0]] } }
function CatalogByName($n) { $id = @($global:Fake.Catalog.Keys | Where-Object { $global:Fake.Catalog[$_].Props.name -eq $n }); if ($id.Count -eq 1) { $global:Fake.Catalog[$id[0]] } }
function New-TempPolicies([hashtable]$Files) {
    $dir = Join-Path $TempRoot ("p{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    foreach ($k in $Files.Keys) { Set-Content -Path (Join-Path $dir $k) -Value $Files[$k] }
    return $dir
}
$WinJson = Get-Content (Join-Path $Fixtures "$WinName.json") -Raw
$LinJson = Get-Content (Join-Path $Fixtures "$LinName.json") -Raw

#endregion

New-Item -ItemType Directory -Path $TempRoot -Force | Out-Null

# --- 1. Observation, fresh tenant --------------------------------------------------------------------
Reset-Fake
$r = Invoke-Deploy
Assert-True '1: exits 0' ($r.Exit -eq 0)
$wc = (Calls POST $ClassicUri)
Assert-True '1: classic created once' ($wc.Count -eq 1)
$inline = @($wc[0].Body['scheduledActionsForRule'][0]['scheduledActionConfigurations'])
Assert-True '1: classic inline schedule is block@8760 only' ($inline.Count -eq 1 -and $inline[0]['actionType'] -eq 'block' -and $inline[0]['gracePeriodHours'] -eq 8760 -and $inline[0]['notificationTemplateId'] -eq $Zero)
Assert-True '1: classic create omits assignments' (-not $wc[0].Body.Contains('assignments'))
Assert-True '1: classic create keeps @odata.type first' ($wc[0].Raw.StartsWith('{"@odata.type":"#microsoft.graph.windows10CompliancePolicy"'))
$lc = (Calls POST $CatalogUri)
Assert-True '1: catalog create carries no schedule and no assignments' ($lc.Count -eq 1 -and -not $lc[0].Body.Contains('scheduledActionsForRule') -and -not $lc[0].Body.Contains('assignments'))
$set = (Calls POST "$CatalogUri/*/setScheduledActions")
Assert-True '1: catalog schedule set after create, block@8760' ($set.Count -eq 1 -and @($set[0].Body['scheduledActions'][0]['scheduledActionConfigurations']).Count -eq 1 -and $set[0].Body['scheduledActions'][0]['scheduledActionConfigurations'][0]['gracePeriodHours'] -eq 8760)
Assert-True '1: tenant ends with WIN at block@8760' ((Get-ActionKeys (ClassicByName $WinName).Actions) -eq 'block@8760')
Assert-True '1: tenant ends with LIN at block@8760, not the default 0' ((Get-ActionKeys (CatalogByName $LinName).Actions) -eq 'block@8760')
Assert-True '1: WIN assigned to CorpWindows' (@((ClassicByName $WinName).Groups) -join ',' -eq 'grp-win')
Assert-True '1: LIN assigned to CorpLinux' (@((CatalogByName $LinName).Groups) -join ',' -eq 'grp-lin')
Assert-True '1: no notification template lookup in observation' ((Calls GET "$Beta/deviceManagement/notificationMessageTemplates").Count -eq 0)
Assert-True '1: both read back after writing' ((Calls GET "$ClassicUri/*`?`$expand=*").Count -eq 1 -and (Calls GET "$CatalogUri/*/settings").Count -eq 1)
Assert-True '1: reports Created twice' (([regex]::Matches($r.Text, ': Created')).Count -eq 2)
Assert-True '1: warns about the 30-day validity period' ($r.Text -match 'validity period.+30 days')
Assert-True '1: no secureByDefault warning (tenant has it on)' ($r.Text -notmatch 'no compliance policy assigned as')

# --- 2. Re-run unchanged -------------------------------------------------------------------------------
$r = Invoke-Deploy
Assert-True '2: re-run exits 0' ($r.Exit -eq 0)
Assert-True '2: re-run writes nothing' ((Writes).Count -eq 0)
Assert-True '2: both Unchanged' (([regex]::Matches($r.Text, ': Unchanged')).Count -eq 2)

# --- 3. Promote with -Enforce ----------------------------------------------------------------------
$r = Invoke-Deploy -Params @{ Enforce = $true; Force = $true }
Assert-True '3: enforce exits 0' ($r.Exit -eq 0)
Assert-True '3: no creates on promotion' ((Calls POST $ClassicUri).Count -eq 0 -and (Calls POST $CatalogUri).Count -eq 0)
$sa = (Calls POST "$ClassicUri/*/scheduleActionsForRules")
$cfg = if ($sa.Count -gt 0) { @($sa[0].Body['deviceComplianceScheduledActionForRules'][0]['scheduledActionConfigurations']) } else { @() }
Assert-True '3: classic schedule replaced with email@0 + block@168' ($sa.Count -eq 1 -and (Get-ActionKeys $cfg) -eq 'block@168,notification@0')
Assert-True '3: email uses the template, matched case-insensitively' (@($cfg | Where-Object { $_['actionType'] -eq 'notification' } | Where-Object { $_['notificationTemplateId'] -eq 'tpl-1' }).Count -eq 1)
Assert-True '3: tenant WIN now designed schedule' ((Get-ActionKeys (ClassicByName $WinName).Actions) -eq 'block@168,notification@0')
Assert-True '3: tenant LIN now designed schedule' ((Get-ActionKeys (CatalogByName $LinName).Actions) -eq 'block@168,notification@0')
Assert-True '3: both Updated' (([regex]::Matches($r.Text, ': Updated')).Count -eq 2)
$r = Invoke-Deploy -Params @{ Enforce = $true; Force = $true }
Assert-True '3: enforce re-run writes nothing' ((Writes).Count -eq 0)
$r = Invoke-Deploy
Assert-True '3: back to observation replaces the schedule' ((Get-ActionKeys (ClassicByName $WinName).Actions) -eq 'block@8760' -and (Get-ActionKeys (CatalogByName $LinName).Actions) -eq 'block@8760')

# --- 4. Enforce on a fresh tenant ------------------------------------------------------------------
Reset-Fake
$r = Invoke-Deploy -Params @{ Enforce = $true; Force = $true }
$inline = @((Calls POST $ClassicUri)[0].Body['scheduledActionsForRule'][0]['scheduledActionConfigurations'])
Assert-True '4: classic created with the designed schedule inline' ((Get-ActionKeys $inline) -eq 'block@168,notification@0')
Assert-True '4: catalog still scheduled separately' ((Calls POST "$CatalogUri/*/setScheduledActions").Count -eq 1)
Assert-True '4: exits 0' ($r.Exit -eq 0)

# --- 5. A schedule that does not land is caught by the read-back --------------------------------------
Reset-Fake
$global:Fake.CatalogIgnoresSet = $true
$r = Invoke-Deploy
Assert-True '5: exits 1' ($r.Exit -eq 1)
Assert-True '5: LIN reported as a read-back schedule mismatch' ($r.Text -match "$LinName.*Read-back mismatch.*schedule" -or $r.Text -match 'ZZ-ICB-TEST-LIN-DELETE: Read-back mismatch after created, schedule set, assigned: schedule')
Assert-True '5: WIN still deployed' ($null -ne (ClassicByName $WinName))

# --- 6. Classic drift ------------------------------------------------------------------------------------
Reset-Fake
[void](Invoke-Deploy)
(ClassicByName $WinName).Props['rtpEnabled'] = $false
$r = Invoke-Deploy
Assert-True '6: drift exits 0' ($r.Exit -eq 0)
Assert-True '6: drift reported with the setting' ($r.Text -match 'Drift' -and $r.Text -match 'rtpEnabled')
Assert-True '6: drift not overwritten by default' ((Calls PATCH '*').Count -eq 0 -and (ClassicByName $WinName).Props['rtpEnabled'] -eq $false)
$r = Invoke-Deploy -Params @{ UpdateExisting = $true }
$patch = (Calls PATCH "$ClassicUri/*")
Assert-True '6: -UpdateExisting PATCHes once' ($patch.Count -eq 1)
Assert-True '6: PATCH carries @odata.type and the template value' ($patch.Count -eq 1 -and $patch[0].Body['@odata.type'] -eq '#microsoft.graph.windows10CompliancePolicy' -and $patch[0].Body['rtpEnabled'] -eq $true)
Assert-True '6: PATCH leaves out the schedule, assignments and name' ($patch.Count -eq 1 -and -not $patch[0].Body.Contains('scheduledActionsForRule') -and -not $patch[0].Body.Contains('assignments') -and -not $patch[0].Body.Contains('displayName'))
Assert-True '6: setting restored and Updated' ((ClassicByName $WinName).Props['rtpEnabled'] -eq $true -and $r.Text -match "${WinName}: Updated")

# --- 7. Settings Catalog drift is reported, not overwritten ----------------------------------------------
(CatalogByName $LinName).Settings[1]['simpleSettingValue']['value'] = 8
$r = Invoke-Deploy -Params @{ UpdateExisting = $true }
Assert-True '7: catalog drift reported' ($r.Text -match "${LinName}: Drift")
Assert-True '7: says catalog policies are not updated in place' ($r.Text -match 'not updated in place')
Assert-True '7: no write to the catalog policy' ((Writes).Count -eq 0)

# --- 8. Missing assignment is added, keeping existing ones ------------------------------------------------
Reset-Fake
[void](Add-ClassicPolicy -Name $WinName -Props @{ roleScopeTagIds = @('0'); description = 'x'; activeFirewallRequired = $true; rtpEnabled = $true; passwordMinimumLength = 6 } -Actions @(@{ actionType = 'block'; gracePeriodHours = 8760 }) -Groups @('grp-other'))
$r = Invoke-Deploy -Params @{ Template = @('ZZ-ICB-TEST-WIN*') }
$assign = (Calls POST "$ClassicUri/*/assign")
$sent = if ($assign.Count -gt 0) { @($assign[0].Body['assignments'] | ForEach-Object { $_['target']['groupId'] }) } else { @() }
Assert-True '8: assign sends existing plus missing group' ($assign.Count -eq 1 -and ($sent -join ',') -eq 'grp-other,grp-win')
Assert-True '8: tenant keeps both assignments' ((@((ClassicByName $WinName).Groups) | Sort-Object) -join ',' -eq 'grp-other,grp-win')
Assert-True '8: existing assignment sent without its read-only fields' ($assign.Count -eq 1 -and -not $assign[0].Body['assignments'][0].Contains('id') -and -not $assign[0].Body['assignments'][0].Contains('source'))
Assert-True '8: no schedule change when schedule already matches' ((Calls POST "$ClassicUri/*/scheduleActionsForRules").Count -eq 0)

# --- 9. Missing group ---------------------------------------------------------------------------------
Reset-Fake
$global:Fake.Groups.Remove('ICB-Persona-CorpLinux')
$r = Invoke-Deploy
Assert-True '9: exits 1' ($r.Exit -eq 1)
Assert-True '9: names the missing group' ($r.Text -match "Group not found in tenant: 'ICB-Persona-CorpLinux'")
Assert-True '9: other template still deployed' ($null -ne (ClassicByName $WinName))
Reset-Fake
$global:Fake.Groups.Remove('ICB-Persona-CorpLinux')
$r = Invoke-Deploy -Params @{ StopOnError = $true }
Assert-True '9: -StopOnError stops before the next template' ($r.Exit -eq 1 -and $null -eq (ClassicByName $WinName))
Reset-Fake
$global:Fake.Groups['ICB-Persona-CorpWindows'] = @('g1', 'g2')
$r = Invoke-Deploy
Assert-True '9: ambiguous group name refused' ($r.Text -match "Multiple groups are named 'ICB-Persona-CorpWindows'" -and $null -eq (ClassicByName $WinName))

# --- 10. Notification template ----------------------------------------------------------------------
Reset-Fake
$global:Fake.Templates = @()
$r = Invoke-Deploy
Assert-True '10: observation needs no template' ($r.Exit -eq 0 -and $null -ne (ClassicByName $WinName))
Reset-Fake
$global:Fake.Templates = @()
$r = Invoke-Deploy -Params @{ Enforce = $true; Force = $true }
Assert-True '10: enforce without a template fails clearly' ($r.Exit -eq 1 -and $r.Text -match 'Notification message template not found' -and $null -eq (ClassicByName $WinName))

# --- 11. Template validation --------------------------------------------------------------------------
Reset-Fake
$dir = New-TempPolicies @{ 'A.json' = ($WinJson -replace 'ZZ-ICB-TEST-WIN-DELETE', 'ZZ-A' -replace 'REPLACE_WITH_ICB_PERSONA_CORPWINDOWS', 'REPLACE_WITH_ICB_PERSONA_NOSUCH') }
$r = Invoke-Deploy -PolicyPath $dir
Assert-True '11: unknown persona placeholder refused' ($r.Exit -eq 1 -and $r.Text -match 'Unknown persona placeholder')
$two = $WinJson -replace '"actionType": "notification"', '"actionType": "block"'
$dir = New-TempPolicies @{ 'B.json' = $two }
$r = Invoke-Deploy -PolicyPath $dir
Assert-True '11: two block actions refused' ($r.Exit -eq 1 -and $r.Text -match "exactly one 'block'")
$dir = New-TempPolicies @{ 'C.json' = ($WinJson -replace '"rtpEnabled": true', '"rtpEnabled": "REPLACE_WITH_SOMETHING"') }
$r = Invoke-Deploy -PolicyPath $dir
Assert-True '11: unresolved placeholder refused' ($r.Exit -eq 1 -and $r.Text -match 'Unresolved placeholder')
$retire = $WinJson -replace '"actionType": "notification",\s*"gracePeriodHours": 0', '"actionType": "retire", "gracePeriodHours": 720'
$dir = New-TempPolicies @{ 'D.json' = $retire }
$r = Invoke-Deploy -PolicyPath $dir
Assert-True '11: observation drops a retire action' ((Get-ActionKeys (ClassicByName $WinName).Actions) -eq 'block@8760')
Reset-Fake
$r = Invoke-Deploy -PolicyPath $dir -Params @{ Enforce = $true; Force = $true }
Assert-True '11: enforce keeps the retire action' ((Get-ActionKeys (ClassicByName $WinName).Actions) -eq 'block@168,retire@720')

# --- 12. Tenant prerequisites ---------------------------------------------------------------------
Reset-Fake
$global:Fake.Settings['secureByDefault'] = $false
$global:Fake.Settings['deviceComplianceCheckinThresholdDays'] = 7
$r = Invoke-Deploy
Assert-True '12: warns when no-policy devices count as compliant' ($r.Text -match "no compliance policy assigned as' is Compliant")
Assert-True '12: no validity warning at 7 days' ($r.Text -notmatch 'validity period')
Reset-Fake
$global:Fake.SettingsStatus = 403
$r = Invoke-Deploy
Assert-True '12: unreadable settings warn and deployment continues' ($r.Text -match 'Could not read the tenant-wide compliance settings' -and $r.Exit -eq 0 -and $null -ne (ClassicByName $WinName))

# --- 13. Session checks -------------------------------------------------------------------------------
Reset-Fake
$global:Fake.Context.Scopes = @('DeviceManagementConfiguration.Read.All', 'Group.Read.All')
$r = Invoke-Deploy
Assert-True '13: missing ReadWrite scope refused before any call' ($r.Exit -eq 1 -and $r.Text -match 'lacks DeviceManagementConfiguration.ReadWrite.All' -and $global:Fake.Calls.Count -eq 0)

# --- 14. -WhatIf -----------------------------------------------------------------------------------
Reset-Fake
$r = Invoke-Deploy -Params @{ WhatIf = $true }
Assert-True '14: -WhatIf writes nothing' ((Writes).Count -eq 0 -and $global:Fake.Classic.Count -eq 0)
Assert-True '14: -WhatIf reports the plan' (([regex]::Matches($r.Text, 'WhatIf')).Count -ge 2 -and $r.Text -match 'create, assign')
[void](Invoke-Deploy)
$r = Invoke-Deploy -Params @{ WhatIf = $true; Enforce = $true }
Assert-True '14: -WhatIf -Enforce plans the promotion, writes nothing' ((Writes).Count -eq 0 -and $r.Text -match 'set enforce schedule')

# --- 15. Throttling ------------------------------------------------------------------------------
Reset-Fake
$global:Fake.Throttle["POST $ClassicUri"] = 2
$r = Invoke-Deploy
Assert-True '15: retries after 429 honouring Retry-After' (($global:Fake.Sleeps -join ',') -eq '3,3' -and $r.Exit -eq 0)
Assert-True '15: creates exactly one policy' ($global:Fake.Classic.Count -eq 1)
Reset-Fake
$global:Fake.Throttle["POST $ClassicUri"] = 9
$r = Invoke-Deploy -Params @{ MaxRetries = 1 }
Assert-True '15: gives up after -MaxRetries' ($r.Exit -eq 1 -and $r.Text -match 'HTTP 429' -and $global:Fake.Classic.Count -eq 0)

# --- 16. Paging ---------------------------------------------------------------------------------
Reset-Fake
[void](Add-ClassicPolicy -Name 'Other A'); [void](Add-ClassicPolicy -Name 'Other B')
[void](Invoke-Deploy)
$global:Fake.PageSize = 1
$r = Invoke-Deploy
Assert-True '16: finds the policy on page 3, creates nothing' ((Calls POST $ClassicUri).Count -eq 0 -and $global:Fake.Classic.Count -eq 3 -and $r.Text -match "${WinName}: Unchanged")

# --- 17. Name collisions -------------------------------------------------------------------------
Reset-Fake
[void](Add-ClassicPolicy -Name $WinName); [void](Add-ClassicPolicy -Name $WinName)
$r = Invoke-Deploy -Params @{ Template = @('ZZ-ICB-TEST-WIN*') }
Assert-True '17: duplicate names refused' ($r.Exit -eq 1 -and $r.Text -match '2 policies in the tenant are named')
Reset-Fake
[void](Add-ClassicPolicy -Name $WinName -Type '#microsoft.graph.macOSCompliancePolicy')
$r = Invoke-Deploy -Params @{ Template = @('ZZ-ICB-TEST-WIN*') }
Assert-True '17: same name, other platform refused' ($r.Exit -eq 1 -and $r.Text -match 'is a #microsoft.graph.macOSCompliancePolicy' -and (Writes).Count -eq 0)

# --- 18. -Template filter ----------------------------------------------------------------------
Reset-Fake
$r = Invoke-Deploy -Params @{ Template = @('ZZ-ICB-TEST-LIN*') }
Assert-True '18: -Template deploys only the match' ($global:Fake.Classic.Count -eq 0 -and $global:Fake.Catalog.Count -eq 1)

# --- 19. A setting dropped on create is caught -------------------------------------------------
Reset-Fake
$global:Fake.ClassicDropOnCreate = 'passwordMinimumLength'
$r = Invoke-Deploy
Assert-True '19: dropped setting fails the template' ($r.Exit -eq 1 -and $r.Text -match 'Read-back mismatch.*passwordMinimumLength')

# --- 20. Settings Catalog read-back with null template references matches ---------------------
Reset-Fake
[void](Invoke-Deploy)
$r = Invoke-Deploy
Assert-True '20: live-shaped catalog read-back is not drift' ($r.Text -match "${LinName}: Unchanged")

# --- 21. A type mismatch in a template is caught ---------------------------------------------
Reset-Fake
$dir = New-TempPolicies @{ 'E.json' = ($WinJson -replace '"rtpEnabled": true', '"rtpEnabled": 1') }
$global:Fake.ClassicDropOnCreate = $null
[void](Invoke-Deploy -PolicyPath $dir)
(ClassicByName $WinName).Props['rtpEnabled'] = $true   # Graph stores a Boolean
$r = Invoke-Deploy -PolicyPath $dir
Assert-True '21: 1 versus true is reported, not silently equal' ($r.Text -match 'rtpEnabled \(template 1, tenant true\)')

Remove-Item -Recurse -Force $TempRoot -ErrorAction SilentlyContinue
"passed: $script:Passed   failed: $script:Failed"
if ($script:Failed -gt 0) { exit 1 }
