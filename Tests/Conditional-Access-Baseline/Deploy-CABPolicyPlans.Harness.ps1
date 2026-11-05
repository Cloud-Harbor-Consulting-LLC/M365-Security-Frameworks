#Requires -Version 7.0
# Regression harness for Deploy-CABPolicyPlans.ps1 (Conditional Access policy plans preview).
#
# Runs the shipped script, unmodified, against a stateful fake of the Graph calls it makes (groups, authentication
# strengths, Terms of Use agreements, and the plans list, create and read-back), so it needs no tenant. The fake
# stores what is posted and returns it on read-back, and can be told to change it on the way in. Prints PASS/FAIL
# per assertion and a closing 'passed: N   failed: M' line; exits 1 on any failure.

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$preview = Join-Path $RepoRoot 'Frameworks' 'Conditional-Access-Baseline' 'Preview' 'Policy-Plans'
$deploy = Join-Path $preview 'Scripts' 'Deploy-CABPolicyPlans.ps1'
$export = Join-Path $preview 'Scripts' 'Export-CABPolicyPlans.ps1'

$script:Passed = 0
$script:Failed = 0
function Assert-Equal {
    param($Name, $Got, $Want)
    $ok = ("$Got" -eq "$Want")
    if ($ok) { $script:Passed++ } else { $script:Failed++ }
    "{0}  {1,-66} got={2,-12} want={3}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $Name, $Got, $Want
}

# The read-back comparison must flatten exactly as the exporter does.
$fnText = foreach ($path in $deploy, $export) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -eq 'ConvertTo-Flat' }, $true))[0].Extent.Text
}
Assert-Equal 'ConvertTo-Flat identical in deployer and exporter' ($fnText[0] -eq $fnText[1]) $true

# -- The fake ----------------------------------------------------------------------
function New-Tenant {
    $global:Fake = [pscustomobject]@{
        Context    = $null
        Groups     = @{ 'CA-Persona-EmergencyAccess' = 'bbbbbbbb-0000-4000-8000-000000000001'; 'CA-Persona-WorkloadIdentities' = 'bbbbbbbb-0000-4000-8000-000000000002'; 'CA-Persona-ServiceAccounts' = 'bbbbbbbb-0000-4000-8000-000000000003' }
        Strengths  = @{ 'AdminAuth' = 'bbbbbbbb-0000-4000-8000-000000000011' }
        Agreements = @{ 'Terms of Use for Guest Users' = 'bbbbbbbb-0000-4000-8000-000000000021' }
        Plans      = [ordered]@{}
        Posts      = [System.Collections.Generic.List[string]]::new()
        Tamper     = $null
        Calls      = [System.Collections.Generic.List[string]]::new()
    }
}
function global:Get-MgContext { $global:Fake.Context }
function global:Connect-MgGraph { param($TenantId, $Scopes, [switch]$NoWelcome) $global:Fake.Context = [pscustomobject]@{ TenantId = 'bbbbbbbb-9999-4000-8000-000000000000'; Account = 'admin@contoso.example'; Scopes = $Scopes } }
function global:Invoke-MgGraphRequest {
    param($Method, $Uri, $Body, $ContentType, $OutputType)
    $global:Fake.Calls.Add("$Method $Uri")
    $page = { param($items) [pscustomobject]@{ value = @($items) } }
    if ($Method -eq 'GET' -and $Uri -match "/groups\?\`$filter=displayName eq '(.+)'&") {
        $n = $Matches[1] -replace "''", "'"
        return & $page @(if ($global:Fake.Groups.ContainsKey($n)) { [pscustomobject]@{ id = $global:Fake.Groups[$n]; displayName = $n } })
    }
    if ($Method -eq 'GET' -and $Uri -like '*/authenticationStrength/policies') { return & $page @($global:Fake.Strengths.GetEnumerator() | ForEach-Object { [pscustomobject]@{ id = $_.Value; displayName = $_.Key } }) }
    if ($Method -eq 'GET' -and $Uri -like '*/termsOfUse/agreements') { return & $page @($global:Fake.Agreements.GetEnumerator() | ForEach-Object { [pscustomobject]@{ id = $_.Value; displayName = $_.Key } }) }
    if ($Method -eq 'GET' -and $Uri -match '/identity/conditionalAccess/plans$') { return & $page @($global:Fake.Plans.Values | ForEach-Object { $_.Plan }) }
    if ($Method -eq 'POST' -and $Uri -match '/identity/conditionalAccess/plans$') {
        $global:Fake.Posts.Add($Body)
        $b = $Body | ConvertFrom-Json -Depth 50
        $id = 'cccccccc-0000-4000-8000-{0:x12}' -f ($global:Fake.Plans.Count + 1)
        $n = 0
        $rules = @($b.rules | ForEach-Object { $n++; $r = $_ | ConvertTo-Json -Depth 50 | ConvertFrom-Json -Depth 50; $r | Add-Member id ('{0}-r{1}' -f $id, $n); $r })
        $plan = [pscustomobject]@{ id = $id; displayName = $b.displayName; description = $b.description; sharedConditions = $b.sharedConditions; version = 1 }
        if ($global:Fake.Tamper) { & $global:Fake.Tamper $plan $rules }
        $global:Fake.Plans[$id] = [pscustomobject]@{ Plan = $plan; Rules = $rules }
        return [pscustomobject]@{ id = $id; displayName = $b.displayName }
    }
    if ($Method -eq 'GET' -and $Uri -match '/plans/([^/]+)/rules$') { return & $page $global:Fake.Plans[$Matches[1]].Rules }
    if ($Method -eq 'GET' -and $Uri -match '/plans/([^/]+)$') { return $global:Fake.Plans[$Matches[1]].Plan }
    throw "Unexpected Graph call in the fake: $Method $Uri"
}
function Invoke-Deploy([hashtable]$Params) {
    $global:LASTEXITCODE = 0
    $err = $null
    # -WhatIf messages go to the host, not to a stream, so a transcript is the only way to capture them.
    $log = Join-Path ([IO.Path]::GetTempPath()) "cab-plans-harness-$PID.log"
    Start-Transcript -Path $log -Force | Out-Null
    try { & $deploy @Params | Out-Null } catch { $err = $_.Exception.Message }
    Stop-Transcript | Out-Null
    $out = Get-Content $log -Raw
    Remove-Item $log -Force
    [pscustomobject]@{ Out = $out; Error = $err; Exit = $LASTEXITCODE; Posts = $global:Fake.Posts.Count }
}
function Count([string]$Text, [string]$Pattern) { ([regex]::Matches($Text, $Pattern)).Count }

# -- WhatIf -------------------------------------------------------------------------
New-Tenant
$r = Invoke-Deploy @{ TenantId = 'contoso.example'; WhatIf = $true }
Assert-Equal 'WhatIf: nothing posted' $r.Posts 0
Assert-Equal 'WhatIf: 3 plans previewed' (Count $r.Out 'What if: Performing the operation "Create" on target "plan CAB-P') 3
Assert-Equal 'WhatIf: exit 0' $r.Exit 0
Assert-Equal 'WhatIf: placeholders still resolved' (Count $r.Out 'REPLACE_WITH_[A-Z_]+ -> ') 5

# -- Deploy all ----------------------------------------------------------------------
New-Tenant
$r = Invoke-Deploy @{ TenantId = 'contoso.example' }
Assert-Equal 'deploy: 3 plans posted' $r.Posts 3
Assert-Equal 'deploy: exit 0' $r.Exit 0
Assert-Equal 'deploy: 3 read-backs match' (Count $r.Out 'read-back matches') 3
$bodies = @($global:Fake.Posts | ForEach-Object { $_ | ConvertFrom-Json -Depth 50 })
Assert-Equal 'deploy: no placeholder left in any body' (Count ($global:Fake.Posts -join "`n") 'REPLACE_WITH_') 0
Assert-Equal 'deploy: 9 rules, all report-only' "$(@($bodies.rules).Count)|$(@($bodies.rules | Where-Object state -eq 'enabledForReportingButNotEnforced').Count)" '9|9'
Assert-Equal 'deploy: rules sent inline with each plan' (($bodies | ForEach-Object { @($_.rules).Count }) -join ',') '2,4,3'
$p6 = @($bodies | Where-Object displayName -eq 'CAB-P6-Guests')[0]
Assert-Equal 'deploy: P6 shares the emergency access group id' ($p6.sharedConditions.users.excludeGroups -join ',') 'bbbbbbbb-0000-4000-8000-000000000001'
Assert-Equal 'deploy: P6 SIG010 grants the resolved Terms of Use' (@($p6.rules | Where-Object displayName -like 'CA-SIG010*')[0].controls.grantControls.termsOfUse -join ',') 'bbbbbbbb-0000-4000-8000-000000000021'
$p1 = @($bodies | Where-Object displayName -eq 'CAB-P1-Admins-PrivilegedAccess')[0]
Assert-Equal 'deploy: P1 AUT003 uses the resolved AdminAuth strength' (@($p1.rules | Where-Object displayName -like 'CA-AUT003*')[0].controls.grantControls.authenticationStrength.id) 'bbbbbbbb-0000-4000-8000-000000000011'
Assert-Equal 'deploy: P1 keeps the 39 admin roles' (@($p1.sharedConditions.users.includeRoles).Count) 39
Assert-Equal 'deploy: no policy endpoint touched' (@($global:Fake.Calls | Where-Object { $_ -like '*conditionalAccess/policies*' }).Count) 0

# -- Re-run: existing plans are skipped ------------------------------------------------
$global:Fake.Posts.Clear()
$r = Invoke-Deploy @{ TenantId = 'contoso.example' }
Assert-Equal 're-run: nothing posted' $r.Posts 0
Assert-Equal 're-run: 3 skipped as existing' (Count $r.Out 'already exists; skipped') 3
Assert-Equal 're-run: exit 0' $r.Exit 0

# -- Prerequisites ---------------------------------------------------------------------
New-Tenant; $global:Fake.Groups.Remove('CA-Persona-EmergencyAccess')
$r = Invoke-Deploy @{ TenantId = 'contoso.example' }
Assert-Equal 'missing group: stops before any post' "$($r.Posts)|$([bool]($r.Error -like 'Group not found*CA-Persona-EmergencyAccess*'))" '0|True'
New-Tenant; $global:Fake.Agreements.Clear()
$r = Invoke-Deploy @{ TenantId = 'contoso.example'; Plan = 'CAB-P1-Admins-PrivilegedAccess' }
Assert-Equal 'no Terms of Use, P1 only: deploys (not needed)' "$($r.Posts)|$($r.Exit)" '1|0'
Assert-Equal 'no Terms of Use, P1 only: agreements never queried' (@($global:Fake.Calls | Where-Object { $_ -like '*termsOfUse*' }).Count) 0
New-Tenant; $global:Fake.Agreements.Clear()
$r = Invoke-Deploy @{ TenantId = 'contoso.example'; Plan = 'CAB-P6-Guests' }
Assert-Equal 'no Terms of Use, P6: stops before any post' "$($r.Posts)|$([bool]($r.Error -like 'Terms of Use agreement not found*'))" '0|True'
New-Tenant
$r = Invoke-Deploy @{ TenantId = 'contoso.example'; Plan = 'CAB-P9-Nope' }
Assert-Equal 'unknown plan name: refused' "$($r.Posts)|$([bool]($r.Error -like 'No plan file for: CAB-P9-Nope*'))" '0|True'

# -- Refusals on the plan files ----------------------------------------------------------
$tmp = Join-Path ([IO.Path]::GetTempPath()) "cab-plans-harness-$PID"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    $src = Get-Content (Join-Path $preview 'Plans' 'CAB-P6-Guests.json') -Raw
    Set-Content -Path (Join-Path $tmp 'CAB-P6-Guests.json') -Value ($src -replace '"enabledForReportingButNotEnforced"', '"enabled"') -Encoding utf8NoBOM
    New-Tenant
    $r = Invoke-Deploy @{ TenantId = 'contoso.example'; PlanPath = $tmp }
    Assert-Equal 'rules not report-only: refused before connecting' "$($r.Posts)|$([bool]($r.Error -like '*are not enabledForReportingButNotEnforced*'))|$($null -eq $global:Fake.Context)" '0|True|True'
    Set-Content -Path (Join-Path $tmp 'CAB-P6-Guests.json') -Value ($src.Replace('REPLACE_WITH_TERMS_OF_USE_ID', 'REPLACE_WITH_SOMETHING_NEW_ID')) -Encoding utf8NoBOM
    New-Tenant
    $r = Invoke-Deploy @{ TenantId = 'contoso.example'; PlanPath = $tmp }
    Assert-Equal 'unknown placeholder: refused before any post' "$($r.Posts)|$([bool]($r.Error -like '*no resolver for REPLACE_WITH_SOMETHING_NEW_ID*'))" '0|True'
} finally { Remove-Item -Recurse -Force $tmp }

# -- Read-back catches what the service changed -------------------------------------------
New-Tenant
$global:Fake.Tamper = { param($plan, $rules) foreach ($x in $rules | Where-Object displayName -like 'CA-SIG006*') { $x.conditions.users.excludeGroups = @($x.conditions.users.excludeGroups | Select-Object -First 1) } }
$r = Invoke-Deploy @{ TenantId = 'contoso.example'; Plan = 'CAB-P6-Guests' }
Assert-Equal 'stored rule lost an exclusion: reported, exit 1' "$([bool]($r.Out -match 'read-back differs'))|$([bool]($r.Out -match 'CA-SIG006.*excludeGroups'))|$($r.Exit)" 'True|True|1'
New-Tenant
$global:Fake.Tamper = { param($plan, $rules) $rules[0].state = 'enabled' }
$r = Invoke-Deploy @{ TenantId = 'contoso.example'; Plan = 'CAB-P1-Admins-PrivilegedAccess' }
Assert-Equal 'stored rule enabled: reported, exit 1' "$([bool]($r.Out -match 'state enabled'))|$($r.Exit)" 'True|1'
New-Tenant
$global:Fake.Tamper = { param($plan, $rules) $plan.sharedConditions.users.excludeGroups = @() }
$r = Invoke-Deploy @{ TenantId = 'contoso.example'; Plan = 'CAB-P3-Global-SessionAndClientHardening' }
Assert-Equal 'stored plan lost shared exclusions: reported, exit 1' "$([bool]($r.Out -match 'sharedConditions\.users\.excludeGroups'))|$($r.Exit)" 'True|1'
New-Tenant
$global:Fake.Tamper = { param($plan, $rules) $plan.sharedConditions | Add-Member clientAppTypes @('all') -Force }
$r = Invoke-Deploy @{ TenantId = 'contoso.example'; Plan = 'CAB-P3-Global-SessionAndClientHardening' }
Assert-Equal 'value added by the service only: not a mismatch' "$([bool]($r.Out -match 'read-back matches'))|$($r.Exit)" 'True|0'

"`npassed: $script:Passed   failed: $script:Failed"
if ($script:Failed) { exit 1 }
