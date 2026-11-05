#Requires -Version 7.0
# Regression harness for Export-CABPolicyPlans.ps1 (Conditional Access policy plans preview): the rule-versus-policy
# comparison that decides MATCH or lists differences.
#
# Self-contained: extracts ConvertTo-Flat, Get-Controls and Get-RuleDiff from the shipped script via AST and runs them
# against fixtures, so it needs no tenant. Fixtures/Plans/ holds 3 plans exported from a demo tenant (2026-11-04) with
# their 9 rules and the 9 policies they copy, sanitized: tenant IDs are replaced, Microsoft's public role and app IDs
# are kept. Prints PASS/FAIL per assertion and a closing 'passed: N   failed: M' line; exits 1 on any failure.
<#
    What is covered:
      1. The live exports: every rule matches its policy, except CA-SIG006, whose only differences are the 3
         guest-type paths (the plan includes 6 types and the rule excludes 1; the policy includes the same 5).
      2. Mutations of real rules and plans that must produce a difference, and harmless variations that must not
         (ported from the prototype's 14 cases).
      3. The reference plans in Preview/Policy-Plans/Plans/: every rule ships report-only, carries a template's name,
         and combined with its plan's shared conditions reproduces that template (CA-SIG006 again differing only in
         the 3 guest-type paths).
#>

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$framework = Join-Path $RepoRoot 'Frameworks' 'Conditional-Access-Baseline'
$scriptPath = Join-Path $framework 'Preview' 'Policy-Plans' 'Scripts' 'Export-CABPolicyPlans.ps1'
$fixtures = Join-Path $PSScriptRoot 'Fixtures' 'Plans'

$script:Passed = 0
$script:Failed = 0
function Assert-Equal {
    param($Name, $Got, $Want)
    $ok = ("$Got" -eq "$Want")
    if ($ok) { $script:Passed++ } else { $script:Failed++ }
    "{0}  {1,-66} got={2,-12} want={3}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $Name, $Got, $Want
}
function Copy-Deep($Obj) { $Obj | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30 }
# Paths of the differences, sorted and joined, so an assertion compares the exact set.
function Get-DiffPaths($Diffs) { (@($Diffs | Where-Object { $_ } | ForEach-Object Path | Sort-Object) -join ',') }

$errs = $null; $toks = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$toks, [ref]$errs)
Assert-Equal 'shipped script parses' $errs.Count 0
$wanted = 'ConvertTo-Flat', 'Get-Controls', 'Get-RuleDiff'
$fns = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -in $wanted }, $true))
Assert-Equal 'comparison functions found in the shipped script' $fns.Count $wanted.Count
foreach ($f in $fns) { . ([scriptblock]::Create($f.Extent.Text)) }

$guestPaths = 'conditions.users.excludeGuestsOrExternalUsers.externalTenants.membershipKind,conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes,conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes'

# -- 1. Live exports --------------------------------------------------------------
$policies = @(Get-Content (Join-Path $fixtures 'policies.json') -Raw | ConvertFrom-Json -Depth 50)
function P([string]$Name) { Copy-Deep (@($policies | Where-Object displayName -eq $Name)[0]) }
$livePlans = @{}
foreach ($id in 'P1', 'P3', 'P6') { $livePlans[$id] = Get-Content (Join-Path $fixtures "plan-$id.json") -Raw | ConvertFrom-Json -Depth 50 }
Assert-Equal 'fixtures: 9 policies' $policies.Count 9
Assert-Equal 'fixtures: 9 rules across 3 plans' (@($livePlans.Values.rules).Count) 9
foreach ($id in 'P1', 'P3', 'P6') {
    $plan = $livePlans[$id]
    foreach ($rule in $plan.rules) {
        $want = if ($rule.displayName -eq 'CA-SIG006-Guests-BlockAdminPortals') { $guestPaths } else { '' }
        Assert-Equal "live $id $($rule.displayName -replace '^CA-(\w+)-.*', '$1') differences" (Get-DiffPaths (Get-RuleDiff $plan.plan.sharedConditions $rule (P $rule.displayName))) $want
    }
}

# -- 2. Mutations and harmless variations ------------------------------------------
# A rule as the migration wizard writes it: the policy's conditions (users optional) and its controls under controls.
function Rule($Policy, [switch]$KeepUsers) {
    $c = Copy-Deep $Policy.conditions
    if (-not $KeepUsers) { $c.users = $null }
    [pscustomobject]@{ conditions = $c; state = 'disabled'; controls = [pscustomobject]@{ grantControls = (Copy-Deep $Policy.grantControls); sessionControls = (Copy-Deep $Policy.sessionControls) } }
}
function Count($Diffs) { @($Diffs | Where-Object { $_ }).Count }
$a = P 'CA-AUT003-Admins-RequireAdminAuthOnAdminPortals'
$c = P 'CA-COV004-Global-BlockDeviceCodeFlow'
$b = P 'CA-COV003-Global-NoPersistentBrowserSessionOnNonCorpDevices'
$g = P 'CA-SIG006-Guests-BlockAdminPortals'
$sharedA = [pscustomobject]@{ users = $a.conditions.users }
$sharedAll = [pscustomobject]@{ clientAppTypes = @('all') }
$sharedExcl = [pscustomobject]@{ clientAppTypes = @('all'); users = [pscustomobject]@{ excludeGroups = $c.conditions.users.excludeGroups } }

Assert-Equal 'users moved to the plan, rest in the rule: no difference' (Count (Get-RuleDiff $sharedA (Rule $a) $a)) 0
Assert-Equal 'All users kept in the rule: no difference' (Count (Get-RuleDiff $sharedAll (Rule $c -KeepUsers) $c)) 0
Assert-Equal 'exclusions also on the plan (duplicated): no difference' (Count (Get-RuleDiff $sharedExcl (Rule $c -KeepUsers) $c)) 0
$r = Rule $c -KeepUsers; $r.conditions.users.excludeGroups = @($r.conditions.users.excludeGroups | Select-Object -Skip 1)
Assert-Equal 'rule drops an exclusion group: detected' (Get-DiffPaths (Get-RuleDiff $sharedAll $r $c)) 'conditions.users.excludeGroups'
$sharedExtra = [pscustomobject]@{ users = [pscustomobject]@{ excludeGroups = @(@($a.conditions.users.excludeGroups) + 'aaaaaaaa-0000-4000-8000-00000000ffff'); includeRoles = $a.conditions.users.includeRoles } }
Assert-Equal 'plan adds an exclusion the policy lacks: detected' (Get-DiffPaths (Get-RuleDiff $sharedExtra (Rule $a) $a)) 'conditions.users.excludeGroups'
$r = Rule $c -KeepUsers; $r.controls.grantControls.builtInControls = @('mfa')
Assert-Equal 'grant control changed: detected' (Get-DiffPaths (Get-RuleDiff $sharedAll $r $c)) 'grantControls.builtInControls'
$r = Rule $b -KeepUsers; $r.controls.sessionControls = $null
Assert-Equal 'session controls dropped: detected' ((Count (Get-RuleDiff $sharedAll $r $b)) -gt 0) $true
$r = Rule $a; $r.controls.grantControls.authenticationStrength = [pscustomobject]@{ id = $a.grantControls.authenticationStrength.id }
Assert-Equal 'strength as id only on the rule, expanded on the policy: no difference' (Count (Get-RuleDiff $sharedA $r $a)) 0
$r = Rule $g -KeepUsers
$r.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes = (($g.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes -split ',') | Sort-Object -Descending) -join ','
Assert-Equal 'guest types in another order: no difference' (Count (Get-RuleDiff $null $r $g)) 0
$r = Rule $g -KeepUsers; $r.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes = 'internalGuest,b2bCollaborationGuest'
Assert-Equal 'guest type removed: detected' (Get-DiffPaths (Get-RuleDiff $null $r $g)) 'conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes'
$r = Rule $c -KeepUsers; $r.controls.sessionControls = [pscustomobject]@{ disableResilienceDefaults = $false }
Assert-Equal 'false boolean on the rule only: no difference' (Count (Get-RuleDiff $sharedAll $r $c)) 0
$r = Rule $g -KeepUsers; $r.conditions.applications.includeApplications = @('MicrosoftAdminPortals')
Assert-Equal 'application removed: detected' (Get-DiffPaths (Get-RuleDiff $null $r $g)) 'conditions.applications.includeApplications'
Assert-Equal "plan client apps 'all' + rule 'browser': no difference" (Count (Get-RuleDiff $sharedExcl (Rule $b -KeepUsers) $b)) 0
Assert-Equal "plan narrows client apps under an all-clients policy: detected" (Get-DiffPaths (Get-RuleDiff ([pscustomobject]@{ clientAppTypes = @('browser') }) (Rule $c -KeepUsers) $c)) 'conditions.clientAppTypes'
$p6 = $livePlans['P6']; $r = Copy-Deep (@($p6.rules | Where-Object displayName -eq 'CA-SIG006-Guests-BlockAdminPortals')[0])
$r.conditions.users.excludeGuestsOrExternalUsers = $null
Assert-Equal 'SIG006 rule loses its guest-type exclusion: differences change' ((Get-DiffPaths (Get-RuleDiff $p6.plan.sharedConditions $r $g)) -eq $guestPaths) $false
$shared6 = Copy-Deep $p6.plan.sharedConditions; $shared6.users.excludeGroups = @()
$r = Copy-Deep (@($p6.rules | Where-Object displayName -eq 'CA-SIG002-Guests-RequireMFA')[0])
Assert-Equal 'plan loses the emergency access exclusion: detected' (Get-DiffPaths (Get-RuleDiff $shared6 $r (P 'CA-SIG002-Guests-RequireMFA'))) 'conditions.users.excludeGroups'

# -- 3. Reference plans reproduce the templates ------------------------------------
$planDir = Join-Path $framework 'Preview' 'Policy-Plans' 'Plans'
$templateDir = Join-Path $framework 'Policies'
$refPlans = @(Get-ChildItem $planDir -Filter '*.json' | Sort-Object Name)
Assert-Equal 'reference plans present' $refPlans.Count 3
foreach ($f in $refPlans) {
    $plan = Get-Content $f.FullName -Raw | ConvertFrom-Json -Depth 50
    Assert-Equal "$($f.BaseName): name matches the file" $plan.displayName $f.BaseName
    foreach ($rule in $plan.rules) {
        $short = $rule.displayName -replace '^CA-(\w+)-.*', '$1'
        Assert-Equal "$($f.BaseName) ${short}: ships report-only" $rule.state 'enabledForReportingButNotEnforced'
        $templatePath = Join-Path $templateDir "$($rule.displayName).json"
        if (-not (Test-Path $templatePath)) { Assert-Equal "$($f.BaseName) ${short}: template exists" $false $true; continue }
        $template = Get-Content $templatePath -Raw | ConvertFrom-Json -Depth 50
        $want = if ($rule.displayName -eq 'CA-SIG006-Guests-BlockAdminPortals') { $guestPaths } else { '' }
        Assert-Equal "$($f.BaseName) ${short}: reproduces the template" (Get-DiffPaths (Get-RuleDiff $plan.sharedConditions $rule $template)) $want
    }
}

"`npassed: $script:Passed   failed: $script:Failed"
if ($script:Failed) { exit 1 }
