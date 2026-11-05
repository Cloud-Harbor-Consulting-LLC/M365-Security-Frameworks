#Requires -Version 7.0
# Regression harness for Compare-CABPlanRuleSignIns.ps1 (Conditional Access policy plans preview): how a plan rule's
# sign-in result is paired with, and compared to, the result of the standalone policy of the same name.
#
# Self-contained: extracts Get-Decision and Get-RulePairs from the shipped script via AST and runs them against
# fixtures, so it needs no tenant. Fixtures/Plans/signins.json holds 4 sign-ins built in the
# appliedConditionalAccessPolicies shape a demo tenant returned (2026-11-04), one per situation seen there: an MFA
# prompt, a rule not yet propagated, a satisfied sign-in, and a block. IDs match the sanitized plan and policy
# fixtures. Prints PASS/FAIL per assertion and a closing 'passed: N   failed: M' line; exits 1 on any failure.

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$scriptPath = Join-Path $RepoRoot 'Frameworks' 'Conditional-Access-Baseline' 'Preview' 'Policy-Plans' 'Scripts' 'Compare-CABPlanRuleSignIns.ps1'
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

$errs = $null; $toks = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$toks, [ref]$errs)
Assert-Equal 'shipped script parses' $errs.Count 0
$wanted = 'Get-Decision', 'Get-RulePairs'
$fns = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -in $wanted }, $true))
Assert-Equal 'comparison functions found in the shipped script' $fns.Count $wanted.Count
foreach ($f in $fns) { . ([scriptblock]::Create($f.Extent.Text)) }

# -- Get-Decision ------------------------------------------------------------------
foreach ($c in @(
        @('reportOnlyInterrupted', 'failure', $true), @('reportOnlyFailure', 'failure', $true), @('reportOnlySuccess', 'success', $true),
        @('reportOnlyNotApplied', 'notApplied', $true), @('reportOnlyInterrupted', 'success', $false), @('reportOnlySuccess', 'failure', $false))) {
    Assert-Equal "decision: rule $($c[0]) vs policy $($c[1]) $(if ($c[2]) { 'agree' } else { 'differ' })" ((Get-Decision $c[0]) -eq (Get-Decision $c[1])) $c[2]
}

# -- Pairing over the fixture sign-ins ----------------------------------------------
$kind = @{}
foreach ($p in (Get-Content (Join-Path $fixtures 'policies.json') -Raw | ConvertFrom-Json)) { $kind[$p.id] = [pscustomobject]@{ Kind = 'policy'; Name = $p.displayName; State = $p.state } }
foreach ($f in (Get-ChildItem $fixtures -Filter 'plan-*.json')) {
    $x = Get-Content $f.FullName -Raw | ConvertFrom-Json
    $kind[$x.plan.id] = [pscustomobject]@{ Kind = 'plan'; Name = $x.plan.displayName; State = '' }
    foreach ($r in $x.rules) { $kind[$r.id] = [pscustomobject]@{ Kind = 'rule'; Name = $r.displayName; State = $r.state; Plan = $x.plan.displayName } }
}
$signIns = @(Get-Content (Join-Path $fixtures 'signins.json') -Raw | ConvertFrom-Json -Depth 30)
Assert-Equal 'fixtures: 4 sign-ins' $signIns.Count 4

$res = Get-RulePairs $signIns $kind
Assert-Equal 'rule entries paired' $res.Pairs.Count 11
Assert-Equal 'every rule entry found its same-named policy' (@($res.Pairs | Where-Object { -not $_.PolicyResult }).Count) 0
Assert-Equal 'decision differences (interrupted counts as failure)' (@($res.Pairs | Where-Object { $_.PolicyResult -and -not $_.Match }).Count) 0
Assert-Equal 'MFA prompt pairs: rule interrupted, policy failure, agree' (@($res.Pairs | Where-Object { $_.RuleResult -eq 'reportOnlyInterrupted' -and $_.PolicyResult -eq 'failure' -and $_.Match }).Count) 2
$fail = @($res.Pairs | Where-Object RuleResult -eq 'reportOnlyFailure')
Assert-Equal 'sign-ins a rule would have failed' $fail.Count 1
Assert-Equal 'that failure is SIG006 on Azure Resource Manager, 53003' "$($fail[0].Name)|$($fail[0].Resource)|$($fail[0].Error)" 'CA-SIG006-Guests-BlockAdminPortals|Azure Resource Manager|53003'
Assert-Equal 'pairs carry the plan name' (@($res.Pairs | Where-Object Plan -eq 'CAB-P6-Guests').Count) 11
Assert-Equal 'policy listed without its rule (not yet propagated)' $res.Missing.Count 1
Assert-Equal 'that policy is SIG006 at 20:45:03' "$($res.Missing[0].Name)|$($res.Missing[0].Time)" "CA-SIG006-Guests-BlockAdminPortals|$($signIns[1].createdDateTime)"
Assert-Equal 'first raw entry recorded for kind rule only' (@($res.FirstRaw.Keys) -join ',') 'rule'

# -- Mutations that must change the result -------------------------------------------
$m = Copy-Deep $signIns
$e = @($m[2].appliedConditionalAccessPolicies | Where-Object { $kind[$_.id].Kind -eq 'rule' -and $_.displayName -like 'CA-SIG002*' })[0]; $e.result = 'reportOnlyFailure'
Assert-Equal 'rule fails where its policy succeeds: one difference' (@((Get-RulePairs $m $kind).Pairs | Where-Object { $_.PolicyResult -and -not $_.Match }).Count) 1
$m = Copy-Deep $signIns
$m[3].appliedConditionalAccessPolicies = @($m[3].appliedConditionalAccessPolicies | Where-Object { -not ($kind[$_.id].Kind -eq 'policy' -and $_.displayName -like 'CA-SIG006*') })
Assert-Equal 'policy entry absent: the rule is unpaired, not a match' (@((Get-RulePairs $m $kind).Pairs | Where-Object { -not $_.PolicyResult }).Count) 1
$m = Copy-Deep $signIns
$m[2].appliedConditionalAccessPolicies += [pscustomobject]@{ id = 'aaaaaaaa-9999-4000-8000-000000000001'; displayName = 'CA-SIG002-Guests-RequireMFA'; result = 'reportOnlySuccess' }
$r = Get-RulePairs $m $kind
Assert-Equal 'entry with an unknown id: paired by name and recorded as unknown' "$($r.Pairs.Count)|$(@($r.FirstRaw.Keys) -join ',')" '12|rule,unknown'
$m = Copy-Deep $signIns
$m[1].appliedConditionalAccessPolicies += (Copy-Deep @($m[2].appliedConditionalAccessPolicies | Where-Object { $kind[$_.id].Kind -eq 'rule' -and $_.displayName -like 'CA-SIG006*' })[0])
Assert-Equal 'rule present after propagation: nothing missing' (Get-RulePairs $m $kind).Missing.Count 0

"`npassed: $script:Passed   failed: $script:Failed"
if ($script:Failed) { exit 1 }
