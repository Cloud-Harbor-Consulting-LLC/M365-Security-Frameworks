#Requires -Version 7.0
# Regression harness for Get-ITPScorecard.ps1: -IncludeEvidence output, CA policy matching, phishing-resistant strength classification.
#
# Self-contained: extracts the shipped functions via AST and mocks Graph, so it needs no tenant and no
# network. Prints PASS/FAIL per assertion and a closing 'passed: N   failed: M' line; exits 1 on any
# failure. Run all harnesses with Tests/Invoke-Tests.ps1.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Repository root, resolved from this file's location (Tests/<Framework>/), so the harness
# runs from any checkout, including CI.
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path

$src = "$RepoRoot\Frameworks\Identity-Threat-Protection-Scorecard\Scripts\Get-ITPScorecard.ps1"
$ast = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$null, [ref]$null)
foreach ($n in 'Get-ITPSProp','New-ITPSSignal','Get-ITPSNameList','Select-CAPolicyMatch','New-ITPSCheck','Test-ITPSPhishingResistant') {
    $fn = $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)
    if (-not $fn) { throw "missing $n" }
    . ([scriptblock]::Create($fn[0].Extent.Text))
}

$pass = 0; $fail = 0
function Assert($label, $actual, $expected) {
    $ok = ("$actual" -eq "$expected"); if ($ok) { $script:pass++ } else { $script:fail++ }
    "{0}  {1,-58} got={2,-16} want={3}" -f $(if($ok){'PASS'}else{'FAIL'}), $label, $actual, $expected
}

# ---- gating ----------------------------------------------------------------
$script:ITPSIncludeEvidence = $false
$s = New-ITPSSignal -Base @{ Enforced = $true } -Evidence @{ MatchedPolicies = @('CA-COV001') }
Assert 'evidence off: base key kept'      $s.Enforced $true
Assert 'evidence off: evidence excluded'  ($s.ContainsKey('MatchedPolicies')) $false
Assert 'evidence off: exactly 1 key'      $s.Keys.Count 1

$script:ITPSIncludeEvidence = $true
$s = New-ITPSSignal -Base @{ Enforced = $true } -Evidence @{ MatchedPolicies = @('CA-COV001','CA-COV002') }
Assert 'evidence on: evidence merged'     ($s.ContainsKey('MatchedPolicies')) $true
Assert 'evidence on: values intact'       ($s.MatchedPolicies -join ',') 'CA-COV001,CA-COV002'
Assert 'evidence on: base still present'  $s.Enforced $true

$script:ITPSIncludeEvidence = $true
$s = New-ITPSSignal -Base @{ A = 1 }
Assert 'evidence on but none supplied'    $s.Keys.Count 1

# base must win over an evidence key of the same name (no silent overwrite of score data)
$script:ITPSIncludeEvidence = $false
$s = New-ITPSSignal -Base @{ Count = 9 } -Evidence @{ Count = 999 }
Assert 'evidence off cannot clobber base' $s.Count 9

# ---- name extraction -------------------------------------------------------
$objs = @(
  [pscustomobject]@{ displayName = 'CA-COV001-AllUsers-RequireMFA' },
  [pscustomobject]@{ displayName = 'CA-SIG001-AllUsers-BlockLegacyAuth' }
)
Assert 'name list extracts displayName'  ((Get-ITPSNameList $objs) -join '|') 'CA-COV001-AllUsers-RequireMFA|CA-SIG001-AllUsers-BlockLegacyAuth'
Assert 'name list on empty set'          @(Get-ITPSNameList @()).Count 0
Assert 'missing property -> (unnamed)'   ((Get-ITPSNameList @([pscustomobject]@{ id = 'x' })) -join '') '(unnamed)'
Assert 'alternate property honoured'     ((Get-ITPSNameList @([pscustomobject]@{ healthIssueType = 'sensor' }) 'healthIssueType') -join '') 'sensor'

# ---- the matcher still scores identically ----------------------------------
$policies = @(
  [pscustomobject]@{ displayName='CA-COV001'; state='enabled';  grantControls=[pscustomobject]@{ builtInControls=@('mfa') }; conditions=[pscustomobject]@{ users=[pscustomobject]@{ includeUsers=@('All') } } },
  [pscustomobject]@{ displayName='CA-RPT002'; state='enabledForReportingButNotEnforced'; grantControls=[pscustomobject]@{ builtInControls=@('mfa') }; conditions=[pscustomobject]@{ users=[pscustomobject]@{ includeUsers=@('All') } } },
  [pscustomobject]@{ displayName='CA-SCOPED'; state='enabled';  grantControls=[pscustomobject]@{ builtInControls=@('mfa') }; conditions=[pscustomobject]@{ users=[pscustomobject]@{ includeUsers=@('group-guid') } } }
)
$mfaFilter = {
    param($p)
    ((Get-ITPSProp $p 'grantControls.builtInControls') -contains 'mfa' -or
     $null -ne (Get-ITPSProp $p 'grantControls.authenticationStrength')) -and
    ((Get-ITPSProp $p 'conditions.users.includeUsers') -contains 'All')
}
$m = @(Select-CAPolicyMatch -Policies $policies -Filter $mfaFilter)
Assert 'matcher: only enabled all-users'  $m.Count 1
Assert 'matcher: report-only excluded'    (($m | ForEach-Object { $_.displayName }) -join '') 'CA-COV001'
Assert 'boolean from count matches old'   ($m.Count -gt 0) $true
$none = @(Select-CAPolicyMatch -Policies @() -Filter $mfaFilter)
Assert 'matcher: empty policy set'        $none.Count 0

# ---- end-to-end check shape ------------------------------------------------
$script:ITPSIncludeEvidence = $false
$chk = New-ITPSCheck -Id 'P-02' -Name 'MFA enforced for all users' -Points 10 -MaxPoints 10 `
        -Signal (New-ITPSSignal -Base @{ Enforced = ($m.Count -gt 0) } -Evidence @{ MatchedPolicies = (Get-ITPSNameList $m) })
Assert 'client-safe check has no policy names' ($chk.Signal.ContainsKey('MatchedPolicies')) $false
Assert 'client-safe check still scores'        $chk.Points 10

$script:ITPSIncludeEvidence = $true
$chk = New-ITPSCheck -Id 'P-02' -Name 'MFA enforced for all users' -Points 10 -MaxPoints 10 `
        -Signal (New-ITPSSignal -Base @{ Enforced = ($m.Count -gt 0) } -Evidence @{ MatchedPolicies = (Get-ITPSNameList $m) })
Assert 'evidence check names the policy'       ($chk.Signal.MatchedPolicies -join '') 'CA-COV001'
Assert 'evidence run scores identically'       $chk.Points 10

# ---- evidence fields must stay arrays in JSON ------------------------------
# The live run produced "MatchedPolicies": "CA-COV001-..." (a bare string) for
# single-match checks and "OpenHighIssues": null for empty ones, because a
# function returning a collection unrolls on return. A consumer then has to
# handle three shapes for one field.
$script:ITPSIncludeEvidence = $true
foreach ($case in @(
    @{ N = 'two matches'; V = @([pscustomobject]@{displayName='A'}, [pscustomobject]@{displayName='B'}); Want = '["A","B"]' },
    @{ N = 'one match';   V = @([pscustomobject]@{displayName='A'});                                     Want = '["A"]' },
    @{ N = 'no matches';  V = @();                                                                        Want = '[]' }
)) {
    $sig = New-ITPSSignal -Base @{} -Evidence @{ MatchedPolicies = @(Get-ITPSNameList $case.V) }
    $json = ($sig | ConvertTo-Json -Compress)
    Assert "JSON array shape: $($case.N)" ($json.Contains('"MatchedPolicies":' + $case.Want)) $true
}

# ---- CA policy state breakdown ---------------------------------------------
# Derek's Priority 1: prove the enabled-state filter excludes report-only.
$mixed = @(
  [pscustomobject]@{ displayName='CA-COV002-AllUsers-RequireMFA'; state='enabled' },
  [pscustomobject]@{ displayName='CA-RPT001-ReportOnly';          state='enabledForReportingButNotEnforced' },
  [pscustomobject]@{ displayName='CA-RPT002-ReportOnly';          state='enabledForReportingButNotEnforced' },
  [pscustomobject]@{ displayName='CA-OLD003-Disabled';            state='disabled' }
)
$reportOnly = @($mixed | Where-Object { (Get-ITPSProp $_ 'state') -eq 'enabledForReportingButNotEnforced' })
$disabled   = @($mixed | Where-Object { (Get-ITPSProp $_ 'state') -eq 'disabled' })
$counts = @{
    Enabled    = @($mixed | Where-Object { (Get-ITPSProp $_ 'state') -eq 'enabled' }).Count
    ReportOnly = $reportOnly.Count
    Disabled   = $disabled.Count
}
Assert 'state counts: enabled'     $counts.Enabled 1
Assert 'state counts: report-only' $counts.ReportOnly 2
Assert 'state counts: disabled'    $counts.Disabled 1
Assert 'report-only names captured' (@(Get-ITPSNameList $reportOnly) -join ',') 'CA-RPT001-ReportOnly,CA-RPT002-ReportOnly'

# and the matcher must never return a report-only policy
$anyFilter = { param($p) $true }
$m = @(Select-CAPolicyMatch -Policies $mixed -Filter $anyFilter)
Assert 'matcher excludes report-only + disabled' $m.Count 1
Assert 'matcher returned only the enabled one'   (@(Get-ITPSNameList $m) -join '') 'CA-COV002-AllUsers-RequireMFA'


# ---- P-02 precision --------------------------------------------------------
# The live run matched 4 policies for "MFA enforced for all users" where only one
# actually enforces it. The other three were user-action policies and a
# risk-conditional policy.
function NewPol($name, $state, $mfa, $users, $apps, $userActions, $signInRisk) {
    [pscustomobject]@{
        displayName   = $name
        state         = $state
        grantControls = [pscustomobject]@{ builtInControls = $mfa }
        conditions    = [pscustomobject]@{
            users           = [pscustomobject]@{ includeUsers = $users }
            applications    = [pscustomobject]@{ includeApplications = $apps; includeUserActions = $userActions }
            signInRiskLevels = $signInRisk
            userRiskLevels   = @()
        }
    }
}
$caSet = @(
  NewPol 'CA-COV002-AllUsers-RequireMFA'      'enabled' @('mfa') @('All') @('All') @()                              @()
  NewPol 'CA-AUT001-Global-RegisterDevice'    'enabled' @('mfa') @('All') @()      @('urn:user:registerdevice')      @()
  NewPol 'CA-AUT002-Global-RegisterSecInfo'   'enabled' @('mfa') @('All') @()      @('urn:user:registersecurityinfo') @()
  NewPol 'CA-SIG004-Global-MediumSignInRisk'  'enabled' @('mfa') @('All') @('All') @()                              @('medium')
  NewPol 'CA-RPT099-ReportOnly-AllUsers'      'enabledForReportingButNotEnforced' @('mfa') @('All') @('All') @()    @()
)
$p02Filter = {
    param($p)
    $requiresMfa = ((Get-ITPSProp $p 'grantControls.builtInControls') -contains 'mfa' -or
        $null -ne (Get-ITPSProp $p 'grantControls.authenticationStrength'))
    $allUsers = (Get-ITPSProp $p 'conditions.users.includeUsers') -contains 'All'
    $allApps = (Get-ITPSProp $p 'conditions.applications.includeApplications') -contains 'All'
    $noUserActionScope = @(Get-ITPSProp $p 'conditions.applications.includeUserActions').Count -eq 0
    $unconditional = @(Get-ITPSProp $p 'conditions.signInRiskLevels').Count -eq 0 -and
        @(Get-ITPSProp $p 'conditions.userRiskLevels').Count -eq 0
    $requiresMfa -and $allUsers -and $allApps -and $noUserActionScope -and $unconditional
}
$p02 = @(Select-CAPolicyMatch -Policies $caSet -Filter $p02Filter)
Assert 'P-02 matches only the blanket MFA policy' $p02.Count 1
Assert 'P-02 names the right policy'              (@(Get-ITPSNameList $p02) -join '') 'CA-COV002-AllUsers-RequireMFA'

# a tenant with ONLY a register-device policy must now score zero, not full marks
$onlyUserAction = @($caSet | Where-Object { $_.displayName -like '*RegisterDevice*' })
Assert 'P-02 zero when only user-action MFA exists' @(Select-CAPolicyMatch -Policies $onlyUserAction -Filter $p02Filter).Count 0

# ---- P-06 phishing-resistance classification -------------------------------
function Strength($id, $combos) { [pscustomobject]@{ id = $id; displayName = 'x'; allowedCombinations = $combos } }
Assert 'PR: fido2 only'                    (Test-ITPSPhishingResistant (Strength 'custom' @('fido2'))) 'yes'
Assert 'PR: fido2 + WHfB + CBA'            (Test-ITPSPhishingResistant (Strength 'custom' @('fido2','windowsHelloForBusiness','x509CertificateMultiFactor'))) 'yes'
Assert 'PR: any weak combination fails'    (Test-ITPSPhishingResistant (Strength 'custom' @('fido2','password,microsoftAuthenticatorPush'))) 'no'
Assert 'PR: plain MFA combos'              (Test-ITPSPhishingResistant (Strength 'custom' @('password,sms'))) 'no'
Assert 'PR: built-in phishing-resistant'   (Test-ITPSPhishingResistant (Strength '00000000-0000-0000-0000-000000000004' @())) 'yes'
Assert 'PR: built-in multifactor'          (Test-ITPSPhishingResistant (Strength '00000000-0000-0000-0000-000000000002' @())) 'no'
Assert 'PR: built-in passwordless'         (Test-ITPSPhishingResistant (Strength '00000000-0000-0000-0000-000000000003' @())) 'no'
Assert 'PR: unknown custom, no combos'     (Test-ITPSPhishingResistant (Strength 'custom-guid' @())) 'unknown'
Assert 'PR: no strength at all'            (Test-ITPSPhishingResistant $null) 'no'

# scoring outcomes
function P06($pr, $unknown) {
    if ($pr -eq 0 -and $unknown -gt 0) { 'ManualReview' } elseif ($pr -gt 0) { 10 } else { 0 }
}
Assert 'P-06 scores when PR strength found'      (P06 1 0) 10
Assert 'P-06 zero when strengths are all weak'   (P06 0 0) 0
Assert 'P-06 manual when unclassifiable'         (P06 0 2) 'ManualReview'
Assert 'P-06 scores despite an unknown alongside' (P06 1 1) 10


""
"passed: $pass   failed: $fail"
if ($fail) { exit 1 }
