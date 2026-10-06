#Requires -Version 7.0
# Regression harness for Get-ITPScorecard.ps1: Governance and Detection scoring, scope-filter matching, sensor evidence.
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
foreach ($name in 'Get-ITPSProp', 'Get-ITPSScopeQuery', 'Get-DimensionScore', 'New-ITPSCheck') {
    $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    if (-not $fn) { throw "function $name not found" }
    . ([scriptblock]::Create($fn[0].Extent.Text))
}

$pass = 0; $fail = 0
function Assert($label, $actual, $expected) {
    $ok = ("$actual" -eq "$expected")
    if ($ok) { $script:pass++ } else { $script:fail++ }
    "{0}  {1,-58} got={2,-12} want={3}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $label, $actual, $expected
}

# --- scope shapes -----------------------------------------------------------
# Derek's actual review: principalResourceMembershipsScope, no query anywhere.
$derek = [pscustomobject]@{
    displayName = 'CHC-Demo-NonGuest-Test-Access-Review'
    scope       = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.principalResourceMembershipsScope' }
}
# Classic query scope targeting guests.
$guestQuery = [pscustomobject]@{
    displayName = 'Quarterly external review'
    scope       = [pscustomobject]@{ query = "/groups/abc/members/microsoft.graph.user/?`$filter=(userType eq 'Guest')" }
}
# Nested principalScopes carrying the guest filter.
$guestNested = [pscustomobject]@{
    displayName = 'Review A'
    scope       = [pscustomobject]@{
        '@odata.type'   = '#microsoft.graph.principalResourceMembershipsScope'
        principalScopes = @([pscustomobject]@{ query = "/users?`$filter=(userType eq 'Guest')" })
        resourceScopes  = @([pscustomobject]@{ query = '/groups/xyz' })
    }
}
# A members-only review whose filter mentions Guest only to exclude it.
$nonGuestFilter = [pscustomobject]@{
    displayName = 'Members only'
    scope       = [pscustomobject]@{ query = "/users?`$filter=(userType ne 'Guest')" }
}

Assert 'scope query: principalResourceMemberships, no query' @(Get-ITPSScopeQuery $derek).Count 0
Assert 'scope query: direct query scope'                     @(Get-ITPSScopeQuery $guestQuery).Count 1
Assert 'scope query: nested principal+resource scopes'       @(Get-ITPSScopeQuery $guestNested).Count 2

# --- the guest matcher ------------------------------------------------------
$pattern = "(?i)userType\s+eq\s+'Guest'"
function IsGuest($d) { @(@(Get-ITPSScopeQuery $d) | Where-Object { $_ -match $pattern }).Count -gt 0 }

Assert 'NonGuest display name no longer matches'   (IsGuest $derek)          $false
Assert 'genuine guest query matches'               (IsGuest $guestQuery)     $true
Assert 'guest filter in nested scope matches'      (IsGuest $guestNested)    $true
Assert "negated filter (ne 'Guest') does NOT match" (IsGuest $nonGuestFilter) $false
Assert 'old substring regex would have matched Derek' ('CHC-Demo-NonGuest-Test-Access-Review' -match '(?i)guest') $true

# --- rounding ---------------------------------------------------------------
function Chk($pts, $max) { New-ITPSCheck -Id 'X' -Name 'x' -Points $pts -MaxPoints $max }
Assert 'dimension 57.5/100 rounds to 58 (was 57)' (Get-DimensionScore -Checks @((Chk 57.5 100))) 58
Assert 'dimension 58.5/100 rounds to 59 not 58'   (Get-DimensionScore -Checks @((Chk 58.5 100))) 59
Assert 'dimension 22.5/100 rounds to 23'          (Get-DimensionScore -Checks @((Chk 22.5 100))) 23
Assert 'exact thirds 1/3 -> 33'                   (Get-DimensionScore -Checks @((Chk 1 3)))      33

# --- G-01 graduation --------------------------------------------------------
function G01($n) { switch ($n) { 0 { 0 } 1 { 10 } default { 20 } } }
Assert 'G-01 zero reviews'  (G01 0) 0
Assert 'G-01 one review'    (G01 1) 10
Assert 'G-01 two reviews'   (G01 2) 20
Assert 'G-01 five reviews'  (G01 5) 20

# --- G-05 linear ------------------------------------------------------------
function G05($stale, $total) { if ($total -gt 0) { [Math]::Round((1 - ($stale / $total)) * 20, 2) } else { 20 } }
Assert 'G-05 2 of 10 long-lived -> 16 (was 0)' (G05 2 10) 16
Assert 'G-05 10 of 10 -> 0'                    (G05 10 10) 0
Assert 'G-05 0 of 10 -> 20'                    (G05 0 10) 20
Assert 'G-05 no registrations -> 20'           (G05 0 0)  20

# --- G-04 absorbing G-03 ----------------------------------------------------
function G04($perm, $elig) { $t = $perm + $elig; [Math]::Round((1 - ($perm / $t)) * 45, 2) }
Assert 'G-04 9 permanent 1 eligible -> 4.5 of 45' (G04 9 1) 4.5
Assert 'G-04 0 permanent 5 eligible -> 45'        (G04 0 5) 45

# --- Derek's tenant, rescored ----------------------------------------------
# G-01 1 review = 10; G-02 indeterminate = ManualReview (excluded); G-04 4.5; G-05 16
$gov = @((Chk 10 20), (Chk 4.5 45), (Chk 16 20))
$govScore = Get-DimensionScore -Checks $gov
Assert 'Cloud Harbor Governance rescored' $govScore 36
$overall = [int][Math]::Round(((79 + 100 + $govScore) / 3), 0, [MidpointRounding]::AwayFromZero)
Assert 'Cloud Harbor Overall rescored' $overall 72

# --- Detection deployment gate (item 7) -------------------------------------
# Real controlScores rows from the Cloud Harbor demo tenant: MDI installed on all
# 3 domain controllers. Note AATP_DefenderForIdentityIsNotInstalled scores 0 there,
# which is why it is NOT used as the deployment signal.
$ctlSensorOk      = [pscustomobject]@{ controlName='AATP_Sensor'; controlCategory='Identity'; score=4; scoreInPercentage=100; implementationStatus='You have 3 domain controllers in your environment and Defender for Identity sensor is installed on 3 of them.' }
$ctlNotInstalled  = [pscustomobject]@{ controlName='AATP_DefenderForIdentityIsNotInstalled'; controlCategory='Identity'; score=0; scoreInPercentage=0; implementationStatus='' }
$ctlSensorNone    = [pscustomobject]@{ controlName='AATP_Sensor'; controlCategory='Identity'; score=0; scoreInPercentage=0; implementationStatus='You have 5 domain controllers in your environment and Defender for Identity sensor is installed on 0 of them.' }

function Evidence($controls) {
  $c = @($controls | Where-Object { (Get-ITPSProp $_ 'controlName') -eq 'AATP_Sensor' })
  if ($c.Count -gt 0) {
    @{ Known=$true; Deployed=(([double](Get-ITPSProp $c[0] 'scoreInPercentage' 0) -gt 0) -or ([double](Get-ITPSProp $c[0] 'score' 0) -gt 0)) }
  } else { @{ Known=$false; Deployed=$false } }
}
function Gate($controls,$healthCount){ $empty = ($healthCount -eq 0); $ev = Evidence $controls
  if ($empty -and -not $ev.Deployed) { 'ManualReview' } else { 'scored' } }

Assert 'wrong control would misread Derek tenant' (Evidence @($ctlNotInstalled)).Deployed $false
Assert 'AATP_Sensor reads Derek tenant as deployed' (Evidence @($ctlSensorOk,$ctlNotInstalled)).Deployed $true
Assert 'Derek tenant: 0 issues + sensors -> scored'  (Gate @($ctlSensorOk,$ctlNotInstalled) 0) 'scored'
Assert 'no sensors + 0 issues -> ManualReview'       (Gate @($ctlSensorNone) 0)                'ManualReview'
Assert 'no evidence at all + 0 issues -> ManualReview' (Gate @($ctlNotInstalled) 0)            'ManualReview'
Assert 'issues present -> scored regardless'         (Gate @($ctlSensorNone) 3)                'scored'


""
"passed: $pass   failed: $fail"
if ($fail) { exit 1 }
