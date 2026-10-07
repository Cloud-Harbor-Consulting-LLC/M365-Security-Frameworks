#Requires -Version 7.0
# Regression harness for Get-ZTReadinessScore.ps1 and Format-ZTReadinessReport.ps1: collection outcomes, the request layer,
# scoring precision, the formatter end to end, and version consistency across the framework.
#
# Self-contained: extracts the shipped functions via AST and mocks Graph, so it needs no tenant and no
# network. Prints PASS/FAIL per assertion and a closing 'passed: N   failed: M' line; exits 1 on any
# failure. Run all harnesses with Tests/Invoke-Tests.ps1.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Repository root, resolved from this file's location (Tests/<Framework>/), so the harness
# runs from any checkout, including CI.
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path

$src = "$RepoRoot\Frameworks\Zero-Trust-Readiness-Assessment\Scripts\Get-ZTReadinessScore.ps1"
$ast = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$null, [ref]$null)
foreach ($n in 'Write-Status','Get-ZTProp','Get-ZTScopeQuery','Get-ZTErrorSummary','Get-ZTRetryDelay',
               'Invoke-ZTGraphSend','Invoke-ZTGraphRequest','Invoke-ZTCollection',
               'Test-ZTPhishingResistant','Test-CAPolicyExists','New-ZTControl','Get-PillarStage') {
    $fn = $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)
    if (-not $fn) { throw "missing function: $n" }
    . ([scriptblock]::Create($fn[0].Extent.Text))
}
$ZT_GUEST_SCOPE_PATTERN = "(?i)userType\s+eq\s+'Guest'"

$pass = 0; $fail = 0
function Assert($label, $actual, $expected) {
    $ok = ("$actual" -eq "$expected"); if ($ok) { $script:pass++ } else { $script:fail++ }
    "{0}  {1,-58} got={2,-14} want={3}" -f $(if($ok){'PASS'}else{'FAIL'}), $label, $actual, $expected
}
function Write-Status { param($Message, $Level) }
$script:slept = @()
function Start-Sleep { param([int]$Seconds) $script:slept += $Seconds }

# ── mocked Graph ─────────────────────────────────────────────────────────────
$script:calls = 0
$script:plan = @()
function Invoke-MgGraphRequest {
    param($Method, $Uri, $OutputType, [switch]$SkipHttpErrorCheck, $StatusCodeVariable, $ResponseHeadersVariable)
    $i = $script:calls; $script:calls++
    $step = if ($i -lt $script:plan.Count) { $script:plan[$i] } else { $script:plan[-1] }
    Set-Variable -Name $StatusCodeVariable -Value $step.Status -Scope 1
    Set-Variable -Name $ResponseHeadersVariable -Value $step.Headers -Scope 1
    return $step.Body
}
$empty  = [pscustomobject]@{ value = @() }
$one    = [pscustomobject]@{ value = @([pscustomobject]@{ id = '1' }) }
$err429 = [pscustomobject]@{ error = [pscustomobject]@{ code='TooManyRequests'; message='Too many requests. Please try again later.' } }
$err403 = [pscustomobject]@{ error = [pscustomobject]@{ code='Authorization_RequestDenied'; message='Insufficient privileges.' } }
function Plan($steps) { $script:calls = 0; $script:slept = @(); $script:plan = $steps }

# ── Z1: the crash that stopped a healthy tenant ──────────────────────────────
# Every one of these threw before: an empty collection unrolled to $null, and
# $null.Count is fatal under Set-StrictMode -Version Latest.
Plan @(@{ Status=200; Headers=@{}; Body=$empty })
$c = Invoke-ZTCollection -Uri 'identityProtection/riskyUsers'
Assert 'zero risky users: call reports Ok'        $c.Ok $true
Assert 'zero risky users: Items is an array'      $c.Items.Count 0
Assert 'zero risky users: .Count no longer throws' (@($c.Items).Count -eq 0) $true

Plan @(@{ Status=200; Headers=@{}; Body=$empty })
$d = Invoke-ZTCollection -Uri 'devices'
Assert 'zero devices: .Count safe'                $d.Items.Count 0

Plan @(@{ Status=403; Headers=@{}; Body=$err403 })
$f = Invoke-ZTCollection -Uri 'applications'
Assert 'failed call: Ok is false'                 $f.Ok $false
Assert 'failed call: Items still an array'        $f.Items.Count 0
Assert 'failed call: error captured'              ($f.Error -like '*Insufficient privileges*') $true

# empty and failed are now distinguishable — they were both $null before
Plan @(@{ Status=200; Headers=@{}; Body=$empty })
$okEmpty = Invoke-ZTCollection -Uri 'x'
Assert 'empty vs failed are distinguishable'      ($okEmpty.Ok -ne $f.Ok) $true

# ── Z2 / Z7: the policy matcher ──────────────────────────────────────────────
Assert 'matcher accepts an empty policy set'      (Test-CAPolicyExists -Policies @() -Filter { param($p) $true }) $false
$noState = @([pscustomobject]@{ displayName = 'policy with no state property' })
Assert 'matcher tolerates a missing state field'  (Test-CAPolicyExists -Policies $noState -Filter { param($p) $true }) $false
$mixed = @(
  [pscustomobject]@{ displayName='enabled-one'; state='enabled' },
  [pscustomobject]@{ displayName='report-only'; state='enabledForReportingButNotEnforced' }
)
Assert 'matcher still honours enabled state'      (Test-CAPolicyExists -Policies $mixed -Filter { param($p) $true }) $true
Assert 'matcher still isolates report-only'       (Test-CAPolicyExists -Policies $mixed -Filter { param($p) $true } -State 'enabledForReportingButNotEnforced') $true

# ── Z3: the pager ceiling ────────────────────────────────────────────────────
$endless = [pscustomobject]@{ value=@(1); '@odata.nextLink'='https://graph.microsoft.com/v1.0/next' }
Plan @(@{ Status=200; Headers=@{}; Body=$endless })
$null = Invoke-ZTGraphRequest -Uri 'devices' -MaxPages 25
Assert 'non-terminating nextLink stops at MaxPages' $script:calls 25
Plan @(@{ Status=200; Headers=@{}; Body=$endless })
$null = Invoke-ZTGraphRequest -Uri 'devices'
Assert 'default ceiling is 200 pages'              $script:calls 200

# ── Z4: throttle handling ────────────────────────────────────────────────────
Plan @(
  @{ Status=429; Headers=@{ 'Retry-After'=@('2') }; Body=$err429 },
  @{ Status=429; Headers=@{ 'Retry-After'=@('3') }; Body=$err429 },
  @{ Status=200; Headers=@{};                       Body=$one }
)
$r = @(Invoke-ZTGraphRequest -Uri 'identityGovernance/accessReviews/definitions')
Assert '429 twice then success: data returned'    $r.Count 1
Assert '429 twice: exactly 3 requests'            $script:calls 3
Assert '429 twice: slept per Retry-After'         ($script:slept -join ',') '2,3'

Plan @(@{ Status=429; Headers=@{ 'Retry-After'=@('1') }; Body=$err429 })
$threw=$false; $msg=''
try { Invoke-ZTGraphRequest -Uri 'devices' -MaxRetry 3 | Out-Null } catch { $threw=$true; $msg=$_.Exception.Message }
Assert 'gives up at the retry ceiling'            $threw $true
Assert 'attempts = 1 + MaxRetry'                  $script:calls 4
Assert 'throttle error names status and count'    ($msg -like 'Graph returned HTTP 429*after 3 retries*') $true

Plan @(@{ Status=403; Headers=@{}; Body=$err403 })
$threw=$false
try { Invoke-ZTGraphRequest -Uri 'applications' | Out-Null } catch { $threw=$true }
Assert '403 is not retried'                       $script:calls 1
Assert '403 never sleeps'                         $script:slept.Count 0
Assert '403 throws'                               $threw $true

Assert 'Retry-After honoured'                     (Get-ZTRetryDelay -Headers @{ 'Retry-After'=@('17') } -Attempt 1) 17
Assert 'missing header -> backoff'                (Get-ZTRetryDelay -Headers @{} -Attempt 3) 8
Assert 'absurd Retry-After capped'                (Get-ZTRetryDelay -Headers @{ 'Retry-After'='9999' } -Attempt 1) 60

# ── Z6: guest review detection ───────────────────────────────────────────────
function IsGuestReview($d) { @(@(Get-ZTScopeQuery $d) | Where-Object { $_ -match $ZT_GUEST_SCOPE_PATTERN }).Count -gt 0 }
$nonGuest = [pscustomobject]@{ displayName='CHC-Demo-NonGuest-Test-Access-Review'
                               scope=[pscustomobject]@{ '@odata.type'='#microsoft.graph.principalResourceMembershipsScope' } }
$guestQ   = [pscustomobject]@{ displayName='Quarterly external review'
                               scope=[pscustomobject]@{ query="/v1.0/users?`$filter=userType eq 'Guest'" } }
$guestNest= [pscustomobject]@{ displayName='Review A'
                               scope=[pscustomobject]@{ '@odata.type'='#microsoft.graph.principalResourceMembershipsScope'
                                                        principalScopes=@([pscustomobject]@{ query="/users?`$filter=(userType eq 'Guest')" })
                                                        resourceScopes=@([pscustomobject]@{ query='/groups/xyz' }) } }
$negated  = [pscustomobject]@{ displayName='Members only'
                               scope=[pscustomobject]@{ query="/users?`$filter=(userType ne 'Guest')" } }
Assert "old matcher would accept 'NonGuest' name" ('CHC-Demo-NonGuest-Test-Access-Review' -match '(?i)guest') $true
Assert 'NonGuest review no longer matches'        (IsGuestReview $nonGuest) $false
Assert 'genuine guest query matches'              (IsGuestReview $guestQ) $true
Assert 'nested principalScopes guest matches'     (IsGuestReview $guestNest) $true
Assert "negated ne 'Guest' does not match"        (IsGuestReview $negated) $false
Assert 'scope with no query yields none'          @(Get-ZTScopeQuery $nonGuest).Count 0
Assert 'nested scopes yield both queries'         @(Get-ZTScopeQuery $guestNest).Count 2

# ── Z8: phishing resistance ──────────────────────────────────────────────────
function Strength($id,$combos) { [pscustomobject]@{ id=$id; displayName='x'; allowedCombinations=$combos } }
Assert 'PR: fido2 only'                           (Test-ZTPhishingResistant (Strength 'c' @('fido2'))) 'yes'
Assert 'PR: all three resistant modes'            (Test-ZTPhishingResistant (Strength 'c' @('fido2','windowsHelloForBusiness','x509CertificateMultiFactor'))) 'yes'
Assert 'PR: one weak combination disqualifies'    (Test-ZTPhishingResistant (Strength 'c' @('fido2','password,sms'))) 'no'
Assert 'PR: built-in phishing-resistant id'       (Test-ZTPhishingResistant (Strength '00000000-0000-0000-0000-000000000004' @())) 'yes'
Assert 'PR: built-in multifactor id'              (Test-ZTPhishingResistant (Strength '00000000-0000-0000-0000-000000000002' @())) 'no'
Assert 'PR: unknown custom strength'              (Test-ZTPhishingResistant (Strength 'custom' @())) 'unknown'
Assert 'PR: no strength at all'                   (Test-ZTPhishingResistant $null) 'no'

# ── Z9: ID-01 tenant-wide MFA ────────────────────────────────────────────────
function Pol($name,$mfa,$users,$apps,$actions,$risk,$strength) {
    [pscustomobject]@{ displayName=$name; state='enabled'
        grantControls=[pscustomobject]@{ builtInControls=$mfa; authenticationStrength=$strength }
        conditions=[pscustomobject]@{ users=[pscustomobject]@{ includeUsers=$users }
                                      applications=[pscustomobject]@{ includeApplications=$apps; includeUserActions=$actions }
                                      signInRiskLevels=$risk; userRiskLevels=@() } }
}
$mfaFilter = {
    param($p)
    $requiresMfa = ((Get-ZTProp $p 'grantControls.builtInControls') -contains 'mfa' -or
        $null -ne (Get-ZTProp $p 'grantControls.authenticationStrength'))
    $allUsers = (Get-ZTProp $p 'conditions.users.includeUsers') -contains 'All'
    $allApps = (Get-ZTProp $p 'conditions.applications.includeApplications') -contains 'All'
    $noUserActionScope = @(Get-ZTProp $p 'conditions.applications.includeUserActions').Count -eq 0
    $unconditional = @(Get-ZTProp $p 'conditions.signInRiskLevels').Count -eq 0 -and
        @(Get-ZTProp $p 'conditions.userRiskLevels').Count -eq 0
    $requiresMfa -and $allUsers -and $allApps -and $noUserActionScope -and $unconditional
}
$blanket   = Pol 'CA-COV002-AllUsers-RequireMFA'   @('mfa') @('All') @('All') @() @() $null
$groupOnly = Pol 'CA-PILOT-GroupMFA'               @('mfa') @('group-guid') @('All') @() @() $null
$userAct   = Pol 'CA-AUT001-Global-RegisterDevice' @('mfa') @('All') @() @('urn:user:registerdevice') @() $null
$riskCond  = Pol 'CA-SIG004-MediumSignInRisk'      @('mfa') @('All') @('All') @() @('medium') $null
Assert 'ID-01 accepts blanket MFA'                (Test-CAPolicyExists -Policies @($blanket) -Filter $mfaFilter) $true
Assert 'ID-01 rejects single-group MFA'           (Test-CAPolicyExists -Policies @($groupOnly) -Filter $mfaFilter) $false
Assert 'ID-01 rejects user-action MFA'            (Test-CAPolicyExists -Policies @($userAct) -Filter $mfaFilter) $false
Assert 'ID-01 rejects risk-conditional MFA'       (Test-CAPolicyExists -Policies @($riskCond) -Filter $mfaFilter) $false

# ── Z10: a failed risky-user call must not grant Stage 4 ────────────────────
function Id05($medEnforced,$highEnforced,$riskyOk,$riskyCount) {
    if ($medEnforced -and $riskyOk -and $riskyCount -eq 0) { 4 }
    elseif ($highEnforced -and $medEnforced) { 3 }
    elseif ($highEnforced) { 2 } else { 1 }
}
Assert 'ID-05 Stage 4 on a genuinely clean tenant' (Id05 $true $true $true 0) 4
Assert 'ID-05 failed call cannot reach Stage 4'    (Id05 $true $true $false 0) 3
Assert 'ID-05 risky users present drops to 3'      (Id05 $true $true $true 5) 3

# ── error summarising ────────────────────────────────────────────────────────
$long = (1..4 | ForEach-Object { '(HTTP request failed with status code: TooManyRequests.{"error":{"code":"TooManyRequests","message":"Too many requests.","innerError":{"request-id":"17a6285c-654b-48e2-af52-665861ef4898"}}})' }) -join ' '
Assert 'raw error is long'                        ($long.Length -gt 500) $true
Assert 'summary is truncated'                     ((Get-ZTErrorSummary $long).Length -le 250) $true
Assert 'empty error handled'                      (Get-ZTErrorSummary '') 'no error detail returned'

# ── pillar median unchanged ──────────────────────────────────────────────────
function Ctl($stage) { New-ZTControl -Id 'X' -Name 'x' -Stage $stage }
Assert 'median of 1,2,3 is 2'                     (Get-PillarStage -Controls @((Ctl 1),(Ctl 2),(Ctl 3))) 2
Assert 'even count rounds down'                   (Get-PillarStage -Controls @((Ctl 1),(Ctl 2),(Ctl 3),(Ctl 4))) 2
Assert 'all-manual pillar is unscored'            ($null -eq (Get-PillarStage -Controls @((Ctl $null),(Ctl $null)))) $true
Assert 'single scored control'                    (Get-PillarStage -Controls @((Ctl 3),(Ctl $null))) 3

# ── Z13: the formatter crashed on a pillar with no gaps ─────────────────────
# Get-TopGaps returns a collection; an empty one unrolls to nothing, leaving
# $gaps as $null and making $gaps.Count throw at line 214. This is the same
# defect corrected in the ITPS formatter, never fixed here. It aborted report
# generation after the technical report had already been written, so the run
# looked partially successful.
$fmt = "$RepoRoot\Frameworks\Zero-Trust-Readiness-Assessment\Scripts\Format-ZTReadinessReport.ps1"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ztra-fmt-" + [Guid]::NewGuid().ToString('N'))
function Ctrl($id,$stage,$manual) {
    [pscustomobject]@{ Id=$id; Name="ctl $id"; NistTenets=@('T1'); RepoXRef=''
                       Stage=$stage; ManualReview=$manual
                       ManualReviewNote=$(if($manual){'assess by hand'}else{''}); Signal=@{} }
}
function RunFormatter($result, $tag) {
    $dir = Join-Path $tmp $tag
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $json = Join-Path $dir 'in.json'
    $result | ConvertTo-Json -Depth 10 | Set-Content $json -Encoding UTF8
    & $fmt -InputPath $json -OutputPath $dir *>$null
    return @(Get-ChildItem $dir -Filter '*.md').Count
}
# a pillar where every control already sits at the pillar stage produces no gaps
$noGaps = [pscustomobject]@{
    TenantId='t'; AssessmentDate='2026-08-18T09:00:00Z'; CollectorVersion='v'
    OverallStage=3; ManualReviewCount=0; GraphScopesUsed=@('x')
    Pillars=@([pscustomobject]@{ Name='Identities'; Stage=3; Controls=@((Ctrl 'ID-01' 3 $false),(Ctrl 'ID-02' 3 $false)) })
}
Assert 'formatter: pillar with no gaps writes 3 reports' (RunFormatter $noGaps 'nogaps') 3

# a tenant that is manual end to end has no stage anywhere
$allManual = [pscustomobject]@{
    TenantId='t'; AssessmentDate='2026-08-18T09:00:00Z'; CollectorVersion='v'
    OverallStage=$null; ManualReviewCount=1; GraphScopesUsed=@('x')
    Pillars=@([pscustomobject]@{ Name='Data'; Stage=$null; Controls=@((Ctrl 'DA-01' $null $true)) })
}
Assert 'formatter: all-manual tenant writes 3 reports'   (RunFormatter $allManual 'manual') 3

# mixed, including an unscored pillar alongside scored ones
$mixed = [pscustomobject]@{
    TenantId='t'; AssessmentDate='2026-08-18T09:00:00Z'; CollectorVersion='v'
    OverallStage=2; ManualReviewCount=1; GraphScopesUsed=@('x')
    Pillars=@(
      [pscustomobject]@{ Name='Identities'; Stage=3; Controls=@((Ctrl 'ID-01' 3 $false),(Ctrl 'ID-02' 2 $false)) }
      [pscustomobject]@{ Name='Applications'; Stage=$null; Controls=@((Ctrl 'AP-01' $null $true)) }
      [pscustomobject]@{ Name='Networks'; Stage=4; Controls=@((Ctrl 'NW-01' 4 $false)) }
    )
}
Assert 'formatter: mixed scored and unscored pillars'    (RunFormatter $mixed 'mixed') 3
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue


# ── live-run findings: a failed call is not an absent control ───────────────
# The demo tenant returned 403 on access packages (missing scope) and 400 on
# sensitivity labels (wrong endpoint). Both were scored as "none configured",
# pulling Applications and Data to Stage 1 on unanswered questions.
function Ap06($ok,$count) {
    if (-not $ok) { 'ManualReview' }
    elseif ($count -gt 5) { 3 } elseif ($count -gt 0) { 2 } else { 1 }
}
Assert 'AP-06 failed call -> ManualReview'        (Ap06 $false 0) 'ManualReview'
Assert 'AP-06 genuinely zero packages -> Stage 1' (Ap06 $true 0) 1
Assert 'AP-06 six packages -> Stage 3'            (Ap06 $true 6) 3

# DA-01 reads the tenant label taxonomy from the documented v1.0 endpoint. Two
# earlier paths returned HTTP 400: informationProtection/sensitivityLabels and
# security/informationProtection/sensitivityLabels. The resource lives under
# security/dataSecurityAndGovernance.
$srcNow = [IO.File]::ReadAllText($src)
Assert 'label call uses dataSecurityAndGovernance' ($srcNow -match [regex]::Escape("security/dataSecurityAndGovernance/sensitivityLabels")) $true
Assert 'no informationProtection path remains'     ($srcNow -notmatch [regex]::Escape("Uri 'informationProtection/sensitivityLabels'")) $true
Assert 'SensitivityLabels.Read.All declared'       ($srcNow -match [regex]::Escape("'SensitivityLabels.Read.All'")) $true
function Da01($ok,$count) { if (-not $ok) { $null } elseif ($count -gt 0) { 2 } else { 1 } }
Assert 'DA-01 failed call carries no stage'        ($null -eq (Da01 $false 0)) $true
Assert 'DA-01 zero labels -> Stage 1'              (Da01 $true 0) 1
Assert 'DA-01 labels present -> Stage 2'           (Da01 $true 4) 2
$dataPillar = @((New-ZTControl -Id 'DA-01' -Name 'x' -Stage $null -ManualReview $true))
Assert 'Data pillar unscored when the call fails'  ($null -eq (Get-PillarStage -Controls $dataPillar)) $true

# ── ID-01 Stage 4 must not rest on a risk-conditional policy ────────────────
$prFilter = {
    param($p)
    (Test-ZTPhishingResistant -Strength (Get-ZTProp $p 'grantControls.authenticationStrength')) -eq 'yes' -and
    (Get-ZTProp $p 'conditions.users.includeUsers') -contains 'All' -and
    (Get-ZTProp $p 'conditions.applications.includeApplications') -contains 'All' -and
    @(Get-ZTProp $p 'conditions.signInRiskLevels').Count -eq 0 -and
    @(Get-ZTProp $p 'conditions.userRiskLevels').Count -eq 0
}
$strongPR = [pscustomobject]@{ id='c'; displayName='StrongAuth'; allowedCombinations=@('fido2') }
$riskOnly = Pol 'CA-SIG004-Global-MediumSignInRisk' @() @('All') @('All') @() @('medium') $strongPR
$always   = Pol 'CA-PR-AllUsers-Always'             @() @('All') @('All') @() @()         $strongPR
$adminOnly= Pol 'CA-AUT003-Admins-Only'             @() @('admin-role') @('All') @() @()  $strongPR
Assert 'ID-01 Stage 4 rejects risk-conditional PR' (Test-CAPolicyExists -Policies @($riskOnly) -Filter $prFilter) $false
Assert 'ID-01 Stage 4 accepts unconditional PR'    (Test-CAPolicyExists -Policies @($always) -Filter $prFilter) $true
Assert 'ID-01 Stage 4 rejects admin-scoped PR'     (Test-CAPolicyExists -Policies @($adminOnly) -Filter $prFilter) $false

# ── declared scopes must cover every endpoint called ───────────────────────
$srcText = [IO.File]::ReadAllText($src)
$declared = @([regex]::Matches($srcText, "'(?<s>[A-Za-z]+\.[A-Za-z.]+)'\s*,?\s*#") | ForEach-Object { $_.Groups['s'].Value })
foreach ($need in @('Application.Read.All','AccessReview.Read.All','EntitlementManagement.Read.All','DelegatedPermissionGrant.Read.All')) {
    Assert "scope declared: $need" ($srcText -match [regex]::Escape("'$need'")) $true
}
# The failed paths are still named in a comment for the record; what must not
# exist is a call to them.
Assert 'no call to security/informationProtection' ($srcText -notmatch [regex]::Escape("Uri 'security/informationProtection")) $true


# ── partial-assessment reporting ────────────────────────────────────────────
# A pillar with no scored control leaves the overall median entirely, which moves
# the result without anything improving: on the live tenant, Data going unscored
# took the overall stage from Traditional to Advanced.
function Overall($stages) {
    $s = @($stages | Where-Object { $null -ne $_ } | Sort-Object)
    if ($s.Count -eq 0) { return $null }
    if ($s.Count % 2 -eq 1) { $s[($s.Count - 1) / 2] } else { $s[($s.Count / 2) - 1] }
}
Assert 'overall with Data wrongly scored 1'  (Overall @(3,3,1,1,1,3)) 1
Assert 'overall with Data correctly unscored' (Overall @(3,3,1,$null,1,3)) 3
$map = [ordered]@{ Identities=3; Endpoints=3; Applications=1; Data=$null; Infrastructure=1; Networks=3 }
$unscored = @($map.Keys | Where-Object { $null -eq $map[$_] })
Assert 'unscored pillars identified'         ($unscored -join ',') 'Data'
Assert 'partial assessment flagged'          ($unscored.Count -gt 0) $true
$allScored = [ordered]@{ A=3; B=2 }
Assert 'fully scored assessment not flagged' (@($allScored.Keys | Where-Object { $null -eq $allScored[$_] }).Count -gt 0) $false

# result object carries the partial-assessment fields
Assert 'result declares IsPartialAssessment'  ($srcNow -match 'IsPartialAssessment') $true
Assert 'result declares UnscoredPillars'      ($srcNow -match 'UnscoredPillars') $true
# ID-08 note no longer claims a scope the collector now requests
Assert 'ID-08 note no longer claims missing scope' ($srcNow -notmatch "SSO coverage requires Application.Read.All, outside") $true


# ── formatter: partial assessments must be disclosed ────────────────────────
# The board report said "Stage 3 — Advanced" and listed Strengths with no
# indication that a whole pillar went unscored and 27 of 40 controls were manual.
$fmtSrc = [IO.File]::ReadAllText("$RepoRoot\Frameworks\Zero-Trust-Readiness-Assessment\Scripts\Format-ZTReadinessReport.ps1")
Assert 'formatter reads UnscoredPillars'        ($fmtSrc -match 'UnscoredPillars') $true
Assert 'formatter emits a partial-assessment note' ($fmtSrc -match 'partial assessment') $true
Assert 'formatter targets per-control next stage'  ($fmtSrc -match [regex]::Escape('$ctrlTarget')) $true

$tmp2 = Join-Path ([IO.Path]::GetTempPath()) ("ztra-partial-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp2 | Out-Null
$partial = [pscustomobject]@{
    TenantId='t'; AssessmentDate='2026-08-18T09:00:00Z'; CollectorVersion='v'
    OverallStage=3; IsPartialAssessment=$true; UnscoredPillars=@('Data')
    ManualReviewCount=27; GraphScopesUsed=@('x')
    Pillars=@(
      [pscustomobject]@{ Name='Identities'; Stage=3; Controls=@((Ctrl 'ID-01' 3 $false),(Ctrl 'ID-04' 2 $false)) }
      [pscustomobject]@{ Name='Data'; Stage=$null; Controls=@((Ctrl 'DA-01' $null $true)) }
    )
}
$jsonP = Join-Path $tmp2 'in.json'
$partial | ConvertTo-Json -Depth 10 | Set-Content $jsonP -Encoding UTF8
& $fmt -InputPath $jsonP -OutputPath $tmp2 *>$null
$boardTxt = Get-Content (Get-ChildItem $tmp2 -Filter '*board.md').FullName -Raw
$execTxt  = Get-Content (Get-ChildItem $tmp2 -Filter '*exec-summary.md').FullName -Raw
Assert 'board discloses the partial assessment'  ($boardTxt -match 'partial assessment') $true
Assert 'board names the unscored pillar'         ($boardTxt -match 'Data could not be scored') $true
Assert 'exec discloses the partial assessment'   ($execTxt -match 'partial assessment') $true
Assert 'Stage 2 control targets Stage 3, not 4'  ($execTxt -match 'ID-04.*from Stage 2 to Stage 3') $true

# a fully scored assessment carries no caveat
$full = [pscustomobject]@{
    TenantId='t'; AssessmentDate='2026-08-18T09:00:00Z'; CollectorVersion='v'
    OverallStage=3; IsPartialAssessment=$false; UnscoredPillars=@()
    ManualReviewCount=0; GraphScopesUsed=@('x')
    Pillars=@([pscustomobject]@{ Name='Identities'; Stage=3; Controls=@((Ctrl 'ID-01' 3 $false)) })
}
$jsonF = Join-Path $tmp2 'full.json'
$full | ConvertTo-Json -Depth 10 | Set-Content $jsonF -Encoding UTF8
$dirF = Join-Path $tmp2 'full'; New-Item -ItemType Directory -Force -Path $dirF | Out-Null
& $fmt -InputPath $jsonF -OutputPath $dirF *>$null
$boardF = Get-Content (Get-ChildItem $dirF -Filter '*board.md').FullName -Raw
Assert 'fully scored report carries no caveat'   ($boardF -match 'partial assessment') $false
Remove-Item $tmp2 -Recurse -Force -ErrorAction SilentlyContinue


# ── -TenantName carries from collector to formatter ─────────────────────────
Assert 'collector declares -TenantName'         ($srcNow -match [regex]::Escape('[string]$TenantName')) $true
Assert 'result carries TenantName'              ($srcNow -match 'TenantName        = \$TenantName') $true

$tmp3 = Join-Path ([IO.Path]::GetTempPath()) ("ztra-name-" + [Guid]::NewGuid().ToString('N'))
function NameCase($tag, $resultName, $overrideName) {
    $dir = Join-Path $tmp3 $tag
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $r = [ordered]@{
        TenantId='76b87c33-6178-4ff9-94a7-164792c8e4c6'
        AssessmentDate='2026-08-18T09:00:00Z'; CollectorVersion='v'; OverallStage=3
        IsPartialAssessment=$false; UnscoredPillars=@(); ManualReviewCount=0; GraphScopesUsed=@('x')
        Pillars=@([pscustomobject]@{ Name='Identities'; Stage=3; Controls=@((Ctrl 'ID-01' 3 $false)) })
    }
    # $null models a result file produced before the collector carried the field
    if ($null -ne $resultName) { $r.Insert(1, 'TenantName', $resultName) }
    $json = Join-Path $dir 'in.json'
    ([pscustomobject]$r) | ConvertTo-Json -Depth 10 | Set-Content $json -Encoding UTF8
    if ($overrideName) { & $fmt -InputPath $json -OutputPath $dir -TenantName $overrideName *>$null }
    else               { & $fmt -InputPath $json -OutputPath $dir *>$null }
    return (Get-ChildItem $dir -Filter '*board.md').Name
}
Assert 'name from collector used in filename'   (NameCase 'carried' 'Cloud Harbor Demo' '') 'Cloud-Harbor-Demo-2026-08-18-board.md'
Assert 'formatter override beats carried name'  (NameCase 'override' 'Cloud Harbor Demo' 'Contoso Ltd') 'Contoso-Ltd-2026-08-18-board.md'
Assert 'falls back to GUID when absent'         (NameCase 'legacy' $null '') '76b87c33-6178-4ff9-94a7-164792c8e4c6-2026-08-18-board.md'
Assert 'empty carried name falls back to GUID'  (NameCase 'blank' '' '') '76b87c33-6178-4ff9-94a7-164792c8e4c6-2026-08-18-board.md'
$carriedBoard = Get-Content (Join-Path $tmp3 'carried\Cloud-Harbor-Demo-2026-08-18-board.md') -Raw
Assert 'report header shows the friendly name'  ($carriedBoard -match 'Cloud Harbor Demo') $true
Remove-Item $tmp3 -Recurse -Force -ErrorAction SilentlyContinue


# ── a note must not contradict the signal beside it ─────────────────────────
# DA-01 said "Microsoft Purview signals are not available via Microsoft Graph"
# on a control that had just reported 4 labels read from Graph.
Assert 'DA-01 success note drops the not-available claim' `
    ($srcNow -match [regex]::Escape('sensitivity label(s) read from Microsoft Graph')) $true
Assert 'DA-01 success note no longer says unavailable' `
    ($srcNow -notmatch 'labelCount sensitivity[\s\S]{0,200}not available via Microsoft Graph') $true

# ── a pillar stage from manual controls only must be disclosed ──────────────
Assert 'technical report has a Scored column'   ($fmtSrc -match [regex]::Escape('| Pillar | Stage | Scored | Automated | Manual review |')) $true
Assert 'formatter flags partial-signal pillars' ($fmtSrc -match 'Stage rests on a partial signal') $true

$tmp4 = Join-Path ([IO.Path]::GetTempPath()) ("ztra-basis-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp4 | Out-Null
function BasisReport($tag, $controls, $stage) {
    $dir = Join-Path $tmp4 $tag; New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $r = [pscustomobject]@{
        TenantId='t'; TenantName='T'; AssessmentDate='2026-08-18T09:00:00Z'; CollectorVersion='v'
        OverallStage=$stage; IsPartialAssessment=$false; UnscoredPillars=@()
        ManualReviewCount=1; GraphScopesUsed=@('x')
        Pillars=@([pscustomobject]@{ Name='Data'; Stage=$stage; Controls=$controls })
    }
    $j = Join-Path $dir 'in.json'; $r | ConvertTo-Json -Depth 10 | Set-Content $j -Encoding UTF8
    & $fmt -InputPath $j -OutputPath $dir *>$null
    return (Get-Content (Get-ChildItem $dir -Filter '*technical.md').FullName -Raw)
}
# stage from a manual control only -> disclosed
$manualOnly = @([pscustomobject]@{ Id='DA-01'; Name='n'; NistTenets=@('T1'); RepoXRef=''; Stage=2; ManualReview=$true; ManualReviewNote='note'; Signal=@{} })
Assert 'manual-only pillar is disclosed'        ((BasisReport 'manualonly' $manualOnly 2) -match 'Stage rests on a partial signal') $true
# stage from an automated control -> no disclosure
$autoScored = @([pscustomobject]@{ Id='DA-01'; Name='n'; NistTenets=@('T1'); RepoXRef=''; Stage=2; ManualReview=$false; ManualReviewNote=''; Signal=@{} })
Assert 'automated pillar carries no disclosure' ((BasisReport 'auto' $autoScored 2) -match 'Stage rests on a partial signal') $false
Remove-Item $tmp4 -Recurse -Force -ErrorAction SilentlyContinue


# ── version strings must agree across the framework ─────────────────────────
# CollectorVersion is stamped into every result and every report, so a stale
# constant makes reports claim a version that did not produce them. The board
# 1-pager also used to hardcode it while the other two read it from the result.
$zt = "$RepoRoot\Frameworks\Zero-Trust-Readiness-Assessment"
$collectorVer = ([regex]::Match($srcNow, "\`$COLLECTOR_VERSION = '([^']+)'")).Groups[1].Value
Assert 'collector version parsed'              ($collectorVer -match '^v\d+\.\d+\.\d+') $true
Assert 'collector header matches constant'     ($srcNow -match [regex]::Escape("Version:  $collectorVer")) $true
Assert 'formatter header matches collector'    ($fmtSrc -match [regex]::Escape("Version:  $collectorVer")) $true
$ztReadme = [IO.File]::ReadAllText("$zt\README.md")
Assert 'framework README status matches'       ($ztReadme -match [regex]::Escape("ztra-$collectorVer")) $true
$rootReadme = [IO.File]::ReadAllText("$RepoRoot\README.md")
Assert 'root README row matches'               ($rootReadme -match [regex]::Escape("ztra-$collectorVer")) $true
# the board footer must read the version from the result, not hardcode it
Assert 'board footer is not hardcoded'         ($fmtSrc -notmatch [regex]::Escape("Assessment: ZTRA v0.")) $true
Assert 'board footer uses CollectorVersion'    ($fmtSrc -match [regex]::Escape('Assessment: ZTRA $($Result.CollectorVersion)')) $true
# scope notes must not name a version, or they go stale every release
Assert 'no versioned scope notes remain'       ($srcNow -notmatch 'outside v\d+\.\d+\.\d+-preview') $true
# The business case carries a version stamp that release prep updates.
$roi = [IO.File]::ReadAllText("$zt\Business-Case\ROI-ZT-READINESS.md")
Assert 'business case footer matches'          ($roi -match [regex]::Escape("ZTRA $collectorVer |")) $true
# The board template is filled by the formatter, which stamps the version from the result; a literal
# version in the template goes stale at the next release, as v0.1.0-preview did after v0.1.1.
$boardTpl = [IO.File]::ReadAllText("$zt\Examples\Board-Summary-Template.md")
Assert 'board template has no literal version' ($boardTpl -notmatch 'ZTRA v\d') $true
# Examples/Sample-Tenant-Report.md is exempt: it is genuine v0.1.0-preview output, from before v0.1.1
# added the Scored column and partial-assessment caveats, and its stamp says so truthfully. It is
# tracked for regeneration from a v0.1.1 run rather than relabelled.


""
"passed: $pass   failed: $fail"
if ($fail) { exit 1 }
