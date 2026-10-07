#Requires -Version 7.0
# Regression harness for Get-ITPScorecard.ps1: throttle-aware retry, Retry-After handling, paging under throttling.
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
foreach ($n in 'Write-Status','Get-ITPSProp','Get-ITPSErrorSummary','Get-ITPSRetryDelay','Invoke-ITPSGraphSend','Invoke-ITPSGraphRequest') {
    $fn = $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)
    if (-not $fn) { throw "missing $n" }
    . ([scriptblock]::Create($fn[0].Extent.Text))
}

$pass = 0; $fail = 0
function Assert($label, $actual, $expected) {
    $ok = ("$actual" -eq "$expected"); if ($ok) { $script:pass++ } else { $script:fail++ }
    "{0}  {1,-56} got={2,-14} want={3}" -f $(if($ok){'PASS'}else{'FAIL'}), $label, $actual, $expected
}

# Silence the operator status lines during the test
function Write-Status { param($Message, $Level) }
# No real sleeping in tests
$script:slept = @()
function Start-Sleep { param([int]$Seconds) $script:slept += $Seconds }

# ---- Retry-After parsing ---------------------------------------------------
Assert 'Retry-After honoured (dict of string[])' (Get-ITPSRetryDelay -Headers @{ 'Retry-After' = @('17') } -Attempt 1) 17
Assert 'Retry-After honoured (plain string)'     (Get-ITPSRetryDelay -Headers @{ 'Retry-After' = '9' }   -Attempt 1) 9
Assert 'missing header -> exponential backoff'   (Get-ITPSRetryDelay -Headers @{} -Attempt 3) 8
Assert 'null headers -> exponential backoff'     (Get-ITPSRetryDelay -Headers $null -Attempt 4) 16
Assert 'absurd Retry-After capped at 60'         (Get-ITPSRetryDelay -Headers @{ 'Retry-After' = '9999' } -Attempt 1) 60
Assert 'unparseable Retry-After -> backoff'      (Get-ITPSRetryDelay -Headers @{ 'Retry-After' = 'soon' } -Attempt 2) 4
Assert 'backoff never returns 0'                 (Get-ITPSRetryDelay -Headers @{} -Attempt 0) 1

# ---- Error summarising -----------------------------------------------------
# Derek's actual note text: four concatenated JSON bodies, 1,600+ chars.
$realError = ((1..4 | ForEach-Object {
  '(HTTP request failed with status code: TooManyRequests.{"error":{"code":"TooManyRequests","message":"Too many requests. Please try again later.","innerError":{"date":"2026-08-17T18:48:37","request-id":"17a6285c-654b-48e2-af52-665861ef4898","client-request-id":"4aa3712a-ab19-494d-a3d4-223865c2641c"}}})'
}) -join ' ')
$summary = Get-ITPSErrorSummary $realError
Assert 'real 429 error was over 1000 chars' ($realError.Length -gt 1000) $true
Assert 'summary capped at 200 + marker'     ($summary.Length -le 240)    $true
Assert 'summary keeps the useful prefix'    ($summary -like '*HTTP request failed with status code: TooManyRequests*' -and $summary -like '*Too many requests*') $true
Assert 'empty error handled'                (Get-ITPSErrorSummary '') 'no error detail returned'

# ---- Retry behaviour against a mocked Graph -------------------------------
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
$okBody = [pscustomobject]@{ value = @([pscustomobject]@{ id = '1' }) }
$err429 = [pscustomobject]@{ error = [pscustomobject]@{ code = 'TooManyRequests'; message = 'Too many requests. Please try again later.' } }
$err403 = [pscustomobject]@{ error = [pscustomobject]@{ code = 'Authorization_RequestDenied'; message = 'Insufficient privileges.' } }

# 429 twice then success
$script:calls = 0; $script:slept = @()
$script:plan = @(
  @{ Status = 429; Headers = @{ 'Retry-After' = @('2') }; Body = $err429 },
  @{ Status = 429; Headers = @{ 'Retry-After' = @('3') }; Body = $err429 },
  @{ Status = 200; Headers = @{};                          Body = $okBody }
)
$r = @(Invoke-ITPSGraphRequest -Uri 'identityGovernance/accessReviews/definitions')
Assert 'recovers after 2 throttles'   $r.Count 1
Assert 'issued exactly 3 requests'    $script:calls 3
Assert 'slept per Retry-After (2,3)'  ($script:slept -join ',') '2,3'

# throttled past MaxRetry -> throws, and the message is short
$script:calls = 0; $script:slept = @()
$script:plan = @(@{ Status = 429; Headers = @{ 'Retry-After' = @('1') }; Body = $err429 })
$threw = $false; $msg = ''
try { Invoke-ITPSGraphRequest -Uri 'identityGovernance/accessReviews/definitions' -MaxRetry 3 | Out-Null }
catch { $threw = $true; $msg = $_.Exception.Message }
Assert 'gives up after MaxRetry'      $threw $true
Assert 'attempts = 1 + MaxRetry'      $script:calls 4
Assert 'message names status + count' ($msg -like 'Graph returned HTTP 429*after 3 retries*') $true
Assert 'message stays short'          ($msg.Length -lt 200) $true

# non-transient 403 -> immediate throw, no retries, no sleeping
$script:calls = 0; $script:slept = @()
$script:plan = @(@{ Status = 403; Headers = @{}; Body = $err403 })
$threw = $false; $msg = ''
try { Invoke-ITPSGraphRequest -Uri 'applications' | Out-Null } catch { $threw = $true; $msg = $_.Exception.Message }
Assert '403 throws immediately'   $threw $true
Assert '403 issues 1 request'     $script:calls 1
Assert '403 never sleeps'         $script:slept.Count 0
Assert '403 surfaces Graph detail' ($msg -like '*Insufficient privileges.*') $true

# paging still works and a mid-page throttle recovers
$script:calls = 0; $script:slept = @()
$page1 = [pscustomobject]@{ value = @([pscustomobject]@{ id='1' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/next' }
$page2 = [pscustomobject]@{ value = @([pscustomobject]@{ id='2' }) }
$script:plan = @(
  @{ Status = 200; Headers = @{}; Body = $page1 },
  @{ Status = 429; Headers = @{ 'Retry-After' = @('1') }; Body = $err429 },
  @{ Status = 200; Headers = @{}; Body = $page2 }
)
$r = @(Invoke-ITPSGraphRequest -Uri 'applications')
Assert 'paging survives mid-page throttle' $r.Count 2
Assert 'mid-page retry issued 3 requests'  $script:calls 3

# FirstPageOnly unaffected
$script:calls = 0
$script:plan = @(@{ Status = 200; Headers = @{}; Body = $page1 })
$r = @(Invoke-ITPSGraphRequest -Uri 'security/secureScores?$top=1' -FirstPageOnly)
Assert 'FirstPageOnly still 1 request' $script:calls 1

""
"passed: $pass   failed: $fail"
if ($fail) { exit 1 }
