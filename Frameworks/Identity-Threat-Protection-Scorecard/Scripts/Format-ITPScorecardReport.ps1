#Requires -Version 7.0
<#
.SYNOPSIS
    ITPS Formatter — generates 3 Markdown report shapes from an ITPSResult object or JSON file.
.DESCRIPTION
    Accepts the structured PSCustomObject from Get-ITPScorecard.ps1 and generates:
      - <prefix>-technical.md      check-by-check detail for security engineers
      - <prefix>-exec-summary.md   dimension scores and top gaps for the CISO
      - <prefix>-board.md          overall tier, strengths, priorities, and business risk

    Numeric values are normalised with [int] on read because ConvertFrom-Json emits
    Int64, which silently fails equality and lookup against Int32 literals.
.PARAMETER Result
    The ITPSResult PSCustomObject from Get-ITPScorecard.ps1. Accepts pipeline input.
.PARAMETER InputPath
    Path to a JSON file exported by Get-ITPScorecard.ps1 -ExportJson.
.PARAMETER OutputPath
    Directory for output files. Default: current directory.
.PARAMETER TenantName
    Optional display name used in file naming and report headers. Overrides the
    TenantName carried in the result object by the collector. When neither is
    supplied, reports fall back to the tenant GUID.
.EXAMPLE
    $result = .\Get-ITPScorecard.ps1 -TenantId 'xxxx'
    .\Format-ITPScorecardReport.ps1 -Result $result -OutputPath '.\Reports' -TenantName 'Fabrikam'
.EXAMPLE
    .\Format-ITPScorecardReport.ps1 -InputPath '.\ITPSResult-20260813-090000.json' -OutputPath '.\Reports'
.NOTES
    Version:  v0.1.1-preview
    Author:   Cloud Harbor Consulting LLC
    Requires: PowerShell 7+
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive operator tool. Progress and output paths are intentionally written to the host.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseProcessBlockForPipelineCommand', '',
    Justification = 'A single ITPSResult object is formatted per invocation by design. Pipeline binding is a convenience for the common one-object case; batching multiple tenant results is not a supported scenario for this script.')]
[CmdletBinding()]
param(
    [Parameter(ParameterSetName = 'Object', Mandatory, ValueFromPipeline)]
    [ValidateNotNull()][PSCustomObject]$Result,

    [Parameter(ParameterSetName = 'File', Mandatory)]
    [ValidateNotNullOrEmpty()][string]$InputPath,

    [string]$OutputPath = '.',
    [string]$TenantName = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Load result ───────────────────────────────────────────────────────────────

if ($PSCmdlet.ParameterSetName -eq 'File') {
    if (-not (Test-Path $InputPath)) { throw "InputPath not found: $InputPath" }
    $Result = Get-Content $InputPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

# ── Helpers ───────────────────────────────────────────────────────────────────

function Get-ITPSValue {
    # Null-safe property read. Guards against Set-StrictMode PropertyNotFoundException
    # when a JSON payload omits an optional property.
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [object]$InputObject,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        $Default = $null
    )
    if ($null -eq $InputObject) { return $Default }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop -or $null -eq $prop.Value) { return $Default }
    return $prop.Value
}

function Get-ScoreLabel {
    [OutputType([string])]
    [CmdletBinding()]
    param([object]$Score)
    if ($null -eq $Score) { return 'Not scored' }
    return "$([int]$Score) / 100"
}

function Get-TierForScore {
    # Comparison-based rather than hashtable-keyed, so an Int64 from ConvertFrom-Json
    # behaves identically to an Int32 from a live collector run.
    [OutputType([string])]
    [CmdletBinding()]
    param([object]$Score)
    if ($null -eq $Score) { return 'Not scored' }
    $s = [int]$Score
    if ($s -ge 85) { return 'Resilient' }
    if ($s -ge 65) { return 'Fortified' }
    if ($s -ge 40) { return 'Protected' }
    return 'Connected'
}

function Get-TierDescription {
    [OutputType([string])]
    [CmdletBinding()]
    param([string]$Tier)
    switch ($Tier) {
        # These describe what the tier band means, not what this tenant has covered.
        # They previously read as findings — "Broad coverage across human and non-human
        # identities" was printed on a board report whose only non-human identity check
        # had scored zero. The dimension table carries the tenant's actual position.
        'Resilient' { 'The highest band: near-complete coverage of the measured controls, with named ownership and a feedback loop when a control degrades. See the dimension scores for where this tenant stands.' }
        'Fortified' { 'Most measured controls are in place and detection is validated rather than assumed. Remaining gaps are named in the dimension scores below.' }
        'Protected' { 'Key identities and key controls are covered. Real gaps remain, usually in non-human identities or in who owns the controls.' }
        'Connected' { 'Some identity telemetry exists and some controls are configured, but protection is partial and inconsistently applied.' }
        default { 'Score not established. Complete the manual checks to produce a tier.' }
    }
}

function Get-DimensionGap {
    # Returns the lowest-scoring checks in a dimension: scored checks that fell short
    # of their maximum first, then manual checks that were never assessed.
    #
    # -ScoredOnly omits the manual checks. A check with no API and no score is not a
    # gap in the tenant's controls — it is an unmeasured area — and presenting the two
    # in one list told a reader that a dimension scoring 100/100 still had a gap.
    [OutputType([object[]])]
    [CmdletBinding()]
    param([object]$Dimension, [int]$Count = 3, [switch]$ScoredOnly)
    $checks = @(Get-ITPSValue -InputObject $Dimension -Name 'Checks' -Default @())
    $missed = @($checks | Where-Object {
            -not (Get-ITPSValue -InputObject $_ -Name 'ManualReview' -Default $false) -and
            [double](Get-ITPSValue -InputObject $_ -Name 'Points' -Default 0) -lt
            [double](Get-ITPSValue -InputObject $_ -Name 'MaxPoints' -Default 0)
        } | Sort-Object { [double](Get-ITPSValue -InputObject $_ -Name 'Points' -Default 0) })
    if ($ScoredOnly) { return @($missed | Select-Object -First $Count) }
    $manual = @($checks | Where-Object { Get-ITPSValue -InputObject $_ -Name 'ManualReview' -Default $false })
    return @($missed + $manual | Select-Object -First $Count)
}

# ── Derived values ────────────────────────────────────────────────────────────

$assessmentDateRaw = Get-ITPSValue -InputObject $Result -Name 'AssessmentDate' -Default (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
$dateStr = ([datetime]::Parse($assessmentDateRaw)).ToString('yyyy-MM-dd')
$tenantId = Get-ITPSValue -InputObject $Result -Name 'TenantId' -Default 'unknown-tenant'

# Display-name precedence:
#   1. -TenantName passed to this script  (explicit override wins)
#   2. TenantName carried in the ITPSResult from the collector
#   3. the tenant GUID
# Step 2 is read defensively so that result files produced before the collector
# carried TenantName still format correctly.
$resultTenantName = Get-ITPSValue -InputObject $Result -Name 'TenantName' -Default ''
$tenantLabel = if ($TenantName) { $TenantName }
elseif (-not [string]::IsNullOrWhiteSpace([string]$resultTenantName)) { [string]$resultTenantName }
else { $tenantId }
$filePrefix = ($tenantLabel -replace '[^\w\-]', '-') + "-$dateStr"

$overallRaw = Get-ITPSValue -InputObject $Result -Name 'OverallScore'
$overallScore = if ($null -ne $overallRaw) { [int]$overallRaw } else { $null }
$tier = Get-TierForScore -Score $overallScore
$collectorVersion = Get-ITPSValue -InputObject $Result -Name 'CollectorVersion' -Default 'v0.1.0-preview'
$dimensions = @(Get-ITPSValue -InputObject $Result -Name 'Dimensions' -Default @())
$manualCount = [int](Get-ITPSValue -InputObject $Result -Name 'ManualReviewCount' -Default 0)
$totalChecks = [int](Get-ITPSValue -InputObject $Result -Name 'TotalCheckCount' -Default 0)
$isPartial = [bool](Get-ITPSValue -InputObject $Result -Name 'IsPartialScore' -Default $false)
$unscored = @(Get-ITPSValue -InputObject $Result -Name 'UnscoredDimensions' -Default @())

$tierDisclosure = 'Tier bands are a Cloud Harbor Consulting scoring convention. Microsoft does not publish numeric thresholds for its Connected, Protected, Fortified, and Resilient tiers, and an ITPS tier will not necessarily match the tier shown on the Defender Coverage and maturity page.'

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
}

# ── Technical report ──────────────────────────────────────────────────────────

$t = [System.Collections.Generic.List[string]]::new()
$t.Add('# ITPS Technical Report')
$t.Add('')
$t.Add("**Tenant:** $tenantLabel  ")
$t.Add("**Assessment date:** $dateStr  ")
$t.Add("**Collector version:** $collectorVersion  ")
$t.Add("**Overall score:** $(Get-ScoreLabel $overallScore) — $tier  ")
$t.Add("**Manual review checks:** $manualCount of $totalChecks  ")
$t.Add('')
if ($isPartial) {
    $t.Add("> **Partial score.** Unscored dimensions: $($unscored -join ', '). Treat the overall score as an upper bound; completing the manual checks can only lower it.")
    $t.Add('')
}
$t.Add('---')
$t.Add('')
$t.Add('## Dimension summary')
$t.Add('')
$t.Add('| Dimension | Weight | Score | Automated checks | Manual checks |')
$t.Add('|---|---|---|---|---|')
foreach ($d in $dimensions) {
    $checks = @(Get-ITPSValue -InputObject $d -Name 'Checks' -Default @())
    $auto = @($checks | Where-Object { -not (Get-ITPSValue -InputObject $_ -Name 'ManualReview' -Default $false) }).Count
    $man = @($checks | Where-Object { Get-ITPSValue -InputObject $_ -Name 'ManualReview' -Default $false }).Count
    $t.Add("| $(Get-ITPSValue -InputObject $d -Name 'Name') | $(Get-ITPSValue -InputObject $d -Name 'Weight' -Default 25)% | $(Get-ScoreLabel (Get-ITPSValue -InputObject $d -Name 'Score')) | $auto | $man |")
}
$t.Add('')
$t.Add('---')
$t.Add('')

foreach ($d in $dimensions) {
    $t.Add("## $(Get-ITPSValue -InputObject $d -Name 'Name')")
    $t.Add('')
    $t.Add("**Dimension score:** $(Get-ScoreLabel (Get-ITPSValue -InputObject $d -Name 'Score'))")
    $t.Add('')
    $t.Add('| Check | Points | Max | Repo X-Ref | Manual |')
    $t.Add('|---|---|---|---|---|')
    foreach ($c in @(Get-ITPSValue -InputObject $d -Name 'Checks' -Default @())) {
        $isManual = [bool](Get-ITPSValue -InputObject $c -Name 'ManualReview' -Default $false)
        $pts = if ($isManual) { '—' } else { (Get-ITPSValue -InputObject $c -Name 'Points' -Default 0) }
        $max = if ($isManual) { '—' } else { (Get-ITPSValue -InputObject $c -Name 'MaxPoints' -Default 0) }
        $xref = Get-ITPSValue -InputObject $c -Name 'RepoXRef' -Default ''
        if ([string]::IsNullOrWhiteSpace($xref)) { $xref = '—' }
        $t.Add("| **$(Get-ITPSValue -InputObject $c -Name 'Id')** $(Get-ITPSValue -InputObject $c -Name 'Name') | $pts | $max | $xref | $(if ($isManual) { 'Yes' } else { 'No' }) |")
    }
    $t.Add('')
    foreach ($c in @(Get-ITPSValue -InputObject $d -Name 'Checks' -Default @())) {
        $note = Get-ITPSValue -InputObject $c -Name 'ManualReviewNote' -Default ''
        if (-not [string]::IsNullOrWhiteSpace($note)) {
            $t.Add("> **$(Get-ITPSValue -InputObject $c -Name 'Id') — manual review:** $note")
            $t.Add('')
        }
    }
    $t.Add('---')
    $t.Add('')
}

$t.Add("*$tierDisclosure*")
$t.Add('')
$t.Add("*Report generated by ITPS Collector $collectorVersion — Cloud Harbor Consulting LLC*")

$techFile = Join-Path $OutputPath "$filePrefix-technical.md"
$t | Set-Content -Path $techFile -Encoding UTF8
Write-Host "  [ok] Technical report:   $techFile"

# ── Executive summary ─────────────────────────────────────────────────────────

$e = [System.Collections.Generic.List[string]]::new()
$e.Add('# ITPS Executive Summary')
$e.Add('')
$e.Add("**Tenant:** $tenantLabel  ")
$e.Add("**Assessment date:** $dateStr  ")
$e.Add("**Overall score:** $(Get-ScoreLabel $overallScore) — $tier  ")
$e.Add('')
$e.Add("> $(Get-TierDescription -Tier $tier)")
$e.Add('')
if ($isPartial) {
    $e.Add("**This is a partial score.** The following dimensions were not scored: $($unscored -join ', '). They require manual assessment. Treat the overall score as an upper bound.")
    $e.Add('')
}
$e.Add('---')
$e.Add('')
$e.Add('## Dimension scores')
$e.Add('')
$e.Add('| Dimension | Score | Tier equivalent | Scored gaps | Not assessed |')
$e.Add('|---|---|---|---|---|')
foreach ($d in $dimensions) {
    $ds = Get-ITPSValue -InputObject $d -Name 'Score'
    # Wrapped in @() because a function returning an empty collection unrolls to
    # nothing, leaving the result as $null and making .Count throw under strict mode.
    # A dimension with every check at full points and no manual checks hits this.
    #
    # Scored gaps and manual checks are reported in separate columns. They were
    # previously merged under a single "Top gaps" heading, which listed unassessed
    # checks as gaps — so Detection at 100/100 appeared to have a gap in D-05, a
    # check that has no API and was never scored at all.
    $checks = @(Get-ITPSValue -InputObject $d -Name 'Checks' -Default @())
    $gaps = @(Get-DimensionGap -Dimension $d -Count 3 -ScoredOnly)
    $manual = @($checks | Where-Object { Get-ITPSValue -InputObject $_ -Name 'ManualReview' -Default $false })
    $gapStr = if ($gaps.Count -gt 0) {
        ($gaps | ForEach-Object { Get-ITPSValue -InputObject $_ -Name 'Id' }) -join ', '
    }
    else { 'None' }
    $manualStr = if ($manual.Count -gt 0) {
        ($manual | Select-Object -First 3 | ForEach-Object { Get-ITPSValue -InputObject $_ -Name 'Id' }) -join ', '
    }
    else { '—' }
    $e.Add("| **$(Get-ITPSValue -InputObject $d -Name 'Name')** | $(Get-ScoreLabel $ds) | $(Get-TierForScore -Score $ds) | $gapStr | $manualStr |")
}
$e.Add('')
$e.Add('---')
$e.Add('')
$e.Add('## Recommended next actions')
$e.Add('')
foreach ($d in $dimensions) {
    $e.Add("### $(Get-ITPSValue -InputObject $d -Name 'Name') — $(Get-ScoreLabel (Get-ITPSValue -InputObject $d -Name 'Score'))")
    $e.Add('')
    # Wrapped in @() because a function returning an empty collection unrolls to
    # nothing, leaving $gaps as $null and making $gaps.Count throw under strict mode.
    # A dimension with every check at full points and no manual checks hits this.
    $gaps = @(Get-DimensionGap -Dimension $d -Count 3)
    if ($gaps.Count -eq 0) {
        $e.Add('- All checks in this dimension earned full points. Maintain and reassess next cycle.')
    }
    else {
        foreach ($g in $gaps) {
            $gid = Get-ITPSValue -InputObject $g -Name 'Id'
            $gname = Get-ITPSValue -InputObject $g -Name 'Name'
            if (Get-ITPSValue -InputObject $g -Name 'ManualReview' -Default $false) {
                $e.Add("- Assess **$gid** ($gname) manually. $(Get-ITPSValue -InputObject $g -Name 'ManualReviewNote' -Default '')")
            }
            else {
                $e.Add("- Close **$gid** ($gname). Currently $(Get-ITPSValue -InputObject $g -Name 'Points' -Default 0) of $(Get-ITPSValue -InputObject $g -Name 'MaxPoints' -Default 0) points.")
            }
        }
    }
    $e.Add('')
}
$e.Add('---')
$e.Add('')
$e.Add('## Manual review items')
$e.Add('')
$e.Add("$manualCount of $totalChecks checks require manual assessment. Each check's manual review note in the technical report gives the exact portal navigation. The Ownership dimension is manual in full, because ownership is an organisational fact rather than a tenant configuration.")
$e.Add('')
$e.Add("*$tierDisclosure*")
$e.Add('')
$e.Add("*Report generated by ITPS Collector $collectorVersion — Cloud Harbor Consulting LLC*")

$execFile = Join-Path $OutputPath "$filePrefix-exec-summary.md"
$e | Set-Content -Path $execFile -Encoding UTF8
Write-Host "  [ok] Executive summary:  $execFile"

# ── Board 1-pager ─────────────────────────────────────────────────────────────

$scoredDims = @($dimensions | Where-Object { $null -ne (Get-ITPSValue -InputObject $_ -Name 'Score') })
$strengths = @($scoredDims | Where-Object { [int](Get-ITPSValue -InputObject $_ -Name 'Score') -ge 65 })
$priorities = @($scoredDims | Where-Object { [int](Get-ITPSValue -InputObject $_ -Name 'Score') -lt 65 } |
    Sort-Object { [int](Get-ITPSValue -InputObject $_ -Name 'Score') })

$b = [System.Collections.Generic.List[string]]::new()
$b.Add('# Identity Threat Protection — Board Summary')
$b.Add('')
$b.Add("**Organization:** $tenantLabel  ")
$b.Add("**Assessment date:** $dateStr  ")
$b.Add('**Assessment framework:** Identity Threat Protection Scorecard (ITPS)  ')
$b.Add('')
$b.Add('---')
$b.Add('')
$b.Add('## Overall identity protection maturity')
$b.Add('')
$b.Add("**$(Get-ScoreLabel $overallScore) — $tier**")
$b.Add('')
$b.Add((Get-TierDescription -Tier $tier))
$b.Add('')
$b.Add('The organization was assessed across 4 dimensions of identity threat protection, weighted equally. Scores reflect current Microsoft 365 and Entra ID configuration.')
$b.Add('')
$b.Add('| Dimension | Score |')
$b.Add('|---|---|')
foreach ($d in $dimensions) {
    $b.Add("| $(Get-ITPSValue -InputObject $d -Name 'Name') | $(Get-ScoreLabel (Get-ITPSValue -InputObject $d -Name 'Score')) |")
}
$b.Add('')
if ($isPartial) {
    $b.Add("**Note:** this is a partial assessment. $($unscored -join ', ') could not be scored automatically and requires manual review. The overall figure is an upper bound.")
    $b.Add('')
}
$b.Add('---')
$b.Add('')
$b.Add('## Strengths')
$b.Add('')
if ($strengths.Count -gt 0) {
    foreach ($s in $strengths) {
        $b.Add("- **$(Get-ITPSValue -InputObject $s -Name 'Name')** scored $(Get-ScoreLabel (Get-ITPSValue -InputObject $s -Name 'Score')). Controls in this dimension are broadly in place and operating.")
    }
}
else {
    $b.Add('- No dimension has reached the Fortified threshold. Every dimension carries gaps that present security risk.')
}
$b.Add('')
$b.Add('---')
$b.Add('')
$b.Add('## Top priorities')
$b.Add('')
if ($priorities.Count -gt 0) {
    foreach ($p in $priorities) {
        $b.Add("- **$(Get-ITPSValue -InputObject $p -Name 'Name')** scored $(Get-ScoreLabel (Get-ITPSValue -InputObject $p -Name 'Score')). Advancing this dimension reduces the risk of credential compromise, undetected intrusion, or unmanaged privileged access.")
    }
}
else {
    $b.Add('- All scored dimensions are at Fortified or above. Focus is on closing the remaining gaps to reach Resilient.')
}
if ($unscored.Count -gt 0) {
    $b.Add("- **$($unscored -join ', ')** could not be measured automatically. Until assessed, the organization cannot demonstrate that these controls have an accountable owner.")
}
$b.Add('')
$b.Add('---')
$b.Add('')
$b.Add('## Business risk context')
$b.Add('')
$b.Add('Identity is the primary control plane for Microsoft 365. An attacker who obtains a valid credential inherits whatever access that identity holds, and the controls that limit the damage are the ones measured here:')
$b.Add('')
$b.Add('- **Prevention** determines whether a stolen credential can be used at all.')
$b.Add('- **Detection** determines whether an intrusion is noticed, and how quickly.')
$b.Add('- **Governance** determines how much access a compromised account inherits.')
$b.Add('- **Ownership** determines whether a degraded control is noticed before an attacker finds it.')
$b.Add('')
$b.Add('The IBM Cost of a Data Breach 2025 report places the average breach cost at $4.44M globally and $10.22M in the United States, an all-time high for any region. Phishing was the most common initial attack vector, accounting for 16% of breaches.')
$b.Add('')
$b.Add('---')
$b.Add('')
$b.Add('## Path forward')
$b.Add('')
if ($null -ne $overallScore -and $tier -ne 'Resilient') {
    $b.Add("Advancing beyond the $tier tier is the recommended next objective. The executive summary identifies the specific checks that are unmet, ranked by dimension, so remediation can be sequenced against the gaps that carry the most risk.")
}
else {
    $b.Add('Maintain current configuration and reassess on the agreed cadence. The value of this score decays from the day it is measured unless ownership is active.')
}
$b.Add('')
$b.Add("*$tierDisclosure*")
$b.Add('')
$b.Add("*Assessment: ITPS $collectorVersion | Delivered by Cloud Harbor Consulting LLC*")

$boardFile = Join-Path $OutputPath "$filePrefix-board.md"
$b | Set-Content -Path $boardFile -Encoding UTF8
Write-Host "  [ok] Board 1-pager:      $boardFile"

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  All 3 reports generated.'
Write-Host "    Technical report:  $filePrefix-technical.md"
Write-Host "    Executive summary: $filePrefix-exec-summary.md"
Write-Host "    Board 1-pager:     $filePrefix-board.md"
Write-Host ''
