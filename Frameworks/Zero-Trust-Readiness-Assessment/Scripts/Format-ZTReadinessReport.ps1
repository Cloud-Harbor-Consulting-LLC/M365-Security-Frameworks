#Requires -Version 7.0

<#
.SYNOPSIS
    ZTRA Formatter — generates 3 Markdown report shapes from a ZTRAResult object or JSON file.

.DESCRIPTION
    Accepts the structured PSCustomObject from Get-ZTReadinessScore.ps1 and generates:
      • <prefix>-technical.md      — control-by-control detail for security engineers
      • <prefix>-exec-summary.md   — per-pillar stages + top gaps for CISO / security leadership
      • <prefix>-board.md          — overall stage, strengths, priorities, and business risk for board

.PARAMETER Result
    The ZTRAResult PSCustomObject from Get-ZTReadinessScore.ps1. Accepts pipeline input.

.PARAMETER InputPath
    Path to a JSON file exported by Get-ZTReadinessScore.ps1 -ExportJson.

.PARAMETER OutputPath
    Directory for output files. Default: current directory.

.PARAMETER TenantName
    Optional display name used in file naming and report headers.
    Default: TenantId from the result object.

.EXAMPLE
    $result = .\Get-ZTReadinessScore.ps1 -TenantId 'xxxx'
    .\Format-ZTReadinessReport.ps1 -Result $result -OutputPath '.\Reports' -TenantName 'Contoso'

.EXAMPLE
    .\Format-ZTReadinessReport.ps1 -InputPath '.\ZTRAResult-20260717-123456.json' -OutputPath '.\Reports' -TenantName 'Contoso'

.NOTES
    Version:  v0.1.0-preview
    Author:   Cloud Harbor Consulting LLC
    Requires: PowerShell 7+
#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName='Object', Mandatory, ValueFromPipeline)]
    [ValidateNotNull()][PSCustomObject]$Result,

    [Parameter(ParameterSetName='File', Mandatory)]
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

# ── Constants ─────────────────────────────────────────────────────────────────

$stageLabels = @{ 1 = 'Traditional'; 2 = 'Initial'; 3 = 'Advanced'; 4 = 'Optimal' }
$stageDesc   = @{
    1 = 'Manual configurations, static policies, no cross-pillar visibility. Reactive posture.'
    2 = 'Automation starting. Initial risk-based access decisions emerging. Some lifecycle management still manual.'
    3 = 'Automated lifecycles. Centralized visibility and analytics. Dynamic risk-based access. Cross-pillar integration active.'
    4 = 'Fully automated JIT and dynamic least privilege. Continuous monitoring with automated response. Complete cross-pillar integration.'
}

$dateStr     = ([datetime]::Parse($Result.AssessmentDate)).ToString('yyyy-MM-dd')
$tenantLabel = if ($TenantName) { $TenantName } else { $Result.TenantId }
$filePrefix  = ($tenantLabel -replace '[^\w\-]', '-') + "-$dateStr"
# ConvertFrom-Json emits numbers as Int64; the stage lookup tables are keyed by Int32,
# so normalize here or every $stageLabels/$stageDesc lookup silently misses and renders empty.
$overallStage = if ($null -ne $Result.OverallStage) { [int]$Result.OverallStage } else { $null }

# ── Helper functions ──────────────────────────────────────────────────────────

function Get-StageBadge {
    param([nullable[int]]$Stage)
    if ($null -eq $Stage) { return 'Manual review required' }
    switch ($Stage) {
        1 { 'Stage 1 — Traditional' }
        2 { 'Stage 2 — Initial'     }
        3 { 'Stage 3 — Advanced'    }
        4 { 'Stage 4 — Optimal'     }
    }
}

function Get-TopGaps {
    param([PSCustomObject]$Pillar, [int]$Count = 3)
    $pillarStage = $Pillar.Stage
    $gaps = @($Pillar.Controls | Where-Object {
        ($null -ne $_.Stage -and ($null -eq $pillarStage -or $_.Stage -lt $pillarStage)) -or
        ($_.ManualReview -and $null -eq $_.Stage)
    } | Sort-Object { if ($null -ne $_.Stage) { $_.Stage } else { 0 } })
    return $gaps | Select-Object -First $Count
}

function Get-NextStageActions {
    param([PSCustomObject]$Pillar)
    $current = $Pillar.Stage
    if ($null -eq $current) {
        return @("Complete manual review for all $($Pillar.Name) controls to establish a baseline stage score.")
    }
    if ($current -ge 4) { return @('Maintain Optimal configuration. Schedule quarterly review to detect drift.') }
    $nextStage      = $current + 1
    $laggingControls = @($Pillar.Controls |
        Where-Object { $null -ne $_.Stage -and $_.Stage -lt $nextStage } |
        Sort-Object Stage | Select-Object -First 3)
    $actions = @()
    foreach ($ctrl in $laggingControls) {
        $actions += "Advance $($ctrl.Id) ($($ctrl.Name)) from Stage $($ctrl.Stage) to Stage $nextStage."
    }
    if ($actions.Count -eq 0) {
        $actions += "Review ManualReview controls in this pillar to verify Stage $nextStage coverage."
    }
    return $actions
}

# ── Technical report ──────────────────────────────────────────────────────────

$t = [System.Collections.Generic.List[string]]::new()

$t.Add('# ZTRA Technical Report')
$t.Add('')
$t.Add("**Tenant:** $tenantLabel  ")
$t.Add("**Assessment date:** $dateStr  ")
$t.Add("**Collector version:** $($Result.CollectorVersion)  ")
$t.Add("**Overall stage:** $(Get-StageBadge $overallStage)  ")
$t.Add("**Manual review controls:** $($Result.ManualReviewCount) of 40  ")
$t.Add('')
$t.Add('---')
$t.Add('')
$t.Add('## Pillar summary')
$t.Add('')
$t.Add('| Pillar | Stage | Automated | Manual review |')
$t.Add('|---|---|---|---|')
foreach ($p in $Result.Pillars) {
    $auto   = @($p.Controls | Where-Object { -not $_.ManualReview }).Count
    $manual = @($p.Controls | Where-Object { $_.ManualReview }).Count
    $t.Add("| $($p.Name) | $(Get-StageBadge $p.Stage) | $auto | $manual |")
}
$t.Add('')
$t.Add('---')
$t.Add('')

foreach ($p in $Result.Pillars) {
    $t.Add("## $($p.Name)")
    $t.Add('')
    $t.Add("**Pillar stage:** $(Get-StageBadge $p.Stage)")
    $t.Add('')
    $t.Add('| Control | Stage | NIST Tenets | Repo X-Ref | Manual Review |')
    $t.Add('|---|---|---|---|---|')
    foreach ($ctrl in $p.Controls) {
        $stageStr  = if ($null -ne $ctrl.Stage) { Get-StageBadge $ctrl.Stage } else { '—' }
        $xref      = if ($ctrl.RepoXRef) { $ctrl.RepoXRef } else { '—' }
        $manualStr = if ($ctrl.ManualReview) { 'Yes' } else { 'No' }
        $t.Add("| **$($ctrl.Id)** $($ctrl.Name) | $stageStr | $($ctrl.NistTenets -join ', ') | $xref | $manualStr |")
    }
    $t.Add('')

    foreach ($ctrl in $p.Controls | Where-Object { $_.ManualReview -or $ctrl.Signal.Count -gt 0 }) {
        if ($ctrl.ManualReview -and $ctrl.ManualReviewNote) {
            $t.Add("> **$($ctrl.Id) — Manual review required:** $($ctrl.ManualReviewNote)")
            $t.Add('')
        }
    }

    $t.Add('---')
    $t.Add('')
}

$t.Add("*Report generated by ZTRA Collector $($Result.CollectorVersion) — Cloud Harbor Consulting LLC*")

$techFile = Join-Path $OutputPath "$filePrefix-technical.md"
$t | Set-Content -Path $techFile -Encoding UTF8
Write-Host "  ✓ Technical report:    $techFile"

# ── Executive summary ─────────────────────────────────────────────────────────

$e = [System.Collections.Generic.List[string]]::new()

$e.Add('# ZTRA Executive Summary')
$e.Add('')
$e.Add("**Tenant:** $tenantLabel  ")
$e.Add("**Assessment date:** $dateStr  ")
$e.Add("**Overall maturity stage:** $(Get-StageBadge $overallStage)  ")
$e.Add('')
if ($null -ne $overallStage) {
    $e.Add("> $($stageDesc[$overallStage])")
    $e.Add('')
}
$e.Add('---')
$e.Add('')
$e.Add('## Per-pillar maturity')
$e.Add('')
$e.Add('| Pillar | Stage | Top gaps |')
$e.Add('|---|---|---|')
foreach ($p in $Result.Pillars) {
    $gaps    = Get-TopGaps -Pillar $p -Count 3
    $gapStr  = if ($gaps.Count -gt 0) { ($gaps | ForEach-Object { $_.Id }) -join ', ' } else { 'None identified at this stage' }
    $e.Add("| **$($p.Name)** | $(Get-StageBadge $p.Stage) | $gapStr |")
}
$e.Add('')
$e.Add('---')
$e.Add('')
$e.Add('## Recommended next actions')
$e.Add('')
foreach ($p in $Result.Pillars) {
    $e.Add("### $($p.Name) — $(Get-StageBadge $p.Stage)")
    $e.Add('')
    foreach ($action in (Get-NextStageActions -Pillar $p)) {
        $e.Add("- $action")
    }
    $e.Add('')
}
$e.Add('---')
$e.Add('')
$e.Add('## Manual review items')
$e.Add('')
$e.Add("$($Result.ManualReviewCount) controls require portal-based assessment. Review each control's ``ManualReviewNote`` in the technical report for exact portal navigation instructions.")
$e.Add('')
$e.Add("*Report generated by ZTRA Collector $($Result.CollectorVersion) — Cloud Harbor Consulting LLC*")

$execFile = Join-Path $OutputPath "$filePrefix-exec-summary.md"
$e | Set-Content -Path $execFile -Encoding UTF8
Write-Host "  ✓ Executive summary:   $execFile"

# ── Board 1-pager ─────────────────────────────────────────────────────────────

$strengths  = @($Result.Pillars | Where-Object { $null -ne $_.Stage -and $_.Stage -ge 3 } | Select-Object -First 3)
$priorities = @($Result.Pillars | Where-Object { $null -eq $_.Stage -or $_.Stage -le 2  } |
    Sort-Object { if ($null -ne $_.Stage) { $_.Stage } else { -1 } } | Select-Object -First 3)

$pathFwd = if ($null -ne $overallStage -and $overallStage -lt 4) {
    "Advancing to Stage $($overallStage + 1) ($($stageLabels[$overallStage + 1])) across all pillars is the recommended next objective. Targeted remediation of the top-priority gaps identified in the executive summary typically requires 3–6 months for organizations at this stage."
} else {
    'The organization is at Optimal stage. Maintain configuration and schedule a reassessment in 12 months to detect drift.'
}

$b = [System.Collections.Generic.List[string]]::new()

$b.Add('# Zero Trust Readiness — Board Summary')
$b.Add('')
$b.Add("**Organization:** $tenantLabel  ")
$b.Add("**Assessment date:** $dateStr  ")
$b.Add("**Assessment framework:** CISA Zero Trust Maturity Model v2.0  ")
$b.Add('')
$b.Add('---')
$b.Add('')
$b.Add('## Overall maturity')
$b.Add('')
$b.Add("**$(Get-StageBadge $overallStage)**")
$b.Add('')
if ($null -ne $overallStage) { $b.Add($stageDesc[$overallStage]) }
$b.Add('')
$b.Add('The organization was assessed across Microsoft''s 6 Zero Trust pillars. Scores reflect current Microsoft 365 and Entra ID configuration state.')
$b.Add('')

$b.Add('| Pillar | Maturity stage |')
$b.Add('|---|---|')
foreach ($p in $Result.Pillars) {
    $b.Add("| $($p.Name) | $(Get-StageBadge $p.Stage) |")
}
$b.Add('')
$b.Add('---')
$b.Add('')
$b.Add('## Strengths')
$b.Add('')
if ($strengths.Count -gt 0) {
    foreach ($s in $strengths) {
        $b.Add("- **$($s.Name)** ($($stageLabels[[int]$s.Stage])): Controls in this pillar meet or exceed the Advanced threshold, indicating automated lifecycle management and dynamic access controls are in place.")
    }
} else {
    $b.Add('- No pillars have reached Stage 3 (Advanced) yet. All pillars have gaps that present security and compliance risk.')
}
$b.Add('')
$b.Add('---')
$b.Add('')
$b.Add('## Top priorities')
$b.Add('')
if ($priorities.Count -gt 0) {
    foreach ($p in $priorities) {
        $stageStr = if ($null -ne $p.Stage) { "$($stageLabels[[int]$p.Stage]) (Stage $($p.Stage))" } else { 'stage not yet established — manual review required' }
        $b.Add("- **$($p.Name)** is currently at $stageStr. Advancing this pillar reduces the risk of credential theft, lateral movement, and unauthorized data access.")
    }
} else {
    $b.Add('- All pillars are at Stage 3 (Advanced) or above. Focus is on closing remaining Optimal-stage gaps.')
}
$b.Add('')
$b.Add('---')
$b.Add('')
$b.Add('## Business risk context')
$b.Add('')
$b.Add('Organizations at Stage 1–2 rely on manual controls and static policies. This posture increases the likelihood of:')
$b.Add('')
$b.Add('- **Credential attacks succeeding** — phishing, password spray, and MFA fatigue are the most common initial access vectors in M365 environments.')
$b.Add('- **Lateral movement going undetected** — without device compliance enforcement and endpoint telemetry, an attacker who gains access to one account can move freely.')
$b.Add('- **Data leaving without visibility** — without sensitivity labels and DLP enforcement, sensitive data can be exfiltrated or shared externally without triggering an alert.')
$b.Add('')
$b.Add('The IBM Cost of a Data Breach 2024 report places the average breach cost at $4.88M globally ($9.36M in the United States). IBM''s 2021 report, the most recent edition to publish a Zero Trust-specific breakdown, found that organizations with a mature Zero Trust strategy averaged $3.28M per breach compared with $5.04M for organizations that had not deployed Zero Trust, a difference of $1.76M.')
$b.Add('')
$b.Add('---')
$b.Add('')
$b.Add('## Path forward')
$b.Add('')
$b.Add($pathFwd)
$b.Add('')
$b.Add('The executive summary and technical report identify the specific configuration changes required at the control level, prioritized by pillar stage gap.')
$b.Add('')
$b.Add('---')
$b.Add('')
$b.Add('*Assessment: ZTRA v0.1.0-preview | Framework: CISA ZTMM v2.0 | Methodology: NIST SP 800-207 | Delivered by Cloud Harbor Consulting LLC*')

$boardFile = Join-Path $OutputPath "$filePrefix-board.md"
$b | Set-Content -Path $boardFile -Encoding UTF8
Write-Host "  ✓ Board 1-pager:       $boardFile"

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  All 3 reports generated.'
Write-Host "    Technical report:   $filePrefix-technical.md"
Write-Host "    Executive summary:  $filePrefix-exec-summary.md"
Write-Host "    Board 1-pager:      $filePrefix-board.md"
Write-Host ''
