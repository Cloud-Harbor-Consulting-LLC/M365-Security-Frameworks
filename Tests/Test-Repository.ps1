#Requires -Version 7.0
<#
.SYNOPSIS
    Repository consistency checks that need no tenant: JSON validity, relative links, and the
    invariants the frameworks' own documentation claims.

.DESCRIPTION
    Checks:
      1. Every JSON file parses.
      2. Every relative link in every Markdown file resolves to a file or folder that exists.
      3. Every Conditional Access Baseline template ships in report-only state, and its displayName
         matches its file name (the CA Baseline README promises both).
      4. The Board & Executive Policy Kit's copy of Board-Posture-Summary.md is byte-identical to the
         canonical one in Examples/ (the kit README promises this).

    Runs on Windows and Linux.

.PARAMETER Path
    Repository root. Defaults to the parent of this script's folder.

.EXAMPLE
    ./Tests/Test-Repository.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$inCI = [bool]$env:GITHUB_ACTIONS
$failures = [System.Collections.Generic.List[string]]::new()
function Add-Failure {
    param([string]$Check, [string]$File, [string]$Message)
    $failures.Add("[$Check] $File - $Message")
    if ($inCI) { Write-Host "::error file=$File::$Message" }
}
function Get-RepoFile {
    param([string]$Filter)
    @(Get-ChildItem -Path $Path -Recurse -Filter $Filter -File |
            Where-Object { $_.FullName -notmatch '[\\/](\.git|node_modules)[\\/]' } |
            Sort-Object FullName)
}
function Get-Relative([string]$Full) { [IO.Path]::GetRelativePath($Path, $Full) -replace '\\', '/' }

# -- 1. JSON parses -----------------------------------------------------------
$jsonFiles = Get-RepoFile '*.json'
foreach ($f in $jsonFiles) {
    try { $null = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json -Depth 100 }
    catch { Add-Failure 'json' (Get-Relative $f.FullName) "does not parse: $($_.Exception.Message)" }
}
Write-Host "JSON files checked: $($jsonFiles.Count)"

# -- 2. Relative Markdown links resolve ---------------------------------------
$mdFiles = Get-RepoFile '*.md'
$linkCount = 0
foreach ($f in $mdFiles) {
    $text = Get-Content -Path $f.FullName -Raw
    # Links inside fenced code blocks and inline code are examples, not links.
    $text = [regex]::Replace($text, '(?ms)^\s*```.*?^\s*```', '')
    $text = [regex]::Replace($text, '`[^`\r\n]*`', '')
    foreach ($m in [regex]::Matches($text, '\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)')) {
        $target = $m.Groups[1].Value
        if ($target -match '^(https?|mailto|ftp):' -or $target.StartsWith('#')) { continue }
        $target = ($target -split '[#?]')[0]
        if (-not $target) { continue }
        $target = [Uri]::UnescapeDataString($target)
        $resolved = Join-Path $f.DirectoryName $target
        $linkCount++
        if (-not (Test-Path -LiteralPath $resolved)) {
            Add-Failure 'link' (Get-Relative $f.FullName) "broken relative link: $($m.Groups[1].Value)"
        }
    }
}
Write-Host "Markdown files checked: $($mdFiles.Count); relative links checked: $linkCount"

# -- 3. CA Baseline templates: report-only, name matches file -----------------
$caPolicies = Join-Path $Path 'Frameworks' 'Conditional-Access-Baseline' 'Policies'
$caTemplates = @(Get-ChildItem -Path $caPolicies -Filter '*.json' -File)
foreach ($f in $caTemplates) {
    $policy = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json -Depth 100
    $state = if ($policy.PSObject.Properties['state']) { $policy.state } else { '<missing>' }
    $name = if ($policy.PSObject.Properties['displayName']) { $policy.displayName } else { '<missing>' }
    if ($state -ne 'enabledForReportingButNotEnforced') {
        Add-Failure 'ca-state' (Get-Relative $f.FullName) "state is '$state'; templates must ship report-only (enabledForReportingButNotEnforced)"
    }
    if ($name -ne $f.BaseName) {
        Add-Failure 'ca-name' (Get-Relative $f.FullName) "displayName '$name' does not match the file name"
    }
}
Write-Host "CA Baseline templates checked: $($caTemplates.Count)"

# -- 4. Policy Kit copy matches the canonical template ------------------------
$srdr = Join-Path $Path 'Frameworks' 'Security-Reporting-Decision-Rubric'
$canonical = Join-Path $srdr 'Examples' 'Board-Posture-Summary.md'
$kitCopy = Join-Path $srdr 'Board-Executive-Policy-Kit' 'Board-Posture-Summary.md'
if ((Test-Path $canonical) -and (Test-Path $kitCopy)) {
    if ((Get-FileHash $canonical).Hash -ne (Get-FileHash $kitCopy).Hash) {
        Add-Failure 'kit-copy' (Get-Relative $kitCopy) 'differs from Examples/Board-Posture-Summary.md; edit the canonical file and re-copy'
    }
    Write-Host 'Policy Kit copy checked.'
}
else {
    Add-Failure 'kit-copy' 'Frameworks/Security-Reporting-Decision-Rubric' 'Board-Posture-Summary.md missing from Examples/ or Board-Executive-Policy-Kit/'
}

Write-Host ''
if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    Write-Host "FAILED: $($failures.Count) problem(s)." -ForegroundColor Red
    exit 1
}
Write-Host 'Repository checks passed.' -ForegroundColor Green
