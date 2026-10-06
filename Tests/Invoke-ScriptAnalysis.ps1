#Requires -Version 7.0
<#
.SYNOPSIS
    Static-analysis gate for every PowerShell script in the repository.

.DESCRIPTION
    Fails on any parse error and on any PSScriptAnalyzer finding of severity Error. Warnings and
    Information findings are reported but do not fail the run. The repository carries several hundred
    of them (Write-Host in interactive scripts, positional parameters in test code and similar), and
    a gate on them would block every change until all were cleared.

.PARAMETER Path
    Repository root. Defaults to the parent of this script's folder.

.EXAMPLE
    ./Tests/Invoke-ScriptAnalysis.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    throw 'PSScriptAnalyzer is not installed. Run: Install-Module PSScriptAnalyzer -Scope CurrentUser'
}

$scripts = @(Get-ChildItem -Path $Path -Recurse -Filter '*.ps1' -File |
        Where-Object { $_.FullName -notmatch '[\\/](\.git|node_modules)[\\/]' } |
        Sort-Object FullName)
if ($scripts.Count -eq 0) { throw "No PowerShell scripts found under $Path." }

$parseFailures = 0
$errorFindings = [System.Collections.Generic.List[object]]::new()
$otherFindings = [System.Collections.Generic.List[object]]::new()
$inCI = [bool]$env:GITHUB_ACTIONS

foreach ($script in $scripts) {
    $relative = [IO.Path]::GetRelativePath($Path, $script.FullName) -replace '\\', '/'
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
    foreach ($e in @($parseErrors)) {
        $parseFailures++
        Write-Host "PARSE ERROR $relative`:$($e.Extent.StartLineNumber) $($e.Message)" -ForegroundColor Red
        if ($inCI) { Write-Host "::error file=$relative,line=$($e.Extent.StartLineNumber)::$($e.Message)" }
    }

    foreach ($finding in @(Invoke-ScriptAnalyzer -Path $script.FullName)) {
        $row = [pscustomobject]@{ File = $relative; Line = $finding.Line; Severity = "$($finding.Severity)"; Rule = $finding.RuleName; Message = $finding.Message }
        if ($row.Severity -eq 'Error' -or $row.Severity -eq 'ParseError') {
            $errorFindings.Add($row)
            Write-Host "ERROR $relative`:$($row.Line) $($row.Rule): $($row.Message)" -ForegroundColor Red
            if ($inCI) { Write-Host "::error file=$relative,line=$($row.Line)::$($row.Rule): $($row.Message)" }
        }
        else {
            $otherFindings.Add($row)
        }
    }
}

Write-Host ''
Write-Host "Scripts analyzed: $($scripts.Count)"
if ($otherFindings.Count -gt 0) {
    Write-Host "Non-blocking findings: $($otherFindings.Count)"
    $otherFindings | Group-Object Severity, Rule | Sort-Object Count -Descending |
        ForEach-Object { Write-Host ("  {0,4}  {1}" -f $_.Count, $_.Name) }
}

if ($parseFailures -gt 0 -or $errorFindings.Count -gt 0) {
    Write-Host "FAILED: $parseFailures parse error(s), $($errorFindings.Count) Error-severity finding(s)." -ForegroundColor Red
    exit 1
}
Write-Host 'No parse errors and no Error-severity findings.' -ForegroundColor Green
