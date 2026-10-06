#Requires -Version 7.0
<#
.SYNOPSIS
    Runs every regression harness under Tests/ and fails if any assertion fails.

.DESCRIPTION
    Each *.Harness.ps1 runs in its own PowerShell process, so the global mocks one harness defines
    cannot leak into another.

    A harness passes only when it exits 0 AND prints a closing "passed: N   failed: 0" line with N
    greater than zero. A harness that crashes, exits non-zero, or never prints its summary counts as
    failed, so a broken harness cannot pass silently.

.PARAMETER Path
    Folder to search for *.Harness.ps1 files. Defaults to the folder this script is in.

.EXAMPLE
    ./Tests/Invoke-Tests.ps1
#>
[CmdletBinding()]
param(
    [string]$Path = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$harnesses = @(Get-ChildItem -Path $Path -Recurse -Filter '*.Harness.ps1' -File | Sort-Object FullName)
if ($harnesses.Count -eq 0) { throw "No *.Harness.ps1 files found under $Path." }

# Run each harness with the same pwsh that is running this script.
$pwsh = (Get-Process -Id $PID).Path
$inCI = [bool]$env:GITHUB_ACTIONS
$summaryPattern = '^passed:\s*(\d+)\s+failed:\s*(\d+)'

$results = foreach ($harness in $harnesses) {
    $relative = [IO.Path]::GetRelativePath($Path, $harness.FullName)
    $output = @(& $pwsh -NoProfile -NonInteractive -File $harness.FullName 2>&1 | ForEach-Object { "$_" })
    $exitCode = $LASTEXITCODE

    $passed = 0
    $failed = 0
    $summary = @($output | Where-Object { $_ -match $summaryPattern }) | Select-Object -Last 1
    if ($summary -and $summary -match $summaryPattern) {
        $passed = [int]$Matches[1]
        $failed = [int]$Matches[2]
    }
    $ok = ($exitCode -eq 0) -and [bool]$summary -and ($failed -eq 0) -and ($passed -gt 0)

    if (-not $ok) {
        Write-Host "`n--- $relative ---" -ForegroundColor Red
        $failLines = @($output | Where-Object { $_ -like 'FAIL*' })
        if ($failLines.Count -gt 0) {
            $failLines | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        }
        else {
            # No assertion failed, so the harness itself broke. Show how it ended.
            Write-Host "  exit code $exitCode; $(if ($summary) { 'summary present' } else { 'no summary line' }). Last lines:" -ForegroundColor Red
            $output | Select-Object -Last 25 | ForEach-Object { Write-Host "    $_" }
        }
        if ($inCI) { Write-Host "::error file=Tests/$($relative -replace '\\', '/')::$relative failed ($failed failed, exit $exitCode)" }
    }

    [pscustomobject]@{
        Harness = $relative
        Passed  = $passed
        Failed  = $failed
        Exit    = $exitCode
        Result  = if ($ok) { 'PASS' } else { 'FAIL' }
    }
}

Write-Host ''
$results | Format-Table Harness, Passed, Failed, Exit, Result -AutoSize | Out-String -Width 200 | Write-Host
$totalPassed = ($results | Measure-Object Passed -Sum).Sum
$totalFailed = ($results | Measure-Object Failed -Sum).Sum
$broken = @($results | Where-Object Result -eq 'FAIL')
Write-Host ("{0} harnesses, {1} assertions passed, {2} failed." -f $results.Count, $totalPassed, $totalFailed)

if ($broken.Count -gt 0) {
    Write-Host "FAILED: $($broken.Harness -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host 'All harnesses passed.' -ForegroundColor Green
