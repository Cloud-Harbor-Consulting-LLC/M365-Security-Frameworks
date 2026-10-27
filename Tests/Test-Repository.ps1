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
      5. Every Intune Compliance Baseline template meets the invariants Deploy-ICBaseline.ps1
         relies on, and classic templates use only properties and types the live tenant returns.

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

# -- 5. ICB templates: the invariants Deploy-ICBaseline relies on ---------------
# Name matches the file; a shape the deployer recognizes; one schedule with exactly one
# mark-noncompliant (block) action; email actions use the notification placeholder; a persona
# assignment and no other placeholder. Classic templates whose type has a live read-back fixture
# also have every property checked against it: the name must exist on the live object and the
# value must have the live type (the first ICB-WIN001 shipped signatureOutOfDate as 1, a number,
# where Graph's type is Boolean).
$icbPolicies = Join-Path $Path 'Frameworks' 'Intune-Compliance-Baseline' 'Policies'
$icbTemplates = @(Get-ChildItem -Path $icbPolicies -Filter '*.json' -File)
$liveFixtures = @{
    '#microsoft.graph.windows10CompliancePolicy' = Join-Path $Path 'Tests' 'Intune-Compliance-Baseline' 'Fixtures' 'Live' 'classic-readback.json'
}
# Properties a live read-back returns as null carry no type; these are Graph's documented types.
$declaredTypes = @{
    passwordMinimumLength = 'number'; passwordMinutesOfInactivityBeforeLock = 'number'; passwordPreviousPasswordBlockCount = 'number'
    passwordExpirationDays = 'number'; passwordMinimumCharacterSetCount = 'number'
    defenderVersion = 'string'; osMinimumVersion = 'string'; osMaximumVersion = 'string'; mobileOsMinimumVersion = 'string'; mobileOsMaximumVersion = 'string'
}
$nonSettings = @('@odata.type', 'displayName', 'name', 'description', 'roleScopeTagIds', 'scheduledActionsForRule', 'assignments', 'settings', 'platforms', 'technologies')
function Get-JsonKind($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return 'boolean' }
    if ($Value -is [string]) { return 'string' }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return 'number' }
    if ($Value -is [System.Collections.IDictionary]) { return 'object' }
    if ($Value -is [System.Collections.IList]) { return 'array' }
    return $Value.GetType().Name
}
$liveCache = @{}
foreach ($f in $icbTemplates) {
    $rel = Get-Relative $f.FullName
    $raw = Get-Content -Path $f.FullName -Raw
    $t = $raw | ConvertFrom-Json -AsHashtable -Depth 100
    $type = [string]$t['@odata.type']
    $classic = $type -like '#microsoft.graph.*CompliancePolicy' -and $type -ne '#microsoft.graph.deviceManagementCompliancePolicy'
    $catalog = (-not $classic) -and $t.ContainsKey('platforms') -and $t.ContainsKey('settings')
    if (-not ($classic -or $catalog)) { Add-Failure 'icb-shape' $rel "neither a classic compliance policy (per-platform @odata.type) nor a Settings Catalog policy (platforms and settings)"; continue }
    $name = if ($classic) { [string]$t['displayName'] } else { [string]$t['name'] }
    if ($name -ne $f.BaseName) { Add-Failure 'icb-name' $rel "$(if ($classic) { 'displayName' } else { 'name' }) '$name' does not match the file name" }

    $rules = @($t['scheduledActionsForRule'] | Where-Object { $null -ne $_ })
    if ($rules.Count -ne 1) { Add-Failure 'icb-schedule' $rel "has $($rules.Count) scheduledActionsForRule entries; exactly one is required" }
    else {
        $actions = @($rules[0]['scheduledActionConfigurations'] | Where-Object { $null -ne $_ })
        $blocks = @($actions | Where-Object { $_['actionType'] -eq 'block' })
        if ($blocks.Count -ne 1) { Add-Failure 'icb-schedule' $rel "has $($blocks.Count) block (mark noncompliant) actions; exactly one is required" }
        foreach ($a in @($actions | Where-Object { $_['actionType'] -eq 'notification' })) {
            if ($a['notificationTemplateId'] -ne 'REPLACE_WITH_NOTIFICATION_TEMPLATE_ID') { Add-Failure 'icb-schedule' $rel "an email action must use REPLACE_WITH_NOTIFICATION_TEMPLATE_ID, not '$($a['notificationTemplateId'])'" }
        }
    }
    $groups = @($t['assignments'] | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_['target']['groupId'] })
    if ($groups.Count -eq 0) { Add-Failure 'icb-assignment' $rel 'has no group assignment' }
    foreach ($g in $groups) {
        if ($g -notmatch '^REPLACE_WITH_ICB_PERSONA_(CORPWINDOWS|CORPMAC|CORPMOBILE|BYODMOBILE|CORPLINUX)_GROUP_OBJECT_ID$') { Add-Failure 'icb-assignment' $rel "assignment target '$g' is not a persona placeholder" }
    }
    foreach ($m in [regex]::Matches($raw, 'REPLACE_WITH_[A-Z_]+')) {
        if ($m.Value -ne 'REPLACE_WITH_NOTIFICATION_TEMPLATE_ID' -and $m.Value -notmatch '^REPLACE_WITH_ICB_PERSONA_(CORPWINDOWS|CORPMAC|CORPMOBILE|BYODMOBILE|CORPLINUX)_GROUP_OBJECT_ID$') { Add-Failure 'icb-placeholder' $rel "unknown placeholder $($m.Value)" }
    }

    if ($classic -and $liveFixtures.ContainsKey($type)) {
        if (-not $liveCache.ContainsKey($type)) { $liveCache[$type] = Get-Content -Path $liveFixtures[$type] -Raw | ConvertFrom-Json -AsHashtable -Depth 100 }
        $live = $liveCache[$type]
        foreach ($key in @($t.Keys | Where-Object { $_ -notin $nonSettings })) {
            if (-not $live.ContainsKey($key)) { Add-Failure 'icb-property' $rel "'$key' is not a property of $type as the live tenant returns it"; continue }
            $want = if ($null -ne $live[$key]) { Get-JsonKind $live[$key] } elseif ($declaredTypes.ContainsKey($key)) { $declaredTypes[$key] } else { $null }
            if (-not $want) { Add-Failure 'icb-property' $rel "'$key' has no known type (live value is null); add it to the declared types"; continue }
            $have = Get-JsonKind $t[$key]
            if ($have -ne $want) { Add-Failure 'icb-type' $rel "'$key' is a $have; Graph's type is $want" }
        }
    }
}
Write-Host "ICB templates checked: $($icbTemplates.Count)"

Write-Host ''
if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host $_ -ForegroundColor Red }
    Write-Host "FAILED: $($failures.Count) problem(s)." -ForegroundColor Red
    exit 1
}
Write-Host 'Repository checks passed.' -ForegroundColor Green
