#Requires -Version 7.0
# Regression harness for Deploy-CABaseline.ps1: default policy path, placeholder coverage and expansion over every template, the
# Trusted IPs resolver, and the CA policy cross-references printed by the ITPS and ZTRA collectors.
#
# Self-contained: extracts the shipped functions via AST and mocks Graph, so it needs no tenant and no
# network. Prints PASS/FAIL per assertion and a closing 'passed: N   failed: M' line; exits 1 on any
# failure. Run all harnesses with Tests/Invoke-Tests.ps1.
<#
    Offline harness for Deploy-CABaseline.ps1.

    Deploy-CABaseline is the only script in this repo that writes to a tenant, so
    it cannot be exercised end to end from a test. Everything up to the point of
    the write is pure text handling — locate the templates, resolve placeholders,
    refuse to deploy a template still carrying one — and that is what this covers.

    Functions are extracted from the shipped file via AST rather than
    reimplemented, so the harness fails if the shipped logic changes underneath it.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Repository root, resolved from this file's location (Tests/<Framework>/), so the harness
# runs from any checkout, including CI.
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path

$script:Passed = 0
$script:Failed = 0
function Assert-Equal {
    param($Name, $Got, $Want)
    $ok = ($Got -eq $Want)
    if ($ok) { $script:Passed++ } else { $script:Failed++ }
    "{0}  {1,-58} got={2,-18} want={3}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $Name, $Got, $Want
}

$repo       = $RepoRoot
$framework  = Join-Path $repo 'Frameworks\Conditional-Access-Baseline'
$scriptDir  = Join-Path $framework 'Scripts'
$deployPath = Join-Path $scriptDir 'Deploy-CABaseline.ps1'

$errs = $null; $toks = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($deployPath, [ref]$toks, [ref]$errs)
Assert-Equal 'shipped script parses' $errs.Count 0

# ── Pull the real Expand-Placeholders out of the shipped file ────────────────
$fn = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -eq 'Expand-Placeholders' }, $true)
Assert-Equal 'Expand-Placeholders found' $fn.Count 1
. ([scriptblock]::Create($fn[0].Extent.Text))

# ── 1. The documented default -PolicyPath actually resolves ─────────────────
# Regression: the default was (Join-Path $PSScriptRoot '\' 'Policies'). Join-Path
# treats the bare separator as a path segment, so it produced Scripts\Policies —
# a directory that has never existed — and the script threw before reading a
# single template. Any invocation relying on the default failed.
$paramBlock = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'PolicyPath' }
Assert-Equal 'PolicyPath parameter exists' ($null -ne $paramBlock) $true

$defaultExpr = $paramBlock.DefaultValue.Extent.Text
Assert-Equal 'default no longer uses a bare separator' ($defaultExpr -notmatch "'\\\\'") $true

$PSScriptRoot_stub = $scriptDir
$resolved = & ([scriptblock]::Create($defaultExpr.Replace('$PSScriptRoot', "'$scriptDir'")))
Assert-Equal 'default -PolicyPath exists' (Test-Path $resolved) $true

$defaultTemplates = @(if (Test-Path $resolved) { Get-ChildItem -Path $resolved -Filter '*.json' -File })
Assert-Equal 'default path finds all 28 policies' $defaultTemplates.Count 28
Assert-Equal 'resolved path is Policies, not Scripts\Policies' `
    $(if (Test-Path $resolved) { (Resolve-Path $resolved).Path.TrimEnd('\') } else { $resolved }) `
    ((Join-Path $framework 'Policies').TrimEnd('\'))

# Everything below reads the canonical Policies directory rather than whatever
# the default resolved to, so a regression in the default path does not mask the
# placeholder and cross-reference checks.
$policyDir = Join-Path $framework 'Policies'
$templates = @(Get-ChildItem -Path $policyDir -Filter '*.json' -File)
Assert-Equal 'canonical Policies dir holds 28 templates' $templates.Count 28

# ── 2. Every placeholder the templates use has a resolver ───────────────────
# The eager substitution map covered 10 of the 12 placeholders in use. Terms of
# Use was resolved lazily; REPLACE_WITH_TRUSTED_IPS_LOCATION_ID had no resolver
# at all, so CA-COV010 always tripped the unresolved-placeholder guard.
# $substitutions is assigned twice — an empty @{} at declaration, then the real
# map — so take the populated one.
$hashes = @($ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left.Extent.Text -eq '$substitutions' }, $true) |
        ForEach-Object { $_.Right.FindAll({ param($m)
                    $m -is [System.Management.Automation.Language.HashtableAst] }, $true) } |
        Where-Object { $_.KeyValuePairs.Count -gt 0 })
Assert-Equal 'substitution map found' $hashes.Count 1
$mapKeys = @($hashes[0].KeyValuePairs | ForEach-Object { $_.Item1.Extent.Text.Trim("'") })
# Derived from the script, not hardcoded — otherwise the orphan check below
# would credit a resolver that does not exist.
$lazyKeys = @([regex]::Matches($ast.Extent.Text,
        "if \(\`$expandedJson -match '(REPLACE_WITH_[A-Z_]+)'\)") |
    ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
Assert-Equal 'lazy resolvers found' $lazyKeys.Count 2
foreach ($k in @('REPLACE_WITH_TERMS_OF_USE_ID', 'REPLACE_WITH_TRUSTED_IPS_LOCATION_ID')) {
    Assert-Equal "lazy resolver present: $k" ($k -in $lazyKeys) $true
}

$used = @($templates | ForEach-Object {
        [regex]::Matches((Get-Content $_.FullName -Raw), 'REPLACE_WITH_[A-Z_]+')
    } | ForEach-Object { $_.Value } | Sort-Object -Unique)
$covered = @($mapKeys) + $lazyKeys
Assert-Equal 'placeholders in templates' $used.Count 12
Assert-Equal 'eager map covers 10' @($mapKeys).Count 10
$orphans = @($used | Where-Object { $_ -notin $covered })
Assert-Equal 'placeholders with no resolver' $orphans.Count 0
if ($orphans.Count) { $orphans | ForEach-Object { "      ORPHAN: $_" } }

# ── 3. Replay the whole expansion offline and confirm the guard never fires ──
# Mirrors the loop in the shipped script: eager map, then each lazy resolver,
# then the "Unresolved placeholders remain" throw.
$fake = @{}
foreach ($k in $mapKeys) { $fake[$k] = [guid]::NewGuid().ToString() }
$script:TouLookups   = 0
$script:TrustedLooks = 0
$script:TouId        = $null
$script:TrustedId    = $null

$guardTrips = 0
$badJson    = 0
$trustedTemplates = @()
foreach ($t in $templates) {
    $raw = Get-Content -Path $t.FullName -Raw
    $expanded = Expand-Placeholders -JsonContent $raw -Substitutions $fake

    # Only the lazy resolvers the script actually declares get to run here, so a
    # missing resolver surfaces as a tripped guard rather than being papered over.
    foreach ($k in $lazyKeys) {
        if ($expanded -notmatch $k) { continue }
        if ($k -eq 'REPLACE_WITH_TRUSTED_IPS_LOCATION_ID') {
            $trustedTemplates += $t.Name
            if (-not $script:TrustedId) {
                $script:TrustedLooks++
                $script:TrustedId = [guid]::NewGuid().ToString()   # stands in for Resolve-NamedLocationId
            }
            $expanded = $expanded -replace $k, $script:TrustedId
        }
        else {
            if (-not $script:TouId) {
                $script:TouLookups++
                $script:TouId = [guid]::NewGuid().ToString()
            }
            $expanded = $expanded -replace $k, $script:TouId
        }
    }

    if ($expanded -match 'REPLACE_WITH_') { $guardTrips++; "      GUARD TRIPPED: $($t.Name)" }
    try { $expanded | ConvertFrom-Json -AsHashtable | Out-Null } catch { $badJson++; "      BAD JSON: $($t.Name) — $_" }
}
Assert-Equal 'templates tripping the unresolved guard' $guardTrips 0
Assert-Equal 'templates failing to parse after expansion' $badJson 0

# ── 4. Lazy means lazy: one lookup, only for the template that needs it ─────
# Resolving Trusted IPs eagerly would call Graph for a named location that most
# tenants do not have, failing all 28 policies instead of the one that uses it.
Assert-Equal 'Trusted IPs resolved exactly once' $script:TrustedLooks 1
Assert-Equal 'Trusted IPs used by one template' $trustedTemplates.Count 1
Assert-Equal 'that template is CA-COV010' `
    ($trustedTemplates.Count -eq 1 -and $trustedTemplates[0] -like 'CA-COV010*') $true
Assert-Equal 'Terms of Use resolved exactly once' $script:TouLookups 1

# ── 5. Default location name matches what the policy doc tells you to create ─
$docPath = Join-Path $framework 'Policies\CA-COV010-WorkloadIdentities.md'
$doc = Get-Content $docPath -Raw
$nameParam = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TrustedIpsLocationName' }
Assert-Equal 'TrustedIpsLocationName parameter exists' ($null -ne $nameParam) $true
$defaultName = if ($nameParam) { $nameParam.DefaultValue.Extent.Text.Trim("'") } else { '<absent>' }
Assert-Equal 'default name documented in CA-COV010 doc' ($doc -match [regex]::Escape($defaultName)) $true
Assert-Equal 'default name is Trusted IPs' $defaultName 'Trusted IPs'

# ── 6. Cross-reference accuracy for the two collectors ──────────────────────
# RepoXRef strings name the CA policy that satisfies a control. They are printed
# into client reports, so a wrong ID sends a reader to a policy that does not do
# what the control says.
$policyIds = @($templates | ForEach-Object { ($_.BaseName -split '-')[0..1] -join '-' } | Sort-Object -Unique)
$collectors = @{
    'ITPS' = Join-Path $repo 'Frameworks\Identity-Threat-Protection-Scorecard\Scripts\Get-ITPScorecard.ps1'
    'ZTRA' = Join-Path $repo 'Frameworks\Zero-Trust-Readiness-Assessment\Scripts\Get-ZTReadinessScore.ps1'
}
# Both collectors use range notation (CA-SIG008-010) alongside single IDs, so a
# reference expands to every ID it spans and each end must exist.
function Expand-XRef {
    param([string]$Ref)
    if ($Ref -match '^(CA-[A-Z]+)(\d{3})-(\d{3})$') {
        $prefix = $Matches[1]
        [int]$Matches[2]..[int]$Matches[3] | ForEach-Object { '{0}{1:D3}' -f $prefix, $_ }
    }
    else { $Ref }
}
foreach ($name in $collectors.Keys) {
    $text = Get-Content $collectors[$name] -Raw
    $refs = @([regex]::Matches($text, "-RepoXRef '([^']+)'") | ForEach-Object { $_.Groups[1].Value } |
        ForEach-Object { $_ -split ',\s*' } | Where-Object { $_ -match '^CA-' } |
        ForEach-Object { Expand-XRef $_ } | Sort-Object -Unique)
    $unknown = @($refs | Where-Object { $_ -notin $policyIds })
    Assert-Equal "$name RepoXRef IDs all exist in Policies/" $unknown.Count 0
    if ($unknown.Count) { $unknown | ForEach-Object { "      UNKNOWN: $_" } }
}

# Legacy auth is blocked by CA-COV001, not CA-SIG001 (Sensitive-Apps compliant
# device). Both collectors cited SIG001 for a legacy-auth control.
# Read the RepoXRef bound inside each control's own declaration. A regex that
# simply scans forward from the control id will run on into the next control's
# block and report whatever it finds there.
function Get-XRefFor {
    param([string]$Path, [string]$Id)
    $text = Get-Content $Path -Raw
    # Split on the constructor call so each segment holds exactly one control.
    $segments = $text -split '(?=New-(?:ITPSCheck|ZTControl) -Id )'
    $seg = $segments | Where-Object { $_ -match "^New-(?:ITPSCheck|ZTControl) -Id '$([regex]::Escape($Id))'" }
    if (-not $seg) { return "<no block for $Id>" }
    if ($seg -match "-RepoXRef '([^']+)'") { return $Matches[1] }
    return "<no RepoXRef>"
}
Assert-Equal 'ITPS P-03 cites CA-COV001' (Get-XRefFor $collectors['ITPS'] 'P-03') 'CA-COV001'
Assert-Equal 'ZTRA ID-03 cites CA-COV001' (Get-XRefFor $collectors['ZTRA'] 'ID-03') 'CA-COV001'
Assert-Equal 'ZTRA EP-03 cites the compliant-device policies' `
    (Get-XRefFor $collectors['ZTRA'] 'EP-03') 'CA-COV008, CA-SIG001, CA-COV014'
Assert-Equal 'ZTRA ID-01 cites the MFA policies' `
    (Get-XRefFor $collectors['ZTRA'] 'ID-01') 'CA-COV002, CA-COV001'
# CA-AUT003 is RequireAdminAuthOnAdminPortals — nothing to do with device compliance.
Assert-Equal 'CA-AUT003 no longer cited for device compliance' `
    ((Get-Content $collectors['ZTRA'] -Raw) -notmatch 'CA-AUT003') $true

# ── 7. A missing Trusted IPs location gets guidance that exists ─────────────
# The resolver's generic "not found" message says to provision from
# Supporting-Artifacts/, but no template exists for Trusted IPs (its ranges are
# tenant-specific). The shipped lazy block is executed here against a mocked
# resolver, not re-implemented.
$trustedIf = @($ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.IfStatementAst] -and
            $n.Clauses[0].Item1.Extent.Text -like "*REPLACE_WITH_TRUSTED_IPS_LOCATION_ID*" }, $true))
Assert-Equal 'Trusted IPs lazy block found' $trustedIf.Count 1
$trustedBlock = [scriptblock]::Create($trustedIf[0].Extent.Text)
$TrustedIpsLocationName = 'Trusted IPs'

function Invoke-TrustedBlock([scriptblock]$Resolver) {
    Set-Item -Path function:global:Resolve-NamedLocationId -Value $Resolver
    $script:TrustedIpsLocationId = $null
    $expandedJson = '{"excludeLocations":["REPLACE_WITH_TRUSTED_IPS_LOCATION_ID"]}'
    try { . $trustedBlock; [pscustomobject]@{ Error = $null; Json = $expandedJson } }
    catch { [pscustomobject]@{ Error = $_.Exception.Message; Json = $expandedJson } }
}

$notFound = { param($DisplayName) throw "Named location not found in tenant: '$DisplayName'. Provision it from Supporting-Artifacts/ before running this script." }
$r = Invoke-TrustedBlock $notFound
Assert-Equal 'missing location: points at CA-COV010 doc' ($r.Error -like '*CA-COV010-WorkloadIdentities.md*') $true
Assert-Equal 'missing location: no Supporting-Artifacts instruction' ($r.Error -like '*Provision it from Supporting-Artifacts*') $false
Assert-Equal 'missing location: names the parameter' ($r.Error -like '*-TrustedIpsLocationName*') $true

$duplicate = { param($DisplayName) throw "Multiple named locations found with displayName '$DisplayName'. Ensure the name is unique." }
$r = Invoke-TrustedBlock $duplicate
Assert-Equal 'duplicate location: original error kept' ($r.Error -like 'Multiple named locations found*') $true

$found = { param($DisplayName) 'aaaa-1111' }
$r = Invoke-TrustedBlock $found
Assert-Equal 'found location: no error' $r.Error $null
Assert-Equal 'found location: placeholder replaced' ($r.Json -like '*aaaa-1111*' -and $r.Json -notlike '*REPLACE_WITH_*') $true

"`npassed: $script:Passed   failed: $script:Failed"
if ($script:Failed) { exit 1 }
