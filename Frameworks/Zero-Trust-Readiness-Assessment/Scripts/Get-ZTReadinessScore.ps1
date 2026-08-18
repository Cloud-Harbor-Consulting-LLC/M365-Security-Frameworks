#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    ZTRA Collector — Zero Trust Readiness Assessment evidence gatherer.
.DESCRIPTION
    Read-only Microsoft Graph assessment across the ZTRA 6-pillar rubric.
    Produces a structured PSCustomObject consumed by Format-ZTReadinessReport.ps1.
    Controls outside Microsoft Graph scope are flagged ManualReview = $true
    with portal navigation instructions.
.PARAMETER TenantId
    The Entra tenant ID to assess. This is the tenant GUID and is used to authenticate.
.PARAMETER TenantName
    Optional friendly display name for the organisation, carried through into the
    ZTRAResult object. Format-ZTReadinessReport.ps1 uses it for report headers and
    output filenames, so supplying it here means it does not have to be repeated at
    format time. When omitted, reports fall back to the tenant GUID.
.PARAMETER OutputPath
    Directory path for JSON export when -ExportJson is specified. Default: current directory.
.PARAMETER ExportJson
    When present, exports the result object to a timestamped JSON file in OutputPath.
.EXAMPLE
    .\Get-ZTReadinessScore.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
.EXAMPLE
    .\Get-ZTReadinessScore.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -ExportJson -OutputPath 'C:\Reports'
.EXAMPLE
    .\Get-ZTReadinessScore.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -TenantName 'Cloud Harbor Demo' -ExportJson -OutputPath 'C:\Reports'
.NOTES
    Version:  v0.1.1-preview
    Author:   Cloud Harbor Consulting LLC
    Requires: PowerShell 7+, Microsoft.Graph.Authentication module
    Scopes:   Policy.Read.All, IdentityRiskyUser.Read.All, AuditLog.Read.All,
              Device.Read.All, RoleManagement.Read.Directory, Reports.Read.All
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive operator tool. The console assessment summary is the primary user-facing output and is intentionally written to the host; the structured result object is returned separately for programmatic use.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
    Justification = 'Get-CAPolicies and Test-CAPolicyExists operate on the policy collection as a whole, which the plural names describe accurately.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TenantId,
    [string]$TenantName = '',
    [string]$OutputPath = '.',
    [switch]$ExportJson
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$COLLECTOR_VERSION = 'v0.1.1-preview'
# Every endpoint the collector calls must be covered here. Four scopes were
# missing, and the gap was invisible on any workstation that had already
# consented to them for another tool: the Microsoft Graph PowerShell client
# carries forward previously consented scopes, so `applications`,
# `accessReviews/definitions`, and `oauth2PermissionGrants` all succeeded on a
# machine that had run the ITPS collector, and would have returned 403 on a
# fresh one.
$REQUIRED_SCOPES = @(
    'Policy.Read.All',                  # CA policies, named locations, authorization and consent policies
    'IdentityRiskyUser.Read.All',       # identityProtection/riskyUsers
    'AuditLog.Read.All',
    'Device.Read.All',                  # devices
    'RoleManagement.Read.Directory',    # PIM eligibility and assignment schedule instances
    'Reports.Read.All',
    'Application.Read.All',             # applications
    'AccessReview.Read.All',            # identityGovernance/accessReviews/definitions
    'EntitlementManagement.Read.All',   # identityGovernance/entitlementManagement/accessPackages
    'DelegatedPermissionGrant.Read.All',# oauth2PermissionGrants
    'SensitivityLabels.Read.All'        # security/dataSecurityAndGovernance/sensitivityLabels
)
# ── Helper functions ──────────────────────────────────────────────────────────
function Write-Status {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Message,
        [ValidateSet('Info','OK','Warn','Skip')][string]$Level = 'Info'
    )
    $prefix = switch ($Level) {
        'Info' { '  →' }
        'OK'   { '  ✓' }
        'Warn' { '  !' }
        'Skip' { '  –' }
    }
    Write-Host "$prefix $Message"
}
# Guest scoping is expressed as an OData filter on the review's scope, never as a
# word in its name. Matching the name instead means a review called
# "...-NonGuest-..." scores as a guest review on a substring hit, and any tenant
# can earn the control by naming a review "guest". Display names are operator-
# supplied free text, not evidence of what is being reviewed.
$ZT_GUEST_SCOPE_PATTERN = "(?i)userType\s+eq\s+'Guest'"

function Get-ZTScopeQuery {
    # Collects every filter query an access review definition's scope exposes.
    #
    # The scope shape varies by how the review was created. An accessReviewQueryScope
    # carries `query` directly. A principalResourceMembershipsScope — the shape the
    # Entra portal produces for most review types — carries no `query` at all and
    # instead nests principalScopes[] and resourceScopes[], each with its own.
    # Reading only `scope.query` therefore returns nothing for the more common shape.
    #
    # Callers must wrap the result in @(): an empty collection unrolls to nothing on
    # return, leaving $null and making .Count throw under strict mode.
    [OutputType([string[]])]
    [CmdletBinding()]
    param([object]$Definition)
    $queries = [System.Collections.Generic.List[string]]::new()
    $scope = Get-ZTProp $Definition 'scope'
    if ($null -eq $scope) { return @() }
    $direct = Get-ZTProp $scope 'query'
    if (-not [string]::IsNullOrWhiteSpace($direct)) { $queries.Add($direct) }
    foreach ($nested in @('principalScopes', 'resourceScopes')) {
        foreach ($entry in @(Get-ZTProp $scope $nested)) {
            $q = Get-ZTProp $entry 'query'
            if (-not [string]::IsNullOrWhiteSpace($q)) { $queries.Add($q) }
        }
    }
    return $queries.ToArray()
}

function Test-ZTPhishingResistant {
    # Classifies a Conditional Access authentication strength as phishing-resistant.
    # Returns 'yes', 'no', or 'unknown'.
    #
    # Testing only that *an* authentication strength is set treats the built-in
    # "Multifactor authentication" strength — which permits SMS and Authenticator
    # push — as equivalent to a phishing-resistant one. allowedCombinations is the
    # authoritative signal: every permitted combination must consist solely of
    # phishing-resistant methods, because a strength is only as strong as its
    # weakest allowed path. Where Graph omits it, fall back to the documented
    # built-in policy ids; where neither resolves, report 'unknown' rather than
    # guessing, since a wrong 'no' understates a tenant that has done the work.
    [OutputType([string])]
    [CmdletBinding()]
    param([object]$Strength)
    if ($null -eq $Strength) { return 'no' }

    $resistantModes = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')
    $combos = @(Get-ZTProp $Strength 'allowedCombinations')
    if ($combos.Count -gt 0) {
        foreach ($combo in $combos) {
            $parts = @(([string]$combo -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($parts.Count -eq 0) { return 'unknown' }
            foreach ($part in $parts) {
                if ($resistantModes -notcontains $part) { return 'no' }
            }
        }
        return 'yes'
    }

    # Built-in authentication strength policy ids. 000...004 is Phishing-resistant
    # MFA; 000...002 (Multifactor authentication) and 000...003 (Passwordless MFA)
    # are not, since Microsoft classifies only FIDO2, Windows Hello for Business,
    # and certificate-based MFA as phishing-resistant.
    switch ([string](Get-ZTProp $Strength 'id' '')) {
        '00000000-0000-0000-0000-000000000004' { return 'yes' }
        '00000000-0000-0000-0000-000000000002' { return 'no' }
        '00000000-0000-0000-0000-000000000003' { return 'no' }
    }
    return 'unknown'
}

function Get-ZTErrorSummary {
    # Condenses a Graph error for display in a report. The Microsoft Graph SDK
    # concatenates one full JSON body per retry, so an unsummarised error puts
    # several hundred characters of request IDs into a client-facing document.
    [OutputType([string])]
    [CmdletBinding()]
    param([string]$Message, [int]$MaxLength = 200)
    if ([string]::IsNullOrWhiteSpace($Message)) { return 'no error detail returned' }
    $flat = ($Message -replace '\s+', ' ').Trim()
    if ($flat.Length -le $MaxLength) { return $flat }
    return $flat.Substring(0, $MaxLength).TrimEnd() + '... (full error in the control Signal)'
}

function Get-ZTRetryDelay {
    # Seconds to wait before retrying a throttled request. Graph normally sends
    # Retry-After on a 429; where it does not, fall back to exponential backoff.
    # Capped so a pathological Retry-After cannot stall an assessment.
    [OutputType([int])]
    [CmdletBinding()]
    param([object]$Headers, [int]$Attempt, [int]$CapSeconds = 60)
    $retryAfter = 0
    if ($null -ne $Headers) {
        # The header collection type varies by SDK version, and indexing a missing
        # key throws on a Dictionary. Probe defensively rather than assume a shape.
        $raw = $null
        try {
            if ($Headers.ContainsKey('Retry-After')) { $raw = @($Headers['Retry-After'])[0] }
        }
        catch { $raw = $null }
        if ($null -ne $raw) { [void][int]::TryParse([string]$raw, [ref]$retryAfter) }
    }
    if ($retryAfter -le 0) { $retryAfter = [int][Math]::Pow(2, [Math]::Min($Attempt, 6)) }
    return [Math]::Max(1, [Math]::Min($retryAfter, $CapSeconds))
}

function Invoke-ZTGraphSend {
    # Issues one Graph GET and returns the parsed body, retrying transient failures.
    #
    # Microsoft Graph throttles per service rather than per tenant, so one endpoint
    # can return 429 while every other call in the same run succeeds. The SDK's own
    # retry gives up after 3 attempts, which is shorter than a typical throttle
    # window. -SkipHttpErrorCheck is used so the status code is read directly rather
    # than parsed out of an exception string; that also means non-2xx responses no
    # longer throw on their own and must be raised here explicitly.
    [OutputType([object])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri,
        [string]$Label = '',
        [int]$MaxRetry = 5
    )
    $transient = @(429, 500, 502, 503, 504)
    $attempt = 0
    while ($true) {
        $statusCode = 0
        $headers = $null
        $body = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject `
            -SkipHttpErrorCheck -StatusCodeVariable statusCode -ResponseHeadersVariable headers

        if ($statusCode -lt 400) { return $body }

        $detail = ''
        if ($null -ne $body) {
            $err = Get-ZTProp $body 'error'
            if ($null -ne $err) { $detail = [string](Get-ZTProp $err 'message' '') }
        }

        if (($transient -contains $statusCode) -and $attempt -lt $MaxRetry) {
            $attempt++
            $wait = Get-ZTRetryDelay -Headers $headers -Attempt $attempt
            # Announced rather than silent: a run that pauses without explanation is
            # indistinguishable from a hang.
            Write-Status "Graph returned $statusCode for $Label. Waiting ${wait}s, then retry $attempt of $MaxRetry." -Level Warn
            Start-Sleep -Seconds $wait
            continue
        }

        $suffix = if ($attempt -gt 0) { " after $attempt retries" } else { '' }
        $reason = if ($detail) { " $detail" } else { '' }
        throw "Graph returned HTTP $statusCode for $Label$suffix.$reason"
    }
}

function Invoke-ZTGraphRequest {
    # Pages through a Graph collection endpoint. Returns an array for collection
    # responses and the raw object for single-entity responses.
    #
    # -MaxPages is a safety ceiling against a nextLink that never terminates. It is
    # deliberately generous; hitting it is reported rather than passed over, because
    # a truncated collection would silently misstate a stage.
    #
    # Callers must wrap the result in @(). A function returning an empty collection
    # unrolls to nothing, leaving the caller with $null and making .Count throw under
    # Set-StrictMode -Version Latest. Prefer Invoke-ZTCollection, which does this and
    # also distinguishes an empty result from a failed call.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri,
        [string]$ApiVersion = 'v1.0',
        [int]$MaxPages = 200,
        [int]$MaxRetry = 5
    )
    $base    = "https://graph.microsoft.com/$ApiVersion"
    $fullUri = if ($Uri -match '^https?://') { $Uri } else { "$base/$($Uri.TrimStart('/'))" }
    $results = [System.Collections.Generic.List[object]]::new()
    $page = 0
    do {
        $response = Invoke-ZTGraphSend -Uri $fullUri -Label $Uri -MaxRetry $MaxRetry
        $page++
        $hasValue = ($null -ne $response) -and
                    ($response.PSObject.Properties.Name -contains 'value')
        if ($hasValue) {
            $results.AddRange([object[]]($response.value))
        } else {
            return $response
        }
        $fullUri = if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $response.'@odata.nextLink'
        } else {
            $null
        }
        if ($fullUri -and $page -ge $MaxPages) {
            Write-Status "Paging ceiling of $MaxPages pages reached for $Uri. Results are truncated." -Level Warn
            break
        }
    } while ($fullUri)
    return $results.ToArray()
}

function Invoke-ZTCollection {
    # Wraps a Graph collection call and reports three distinct outcomes:
    #   Ok = $true,  Items = @()      -> the endpoint answered and the set is genuinely empty
    #   Ok = $true,  Items = @(...)   -> the endpoint answered with data
    #   Ok = $false, Error = '...'    -> the call failed and the control cannot be assessed
    #
    # This distinction is the point. The previous idiom, `$x = try { fn } catch { @() }`,
    # collapsed all three into one: an empty result unrolls to $null on return, so a
    # tenant with zero risky users produced the same $null as a failed call — and then
    # $x.Count threw under strict mode, stopping the assessment outright.
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri,
        [string]$ApiVersion = 'v1.0'
    )
    $items = @(); $ok = $true; $err = ''
    try { $items = @(Invoke-ZTGraphRequest -Uri $Uri -ApiVersion $ApiVersion) }
    catch { $ok = $false; $err = $_.Exception.Message }
    [PSCustomObject]@{ Ok = $ok; Items = $items; Error = $err }
}
function Get-ZTProp {
    # Safely walk a dotted property path on a PSObject. Returns $Default if any
    # segment is missing or null. Prevents PropertyNotFoundException under
    # Set-StrictMode -Version Latest when Graph omits absent/empty optional properties.
    [CmdletBinding()]
    param(
        [object]$InputObject,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
        $Default = $null
    )
    $current = $InputObject
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $Default }
        $prop = $current.PSObject.Properties[$segment]
        if ($null -eq $prop -or $null -eq $prop.Value) { return $Default }
        $current = $prop.Value
    }
    return $current
}
function New-ZTControl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Constructs an in-memory PSCustomObject and changes no system state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Id,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        [string[]]$NistTenets       = @(),
        [string]$RepoXRef           = '',
        [nullable[int]]$Stage,
        [bool]$ManualReview         = $false,
        [string]$ManualReviewNote   = '',
        [hashtable]$Signal          = @{}
    )
    [PSCustomObject]@{
        Id               = $Id
        Name             = $Name
        NistTenets       = $NistTenets
        RepoXRef         = $RepoXRef
        Stage            = $Stage
        ManualReview     = $ManualReview
        ManualReviewNote = $ManualReviewNote
        Signal           = $Signal
    }
}
function Get-PillarStage {
    [CmdletBinding()]
    param([PSCustomObject[]]$Controls)
    $scored = @($Controls | Where-Object { $null -ne $_.Stage } | ForEach-Object { [int]$_.Stage })
    if ($scored.Count -eq 0) { return $null }
    $sorted = @($scored | Sort-Object)
    $count  = $sorted.Count
    if ($count % 2 -eq 1) {
        return $sorted[($count - 1) / 2]
    } else {
        # Even count: return lower of two middle values (round down on ties)
        return $sorted[($count / 2) - 1]
    }
}
function Get-CAPolicies {
    Write-Status 'Fetching Conditional Access policies (beta endpoint)...'
    # Beta required: preview fields (signInFrequency everyTime, Agent ID conditions)
    Invoke-ZTCollection -Uri 'identity/conditionalAccess/policies' -ApiVersion 'beta'
}
function Test-CAPolicyExists {
    # -AllowEmptyCollection because a tenant with no Conditional Access policies is a
    # real state the assessment must report, not a binding error. Mandatory without it
    # made every Prevention-style control unreachable on such a tenant.
    #
    # State is read through Get-ZTProp rather than $_.state: under
    # Set-StrictMode -Version Latest a policy object missing the property throws,
    # which is the hazard Get-ZTProp exists to prevent everywhere else in this file.
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Policies,
        [Parameter(Mandatory)][scriptblock]$Filter,
        [ValidateSet('enabled','enabledForReportingButNotEnforced','disabled')]
        [string]$State = 'enabled'
    )
    $matching = @($Policies | Where-Object { (Get-ZTProp $_ 'state') -eq $State -and (& $Filter $_) })
    return ($matching.Count -gt 0)
}
# ── Connect ───────────────────────────────────────────────────────────────────
Write-Status "Connecting to Microsoft Graph (tenant: $TenantId)..."
Connect-MgGraph -TenantId $TenantId -Scopes $REQUIRED_SCOPES -NoWelcome
Write-Status 'Connected.' -Level OK
# ── Shared data ───────────────────────────────────────────────────────────────
Write-Status 'Loading shared data...'
$caCall     = Get-CAPolicies
$deviceCall = Invoke-ZTCollection -Uri 'devices'
$riskyCall  = Invoke-ZTCollection -Uri 'identityProtection/riskyUsers'
$caPolicies = $caCall.Items
$devices    = $deviceCall.Items
$riskyUsers = $riskyCall.Items
foreach ($c in @(
        @{ N = 'Conditional Access policies'; C = $caCall },
        @{ N = 'devices';                     C = $deviceCall },
        @{ N = 'risky users';                 C = $riskyCall })) {
    if (-not $c.C.Ok) { Write-Status "$($c.N) unavailable: $(Get-ZTErrorSummary $c.C.Error)" -Level Warn }
}
Write-Status "Loaded: $($caPolicies.Count) CA policies, $($devices.Count) devices, $($riskyUsers.Count) risky users." -Level OK
# ── Pillar 1 — Identities ─────────────────────────────────────────────────────
Write-Status 'Assessing Pillar 1 — Identities...'
$idControls = [System.Collections.Generic.List[PSCustomObject]]::new()
# ID-01: MFA enrollment and coverage
$legacyAuthBlocked = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ((Get-ZTProp $p 'conditions.clientAppTypes') -contains 'exchangeActiveSync' -or
     (Get-ZTProp $p 'conditions.clientAppTypes') -contains 'other') -and
    (Get-ZTProp $p 'grantControls.builtInControls') -contains 'block'
}
# ID-01 measures coverage across the tenant, so the policy must include All users
# and All applications and impose no risk precondition. The previous filter also
# accepted any policy scoped to at least one group, which meant a policy covering
# a single pilot group read as tenant-wide MFA coverage; and it accepted
# user-action policies (register security info, register or join device), which
# require MFA for one enrolment flow rather than for access generally.
$mfaCoverageEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
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
# Stage 4 claims phishing-resistant authentication is enforced for all users, so
# the strength has to actually be phishing-resistant, the policy has to cover the
# tenant, and it has to apply unconditionally. Omitting the last test let a
# risk-conditional policy carry Stage 4: on a live tenant the only policy with a
# phishing-resistant strength and All users / All applications fired solely at
# medium sign-in risk, which is not "enforced for all users" by any reading.
$phishResistantEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    (Test-ZTPhishingResistant -Strength (Get-ZTProp $p 'grantControls.authenticationStrength')) -eq 'yes' -and
    (Get-ZTProp $p 'conditions.users.includeUsers') -contains 'All' -and
    (Get-ZTProp $p 'conditions.applications.includeApplications') -contains 'All' -and
    @(Get-ZTProp $p 'conditions.signInRiskLevels').Count -eq 0 -and
    @(Get-ZTProp $p 'conditions.userRiskLevels').Count -eq 0
}
$mfaReportOnly = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    (Get-ZTProp $p 'grantControls.builtInControls') -contains 'mfa' -or
    $null -ne (Get-ZTProp $p 'grantControls.authenticationStrength')
} -State 'enabledForReportingButNotEnforced'
$id01Stage = if ($phishResistantEnforced -and $legacyAuthBlocked) { 4 }
             elseif ($mfaCoverageEnforced -and $legacyAuthBlocked) { 3 }
             elseif ($mfaCoverageEnforced -or $mfaReportOnly)      { 2 }
             else                                                   { 1 }
$idControls.Add((New-ZTControl -Id 'ID-01' -Name 'MFA enrollment and coverage' `
    -NistTenets @('T4','T6') -RepoXRef 'CA-COV001-009, CA-SIG001' -Stage $id01Stage `
    -Signal @{
        LegacyAuthBlocked      = $legacyAuthBlocked
        MfaCoverageEnforced    = $mfaCoverageEnforced
        PhishResistantEnforced = $phishResistantEnforced
        CAPolicyDataOk         = $caCall.Ok
    }))
# ID-02: Admin MFA and privileged identity protection
$adminMfaEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ((Get-ZTProp $p 'conditions.users.includeRoles') | Measure-Object).Count -gt 0 -and
    ($null -ne (Get-ZTProp $p 'grantControls.authenticationStrength') -or
     (Get-ZTProp $p 'grantControls.builtInControls') -contains 'mfa')
}
$adminSignInRiskCA = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ((Get-ZTProp $p 'conditions.users.includeRoles') | Measure-Object).Count -gt 0 -and
    ((Get-ZTProp $p 'conditions.signInRiskLevels') | Measure-Object).Count -gt 0
}
# PIM for Microsoft Entra roles — unified role-management model (v1.0 GA).
# Eligible = roleEligibilityScheduleInstances; permanent standing = roleAssignmentScheduleInstances
# where assignmentType is 'Assigned' (not 'Activated') and endDateTime is null (perpetual).
$eligibleCall = Invoke-ZTCollection -Uri 'roleManagement/directory/roleEligibilityScheduleInstances'
$activeCall   = Invoke-ZTCollection -Uri 'roleManagement/directory/roleAssignmentScheduleInstances'
$pimError     = @($eligibleCall.Error, $activeCall.Error | Where-Object { $_ }) -join ' '
$pimData      = if ($eligibleCall.Ok -and $activeCall.Ok) {
    $permanent = @($activeCall.Items | Where-Object {
            (Get-ZTProp $_ 'assignmentType') -eq 'Assigned' -and $null -eq (Get-ZTProp $_ 'endDateTime')
        }).Count
    @{ Eligible = $eligibleCall.Items.Count; Permanent = $permanent }
}
else {
    Write-Status "PIM role assignment data unavailable — flagging ManualReview for ID-02 and ID-06. $(Get-ZTErrorSummary $pimError)" -Level Warn
    $null
}
$id02Stage = if ($null -eq $pimData) { $null }
             elseif ($adminMfaEnforced -and $adminSignInRiskCA -and $pimData.Permanent -eq 0) { 4 }
             elseif ($adminMfaEnforced -and $pimData.Eligible -gt 0)                          { 3 }
             elseif ($adminMfaEnforced -or $pimData.Eligible -gt 0)                           { 2 }
             else                                                                              { 1 }
$idControls.Add((New-ZTControl -Id 'ID-02' -Name 'Admin MFA and privileged identity protection' `
    -NistTenets @('T3','T4','T6') -RepoXRef 'CA-AUT001-003, CA-SIG005' -Stage $id02Stage `
    -ManualReview ($null -eq $pimData) `
    -ManualReviewNote $(if ($null -eq $pimData) { "PIM role assignment call failed: $(Get-ZTErrorSummary $pimError) Review in Entra admin center > Identity Governance > Privileged Identity Management > Microsoft Entra roles > Assignments." } else { '' }) `
    -Signal @{ AdminMfaEnforced = $adminMfaEnforced; AdminSignInRiskCA = $adminSignInRiskCA; PimData = $pimData }))
# ID-03: Block legacy authentication
$legacyBlockEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ((Get-ZTProp $p 'conditions.clientAppTypes') -contains 'exchangeActiveSync' -or
     (Get-ZTProp $p 'conditions.clientAppTypes') -contains 'other') -and
    (Get-ZTProp $p 'grantControls.builtInControls') -contains 'block'
}
$legacyBlockReportOnly = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ((Get-ZTProp $p 'conditions.clientAppTypes') -contains 'exchangeActiveSync' -or
     (Get-ZTProp $p 'conditions.clientAppTypes') -contains 'other') -and
    (Get-ZTProp $p 'grantControls.builtInControls') -contains 'block'
} -State 'enabledForReportingButNotEnforced'
$id03Stage = if ($legacyBlockEnforced)      { 3 }
             elseif ($legacyBlockReportOnly) { 2 }
             else                            { 1 }
$idControls.Add((New-ZTControl -Id 'ID-03' -Name 'Block legacy authentication' `
    -NistTenets @('T2','T6') -RepoXRef 'CA-SIG001' -Stage $id03Stage `
    -Signal @{ LegacyBlockEnforced = $legacyBlockEnforced; LegacyBlockReportOnly = $legacyBlockReportOnly }))
# ID-04: Sign-in risk CA enforcement
$signInRiskEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ((Get-ZTProp $p 'conditions.signInRiskLevels') -contains 'medium' -or
     (Get-ZTProp $p 'conditions.signInRiskLevels') -contains 'high') -and
    ((Get-ZTProp $p 'grantControls.builtInControls') | Measure-Object).Count -gt 0
}
$signInRiskReportOnly = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ((Get-ZTProp $p 'conditions.signInRiskLevels') | Measure-Object).Count -gt 0
} -State 'enabledForReportingButNotEnforced'
$id04Stage = if ($signInRiskEnforced)      { 3 }
             elseif ($signInRiskReportOnly) { 2 }
             else                          { 1 }
$idControls.Add((New-ZTControl -Id 'ID-04' -Name 'Sign-in risk CA enforcement' `
    -NistTenets @('T4','T5','T7') -RepoXRef 'CA-SIG005-007' -Stage $id04Stage `
    -Signal @{ SignInRiskEnforced = $signInRiskEnforced; SignInRiskReportOnly = $signInRiskReportOnly }))
# ID-05: User risk CA enforcement
$userRiskHighEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    (Get-ZTProp $p 'conditions.userRiskLevels') -contains 'high' -and
    ((Get-ZTProp $p 'grantControls.builtInControls') | Measure-Object).Count -gt 0
}
$userRiskMedEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ((Get-ZTProp $p 'conditions.userRiskLevels') -contains 'medium' -or
     (Get-ZTProp $p 'conditions.userRiskLevels') -contains 'high') -and
    ((Get-ZTProp $p 'grantControls.builtInControls') | Measure-Object).Count -gt 0
}
# Stage 4 requires evidence that no user currently carries risk. A failed call
# returns no users either, so it must not be read as a clean tenant — that would
# award the top stage for an unanswered question.
$id05Stage = if ($userRiskMedEnforced -and $riskyCall.Ok -and $riskyUsers.Count -eq 0) { 4 }
             elseif ($userRiskHighEnforced -and $userRiskMedEnforced) { 3 }
             elseif ($userRiskHighEnforced)                           { 2 }
             else                                                     { 1 }
$idControls.Add((New-ZTControl -Id 'ID-05' -Name 'User risk CA enforcement' `
    -NistTenets @('T4','T5','T7') -RepoXRef 'CA-SIG008-010' -Stage $id05Stage `
    -Signal @{
        UserRiskHighEnforced = $userRiskHighEnforced
        UserRiskMedEnforced  = $userRiskMedEnforced
        RiskyUserCount       = $riskyUsers.Count
        RiskyUserDataOk      = $riskyCall.Ok
    }))
# ID-06: PIM JIT access (reuses $pimData from ID-02)
$id06Stage = if ($null -eq $pimData) { $null }
             elseif ($pimData.Permanent -eq 0 -and $pimData.Eligible -gt 0)               { 4 }
             elseif ($pimData.Eligible -gt 0 -and $pimData.Eligible -ge $pimData.Permanent) { 3 }
             elseif ($pimData.Eligible -gt 0)                                              { 2 }
             else                                                                          { 1 }
$idControls.Add((New-ZTControl -Id 'ID-06' -Name 'Privileged identity management JIT access' `
    -NistTenets @('T3','T4','T5') -RepoXRef 'EIG-AR002' -Stage $id06Stage `
    -ManualReview ($null -eq $pimData) `
    -ManualReviewNote $(if ($null -eq $pimData) { "PIM role assignment call failed: $(Get-ZTErrorSummary $pimError) Review in Entra admin center > Identity Governance > PIM > Microsoft Entra roles > Assignments." } else { '' }) `
    -Signal @{ PimData = $pimData }))
# ID-07: External identity lifecycle governance
$authPolicy        = try { Invoke-ZTGraphRequest -Uri 'policies/authorizationPolicy' } catch { Write-Status "Authorization policy unavailable: $(Get-ZTErrorSummary $_.Exception.Message)" -Level Warn; $null }
$guestInvitePolicy = if ($null -ne $authPolicy) { Get-ZTProp $authPolicy 'allowInvitesFrom' 'unknown' } else { 'unknown' }
$guestPolicyStage = switch ($guestInvitePolicy) {
    'none'                          { 4 }
    'adminsAndGuestInviters'        { 3 }
    'adminsGuestInvitersAndMembers' { 2 }
    'everyone'                      { 1 }
    default                         { 1 }
}
$reviewCall = Invoke-ZTCollection -Uri 'identityGovernance/accessReviews/definitions'
if (-not $reviewCall.Ok) { Write-Status "Access review definitions unavailable: $(Get-ZTErrorSummary $reviewCall.Error)" -Level Warn }
$accessReviewsExist = @($reviewCall.Items | Where-Object {
        @(@(Get-ZTScopeQuery $_) | Where-Object { $_ -match $ZT_GUEST_SCOPE_PATTERN }).Count -gt 0
    }).Count -gt 0
$id07Stage = if ($guestPolicyStage -ge 3 -and $accessReviewsExist) { $guestPolicyStage }
             elseif ($guestPolicyStage -ge 2)                       { $guestPolicyStage }
             else                                                    { 1 }
$idControls.Add((New-ZTControl -Id 'ID-07' -Name 'External identity lifecycle governance' `
    -NistTenets @('T4','T5') -RepoXRef 'EIG-AR001' -Stage $id07Stage `
    -Signal @{ GuestInvitePolicy = $guestInvitePolicy; AccessReviewsExist = $accessReviewsExist }))
# ID-08: SSO coverage for sanctioned applications — outside Graph-only scope
$idControls.Add((New-ZTControl -Id 'ID-08' -Name 'SSO coverage for sanctioned applications' `
    -NistTenets @('T3','T6') -Stage $null -ManualReview $true `
    -ManualReviewNote 'SSO coverage is not yet implemented in the collector. The Application.Read.All scope is now requested, so this control is a candidate for automation in a later release. Review in Entra admin center > Enterprise applications > All applications — filter by Single sign-on status.' `
    -Signal @{}))
$pillar1Stage = Get-PillarStage -Controls $idControls.ToArray()
Write-Status "Pillar 1 (Identities) stage: $pillar1Stage" -Level OK
# ── Pillar 2 — Endpoints ──────────────────────────────────────────────────────
Write-Status 'Assessing Pillar 2 — Endpoints...'
$epControls = [System.Collections.Generic.List[PSCustomObject]]::new()
# EP-01: Device registration with cloud identity
$joinedCount     = @($devices | Where-Object { (Get-ZTProp $_ 'trustType') -in @('AzureAD','ServerAD') }).Count
$registeredCount = @($devices | Where-Object { (Get-ZTProp $_ 'trustType') -eq 'Workplace' }).Count
$totalCount      = $devices.Count
$ep01Stage = if ($totalCount -eq 0)                                               { 1 }
             elseif (($joinedCount + $registeredCount) -ge ($totalCount * 0.95))  { 4 }
             elseif ($joinedCount -gt 0 -and $registeredCount -gt 0)              { 3 }
             elseif ($joinedCount -gt 0)                                           { 2 }
             else                                                                  { 1 }
$epControls.Add((New-ZTControl -Id 'EP-01' -Name 'Device registration with cloud identity' `
    -NistTenets @('T1','T5') -Stage $ep01Stage `
    -Signal @{ TotalDevices = $totalCount; JoinedDevices = $joinedCount; RegisteredDevices = $registeredCount }))
# EP-02: Device compliance policies — Intune scope required
$epControls.Add((New-ZTControl -Id 'EP-02' -Name 'Device compliance policies' `
    -NistTenets @('T4','T5') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Requires DeviceManagementConfiguration.Read.All, outside the current scope of this collector. Review in Intune admin center > Devices > Compliance policies.' `
    -Signal @{}))
# EP-03: CA enforcement of device compliance
$compliantDeviceEnforced = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    (Get-ZTProp $p 'grantControls.builtInControls') -contains 'compliantDevice'
}
$compliantDeviceReportOnly = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    (Get-ZTProp $p 'grantControls.builtInControls') -contains 'compliantDevice'
} -State 'enabledForReportingButNotEnforced'
$ep03Stage = if ($compliantDeviceEnforced)      { 3 }
             elseif ($compliantDeviceReportOnly) { 2 }
             else                               { 1 }
$epControls.Add((New-ZTControl -Id 'EP-03' -Name 'CA enforcement of device compliance' `
    -NistTenets @('T3','T4','T6') -RepoXRef 'CA-AUT003' -Stage $ep03Stage `
    -Signal @{ CompliantDeviceEnforced = $compliantDeviceEnforced; CompliantDeviceReportOnly = $compliantDeviceReportOnly }))
# EP-04 through EP-07 — Intune-scoped, ManualReview
$epControls.Add((New-ZTControl -Id 'EP-04' -Name 'App protection policies BYOD MAM' `
    -NistTenets @('T1','T4') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Requires DeviceManagementApps.Read.All, outside the current scope of this collector. Review in Intune admin center > Apps > App protection policies.' `
    -Signal @{}))
$epControls.Add((New-ZTControl -Id 'EP-05' -Name 'Security baselines and configuration enforcement' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Requires DeviceManagementConfiguration.Read.All, outside the current scope of this collector. Review in Intune admin center > Endpoint security > Security baselines.' `
    -Signal @{}))
$epControls.Add((New-ZTControl -Id 'EP-06' -Name 'Device encryption' `
    -NistTenets @('T1','T2') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Requires DeviceManagementConfiguration.Read.All, outside the current scope of this collector. Review in Intune admin center > Devices > Compliance policies — verify encryption requirement per platform.' `
    -Signal @{}))
$epControls.Add((New-ZTControl -Id 'EP-07' -Name 'Endpoint threat detection' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Requires DeviceManagementManagedDevices.Read.All, outside the current scope of this collector. Review in Defender portal > Settings > Endpoints > Onboarding and Intune admin center > Endpoint security > Microsoft Defender for Endpoint.' `
    -Signal @{}))
$pillar2Stage = Get-PillarStage -Controls $epControls.ToArray()
Write-Status "Pillar 2 (Endpoints) stage: $pillar2Stage" -Level OK
# ── Pillar 3 — Applications ───────────────────────────────────────────────────
Write-Status 'Assessing Pillar 3 — Applications...'
$apControls = [System.Collections.Generic.List[PSCustomObject]]::new()
# AP-01: Shadow IT discovery — Defender for Cloud Apps, not in Graph
$apControls.Add((New-ZTControl -Id 'AP-01' -Name 'Shadow IT discovery' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Defender for Cloud Apps state is not available via Microsoft Graph. Review in Defender portal > Cloud Apps > Cloud discovery > Dashboard — verify log source and MDE stream integration.' `
    -Signal @{}))
# AP-02: OAuth consent governance
$consentPolicy  = try { Invoke-ZTGraphRequest -Uri 'policies/adminConsentRequestPolicy' } catch { Write-Status "Admin consent request policy unavailable: $(Get-ZTErrorSummary $_.Exception.Message)" -Level Warn; $null }
$consentEnabled = if ($null -ne $consentPolicy) { [bool](Get-ZTProp $consentPolicy 'isEnabled' $false) } else { $false }
$grantCall      = Invoke-ZTCollection -Uri 'oauth2PermissionGrants'
if (-not $grantCall.Ok) { Write-Status "OAuth2 permission grants unavailable: $(Get-ZTErrorSummary $grantCall.Error)" -Level Warn }
$highPrivGrants = @($grantCall.Items | Where-Object { (Get-ZTProp $_ 'scope') -match 'Mail\.|Files\.|Directory\.' }).Count
$ap02Stage = if ($consentEnabled -and $highPrivGrants -eq 0) { 4 }
             elseif ($consentEnabled)                         { 3 }
             elseif ($highPrivGrants -lt 10)                  { 2 }
             else                                             { 1 }
$apControls.Add((New-ZTControl -Id 'AP-02' -Name 'OAuth consent governance' `
    -NistTenets @('T4','T5') -Stage $ap02Stage `
    -Signal @{ AdminConsentEnabled = $consentEnabled; HighPrivilegeGrantCount = $highPrivGrants }))
# AP-03: CAAC session controls
$caacEnabled = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    $null -ne (Get-ZTProp $p 'sessionControls.cloudAppSecurity')
}
$ap03Stage = if ($caacEnabled) { 3 } else { 1 }
$apControls.Add((New-ZTControl -Id 'AP-03' -Name 'Conditional Access App Control session controls' `
    -NistTenets @('T3','T4') -Stage $ap03Stage `
    -Signal @{ CaacEnabled = $caacEnabled }))
# AP-04, AP-05 — Purview / Defender for Cloud Apps, ManualReview
$apControls.Add((New-ZTControl -Id 'AP-04' -Name 'Application DLP' `
    -NistTenets @('T4','T5') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Microsoft Purview DLP is not available via Microsoft Graph. Review in Purview compliance portal > Data loss prevention > Policies — verify mode (audit vs. enforce) per workload.' `
    -Signal @{}))
$apControls.Add((New-ZTControl -Id 'AP-05' -Name 'UEBA and anomaly detection' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote 'Defender for Cloud Apps anomaly detection state is not available via Microsoft Graph. Review in Defender portal > Cloud Apps > Policies > Policy management.' `
    -Signal @{}))
# AP-06: Entitlement governance
$packageCall        = Invoke-ZTCollection -Uri 'identityGovernance/entitlementManagement/accessPackages'
if (-not $packageCall.Ok) { Write-Status "Access packages unavailable: $(Get-ZTErrorSummary $packageCall.Error)" -Level Warn }
$accessPackageCount = $packageCall.Items.Count
# A failed call returns no access packages, and so does a tenant that has none.
# Scoring both as Stage 1 reports absence of entitlement governance on the
# evidence of an unanswered question — the live tenant returned 403 here for a
# missing scope and was marked Traditional for it.
if ($packageCall.Ok) {
    $ap06Stage = if ($accessPackageCount -gt 5)   { 3 }
                 elseif ($accessPackageCount -gt 0) { 2 }
                 else                               { 1 }
    $apControls.Add((New-ZTControl -Id 'AP-06' -Name 'App-level access permissions and entitlement governance' `
        -NistTenets @('T3','T4') -RepoXRef 'EIG-AR001, EIG-AR002' -Stage $ap06Stage `
        -Signal @{ AccessPackageCount = $accessPackageCount; AccessPackageDataOk = $true }))
}
else {
    $apControls.Add((New-ZTControl -Id 'AP-06' -Name 'App-level access permissions and entitlement governance' `
        -NistTenets @('T3','T4') -RepoXRef 'EIG-AR001, EIG-AR002' -Stage $null -ManualReview $true `
        -ManualReviewNote "Access package call failed: $(Get-ZTErrorSummary $packageCall.Error) Review in Entra admin center > Identity Governance > Entitlement management > Access packages." `
        -Signal @{ AccessPackageDataOk = $false; GraphError = $packageCall.Error }))
}
$pillar3Stage = Get-PillarStage -Controls $apControls.ToArray()
Write-Status "Pillar 3 (Applications) stage: $pillar3Stage" -Level OK
# ── Pillar 4 — Data ───────────────────────────────────────────────────────────
Write-Status 'Assessing Pillar 4 — Data...'
$daControls  = [System.Collections.Generic.List[PSCustomObject]]::new()
$purviewNote = 'Microsoft Purview signals are not available via Microsoft Graph to this collector. Review in Purview compliance portal'
# DA-01: Sensitivity labels — partial Graph signal available
# Tenant sensitivity label taxonomy.
#
# The resource lives under the dataSecurityAndGovernance namespace, not
# informationProtection. Two earlier paths both returned HTTP 400:
# `informationProtection/sensitivityLabels` for the segment 'sensitivityLabels',
# and `security/informationProtection/sensitivityLabels` for the segment
# 'informationProtection'. `GET /security/dataSecurityAndGovernance/sensitivityLabels`
# is GA in v1.0 and returns the labels available to the entire tenant.
#
# Availability note: this API is published for the global service only. It is not
# available in US Government L4, US Government L5 (DOD), or China operated by
# 21Vianet, where the call will fail and DA-01 falls to manual review.
$labelCall  = Invoke-ZTCollection -Uri 'security/dataSecurityAndGovernance/sensitivityLabels'
if (-not $labelCall.Ok) { Write-Status "Sensitivity labels unavailable: $(Get-ZTErrorSummary $labelCall.Error)" -Level Warn }
$labelCount = $labelCall.Items.Count
# A failed call returns no labels, and so does a tenant with no taxonomy. Only
# the second is a finding. DA-01 stays ManualReview either way — the label count
# says nothing about publication, auto-labeling, or coverage — but a stage is
# recorded only when the question was actually answered, because a control with a
# non-null stage feeds the pillar median.
$da01Stage = if (-not $labelCall.Ok) { $null }
             elseif ($labelCount -gt 0) { 2 }
             else { 1 }
# The note must not contradict the signal beside it. DA-01 previously said
# "Microsoft Purview signals are not available via Microsoft Graph" on a control
# that had just reported a label count read from Graph. The taxonomy is readable;
# what is not readable is whether those labels are published, auto-applied, or
# actually used — which is why the control stays ManualReview.
$da01Note = if ($labelCall.Ok) {
    "$labelCount sensitivity label(s) read from Microsoft Graph. The taxonomy is only the first of the three things this control measures: publication policy, auto-labeling configuration, and actual label coverage are not exposed via Graph. Confirm those in Purview compliance portal > Information protection > Labels, and read coverage from Content Explorer."
}
else {
    "Sensitivity label call failed: $(Get-ZTErrorSummary $labelCall.Error) Assess the full control by hand in Purview compliance portal > Information protection > Labels — verify the taxonomy, publication policy, auto-labeling configuration, and label coverage metrics in Content Explorer."
}
$daControls.Add((New-ZTControl -Id 'DA-01' -Name 'Data classification framework and sensitivity label taxonomy' `
    -NistTenets @('T1','T5') -Stage $da01Stage -ManualReview $true `
    -ManualReviewNote $da01Note `
    -Signal @{ SensitivityLabelCount = $labelCount; SensitivityLabelDataOk = $labelCall.Ok }))
# DA-02 through DA-07 — all Purview-scoped, ManualReview
$daControls.Add((New-ZTControl -Id 'DA-02' -Name 'Information protection encryption and rights management' `
    -NistTenets @('T1','T2','T4') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Information protection > Labels — verify encryption is configured on Confidential and Highly Confidential labels." `
    -Signal @{}))
$daControls.Add((New-ZTControl -Id 'DA-03' -Name 'Container-level data protection Teams M365 Groups SharePoint' `
    -NistTenets @('T3','T4') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Information protection — verify container labels applied to Teams and SharePoint sites. Also review SharePoint admin center > Policies > Sharing." `
    -Signal @{}))
$daControls.Add((New-ZTControl -Id 'DA-04' -Name 'Data Loss Prevention policy coverage and maturity' `
    -NistTenets @('T4','T5') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Data loss prevention > Policies — verify mode (audit vs. enforce) and coverage across Exchange, SharePoint, OneDrive, Teams, and Endpoint." `
    -Signal @{}))
$daControls.Add((New-ZTControl -Id 'DA-05' -Name 'Insider Risk Management' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Insider risk management > Policies — verify active policy count, alert review state, and HR connector configuration." `
    -Signal @{}))
$daControls.Add((New-ZTControl -Id 'DA-06' -Name 'Data lifecycle and records management' `
    -NistTenets @('T5') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Data lifecycle management > Retention policies — verify workload coverage and retention label deployment." `
    -Signal @{}))
$daControls.Add((New-ZTControl -Id 'DA-07' -Name 'Data discovery and content inventory' `
    -NistTenets @('T1','T5') -Stage $null -ManualReview $true `
    -ManualReviewNote "$purviewNote > Content explorer — verify labeled item count by workload and on-premises scanner deployment state." `
    -Signal @{}))
$pillar4Stage = Get-PillarStage -Controls $daControls.ToArray()
Write-Status "Pillar 4 (Data) stage: $pillar4Stage" -Level OK
# ── Pillar 5 — Infrastructure ─────────────────────────────────────────────────
Write-Status 'Assessing Pillar 5 — Infrastructure...'
$infraControls = [System.Collections.Generic.List[PSCustomObject]]::new()
$azureNote     = 'Requires Azure Management API signals, outside the Graph-only scope of this collector.'
# IN-01: JIT privileged access for Azure resource roles — ARM-only, not available via Microsoft Graph.
# PIM for Azure resource roles is managed through the Azure Resource Manager APIs
# (Microsoft.Authorization/roleEligibilityScheduleInstances), not Microsoft Graph, so this control
# is manual-review in this Graph-only collector.
$infraControls.Add((New-ZTControl -Id 'IN-01' -Name 'JIT privileged access for Azure resource roles' `
    -NistTenets @('T3','T4','T5') -RepoXRef 'EIG-AR002' -Stage $null -ManualReview $true `
    -ManualReviewNote "$azureNote PIM for Azure resource roles is managed via the Azure Resource Manager APIs, not Microsoft Graph. Review in Entra admin center > Identity Governance > Privileged Identity Management > Azure resources > Assignments." `
    -Signal @{}))
# IN-02: Workload identity — managed identities vs. secrets
$appCall      = Invoke-ZTCollection -Uri 'applications'
if (-not $appCall.Ok) { Write-Status "Application registrations unavailable: $(Get-ZTErrorSummary $appCall.Error)" -Level Warn }
$appRegs      = $appCall.Items
$staleSecrets = @($appRegs | Where-Object {
    @((Get-ZTProp $_ 'passwordCredentials') | Where-Object {
        $null -eq (Get-ZTProp $_ 'endDateTime') -or
        ([datetime](Get-ZTProp $_ 'endDateTime') - [datetime]::UtcNow).TotalDays -gt 365
    }).Count -gt 0
}).Count
$in02Stage = if ($appRegs.Count -gt 0 -and $staleSecrets -eq 0)                              { 3 }
             elseif ($appRegs.Count -gt 0 -and $staleSecrets -lt ($appRegs.Count * 0.2))     { 2 }
             else                                                                              { 1 }
$infraControls.Add((New-ZTControl -Id 'IN-02' -Name 'Workload identity managed identities vs. secrets' `
    -NistTenets @('T1','T6') -Stage $in02Stage -ManualReview $true `
    -ManualReviewNote "$azureNote For managed identity coverage, review Azure portal > resource > Identity — verify system-assigned or user-assigned managed identity is enabled." `
    -Signal @{ AppRegistrationCount = $appRegs.Count; AppsWithStaleSecrets = $staleSecrets }))
# IN-03 through IN-06 — Azure Management API, all ManualReview
$infraControls.Add((New-ZTControl -Id 'IN-03' -Name 'Workload monitoring and threat detection' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote "$azureNote Review Defender for Cloud > Environment settings — verify plans enabled per resource type. Review Sentinel > Data connectors — verify key workload connectors." `
    -Signal @{}))
$infraControls.Add((New-ZTControl -Id 'IN-04' -Name 'RBAC for subscriptions and resources' `
    -NistTenets @('T4','T6') -Stage $null -ManualReview $true `
    -ManualReviewNote "$azureNote Review Azure portal > Subscriptions > Access control (IAM) — verify Owner and Contributor assignment count and last review date." `
    -Signal @{}))
$infraControls.Add((New-ZTControl -Id 'IN-05' -Name 'Vulnerability management' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote "$azureNote Review Defender for Cloud > Recommendations — verify vulnerability assessment coverage and critical/high CVE count and age." `
    -Signal @{}))
$infraControls.Add((New-ZTControl -Id 'IN-06' -Name 'Deployment governance and configuration policy' `
    -NistTenets @('T4','T5') -Stage $null -ManualReview $true `
    -ManualReviewNote "$azureNote Review Azure portal > Policy > Compliance — verify assigned policy count and overall compliance percentage. Confirm IaC adoption via repository evidence." `
    -Signal @{}))
$pillar5Stage = Get-PillarStage -Controls $infraControls.ToArray()
Write-Status "Pillar 5 (Infrastructure) stage: $pillar5Stage" -Level OK
# ── Pillar 6 — Networks ───────────────────────────────────────────────────────
Write-Status 'Assessing Pillar 6 — Networks...'
$nwControls  = [System.Collections.Generic.List[PSCustomObject]]::new()
$networkNote = 'Requires Azure Management API or GSA-specific Graph scopes, outside the current scope of this collector.'
# NW-01, NW-02 — GSA scopes not in collector scope, ManualReview
$nwControls.Add((New-ZTControl -Id 'NW-01' -Name 'Legacy VPN displacement private access' `
    -NistTenets @('T2','T3') -Stage $null -ManualReview $true `
    -ManualReviewNote "$networkNote Review Entra admin center > Global Secure Access > Connect > Private access — verify connector group count and application segment count." `
    -Signal @{}))
$nwControls.Add((New-ZTControl -Id 'NW-02' -Name 'Internet access security Entra Internet Access SWG' `
    -NistTenets @('T2','T4') -Stage $null -ManualReview $true `
    -ManualReviewNote "$networkNote Review Entra admin center > Global Secure Access > Connect > Internet access — verify forwarding profile state and web category filtering policy." `
    -Signal @{}))
# NW-03: Compliant network CA enforcement — partial Graph signal available
$locationCall   = Invoke-ZTCollection -Uri 'identity/conditionalAccess/namedLocations' -ApiVersion 'beta'
if (-not $locationCall.Ok) { Write-Status "Named locations unavailable: $(Get-ZTErrorSummary $locationCall.Error)" -Level Warn }
$namedLocations = $locationCall.Items
$gsaLocationFound = @($namedLocations | Where-Object {
    (Get-ZTProp $_ 'displayName') -match '(?i)(compliant|GSA|Global Secure)'
}).Count -gt 0
$compliantNetworkCA = Test-CAPolicyExists -Policies $caPolicies -Filter {
    param($p)
    ((Get-ZTProp $p 'conditions.locations.includeLocations') | Measure-Object).Count -gt 0
} -State 'enabled'
$nw03Stage = if ($gsaLocationFound -and $compliantNetworkCA) { 3 }
             elseif ($namedLocations.Count -gt 0)             { 2 }
             else                                             { 1 }
$nwControls.Add((New-ZTControl -Id 'NW-03' -Name 'Compliant network CA enforcement GSA' `
    -NistTenets @('T3','T4') -RepoXRef 'CA-COV015' -Stage $nw03Stage `
    -Signal @{ GsaLocationFound = $gsaLocationFound; NamedLocationCount = $namedLocations.Count; CompliantNetworkCA = $compliantNetworkCA }))
# NW-04 through NW-06 — Azure Management API, all ManualReview
$nwControls.Add((New-ZTControl -Id 'NW-04' -Name 'Network segmentation' `
    -NistTenets @('T2','T4') -Stage $null -ManualReview $true `
    -ManualReviewNote "$networkNote Review Azure portal > Virtual networks — verify VNet segmentation, NSG rule coverage per subnet, and Azure Firewall deployment for east-west inspection." `
    -Signal @{}))
$nwControls.Add((New-ZTControl -Id 'NW-05' -Name 'Encryption in transit' `
    -NistTenets @('T2') -Stage $null -ManualReview $true `
    -ManualReviewNote "$networkNote Review Entra admin center > Global Secure Access > Internet access > TLS inspection policy. Also verify TLS version enforcement in Azure App Service and API Management." `
    -Signal @{}))
$nwControls.Add((New-ZTControl -Id 'NW-06' -Name 'Network traffic monitoring and analytics' `
    -NistTenets @('T5','T7') -Stage $null -ManualReview $true `
    -ManualReviewNote "$networkNote Review Azure portal > Network Watcher > NSG flow logs — verify enablement per VNet. Review Sentinel > Data connectors — verify Azure Firewall and Entra Internet Access connectors." `
    -Signal @{}))
$pillar6Stage = Get-PillarStage -Controls $nwControls.ToArray()
Write-Status "Pillar 6 (Networks) stage: $pillar6Stage" -Level OK
# ── Result assembly ───────────────────────────────────────────────────────────
Write-Status 'Assembling result...'
$allPillarStages = @(@($pillar1Stage, $pillar2Stage, $pillar3Stage, $pillar4Stage, $pillar5Stage, $pillar6Stage) |
    Where-Object { $null -ne $_ } | Sort-Object)
$overallStage = if ($allPillarStages.Count -eq 0) { $null }
               elseif ($allPillarStages.Count % 2 -eq 1) {
                   $allPillarStages[($allPillarStages.Count - 1) / 2]
               } else {
                   $allPillarStages[($allPillarStages.Count / 2) - 1]
               }
$allControls       = @($idControls + $epControls + $apControls + $daControls + $infraControls + $nwControls)
$manualReviewCount = @($allControls | Where-Object { $_.ManualReview -eq $true }).Count
# A pillar with no scored control drops out of the overall median entirely, which
# moves the result without anything having improved. On a live tenant the Data
# pillar going unscored took the overall stage from Traditional to Advanced —
# correct arithmetic, but a reader is owed the fact that a sixth of the framework
# was never measured.
$pillarStageMap    = [ordered]@{
    Identities     = $pillar1Stage
    Endpoints      = $pillar2Stage
    Applications   = $pillar3Stage
    Data           = $pillar4Stage
    Infrastructure = $pillar5Stage
    Networks       = $pillar6Stage
}
$unscoredPillars   = @($pillarStageMap.Keys | Where-Object { $null -eq $pillarStageMap[$_] })
$result = [PSCustomObject]@{
    TenantId          = $TenantId
    # Presentation only. TenantId is the GUID the collector authenticates with;
    # TenantName travels with the result so the JSON export is self-describing and
    # the formatter does not need the name repeated at format time.
    TenantName        = $TenantName
    AssessmentDate    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
    CollectorVersion  = $COLLECTOR_VERSION
    OverallStage      = $overallStage
    IsPartialAssessment = ($unscoredPillars.Count -gt 0)
    UnscoredPillars   = $unscoredPillars
    ManualReviewCount = $manualReviewCount
    GraphScopesUsed   = $REQUIRED_SCOPES
    Pillars           = @(
        [PSCustomObject]@{ Name = 'Identities';     Stage = $pillar1Stage; Controls = $idControls.ToArray()    }
        [PSCustomObject]@{ Name = 'Endpoints';      Stage = $pillar2Stage; Controls = $epControls.ToArray()    }
        [PSCustomObject]@{ Name = 'Applications';   Stage = $pillar3Stage; Controls = $apControls.ToArray()    }
        [PSCustomObject]@{ Name = 'Data';           Stage = $pillar4Stage; Controls = $daControls.ToArray()    }
        [PSCustomObject]@{ Name = 'Infrastructure'; Stage = $pillar5Stage; Controls = $infraControls.ToArray() }
        [PSCustomObject]@{ Name = 'Networks';       Stage = $pillar6Stage; Controls = $nwControls.ToArray()    }
    )
}
# ── Summary output ────────────────────────────────────────────────────────────
$stageLabels = @{ 1 = 'Traditional'; 2 = 'Initial'; 3 = 'Advanced'; 4 = 'Optimal' }
Write-Host ''
Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
Write-Host "  ZTRA — Zero Trust Readiness Assessment   $($result.AssessmentDate)"
Write-Host "  Tenant:        $(if ($TenantName) { "$TenantName ($TenantId)" } else { $TenantId })"
Write-Host "  Collector:     $COLLECTOR_VERSION"
$overallLabel = if ($null -ne $overallStage) { "Stage $overallStage — $($stageLabels[$overallStage])" } else { 'Indeterminate' }
Write-Host "  Overall Stage: $overallLabel"
Write-Host "  Manual Review: $manualReviewCount of 40 controls require manual assessment"
Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
foreach ($pillar in $result.Pillars) {
    $stageStr    = if ($null -ne $pillar.Stage) { "Stage $($pillar.Stage) — $($stageLabels[$pillar.Stage])" } else { 'Manual review required' }
    $manualCount = @($pillar.Controls | Where-Object { $_.ManualReview }).Count
    Write-Host ("  {0,-16} {1,-38} ({2} manual)" -f $pillar.Name, $stageStr, $manualCount)
}
Write-Host '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'
Write-Host ''
Write-Host '  Next step: pipe this result to Format-ZTReadinessReport.ps1'
Write-Host ''
# ── JSON export ───────────────────────────────────────────────────────────────
if ($ExportJson) {
    $timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $exportFile = Join-Path $OutputPath "ZTRAResult-$timestamp.json"
    $result | ConvertTo-Json -Depth 10 | Set-Content -Path $exportFile -Encoding UTF8
    Write-Status "JSON exported: $exportFile" -Level OK
}
# ── Disconnect and return ─────────────────────────────────────────────────────
# -WarningAction as well as -ErrorAction: the SDK emits a warning rather than an
# error when it cannot clear the persisted MSAL token cache, which printed
# "The authority (including the tenant ID) must be in a well-formed URI format"
# at the end of every otherwise clean run and read as a failure.
Disconnect-MgGraph -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
return $result
