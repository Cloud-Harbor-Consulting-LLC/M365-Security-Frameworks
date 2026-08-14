#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    ITPS Collector — Identity Threat Protection Scorecard evidence gatherer.
.DESCRIPTION
    Read-only Microsoft Graph assessment across the ITPS 4-dimension model:
    Prevention, Detection, Governance, and Ownership.

    Produces a structured PSCustomObject consumed by Format-ITPScorecardReport.ps1.
    Checks with no programmatic surface are flagged ManualReview = $true with
    portal navigation instructions rather than being skipped or scored zero.

    Ownership is entirely manual and always returns a null score. The Defender
    Coverage and maturity composite score has no API and is also manual.
.PARAMETER TenantId
    The Entra tenant ID to assess. This is the tenant GUID and is used to authenticate.
.PARAMETER TenantName
    Optional friendly display name for the organisation, carried through into the
    ITPSResult object. Format-ITPScorecardReport.ps1 uses it for report headers and
    output filenames, so supplying it here means it does not have to be repeated at
    format time. When omitted, reports fall back to the tenant GUID.
.PARAMETER OutputPath
    Directory path for JSON export when -ExportJson is specified. Default: current directory.
.PARAMETER ExportJson
    When present, exports the result object to a timestamped JSON file in OutputPath.
.EXAMPLE
    .\Get-ITPScorecard.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
.EXAMPLE
    .\Get-ITPScorecard.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -TenantName 'Cloud Harbor Demo' -ExportJson -OutputPath 'C:\Reports'
.NOTES
    Version:  v0.1.0-preview
    Author:   Cloud Harbor Consulting LLC
    Requires: PowerShell 7+, Microsoft.Graph.Authentication module
    Scopes:   SecurityEvents.Read.All, SecurityIdentitiesHealth.Read.All,
              Policy.Read.All, AccessReview.Read.All,
              RoleManagement.Read.Directory, Application.Read.All
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive operator tool. The console scorecard summary is the primary user-facing output and is intentionally written to the host; the structured result object is returned separately for programmatic use.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$TenantId,
    [string]$TenantName = '',
    [string]$OutputPath = '.',
    [switch]$ExportJson
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$COLLECTOR_VERSION = 'v0.1.0-preview'
$REQUIRED_SCOPES = @(
    'SecurityEvents.Read.All',
    'SecurityIdentitiesHealth.Read.All',
    'Policy.Read.All',
    'AccessReview.Read.All',
    'RoleManagement.Read.Directory',
    'Application.Read.All'
)

# CHC scoring convention. Microsoft does not publish numeric thresholds for its
# Connected / Protected / Fortified / Resilient tiers. See Design/SCORING-METHODOLOGY.md.
$TIER_BANDS = @(
    [PSCustomObject]@{ Floor = 85; Name = 'Resilient' }
    [PSCustomObject]@{ Floor = 65; Name = 'Fortified' }
    [PSCustomObject]@{ Floor = 40; Name = 'Protected' }
    [PSCustomObject]@{ Floor = 0;  Name = 'Connected' }
)

# ── Helper functions ──────────────────────────────────────────────────────────

function Write-Status {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Message,
        [ValidateSet('Info', 'OK', 'Warn', 'Skip')][string]$Level = 'Info'
    )
    $prefix = switch ($Level) {
        'Info' { '  ->' }
        'OK' { '  [ok]' }
        'Warn' { '  [!]' }
        'Skip' { '  [-]' }
    }
    Write-Host "$prefix $Message"
}

function Invoke-ITPSGraphRequest {
    # Pages through a Graph collection endpoint. Returns an array for collection
    # responses and the raw object for single-entity responses.
    #
    # -FirstPageOnly stops after the first response. Use it when only the newest
    # record is wanted. In Microsoft Graph, $top sets the PAGE SIZE rather than a
    # result limit, so a URI such as 'security/secureScores?$top=1' returns one
    # record per page and a nextLink for the rest. Paging that to exhaustion issues
    # one HTTP request per day of retained history, which is slow enough to look
    # like a hang and long enough to cross a token-refresh boundary.
    #
    # -MaxPages is a safety ceiling against a nextLink that never terminates. It is
    # deliberately generous; hitting it is reported rather than passed over, because
    # a truncated collection would silently understate a score.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri,
        [string]$ApiVersion = 'v1.0',
        [switch]$FirstPageOnly,
        [int]$MaxPages = 200
    )
    $base = "https://graph.microsoft.com/$ApiVersion"
    $fullUri = if ($Uri -match '^https?://') { $Uri } else { "$base/$($Uri.TrimStart('/'))" }
    $results = [System.Collections.Generic.List[object]]::new()
    $page = 0
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $fullUri -OutputType PSObject
        $page++
        $hasValue = ($null -ne $response) -and
                    ($response.PSObject.Properties.Name -contains 'value')
        if ($hasValue) {
            $results.AddRange([object[]]($response.value))
        }
        else {
            return $response
        }
        if ($FirstPageOnly) { break }
        $fullUri = if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $response.'@odata.nextLink'
        }
        else {
            $null
        }
        if ($fullUri -and $page -ge $MaxPages) {
            Write-Status "Paging ceiling of $MaxPages pages reached for $Uri. Results are truncated." -Level Warn
            break
        }
    } while ($fullUri)
    return $results.ToArray()
}

function Get-ITPSProp {
    # Safely walk a dotted property path. Returns $Default when any segment is
    # missing or null. Required under Set-StrictMode -Version Latest, which throws
    # PropertyNotFoundException when Graph omits an absent optional property.
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

function Get-ITPSScopeQuery {
    # Collects every filter query a review definition's scope exposes.
    #
    # The scope shape varies by how the review was created. An accessReviewQueryScope
    # carries `query` directly. A principalResourceMembershipsScope — the shape the
    # Entra portal produces for most review types — carries no `query` at all and
    # instead nests principalScopes[] and resourceScopes[], each with its own. Reading
    # only `scope.query` therefore returns nothing for the more common shape, which is
    # what left G-02 relying entirely on the review's display name.
    #
    # Callers must wrap the result in @(). A function returning an empty collection
    # unrolls to nothing, leaving the caller with $null and making .Count throw under
    # Set-StrictMode -Version Latest — the same hazard corrected in the collector and
    # formatter previously.
    [OutputType([string[]])]
    [CmdletBinding()]
    param([object]$Definition)
    $queries = [Collections.Generic.List[string]]::new()
    $scope = Get-ITPSProp $Definition 'scope'
    if ($null -eq $scope) { return @() }
    $direct = Get-ITPSProp $scope 'query'
    if (-not [string]::IsNullOrWhiteSpace($direct)) { $queries.Add($direct) }
    foreach ($nested in @('principalScopes', 'resourceScopes')) {
        foreach ($entry in @(Get-ITPSProp $scope $nested)) {
            $q = Get-ITPSProp $entry 'query'
            if (-not [string]::IsNullOrWhiteSpace($q)) { $queries.Add($q) }
        }
    }
    return $queries.ToArray()
}

function New-ITPSCheck {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Constructs an in-memory PSCustomObject and changes no system state.')]
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Id,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        [double]$Points = 0,
        [double]$MaxPoints = 0,
        [bool]$ManualReview = $false,
        [string]$ManualReviewNote = '',
        [string]$RepoXRef = '',
        [hashtable]$Signal = @{}
    )
    [PSCustomObject]@{
        Id               = $Id
        Name             = $Name
        Points           = $Points
        MaxPoints        = $MaxPoints
        ManualReview     = $ManualReview
        ManualReviewNote = $ManualReviewNote
        RepoXRef         = $RepoXRef
        Signal           = $Signal
    }
}

function Get-DimensionScore {
    # Dimension score = earned points over available points from scored checks,
    # normalised to 0-100. Manual checks are excluded from the denominator so a
    # partial assessment yields an honest partial score rather than a depressed one.
    [OutputType([int])]
    [CmdletBinding()]
    param([PSCustomObject[]]$Checks)
    $scored = @($Checks | Where-Object { -not $_.ManualReview })
    if ($scored.Count -eq 0) { return $null }
    $available = ($scored | Measure-Object -Property MaxPoints -Sum).Sum
    if ($null -eq $available -or $available -le 0) { return $null }
    $earned = ($scored | Measure-Object -Property Points -Sum).Sum
    # Multiply before dividing. ($earned / $available) * 100 loses precision: with
    # 57.5 of 100 the intermediate is 57.49999999999999, which rounds to 57 rather
    # than 58. AwayFromZero is also specified because [Math]::Round defaults to
    # banker's rounding, which would send 58.5 down to 58 — not what a reader of a
    # score expects.
    return [int][Math]::Round(($earned * 100 / $available), 0, [MidpointRounding]::AwayFromZero)
}

function Invoke-ITPSCollection {
    # Wraps a Graph collection call and reports three distinct outcomes:
    #   Ok = $true,  Items = @()      -> the endpoint answered and the set is genuinely empty
    #   Ok = $true,  Items = @(...)   -> the endpoint answered with data
    #   Ok = $false, Error = '...'    -> the call failed and the check cannot be assessed
    #
    # This distinction matters. Assigning a collection through a try/catch
    # (`$x = try { @(fn) } catch { $null }`) silently yields $null when the result
    # is empty, because PowerShell unrolls an empty collection to zero pipeline
    # objects. That made "no records exist" indistinguishable from "call failed",
    # which excluded genuinely-absent controls from scoring instead of scoring them
    # zero. The scriptblock result is captured inside the try, never through it.
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri,
        [string]$ApiVersion = 'v1.0',
        [switch]$FirstPageOnly
    )
    $items = @()
    $ok = $true
    $err = ''
    try {
        $items = @(Invoke-ITPSGraphRequest -Uri $Uri -ApiVersion $ApiVersion -FirstPageOnly:$FirstPageOnly)
    }
    catch {
        $ok = $false
        $err = $_.Exception.Message
    }
    [PSCustomObject]@{ Ok = $ok; Items = $items; Error = $err }
}
function Get-ITPSTier {
    [OutputType([string])]
    [CmdletBinding()]
    param([nullable[int]]$Score)
    if ($null -eq $Score) { return 'Not scored' }
    foreach ($band in $TIER_BANDS) {
        if ($Score -ge $band.Floor) { return $band.Name }
    }
    return 'Connected'
}

function Test-CAPolicyMatch {
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Policies,
        [Parameter(Mandatory)][scriptblock]$Filter,
        [string]$State = 'enabled'
    )
    $matching = @($Policies | Where-Object { (Get-ITPSProp $_ 'state') -eq $State -and (& $Filter $_) })
    return ($matching.Count -gt 0)
}

# ── Connect ───────────────────────────────────────────────────────────────────

Write-Status "Connecting to Microsoft Graph (tenant: $TenantId)..."
Connect-MgGraph -TenantId $TenantId -Scopes $REQUIRED_SCOPES -NoWelcome
Write-Status 'Connected.' -Level OK

# ── Dimension 1 — Prevention ──────────────────────────────────────────────────

Write-Status 'Assessing Prevention...'
$preventionChecks = [System.Collections.Generic.List[PSCustomObject]]::new()

# P-01 Secure Score attainment (0-50)
# Only the newest Secure Score record is needed. $top=1 sets the page size, so
# without -FirstPageOnly this walks the entire retained history one record per
# request. See the note on Invoke-ITPSGraphRequest.
$secureScoreCall = Invoke-ITPSCollection -Uri 'security/secureScores?$top=1' -FirstPageOnly
$secureScore = if ($secureScoreCall.Ok -and $secureScoreCall.Items.Count -gt 0) {
    $secureScoreCall.Items[0]
}
else {
    if (-not $secureScoreCall.Ok) {
        Write-Status "Secure Score call failed — flagging P-01 for manual review. $($secureScoreCall.Error)" -Level Warn
    }
    else {
        Write-Status 'Secure Score returned no records — flagging P-01 for manual review.' -Level Warn
    }
    $null
}

# Initialised before the block below so the Detection dimension can always read it.
# When the Secure Score call fails, deployment is simply unknown — which is a
# distinct outcome from known-and-absent, and is handled as such at D-01..D-04.
$mdiEvidence = @{ Known = $false; Deployed = $false; SensorScorePercent = 0; ImplementationStatus = '' }

if ($null -ne $secureScore) {
    $current = [double](Get-ITPSProp $secureScore 'currentScore' 0)
    $max = [double](Get-ITPSProp $secureScore 'maxScore' 0)
    $attainmentPct = if ($max -gt 0) { ($current / $max) * 100 } else { 0 }
    $identityControls = @(
        (Get-ITPSProp $secureScore 'controlScores') |
        Where-Object { (Get-ITPSProp $_ 'controlCategory') -eq 'Identity' }
    )
    $identityPoints = ($identityControls | ForEach-Object { [double](Get-ITPSProp $_ 'score' 0) } |
        Measure-Object -Sum).Sum
    if ($null -eq $identityPoints) { $identityPoints = 0 }

    # Defender for Identity deployment evidence, read from the Secure Score payload
    # already in hand rather than from a second endpoint. The Detection dimension
    # needs it: an empty health-issues collection means "deployed and healthy" OR
    # "no sensors at all", and those must not score the same.
    #
    # AATP_Sensor is the control that carries it. Its implementationStatus names the
    # domain controller count and how many carry a sensor, and its scoreInPercentage
    # reaches 100 at full coverage.
    #
    # AATP_DefenderForIdentityIsNotInstalled is deliberately NOT used. On a tenant
    # with sensors installed on all 3 of its domain controllers, that control scored
    # 0 with an empty implementationStatus — so reading it as an installed flag would
    # report a fully deployed tenant as having no deployment.
    $sensorControl = @($identityControls | Where-Object {
            (Get-ITPSProp $_ 'controlName') -eq 'AATP_Sensor'
        })[0]
    $mdiEvidence = if ($null -ne $sensorControl) {
        @{
            Known                = $true
            Deployed             = ([double](Get-ITPSProp $sensorControl 'scoreInPercentage' 0) -gt 0) -or
            ([double](Get-ITPSProp $sensorControl 'score' 0) -gt 0)
            SensorScorePercent   = [double](Get-ITPSProp $sensorControl 'scoreInPercentage' 0)
            ImplementationStatus = [string](Get-ITPSProp $sensorControl 'implementationStatus' '')
        }
    }
    else {
        @{ Known = $false; Deployed = $false; SensorScorePercent = 0; ImplementationStatus = '' }
    }

    $preventionChecks.Add((New-ITPSCheck -Id 'P-01' -Name 'Secure Score attainment' `
                -Points ([Math]::Round($attainmentPct * 0.5, 2)) -MaxPoints 50 `
                -Signal @{
                TenantCurrentScore    = $current
                TenantMaxScore        = $max
                AttainmentPercent     = [Math]::Round($attainmentPct, 1)
                IdentityControlCount  = $identityControls.Count
                IdentityPointsEarned  = $identityPoints
                IdentityControlNames  = @($identityControls | ForEach-Object { Get-ITPSProp $_ 'controlName' })
                NormalisationNote     = 'Graph v1.0 secureScores exposes no per-category maximum. Scored on tenant-wide attainment; Identity breakdown is evidence only.'
            }))
}
else {
    $p01Note = if (-not $secureScoreCall.Ok) {
        "Secure Score call failed: $($secureScoreCall.Error) Review in Microsoft Defender portal > Exposure management > Secure score, and filter to the Identity category."
    }
    else {
        'Secure Score returned no records for this tenant. Review in Microsoft Defender portal > Exposure management > Secure score, and filter to the Identity category.'
    }
    $preventionChecks.Add((New-ITPSCheck -Id 'P-01' -Name 'Secure Score attainment' `
                -ManualReview $true -ManualReviewNote $p01Note))
}

# CA policy checks P-02 through P-06
$caCall = Invoke-ITPSCollection -Uri 'identity/conditionalAccess/policies'
if (-not $caCall.Ok) {
    Write-Status "Conditional Access policies unavailable — flagging P-02..P-06 for manual review. $($caCall.Error)" -Level Warn
}
elseif ($caCall.Items.Count -eq 0) {
    Write-Status 'No Conditional Access policies exist in this tenant — P-02..P-06 score zero.' -Level Warn
}
$caPolicies = $caCall.Items

if ($caCall.Ok) {
    $mfaEnforced = Test-CAPolicyMatch -Policies $caPolicies -Filter {
        param($p)
        ((Get-ITPSProp $p 'grantControls.builtInControls') -contains 'mfa' -or
         $null -ne (Get-ITPSProp $p 'grantControls.authenticationStrength')) -and
        ((Get-ITPSProp $p 'conditions.users.includeUsers') -contains 'All')
    }
    $legacyBlocked = Test-CAPolicyMatch -Policies $caPolicies -Filter {
        param($p)
        ((Get-ITPSProp $p 'conditions.clientAppTypes') -contains 'exchangeActiveSync' -or
         (Get-ITPSProp $p 'conditions.clientAppTypes') -contains 'other') -and
        (Get-ITPSProp $p 'grantControls.builtInControls') -contains 'block'
    }
    $riskPolicyPresent = Test-CAPolicyMatch -Policies $caPolicies -Filter {
        param($p)
        ((Get-ITPSProp $p 'conditions.signInRiskLevels') | Measure-Object).Count -gt 0 -or
        ((Get-ITPSProp $p 'conditions.userRiskLevels') | Measure-Object).Count -gt 0
    }
    $privRolesTargeted = Test-CAPolicyMatch -Policies $caPolicies -Filter {
        param($p)
        ((Get-ITPSProp $p 'conditions.users.includeRoles') | Measure-Object).Count -gt 0
    }
    $authStrengthUsed = Test-CAPolicyMatch -Policies $caPolicies -Filter {
        param($p)
        $null -ne (Get-ITPSProp $p 'grantControls.authenticationStrength')
    }

    $preventionChecks.Add((New-ITPSCheck -Id 'P-02' -Name 'MFA enforced for all users' `
                -Points ($(if ($mfaEnforced) { 10 } else { 0 })) -MaxPoints 10 `
                -RepoXRef 'CA-COV001-009' -Signal @{ Enforced = $mfaEnforced }))
    $preventionChecks.Add((New-ITPSCheck -Id 'P-03' -Name 'Legacy authentication blocked' `
                -Points ($(if ($legacyBlocked) { 10 } else { 0 })) -MaxPoints 10 `
                -RepoXRef 'CA-SIG001' -Signal @{ Blocked = $legacyBlocked }))
    $preventionChecks.Add((New-ITPSCheck -Id 'P-04' -Name 'Risk-based policy present' `
                -Points ($(if ($riskPolicyPresent) { 10 } else { 0 })) -MaxPoints 10 `
                -RepoXRef 'CA-SIG003, CA-SIG004, CA-SIG008, CA-SIG009' `
                -Signal @{ Present = $riskPolicyPresent }))
    $preventionChecks.Add((New-ITPSCheck -Id 'P-05' -Name 'Privileged roles targeted' `
                -Points ($(if ($privRolesTargeted) { 10 } else { 0 })) -MaxPoints 10 `
                -RepoXRef 'CA-AUT001-003' -Signal @{ Targeted = $privRolesTargeted }))
    $preventionChecks.Add((New-ITPSCheck -Id 'P-06' -Name 'Phishing-resistant strength in use' `
                -Points ($(if ($authStrengthUsed) { 10 } else { 0 })) -MaxPoints 10 `
                -Signal @{ InUse = $authStrengthUsed; PolicyCount = $caPolicies.Count }))
}
else {
    foreach ($c in @(
            @{ Id = 'P-02'; Name = 'MFA enforced for all users' },
            @{ Id = 'P-03'; Name = 'Legacy authentication blocked' },
            @{ Id = 'P-04'; Name = 'Risk-based policy present' },
            @{ Id = 'P-05'; Name = 'Privileged roles targeted' },
            @{ Id = 'P-06'; Name = 'Phishing-resistant strength in use' })) {
        $preventionChecks.Add((New-ITPSCheck -Id $c.Id -Name $c.Name -ManualReview $true `
                    -ManualReviewNote "Conditional Access policy call failed: $($caCall.Error) Review in Entra admin center > Protection > Conditional Access > Policies."))
    }
}

$preventionScore = Get-DimensionScore -Checks $preventionChecks.ToArray()
Write-Status "Prevention score: $preventionScore" -Level OK

# ── Dimension 2 — Detection ───────────────────────────────────────────────────

Write-Status 'Assessing Detection...'
$detectionChecks = [System.Collections.Generic.List[PSCustomObject]]::new()

$healthCall = Invoke-ITPSCollection -Uri "security/identities/healthIssues?`$filter=Status eq 'open'"

# An empty health-issues collection has two very different meanings: sensors are
# deployed and reporting nothing wrong, or there are no sensors to report anything
# at all. Scoring both at full marks certified a detection capability that may not
# exist — the inverse of the empty-collection defect corrected previously, where
# empty was wrongly treated as failure.
#
# The deployment evidence comes from the AATP_Sensor Secure Score control gathered
# above. It is only consulted when the collection is empty; if health issues came
# back, sensors demonstrably exist.
$healthEmpty = $healthCall.Ok -and $healthCall.Items.Count -eq 0
$detectionUnprovable = $healthEmpty -and -not $mdiEvidence.Deployed

if (-not $healthCall.Ok) {
    Write-Status "Defender for Identity health issues unavailable — flagging D-01..D-04 for manual review. $($healthCall.Error)" -Level Warn
}
elseif ($detectionUnprovable) {
    Write-Status ('No open Defender for Identity health issues, and no sensor deployment evidence — flagging D-01..D-04 for manual review ' +
        'rather than awarding full points for an absent deployment.') -Level Warn
}
elseif ($healthEmpty) {
    Write-Status "No open Defender for Identity health issues, sensors confirmed deployed — D-01..D-04 earn full points. $($mdiEvidence.ImplementationStatus)" -Level OK
}
$healthIssues = $healthCall.Items

if ($healthCall.Ok -and -not $detectionUnprovable) {
    $openHigh = @($healthIssues | Where-Object { (Get-ITPSProp $_ 'severity') -eq 'high' }).Count
    $openMedium = @($healthIssues | Where-Object { (Get-ITPSProp $_ 'severity') -eq 'medium' }).Count
    $openSensor = @($healthIssues | Where-Object { (Get-ITPSProp $_ 'healthIssueType') -match '(?i)sensor' }).Count

    $detectionChecks.Add((New-ITPSCheck -Id 'D-01' -Name 'No open high-severity health issues' `
                -Points ($(if ($openHigh -eq 0) { 25 } else { 0 })) -MaxPoints 25 `
                -Signal @{ OpenHighCount = $openHigh }))
    $detectionChecks.Add((New-ITPSCheck -Id 'D-02' -Name 'No open medium-severity health issues' `
                -Points ($(if ($openMedium -eq 0) { 15 } else { 0 })) -MaxPoints 15 `
                -Signal @{ OpenMediumCount = $openMedium }))
    $detectionChecks.Add((New-ITPSCheck -Id 'D-03' -Name 'Sensor health issues resolved' `
                -Points ($(if ($openSensor -eq 0) { 10 } else { 0 })) -MaxPoints 10 `
                -Signal @{ OpenSensorIssueCount = $openSensor }))
    $detectionChecks.Add((New-ITPSCheck -Id 'D-04' -Name 'Health signal reachable' `
                -Points 10 -MaxPoints 10 `
                -Signal @{
                TotalOpenIssues      = $healthIssues.Count
                Reachable            = $true
                SensorDeployment     = $mdiEvidence.ImplementationStatus
                SensorScorePercent   = $mdiEvidence.SensorScorePercent
            }))
}
else {
    # Two routes here, and they are not the same finding. Either the call failed, or
    # it succeeded with nothing and no sensor deployment could be evidenced.
    $detectionNote = if (-not $healthCall.Ok) {
        "Defender for Identity health issue call failed: $($healthCall.Error) This commonly means Defender for Identity is not licensed or not provisioned, but confirm against the error above rather than assuming. Review in Microsoft Defender portal > Settings > Identities > Health issues."
    }
    elseif ($mdiEvidence.Known) {
        ('The health issue endpoint answered with no open issues, but the AATP_Sensor Secure Score control reports no sensor coverage ' +
        "($($mdiEvidence.SensorScorePercent)%). With no sensors deployed there is nothing to raise a health issue, so an empty result is not " +
        'evidence of a healthy deployment and is not scored as one. Confirm sensor coverage in Microsoft Defender portal > Settings > ' +
        'Identities > Sensors before treating Detection as covered.')
    }
    else {
        ('The health issue endpoint answered with no open issues, and sensor deployment could not be confirmed because the AATP_Sensor ' +
        'Secure Score control was unavailable. An empty result cannot be distinguished from an absent deployment, so it is not scored. ' +
        'Confirm sensor coverage in Microsoft Defender portal > Settings > Identities > Sensors.')
    }
    foreach ($c in @(
            @{ Id = 'D-01'; Name = 'No open high-severity health issues' },
            @{ Id = 'D-02'; Name = 'No open medium-severity health issues' },
            @{ Id = 'D-03'; Name = 'Sensor health issues resolved' },
            @{ Id = 'D-04'; Name = 'Health signal reachable' })) {
        $detectionChecks.Add((New-ITPSCheck -Id $c.Id -Name $c.Name -ManualReview $true `
                    -ManualReviewNote $detectionNote `
                    -Signal @{
                    SensorDeploymentKnown = $mdiEvidence.Known
                    SensorScorePercent    = $mdiEvidence.SensorScorePercent
                }))
    }
}

# D-05 has no API. Always manual.
$detectionChecks.Add((New-ITPSCheck -Id 'D-05' -Name 'Coverage and maturity composite score' `
            -ManualReview $true `
            -ManualReviewNote 'No API exists for this signal. Read the composite score and tier from Microsoft Defender portal > Identities > Coverage and maturity. Requires a Defender for Cloud Apps or Defender for Identity license and at least Security Reader. The page is in Preview and rolling out gradually.'))

$detectionScore = Get-DimensionScore -Checks $detectionChecks.ToArray()
Write-Status "Detection score: $detectionScore" -Level OK

# ── Dimension 3 — Governance ──────────────────────────────────────────────────

Write-Status 'Assessing Governance...'
$governanceChecks = [System.Collections.Generic.List[PSCustomObject]]::new()

# G-01, G-02 access reviews
$reviewCall = Invoke-ITPSCollection -Uri 'identityGovernance/accessReviews/definitions'
if (-not $reviewCall.Ok) {
    Write-Status "Access review definitions unavailable — flagging G-01 and G-02 for manual review. $($reviewCall.Error)" -Level Warn
}
elseif ($reviewCall.Items.Count -eq 0) {
    Write-Status 'No access review definitions exist in this tenant — G-01 and G-02 score zero.' -Level Warn
}
$accessReviews = $reviewCall.Items

if ($reviewCall.Ok) {
    $reviewCount = $accessReviews.Count

    # G-01 is graduated rather than binary. It previously awarded full marks for a
    # single definition, so one review made the check indistinguishable from a mature
    # programme. The EIG Toolkit in this repo ships 2 reviews — EIG-AR001 (guest
    # access) and EIG-AR002 (dormant admin roles) — so a tenant running both is the
    # baseline this repo actually recommends, and that is where full points sit.
    $g01Points = switch ($reviewCount) {
        0 { 0 }
        1 { 10 }
        default { 20 }
    }

    # G-02 reads the scope filter, never the review's name. The previous matcher
    # substring-matched 'guest' against displayName, so a review named
    # "CHC-Demo-NonGuest-Test-Access-Review" scored as a guest review — and any
    # tenant could have earned the points by naming a review "guest". A display name
    # is free text supplied by the operator, not evidence of what is being reviewed.
    $guestFilterPattern = "(?i)userType\s+eq\s+'Guest'"
    $reviewScopes = @(foreach ($d in $accessReviews) {
            [PSCustomObject]@{
                Name    = [string](Get-ITPSProp $d 'displayName' '(unnamed)')
                Queries = @(Get-ITPSScopeQuery $d)
            }
        })
    $guestReviews = @($reviewScopes | Where-Object {
            @($_.Queries | Where-Object { $_ -match $guestFilterPattern }).Count -gt 0
        })
    $scopeQueryCount = @($reviewScopes | ForEach-Object { $_.Queries }).Count

    $governanceChecks.Add((New-ITPSCheck -Id 'G-01' -Name 'Access reviews configured' `
                -Points $g01Points -MaxPoints 20 `
                -RepoXRef 'EIG-AR001, EIG-AR002' -Signal @{
                ReviewDefinitionCount = $reviewCount
                ReviewNames           = @($reviewScopes | ForEach-Object { $_.Name })
                ScoringNote           = 'Graduated: 0 reviews = 0, 1 = 10, 2 or more = 20 (the EIG Toolkit baseline of guest plus dormant-admin reviews).'
            }))

    if ($guestReviews.Count -gt 0) {
        $governanceChecks.Add((New-ITPSCheck -Id 'G-02' -Name 'Guest access reviewed' `
                    -Points 15 -MaxPoints 15 -RepoXRef 'EIG-AR001' -Signal @{
                    GuestReviewPresent = $true
                    MatchedReviewNames = @($guestReviews | ForEach-Object { $_.Name })
                    MatchedOnPattern   = $guestFilterPattern
                    ScopeQueriesFound  = $scopeQueryCount
                }))
    }
    elseif ($reviewCount -eq 0 -or $scopeQueryCount -gt 0) {
        # Two distinct routes to a genuine zero: the tenant has no review definitions
        # at all, so guests are definitively not reviewed; or definitions exist, their
        # scope filters were readable, and none of them target guests. Both are an
        # absence rather than an unknown, so both score zero and count in the
        # denominator. Only a readable-definition-with-unreadable-scope falls through
        # to manual review below.
        $governanceChecks.Add((New-ITPSCheck -Id 'G-02' -Name 'Guest access reviewed' `
                    -Points 0 -MaxPoints 15 -RepoXRef 'EIG-AR001' -Signal @{
                    GuestReviewPresent = $false
                    ReviewNames        = @($reviewScopes | ForEach-Object { $_.Name })
                    MatchedOnPattern   = $guestFilterPattern
                    ScopeQueriesFound  = $scopeQueryCount
                }))
    }
    else {
        # Definitions exist but expose no readable scope filter, so guest coverage
        # cannot be determined either way. Scoring zero would understate a tenant
        # that does review guests; scoring 15 is the defect this replaces.
        $governanceChecks.Add((New-ITPSCheck -Id 'G-02' -Name 'Guest access reviewed' -ManualReview $true `
                    -RepoXRef 'EIG-AR001' `
                    -ManualReviewNote ("$reviewCount access review definition(s) exist, but none exposes a scope filter this collector can read, " +
                        'so whether guest access is reviewed cannot be determined from the API. Confirm in Entra admin center > Identity Governance > ' +
                        'Access reviews, and check whether any review scopes to external or guest users.') `
                    -Signal @{
                    ReviewNames       = @($reviewScopes | ForEach-Object { $_.Name })
                    ScopeQueriesFound = 0
                }))
    }
}
else {
    foreach ($c in @(
            @{ Id = 'G-01'; Name = 'Access reviews configured' },
            @{ Id = 'G-02'; Name = 'Guest access reviewed' })) {
        $governanceChecks.Add((New-ITPSCheck -Id $c.Id -Name $c.Name -ManualReview $true `
                    -ManualReviewNote "Access review definition call failed: $($reviewCall.Error) Access Reviews require Entra ID P2 or Entra ID Governance, but confirm against the error above rather than assuming a licensing cause. Review in Entra admin center > Identity Governance > Access reviews."))
    }
}

# G-04 PIM (absorbs the withdrawn G-03)
$eligibleCall = Invoke-ITPSCollection -Uri 'roleManagement/directory/roleEligibilityScheduleInstances'
$activeCall = Invoke-ITPSCollection -Uri 'roleManagement/directory/roleAssignmentScheduleInstances'
$pimOk = $eligibleCall.Ok -and $activeCall.Ok
$pimError = @($eligibleCall.Error, $activeCall.Error | Where-Object { $_ }) -join ' '
$pimData = $null
if ($pimOk) {
    $permanent = @($activeCall.Items | Where-Object {
            (Get-ITPSProp $_ 'assignmentType') -eq 'Assigned' -and
            $null -eq (Get-ITPSProp $_ 'endDateTime')
        }).Count
    $pimData = @{ Eligible = $eligibleCall.Items.Count; Permanent = $permanent }
    if ($eligibleCall.Items.Count -eq 0 -and $permanent -eq 0) {
        Write-Status 'No PIM role assignments found on either endpoint — flagging G-04 for manual review rather than scoring an empty set.' -Level Warn
    }
}
else {
    Write-Status "PIM assignment data unavailable — flagging G-04 for manual review. $pimError" -Level Warn
}

if ($pimOk) {
    $totalAssignments = $pimData.Eligible + $pimData.Permanent

    if ($totalAssignments -eq 0) {
        # Every tenant holds at least one privileged role assignment, so an empty set
        # on both endpoints means the signal is unreliable rather than that privilege
        # is perfectly managed. Scoring it would award full marks for missing data.
        $governanceChecks.Add((New-ITPSCheck -Id 'G-04' -Name 'Standing privilege minimised' -ManualReview $true `
                    -RepoXRef 'EIG-AR002' `
                    -ManualReviewNote ('Both PIM assignment endpoints answered but returned no role assignments at all. Every tenant has at least ' +
                        'one privileged assignment, so treat this as an unreadable signal rather than as zero standing privilege. Review in Entra ' +
                        'admin center > Identity Governance > Privileged Identity Management > Microsoft Entra roles > Assignments.') `
                    -Signal @{ EligibleCount = 0; PermanentCount = 0 }))
    }
    else {
        # G-04 scales linearly: full points at zero standing privilege, zero points
        # when every privileged assignment is permanent.
        #
        # G-03 ("PIM eligible assignments in use") was merged into this check. It
        # scored a binary 20/20 whenever a single eligible assignment existed, which
        # read the same underlying data as G-04 and could contradict it outright — a
        # tenant with 1 eligible and 9 permanent assignments scored 20/20 for PIM
        # adoption alongside 2.5/25 for standing privilege. One axis, one check.
        $standingRatio = $pimData.Permanent / $totalAssignments
        $g04Points = [Math]::Round((1 - $standingRatio) * 45, 2)

        $governanceChecks.Add((New-ITPSCheck -Id 'G-04' -Name 'Standing privilege minimised' `
                    -Points $g04Points -MaxPoints 45 `
                    -RepoXRef 'EIG-AR002' `
                    -Signal @{
                    PermanentCount = $pimData.Permanent
                    EligibleCount  = $pimData.Eligible
                    StandingRatio  = [Math]::Round($standingRatio, 3)
                    ScoringNote    = 'Linear on the share of privileged assignments that are permanent. Absorbs the former G-03, which scored the same data as a binary presence test.'
                }))
    }
}
else {
    $governanceChecks.Add((New-ITPSCheck -Id 'G-04' -Name 'Standing privilege minimised' -ManualReview $true `
                -RepoXRef 'EIG-AR002' `
                -ManualReviewNote "PIM assignment call failed: $pimError PIM requires Entra ID P2 or Entra ID Governance, but confirm against the error above rather than assuming a licensing cause. Review in Entra admin center > Identity Governance > Privileged Identity Management > Microsoft Entra roles > Assignments."))
}

# G-05 workload identity credential lifetime
$longLivedSecretThresholdDays = 365
$appCall = Invoke-ITPSCollection -Uri 'applications'
if (-not $appCall.Ok) {
    Write-Status "Application registrations unavailable — flagging G-05 for manual review. $($appCall.Error)" -Level Warn
}
elseif ($appCall.Items.Count -eq 0) {
    Write-Status 'No application registrations exist in this tenant — G-05 earns full points by default.' -Level OK
}
$appRegs = $appCall.Items

if ($appCall.Ok) {
    # The predicate matches secrets that never expire or that run beyond the
    # threshold. It deliberately does not match already-expired secrets: an expired
    # credential cannot authenticate, so it is not the risk being measured. The check
    # was previously named "credential hygiene" with an AppsWithStaleSecrets signal,
    # which described neither what is matched nor why it matters.
    $longLivedSecretApps = @($appRegs | Where-Object {
            $creds = @(Get-ITPSProp $_ 'passwordCredentials')
            @($creds | Where-Object {
                    $end = Get-ITPSProp $_ 'endDateTime'
                    $null -eq $end -or ([datetime]$end - [datetime]::UtcNow).TotalDays -gt $longLivedSecretThresholdDays
                }).Count -gt 0
        }).Count

    # Linear on the share of registrations carrying a long-lived secret, matching
    # G-04's treatment of standing privilege. The previous binary scored 0 of 20 for
    # a single offending registration, so a tenant with 2 of 10 affected scored the
    # same as one with 10 of 10.
    $g05Points = if ($appRegs.Count -gt 0) {
        [Math]::Round((1 - ($longLivedSecretApps / $appRegs.Count)) * 20, 2)
    }
    else { 20 }

    $governanceChecks.Add((New-ITPSCheck -Id 'G-05' -Name 'Workload identity credential lifetime' `
                -Points $g05Points -MaxPoints 20 `
                -Signal @{
                AppRegistrationCount      = $appRegs.Count
                AppsWithLongLivedSecrets  = $longLivedSecretApps
                LongLivedThresholdDays    = $longLivedSecretThresholdDays
                ScoringNote               = 'Linear on the share of registrations holding a secret that never expires or runs beyond the threshold. Already-expired secrets are not counted, because an expired credential cannot authenticate.'
            }))
}
else {
    $governanceChecks.Add((New-ITPSCheck -Id 'G-05' -Name 'Workload identity credential lifetime' `
                -ManualReview $true `
                -ManualReviewNote "Application registration call failed: $($appCall.Error) Review in Entra admin center > Identity > Applications > App registrations > Certificates and secrets for each application."))
}

$governanceScore = Get-DimensionScore -Checks $governanceChecks.ToArray()
Write-Status "Governance score: $governanceScore" -Level OK

# ── Dimension 4 — Ownership ───────────────────────────────────────────────────

Write-Status 'Assessing Ownership...'
Write-Status 'Ownership has no tenant API and is scored manually.' -Level Skip
$ownershipChecks = [System.Collections.Generic.List[PSCustomObject]]::new()

$ownershipNote = 'Ownership is an organisational fact and has no tenant API. Score by hand against Examples/Ownership-Matrix-Template.md.'
foreach ($c in @(
        @{ Id = 'O-01'; Name = 'Ownership matrix exists' },
        @{ Id = 'O-02'; Name = 'Named owner per control area' },
        @{ Id = 'O-03'; Name = 'Backup owner named' },
        @{ Id = 'O-04'; Name = 'Review cadence defined' },
        @{ Id = 'O-05'; Name = 'Last reviewed within cadence' },
        @{ Id = 'O-06'; Name = 'Escalation path defined' })) {
    $ownershipChecks.Add((New-ITPSCheck -Id $c.Id -Name $c.Name -ManualReview $true `
                -ManualReviewNote $ownershipNote))
}

$ownershipScore = Get-DimensionScore -Checks $ownershipChecks.ToArray()

# ── Result assembly ───────────────────────────────────────────────────────────

Write-Status 'Assembling result...'

$dimensions = @(
    [PSCustomObject]@{ Name = 'Prevention'; Score = $preventionScore; Weight = 25; Checks = $preventionChecks.ToArray() }
    [PSCustomObject]@{ Name = 'Detection'; Score = $detectionScore; Weight = 25; Checks = $detectionChecks.ToArray() }
    [PSCustomObject]@{ Name = 'Governance'; Score = $governanceScore; Weight = 25; Checks = $governanceChecks.ToArray() }
    [PSCustomObject]@{ Name = 'Ownership'; Score = $ownershipScore; Weight = 25; Checks = $ownershipChecks.ToArray() }
)

$scoredDimensions = @($dimensions | Where-Object { $null -ne $_.Score })
$unscoredDimensions = @($dimensions | Where-Object { $null -eq $_.Score } | ForEach-Object { $_.Name })

$overallScore = if ($scoredDimensions.Count -eq 0) {
    $null
}
else {
    [int][Math]::Round((($scoredDimensions | Measure-Object -Property Score -Average).Average), 0,
        [MidpointRounding]::AwayFromZero)
}

$allChecks = @($dimensions | ForEach-Object { $_.Checks })
$manualReviewCount = @($allChecks | Where-Object { $_.ManualReview }).Count
$isPartial = $unscoredDimensions.Count -gt 0

$result = [PSCustomObject]@{
    TenantId          = $TenantId
    TenantName        = $TenantName
    AssessmentDate    = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
    CollectorVersion  = $COLLECTOR_VERSION
    OverallScore      = $overallScore
    MaturityTier      = (Get-ITPSTier -Score $overallScore)
    IsPartialScore    = $isPartial
    UnscoredDimensions = $unscoredDimensions
    ManualReviewCount = $manualReviewCount
    TotalCheckCount   = $allChecks.Count
    GraphScopesUsed   = $REQUIRED_SCOPES
    TierBandSource    = 'Cloud Harbor Consulting scoring convention. Microsoft does not publish numeric thresholds for its Connected/Protected/Fortified/Resilient tiers.'
    Dimensions        = $dimensions
}

# ── Summary output ────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '=============================================================='
Write-Host "  ITPS - Identity Threat Protection Scorecard   $($result.AssessmentDate)"
$tenantDisplay = if ($TenantName) { "$TenantName ($TenantId)" } else { $TenantId }
Write-Host "  Tenant:     $tenantDisplay"
Write-Host "  Collector:  $COLLECTOR_VERSION"
$scoreLabel = if ($null -ne $overallScore) { "$overallScore / 100 - $($result.MaturityTier)" } else { 'Not scored' }
Write-Host "  Overall:    $scoreLabel"
Write-Host "  Manual:     $manualReviewCount of $($allChecks.Count) checks require manual assessment"
Write-Host '=============================================================='
foreach ($dim in $result.Dimensions) {
    $dimScore = if ($null -ne $dim.Score) { "$($dim.Score) / 100" } else { 'manual only' }
    $dimManual = @($dim.Checks | Where-Object { $_.ManualReview }).Count
    Write-Host ("  {0,-12} {1,-14} ({2} manual)" -f $dim.Name, $dimScore, $dimManual)
}
Write-Host '=============================================================='
if ($isPartial) {
    Write-Host ''
    Write-Host "  PARTIAL SCORE. Unscored dimensions: $($unscoredDimensions -join ', ')"
    Write-Host '  Treat this as an upper bound. Completing the manual checks can only lower it.'
}
Write-Host ''
Write-Host '  Next step: pipe this result to Format-ITPScorecardReport.ps1'
Write-Host ''

# ── JSON export ───────────────────────────────────────────────────────────────

if ($ExportJson) {
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $exportFile = Join-Path $OutputPath "ITPSResult-$timestamp.json"
    $result | ConvertTo-Json -Depth 10 | Set-Content -Path $exportFile -Encoding UTF8
    Write-Status "JSON exported: $exportFile" -Level OK
}

# ── Disconnect and return ─────────────────────────────────────────────────────

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
return $result
