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
    The Entra tenant ID to assess.
.PARAMETER OutputPath
    Directory path for JSON export when -ExportJson is specified. Default: current directory.
.PARAMETER ExportJson
    When present, exports the result object to a timestamped JSON file in OutputPath.
.EXAMPLE
    .\Get-ITPScorecard.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
.EXAMPLE
    .\Get-ITPScorecard.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -ExportJson -OutputPath 'C:\Reports'
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri,
        [string]$ApiVersion = 'v1.0'
    )
    $base = "https://graph.microsoft.com/$ApiVersion"
    $fullUri = if ($Uri -match '^https?://') { $Uri } else { "$base/$($Uri.TrimStart('/'))" }
    $results = [System.Collections.Generic.List[object]]::new()
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $fullUri -OutputType PSObject
        $hasValue = ($null -ne $response) -and
                    ($response.PSObject.Properties.Name -contains 'value')
        if ($hasValue) {
            $results.AddRange([object[]]($response.value))
        }
        else {
            return $response
        }
        $fullUri = if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $response.'@odata.nextLink'
        }
        else {
            $null
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
    return [int][Math]::Round(($earned / $available) * 100, 0)
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
$secureScore = try {
    @(Invoke-ITPSGraphRequest -Uri 'security/secureScores?$top=1') | Select-Object -First 1
}
catch {
    Write-Status 'Secure Score unavailable — flagging P-01 for manual review.' -Level Warn
    $null
}

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
    $preventionChecks.Add((New-ITPSCheck -Id 'P-01' -Name 'Secure Score attainment' `
                -ManualReview $true `
                -ManualReviewNote 'Secure Score not returned. Review in Microsoft Defender portal > Exposure management > Secure score, and filter to the Identity category.'))
}

# CA policy checks P-02 through P-06
$caPolicies = try {
    @(Invoke-ITPSGraphRequest -Uri 'identity/conditionalAccess/policies')
}
catch {
    Write-Status 'Conditional Access policies unavailable — flagging P-02..P-06 for manual review.' -Level Warn
    $null
}

if ($null -ne $caPolicies) {
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
                    -ManualReviewNote 'Conditional Access policies not returned. Review in Entra admin center > Protection > Conditional Access > Policies.'))
    }
}

$preventionScore = Get-DimensionScore -Checks $preventionChecks.ToArray()
Write-Status "Prevention score: $preventionScore" -Level OK

# ── Dimension 2 — Detection ───────────────────────────────────────────────────

Write-Status 'Assessing Detection...'
$detectionChecks = [System.Collections.Generic.List[PSCustomObject]]::new()

$healthIssues = try {
    @(Invoke-ITPSGraphRequest -Uri "security/identities/healthIssues?`$filter=Status eq 'open'")
}
catch {
    Write-Status 'Defender for Identity health issues unavailable — flagging D-01..D-04 for manual review.' -Level Warn
    $null
}

if ($null -ne $healthIssues) {
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
                -Signal @{ TotalOpenIssues = $healthIssues.Count; Reachable = $true }))
}
else {
    foreach ($c in @(
            @{ Id = 'D-01'; Name = 'No open high-severity health issues' },
            @{ Id = 'D-02'; Name = 'No open medium-severity health issues' },
            @{ Id = 'D-03'; Name = 'Sensor health issues resolved' },
            @{ Id = 'D-04'; Name = 'Health signal reachable' })) {
        $detectionChecks.Add((New-ITPSCheck -Id $c.Id -Name $c.Name -ManualReview $true `
                    -ManualReviewNote 'Defender for Identity health issues not returned. This usually means Defender for Identity is not licensed or not provisioned. Review in Microsoft Defender portal > Settings > Identities > Health issues.'))
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
$accessReviews = try {
    @(Invoke-ITPSGraphRequest -Uri 'identityGovernance/accessReviews/definitions')
}
catch {
    Write-Status 'Access review definitions unavailable — flagging G-01 and G-02 for manual review.' -Level Warn
    $null
}

if ($null -ne $accessReviews) {
    $reviewCount = $accessReviews.Count
    $guestReviewPresent = @($accessReviews | Where-Object {
            (Get-ITPSProp $_ 'displayName') -match '(?i)guest' -or
            (Get-ITPSProp $_ 'scope.query') -match '(?i)guest'
        }).Count -gt 0

    $governanceChecks.Add((New-ITPSCheck -Id 'G-01' -Name 'Access reviews configured' `
                -Points ($(if ($reviewCount -gt 0) { 20 } else { 0 })) -MaxPoints 20 `
                -RepoXRef 'EIG-AR001, EIG-AR002' -Signal @{ ReviewDefinitionCount = $reviewCount }))
    $governanceChecks.Add((New-ITPSCheck -Id 'G-02' -Name 'Guest access reviewed' `
                -Points ($(if ($guestReviewPresent) { 15 } else { 0 })) -MaxPoints 15 `
                -RepoXRef 'EIG-AR001' -Signal @{ GuestReviewPresent = $guestReviewPresent }))
}
else {
    foreach ($c in @(
            @{ Id = 'G-01'; Name = 'Access reviews configured' },
            @{ Id = 'G-02'; Name = 'Guest access reviewed' })) {
        $governanceChecks.Add((New-ITPSCheck -Id $c.Id -Name $c.Name -ManualReview $true `
                    -ManualReviewNote 'Access review definitions not returned. Requires Entra ID P2 or Entra ID Governance. Review in Entra admin center > Identity Governance > Access reviews.'))
    }
}

# G-03, G-04 PIM
$pimData = try {
    $eligible = @(Invoke-ITPSGraphRequest -Uri 'roleManagement/directory/roleEligibilityScheduleInstances').Count
    $active = @(Invoke-ITPSGraphRequest -Uri 'roleManagement/directory/roleAssignmentScheduleInstances')
    $permanent = @($active | Where-Object {
            (Get-ITPSProp $_ 'assignmentType') -eq 'Assigned' -and
            $null -eq (Get-ITPSProp $_ 'endDateTime')
        }).Count
    @{ Eligible = $eligible; Permanent = $permanent }
}
catch {
    Write-Status 'PIM assignment data unavailable — flagging G-03 and G-04 for manual review.' -Level Warn
    $null
}

if ($null -ne $pimData) {
    $totalAssignments = $pimData.Eligible + $pimData.Permanent
    # G-04 scales linearly: full points at zero standing privilege, zero points when
    # every privileged assignment is permanent.
    $standingRatio = if ($totalAssignments -gt 0) { $pimData.Permanent / $totalAssignments } else { 0 }
    $g04Points = [Math]::Round((1 - $standingRatio) * 25, 2)

    $governanceChecks.Add((New-ITPSCheck -Id 'G-03' -Name 'PIM eligible assignments in use' `
                -Points ($(if ($pimData.Eligible -gt 0) { 20 } else { 0 })) -MaxPoints 20 `
                -RepoXRef 'EIG-AR002' -Signal @{ EligibleCount = $pimData.Eligible }))
    $governanceChecks.Add((New-ITPSCheck -Id 'G-04' -Name 'Standing privilege minimised' `
                -Points $g04Points -MaxPoints 25 `
                -RepoXRef 'EIG-AR002' `
                -Signal @{
                PermanentCount = $pimData.Permanent
                EligibleCount  = $pimData.Eligible
                StandingRatio  = [Math]::Round($standingRatio, 3)
            }))
}
else {
    foreach ($c in @(
            @{ Id = 'G-03'; Name = 'PIM eligible assignments in use' },
            @{ Id = 'G-04'; Name = 'Standing privilege minimised' })) {
        $governanceChecks.Add((New-ITPSCheck -Id $c.Id -Name $c.Name -ManualReview $true `
                    -ManualReviewNote 'PIM assignment data not returned. Requires Entra ID P2 or Entra ID Governance. Review in Entra admin center > Identity Governance > Privileged Identity Management > Microsoft Entra roles > Assignments.'))
    }
}

# G-05 workload identity credential hygiene
$appRegs = try {
    @(Invoke-ITPSGraphRequest -Uri 'applications')
}
catch {
    Write-Status 'Application registrations unavailable — flagging G-05 for manual review.' -Level Warn
    $null
}

if ($null -ne $appRegs) {
    $staleSecretApps = @($appRegs | Where-Object {
            $creds = @(Get-ITPSProp $_ 'passwordCredentials')
            @($creds | Where-Object {
                    $end = Get-ITPSProp $_ 'endDateTime'
                    $null -eq $end -or ([datetime]$end - [datetime]::UtcNow).TotalDays -gt 365
                }).Count -gt 0
        }).Count

    $governanceChecks.Add((New-ITPSCheck -Id 'G-05' -Name 'Workload identity credential hygiene' `
                -Points ($(if ($staleSecretApps -eq 0) { 20 } else { 0 })) -MaxPoints 20 `
                -Signal @{
                AppRegistrationCount = $appRegs.Count
                AppsWithStaleSecrets = $staleSecretApps
            }))
}
else {
    $governanceChecks.Add((New-ITPSCheck -Id 'G-05' -Name 'Workload identity credential hygiene' `
                -ManualReview $true `
                -ManualReviewNote 'Application registrations not returned. Review in Entra admin center > Identity > Applications > App registrations > Certificates and secrets for each application.'))
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
    [int][Math]::Round((($scoredDimensions | Measure-Object -Property Score -Average).Average), 0)
}

$allChecks = @($dimensions | ForEach-Object { $_.Checks })
$manualReviewCount = @($allChecks | Where-Object { $_.ManualReview }).Count
$isPartial = $unscoredDimensions.Count -gt 0

$result = [PSCustomObject]@{
    TenantId          = $TenantId
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
Write-Host "  Tenant:     $TenantId"
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
