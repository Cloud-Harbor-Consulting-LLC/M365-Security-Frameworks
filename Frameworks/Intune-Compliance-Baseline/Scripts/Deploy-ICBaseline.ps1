#Requires -Version 7.0
<#
.SYNOPSIS
    Deploys the Intune Compliance Baseline templates to a Microsoft Intune tenant, in observation
    mode by default.

.DESCRIPTION
    Deploy-ICBaseline.ps1 deploys the ICB-* compliance policy templates through Microsoft Graph beta,
    using only the Microsoft.Graph.Authentication module. It talks to both Intune compliance APIs:

      - /deviceManagement/deviceCompliancePolicies   Windows, macOS, iOS/iPadOS, Android (classic)
      - /deviceManagement/compliancePolicies         Linux (Settings Catalog)

    OBSERVATION MODE (the default). Each policy is deployed with a single action: mark the device
    noncompliant after 365 days, the longest delay Intune allows. Devices report real compliance
    results in Intune, while Conditional Access treats them as compliant (in grace period), and no
    email is sent. Intune compliance policies have no report-only state and cannot drop the
    mark-noncompliant action, so this is the closest equivalent. See POLICY-DESIGN.md section 5.2.

    -ENFORCE applies each template's designed schedule (POLICY-DESIGN.md section 5.1): an email at
    0 hours and mark noncompliant at 0 or 168 hours, plus "add to retire list" for personally owned
    Android. It asks for confirmation unless -Force is given.

    The script is safe to re-run. Each template is matched to an existing policy by name:

      Absent                           Created, assigned, and read back.
      Present, schedule differs        The schedule is replaced with the one for the chosen mode.
                                       This is how -Enforce promotes an observed policy.
      Present, not assigned            Assigned to the template's persona group.
      Present, settings differ         Reported as Drift and left alone, unless -UpdateExisting is
                                       given (classic policies only; Settings Catalog policies are
                                       reported).

    Every write is read back from Graph and compared with the template. A setting, action or
    assignment that did not land as sent fails that template. This matters: Graph accepts a Linux
    policy created with an inline schedule and silently stores its own default (mark noncompliant
    at 0 hours) instead, so Linux schedules are set with a separate call after creation.

    Tenant-wide prerequisites (POLICY-DESIGN.md section 7.1) are read and warned about, never
    changed: "Mark devices with no compliance policy assigned as" should be Not compliant, and the
    compliance status validity period should be 7 days or fewer.

.PARAMETER PolicyPath
    Folder containing the JSON templates. Defaults to the Policies/ folder next to Scripts/.

.PARAMETER Template
    Deploy only the templates whose file names (without .json) match one of these wildcards,
    for example 'ICB-WIN*'. Default: all templates in -PolicyPath.

.PARAMETER Enforce
    Apply each template's designed schedule instead of observation mode.

.PARAMETER Force
    With -Enforce, skip the confirmation prompt.

.PARAMETER UpdateExisting
    Overwrite the settings of an existing classic policy that differ from its template. Without
    it, differences are reported as Drift and left in place.

.PARAMETER NotificationTemplateName
    Display name of the Intune notification message template used by the email action. Needed
    only with -Enforce. Matched case-insensitively. Default: ICB - Device noncompliant

.PARAMETER CorpWindowsGroupName
    Persona group for REPLACE_WITH_ICB_PERSONA_CORPWINDOWS_GROUP_OBJECT_ID. Default: ICB-Persona-CorpWindows

.PARAMETER CorpMacGroupName
    Persona group for REPLACE_WITH_ICB_PERSONA_CORPMAC_GROUP_OBJECT_ID. Default: ICB-Persona-CorpMac

.PARAMETER CorpMobileGroupName
    Persona group for REPLACE_WITH_ICB_PERSONA_CORPMOBILE_GROUP_OBJECT_ID. Default: ICB-Persona-CorpMobile

.PARAMETER BYODMobileGroupName
    Persona group for REPLACE_WITH_ICB_PERSONA_BYODMOBILE_GROUP_OBJECT_ID. Default: ICB-Persona-BYODMobile

.PARAMETER CorpLinuxGroupName
    Persona group for REPLACE_WITH_ICB_PERSONA_CORPLINUX_GROUP_OBJECT_ID. Default: ICB-Persona-CorpLinux

.PARAMETER StopOnError
    Stop at the first template that fails. By default the script continues and reports every
    failure at the end.

.PARAMETER MaxRetries
    Retries for throttled (429) or transient (500, 502, 503, 504) responses. Default 4.

.PARAMETER MaxPages
    Upper bound on pages read from any list. Default 50.

.EXAMPLE
    .\Deploy-ICBaseline.ps1 -WhatIf
    Reads the tenant and shows what would be created or changed, without writing anything.

.EXAMPLE
    .\Deploy-ICBaseline.ps1
    Deploys every template in observation mode.

.EXAMPLE
    .\Deploy-ICBaseline.ps1 -Template 'ICB-WIN001*' -Enforce
    Promotes ICB-WIN001 to its designed schedule after its observation period.

.NOTES
    Requires PowerShell 7 and the Microsoft.Graph.Authentication module.
    Graph scopes: DeviceManagementConfiguration.ReadWrite.All, Group.Read.All
      Connect-MgGraph -Scopes DeviceManagementConfiguration.ReadWrite.All, Group.Read.All
    Endpoint: https://graph.microsoft.com/beta (7 of ICB-WIN001's original settings are beta-only).

    Author: Derek Morgan, Cloud Harbor Consulting
    Repository: https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [string]$PolicyPath = (Join-Path $PSScriptRoot '..' 'Policies'),

    [string[]]$Template = @('*'),

    [switch]$Enforce,

    [switch]$Force,

    [switch]$UpdateExisting,

    [string]$NotificationTemplateName = 'ICB - Device noncompliant',

    [string]$CorpWindowsGroupName = 'ICB-Persona-CorpWindows',

    [string]$CorpMacGroupName = 'ICB-Persona-CorpMac',

    [string]$CorpMobileGroupName = 'ICB-Persona-CorpMobile',

    [string]$BYODMobileGroupName = 'ICB-Persona-BYODMobile',

    [string]$CorpLinuxGroupName = 'ICB-Persona-CorpLinux',

    [switch]$StopOnError,

    [ValidateRange(0, 10)]
    [int]$MaxRetries = 4,

    [ValidateRange(1, 1000)]
    [int]$MaxPages = 50
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GraphBeta = 'https://graph.microsoft.com/beta'
$GraphV1 = 'https://graph.microsoft.com/v1.0'
$ClassicUri = "$GraphBeta/deviceManagement/deviceCompliancePolicies"
$CatalogUri = "$GraphBeta/deviceManagement/compliancePolicies"
$ZeroGuid = '00000000-0000-0000-0000-000000000000'

# Observation mode: mark noncompliant after 365 days, Intune's maximum.
$ObservationGraceHours = 8760

# Declared once, and used for the check, the connect hint and the help text above.
$RequiredScopes = @('DeviceManagementConfiguration.ReadWrite.All', 'Group.Read.All')

# Template properties that identify or describe a policy rather than configure it. They are not
# compared when checking an existing policy for drift.
$NonSettingKeys = @('@odata.type', 'id', 'displayName', 'name', 'description', 'roleScopeTagIds', 'scheduledActionsForRule', 'assignments', 'settings', 'platforms', 'technologies')

#region Helpers

function Write-Status {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')][string]$Level = 'Info'
    )
    $color = switch ($Level) { 'Success' { 'Green' } 'Warning' { 'Yellow' } 'Error' { 'Red' } default { 'Cyan' } }
    $prefix = switch ($Level) { 'Success' { '[OK]   ' } 'Warning' { '[WARN] ' } 'Error' { '[ERR]  ' } default { '[INFO] ' } }
    Write-Host "$prefix$Message" -ForegroundColor $color
}

function Get-Prop {
    # Strict-mode-safe read from a dictionary or an object. Returns $null when absent.
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function ConvertTo-OrderedData {
    # Turns parsed JSON (PSCustomObject trees) into ordered dictionaries, keeping property order.
    # Graph expects "@odata.type" ahead of the properties it types, so order is preserved.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) { $ordered[$p.Name] = ConvertTo-OrderedData $p.Value }
        return $ordered
    }
    if ($Value -is [System.Collections.IList] -and $Value -isnot [string]) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($v in $Value) { $items.Add((ConvertTo-OrderedData $v)) }
        return , $items.ToArray()
    }
    return $Value
}

function ConvertTo-CanonicalJson {
    # Order-independent JSON for comparisons: keys sorted at every level. -DropNull removes
    # null-valued properties, for Settings Catalog read-backs that add null template references.
    param($Value, [switch]$DropNull)
    function Format-Node($Node) {
        if ($null -eq $Node) { return $null }
        if ($Node -is [System.Collections.IDictionary] -or $Node -is [System.Management.Automation.PSCustomObject]) {
            $pairs = if ($Node -is [System.Collections.IDictionary]) { @($Node.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $Node[$_] } }) }
            else { @($Node.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
            $sorted = [ordered]@{}
            foreach ($pair in ($pairs | Sort-Object Name)) {
                if ($DropNull -and $null -eq $pair.Value) { continue }
                $sorted[$pair.Name] = Format-Node $pair.Value
            }
            return $sorted
        }
        if ($Node -is [System.Collections.IList] -and $Node -isnot [string]) {
            return , @($Node | ForEach-Object { Format-Node $_ })
        }
        return $Node
    }
    return (ConvertTo-Json -InputObject (Format-Node $Value) -Depth 50 -Compress)
}

function Get-RetryDelay {
    # Honours Retry-After when Graph sends one, otherwise backs off exponentially. Capped at 60s.
    param($Headers, [Parameter(Mandatory)][int]$Attempt)
    $retryAfter = $null
    if ($Headers) {
        foreach ($key in @($Headers.Keys)) { if ($key -ieq 'Retry-After') { $retryAfter = @($Headers[$key])[0] } }
    }
    [int]$seconds = 0
    if ($null -ne $retryAfter -and [int]::TryParse([string]$retryAfter, [ref]$seconds) -and $seconds -gt 0) {
        return [Math]::Min($seconds, 60)
    }
    return [int][Math]::Min([Math]::Pow(2, [Math]::Max($Attempt, 0)), 60)
}

function Invoke-ICBGraph {
    # One Graph call with throttle-aware retry. Returns the parsed body, or $null for an empty one
    # (assign and both schedule actions answer 200 with an empty body). Throws on any other status.
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        $Body
    )
    $json = if ($null -ne $Body) { ConvertTo-Json -InputObject $Body -Depth 50 -Compress } else { $null }
    $attempt = 0
    while ($true) {
        $attempt++
        $statusCode = $null
        $responseHeaders = $null
        $request = @{
            Method = $Method; Uri = $Uri; OutputType = 'Json'; SkipHttpErrorCheck = $true
            StatusCodeVariable = 'statusCode'; ResponseHeadersVariable = 'responseHeaders'
        }
        if ($json) { $request['Body'] = $json; $request['ContentType'] = 'application/json' }
        $raw = [string](Invoke-MgGraphRequest @request)

        if ($statusCode -ge 200 -and $statusCode -lt 300) {
            if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
            return ($raw | ConvertFrom-Json)
        }
        if ($statusCode -in 429, 500, 502, 503, 504 -and $attempt -le $MaxRetries) {
            $delay = Get-RetryDelay -Headers $responseHeaders -Attempt $attempt
            Write-Status ("Graph returned {0} for {1}; retrying in {2}s ({3} of {4})" -f $statusCode, $Method, $delay, $attempt, $MaxRetries) -Level Warning
            Start-Sleep -Seconds $delay
            continue
        }
        $detail = $null
        try { $detail = [string](Get-Prop (Get-Prop ($raw | ConvertFrom-Json) 'error') 'message') } catch { $detail = $null }
        if (-not $detail -and $raw) { $detail = $raw.Substring(0, [Math]::Min(300, $raw.Length)) }
        throw "$Method $Uri returned HTTP $statusCode$(if ($detail) { ": $detail" })"
    }
}

function Get-AllItem {
    # Follows @odata.nextLink up to -MaxPages; emits each item. Callers wrap the call in @().
    param([Parameter(Mandatory)][string]$Uri)
    $next = $Uri
    $pages = 0
    while ($next) {
        $pages++
        if ($pages -gt $MaxPages) { throw "Stopped reading $Uri after $MaxPages pages; raise -MaxPages." }
        $page = Invoke-ICBGraph -Method GET -Uri $next
        foreach ($item in @(Get-Prop $page 'value' | Where-Object { $null -ne $_ })) { $item }
        $next = Get-Prop $page '@odata.nextLink'
    }
}

function Resolve-GroupId {
    param([Parameter(Mandatory)][string]$DisplayName)
    $escaped = $DisplayName -replace "'", "''"
    $groups = @(Get-AllItem -Uri "$GraphV1/groups?`$filter=displayName eq '$escaped'&`$select=id,displayName")
    if ($groups.Count -eq 0) { throw "Group not found in tenant: '$DisplayName'. Create it (POLICY-DESIGN.md section 3) or pass its name with the matching -<Persona>GroupName parameter." }
    if ($groups.Count -gt 1) { throw "Multiple groups are named '$DisplayName'. Persona group names must be unique." }
    return [string](Get-Prop $groups[0] 'id')
}

function Resolve-NotificationTemplateId {
    param([Parameter(Mandatory)][string]$DisplayName)
    $templates = @(Get-AllItem -Uri "$GraphBeta/deviceManagement/notificationMessageTemplates")
    $match = @($templates | Where-Object { [string](Get-Prop $_ 'displayName') -eq $DisplayName })
    if ($match.Count -eq 0) { throw "Notification message template not found: '$DisplayName'. -Enforce emails users, so create it (POLICY-DESIGN.md section 7.1) or pass -NotificationTemplateName." }
    if ($match.Count -gt 1) { throw "Multiple notification message templates are named '$DisplayName'." }
    return [string](Get-Prop $match[0] 'id')
}

function Get-TemplateApi {
    # Classic templates carry a per-platform @odata.type; Settings Catalog templates carry
    # platforms and settings.
    param([Parameter(Mandatory)]$Body)
    $type = [string](Get-Prop $Body '@odata.type')
    if ($type -like '#microsoft.graph.*CompliancePolicy' -and $type -ne '#microsoft.graph.deviceManagementCompliancePolicy') { return 'Classic' }
    if ($null -ne (Get-Prop $Body 'platforms') -and $null -ne (Get-Prop $Body 'settings')) { return 'Catalog' }
    throw "Unrecognized template shape: expected a per-platform '@odata.type' (classic API) or 'platforms' with 'settings' (Settings Catalog)."
}

function Get-ActionKey {
    # One comparable string per action. The template ID only matters for the email action; the
    # block action's ID is always the all-zeros GUID, however the template wrote it.
    param([Parameter(Mandatory)]$Action)
    $type = [string](Get-Prop $Action 'actionType')
    $template = [string](Get-Prop $Action 'notificationTemplateId')
    if ($type -ne 'notification' -or -not $template) { $template = $ZeroGuid }
    return '{0}@{1}h/{2}' -f $type, [int](Get-Prop $Action 'gracePeriodHours'), $template.ToLowerInvariant()
}

function Get-ScheduleKey {
    param([object[]]$Actions)
    return (@($Actions | ForEach-Object { Get-ActionKey $_ } | Sort-Object) -join ', ')
}

function New-ModeSchedule {
    # The actions a policy should carry in the chosen mode. Observation keeps only
    # mark-noncompliant, moved to 365 days: no email, no retire list.
    param(
        [Parameter(Mandatory)][object[]]$TemplateActions,
        [Parameter(Mandatory)][bool]$EnforceMode,
        [string]$TemplateId
    )
    $blocks = @($TemplateActions | Where-Object { (Get-Prop $_ 'actionType') -eq 'block' })
    if ($blocks.Count -ne 1) { throw "The template must have exactly one 'block' (mark noncompliant) action; it has $($blocks.Count)." }
    $result = [System.Collections.Generic.List[object]]::new()
    if (-not $EnforceMode) {
        $result.Add([ordered]@{ actionType = 'block'; gracePeriodHours = $ObservationGraceHours; notificationTemplateId = $ZeroGuid; notificationMessageCCList = @() })
        return , $result.ToArray()
    }
    foreach ($action in $TemplateActions) {
        $type = [string](Get-Prop $action 'actionType')
        $id = [string](Get-Prop $action 'notificationTemplateId')
        if ($type -eq 'notification') {
            if (-not $TemplateId) { throw 'The template emails users, but no notification message template was resolved.' }
            $id = $TemplateId
        }
        elseif (-not $id -or $id -like 'REPLACE_WITH_*') { $id = $ZeroGuid }
        $cc = @(Get-Prop $action 'notificationMessageCCList' | Where-Object { $_ })
        $result.Add([ordered]@{ actionType = $type; gracePeriodHours = [int](Get-Prop $action 'gracePeriodHours'); notificationTemplateId = $id; notificationMessageCCList = $cc })
    }
    return , $result.ToArray()
}

function Get-SettingsDrift {
    # Names of template settings whose values differ from the policy in the tenant.
    param([Parameter(Mandatory)][string]$Api, [Parameter(Mandatory)]$Desired, [Parameter(Mandatory)]$Current, $CurrentSettings)
    $differences = [System.Collections.Generic.List[string]]::new()
    if ($Api -eq 'Classic') {
        foreach ($key in @($Desired.Keys)) {
            if ($key -in $NonSettingKeys) { continue }
            $want = ConvertTo-CanonicalJson (Get-Prop $Desired $key)
            $have = ConvertTo-CanonicalJson (Get-Prop $Current $key)
            if ($want -ne $have) { $differences.Add("$key (template $want, tenant $have)") }
        }
    }
    else {
        $want = @(@(Get-Prop $Desired 'settings') | ForEach-Object { Get-Prop $_ 'settingInstance' } | Sort-Object { [string](Get-Prop $_ 'settingDefinitionId') } | ForEach-Object { ConvertTo-CanonicalJson $_ -DropNull })
        $have = @(@($CurrentSettings) | ForEach-Object { Get-Prop $_ 'settingInstance' } | Sort-Object { [string](Get-Prop $_ 'settingDefinitionId') } | ForEach-Object { ConvertTo-CanonicalJson $_ -DropNull })
        if (($want -join "`n") -ne ($have -join "`n")) { $differences.Add('settings') }
    }
    return , $differences.ToArray()
}

function Get-PolicyState {
    # Reads a policy back: properties, settings (Settings Catalog), actions and assigned groups.
    param([Parameter(Mandatory)][string]$Api, [Parameter(Mandatory)][string]$Id)
    if ($Api -eq 'Classic') {
        $policy = Invoke-ICBGraph -Method GET -Uri "$ClassicUri/$Id`?`$expand=scheduledActionsForRule(`$expand=scheduledActionConfigurations)"
        $rules = @(Get-Prop $policy 'scheduledActionsForRule' | Where-Object { $null -ne $_ })
        $actions = @($rules | ForEach-Object { @(Get-Prop $_ 'scheduledActionConfigurations') } | Where-Object { $null -ne $_ })
        $settings = $null
        $assignUri = "$ClassicUri/$Id/assignments"
    }
    else {
        $policy = Invoke-ICBGraph -Method GET -Uri "$CatalogUri/$Id"
        $settings = @(Get-AllItem -Uri "$CatalogUri/$Id/settings")
        $rules = @(Get-AllItem -Uri "$CatalogUri/$Id/scheduledActionsForRule?`$expand=scheduledActionConfigurations")
        $actions = @($rules | ForEach-Object { @(Get-Prop $_ 'scheduledActionConfigurations') } | Where-Object { $null -ne $_ })
        $assignUri = "$CatalogUri/$Id/assignments"
    }
    $assignments = @(Get-AllItem -Uri $assignUri)
    [pscustomobject]@{
        Policy      = $policy
        Settings    = $settings
        Actions     = $actions
        Assignments = $assignments
        GroupIds    = @($assignments | ForEach-Object { [string](Get-Prop (Get-Prop $_ 'target') 'groupId') } | Where-Object { $_ })
    }
}

function Set-PolicySchedule {
    param([Parameter(Mandatory)][string]$Api, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][object[]]$Actions, $RuleName)
    $rule = [ordered]@{ ruleName = $RuleName; scheduledActionConfigurations = $Actions }
    if ($Api -eq 'Classic') {
        [void](Invoke-ICBGraph -Method POST -Uri "$ClassicUri/$Id/scheduleActionsForRules" -Body ([ordered]@{ deviceComplianceScheduledActionForRules = @($rule) }))
    }
    else {
        [void](Invoke-ICBGraph -Method POST -Uri "$CatalogUri/$Id/setScheduledActions" -Body ([ordered]@{ scheduledActions = @($rule) }))
    }
}

function Set-PolicyAssignment {
    # Sends the existing assignments plus the missing groups. Intune's assign action sets the
    # policy's full assignment list, so sending only the new group would drop the others.
    param([Parameter(Mandatory)][string]$Api, [Parameter(Mandatory)][string]$Id, [object[]]$Existing, [Parameter(Mandatory)][string[]]$AddGroupIds)
    $targets = [System.Collections.Generic.List[object]]::new()
    foreach ($assignment in @($Existing)) {
        if ($null -eq $assignment) { continue }
        $targets.Add([ordered]@{ target = (ConvertTo-OrderedData (Get-Prop $assignment 'target')) })
    }
    foreach ($groupId in $AddGroupIds) {
        $targets.Add([ordered]@{ target = [ordered]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $groupId } })
    }
    $uri = if ($Api -eq 'Classic') { "$ClassicUri/$Id/assign" } else { "$CatalogUri/$Id/assign" }
    [void](Invoke-ICBGraph -Method POST -Uri $uri -Body ([ordered]@{ assignments = $targets.ToArray() }))
}

function Test-PolicyState {
    # Compares a read-back with what was intended. Returns the mismatches; empty means clean.
    param([Parameter(Mandatory)][string]$Api, [Parameter(Mandatory)]$Desired, [Parameter(Mandatory)][object[]]$DesiredActions, [string[]]$DesiredGroupIds, [Parameter(Mandatory)]$State, [bool]$CheckSettings = $true)
    $problems = [System.Collections.Generic.List[string]]::new()
    if ($CheckSettings) {
        foreach ($d in (Get-SettingsDrift -Api $Api -Desired $Desired -Current $State.Policy -CurrentSettings $State.Settings)) { $problems.Add("setting $d") }
    }
    $wantSchedule = Get-ScheduleKey $DesiredActions
    $haveSchedule = Get-ScheduleKey $State.Actions
    if ($wantSchedule -ne $haveSchedule) { $problems.Add("schedule (sent $wantSchedule; tenant has $haveSchedule)") }
    foreach ($g in @($DesiredGroupIds)) { if ($g -notin $State.GroupIds) { $problems.Add("assignment to group $g") } }
    return , $problems.ToArray()
}

#endregion

#region Main

try {
    Write-Status 'Deploy-ICBaseline starting'
    $isWhatIf = [bool]$WhatIfPreference
    $mode = if ($Enforce) { 'Enforce' } else { 'Observation' }
    Write-Status ("Mode: {0}" -f $(if ($Enforce) { 'ENFORCE (designed schedules)' } else { "observation (mark noncompliant after $ObservationGraceHours hours, no email)" }))
    if ($isWhatIf) { Write-Status 'WhatIf: the tenant is read, nothing is written.' -Level Warning }

    # --- Templates --------------------------------------------------------------------------
    $resolvedPath = Resolve-Path -Path $PolicyPath -ErrorAction SilentlyContinue
    if (-not $resolvedPath) { throw "Policy path not found: $PolicyPath" }
    $files = @(Get-ChildItem -Path $resolvedPath -Filter '*.json' -File | Where-Object {
            $base = $_.BaseName
            @($Template | Where-Object { $base -like $_ }).Count -gt 0
        } | Sort-Object Name)
    if ($files.Count -eq 0) { throw "No JSON templates matching '$($Template -join "', '")' in $resolvedPath" }
    Write-Status "Templates: $($files.Count) in $resolvedPath" -Level Success

    # --- Session ------------------------------------------------------------------------------
    if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
        throw 'Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    $connectHint = "Connect-MgGraph -Scopes $($RequiredScopes -join ', ')"
    $context = Get-MgContext
    if (-not $context) { throw "Not connected to Microsoft Graph. Run: $connectHint" }
    $scopes = @(Get-Prop $context 'Scopes' | Where-Object { $_ })
    $missing = @($RequiredScopes | Where-Object { $_ -notin $scopes })
    if ($scopes.Count -gt 0 -and $missing.Count -gt 0) { throw "The Graph session lacks $($missing -join ', '). Reconnect with: $connectHint" }
    if ($scopes.Count -eq 0) { Write-Status "Could not read the session's scopes; Graph will refuse any call the session cannot make." -Level Warning }
    Write-Status ("Connected tenant: {0}" -f (Get-Prop $context 'TenantId')) -Level Success

    # --- Tenant prerequisites (read only) -----------------------------------------------------
    try {
        $tenantSettings = Invoke-ICBGraph -Method GET -Uri "$GraphBeta/deviceManagement/settings"
        if ((Get-Prop $tenantSettings 'secureByDefault') -ne $true) {
            Write-Status "Tenant setting 'Mark devices with no compliance policy assigned as' is Compliant. Set it to Not compliant (POLICY-DESIGN.md section 7.1); until then a device outside every compliance policy passes Conditional Access's 'require compliant device'." -Level Warning
        }
        $threshold = Get-Prop $tenantSettings 'deviceComplianceCheckinThresholdDays'
        if ($null -ne $threshold -and [int]$threshold -gt 7) {
            Write-Status "Tenant setting 'Compliance status validity period' is $threshold days. ICB expects 7 or fewer (POLICY-DESIGN.md section 7.1)." -Level Warning
        }
    }
    catch {
        Write-Status "Could not read the tenant-wide compliance settings ($($_.Exception.Message)). Check them by hand: POLICY-DESIGN.md section 7.1." -Level Warning
    }

    # --- Existing policies --------------------------------------------------------------------
    $existingClassic = @(Get-AllItem -Uri "$ClassicUri`?`$select=id,displayName")
    $existingCatalog = @(Get-AllItem -Uri "$CatalogUri`?`$select=id,name")

    if ($Enforce -and -not $isWhatIf -and -not $Force) {
        if (-not $PSCmdlet.ShouldContinue("Apply the designed schedules to $($files.Count) template(s) on tenant $(Get-Prop $context 'TenantId')? Noncompliant devices will be emailed and, once each schedule elapses, blocked by Conditional Access policies that require a compliant device.", 'Confirm enforced deployment')) {
            Write-Status 'Cancelled.' -Level Warning
            return
        }
    }

    $groupCache = @{}
    $script:NotificationTemplateId = $null
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($file in $files) {
        $row = [ordered]@{ Template = $file.BaseName; Policy = ''; Api = ''; Status = ''; Actions = ''; Detail = '' }
        $actionsTaken = [System.Collections.Generic.List[string]]::new()
        try {
            $raw = Get-Content -Path $file.FullName -Raw

            # Persona groups, resolved only for the templates being deployed.
            foreach ($m in @([regex]::Matches($raw, 'REPLACE_WITH_ICB_PERSONA_([A-Z]+)_GROUP_OBJECT_ID') | ForEach-Object { $_ })) {
                $persona = $m.Groups[1].Value
                if (-not $groupCache.ContainsKey($persona)) {
                    $groupName = switch ($persona) {
                        'CORPWINDOWS' { $CorpWindowsGroupName } 'CORPMAC' { $CorpMacGroupName } 'CORPMOBILE' { $CorpMobileGroupName }
                        'BYODMOBILE' { $BYODMobileGroupName } 'CORPLINUX' { $CorpLinuxGroupName }
                        default { throw "Unknown persona placeholder: $($m.Value)" }
                    }
                    $groupCache[$persona] = Resolve-GroupId -DisplayName $groupName
                }
                $raw = $raw.Replace($m.Value, $groupCache[$persona])
            }
            # The email action's template ID is substituted when the schedule is built.
            if ($raw -match 'REPLACE_WITH_(?!NOTIFICATION_TEMPLATE_ID)') { throw "Unresolved placeholder in $($file.Name): $($Matches[0])..." }

            $body = ConvertTo-OrderedData ($raw | ConvertFrom-Json)
            $api = Get-TemplateApi $body
            $row.Api = $api
            $name = if ($api -eq 'Classic') { [string](Get-Prop $body 'displayName') } else { [string](Get-Prop $body 'name') }
            if (-not $name) { throw 'The template has no displayName (classic) or name (Settings Catalog).' }
            $row.Policy = $name

            $templateRules = @(Get-Prop $body 'scheduledActionsForRule' | Where-Object { $null -ne $_ })
            if ($templateRules.Count -ne 1) { throw "The template must have exactly one scheduledActionsForRule entry; it has $($templateRules.Count)." }
            $templateActions = @(Get-Prop $templateRules[0] 'scheduledActionConfigurations' | Where-Object { $null -ne $_ })
            $ruleName = Get-Prop $templateRules[0] 'ruleName'
            if ($Enforce -and @($templateActions | Where-Object { (Get-Prop $_ 'actionType') -eq 'notification' }).Count -gt 0 -and -not $script:NotificationTemplateId) {
                $script:NotificationTemplateId = Resolve-NotificationTemplateId -DisplayName $NotificationTemplateName
            }
            $desiredActions = New-ModeSchedule -TemplateActions $templateActions -EnforceMode ([bool]$Enforce) -TemplateId $script:NotificationTemplateId
            $desiredGroups = @(@(Get-Prop $body 'assignments') | Where-Object { $null -ne $_ } | ForEach-Object { [string](Get-Prop (Get-Prop $_ 'target') 'groupId') } | Where-Object { $_ })
            if ($desiredGroups.Count -eq 0) { throw 'The template has no group assignment.' }

            # The body sent on create: everything except the actions and assignments, which are
            # written separately, except that classic policies keep their schedule inline.
            $createBody = [ordered]@{}
            foreach ($key in @($body.Keys)) { if ($key -notin 'scheduledActionsForRule', 'assignments') { $createBody[$key] = $body[$key] } }

            # @() around the whole if: an if-expression unrolls a one-item array to a scalar.
            $existing = @(if ($api -eq 'Classic') { $existingClassic | Where-Object { [string](Get-Prop $_ 'displayName') -eq $name } }
                else { $existingCatalog | Where-Object { [string](Get-Prop $_ 'name') -eq $name } })
            if ($existing.Count -gt 1) { throw "$($existing.Count) policies in the tenant are named '$name'. Rename or delete the extras." }

            $id = $null
            $wrote = $false
            if ($existing.Count -eq 0) {
                # --- Absent: create, schedule, assign -------------------------------------------
                if (-not $PSCmdlet.ShouldProcess($name, "Create $mode compliance policy")) {
                    $row.Status = 'WhatIf'; $row.Actions = 'create, assign'
                    $results.Add([pscustomobject]$row)
                    continue
                }
                if ($api -eq 'Classic') {
                    $createBody['scheduledActionsForRule'] = @([ordered]@{ ruleName = $ruleName; scheduledActionConfigurations = $desiredActions })
                    $created = Invoke-ICBGraph -Method POST -Uri $ClassicUri -Body $createBody
                    $id = [string](Get-Prop $created 'id')
                    $actionsTaken.Add('created')
                }
                else {
                    # Never inline: Graph accepts an inline schedule here and stores its default instead.
                    $created = Invoke-ICBGraph -Method POST -Uri $CatalogUri -Body $createBody
                    $id = [string](Get-Prop $created 'id')
                    $actionsTaken.Add('created')
                    Set-PolicySchedule -Api $api -Id $id -Actions $desiredActions -RuleName $ruleName
                    $actionsTaken.Add('schedule set')
                }
                if (-not $id) { throw 'Graph did not return an ID for the new policy.' }
                Set-PolicyAssignment -Api $api -Id $id -Existing @() -AddGroupIds $desiredGroups
                $actionsTaken.Add('assigned')
                $wrote = $true
                $row.Status = 'Created'
            }
            else {
                # --- Present: compare, then bring the schedule and assignment in line ---------
                $id = [string](Get-Prop $existing[0] 'id')
                $state = Get-PolicyState -Api $api -Id $id
                if ($api -eq 'Classic' -and [string](Get-Prop $state.Policy '@odata.type') -ne [string](Get-Prop $body '@odata.type')) {
                    throw "A policy named '$name' exists but is a $(Get-Prop $state.Policy '@odata.type'), not a $(Get-Prop $body '@odata.type')."
                }
                $drift = Get-SettingsDrift -Api $api -Desired $body -Current $state.Policy -CurrentSettings $state.Settings
                $scheduleDiffers = (Get-ScheduleKey $desiredActions) -ne (Get-ScheduleKey $state.Actions)
                $missingGroups = @($desiredGroups | Where-Object { $_ -notin $state.GroupIds })
                $planned = [System.Collections.Generic.List[string]]::new()
                if ($drift.Count -gt 0 -and $UpdateExisting -and $api -eq 'Classic') { $planned.Add('update settings') }
                if ($scheduleDiffers) { $planned.Add("set $mode schedule".ToLowerInvariant()) }
                if ($missingGroups.Count -gt 0) { $planned.Add('assign') }

                if ($planned.Count -gt 0 -and -not $PSCmdlet.ShouldProcess($name, ($planned -join ', '))) {
                    $row.Status = 'WhatIf'; $row.Actions = ($planned -join ', ')
                    if ($drift.Count -gt 0) { $row.Detail = "drift: $($drift -join '; ')" }
                    $results.Add([pscustomobject]$row)
                    continue
                }
                if ($drift.Count -gt 0 -and $UpdateExisting -and $api -eq 'Classic') {
                    $patch = [ordered]@{ '@odata.type' = Get-Prop $body '@odata.type' }
                    foreach ($key in @($body.Keys)) { if ($key -notin $NonSettingKeys) { $patch[$key] = $body[$key] } }
                    [void](Invoke-ICBGraph -Method PATCH -Uri "$ClassicUri/$id" -Body $patch)
                    $actionsTaken.Add('settings updated')
                }
                if ($scheduleDiffers) {
                    Set-PolicySchedule -Api $api -Id $id -Actions $desiredActions -RuleName $ruleName
                    $actionsTaken.Add('schedule set')
                }
                if ($missingGroups.Count -gt 0) {
                    Set-PolicyAssignment -Api $api -Id $id -Existing $state.Assignments -AddGroupIds $missingGroups
                    $actionsTaken.Add('assigned')
                }
                $wrote = $actionsTaken.Count -gt 0
                $settingsLeft = ($drift.Count -gt 0) -and -not ($UpdateExisting -and $api -eq 'Classic')
                if ($settingsLeft) {
                    $row.Detail = "drift: $($drift -join '; ')"
                    if ($UpdateExisting) { $row.Detail += ' (Settings Catalog policies are not updated in place; edit or recreate it)' }
                }
                $row.Status = if ($settingsLeft) { 'Drift' } elseif ($wrote) { 'Updated' } else { 'Unchanged' }
            }

            # --- Read back every write and compare --------------------------------------------
            if ($wrote) {
                $after = Get-PolicyState -Api $api -Id $id
                $checkSettings = -not ($row.Status -eq 'Drift')
                $problems = Test-PolicyState -Api $api -Desired $body -DesiredActions $desiredActions -DesiredGroupIds $desiredGroups -State $after -CheckSettings $checkSettings
                if ($problems.Count -gt 0) { throw "Read-back mismatch after $($actionsTaken -join ', '): $($problems -join '; ')" }
            }
            $row.Actions = ($actionsTaken -join ', ')
            $level = if ($row.Status -eq 'Drift') { 'Warning' } else { 'Success' }
            Write-Status ("{0}: {1}{2}" -f $name, $row.Status, $(if ($row.Actions) { " ($($row.Actions))" } else { '' })) -Level $level
            if ($row.Detail) { Write-Status "  $($row.Detail)" -Level Warning }
        }
        catch {
            $row.Status = 'Error'
            $row.Actions = ($actionsTaken -join ', ')
            $row.Detail = $_.Exception.Message
            Write-Status "$($file.BaseName): $($_.Exception.Message)" -Level Error
            if ($StopOnError) {
                $results.Add([pscustomobject]$row)
                $results | Format-Table Template, Status, Actions, Detail -AutoSize -Wrap | Out-String -Width 220 | Write-Host
                throw "Stopped at the first failure (-StopOnError)."
            }
        }
        $results.Add([pscustomobject]$row)
    }

    Write-Host ''
    $results | Format-Table Template, Api, Status, Actions, Detail -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    $count = { param($s) @($results | Where-Object { $_.Status -eq $s }).Count }
    Write-Status ("Created: {0}  Updated: {1}  Unchanged: {2}  Drift: {3}  WhatIf: {4}  Errors: {5}" -f (& $count 'Created'), (& $count 'Updated'), (& $count 'Unchanged'), (& $count 'Drift'), (& $count 'WhatIf'), (& $count 'Error'))
    if ((& $count 'Error') -gt 0) {
        Write-Status 'Completed with errors. Review the output above.' -Level Warning
        exit 1
    }
    if (-not $Enforce -and -not $isWhatIf) {
        Write-Status "Observation mode: review Intune's compliance reports for each template's observation period (POLICY-DESIGN.md section 7.2), then re-run with -Enforce." -Level Info
    }
}
catch {
    Write-Status "$($_.Exception.Message)" -Level Error
    exit 1
}

#endregion
