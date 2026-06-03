#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    EIG-AR001. Stands up the quarterly Access Review over B2B guest accounts.

.DESCRIPTION
    Creates a recurring quarterly Microsoft Entra access review covering guest
    user membership across all Microsoft 365 groups. Decisions default to Deny
    when a reviewer does not respond before the review closes, decisions are
    auto-applied, and a denied guest is removed from the reviewed group. The
    recurrence and reviewer assignment live in the review definition so the
    control recurs without an operator remembering to run it.

    Part of the Entra ID Governance Toolkit. Self-invoking. No unified deployer
    at v0.1.0-preview.

.PARAMETER FallbackReviewerId
    Object ID of the named fallback reviewer team that reviews guests with no
    recorded sponsor. Replace the REPLACE_WITH placeholder before running.

.PARAMETER StartDate
    First occurrence date in yyyy-MM-dd form. Defaults to today.

.PARAMETER InstanceDurationInDays
    Number of days each review instance stays open. Defaults to 25.

.PARAMETER DisplayName
    Display name for the review definition.

.NOTES
    EIG-AR001-QuarterlyGuestAccessReview
    Paired contract: EIG-AR001-QuarterlyGuestAccessReview.md
    Graph surface : POST /identityGovernance/accessReviews/definitions (v1.0)
    Required scopes: AccessReview.ReadWrite.All, AccessReview.ReadWrite.Membership
    Prerequisites : Entra ID P2, PowerShell 7, Microsoft.Graph.Authentication
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string]$FallbackReviewerId = 'REPLACE_WITH_FALLBACK_REVIEWERS_GROUP_OBJECT_ID',

    [Parameter()]
    [string]$StartDate = (Get-Date).ToString('yyyy-MM-dd'),

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$InstanceDurationInDays = 25,

    [Parameter()]
    [string]$DisplayName = 'EIG-AR001 Quarterly Guest Access Review'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Status {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Success', 'Warning')]
        [string]$Level = 'Info'
    )
    $prefix = switch ($Level) {
        'Success' { '[ OK ]' }
        'Warning' { '[WARN]' }
        default   { '[INFO]' }
    }
    Write-Host "$prefix $Message"
}

# Sponsor-first reviewer model.
# Design spec EIG-AR001 assigns the guest sponsor as the primary reviewer, with
# the named fallback team reviewing guests that have no recorded sponsor.
#
# CONFIRM-IN-TENANT: the exact accessReviewReviewerScope query for guest
# sponsors was not verified against a live tenant for this preview. Validate the
# sponsor reviewer query in your own tenant, then replace the placeholder below.
# The fallback reviewers block is verified and ready. See the paired contract
# EIG-AR001-QuarterlyGuestAccessReview.md, section "Reviewer model".
$reviewers = @(
    @{
        query     = 'REPLACE_WITH_VERIFIED_SPONSOR_REVIEWER_QUERY'
        queryType = 'MicrosoftGraph'
    }
)

$fallbackReviewers = @(
    @{
        query     = "/groups/$FallbackReviewerId"
        queryType = 'MicrosoftGraph'
    }
)

# Refuse to run while REPLACE_WITH placeholders are unresolved.
$unresolved = [System.Collections.Generic.List[string]]::new()
if ($FallbackReviewerId -like 'REPLACE_WITH_*') { $unresolved.Add('FallbackReviewerId') }
if ($reviewers[0].query -like 'REPLACE_WITH_*') { $unresolved.Add('sponsor reviewer query') }
if ($unresolved.Count -gt 0) {
    throw "Unresolved placeholders: $($unresolved -join ', '). Resolve them before running. See EIG-AR001-QuarterlyGuestAccessReview.md."
}

$requiredScopes = @('AccessReview.ReadWrite.All', 'AccessReview.ReadWrite.Membership')
if (-not (Get-MgContext)) {
    Write-Status "Connecting to Microsoft Graph with scopes: $($requiredScopes -join ', ')."
    Connect-MgGraph -Scopes $requiredScopes | Out-Null
}

$definition = @{
    displayName             = $DisplayName
    descriptionForAdmins    = 'Quarterly access review of B2B guest membership across all Microsoft 365 groups. Denies access when the reviewer does not respond before the review closes and removes the denied guest from the reviewed group.'
    descriptionForReviewers = 'Confirm whether each guest still needs access to this group. If you do not respond before the review closes, access is denied by default and the guest is removed from the group.'
    scope = @{
        '@odata.type' = '#microsoft.graph.accessReviewQueryScope'
        query         = './members/microsoft.graph.user/?$count=true&$filter=(userType eq ''Guest'')'
        queryType     = 'MicrosoftGraph'
    }
    instanceEnumerationScope = @{
        '@odata.type' = '#microsoft.graph.accessReviewQueryScope'
        query         = '/groups?$filter=(groupTypes/any(c:c eq ''Unified''))'
        queryType     = 'MicrosoftGraph'
    }
    reviewers         = $reviewers
    fallbackReviewers = $fallbackReviewers
    settings = @{
        mailNotificationsEnabled        = $true
        reminderNotificationsEnabled    = $true
        justificationRequiredOnApproval = $true
        defaultDecisionEnabled          = $true
        defaultDecision                 = 'Deny'
        instanceDurationInDays          = $InstanceDurationInDays
        autoApplyDecisionsEnabled       = $true
        recommendationsEnabled          = $true
        recurrence = @{
            pattern = @{
                type       = 'absoluteMonthly'
                interval   = 3
                dayOfMonth = 1
            }
            range = @{
                type      = 'noEnd'
                startDate = $StartDate
            }
        }
    }
}

$uri = 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions'

if ($PSCmdlet.ShouldProcess($DisplayName, 'Create quarterly guest access review definition')) {
    $body = $definition | ConvertTo-Json -Depth 12
    $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json'
    Write-Status "Created access review definition '$($response.displayName)' with id $($response.id)." -Level Success
    Write-Status 'Confirm in the Entra admin center that the recurrence and reviewer assignment match the design.'
}
else {
    Write-Status 'WhatIf: no access review definition was created.' -Level Warning
}
