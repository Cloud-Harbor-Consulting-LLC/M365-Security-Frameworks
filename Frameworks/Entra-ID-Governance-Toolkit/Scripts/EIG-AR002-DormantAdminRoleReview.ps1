#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    EIG-AR002. Stands up the monthly Access Review over dormant administrative
    role assignments.

.DESCRIPTION
    Creates a recurring monthly Microsoft Entra access review covering
    administrative role assignments that have gone dormant. The review uses the
    Microsoft Graph inactivity look-back so assignments not exercised in the
    prior 30 days are recommended for denial. Decisions default to Deny when a
    reviewer does not respond before the review closes, decisions are
    auto-applied, and a denied assignment is removed from the role. The
    recurrence and reviewer assignment live in the review definition so the
    control recurs without an operator remembering to run it.

    Part of the Entra ID Governance Toolkit. Self-invoking. No unified deployer
    at v0.1.0-preview.

.PARAMETER FallbackReviewerId
    Object ID of the named fallback reviewer group that reviews assignments with
    no resolvable role owner or delegated governance reviewer. Replace the
    REPLACE_WITH placeholder before running.

.PARAMETER StartDate
    First occurrence date in yyyy-MM-dd form. Defaults to today.

.PARAMETER InstanceDurationInDays
    Number of days each review instance stays open. Defaults to 25.

.PARAMETER DisplayName
    Display name for the review definition.

.NOTES
    EIG-AR002-DormantAdminRoleReview
    Paired contract: EIG-AR002-DormantAdminRoleReview.md
    Graph surface : POST /identityGovernance/accessReviews/definitions (v1.0)
    Required scopes: AccessReview.ReadWrite.All, AccessReview.ReadWrite.Membership,
                     RoleManagement.ReadWrite.Directory
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
    [string]$DisplayName = 'EIG-AR002 Monthly Dormant Admin Role Review'
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

# Resource scope: a directory (administrative) role to review.
# Verified Graph shape (principalResourceMembershipsScope -> resourceScopes ->
# /roleManagement/directory/roleDefinitions/{role id}); the role definition ID
# itself is tenant-specific. There is no documented query that targets every
# directory role in one resourceScope, so the operator names the privileged role
# to review and runs the script once per role. Replace the placeholder below.
$roleDefinitionId = 'REPLACE_WITH_DIRECTORY_ROLE_DEFINITION_ID'

# Role-owner-first reviewer model.
# Design spec EIG-AR002 assigns the role owner or a delegated governance
# reviewer as the primary reviewer, with the named fallback group reviewing
# assignments that have no resolvable owner.
#
# CONFIRM-IN-TENANT: the exact accessReviewReviewerScope query for the role
# owner / delegated governance reviewer was not verified against a live tenant
# for this preview. Directory roles have no single documented "owner" reviewer
# query the way a group owner does. Validate the primary reviewer query in your
# own tenant, then replace the placeholder below. The fallback reviewers block
# is verified and ready. See the paired contract
# EIG-AR002-DormantAdminRoleReview.md, section "Reviewer model".
$reviewers = @(
    @{
        query     = 'REPLACE_WITH_VERIFIED_PRIMARY_REVIEWER_QUERY'
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
if ($roleDefinitionId -like 'REPLACE_WITH_*') { $unresolved.Add('directory role definition ID') }
if ($reviewers[0].query -like 'REPLACE_WITH_*') { $unresolved.Add('primary reviewer query') }
if ($unresolved.Count -gt 0) {
    throw "Unresolved placeholders: $($unresolved -join ', '). Resolve them before running. See EIG-AR002-DormantAdminRoleReview.md."
}

$requiredScopes = @(
    'AccessReview.ReadWrite.All',
    'AccessReview.ReadWrite.Membership',
    'RoleManagement.ReadWrite.Directory'
)
if (-not (Get-MgContext)) {
    Write-Status "Connecting to Microsoft Graph with scopes: $($requiredScopes -join ', ')."
    Connect-MgGraph -Scopes $requiredScopes | Out-Null
}

$definition = @{
    displayName             = $DisplayName
    descriptionForAdmins    = 'Monthly access review of dormant administrative role assignments. Uses a 30-day inactivity look-back so assignments not exercised in the prior 30 days are recommended for denial. Denies access when the reviewer does not respond before the review closes and removes the denied assignment from the role.'
    descriptionForReviewers = 'Confirm whether each principal still needs this administrative role. Assignments dormant for 30 or more days are recommended for denial. If you do not respond before the review closes, access is denied by default and the assignment is removed.'
    scope = @{
        '@odata.type' = '#microsoft.graph.principalResourceMembershipsScope'
        principalScopes = @(
            @{
                '@odata.type' = '#microsoft.graph.accessReviewQueryScope'
                query         = '/users'
                queryType     = 'MicrosoftGraph'
            }
        )
        resourceScopes = @(
            @{
                '@odata.type' = '#microsoft.graph.accessReviewQueryScope'
                query         = "/roleManagement/directory/roleDefinitions/$roleDefinitionId"
                queryType     = 'MicrosoftGraph'
            }
        )
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
        recommendationLookBackDuration  = 'P30D'
        recurrence = @{
            pattern = @{
                type       = 'absoluteMonthly'
                interval   = 1
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

if ($PSCmdlet.ShouldProcess($DisplayName, 'Create monthly dormant admin role access review definition')) {
    $body = $definition | ConvertTo-Json -Depth 12
    $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json'
    Write-Status "Created access review definition '$($response.displayName)' with id $($response.id)." -Level Success
    Write-Status 'Confirm in the Entra admin center that the recurrence, reviewer assignment, and inactivity look-back match the design.'
}
else {
    Write-Status 'WhatIf: no access review definition was created.' -Level Warning
}
