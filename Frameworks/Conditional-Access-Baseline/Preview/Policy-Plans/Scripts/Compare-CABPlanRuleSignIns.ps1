#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Read-only. For sign-ins since -Since, compares each Conditional Access policy plan rule's result
    with the result of the standalone policy of the same name.

.DESCRIPTION
    Built for validating plan rules in report-only next to the enforced policies they copy. The
    migration wizard keeps each policy's name on its rule, so rules and policies pair by name.

    A rule appears in a sign-in's appliedConditionalAccessPolicies as its own entry, with the rule's
    ID and no reference to its plan, so entries are told apart by matching IDs against the tenant's
    policies, plans and rules.

    Results compare without the reportOnly prefix, and a report-only 'interrupted' counts as the
    enforced 'failure': on an MFA or Terms of Use prompt the enforced policy logs failure and the
    report-only rule logs reportOnlyInterrupted (errors 50074, 50076 and 50158 in the demo tenant).

    The log also lists the sign-ins a rule would have failed, and the sign-ins where a policy appears
    without its same-named rule. New and changed rules took 6 to 9 minutes to appear in sign-in
    evaluations in testing, so expect a few of those just after a change.

.PARAMETER Since
    Start of the sign-in window (any value [datetime] accepts; UTC with a Z suffix is unambiguous).

.PARAMETER TenantId
    Tenant ID or primary domain to sign in to. Omit to use the account's home tenant.

.PARAMETER UserPrincipalName
    Only sign-ins for this user.

.PARAMETER OutFile
    Log file. Default: cab-plan-rule-signins-<tenant>-<time>.log in the current folder.

.EXAMPLE
    ./Compare-CABPlanRuleSignIns.ps1 -Since '2026-11-04T20:40:00Z'

.NOTES
    Delegated scopes: Policy.Read.All, AuditLog.Read.All, Directory.Read.All.
#>
param(
    [Parameter(Mandatory)] [datetime]$Since,
    [string]$TenantId,
    [string]$UserPrincipalName,
    [string]$OutFile
)
$ErrorActionPreference = 'Stop'
$beta = 'https://graph.microsoft.com/beta'
$out = New-Object System.Collections.Generic.List[string]
function Say($Text) { $out.Add("$Text"); Write-Host $Text }
function Get-All([string]$Uri) {
    $items = @()
    while ($Uri) { $r = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject; $items += @($r.value); $Uri = $r.'@odata.nextLink' }
    $items
}
# An enforced policy logs 'failure' where a report-only one logs 'reportOnlyInterrupted' (an MFA or Terms of Use
# prompt; demo sign-ins 2026-11-04, errors 50074, 50076 and 50158), so 'interrupted' compares as 'failure'.
function Get-Decision([string]$Result) { $Result -replace '^reportOnly', '' -replace '^(.)', { $_.Value.ToLower() } -replace '^interrupted$', 'failure' }

# Pairs every plan or rule entry in each sign-in with the same-named policy entry, and lists policies whose
# same-named rule is absent from a sign-in. $Kind maps an id to Kind (policy, plan or rule), Name and Plan.
function Get-RulePairs($SignIns, $Kind) {
    $pairs = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[object]
    $firstRaw = [ordered]@{}
    $ruleNames = @($Kind.Values | Where-Object Kind -eq 'rule' | ForEach-Object Name)
    foreach ($s in $SignIns) {
        $entries = @($s.appliedConditionalAccessPolicies)
        # A policy with a same-named rule whose entry is absent from this sign-in (for example, before a new rule propagates).
        $entryNames = @($entries | Where-Object { $Kind[$_.id].Kind -eq 'rule' } | ForEach-Object { $Kind[$_.id].Name })
        foreach ($e in @($entries | Where-Object { $Kind[$_.id].Kind -eq 'policy' -and $_.displayName -in $ruleNames -and $_.displayName -notin $entryNames })) {
            $missing.Add([pscustomobject]@{ Time = $s.createdDateTime; User = $s.userPrincipalName; App = $s.appDisplayName; Name = $e.displayName; PolicyResult = $e.result })
        }
        foreach ($e in $entries) {
            $k = $Kind[$e.id]
            $label = if ($k) { $k.Kind } else { 'unknown' }
            if ($label -ne 'policy' -and -not $firstRaw.Contains($label)) { $firstRaw[$label] = [pscustomobject]@{ SignIn = $s.id; Time = $s.createdDateTime; Entry = $e } }
            if ($label -in 'rule', 'plan', 'unknown') {
                $name = if ($k -and $k.Kind -eq 'rule') { $k.Name } else { $e.displayName }
                $policy = @($entries | Where-Object { $_.id -ne $e.id -and $Kind[$_.id].Kind -eq 'policy' -and $_.displayName -eq $name })[0]
                $pairs.Add([pscustomobject]@{
                        Time = $s.createdDateTime; User = $s.userPrincipalName; App = $s.appDisplayName; Resource = $s.resourceDisplayName
                        Name = $name; Plan = $k.Plan; RuleResult = $e.result; PolicyResult = $policy.result
                        Match = [bool]($policy -and ((Get-Decision $e.result) -eq (Get-Decision $policy.result)))
                        Error = $s.status.errorCode; Correlation = $s.correlationId
                    })
            }
        }
    }
    [pscustomobject]@{ Pairs = $pairs; Missing = $missing; FirstRaw = $firstRaw }
}

$connect = @{ NoWelcome = $true; Scopes = 'Policy.Read.All', 'AuditLog.Read.All', 'Directory.Read.All' }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect
$tenant = (Get-MgContext).TenantId
if (-not $OutFile) { $OutFile = Join-Path (Get-Location) "cab-plan-rule-signins-$tenant-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" }

$fromUtc = $Since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Say "Plan rule vs policy sign-in comparison in tenant $tenant, $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'); since $fromUtc$(if ($UserPrincipalName) { " for $UserPrincipalName" })"

$kind = @{}
Get-All "$beta/identity/conditionalAccess/policies" | ForEach-Object { $kind[$_.id] = [pscustomobject]@{ Kind = 'policy'; Name = $_.displayName; State = $_.state } }
foreach ($plan in Get-All "$beta/identity/conditionalAccess/plans") {
    $kind[$plan.id] = [pscustomobject]@{ Kind = 'plan'; Name = $plan.displayName; State = '' }
    Get-All "$beta/identity/conditionalAccess/plans/$($plan.id)/rules" | ForEach-Object { $kind[$_.id] = [pscustomobject]@{ Kind = 'rule'; Name = $_.displayName; State = $_.state; Plan = $plan.displayName } }
}
Say ("Known ids: {0} policies, {1} plans, {2} rules" -f @($kind.Values | Where-Object Kind -eq 'policy').Count, @($kind.Values | Where-Object Kind -eq 'plan').Count, @($kind.Values | Where-Object Kind -eq 'rule').Count)

# The sign-ins API rejects $select combined with the signInEventTypes filter ("Unsupported Query").
$filter = "createdDateTime ge $fromUtc and (signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser'))"
if ($UserPrincipalName) { $filter += " and userPrincipalName eq '$UserPrincipalName'" }
$signIns = @(Get-All "$beta/auditLogs/signIns?`$filter=$filter&`$top=999" | Sort-Object createdDateTime)
Say "Sign-ins in window: $($signIns.Count)"

$result = Get-RulePairs $signIns $kind
$pairs = $result.Pairs
foreach ($label in $result.FirstRaw.Keys) {
    $f = $result.FirstRaw[$label]
    Say ''
    Say "First raw entry of kind '$label' (sign-in $($f.SignIn), $($f.Time)):"
    Say ($f.Entry | ConvertTo-Json -Depth 10)
}

Say ''
Say '== Per rule: decisions compared with the same-named policy (reportOnly prefix ignored) =='
if (-not $pairs.Count) { Say '(no plan or rule entries in the window)' }
foreach ($grp in ($pairs | Group-Object Name | Sort-Object Name)) {
    $m = @($grp.Group | Where-Object Match).Count
    $unpaired = @($grp.Group | Where-Object { -not $_.PolicyResult }).Count
    Say ("{0}: {1} evaluations, {2} match, {3} differ, {4} without a same-named policy" -f $grp.Name, $grp.Count, $m, ($grp.Count - $m - $unpaired), $unpaired)
    $grp.Group | Group-Object { "rule $($_.RuleResult) / policy $($_.PolicyResult ?? 'n/a')" } | Sort-Object Count -Descending |
        ForEach-Object { Say ("    {0,4}x  {1}" -f $_.Count, $_.Name) }
}

$diff = @($pairs | Where-Object { $_.PolicyResult -and -not $_.Match })
Say ''
Say "== Sign-ins where the rule and the policy decided differently: $($diff.Count) =="
foreach ($d in $diff) {
    Say ("{0}  {1}  {2} -> {3}  {4}: rule {5}, policy {6}; error {7}; correlation {8}" -f $d.Time, $d.User, $d.App, $d.Resource, $d.Name, $d.RuleResult, $d.PolicyResult, $d.Error, $d.Correlation)
}

$blocked = @($pairs | Where-Object RuleResult -eq 'reportOnlyFailure')
Say ''
Say "== Sign-ins a rule would have failed (reportOnlyFailure): $($blocked.Count) =="
foreach ($b in $blocked) {
    Say ("{0}  {1}  {2} -> {3}  {4}: policy {5}; error {6}; correlation {7}" -f $b.Time, $b.User, $b.App, $b.Resource, $b.Name, $b.PolicyResult, $b.Error, $b.Correlation)
}

Say ''
Say "== Sign-ins with a policy but no entry for its same-named rule: $($result.Missing.Count) =="
foreach ($m in $result.Missing) {
    Say ("{0}  {1}  {2}  {3}: policy {4}" -f $m.Time, $m.User, $m.App, $m.Name, $m.PolicyResult)
}
$out | Set-Content -Path $OutFile -Encoding utf8
Write-Host "`nWritten to $OutFile"
