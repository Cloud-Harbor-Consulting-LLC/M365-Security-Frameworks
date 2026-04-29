# CA-COV003 — Workload Identities: Trusted Locations Only

Blocks service principal sign-ins from outside a tenant-defined trusted IPs named location. Closes the workload identity gap that user-targeted policies (CA-SIG003, CA-COV001/002) cannot address — service principals do not have user accounts, so MFA and risk-based grant controls do not apply to them.

## Hard prerequisites

This policy will not evaluate without both of the following. The deployer's `-WhatIf` mode will load and lint the JSON either way; **applying past report-only will fail at creation time** if the SKU is missing.

1. **Microsoft Entra Workload Identities Premium** — separate SKU from Entra ID P1/P2. Confirm via [Microsoft Entra admin center → Identity → Overview → Licenses](https://entra.microsoft.com) before applying. Trial activation is available for non-production tenants.
2. **A Trusted IPs named location** — see "Pre-flight" below.

## Pre-flight: create the Trusted IPs named location

If you do not yet have a named location representing your trusted egress ranges (office, VPN, or remote-worker static IPs), create one first:

1. Microsoft Entra admin center → Protection → Conditional Access → Named locations → **+ IP ranges location**
2. Name: `Trusted IPs` (or your convention)
3. Add CIDR ranges representing every egress IP you trust
4. Mark **Define as trusted location**: Yes
5. Save, then capture the location's object ID — replace `REPLACE_WITH_TRUSTED_IPS_LOCATION_ID` in `CA-COV003-WorkloadIdentities-TrustedLocations.json` with that ID before deploying

> **Remote-only operators:** if you have no fixed egress, the operational pattern shifts. Either (a) define your residential static IPs as the trusted set and accept the brittleness, (b) defer this policy until a static-egress source exists (cloud bastion, vendor like Cloudflare WARP with dedicated egress), or (c) tighten scope to specific high-risk service principals only. Document which path your tenant takes.

## Scope

| Setting | Value | Rationale |
|---|---|---|
| Include service principals | `ServicePrincipalsInMyTenant` | Default-deny model — every SPN inherits the policy unless explicitly excluded |
| Exclude service principals | tenant-specific | Populate per the discovery query below |
| Applications | `All` | Workload identity policies do not need per-app scoping; the SPN is the identity being protected |
| Locations | All except Trusted IPs | Block boundary defined by the named location, not by user attribute |
| Grant control | `block` | Service principals cannot satisfy MFA or other interactive controls — block is the only meaningful enforcement |

## Exclusion model — read this carefully

CA-EXC001 (the Emergency Access exclusion contract) is **user-only**. It does not apply to CA-COV003 because workload identities are not user objects.

Workload identity exclusions are managed **per-service-principal**, by object ID, in the policy itself — there is no "Emergency Access workload identities" group equivalent. This is by design in the Microsoft Graph schema: `excludeServicePrincipals` accepts SPN object IDs only.

**Exclusion governance pattern:**

- Maintain the exclude list inline in the JSON, with a comment-style commit message explaining each addition (PR description, since JSON does not support comments)
- Re-attest the exclude list quarterly alongside CA-EXC001's recovery drill
- Any addition to the exclude list requires a paired GitHub issue documenting the SPN, owner, and reason for exemption

## Discovery: finding SPNs that may need exclusion

Run this against the tenant before applying the policy past report-only. Any SPN that signed in from outside the trusted location in the last 30 days will be blocked once enforced — review and decide per-SPN whether to exclude or to fix the egress.

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All","Application.Read.All"

$start = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filter = "createdDateTime ge $start and signInEventTypes/any(t:t eq 'servicePrincipal')"
$signIns = Get-MgAuditLogSignIn -Filter $filter -All

$signIns |
    Group-Object ServicePrincipalName, IpAddress |
    Sort-Object Count -Descending |
    Select-Object Count,
        @{N='ServicePrincipal';E={$_.Group[0].ServicePrincipalName}},
        @{N='SPNObjectId';E={$_.Group[0].ServicePrincipalId}},
        @{N='SourceIP';E={$_.Group[0].IpAddress}} |
    Format-Table -AutoSize
```

Cross-reference the `SourceIP` column against the trusted IPs ranges. SPNs signing in from non-trusted IPs are candidates for either exclusion (if legitimately remote, e.g., Microsoft first-party connectors with dynamic egress) or remediation (route through trusted egress).

## Continuous Access Evaluation — does not apply

CAE is a user-token feature. Workload identity tokens are **not** subject to CAE re-evaluation. If a service principal token is issued and the SPN is later compromised, revocation requires:

1. Disabling the SPN in Entra (`Update-MgServicePrincipal -ServicePrincipalId <id> -AccountEnabled:$false`), or
2. Rotating the SPN's credentials (cert/secret rollover), or
3. Adding the SPN object ID to a block-targeted CA policy and waiting for the existing token's natural expiry

Do not assume CA-COV003 provides the same fast-revocation guarantees that CAE-aware user policies do.

## Validation (after policy ships in report-only)

```powershell
.\Scripts\Get-CABaselineImpact.ps1 -PolicyNameFilter 'CA-COV003' -Days 7
```

Expected pattern in a healthy tenant:

- `WouldBlock` — SPNs signing in from non-trusted IPs. Investigate each one before enforcing.
- `WouldPass` — SPNs signing in from trusted IPs. Working as intended.
- `NotApplied` — entries for SPNs in the `excludeServicePrincipals` list, plus all user sign-ins (workload identity policies do not target users).

If `WouldBlock` includes Microsoft first-party SPNs (Microsoft Graph, Exchange Online, etc.), do **not** add them to the exclude list — investigate why a first-party SPN is appearing in your tenant's sign-in logs before changing the policy.
