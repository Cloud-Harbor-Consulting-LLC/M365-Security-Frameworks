# CA-EXC002 — ServiceAccounts Exclusion

**Type:** Documentation / operational contract
**Status:** Required for any baseline deployment that includes service accounts (non-human workload identities operated as user accounts)
**Persona:** `CA-Persona-ServiceAccounts`
**Replaces deployable template:** No — this is a written contract enforced via the `users.excludeGroups` block in human-targeted CA-* policies, and via the `users.includeGroups` block in CA-COV010.

## Purpose

A baseline tuned for interactive human sign-ins will misfire against service accounts. Service accounts (unattended scripts, scheduled tasks, integration runners, legacy app pool identities operated as user accounts) cannot satisfy MFA, cannot register a device, cannot pass risk-based step-up, and have no interactive user to respond to a phishing-resistant credential prompt. Leaving them in scope of the human baseline produces one of two failure modes: the policy blocks the workload (outage), or the team writes per-policy ad-hoc exclusions that drift over time and lose accountability.

This document defines the contract every CA-* policy in this baseline honors for service accounts, and the compensating controls that keep the exclusion safe.

## The contract

**Every human-targeted Conditional Access policy in this baseline excludes `CA-Persona-ServiceAccounts` from its `users.includeUsers` / `users.includeGroups` scope via the `users.excludeGroups` block.**

In v1.2, the persona is also the inclusion target for `CA-COV010-ServiceAccounts-BlockUntrustedLocations`, which is the compensating control described in section 3.

This applies to:

| Policy | Excludes ServiceAccounts? |
|--------|---------------------------|
| CA-COV001-AllUsers-BlockLegacyAuth | Yes |
| CA-COV002-AllUsers-RequireMFA | Yes |
| CA-COV003-WorkloadIdentities-TrustedLocations | Not applicable (targets workload identities, not user accounts) |
| CA-SIG001-SensApps-RequireCompliantDevice | Yes |
| CA-SIG002-AllUsers-RequireStepUpOnRisk | Yes |
| CA-SIG003-Guests-RequireMFA | Yes |
| CA-AUT001-PrivAccounts-RequirePhishResistantMFA | Yes |
| CA-AUT002-PrivRoles-RequirePhishResistantMFA | Yes |

If a future human-targeted policy is added to the baseline and does **not** exclude `CA-Persona-ServiceAccounts`, that is a bug. Open an issue using the policy-request template.

CA-COV010 is the inverse: it **includes** `CA-Persona-ServiceAccounts` and excludes all trusted locations. The two policies together implement the compensating-control model described below.

## Why exclude rather than enforce human controls

Three reasons:

1. **MFA is not satisfiable.** A service account has no second factor that a scheduled task can present. Requiring MFA does not improve security here; it produces an outage and forces operators to disable the policy or carve out per-policy exclusions.

2. **Persona accountability.** A single membership list (`CA-Persona-ServiceAccounts`) gives one place to audit which identities are operating outside human controls. Per-policy ad-hoc exclusions scatter that list across dozens of JSON files and erode it over time.

3. **Compensating-control surface.** Pulling service accounts out of the human baseline lets the baseline apply a service-account-shaped policy in their place (location pinning via CA-COV010), instead of a watered-down version of a human policy that satisfies neither use case.

The trade-off is real: members of `CA-Persona-ServiceAccounts` are not subject to MFA, device compliance, risk-based step-up, or phishing-resistant credential requirements. Section 4 describes how operational practices and CA-COV010 compensate.

## Persona membership rules

Members of `CA-Persona-ServiceAccounts`:

- Must be cloud-only accounts (no on-prem AD sync) wherever feasible. Where an on-prem origin is unavoidable, document the source.
- Must use a UPN suffix or naming pattern that is clearly identifiable as non-human (e.g., `svc-<purpose>@<tenant>`).
- Must not be assigned a directory role unless the workload provably requires it. Where a directory role is required, document the role, the workload, and the business owner in the operational log (section 4.2).
- Must not have a mailbox, OneDrive, or Teams presence. If the workload requires mail, use a shared mailbox or a separate licensed identity, not the service account.
- Must have a documented business owner. An account without a current owner is removed from the persona at the next monthly attestation.
- Must originate from a known, allow-listed IP range covered by a Trusted Location, so that CA-COV010 can pin sign-ins to that range.

Workloads that **cannot** meet the location-pinning requirement are not candidates for this persona. Use a workload identity (service principal or managed identity) and the `CA-COV003-WorkloadIdentities-TrustedLocations` pattern instead.

## Operational practices

The exclusion contract is only safe if these practices are continuously honored. Treat each as non-negotiable.

### 4.1 Compensating control: location pinning (CA-COV010)

Every member of `CA-Persona-ServiceAccounts` is in scope of `CA-COV010-ServiceAccounts-BlockUntrustedLocations`. CA-COV010 blocks sign-ins from any location not in the tenant's Trusted Locations set. A service account that signs in from outside the allow-listed range is blocked at the policy layer regardless of whether the credential is valid.

If CA-COV010 is not deployed (or is in report-only mode), the exclusion contract is operating without its compensating control. Treat this state as a temporary gap and resolve before promoting any service account into the persona.

### 4.2 Monthly attestation

On the first business day of each month, the framework owner confirms:

- Membership of `CA-Persona-ServiceAccounts` matches the documented roster.
- Each account has a current, named business owner.
- Each account's last sign-in source IP is inside the Trusted Locations set.
- No account in the persona is assigned a directory role without a documented justification.
- CA-COV010 is deployed and enforced (not report-only).

Record the attestation in the framework's operational log (a SharePoint list, a spreadsheet, or an issue with the `attestation` label on this repo). An account that fails any of the above is either remediated or removed from the persona before the attestation closes.

### 4.3 Sign-in review (quarterly)

Once per quarter, review sign-in logs for the persona and confirm:

- No sign-in succeeded from a location outside the Trusted Locations set (CA-COV010 enforcement check).
- No sign-in used a legacy authentication protocol. The persona is excluded from CA-COV001 by contract, so this is a sign-in-log review, not a policy enforcement.
- No interactive sign-in occurred. Service accounts should sign in non-interactively. An interactive sign-in is a finding and triggers an investigation into whether the account is being used by a person.

Record the review result and any findings in the operational log.

### 4.4 Credential rotation

Service account credentials are rotated on a documented cadence (default: annually) or immediately on:

- Departure of any person with credential access.
- Suspected compromise of the credential store.
- A failed sign-in review (4.3) where the cause cannot be ruled out as test-environment-specific.
- Workload retirement or business-owner change.

Rotation procedure:

1. Generate the new credential in the credential vault.
2. Roll the workload to the new credential and verify a successful non-interactive sign-in.
3. Revoke the old credential.
4. Record the rotation in the operational log.

## Validation

After each deployment of `Deploy-CABaseline.ps1`, verify the contract holds:

```powershell
$serviceAccountsGroupId = 'REPLACE_WITH_SERVICEACCOUNTS_GROUP_OBJECT_ID'

Get-MgIdentityConditionalAccessPolicy |
    Where-Object { $_.DisplayName -like 'CA-*' } |
    ForEach-Object {
        $excludesServiceAccounts = $_.Conditions.Users.ExcludeGroups -contains $serviceAccountsGroupId
        [pscustomobject]@{
            Policy = $_.DisplayName
            ExcludesServiceAccounts = $excludesServiceAccounts
        }
    } | Format-Table -AutoSize
```

Every row must show `ExcludesServiceAccounts = True`, with two documented exceptions:

- `CA-COV003-WorkloadIdentities-TrustedLocations` — targets workload identities, not user accounts. Service-account exclusion is not applicable.
- `CA-COV010-ServiceAccounts-BlockUntrustedLocations` — **includes** the persona (it is the compensating control). Expect `ExcludesServiceAccounts = False` and `IncludeGroups -contains $serviceAccountsGroupId = True`.

Any other row showing `False` violates the contract. Update the JSON template and redeploy.

## References

- Microsoft Learn: [Securing service accounts](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-introduction-azure)
- CA-EXC001-EmergencyAccess-Exclusion.md — parallel exclusion contract for break-glass accounts
- CA-COV010-ServiceAccounts-BlockUntrustedLocations (v1.2) — compensating control
- POLICY-DESIGN.md — persona model and exclusion strategy
- Repo root README — framework overview
