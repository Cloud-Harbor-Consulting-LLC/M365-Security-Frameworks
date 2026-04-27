# CA-EXC001 — Emergency Access Exclusion

**Type:** Documentation / operational contract
**Status:** Required for all baseline deployments
**Persona:** `CA-Persona-EmergencyAccess`
**Replaces deployable template:** No — this is a written contract enforced via the `users.excludeGroups` block in every other CA-* policy.

## Purpose

A Conditional Access baseline is only safe if there is a documented, tested, and monitored path that survives a misconfiguration of the baseline itself. Emergency access accounts (also called break-glass accounts) are that path. This document defines the contract every CA-* policy in this baseline honors, and the operational practices that keep emergency access trustworthy.

## The contract

**Every Conditional Access policy in this baseline excludes `CA-Persona-EmergencyAccess` from its `users.includeUsers` / `users.includeGroups` scope via the `users.excludeGroups` block.**

This applies to:

| Policy | Excludes EmergencyAccess? |
|--------|---------------------------|
| CA-COV001-AllUsers-RequireMFA | Yes |
| CA-COV002-AllUsers-BlockLegacyAuth | Yes |
| CA-SIG001-Admins-RequireCompliantDevice | Yes |
| CA-SIG002-RiskySignIns-RequireMFAOrBlock | Yes |
| CA-AUT001-PrivAccounts-RequirePhishResistantMFA | Yes |
| CA-AUT002-AllAdmins-RequirePhishResistantMFA | Yes |

If a future policy is added to the baseline and does **not** exclude `CA-Persona-EmergencyAccess`, that is a bug. Open an issue using the policy-request template.

## Why exclude rather than include with looser controls

Two reasons:

1. **Fail-closed assumptions.** A misconfigured CA policy can lock every user out of every Microsoft service. The only reliable recovery path is an account that no policy can touch. Adding the emergency account to a "looser" policy still leaves it subject to that policy's evaluation engine — and the evaluation engine is exactly what failed.

2. **Reduced blast radius.** The fewer policies that evaluate against the emergency account, the smaller the chance that a future change to any policy accidentally affects it.

The trade-off is real: emergency accounts have weaker enforced controls than standard users. Section 4 below describes how operational practices compensate.

## Persona membership rules

Members of `CA-Persona-EmergencyAccess`:

- Must be cloud-only accounts (no on-prem AD sync).
- Must use a UPN suffix that is clearly identifiable (e.g., `breakglass@<tenant>.onmicrosoft.com`).
- Must be assigned the Global Administrator role permanently, **not** via PIM. The recovery path cannot depend on a service that may itself be down.
- Must have phishing-resistant credentials registered (FIDO2 hardware key — physical token kept in a documented, alarm-monitored location).
- Must not have a password manager entry, mailbox, OneDrive, or any other footprint beyond the directory account.
- Minimum count: 2. Maximum: 3. More than 3 dilutes accountability without adding resilience.

## Operational practices

The exclusion contract is only safe if these practices are continuously honored. Treat each as a non-negotiable.

### 4.1 Alerting

A sign-in to any account in `CA-Persona-EmergencyAccess` must trigger an immediate alert to:

- The security operations team (or designated equivalent for small orgs)
- The IT leader on call
- A documented escalation contact who is not also a member of the persona

Recommended implementation: an Entra ID sign-in log diagnostic setting forwarding to a Log Analytics workspace, with a scheduled query alert on `userPrincipalName` matching the emergency accounts. Trigger on every sign-in, not just risky ones.

### 4.2 Monthly attestation

On the first business day of each month, the framework owner confirms:

- Membership of `CA-Persona-EmergencyAccess` matches the documented roster.
- Each account's last sign-in is either "never" or matches a documented test event.
- The physical FIDO2 key for each account is present in its documented location.
- The alerting pipeline (4.1) fired correctly on the most recent test sign-in.

Record the attestation in the framework's operational log (a SharePoint list, a spreadsheet, or an issue with the `attestation` label on this repo).

### 4.3 Quarterly recovery drill

Once per quarter, exercise the recovery path:

1. From a workstation that has never signed in to the emergency account before, navigate to <https://entra.microsoft.com>.
2. Sign in with the emergency account using the FIDO2 key.
3. Confirm the alert in 4.1 fired within 60 seconds.
4. Sign out. Do not perform any privileged action — this is a sign-in test, not an admin operation.
5. Record the drill result and the alert latency.

If the drill fails, treat as a P1 incident and resolve before the next deployment of any CA policy.

### 4.4 Rotation

FIDO2 keys for emergency accounts are rotated annually, or immediately on:

- Departure of any person with knowledge of the key's location.
- Suspected compromise of the key's storage location.
- A failed recovery drill (4.3) where the cause cannot be ruled out as test-environment-specific.

Rotation procedure:

1. Register a new FIDO2 key on the account before removing the old one.
2. Verify a recovery drill passes with the new key.
3. Remove the old key from the account.
4. Physically destroy the old key.
5. Update the documented location for the new key.
6. Record the rotation in the operational log.

## Validation

After each deployment of `Deploy-CABaseline.ps1`, verify the contract holds:

```powershell
Get-MgIdentityConditionalAccessPolicy |
    Where-Object { $_.DisplayName -like 'CA-*' } |
    ForEach-Object {
        $excludesEmergency = $_.Conditions.Users.ExcludeGroups -contains $emergencyAccessGroupId
        [pscustomobject]@{
            Policy = $_.DisplayName
            ExcludesEmergencyAccess = $excludesEmergency
        }
    } | Format-Table -AutoSize
```

(Replace `$emergencyAccessGroupId` with the object ID of `CA-Persona-EmergencyAccess`.)

Every row must show `ExcludesEmergencyAccess = True`. If any row is `False`, the policy violates the contract. Update the JSON template and redeploy.

## References

- Microsoft Learn: [Manage emergency access accounts in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- Policy-Design.md — section on persona model and exclusion strategy
- Repo root README — framework overview
