# Policy plans (preview)

> **Preview.** Conditional Access policy plans are a Microsoft Entra preview feature, and this folder is a preview of how the baseline will use them. The scripts only read. The plans aren't deployed by anything in this repository. Production tenants should keep the standalone policies in [`../../Policies/`](../../Policies/).

A policy plan holds shared conditions once, and its rules inherit them. This folder lets you prototype plans next to the baseline's policies and check, on real sign-ins, that each rule decides the same way as the policy it copies.

| Path | What it is |
|---|---|
| [POLICY-PLANS-PREVIEW.md](POLICY-PLANS-PREVIEW.md) | How plans behave as tested, the baseline's design rules for plans, and the target design |
| [Scripts/Export-CABPolicyPlans.ps1](Scripts/Export-CABPolicyPlans.ps1) | Read-only. Exports every plan with its rules, snapshots the policies, and compares each rule with the policy of the same name |
| [Scripts/Compare-CABPlanRuleSignIns.ps1](Scripts/Compare-CABPlanRuleSignIns.ps1) | Read-only. Compares each rule's sign-in results with its policy's results |
| [Plans/](Plans/) | Reference JSON for 3 plans (P1 Admins, P3 Session and client hardening, P6 Guests). Not deployable |

## Prerequisites

- PowerShell 7 and the `Microsoft.Graph.Authentication` module: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`.
- An account that can read Conditional Access and sign-in logs. The scripts request the delegated scopes `Policy.Read.All`, `Directory.Read.All` and `AuditLog.Read.All`.
- Creating plans in the Entra admin center needs the Conditional Access Administrator role, and Conditional Access needs Microsoft Entra ID P1.

## Prototype a plan

1. **Keep the originals.** Leave the standalone policies enforced and unedited for the whole test.
2. **Create the plan in the Entra admin center** (Conditional Access › Policy plans (Preview)).
   - For policies that target All users, use **Create plan** and add the shared exclusions yourself. The migration wizard keeps those exclusions on every rule.
   - Name each rule exactly as the policy it copies. The scripts pair rules with policies by name.
   - Set every rule to **Report-only**.
3. **Set shared exclusions** to only the exclusions every member policy already has. See design rule R2.
4. **Keep Location policies out of plans** during the preview (rule R5).
5. **Wait about 10 minutes,** then run the exporter. Every rule should show `MATCH`.

   ```powershell
   ./Scripts/Export-CABPolicyPlans.ps1 -TenantId contoso.onmicrosoft.com
   ```

6. **Generate sign-ins** that each rule should and shouldn't apply to, then compare the decisions:

   ```powershell
   ./Scripts/Compare-CABPlanRuleSignIns.ps1 -Since '2026-11-04T20:40:00Z'
   ```

   Expect `Sign-ins where the rule and the policy decided differently: 0`. A few "policy but no entry for its same-named rule" lines just after a change are propagation. New and changed rules took 6 to 9 minutes to appear in testing.
7. **Keep the export.** Policy backups don't include plans. The exporter writes each plan with its rules, which is the backup.

To retire the originals later, follow Microsoft's order: turn the rules on, turn the originals off, then delete the originals after a validation period.

## Reading the exporter's output

- **`MATCH`:** the plan's shared conditions plus the rule equal the policy.
- **Differences** list each setting path with the policy's value and the plan-plus-rule value.
  - Values combine as a union.
  - Client app types are the exception: they must match both, and `all` means no restriction.
  - A guest-type difference can still be the same scope, written differently. For example, the plan includes 6 types and the rule excludes 1, where the policy includes the same 5.
- **`duplicated from plan`:** a value the rule carries that the plan already shares. Wizard-created rules keep these copies.

## Reference plans

[`Plans/`](Plans/) holds the target design for 3 plans:

| File | Shared conditions | Rules |
|---|---|---|
| [CAB-P1-Admins-PrivilegedAccess.json](Plans/CAB-P1-Admins-PrivilegedAccess.json) | The 39 admin roles; emergency access, workload identity and service account exclusions | CA-AUT003, CA-SIG005 |
| [CAB-P3-Global-SessionAndClientHardening.json](Plans/CAB-P3-Global-SessionAndClientHardening.json) | Emergency access, workload identity and service account exclusions | CA-COV003, CA-COV004, CA-COV005, CA-COV006 |
| [CAB-P6-Guests.json](Plans/CAB-P6-Guests.json) | All 6 guest and external user types; emergency access exclusion | CA-SIG002, CA-SIG010, CA-SIG006 |

- **Shape:** each file is a plan object (`displayName`, `description`, `sharedConditions`) with its `rules`. Each rule has a `state`, `conditions` and `controls`.
- **Placeholders:** IDs use the same placeholders as the policy templates (for example `REPLACE_WITH_EMERGENCY_ACCESS_GROUP_OBJECT_ID`).
- **State:** every rule ships report-only.
- **Tested:** the repository's tests check that each rule, combined with its plan, reproduces its template.

Nothing here deploys them. Create the plan in the portal from these values, or with Graph beta: `POST /identity/conditionalAccess/plans`, then one `POST /identity/conditionalAccess/plans/{id}/rules` per rule.

## Known gaps in the preview

- **Sign-in logs:** a rule has no plan reference, so filter by rule ID, not by name.
- **What If** lists rules as `[Plan: name] [Rule: name]`, but left one rule out of both result lists, and doesn't accept guests.
- **The rule details panel** can leave out conditions, such as an authentication flow. Check rules in the editor or the plan's JSON view.
- **The migration picker** doesn't mark policies already in a plan.
- **Location token caveat:** plans with a Location condition get one-hour tokens without instant IP enforcement during the preview.

The tests for both scripts are in [`Tests/Conditional-Access-Baseline/`](../../../../Tests/Conditional-Access-Baseline/).
