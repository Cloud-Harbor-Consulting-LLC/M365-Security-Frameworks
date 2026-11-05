# Policy plans (preview)

> **Preview.** Conditional Access policy plans are a Microsoft Entra preview feature, and this folder is a preview of how the baseline will use them. The deployer creates plans with every rule in report-only and never touches the standalone policies in [`../../Policies/`](../../Policies/), which stay the supported edition. The other scripts only read.

A policy plan holds shared conditions once, and its rules inherit them. This folder deploys 3 of the baseline's plans next to its policies, and checks, on real sign-ins, that each rule decides the same way as the policy it copies.

| Path | What it is |
|---|---|
| [POLICY-PLANS-PREVIEW.md](POLICY-PLANS-PREVIEW.md) | How plans behave as tested, the baseline's design rules for plans, and the target design |
| [Plans/](Plans/) | 3 plans (P1 Admins, P3 Session and client hardening, P6 Guests), every rule report-only |
| [Scripts/Deploy-CABPolicyPlans.ps1](Scripts/Deploy-CABPolicyPlans.ps1) | Creates the plans in a tenant, report-only, and reads each one back |
| [Scripts/Export-CABPolicyPlans.ps1](Scripts/Export-CABPolicyPlans.ps1) | Read-only. Exports every plan with its rules, snapshots the policies, and compares each rule with the policy of the same name |
| [Scripts/Compare-CABPlanRuleSignIns.ps1](Scripts/Compare-CABPlanRuleSignIns.ps1) | Read-only. Compares each rule's sign-in results with its policy's results |

## Prerequisites

- PowerShell 7 and the `Microsoft.Graph.Authentication` module: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`.
- The baseline's prerequisites for the policies the plans copy:
  - the persona groups `CA-Persona-EmergencyAccess`, `CA-Persona-WorkloadIdentities` and `CA-Persona-ServiceAccounts`;
  - the AdminAuth authentication strength (P1);
  - the guest Terms of Use agreement (P6).

  See [`../../Scripts/README.md`](../../Scripts/README.md). Different names are passed as parameters.
- An account with the Conditional Access Administrator role. Conditional Access needs Microsoft Entra ID P1.
- Delegated scopes:
  - the deployer requests `Policy.ReadWrite.ConditionalAccess`, `Policy.Read.All`, `Group.Read.All` and `Agreement.Read.All`;
  - the read-only scripts request `Policy.Read.All`, `Directory.Read.All` and `AuditLog.Read.All`.

## Deploy and validate

1. **Keep the originals.** Leave the standalone policies enforced and unedited for the whole test. The deployer doesn't touch them.
2. **Preview the deployment.** It resolves every placeholder and lists the plans it would create, without writing:

   ```powershell
   ./Scripts/Deploy-CABPolicyPlans.ps1 -TenantId contoso.onmicrosoft.com -WhatIf
   ```

3. **Deploy.** Use `-Plan` to choose plans, and `-TermsOfUseName` if your guest agreement has another name.

   ```powershell
   ./Scripts/Deploy-CABPolicyPlans.ps1 -TenantId contoso.onmicrosoft.com
   ```

   - **What it does:** each plan is created with its rules in one request, then read back. The script reports any value Graph didn't store as sent, and exits 1 if anything differs.
   - **Existing plans:** a plan that already exists with the same name is skipped. Nothing is ever updated or replaced.
   - **State:** every rule is report-only, and the script has no option to enforce.
4. **Check the portal.** The plans appear under Conditional Access › Policy plans (Preview).
5. **Wait about 10 minutes,** then run the exporter. Every rule should show `MATCH`. CA-SIG006 is the exception: it shows its 3 guest-type paths, the same scope written differently.

   ```powershell
   ./Scripts/Export-CABPolicyPlans.ps1 -TenantId contoso.onmicrosoft.com
   ```

6. **Generate sign-ins** that each rule should and shouldn't apply to, then compare the decisions:

   ```powershell
   ./Scripts/Compare-CABPlanRuleSignIns.ps1 -Since '2026-11-04T20:40:00Z'
   ```

   Expect `Sign-ins where the rule and the policy decided differently: 0`. A few "policy but no entry for its same-named rule" lines just after a change are propagation. New and changed rules took 6 to 9 minutes to appear in testing.
7. **Keep the export.** Policy backups don't include plans. The exporter writes each plan with its rules, which is the backup.

**Building your own plan in the portal instead:**

- For policies that target All users, use **Create plan** and add the shared exclusions yourself. The migration wizard keeps those exclusions on every rule.
- Name each rule exactly as the policy it copies, because the scripts pair them by name.
- Keep plan-level exclusions to those every member policy already has (design rule R2), and keep Location policies out of plans during the preview (R5).

**To retire the originals later,** follow Microsoft's order: turn the rules on in the portal, turn the originals off, then delete the originals after a validation period. To remove a plan, delete it under Policy plans (Preview), after exporting it.

## Reading the exporter's output

- **`MATCH`:** the plan's shared conditions plus the rule equal the policy.
- **Differences** list each setting path with the policy's value and the plan-plus-rule value.
  - Values combine as a union.
  - Client app types are the exception: they must match both, and `all` means no restriction.
  - A guest-type difference can still be the same scope, written differently. For example, the plan includes 6 types and the rule excludes 1, where the policy includes the same 5.
- **`duplicated from plan`:** a value the rule carries that the plan already shares. Wizard-created rules keep these copies.
- **Deployed plans compared with customized policies:** the deployed rules copy the repository's templates. Where a tenant has changed its own policy (for example, an extra exclusion group, or a compliant device added to a grant), the exporter shows that change as a difference. That's drift from the baseline, not a deployment fault.

## The plans

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

The deployer sends each file, with its placeholders resolved, as the body of `POST /identity/conditionalAccess/plans` (Graph beta), which creates the plan and its rules together.

## Known gaps in the preview

- **Sign-in logs:** a rule has no plan reference, so filter by rule ID, not by name.
- **What If** lists rules as `[Plan: name] [Rule: name]`, but left one rule out of both result lists, and doesn't accept guests.
- **The rule details panel** can leave out conditions, such as an authentication flow. Check rules in the editor or the plan's JSON view.
- **The migration picker** doesn't mark policies already in a plan.
- **Owners:** plans created through the API have no owners, while the portal sets the signed-in admin as owner. Owners are metadata only. Add them under Edit plan if you track them.
- **Location token caveat:** plans with a Location condition get one-hour tokens without instant IP enforcement during the preview.

The tests for all three scripts are in [`Tests/Conditional-Access-Baseline/`](../../../../Tests/Conditional-Access-Baseline/).
