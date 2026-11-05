# Conditional Access policy plans: preview design note

**Status:** preview, November 2026. Conditional Access policy plans are a Microsoft Entra preview feature. `Scripts/Deploy-CABPolicyPlans.ps1` deploys the plans in [`Plans/`](Plans/) with every rule in report-only, alongside the baseline's standalone policies in [`../../Policies/`](../../Policies/), which remain the supported edition. Enforced plans, plan support in `Deploy-CABaseline.ps1`, and plans as an edition of the baseline wait for general availability (CAB v2.0 on the roadmap).

This note records how plans behave, as tested against the baseline in a demo tenant, and the rules the baseline will follow when it adopts them.

## 1. How a plan works

- **Structure.** A plan has details (name, description, owners, tags), optional shared conditions, and at least one rule. Each rule is evaluated as its own decision.
- **Evaluation.** Plans and standalone policies apply together, with no precedence. Every policy and every rule that applies must be satisfied.
- **Constraints** ([concept page](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-plans)):
  - All users and All resources can be set only on a rule.
  - Shared conditions can't mix identity types.
  - A rule can add exclusions but can't remove a plan exclusion.
- **Role and license.** Creating or editing a plan needs the Conditional Access Administrator role. Microsoft's plan pages point to the standard Conditional Access license requirement, Microsoft Entra ID P1.
- **API.** Plans are on Microsoft Graph beta, at `/identity/conditionalAccess/plans`. Rules are at `/identity/conditionalAccess/plans/{id}/rules`, with grant and session controls nested under `controls`. This is a separate endpoint from `/policies`, so anything that reads only `/policies` doesn't see plans. That includes policy backups and reports.
- **Preview caveat.** During the preview, plans that target users with a Location condition get one-hour access tokens without the instant IP enforcement check.

## 2. What testing showed

**Method.** Three plans were built in a demo tenant (November 2026). Each rule ran in report-only next to the enforced standalone policy it copies, and the policies were left untouched. The two scripts in [`Scripts/`](Scripts/) compared the configuration and the sign-in decisions.

| Plan | Built with | Rules |
|---|---|---|
| P1 Admins | Migration wizard | CA-AUT003, CA-SIG005 |
| P3 Session and client hardening | Migration wizard | CA-COV003, CA-COV004, CA-COV005, CA-COV006 |
| P6 Guests | Created from scratch | CA-SIG002, CA-SIG010, CA-SIG006 |

**Result.** Across all 9 rules, rules and policies reached the same decision on every sign-in compared (90 in the final window).

**Findings:**

1. **The migration wizard created no shared conditions for All users policies.** For P1, the identical role targeting and exclusions moved to the plan. For P3, every rule kept its own copy of the three exclusion groups. A plan created from scratch got real shared conditions, with no copies on its rules.
2. **Plan and rule conditions don't all combine the same way.**
   - Exclusions accumulate.
   - Client app types must match both the plan and the rule, with `all` meaning no restriction. A plan set to `all` and a rule set to `browser` applied only to browsers: desktop-app sign-ins reported `conditionsNotSatisfied: clientType`.
   - Platforms and risk levels are untested.
3. **A rule appears in sign-in logs with no plan reference.** In `appliedConditionalAccessPolicies` a rule is its own entry, with the rule's ID and name and the same fields as a policy. The wizard gives each rule its policy's name, so during a migration only the ID tells a rule from its source policy.
4. **The portal shows a merged view.**
   - The rule editor locks inherited items ("Inherited from plan"), but Graph still stores each wizard-created rule's own copy of the exclusions.
   - The read-only rule details panel left out an authentication flow condition. The editor shows it.
5. **What If evaluates rules, with gaps.**
   - Rules are listed as `[Plan: name] [Rule: name]`, with the same reasons as their policies.
   - One rule, the only one with a device filter and with session controls and no grant, was in neither result list.
   - The user picker doesn't accept guests.
6. **The migration picker doesn't mark policies already in a plan,** so they can be selected again.
7. **Report-only and enforced results differ in wording.** On an MFA or Terms of Use prompt the enforced policy logs `failure` and the report-only rule logs `reportOnlyInterrupted`. The comparison script treats them as the same decision.
8. **Propagation.** New and changed rules took 6 to 9 minutes to appear in sign-in evaluations.

## 3. Design rules for the baseline

- **R1. One plan per security objective; rules keep the CA-XXX policy names.** Sign-in queries, the ITPS and ZTRA collectors, and exports stay readable.
- **R2. Plan-level exclusions are the intersection of the member policies' exclusions.**
  - A rule can't remove a plan exclusion, so an exclusion at plan level that a member policy didn't have widens that rule.
  - Extra exclusions stay on the rule.
  - This keeps the per-policy exclusion judgment in [POLICY-DESIGN.md](../../Design/POLICY-DESIGN.md) section 4.
- **R3. Emergency access is always a plan-level exclusion.**
- **R4. One identity type per plan's shared conditions.** Users, including guests, go in user plans. Agents and workload identities go in their own plans.
- **R5. No Location conditions in plans during the preview,** because of the token caveat in section 1. Location policies stay standalone.
- **R6. Report-only first.**
  - Rules are compared with the originals in sign-in logs.
  - Rules go On before the originals go Off, as in Microsoft's [migration guidance](https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-migrate-conditional-access-policy-plan).
  - The originals aren't edited during validation.
- **R7. Back up plans separately.** Policy backups don't include plans, and a rule exported without its plan is incomplete.

## 4. Target design (v2.0 candidate)

Exclusion shorthand: EA emergency access, WI workload identities, SA service accounts.

| Plan | Shared conditions | Rules | At rule level |
|---|---|---|---|
| P1 Admins: privileged access | The 39 admin roles; exclude EA, WI, SA | AUT003, SIG005 | Apps, risk, controls |
| P2 Registration | Exclude EA, WI, SA | AUT001, AUT002 | All users and the user action; AUT002 also excludes all guest types |
| P3 Session and client hardening | Exclude EA, WI, SA | COV003, COV004, COV005, COV006 | All users, All resources, platform, flow and device-filter conditions |
| P4 Identity risk | Exclude EA, WI | SIG003, SIG004, SIG008, SIG009 | SA exclusion on SIG003 and SIG004 |
| P5 Internal device trust | InternalUsers; exclude EA, WI | COV008, SIG001, SIG007 | SA exclusion on COV008 and SIG007 |
| P6 Guests | All 6 guest and external user types; exclude EA | SIG002, SIG010, SIG006 | SIG006 excludes the service provider type plus WI and SA |
| P7 Authentication floor | Exclude EA | COV001, COV002 | All users; WI exclusion on COV002 |
| P8 Agent risk | Agent risk medium and high | COV011, COV013 | Identity and resources |
| Standalone | — | COV007, COV009, COV014, COV015 (Location, R5); COV010; COV012 | — |

**Counted from the 28 templates:**

- **Objects:** 28 → 14 (8 plans holding 22 rules, plus 6 standalone policies).
- **Exclusion-group references:** 55 → 27.
- **The 39-role list:** written once instead of twice.
- **Not reduced:** emergency access still appears in 9 places, because plans remove duplication within a plan, not across plans.

P1, P3 and P6 are in [`Plans/`](Plans/), ready for the deployer. Combined with its plan's shared conditions, each rule reproduces its template, which the repository's tests check. CA-SIG006 is the one exception: it differs only in how its guest types are written. The template includes 5 types, while the plan includes 6 and the rule excludes 1, which is the same effective scope.

## 5. Open questions

1. Do rules count toward the tenant's Conditional Access policy limit? Microsoft's plan pages don't say.
2. How do platform, location and risk conditions combine between plan and rule?
3. What happens to a plan's rules when the plan is deleted, and how is it audited?
4. Why does What If leave out a rule with a device filter and session controls only?

## Sources

- Microsoft Learn: [What are Conditional Access policy plans? (preview)](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-plans)
- Microsoft Learn: [Create a policy plan](https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-create-conditional-access-policy-plan)
- Microsoft Learn: [Migrate policies to a policy plan](https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-migrate-conditional-access-policy-plan)
- Microsoft Graph beta: [Delete conditionalAccessPolicyRule](https://learn.microsoft.com/en-us/graph/api/conditionalaccesspolicyplan-delete-rules?view=graph-rest-beta) (documents the `/plans/{id}/rules` path)
- Microsoft Learn: [Conditional Access license requirements](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
