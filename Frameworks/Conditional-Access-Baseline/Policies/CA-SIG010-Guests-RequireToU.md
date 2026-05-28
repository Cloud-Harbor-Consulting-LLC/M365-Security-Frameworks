# CA-SIG010-Guests-RequireToU — Terms of Use enforcement for B2B guests

This document explains why a Terms of Use gate exists for B2B guests, how it layers with the MFA requirement in CA-SIG002, what the ToU lifecycle looks like from draft to re-consent, and what adopters must do before promoting this policy to enforcement.

This is paired documentation for the policy template `CA-SIG010-Guests-RequireToU.json` in the same folder. The two ship and are deployed as one unit.

---

## 1. Purpose

B2B guest access grants an external user a token in your tenant. That token can reach shared mailboxes, SharePoint sites, Teams channels, and any other application the guest is permitted to access. At no point in the standard B2B invitation and redemption flow is the guest required to acknowledge that they understand the data-handling rules of your organization.

CA-SIG010 closes that gap. It gates every guest sign-in on acceptance of a tenant-defined Terms of Use agreement before any access is granted. Three outcomes follow from this gate:

**Legal acknowledgment of data-handling rules.** The guest clicks "accept" on a document your legal team controls. The acceptance is timestamped, logged in Microsoft Entra, and queryable via the Microsoft Graph Terms of Use reporting endpoints. This is not a substitute for a signed data-processing agreement, but it is an automated, per-sign-in capture of the guest's acknowledgment of the conditions under which they are accessing your environment.

**Audit-evidence trail for compliance.** Regulated industries (financial services, healthcare, legal) frequently need to demonstrate that third parties accessing tenant data were informed of and accepted data-handling conditions. The Entra ID ToU feature produces an acceptance log that can be exported and presented to auditors. Without this control, that evidence trail does not exist — the guest was invited, redeemed the invitation, and received a token with no recorded consent event.

**Separation of access grant from terms acceptance.** Without CA-SIG010, the invitation redemption step (where the guest creates their account in the tenant) is the only moment where terms can be surfaced, and that moment happens once at account creation. CA-SIG010 moves the acceptance requirement to every sign-in cycle (or to the configured acceptance frequency), meaning the guest re-encounters the ToU at defined intervals rather than only at onboarding.

---

## 2. Layering with CA-SIG002

CA-SIG002-Guests-RequireMFA and CA-SIG010-Guests-RequireToU target the same guest scope and apply simultaneously. They are not alternatives — they address different layers of the access decision.

**CA-SIG002 operates at the identity layer.** It answers: can this external identity prove they are who they claim to be, using a second factor? The grant control is `builtInControls: mfa`. Passing this check means the identity has been verified.

**CA-SIG010 operates at the grant layer.** It answers: has this verified external identity explicitly accepted the conditions under which access is being granted? The grant control is `termsOfUse`. Passing this check means the guest has clicked "accept" on the ToU document within the current acceptance window.

Both policies evaluate for every qualifying sign-in. Entra Conditional Access evaluates all applicable policies and requires all grant controls from all matching policies to be satisfied. A guest who has satisfied MFA (CA-SIG002) but has not yet accepted the ToU (CA-SIG010) is prompted to accept before access is granted. A guest who has accepted the ToU but has not yet completed MFA satisfies neither policy and is challenged for MFA first.

The combined effect is a three-policy Guests persona stack:

| Policy | Layer | What it enforces |
|---|---|---|
| CA-SIG002-Guests-RequireMFA | Identity | Second-factor authentication |
| CA-SIG010-Guests-RequireToU | Grant | ToU acceptance |
| CA-SIG006-Guests-BlockNonGuestAppAccess | Application scope | Restricts guest tokens to Office365 applications |

CA-SIG002 and CA-SIG010 each use `operator: "OR"` because each has exactly one grant requirement. This is not a multi-control combination within a single policy; the AND semantics emerge from Conditional Access evaluating both policies independently and requiring both to pass.

---

## 3. Microsoft Entra ID Premium P2 prerequisite

The Terms of Use feature in Microsoft Entra ID requires **Entra ID Premium P2** licensing for each user who is covered by a ToU-based Conditional Access policy.

For guest users, licensing is determined by the 1:5 ratio rule: one Entra ID P2 license in the tenant covers up to five guest users. This means a tenant with 10 Entra ID P2 licenses can extend ToU enforcement to up to 50 guest users without additional guest licensing. Tenants whose guest population exceeds the 5x multiplier of P2 licenses need to acquire additional licenses before enforcing this policy.

Verify your licensing position before promoting CA-SIG010 from report-only to enforced. Enforcement without sufficient licenses may violate your Microsoft licensing agreement, and Microsoft may throttle the ToU feature for unlicensed guests.

Full documentation for the Terms of Use feature, including licensing requirements, the acceptance log schema, and re-consent configuration options, is at:

<https://learn.microsoft.com/en-us/entra/identity/conditional-access/terms-of-use>

---

## 4. ToU lifecycle

### 4.1 Drafting

The ToU document should be drafted by your legal team. Common inclusions:

- The categories of data the guest may access in your tenant
- The permitted and prohibited uses of that data
- The guest's responsibility to report unauthorized access or data exposure
- The duration of the access grant and the renewal or termination process
- The governing law and jurisdiction for disputes

Pin a version number in the document filename and footer. When the document content changes materially (new data categories, new restrictions, change of governing jurisdiction), increment the version number. Entra ID tracks acceptance by agreement ID, not by document version, so version pinning in the document itself is the only way to maintain a human-readable record of which version a guest accepted.

### 4.2 Publishing to Microsoft Entra

Publish the ToU document via the Microsoft Entra admin center:

1. Navigate to **Microsoft Entra ID > External Identities > Terms of use**.
2. Click **New terms**.
3. Upload the ToU document (PDF format, under 4 MB).
4. Set the display name (this is the name you will pass to `Deploy-CABaseline.ps1 -TermsOfUseName`).
5. Enable **Require users to expand the terms of use** if you want to force the guest to scroll the document before accepting.
6. Set the **Expire consents** option if your legal requirements call for periodic re-consent (common in regulated industries — annual re-consent is a standard pattern).
7. Set the language. If your guest population spans languages, upload localized versions.
8. Click **Create**.

After creation, the agreement appears in the Terms of use list with a unique agreement ID.

### 4.3 Capturing the agreement ID

The agreement ID is the GUID that `CA-SIG010-Guests-RequireToU.json` carries in the `grantControls.termsOfUse` array as `REPLACE_WITH_TERMS_OF_USE_ID`.

Retrieve it from the Microsoft Graph:

```http
GET https://graph.microsoft.com/beta/identityGovernance/termsOfUse/agreements
```

Alternatively:

```powershell
Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/identityGovernance/termsOfUse/agreements" |
    Select-Object -ExpandProperty value |
    Select-Object id, displayName
```

The `id` field is the GUID to substitute into the template. `Deploy-CABaseline.ps1` resolves this automatically at runtime via the `Resolve-TermsOfUseId` helper when you pass `-TermsOfUseName "<DisplayName>"`.

### 4.4 Re-consent triggers

Guests are re-prompted to accept the ToU in the following situations:

- **ToU expiry.** If you configured expiry (for example, 12-month re-consent), the guest is prompted again at the next sign-in after the acceptance expires.
- **ToU document update.** If you upload a new version of the ToU document to the same agreement, Entra ID can be configured to require re-consent. Enable **Re-evaluate consents** in the agreement settings after uploading a revised document.
- **Manual revocation.** An administrator can revoke a specific guest's acceptance in the Microsoft Entra admin center or via the Graph API. The guest is re-prompted at their next sign-in.
- **New agreement deployment.** If you replace the ToU agreement entirely (different agreement ID), all guests must re-consent because the new policy references a new ID that no guest has yet accepted.

### 4.5 Removal procedure

To remove the ToU gate:

1. Promote CA-SIG010 to `disabled` state via the Entra admin center or the deployer.
2. Wait for the change to propagate (typically under 5 minutes).
3. Verify guest sign-ins no longer show a ToU prompt in the sign-in log.
4. Delete or archive the ToU agreement in **External Identities > Terms of use** if no other policies reference it.

Do not delete the ToU agreement while the policy is still in report-only or enforced state — the policy will fail to evaluate and will block guest access.

---

## 5. Adopter checklist

Complete these steps in order before enforcing CA-SIG010:

1. **Draft and legal-review the ToU document.** Obtain sign-off from your legal team on the content and version.
2. **Publish the ToU agreement** in the tenant via **Microsoft Entra > External Identities > Terms of use**. Note the display name you use — this becomes the value of `-TermsOfUseName`.
3. **Capture the agreement ID** from the Graph endpoint `https://graph.microsoft.com/beta/identityGovernance/termsOfUse/agreements`. Confirm the ID maps to the correct agreement.
4. **Deploy the policy in report-only** by running:

   ```powershell
   .\Scripts\Deploy-CABaseline.ps1 -TermsOfUseName "Your ToU Display Name"
   ```

   The deployer resolves the agreement ID at runtime and substitutes `REPLACE_WITH_TERMS_OF_USE_ID` in the template before creating the policy.

5. **Soak the policy in report-only for 14 days.** See Section 6 for what to monitor.
6. **Verify licensing.** Confirm Entra ID P2 seat count covers the guest population (1:5 ratio rule).
7. **Promote to enforcement** after the soak window closes and the impact analysis is clean.

---

## 6. 14-day report-only validation

### What to monitor in sign-in logs

During the 14-day soak, review sign-in logs filtered to:

- **User type:** Guest
- **Policy:** CA-SIG010-Guests-RequireToU
- **Result:** `reportOnlyInterrupted`

`reportOnlyInterrupted` means the policy would have prompted the guest for ToU acceptance if enforced. This is the expected behavior for any guest who has not yet accepted the ToU. It is not a failure state — it is the count of guests who will see the prompt on enforcement day.

Also review:

- **`reportOnlyFailure`** — these are guests who would have been blocked even if they tried to accept the ToU. This typically indicates a misconfigured agreement ID or an agreement that is in a draft state. Investigate before enforcement.
- **`reportOnlySuccess`** — guests who have already accepted the ToU within the configured acceptance window. These guests will not be re-prompted on enforcement day.
- **`reportOnlyNotApplied`** — guests excluded from the policy scope (EmergencyAccess) or who don't match the conditions. Confirm this population is expected.

### How to verify guests are prompted but not blocked

In report-only mode, the policy evaluates but does not enforce. Guests who would be prompted for ToU acceptance in enforced mode see no prompt during the soak. Sign-in proceeds normally. The only signal that the policy would have applied is the `reportOnly*` result codes in the sign-in log.

To confirm the prompt mechanism works before enforcement day, promote the policy to enforced on a test guest account (an account you control that holds a guest identity in the tenant). Sign in as the test guest and verify:

1. The ToU document is displayed.
2. The display name matches the expected agreement.
3. Accepting the ToU completes the sign-in successfully.
4. Declining the ToU returns an access-denied result and the sign-in is blocked.
5. The acceptance event appears in **Microsoft Entra > External Identities > Terms of use > Agreements > [your agreement] > Consents**.

Return the policy to report-only after the test.

### Promotion criteria to enforcement

Promote CA-SIG010 to enforced when all of the following are true:

- The 14-day soak window is complete.
- No `reportOnlyFailure` results appear in the sign-in log.
- The `reportOnlyInterrupted` count is understood (each guest will be prompted once on enforcement day; plan for user communications if the count is large).
- Licensing is confirmed (Entra ID P2 at the 1:5 guest ratio).
- The ToU document is legally reviewed and version-pinned.
- The acceptance event confirmed via the test guest account (see above).

---

## 7. Out-of-scope coverage

The ToU grant control captures **click-through consent only**. It records that a guest clicked the "Accept" button on the ToU document at a specific timestamp. It does not:

- Verify that the guest read the document
- Enforce that the guest understood the document
- Validate that the guest complied with the terms after acceptance
- Substitute for a signed data-processing agreement or a formal NDA
- Enforce the content of the terms — that is an operational and legal responsibility

If your compliance framework requires evidence that a guest actually read specific provisions, click-through acceptance alone does not satisfy that requirement. In those cases, supplement the technical control with a business process (for example, a required attestation call with the guest before onboarding, or a separate countersigned agreement).

The ToU control closes the gap between "guest has access" and "guest has acknowledged the conditions of that access." It does not close the gap between "guest acknowledged the conditions" and "guest behaved in accordance with them."

---

## 8. Rollout-sequence position

CA-SIG010 sits at **position 24** in the v1.3 baseline rollout sequence, after CA-SIG009-AllUsers-BlockHighSignInRisk (position 21) and after the WorkloadIdentities and Agents persona policies (positions 22 and 23).

The ToU gate is an administrative consent control rather than a signal-driven security control. It does not respond to real-time identity or sign-in signals; it enforces a static accept/decline gate at sign-in time. For this reason it sits after the risk-signal policies (CA-SIG003 through CA-SIG009), which are operationally more demanding to validate and more disruptive if misconfigured.

Placing CA-SIG010 last in the sequence also ensures that all Guests persona enforcement policies (CA-SIG002, CA-SIG006) are already enforced before the ToU gate is added. This prevents a situation where the ToU prompt is seen by guests before MFA enforcement is stable, which would complicate attribution of any guest access issues during the soak.

**Minimum report-only soak:** 14 days, driven by the licensing verification requirement and the need to communicate the ToU prompt to the guest population before enforcement.

**Prerequisites before promotion:**

- Entra ID P2 licensing confirmed for the guest population
- ToU agreement published and agreement ID captured
- Test guest acceptance verified
- Guest population notified of the upcoming prompt

This document is paired with the JSON template in `CA-SIG010-Guests-RequireToU.json`. Both ship as one unit; the deployer treats them as a single policy artifact.
