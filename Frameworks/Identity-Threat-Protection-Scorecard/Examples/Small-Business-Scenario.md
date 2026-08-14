# ITPS Scenario — Northwind Bakery Group (small business)

> **Note:** Northwind Bakery Group is a fictional organization. All data in this document is illustrative and does not represent any real tenant.

**Profile:** 45 users, 3 locations, Microsoft 365 Business Premium. No dedicated security headcount. IT is one internal generalist plus a managed service provider on a break-fix contract.

**Overall score: 36 / 100 — Connected**

| Dimension | Score | Tier equivalent |
|---|---|---|
| Prevention | 51 | Protected |
| Detection | Not scored | — |
| Governance | 20 | Connected |
| Ownership | Not scored | — |

Overall is the mean of the 2 scored dimensions. Detection and Ownership were not assessed, so the figure is an upper bound.

---

## What the scorecard found

### Prevention — 51

Business Premium includes Entra ID P1, and the MSP enabled Security Defaults at tenant setup. That single action earns most of this dimension's score: MFA is enforced for all users and legacy authentication is blocked, because Security Defaults does both.

| Check | Result | Note |
|---|---|---|
| P-01 Secure Score attainment | 31 / 50 | Tenant attainment 62% |
| P-02 MFA enforced for all users | 10 / 10 | Via Security Defaults |
| P-03 Legacy authentication blocked | 10 / 10 | Via Security Defaults |
| P-04 Risk-based policy present | 0 / 10 | Requires P2 Identity Protection |
| P-05 Privileged roles targeted | 0 / 10 | No role-targeted policy |
| P-06 Phishing-resistant strength in use | 0 / 10 | SMS and authenticator app only |

### Detection — not scored

The tenant has no Defender for Identity license and no Defender for Cloud Apps license. The health issues endpoint was unreachable, and the Coverage and maturity page is not available.

Every check in this dimension therefore fell back to manual review, and the collector returned **no score rather than a zero**. That distinction matters: a zero would assert that detection was assessed and found absent, when in fact it could not be assessed at all. For a Business Premium tenant this is the honest output — there is no identity threat detection capability present to measure.

### Governance — 20

| Check | Result | Note |
|---|---|---|
| G-01 Access reviews configured | 0 / 20 | No review definitions exist; Access Reviews requires P2 |
| G-02 Guest access reviewed | 0 / 15 | 11 guest accounts, none reviewed |
| G-04 Standing privilege minimised | 0 / 45 | 4 permanent Global Administrators, no eligible assignments |
| G-05 Workload identity credential lifetime | 20 / 20 | 2 app registrations, both with 6-month secrets |

G-05 passes almost by accident: the tenant has very few app registrations, and the MSP happened to set short expiries.

G-02 scores a genuine zero rather than falling to manual review. The tenant has no access review definitions at all, so guest coverage is definitively absent — not merely unreadable.

### Ownership — not scored

No ownership matrix exists. When asked who would notice if MFA enforcement were switched off, the answer was "the MSP would probably catch it." Probably is not an owner.

---

## The diagnostic

Northwind's real problem is not that its score is 36. It is that **3 of its 4 dimensions are constrained by a licensing decision nobody revisited since the tenant was created.**

Prevention scores respectably because Security Defaults is genuinely effective for a tenant this size. But Security Defaults is all-or-nothing: it cannot be scoped, cannot be tuned, and cannot express "require phishing-resistant MFA for the 4 admins." The tenant has hit the ceiling of what P1 plus Security Defaults can do, and the remaining Prevention points all require P2.

The 4 permanent Global Administrators are the highest-severity finding on this scorecard, and the cheapest to fix. Reducing to 2, with one break-glass account excluded from Conditional Access, costs nothing and removes the single most valuable target in the tenant.

### Recommended sequence

1. **Reduce Global Administrators from 4 to 2** and document a break-glass account. No license required, no cost, largest single risk reduction available.
2. **Review the 11 guest accounts by hand.** Access Reviews needs P2, but a spreadsheet and an afternoon does not.
3. **Assign ownership.** Name one person accountable for each control area, even if that person is the same for all of them. A named owner with a quarterly calendar reminder converts this from an unmonitored configuration into a managed one.
4. **Then evaluate Entra ID P2** for the 4 admin accounts rather than all 45 users. P2 is licensed per user, and the accounts that need Identity Protection and PIM most are the privileged ones.

### The uncomfortable part

Steps 1 through 3 cost nothing and materially reduce Northwind's risk. They will barely move the automated score.

Reducing Global Administrators does not improve G-04. The check scores the share of privileged assignments that are permanent, and without P2 there are no eligible assignments to shift that share — going from 4 permanent to 2 leaves the ratio at 100% either way. Reviewing guests by hand does not improve G-02, because G-02 looks for a configured review definition and its scope filter. Naming owners does not improve Ownership until the matrix is scored by hand.

That is worth stating plainly rather than hiding: **for an under-licensed tenant, a meaningful share of risk reduction happens outside what the automated checks can observe.** The scorecard measures configuration, and configuration is only part of Northwind's security. Use the number to start the licensing conversation, not to grade the work.

The licensing conversation is the real output of this assessment. Northwind is not insecure because its team is careless. It is capped at roughly 36 because 3 of 4 dimensions need capabilities its current SKU does not include.
