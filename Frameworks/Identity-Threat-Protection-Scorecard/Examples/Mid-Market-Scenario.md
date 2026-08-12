# ITPS Scenario — Silverline Logistics (mid-market)

> **Note:** Silverline Logistics is a fictional organization. All data in this document is illustrative and does not represent any real tenant.

**Profile:** 850 users, Microsoft 365 E3 with an Entra ID P2 add-on for 120 users, Defender for Identity licensed and deployed to 2 of 5 domain controllers. Security is a 2-person team inside a 9-person IT department. A Conditional Access baseline was deployed 8 months ago by a consultant.

**Overall score: 62 / 100 — Protected**

| Dimension | Score | Tier equivalent |
|---|---|---|
| Prevention | 54 | Protected |
| Detection | 58 | Protected |
| Governance | 73 | Fortified |
| Ownership | Not scored | — |

Overall is the mean of the 3 scored dimensions. Ownership was not assessed, so the figure is an upper bound.

---

## What the scorecard found

### Prevention — 54

The consultant's Conditional Access baseline is comprehensive and mostly still in report-only mode.

| Check | Result | Note |
|---|---|---|
| P-01 Secure Score attainment | 34 / 50 | Tenant attainment 68% |
| P-02 MFA enforced for all users | 10 / 10 | Enforced |
| P-03 Legacy authentication blocked | 10 / 10 | Enforced |
| P-04 Risk-based policy present | 0 / 10 | 4 risk policies exist, all report-only |
| P-05 Privileged roles targeted | 0 / 10 | Admin policy exists, report-only |
| P-06 Phishing-resistant strength in use | 0 / 10 | Authentication strength configured, report-only |

**This is the finding that matters.** Silverline has already done the design work. Four risk policies, an admin-targeted policy, and an authentication strength policy are all configured correctly and none of them are enforcing. The checks require `enabled` state, so all 4 score zero.

The tenant's dashboards show a complete Conditional Access baseline. Its actual enforcement posture is MFA and a legacy auth block.

### Detection — 58

| Check | Result | Note |
|---|---|---|
| D-01 No open high-severity health issues | 25 / 25 | None open |
| D-02 No open medium-severity health issues | 0 / 15 | 3 open |
| D-03 Sensor health issues resolved | 0 / 10 | 3 domain controllers have no sensor |
| D-04 Health signal reachable | 10 / 10 | Defender for Identity provisioned |
| D-05 Coverage and maturity composite | Manual | Portal reading: 61, Protected |

Defender for Identity covers 2 of 5 domain controllers. The 3 uncovered controllers include the one that authenticates the manufacturing site VPN.

There are no alerts from those 3 controllers. That is not evidence of safety; it is the absence of a sensor.

### Governance — 73

| Check | Result | Note |
|---|---|---|
| G-01 Access reviews configured | 20 / 20 | 3 review definitions |
| G-02 Guest access reviewed | 15 / 15 | Quarterly guest review active |
| G-03 PIM eligible assignments | 20 / 20 | 34 eligible assignments |
| G-04 Standing privilege minimised | 17.71 / 25 | 14 permanent of 48 total, a 29% standing ratio |
| G-05 Workload identity credential hygiene | 0 / 20 | 9 of 22 app registrations hold secrets over 12 months |

Governance is Silverline's strongest dimension, driven by a P2 add-on that was purchased specifically for PIM. The gap is non-human identities: 9 application registrations hold long-lived secrets, several created for integrations that ended.

### Ownership — not scored

No ownership matrix. The security team knows who does what informally, which works until someone is on leave.

---

## The diagnostic

Silverline is the most common mid-market pattern: **the work has been done and not switched on.**

The consultant delivered a correct Conditional Access design. Eight months later it is still in report-only, because promoting it requires someone to accept the risk of a user-impacting change, and no one owns that decision. The report-only data has been accumulating for 8 months and nobody has reviewed it, because reviewing it is also unowned.

This is why Ownership is a scored dimension rather than a footnote. Silverline's Prevention score is 54 not because of a technology gap but because of an accountability gap. Every point available in P-04, P-05, and P-06 is one policy-state change away.

### Recommended sequence

1. **Review 8 months of report-only data and promote the 4 risk policies.** The impact analysis is already sitting in the tenant. This alone moves Prevention from 54 to 84.
2. **Deploy Defender for Identity sensors to the remaining 3 domain controllers**, starting with the manufacturing VPN authenticator. Clearing the sensor and medium-severity findings moves Detection from 58 to 100.
3. **Rotate or retire the 9 long-lived app secrets.** Cross-reference `KQL/workload-identity-review.kql` first: registrations with no sign-ins in 90 days should be deleted, not rotated. Moves Governance from 73 to 93.
4. **Build the ownership matrix.** Silverline's gap is not knowledge, it is that the knowledge is not written down and not assigned.

Steps 1 through 3 require no purchase and would move the overall score to roughly 92 using licenses Silverline already owns. That figure remains an upper bound until Ownership is scored, which is exactly the dimension that caused the delay in the first place.
