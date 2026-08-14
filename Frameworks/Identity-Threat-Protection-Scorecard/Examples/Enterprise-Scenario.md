# ITPS Scenario — Meridian Financial Holdings (enterprise)

> **Note:** Meridian Financial Holdings is a fictional organization. All data in this document is illustrative and does not represent any real tenant.

**Profile:** 14,000 users across 6 subsidiaries, Microsoft 365 E5 tenant-wide, Entra ID Governance add-on, Defender for Identity on all 31 domain controllers, a 24/7 SOC of 18 analysts, and a dedicated identity engineering team of 4. Regulated: SOC 2 Type II and PCI-DSS in scope.

**Overall score: 82 / 100 — Fortified**

| Dimension | Score | Tier equivalent |
|---|---|---|
| Prevention | 88 | Resilient |
| Detection | 100 | Resilient |
| Governance | 58 | Protected |
| Ownership | Not scored | — |

Overall is the mean of the 3 scored dimensions. Ownership was not assessed, so the figure is an upper bound.

---

## What the scorecard found

### Prevention — 88

| Check | Result | Note |
|---|---|---|
| P-01 Secure Score attainment | 38 / 50 | Tenant attainment 76% |
| P-02 MFA enforced for all users | 10 / 10 | Enforced |
| P-03 Legacy authentication blocked | 10 / 10 | Enforced |
| P-04 Risk-based policy present | 10 / 10 | Enforced, all risk levels |
| P-05 Privileged roles targeted | 10 / 10 | 39 directory roles targeted |
| P-06 Phishing-resistant strength in use | 10 / 10 | FIDO2 required for admins |

Every discrete Conditional Access check passes. The 12-point gap is entirely in P-01, and Secure Score attainment at 76% is a good result for a tenant this size.

### Detection — 100

| Check | Result | Note |
|---|---|---|
| D-01 No open high-severity health issues | 25 / 25 | None open |
| D-02 No open medium-severity health issues | 15 / 15 | None open |
| D-03 Sensor health issues resolved | 10 / 10 | 31 of 31 controllers covered |
| D-04 Health signal reachable | 10 / 10 | Healthy |
| D-05 Coverage and maturity composite | Manual | Portal reading: 89, Resilient |

Detection is genuinely excellent. Full sensor coverage, no open health issues, and a SOC that acts on what the sensors produce.

### Governance — 58

| Check | Result | Note |
|---|---|---|
| G-01 Access reviews configured | 20 / 20 | 22 review definitions |
| G-02 Guest access reviewed | 15 / 15 | Quarterly, automated, scoped to `userType eq 'Guest'` |
| G-04 Standing privilege minimised | 6.75 / 45 | 391 permanent of 460 total, an 85% standing ratio |
| G-05 Workload identity credential lifetime | 15.96 / 20 | 63 of 312 app registrations hold secrets over 12 months |

This is the finding. Meridian has PIM deployed with 69 eligible assignments, and **391 permanent standing assignments alongside them.** PIM was rolled out to the identity team's own roles and to a pilot group, and the migration stopped there. The subsidiaries were never onboarded.

Meridian is the tenant that retired a check. Earlier revisions of this rubric carried a separate G-03, "PIM eligible assignments in use", which awarded a binary 20 points merely for PIM being switched on somewhere. Meridian earned those 20 in full while earning 15% of G-04, the check that measures whether PIM is actually displacing standing privilege. One scorecard, two opposite verdicts, drawn from the same 460 assignments. G-03 has since been folded into G-04, which now carries 45 points on that single axis — so a tenant that has bought PIM and not finished deploying it can no longer bank points for the purchase.

Sixty-three application registrations hold secrets older than a year, several belonging to subsidiaries acquired in the last 3 years whose original owners have left.

### Ownership — not scored

Meridian has more documented process than either smaller scenario, and still no single artifact that answers "when this control degrades, who fixes it." Responsibility is distributed across an identity engineering team, a SOC, 6 subsidiary IT groups, and a GRC function. Each assumes one of the others owns the app registration inventory.

---

## The diagnostic

Meridian is the enterprise pattern: **excellent at the controls that a central team can own, weak at the controls that require organisational reach.**

Prevention and Detection are both at or above 88 because the identity engineering team can configure Conditional Access and deploy sensors without anyone else's cooperation. Governance is at 59 because eliminating standing privilege and cleaning up app registrations requires 6 subsidiary IT groups to change how they work.

The overall score of 82 understates the risk. An attacker does not experience the average. They experience the weakest path, and Meridian's weakest path is 391 permanent privileged assignments across subsidiaries with uneven oversight, plus 63 long-lived credentials whose owners have left the company. Excellent detection narrows the window after compromise. It does not narrow the standing privilege that makes the compromise worth attempting.

This is the argument for equal dimension weighting stated as a finding: a weighted model that privileged Prevention and Detection would report Meridian as Resilient, and Meridian is not Resilient.

### Recommended sequence

1. **Complete the PIM migration to the 6 subsidiaries.** Reducing permanent assignments from 391 to under 50 moves G-04 from 6.75 to roughly 26, and Governance from 59 to 77.
2. **Run an app registration amnesty.** Use `KQL/workload-identity-review.kql` to separate the 63 stale-credential registrations into active (rotate) and dormant (delete). Expect most to be dormant.
3. **Build the ownership matrix first, not last.** Meridian's Governance gap exists because no one owns cross-subsidiary identity hygiene. Assigning that ownership is a prerequisite for steps 1 and 2, not a follow-up to them.
4. **Use the compliance angle.** SOC 2 CC6.1 and CC6.3 both speak to restricting privileged access. 391 permanent assignments is an audit finding waiting to be written. That is usually the argument that unlocks subsidiary cooperation when a security argument has not.

Completing steps 1 and 2 moves Governance to roughly 81 and the overall score to roughly 90 — Resilient — with no additional licensing. That figure still assumes Ownership scores well, which is precisely what step 3 exists to establish. Do not report Meridian as Resilient until it does.
