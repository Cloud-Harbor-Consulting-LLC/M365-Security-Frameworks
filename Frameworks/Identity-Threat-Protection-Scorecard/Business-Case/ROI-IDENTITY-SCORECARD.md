# Business Case: Identity Threat Protection Scorecard

**Framework:** Identity Threat Protection Scorecard (ITPS)
**Version:** v0.1.0-preview
**Author:** Cloud Harbor Consulting LLC

---

## The core argument

Identity security controls get funded when someone can measure them, and they decay when nobody does.

This is not a claim about security. It is a claim about how budget decisions are actually made, and the mechanism is worth stating precisely rather than asserting.

A security request without a measurement competes on credibility. "We should deploy phishing-resistant MFA for admins" is an opinion held by the person saying it, and it competes against every other opinion in the room on the basis of who is more persuasive. A finance function cannot evaluate it, cannot compare it to the request from the team next door, and cannot tell afterwards whether the money worked.

A security request with a measurement competes on evidence. "Our Prevention dimension scores 54 of 100, and the 3 unmet checks are all one policy-state change away" is a claim with a number attached, a defined method behind the number, and a specific delta the spend is expected to produce. That request can be evaluated, compared, sequenced against other requests, and audited afterwards.

The scorecard does not make the tenant more secure. It makes the argument for making the tenant more secure legible to the people who control the budget. That is a narrower claim than most security frameworks make, and it is the one this framework can actually support.

---

## What the measurement changes

Three decisions become possible that were not possible before, and each maps to a specific failure this framework has observed:

**Sequencing.** Without a score, remediation follows whichever gap was raised most recently or most loudly. With a per-dimension score, it follows the largest gap. The Enterprise scenario in `Examples/` is the archetype: excellent Prevention and Detection, Governance at 59, and an instinct to keep investing in the dimensions that were already strong because those were the ones the central team could act on alone.

**Justification.** A dimension score converts "we need Entra ID P2" into "Governance is capped at 20 because 4 of 5 checks require capabilities our current SKU does not include." The second version survives the follow-up question.

**Proof of return.** A score taken before remediation and again after produces a delta. Without a before-measurement, the security team's claim of improvement is unfalsifiable, which is a poor position from which to request the next budget cycle.

---

## What a breach costs

The figures below are reproduced from `Frameworks/Zero-Trust-Readiness-Assessment/Business-Case/ROI-ZT-READINESS.md`, which verified them against the primary sources. They are not re-sourced here, and no new statistics are introduced.

| Metric | IBM 2025 finding |
|---|---|
| Global average breach cost | $4.44M (down 9% from $4.88M in 2024, the first decrease in 5 years) |
| United States average breach cost | $10.22M (up 9% from $9.36M, an all-time high for any region) |
| Average days to identify and contain | 241 days (181 to identify, 60 to contain), a 9-year low |
| Extensive use of security AI and automation | $1.9M lower cost and 80 fewer days per breach |
| Most common initial attack vector | Phishing, at 16% of breaches, having overtaken compromised credentials |

Source: IBM Cost of a Data Breach Report 2025, which studied 600 organizations breached between March 2024 and February 2025.

**Phishing is the most common initial attack vector, and compromised credentials are second.** Both are identity attacks. That is the entire argument for measuring identity protection specifically rather than folding it into a general security posture score: the top two entry points in the current data are both defended by the controls in this scorecard's Prevention and Detection dimensions.

### The Zero Trust comparison, with its caveat

IBM's 2021 report is the most recent edition to publish a Zero Trust-specific breakdown: organizations with a mature Zero Trust strategy averaged $3.28M per breach against $5.04M for organizations that had not deployed it, a 35% reduction.

That figure is 5 years old. IBM's 2022 report showed a smaller gap, and the 2023, 2024, and 2025 editions contain no Zero Trust analysis at all. Cite the year whenever the figure is used, and do not present it as current-year data.

---

## What this ROI model does and does not claim

**It does not claim that ITPS reduces breach probability.** IBM's study population is organizations that were already breached. The report measures the cost of breaches that occurred; it has no denominator of non-breached organizations and therefore cannot speak to likelihood. Any model that multiplies an IBM cost figure by a breach probability and attributes the probability to IBM is misusing the data.

**It does not claim that the assessment itself reduces risk.** An assessment changes no configuration and blocks no attacker. Presenting a scorecard as risk reduction invites the first informed question in the room and loses it.

**What it does claim** is narrower and defensible: the assessment determines where remediation spend goes, and misallocated remediation spend is the largest avoidable cost in an identity security programme.

### The honest framing

> An identity assessment costs a fraction of the remediation programme it informs. Its return is not risk reduction. It is avoiding the misallocation of the remediation budget, and providing the before-measurement that makes the next budget request evidence-based rather than anecdotal.

The scenarios in `Examples/` make this concrete. Silverline Logistics had already paid for a complete Conditional Access design and left it in report-only for 8 months. The remediation spend was already made; what was missing was the measurement that would have shown it was not delivering. No additional licensing would have fixed that. A scorecard would have.

---

## Compliance alignment

The 4 dimensions produce evidence for several frameworks. The table below is scoped to what the dimensions actually support, rather than to every control a framework contains.

| Framework | Dimensions that produce evidence | Control mapping |
|---|---|---|
| NIST SP 800-53 Rev 5 | Prevention, Governance, Detection | AC-2 (account management), AC-6 (least privilege), AU-2 (event logging), IA-4 (identifier management), RA-3 (risk assessment) |
| SOC 2 Trust Services Criteria | Prevention, Governance | CC6.1 (logical access controls), CC6.3 (access restricted by role) |
| ISO 27001:2022 | Prevention, Governance, Detection | A.5.15 (access control), A.5.18 (access rights), A.8.16 (monitoring activities) |
| HIPAA Security Rule | Prevention, Governance | 164.312(a) access control, 164.312(d) person or entity authentication |
| PCI-DSS v4.0 | Prevention, Governance | Requirement 7 (access control), Requirement 8 (identity management) |
| CMMC 2.0 Level 2 | Prevention, Governance, Detection | AC, IA, and AU practice families |

Two limits on this table are worth stating.

**The Ownership dimension maps to no framework control.** Every framework above assumes controls have owners and none of them scores whether that assumption holds. Ownership is in this scorecard precisely because it is the gap that compliance frameworks leave open.

**A scorecard is evidence, not an attestation.** These mappings help assemble an audit package. They do not constitute one. `Frameworks/Security-Reporting-Decision-Rubric/Examples/Audit-Attestation.md` is the artifact for that.

---

## Where the scorecard fits

| Step | Activity | ITPS artifact |
|---|---|---|
| 1 | Establish the baseline across all 4 dimensions | `Design/SCORING-METHODOLOGY.md` + `Scripts/Get-ITPScorecard.ps1` |
| 2 | Identify and sequence the gaps | `Scripts/Format-ITPScorecardReport.ps1` — technical and executive summary |
| 3 | Present findings and request budget | `Scripts/Format-ITPScorecardReport.ps1` — board 1-pager |
| 4 | Assign accountability | `Examples/Ownership-Matrix-Template.md` |
| 5 | Remediate and reassess | Deploy the CA Baseline and EIG Toolkit; reassess on the cadence in the ownership matrix |

Step 4 is deliberately placed before step 5. The Ownership dimension exists because remediation without an owner reverts, and a scorecard that measures the reversion after the fact is less useful than one that prevents it.

---

## Related frameworks

- [Conditional Access Baseline](../../Conditional-Access-Baseline/) — the policy set that satisfies most Prevention checks. Note that its risk policies ship report-only; ITPS Prevention checks require enforced state, so deploying the baseline is necessary but not sufficient.
- [Entra ID Governance Toolkit](../../Entra-ID-Governance-Toolkit/) — the access review automations behind Governance checks G-01 and G-02, and the business case for the Entra ID P2 license that the Governance dimension depends on.
- [Zero Trust Readiness Assessment](../../Zero-Trust-Readiness-Assessment/) — the broader 6-pillar posture assessment. ITPS goes deeper on identity specifically; ZTRA covers the other 5 pillars. Run ZTRA for breadth and ITPS for identity depth.

---

## Sources

- IBM Cost of a Data Breach Report 2025 — current cost benchmarks, breach lifecycle, and initial attack vectors. Figures reproduced from the verified citation in `ROI-ZT-READINESS.md`.
- IBM Cost of a Data Breach Report 2021 — the most recent edition to publish a Zero Trust-specific breakdown.
- [Microsoft Learn — View your identity coverage and maturity (Preview)](https://learn.microsoft.com/en-us/defender-xdr/identity-security/coverage-maturity) — maturity tier definitions.

---

*Maintained by Cloud Harbor Consulting LLC — [cloudharborconsulting.cloud](https://cloudharborconsulting.cloud)*
*ITPS v0.1.0-preview*
