# Business Case: Zero Trust Readiness Assessment

**Framework:** Zero Trust Readiness Assessment (ZTRA)  
**Version:** v0.1.0-preview  
**Author:** Cloud Harbor Consulting LLC  

---

## The core question

Before an organization commits budget to Zero Trust remediation, it needs to answer 3 questions:

1. Where is the organization today across each pillar?
2. Which gaps carry the most risk?
3. Which fixes deliver the most risk reduction per dollar spent?

A Zero Trust readiness assessment answers all 3. Without it, remediation spending is driven by
vendor recommendations, audit findings, or whoever has the loudest voice in the room, rather than
by actual posture data.

---

## What a breach costs

The IBM Cost of a Data Breach 2025 report studied 600 organizations that experienced a breach
between March 2024 and February 2025, across 17 industries and 16 countries and regions.

| Metric | IBM 2025 finding |
|---|---|
| Global average breach cost | $4.44M (down 9% from $4.88M in 2024, the first decrease in 5 years) |
| United States average breach cost | $10.22M (up 9% from $9.36M, an all-time high for any region) |
| Healthcare average breach cost | $7.42M (highest of any industry for the 12th consecutive year) |
| Average days to identify and contain | 241 days (181 to identify, 60 to contain), a 9-year low |
| Extensive use of security AI and automation | $1.9M lower cost and 80 fewer days per breach |
| Shadow AI involvement | $670K added cost per breach |

The direction of travel matters for US organizations. The global average fell in 2025, but the
United States average rose 9% to a record $10.22M, driven by higher regulatory fines and
increased detection and escalation costs. A US organization should plan against the US figure,
not the global one.

### Where breaches start

IBM 2025 ranks initial attack vectors by both frequency and cost:

- **Phishing is the most common initial attack vector, at 16% of breaches.** It overtook
  compromised credentials this year to take the top spot.
- Average cost by vector: malicious insider $4.92M, third-party and supply chain compromise
  $4.91M, phishing $4.80M, compromised credentials $4.67M, vulnerability exploitation $4.24M.
- 16% of breaches involved attackers using AI, most often for AI-generated phishing (37%) and
  deepfake impersonation (35%). IBM notes gen AI has cut the time to craft a convincing phishing
  email from 16 hours to 5 minutes.

The Verizon 2024 Data Breach Investigations Report, which analyzed 30,458 security incidents and
10,626 confirmed breaches, found that 68% of breaches involved a non-malicious human element,
meaning insider error or a person falling for social engineering.

Phishing and credential abuse are the attack paths that the Identities pillar controls in the
ZTRA rubric are designed to close.

---

## Why ZT maturity reduces breach cost

IBM's 2021 Cost of a Data Breach report is the most recent edition to publish a Zero
Trust-specific breakdown. In that edition, organizations with a mature Zero Trust strategy
averaged $3.28M per breach, compared with $5.04M for organizations that had not deployed Zero
Trust at all. That is a reduction of 35%.

Two caveats matter when using this figure:

1. It is 2021 data. IBM's 2022 report showed a smaller gap (Zero Trust deployed $4.15M versus
   $5.10M not deployed), and the 2023, 2024, and 2025 editions do not analyze Zero Trust at all.
   Cite the year explicitly whenever this figure is used.
2. It measures the cost of breaches that occurred. It does not measure how likely a breach is.
   IBM's study population is organizations that were breached, so the report cannot support any
   claim that Zero Trust reduces breach probability.

The mechanism behind the cost reduction is speed of detection and containment:

- **Stage 3–4 (Advanced / Optimal):** Automated detection and response. Risk-based CA policies
  block compromised sessions in real time. Device compliance enforcement prevents lateral
  movement from non-compliant endpoints. Data loss prevention blocks exfiltration before it
  completes.

- **Stage 1–2 (Traditional / Initial):** Detection is reactive. An attacker with valid
  credentials can move freely until someone files a helpdesk ticket or a scheduled log review
  catches anomalous activity.

IBM 2025 quantifies what that speed is worth in current data: organizations using security AI and
automation extensively across prevention, detection, investigation, and response shortened their
breach lifecycle by 80 days and lowered their average breach cost by $1.9M. The global lifecycle
average is 241 days.

The ZT controls that most directly affect detection speed are sign-in risk CA, device compliance
enforcement, and endpoint telemetry (EDR). These map to the Identities and Endpoints pillars in
the ZTRA rubric.

---

## The cost of remediating without a baseline

Organizations that skip an assessment and go straight to remediation make 2 predictable mistakes:

**Mistake 1 — Fixing the wrong things first.**
Without a scored baseline, remediation effort goes to the loudest requirement, usually the one an
auditor flagged or the one a vendor just sold. A Stage 1 tenant that buys a CASB license before
deploying a CA coverage set has spent $40–60 per user per year on a visibility tool while
phishing and credential abuse, the 2 most common initial access vectors in IBM's 2025 data,
remain wide open.

**Mistake 2 — No way to measure progress.**
Without a baseline, the CISO cannot demonstrate to the board that the security program is
improving. Anecdotal claims ("we're improving our ZT posture") do not hold up when the board asks
for metrics. An assessed baseline produces a scored number. The next assessment produces a new
number. The difference is the ROI of the remediation investment.

---

## Assessment ROI model

### What this model does and does not claim

This model estimates the change in **expected annual loss** from advancing Zero Trust maturity.
It is built on 2 inputs with very different pedigrees, and they are labeled accordingly:

- **Cost per breach** comes from IBM (2025 for current cost levels, 2021 for the Zero Trust
  reduction). This is measured data.
- **Annual breach probability** is an assumption the reader supplies. No figure in this document
  is a source for it. IBM's study population is organizations that were already breached, so it
  cannot estimate breach likelihood. Any model claiming Zero Trust reduces breach probability is
  misusing the data.

Accordingly, the model holds breach probability **constant** and lets maturity reduce **cost
only**. This is the conservative reading, and it is the one that survives scrutiny from a CFO who
opens the source report.

### Inputs

| Input | Value | Source |
|---|---|---|
| Cost per breach, low maturity (US) | $10.22M | IBM 2025, United States average |
| Cost per breach, low maturity (global) | $4.44M | IBM 2025, global average |
| Zero Trust cost reduction at mature stage | 35% | IBM 2021 ($3.28M vs $5.04M), applied as a relative reduction to current cost levels |
| Annual breach probability | 10% / 20% / 30% | **Reader-supplied assumption. Not an IBM figure.** |
| Assessment cost | $15,000–$40,000 consulting, or $0 self-service with this framework | CHC engagement pricing |

### Sensitivity: expected annual loss reduction

Using the US cost base of $10.22M, with a mature Zero Trust estimate of $6.64M (35% lower):

| Annual breach probability | Expected loss, low maturity | Expected loss, mature ZT | Annual reduction |
|---|---|---|---|
| 10% | $1.02M | $664K | **$358K** |
| 20% | $2.04M | $1.33M | **$715K** |
| 30% | $3.07M | $1.99M | **$1.07M** |

Using the global cost base of $4.44M, with a mature Zero Trust estimate of $2.89M:

| Annual breach probability | Expected loss, low maturity | Expected loss, mature ZT | Annual reduction |
|---|---|---|---|
| 10% | $444K | $289K | **$155K** |
| 20% | $888K | $577K | **$311K** |
| 30% | $1.33M | $866K | **$466K** |

These are directional estimates. The 35% reduction is a 2021 relative finding applied to 2025
cost levels, and the current averages include organizations at every maturity stage, so the low
maturity row is an approximation rather than a measured cohort cost. Substitute the
organization's own sector figure and probability assumption wherever better data exists.

### What the assessment itself is worth

The assessment does not produce the risk reduction in the tables above. Remediation does. An
assessment changes no configuration and blocks no attacker. Presenting a $25,000 assessment as if
it buys $715K per year invites the first informed question in the room and loses it.

The honest case is stronger:

> A readiness assessment costs 1–3% of a typical Zero Trust remediation program. It determines
> whether the other 97–99% is spent on the controls that actually close the organization's top
> attack paths. Its return is not risk reduction. It is avoiding the misallocation of the
> remediation budget.

On a $1M remediation program, a $25,000 assessment that redirects even 10% of the spend from
low-impact to high-impact controls has paid for itself 4 times over, before any breach is
avoided.

### What the assessment unlocks

A scored baseline enables 3 decisions that cannot be made well without it:

1. **Remediation prioritization** — which pillar gaps to close first, ranked by risk reduction
   per dollar spent.
2. **Budget justification** — a specific, numbered current state (e.g., Identities at Stage 2,
   Infrastructure at Stage 1) that anchors the budget request for remediation tools and services.
3. **Progress measurement** — a scored before-state against which the next assessment is compared.

---

## Compliance alignment

A Zero Trust readiness assessment provides evidence for several compliance frameworks:

| Compliance framework | Relevant ZTRA pillars | Control mapping |
|---|---|---|
| NIST SP 800-53 r5 | All 6 pillars | AC, IA, SC, SI, AU control families |
| SOC 2 Type II | Identities, Endpoints, Data | CC6 (Logical and Physical Access), CC7 (System Operations) |
| ISO 27001:2022 | Identities, Endpoints, Applications | A.5 (Organizational Controls), A.8 (Technological Controls) |
| HIPAA Security Rule | Identities, Data, Networks | 164.312 Technical Safeguards |
| PCI-DSS v4.0 | Identities, Endpoints, Networks | Requirements 7 (Access Control), 8 (Identity Management), 10 (Logging) |
| CMMC 2.0 Level 2 | All 6 pillars | AC, IA, SC, SI, AU practice families |
| CISA ZTMM v2.0 | All 6 pillars | Primary alignment framework for ZTRA scoring |

The ZTRA scoring rubric maps each control row to NIST SP 800-207 tenets (T1–T7), which are the
foundational principles behind most of the compliance frameworks above. An organization that has
completed a ZTRA assessment has a documented, per-control evidence trail that maps directly to
audit requirements.

---

## How ZTRA fits into a ZT improvement program

A readiness assessment is step 1 of a 4-step program:

| Step | Activity | ZTRA artifact |
|---|---|---|
| 1 | Assess current posture across all 6 pillars | `Design/SCORING-RUBRIC.md` + `Scripts/Get-ZTReadinessScore.ps1` |
| 2 | Identify gaps and prioritize remediation | `Scripts/Format-ZTReadinessReport.ps1` — technical and executive summary outputs |
| 3 | Present findings and secure budget | `Scripts/Format-ZTReadinessReport.ps1` — board 1-pager output |
| 4 | Execute remediation and reassess | Deploy CA Baseline, Intune Compliance Baseline, EIG Toolkit; reassess quarterly |

The ZTRA framework is designed to be used before deploying remediation tooling. It is not a
post-deployment verification tool. Running the assessment before committing to remediation
ensures that investment goes to the highest-risk gaps, rather than to the easiest gaps, the most
visible gaps, or the gaps a vendor happens to be selling against.

---

## Using this framework with clients

This framework is intended for independent consultants and in-house security teams. CHC uses ZTRA
in a standard assessment engagement structured as follows:

1. **Scope confirmation** (0.5 days): confirm tenant access, Graph scope grant, and output
   format preferences with the client stakeholder.
2. **Automated data collection** (2–4 hours): run `Get-ZTReadinessScore.ps1` against the tenant.
   Collect manual review portal evidence for the 27 controls outside the collector's read-only
   Graph scope.
3. **Report generation** (1 day): run `Format-ZTReadinessReport.ps1` to generate the 3 output
   shapes. Review and customize the board 1-pager for the client's sector and language.
4. **Findings presentation** (2–4 hours): present executive summary to CISO; present board
   1-pager to executive sponsor or board liaison.
5. **Remediation roadmap** (optional 1–2 days): produce a prioritized 90-day remediation plan
   tied to the stage gaps identified in the assessment.

Total engagement: 3–5 days of consulting time. The ZTRA framework delivers the core deliverables;
the consultant adds client context, sector-specific risk framing, and remediation sequencing.

---

## Related frameworks

- [Conditional Access Baseline v1.4.0](../../Conditional-Access-Baseline/) — 28 CA policies
  that, when deployed, advance the Identities pillar from Stage 1–2 to Stage 3 for most
  ZTRA controls (ID-01, ID-02, ID-03, ID-04, ID-05, NW-03).
- [Entra ID Governance Toolkit v0.1.0-preview](../../Entra-ID-Governance-Toolkit/) — Access
  review automations that satisfy ID-07 (guest lifecycle governance) and contribute to
  ID-06 (PIM access reviews).
- [Intune Compliance Baseline](../../Intune-Compliance-Baseline/) — Device compliance policies
  that, when linked to CA, satisfy EP-03 (CA enforcement of device compliance).

---

## Sources

- IBM Cost of a Data Breach Report 2025 — current cost benchmarks, breach lifecycle, initial
  attack vectors, and security AI and automation impact. Contains no Zero Trust analysis.
- IBM Cost of a Data Breach Report 2021 — the most recent edition to publish a Zero
  Trust-specific breakdown ($3.28M mature Zero Trust versus $5.04M not deployed).
- Verizon Data Breach Investigations Report 2024 — human element in breaches.
- CISA Zero Trust Maturity Model v2.0 — the maturity scale used by the ZTRA scoring rubric.
- NIST SP 800-207 — the Zero Trust tenets (T1–T7) cited per control row in the rubric.

---

*Maintained by Cloud Harbor Consulting LLC — [cloudharborconsulting.cloud](https://cloudharborconsulting.cloud)*  
*ZTRA v0.1.0-preview | Framework: CISA ZTMM v2.0 | Methodology: NIST SP 800-207*
