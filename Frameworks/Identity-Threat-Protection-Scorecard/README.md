# Identity Threat Protection Scorecard

> **Status:** 🟡 Preview — `itps-v0.1.0-preview`

Measures an M365 tenant's identity threat protection across 4 dimensions — Prevention, Detection, Governance, and Ownership — each scored 0 to 100 and weighted equally. The 4 dimension scores average into an overall score, which maps to a maturity tier: Connected, Protected, Fortified, or Resilient.

The scoring methodology is usable as a standalone assessment instrument. A read-only Microsoft Graph collector automates the signals Microsoft exposes programmatically, and flags the two it does not — the Defender Coverage and maturity composite score, and Ownership in full — as manual checks with portal navigation rather than skipping or zeroing them.

**Companion reading:** this framework is the GitHub companion to The Security Bridge™ Series: Identity Threat Protection in Microsoft 365.

- Part 1 — [Identity threat protection starts after authentication](https://www.cloudharborconsulting.cloud/post/identity-threat-protection-starts-after)
- Part 2 — `[PART 2 BLOG URL — confirm with Derek]`
- Part 3 — [Conditional Access is a gate, not a guard](https://www.cloudharborconsulting.cloud/post/the-security-bridge-identity-threat-protection-in-microsoft-365-part-3-conditional-access-is-a)
- Part 4 — `[PART 4 BLOG URL — confirm with Derek]`
- Part 5 — `[PART 5 BLOG URL — not yet published]`

---

## Assessment structure

| Dimension | Choice | Authority |
|---|---|---|
| Assessment domains | 4 dimensions: Prevention, Detection, Governance, Ownership | Cloud Harbor Consulting, informed by The Security Bridge™ Series |
| Maturity tiers | Connected, Protected, Fortified, Resilient | [Microsoft Defender identity coverage and maturity (Preview)](https://learn.microsoft.com/en-us/defender-xdr/identity-security/coverage-maturity) |
| Tier thresholds | 0–39, 40–64, 65–84, 85–100 | **Cloud Harbor Consulting scoring convention — not a Microsoft-published spec** |
| Dimension weighting | Equal, 25% each | Reasoned in `Design/SCORING-METHODOLOGY.md` |

Dimension score = earned points over available points across scored checks, normalised to 0–100. Overall score = mean of the scored dimension scores. Manual checks are excluded from the denominator rather than counted as zero, so a partial assessment produces an honest partial score.

**A required disclosure.** Microsoft uses the tier names above on its Coverage and maturity page and does not publish the numeric thresholds behind them. The bands in this framework are Cloud Harbor Consulting's own convention, and an ITPS tier will not necessarily match the tier shown in the Defender portal. The two scores measure different things. See `Design/SCORING-METHODOLOGY.md` for the full disclosure.

---

## Framework contents

| Artifact | Description |
|---|---|
| `Design/SCORING-METHODOLOGY.md` | The full rubric. One section per dimension with the observable signal behind each check, a point breakdown, the tier-threshold disclosure, and the equal-weighting rationale. Usable without the scripts. |
| `Design/IDENTITY-ATTACK-PATHS.md` | The threat model: 5 attack paths through M365 after authentication succeeds, and which dimension intervenes on each. Ties to blog Parts 1 and 2. |
| `Design/PREVENTION-VS-DETECTION.md` | Where Conditional Access's job ends and detection's begins, and why 2 checks cannot be automated. Ties to blog Part 3. |
| `Scripts/Get-ITPScorecard.ps1` | Read-only Microsoft Graph collector. 6 read-only scopes, no write permissions. Returns a structured `ITPSResult` object with per-dimension scores and manual-review flags. |
| `Scripts/Format-ITPScorecardReport.ps1` | Accepts the collector output or its JSON export and generates 3 Markdown reports: technical detail, executive summary, and board 1-pager. |
| `Scripts/README.md` | Prerequisites, Graph scope table, authentication setup, parameter reference, output object shape, manual review guidance, and scoring logic. |
| `KQL/identity-coverage-validation.kql` | Hunts for successful sign-ins that no Conditional Access policy applied to. Validates Prevention assumptions against telemetry. |
| `KQL/privileged-activity-review.kql` | Directory role assignment and PIM activation activity. Complements EIG-AR002. |
| `KQL/risky-signin-hunting.kql` | Risky sign-ins that succeeded — the signal that a risk policy is missing or still report-only. |
| `KQL/workload-identity-review.kql` | Service principal sign-in patterns. Pairs with Governance check G-05. |
| `Examples/Small-Business-Scenario.md` | Northwind Bakery Group, 45 users, Business Premium. Scores 36 — Connected. Shows a licensing-capped tenant. |
| `Examples/Mid-Market-Scenario.md` | Silverline Logistics, 850 users, E3 plus P2 add-on. Scores 62 — Protected. Shows a tenant whose controls are configured and not enforced. |
| `Examples/Enterprise-Scenario.md` | Meridian Financial Holdings, 14,000 users, E5. Scores 82 — Fortified. Shows strong central controls and weak cross-organisational governance. |
| `Examples/Sample-Tenant-Scorecard.md` | All 3 output shapes for a single fictional tenant, reproduced verbatim from the formatter. |
| `Examples/Ownership-Matrix-Template.md` | Blank ownership matrix. The instrument the Ownership dimension is scored against. |
| `Business-Case/ROI-IDENTITY-SCORECARD.md` | Why measurement is what turns a security ask into a funded line item, with breach cost benchmarks and a compliance alignment table. |

---

## Required Graph scopes

The collector uses read-only scopes only.

| Scope | Dimension | Signal |
|---|---|---|
| `SecurityEvents.Read.All` | Prevention | `GET /security/secureScores` — Secure Score and Identity-category controls |
| `Policy.Read.All` | Prevention | `GET /identity/conditionalAccess/policies` |
| `SecurityIdentitiesHealth.Read.All` | Detection | `GET /security/identities/healthIssues` — Defender for Identity deployment health |
| `AccessReview.Read.All` | Governance | `GET /identityGovernance/accessReviews/definitions` |
| `RoleManagement.Read.Directory` | Governance | PIM eligible and active role assignment schedule instances |
| `Application.Read.All` | Governance | `GET /applications` — workload identity credential expiry |

---

## Prerequisites

- PowerShell 7+
- `Microsoft.Graph.Authentication` module
- An Entra ID account with the scopes above granted (delegated) or an app registration with those scopes (application)
- Microsoft 365 tenant with Entra ID P1 minimum. Entra ID P2 is required for the Governance dimension (Access Reviews, PIM) and for Identity Protection risk policies in Prevention
- Microsoft Defender for Identity for the Detection dimension. Without it, Detection returns no score rather than a zero

---

## How to use this framework

**Option A — Manual assessment against the methodology (no scripts required)**

1. Open `Design/SCORING-METHODOLOGY.md`.
2. Work through each dimension. For each check, determine whether your tenant meets it and record the points earned.
3. Compute each dimension score as earned points over available points, normalised to 0–100.
4. Average the dimension scores and map the result to a tier using the threshold bands.
5. Use `Examples/Ownership-Matrix-Template.md` to score the Ownership dimension.

**Option B — Automated assessment**

```powershell
# Step 1 — Collect tenant signals
.\Scripts\Get-ITPScorecard.ps1 -TenantId <your-tenant-id> -ExportJson -OutputPath .\Results\

# Step 2 — Generate all three output reports
.\Scripts\Format-ITPScorecardReport.ps1 -InputPath .\Results\<result-file>.json -OutputPath .\Reports\
```

Both scripts require prior authentication via `Connect-MgGraph` with the scopes listed above. See `Scripts/README.md` for the full walkthrough.

**An automated run is always a partial assessment.** Ownership has no tenant API and is manual in full, and the Defender Coverage and maturity composite has no API either. The collector labels the result partial and the formatter carries the label into all 3 reports. Treat a partial score as an upper bound.

---

## Repo cross-references

Checks in the scoring methodology cross-reference deployed artifacts from this repo where those artifacts serve as evidence.

| Check | Repo artifact |
|---|---|
| P-02 MFA enforced for all users | `Frameworks/Conditional-Access-Baseline/Policies/CA-COV001-009-*` |
| P-03 Legacy authentication blocked | `Frameworks/Conditional-Access-Baseline/Policies/CA-SIG001-*` |
| P-04 Risk-based policy present | `Frameworks/Conditional-Access-Baseline/Policies/CA-SIG003, CA-SIG004, CA-SIG008, CA-SIG009` |
| P-05 Privileged roles targeted | `Frameworks/Conditional-Access-Baseline/Policies/CA-AUT001-003-*` |
| G-01, G-02 Access reviews | `Frameworks/Entra-ID-Governance-Toolkit/` (EIG-AR001) |
| G-03, G-04 PIM and standing privilege | `Frameworks/Entra-ID-Governance-Toolkit/` (EIG-AR002) |

Note that the Conditional Access Baseline ships its risk policies in report-only mode. The Prevention checks require enforced state, so deploying the baseline is necessary but not sufficient to earn those points.

---

## Related frameworks

- [Conditional Access Baseline v1.4.0](../Conditional-Access-Baseline/) — 28 CA policies across 8 personas; deployed and enforced controls satisfy most Prevention checks.
- [Entra ID Governance Toolkit v0.1.0-preview](../Entra-ID-Governance-Toolkit/) — Access review automations satisfying Governance checks G-01 and G-02, plus the Entra ID P2 business case the Governance dimension depends on.
- [Zero Trust Readiness Assessment ztra-v0.1.0-preview](../Zero-Trust-Readiness-Assessment/) — 6-pillar posture assessment across the full Zero Trust surface. ITPS goes deeper on identity; ZTRA covers breadth.
- [Security Reporting Decision Rubric](../Security-Reporting-Decision-Rubric/) — audience-scoped reporting guidance. The ITPS formatter's 3 output shapes follow its severity floors and audience model.

---

## About

Maintained by **Derek Morgan**, Founder & Principal Consultant/Architect at [Cloud Harbor Consulting](https://cloudharborconsulting.cloud). Connect on [LinkedIn](https://www.linkedin.com/in/derek-morgan-ii-14370775/).
