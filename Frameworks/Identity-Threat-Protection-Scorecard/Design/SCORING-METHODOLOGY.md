# ITPS Scoring Methodology

**Framework:** Identity Threat Protection Scorecard (ITPS)
**Version:** v0.1.0-preview
**Dimensions:** 4 — Prevention, Detection, Governance, Ownership
**Weighting:** Equal, 25% each
**Maturity tiers:** Connected, Protected, Fortified, Resilient

---

## How to score

1. Work through each dimension section below. Each dimension is scored 0 to 100.
2. Within a dimension, each check carries a point value. Add the points earned, divide by the points available from the checks you were able to assess, and multiply by 100.
3. Overall score = the average of the 4 dimension scores.
4. Map the overall score to a maturity tier using the threshold bands below.

Checks that cannot be assessed from Microsoft Graph are marked **Manual**. Score them by hand using the portal navigation given in the check, or leave them unassessed. The collector script excludes unassessed checks from the denominator rather than scoring them zero, so a partial assessment produces an honest partial score instead of an artificially depressed one.

---

## A required disclosure about the tier names

This framework reuses Microsoft's four identity maturity tier names — **Connected, Protected, Fortified, Resilient** — because the Defender portal's Coverage and maturity page uses them, and because a scorecard that invented parallel vocabulary for the same concept would create confusion rather than clarity.

**Microsoft does not publish the numeric thresholds behind its own tiers.** The Coverage and maturity documentation states that the maturity level is based on a score from 0 to 100 and that "as your score increases, your maturity tier progresses from Connected through Protected and Fortified to Resilient." It gives no cutoffs.

The threshold bands below are **Cloud Harbor Consulting's own scoring convention for this framework**. They are not Microsoft's cutoffs, they are not derived from Microsoft's cutoffs, and an ITPS tier will not necessarily match the tier shown on the Defender Coverage and maturity page. The two scores measure different things: Microsoft's measures identity source coverage; ITPS measures prevention, detection, governance, and ownership across the tenant.

Source for the tier definitions: [Microsoft Learn — View your identity coverage and maturity (Preview)](https://learn.microsoft.com/en-us/defender-xdr/identity-security/coverage-maturity).

### Threshold bands

| Overall score | ITPS tier | What this state looks like |
|---|---|---|
| 0–39 | Connected | Some identity telemetry exists and some controls are configured, but protection is partial and inconsistently applied. |
| 40–64 | Protected | Key identities and key controls are covered. Real gaps remain, usually in non-human identities or in who owns the controls. |
| 65–84 | Fortified | Broad coverage across human and non-human identities, with detection validated rather than assumed. |
| 85–100 | Resilient | Full coverage across identity types, with named ownership and a working feedback loop when a control degrades. |

### Why the bands are not even quartiles

Even quartiles (0–25, 26–50, 51–75, 76–100) would be simpler, and they would be wrong in two places.

At the bottom, the qualitative distance between a tenant scoring 10 and a tenant scoring 30 is small in outcome terms. Both have partial, inconsistent protection, and an attacker experiences them roughly the same way. Compressing that range into a single wider band (0–39) avoids implying a promotion that the tenant has not earned.

At the top, Microsoft defines Resilient as *full* coverage of all identity types in all environments. A tenant at 76 has roughly a quarter of its assessed controls unmet, which is not full coverage by any reading. Setting the Resilient floor at 85 keeps the top tier meaning what its name says.

The middle bands are sized to match the transitions that actually matter: crossing into Protected requires that the majority of assessed controls are met, and crossing into Fortified requires that non-human identities and detection validation are addressed, which is where most tenants stall.

---

## Why the dimensions are equally weighted

Each dimension carries 25%. This is a deliberate choice, not a default.

The four dimensions are not a hierarchy where one matters more than the others. They are sequential dependencies, and a gap in any one of them nullifies the value of the others:

- **Prevention without Detection** is a tenant that blocks what it anticipated and never learns about what it did not.
- **Detection without Ownership** is an alert queue that nobody is accountable for acting on. The signal exists and changes nothing.
- **Governance without Prevention** is a documented, recertified, well-reviewed set of access rights to a tenant that an attacker can authenticate into anyway.
- **Ownership without Governance** is a named owner with no defined cadence, which decays into an owner in name only.

Weighting one dimension above the others would imply the dimensions are tradeable — that a very strong Prevention score can compensate for absent Ownership. The failure modes above are the argument that it cannot. Equal weighting encodes that claim.

This is the same reasoning register as the Zero Trust Readiness Assessment's equal pillar weighting, which is anchored in CISA ZTMM v2.0's horizontal progress design. The conclusion is the same and the justification is dimension-specific rather than borrowed.

---

## Dimension 1 — Prevention (25%)

**What it measures.** Whether the tenant's identity controls stop a credential-based attack before a session is granted: Conditional Access coverage, privileged access management, and authentication strength.

**Automated.** Yes, fully.

### Signals

| Signal | Source | Graph scope |
|---|---|---|
| Identity Secure Score attainment | `GET /security/secureScores?$top=1`, `controlScores` filtered to `controlCategory` = `Identity` | `SecurityEvents.Read.All` |
| Conditional Access policy configuration | `GET /identity/conditionalAccess/policies` | `Policy.Read.All` |

### Scoring

| Check | Points | How it is assessed |
|---|---|---|
| P-01 Secure Score attainment | 0–50 | Tenant `currentScore / maxScore` as a percentage, multiplied by 0.5 |
| P-02 MFA enforced for all users | 10 | A Conditional Access policy in `enabled` state grants `mfa` or an `authenticationStrength` to a coverage set including all users |
| P-03 Legacy authentication blocked | 10 | A policy in `enabled` state targets `exchangeActiveSync` or `other` client app types with a `block` grant |
| P-04 Risk-based policy present | 10 | A policy in `enabled` state carries `signInRiskLevels` or `userRiskLevels` conditions |
| P-05 Privileged roles targeted | 10 | A policy in `enabled` state targets directory roles via `includeRoles` |
| P-06 Phishing-resistant strength in use | 10 | At least one policy in `enabled` state uses `authenticationStrength` rather than the built-in `mfa` control |

Maximum: 100.

**A limitation worth stating.** The v1.0 `secureScores` payload gives an achieved `score` per control and a tenant-wide `currentScore` and `maxScore`, but it does not expose a maximum per control category. There is therefore no documented way to compute an Identity-category percentage directly. P-01 uses the tenant-wide attainment percentage as the scored component, and the collector records the Identity-category control names and achieved points in the output object as supporting evidence. Do not report P-01 as an "Identity Secure Score percentage" — it is a tenant-wide percentage used as a proxy, and the scorecard says so.

**Repo cross-reference.** Deployed Conditional Access Baseline policies satisfy P-02 through P-06 directly: `CA-COV001`–`CA-COV009` (coverage set), `CA-SIG001` (legacy authentication block), `CA-SIG003`, `CA-SIG004`, `CA-SIG008`, `CA-SIG009` (risk policies), `CA-AUT001`–`CA-AUT003` (admin authentication). Note that the CA Baseline ships its risk policies in report-only mode; P-02 through P-06 require `enabled` state, so a tenant that has deployed the baseline but not promoted it scores zero on those checks. That is intentional. A report-only policy does not prevent anything.

---

## Dimension 2 — Detection (25%)

**What it measures.** Whether identity threat detection is deployed, healthy, and validated — not merely licensed.

**Automated.** Partially. The Defender for Identity health signal is available via Graph. The Coverage and maturity composite score is not.

### Signals

| Signal | Source | Graph scope |
|---|---|---|
| Defender for Identity deployment health | `GET /security/identities/healthIssues` | `SecurityIdentitiesHealth.Read.All` |
| Coverage and maturity composite score and tier | Defender portal only — no API | Manual |

### Scoring

| Check | Points | How it is assessed |
|---|---|---|
| D-01 No open high-severity health issues | 25 | Full points when `$filter=Status eq 'open' and severity eq 'high'` returns zero results |
| D-02 No open medium-severity health issues | 15 | Full points when the equivalent medium-severity filter returns zero results |
| D-03 Sensor health issues resolved | 10 | Full points when no open issue has `healthIssueType` = `sensor` |
| D-04 Health signal reachable at all | 10 | Full points when the endpoint returns successfully, which establishes that Defender for Identity is licensed and provisioned |
| D-05 Coverage and maturity composite | **Manual** | Read the composite score and tier from the Defender portal and record them alongside the ITPS score |

Maximum from automated checks: 60. D-05 is excluded from the denominator unless scored by hand.

**What the health signal actually means.** `healthIssues` reports Defender for Identity *deployment and sensor health*, not threat detections. A tenant with open sensor health issues has detection gaps it may not know about, which is precisely the failure this dimension is designed to surface: detection that is assumed to be working rather than validated. Do not read D-01 through D-04 as a count of threats detected.

**Manual navigation for D-05.** Microsoft Defender portal → **Identities** → **Coverage and maturity**. Requires a Defender for Cloud Apps or Defender for Identity license and at least the Security Reader role. The page is in Preview and is being rolled out gradually, so it may not be present in every tenant yet. See `PREVENTION-VS-DETECTION.md` for why this is not automatable.

---

## Dimension 3 — Governance (25%)

**What it measures.** Whether identities are reviewed, recertified, and lifecycle-managed over time, including non-human identities.

**Automated.** Yes, fully.

### Signals

| Signal | Source | Graph scope |
|---|---|---|
| Access review definitions | `GET /identityGovernance/accessReviews/definitions` | `AccessReview.Read.All` |
| Privileged role assignments, eligible vs permanent | `GET /roleManagement/directory/roleEligibilityScheduleInstances` and `GET /roleManagement/directory/roleAssignmentScheduleInstances` | `RoleManagement.Read.Directory` |
| Application credential hygiene | `GET /applications` | `Application.Read.All` |

### Scoring

| Check | Points | How it is assessed |
|---|---|---|
| G-01 Access reviews configured | 20 | At least one access review definition exists |
| G-02 Guest access reviewed | 15 | At least one review definition scopes guests |
| G-03 PIM eligible assignments in use | 20 | `roleEligibilityScheduleInstances` returns at least one result |
| G-04 Standing privilege minimised | 25 | Full points when zero permanent active assignments exist, scaled down as the permanent share rises |
| G-05 Workload identity credential hygiene | 20 | Full points when no application registration holds a client secret with no expiry or an expiry beyond 12 months |

Maximum: 100.

Permanent standing assignments are counted from `roleAssignmentScheduleInstances` where `assignmentType` is `Assigned` and `endDateTime` is null. An `Activated` assignment is a just-in-time activation of an eligible role and is not standing privilege.

**Repo cross-reference.** `EIG-AR001` (quarterly guest access review) satisfies G-01 and G-02 when deployed. `EIG-AR002` (dormant admin role review) contributes to G-03 and G-04.

---

## Dimension 4 — Ownership (25%)

**What it measures.** Accountability. When a control degrades, who is responsible for noticing and for fixing it, and is that responsibility written down and current.

**Automated.** No. Entirely manual.

There is no Microsoft Graph endpoint that returns who owns a control, because ownership is an organisational fact rather than a tenant configuration. This dimension is scored against `Examples/Ownership-Matrix-Template.md`.

### Scoring

| Check | Points | How it is assessed |
|---|---|---|
| O-01 Ownership matrix exists | 20 | A completed ownership matrix covers every control area in dimensions 1 through 3 |
| O-02 Named owner per control area | 20 | Every row names a specific role, not a team alias or a vacant position |
| O-03 Backup owner named | 15 | Every row names a backup owner |
| O-04 Review cadence defined | 15 | Every row states a cadence and the cadence is met |
| O-05 Last reviewed within cadence | 15 | Every row's last-reviewed date falls within its stated cadence |
| O-06 Escalation path defined | 15 | Every row states who is escalated to when the owner cannot resolve a degradation |

Maximum: 100.

All 6 checks are manual. The collector emits this dimension with a null score and `ManualReview = $true` so that an automated run cannot silently report an Ownership score the tenant has not earned.

**Why Ownership is a dimension rather than a footnote.** Every other dimension degrades silently. A Conditional Access policy can be scoped out, a sensor can go unhealthy, an access review can lapse — and none of those events announce themselves. Ownership is the control that catches the other controls failing. A tenant with excellent Prevention, Detection, and Governance and no Ownership is a tenant whose score was accurate on the day it was measured and is decaying from that day forward.

---

## Overall score and tier

Overall score = the mean of the 4 dimension scores, rounded to the nearest whole number.

When a dimension has no scored checks — most commonly Ownership on an automated-only run — the collector computes the mean of the dimensions that were scored and records which dimensions were excluded. An automated run therefore produces a Prevention, Detection, and Governance mean, clearly labelled as a partial score. Treat a partial score as an upper bound: Ownership gaps can only lower it.

Map the overall score to a tier using the threshold bands above, and remember the disclosure: those bands are this framework's convention, not Microsoft's.

---

*Identity Threat Protection Scorecard v0.1.0-preview — Cloud Harbor Consulting LLC*
