# SOC Lead Weekly Report

**Reporting period:** [Week of Mon DD – Fri DD, YYYY]
**Prepared by:** [SOC lead name]
**Reading time:** under 10 minutes

## 1. Detection and response performance

| Metric | This week | Last week | 30-day trend |
|---|---|---|---|
| MTTD — median (minutes) | [X] | [X] | [up / down / flat] |
| MTTD — 90th percentile (minutes) | [X] | [X] | [up / down / flat] |
| MTTR — median (hours) | [X] | [X] | [up / down / flat] |
| Incidents with Copilot investigation summary | [X%] | [X%] | [up / down / flat] |
| Analyst hours: confirmed incidents vs false positives | [X% / Y%] | [X% / Y%] | — |

One sentence narrative. If MTTD or MTTR is trending up, name the cause and what changes next week.

MTTD is measured as time from incident creation to first analyst action. MTTR is measured as time from incident creation to closure. Incidents with a Microsoft Security Copilot investigation summary are the proxy for auto-triage coverage; this is not the same as auto-resolved incidents.

## 2. False-positive tuning candidates

Top 5 detection rules by false-positive rate this week. A rule with a false-positive rate above 30 percent is a tuning candidate.

| Rule name | Alerts fired | Confirmed true positives | False-positive rate | Recommended action |
|---|---|---|---|---|
| [Rule 1] | [X] | [X] | [X%] | [Tune threshold / Suppress / Review logic] |
| [Rule 2] | [X] | [X] | [X%] | — |
| [Rule 3] | [X] | [X] | [X%] | — |
| [Rule 4] | [X] | [X] | [X%] | — |
| [Rule 5] | [X] | [X] | [X%] | — |

## 3. Exception backlog

| Exception ID | Age (days) | Risk owner | Renewal or remediation date |
|---|---|---|---|
| [ID] | [X] | [name] | [date] |

Show all open exceptions. If the backlog is growing, name the cause. An exception older than 90 days with no renewal or remediation date is overdue for a risk acceptance decision.

## 4. Agent ID risk detections

Complete this section only for tenants with Conditional Access for Agents deployed (CA-COV011).

| Metric | This week | Last week | 30-day trend |
|---|---|---|---|
| Agent ID risk detections (count) | [X] | [X] | [up / down / flat] |
| Mean time to detect — Agent ID risk (minutes) | [X] | [X] | [up / down / flat] |

Source: Microsoft Entra Identity Protection, Agent ID risk events. If CA-COV011 is not deployed, mark this section "Not applicable."

## 5. Actions required

Bullet list of items requiring SOC lead decision or escalation before next week's report. Maximum 5. Each item names the decision and who owns it.

- [Item 1] — owner: [name], deadline: [date]

If nothing requires action, state "None."

---

## Format rules for this template

- 2 to 3 pages maximum.
- Severity floor: Medium and above for incident counts; Low and above appears as a trend line only in section 1 (not in incident detail).
- Do not include alert volume metrics (total alerts fired, total phishing blocked). Replace with outcome metrics: MTTD, MTTR, FP rate, Copilot coverage.
- Section 4 is required only for tenants with CA-COV011 deployed. Mark it "Not applicable" otherwise rather than deleting it, so reviewers can confirm the assessment was made.
- Every row in section 5 must name a decision and an owner. Items without an owner are status updates, not action items.
