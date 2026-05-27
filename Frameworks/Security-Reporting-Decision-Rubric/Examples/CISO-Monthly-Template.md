# CISO Monthly Security Review

**Reporting period:** [Month YYYY]
**Prepared by:** [SOC lead name]
**Reading time:** under 10 minutes

## 1. Detection and response performance

| Metric | This month | Last month | 90 day trend |
|---|---|---|---|
| MTTD (median) | [X minutes] | [X minutes] | [up / down / flat] |
| MTTR (median) | [X hours] | [X hours] | [up / down / flat] |
| Percent of incidents auto triaged by Security Copilot | [X%] | [X%] | [up / down / flat] |
| Percent of analyst hours on confirmed incidents vs false positives | [X% / Y%] | [X% / Y%] | [up / down / flat] |

One sentence narrative. If MTTR is up, name the cause and what is changing next month.

## 2. Top 3 material incidents

1. **[Incident 1]** — what happened, business impact, current status, owner.
2. **[Incident 2]** — same fields.
3. **[Incident 3]** — same fields.

Material means High severity confirmed true positive that affected a critical asset, a regulated data set, or a customer facing system. Do not pad with Mediums.

## 3. Control coverage gaps

| Zero Trust pillar | Target state | Current state | Gap owner |
|---|---|---|---|
| Identity | [target] | [current] | [name] |
| Devices | [target] | [current] | [name] |
| Data | [target] | [current] | [name] |
| Apps | [target] | [current] | [name] |
| Infrastructure | [target] | [current] | [name] |
| Network | [target] | [current] | [name] |

One sentence per row only if the gap is widening.

## 4. Exception backlog

| Exception ID | Age | Risk owner | Renewal or remediation date |
|---|---|---|---|
| [ID] | [days] | [name] | [date] |

Show the oldest 10. If the list is empty, say so. If the list is growing, name the cause.

## 5. Decisions requested

Bullet list, 1 to 3 items. Each item names the decision and the deadline. If nothing needs CISO sign off this month, say "None."

---

## Format rules for this template

- 1 page front and back maximum.
- Medium severity and above. Low severity appears as a trend line only, not in incident detail.
- Every metric must tie to a decision a CISO can make this month. If it cannot, cut it.
- Replace alert volume language with outcome language. "Triaged 18,400 alerts" is volume. "Median MTTD held at 14 minutes; 62 percent of incidents auto triaged" is outcome.
