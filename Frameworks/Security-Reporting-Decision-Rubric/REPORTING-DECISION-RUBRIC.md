# Reporting Decision Rubric

A report that names no decision is overhead. This rubric exists to keep that from happening.

## The 4 question decision flow

For every report you produce, answer these in order. If you cannot answer any of them in 1 sentence, the report is a kill candidate.

1. **Who reads it?** Name the role, not the team. A board reader is not a CISO is not a SOC lead is not an analyst.
2. **What decision does the reader make from it?** Approve a budget line. Authorize an exception. Open or close an incident. Tune a detection. If the answer is "be aware," kill the report.
3. **What cadence matches that decision?** Real time for analyst queues. Daily for SOC operations. Weekly for SOC leadership. Monthly for CISO and security leadership. Quarterly for the board.
4. **What severity floor does this audience need?** Higher in the org chart means a higher floor. The board does not need to see Low severity alerts. The SOC analyst does not need a quarterly view.

If the report passes all 4 questions, it stays. If it fails any of them, it goes on the kill list.

## Audience by cadence by decision type matrix

| Audience | Cadence | Decision type | Severity floor | Length |
|---|---|---|---|---|
| SOC analyst | Real time | Triage and contain | Informational and above | Live queue, no static report |
| SOC lead | Daily | Reassign work, escalate trends | Medium and above | 1 page |
| SOC lead | Weekly | Tune detections, justify staffing | Low and above (trend only) | 2 to 3 pages |
| CISO | Monthly | Adjust controls, approve exceptions, brief execs | High and above (Medium as trend) | 1 page |
| Executive committee | Quarterly | Approve investment, accept risk | High only (material incidents) | 1 page |
| Board | Quarterly or biannual | Approve strategy, accept residual risk | Material incidents only | Half page to 1 page |

## Severity floor guidance

Microsoft Defender XDR classifies alerts as Informational, Low, Medium, or High, driven by what kind of activity triggered the alert and how confident Microsoft is that the alert is real. High severity covers confirmed malware, ransomware, or a successful exploit. Medium covers suspicious activity that needs analyst review. Low covers minor or informational events, blocked attacks, and routine admin actions. Source: Microsoft Learn, Investigate alerts in Microsoft Defender XDR.

Practical floor rules:

- Anything below Medium should not appear in a CISO monthly except as a trend line.
- Anything below High should not appear in a quarterly board readout. Material incidents only.
- Informational severity belongs in the analyst queue and in detection tuning reviews, nowhere else.
- Defender XDR ships with built in alert tuning rules that suppress common benign activity without affecting automated investigation and response. Turn those on before you build reports against the raw alert queue. Reporting against unfiltered Informational and Low severity will produce dashboards that no one trusts. Source: Microsoft Learn, Investigate alerts in Microsoft Defender XDR.

## Recommended metrics by audience

### SOC lead (weekly)

- Mean time to detect (MTTD) and mean time to respond (MTTR), 7 day and 30 day trend
- Percent of incidents auto triaged by Microsoft Security Copilot
- Percent of analyst hours on incidents versus false positives
- Top 5 detection rules by false positive rate (tuning candidates)
- Exception backlog count and age

### CISO (monthly)

- MTTD and MTTR trend, 90 day rolling
- Percent of incidents auto triaged
- Control coverage gaps (which Zero Trust pillars are not at target)
- Exception backlog count, age, and risk owners
- Top 3 material incidents with root cause and remediation status

### Executive committee and board (quarterly)

- Risk posture deltas since last reporting period
- Top 3 material incidents (1 sentence each, plus business impact)
- Dwell time trend
- Investment to date versus risk reduction achieved
- One open ask of the board, if any

## The kill list

Reports that almost always fail the 4 question test:

- "All alerts in the last 30 days." Reader is unspecified. Decision is unspecified.
- "All sign in failures by user." Almost never tied to a decision a human will make at scale.
- "Endpoint compliance percentage" without a target. A number with no threshold is not a decision input.
- "Top users by data download volume" outside an active investigation. Without context, this is surveillance, not security.
- "Phishing emails blocked this month." Vanity metric. Reader cannot change it.
- "Total alerts triaged." Volume metric, not outcome metric. Replace with MTTD and MTTR.

## Versioning and updates

This rubric is intentionally short. Additions are welcome by pull request. Anything that adds a metric should also name the decision the metric drives and the audience that owns it. If it cannot pass the 4 question test, it does not go in.
