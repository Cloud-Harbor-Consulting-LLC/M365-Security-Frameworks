# Security Reporting Decision Rubric

**Status:** v0.1.0-preview (pending, not yet tagged)
**Maintainer:** Cloud Harbor Consulting
**Pillar mapping:** Security ROI & Business Case (primary); Threat Detection & Response (secondary)

## What this is

A short, opinionated rubric for deciding what belongs in a security report, who reads it, and what decision it should drive. The rubric is built around one premise: a report that names no decision is overhead, not value.

Most security reports fail not because the data is wrong, but because the report has no owner of the decision. A 40 page export of every alert from the last 30 days does not help a CISO approve next quarter's spend, and it does not help an analyst contain an active incident. Different audiences need different cuts of the same telemetry, scoped to the decision they are actually accountable for.

## Who this is for

- **Security architects** designing reporting layers for Microsoft Defender XDR, Microsoft Sentinel, and Microsoft Security Copilot
- **SOC leads** rebuilding cadence after consolidating onto Microsoft unified SecOps
- **CISOs** trying to replace alert volume metrics with outcome metrics that the board will actually use
- **MSSP architects** standardizing client reporting packages

## What is in this repo

- `REPORTING-DECISION-RUBRIC.md` — the rubric itself: 4 question decision flow, audience by cadence by decision type matrix, severity floor guidance, recommended metrics by audience, and a kill list of reports that name no decision.
- `Examples/Board-Quarterly-Template.md` — one page quarterly board readout.
- `Examples/CISO-Monthly-Template.md` — one page CISO monthly review.

## How to use it

1. For each existing report in your environment, run it through the 4 question decision flow in REPORTING-DECISION-RUBRIC.md. If it fails any question, the report is a kill candidate.
2. Use the audience matrix to pick the right cadence and severity floor for each surviving report.
3. Replace alert volume metrics with the outcome metrics listed for that audience.
4. Adopt the two example templates as starting points. They are not finished products. Cut what does not apply to your environment.

## Companion content

This rubric pairs with the article "If Every Alert Is Important, None Are: Designing Security Reports That Drive Decisions" on the Cloud Harbor Consulting blog.

## License

MIT. Use it, fork it, cut it apart. Attribution appreciated, not required.
