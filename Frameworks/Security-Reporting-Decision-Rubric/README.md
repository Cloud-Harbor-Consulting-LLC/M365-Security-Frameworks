# Security Reporting Decision Rubric

**Status:** 🟢 Released — v1.0.0 (2026-08-14)  
**Maintainer:** Cloud Harbor Consulting  
**Pillar mapping:** Security ROI & Business Case (primary); Threat Detection & Response (secondary)

## What this is

A short, opinionated rubric for deciding what belongs in a security report, who reads it, and what decision it should drive. The rubric is built around one premise: a report that names no decision is overhead, not value.

Most security reports fail not because the data is wrong, but because the report has no owner of the decision. A 40-page export of every alert from the last 30 days does not help a CISO approve next quarter's spend, and it does not help an analyst contain an active incident. Different audiences need different cuts of the same telemetry, scoped to the decision they are actually accountable for.

## Who this is for

- **Security architects** designing reporting layers for Microsoft Defender XDR, Microsoft Sentinel, and Microsoft Security Copilot
- **SOC leads** rebuilding cadence after consolidating onto Microsoft unified SecOps
- **CISOs** trying to replace alert volume metrics with outcome metrics that the board will actually use
- **MSSP architects** standardizing client reporting packages

## What is in this repo

### Core rubric

- `REPORTING-DECISION-RUBRIC.md` — the rubric itself: 4-question decision flow, audience by cadence by decision type matrix, severity floor guidance grounded in Defender XDR's severity model, recommended metrics by audience (including Agent ID risk detection metrics), and a 9-entry kill list of reports that name no decision.

### Example templates (6)

- `Examples/Board-Quarterly-Template.md` — one-page quarterly board readout.
- `Examples/CISO-Monthly-Template.md` — one-page CISO monthly review.
- `Examples/Board-Posture-Summary.md` — always-current 1-page M365 security posture summary for boards. Uses CISA ZTMM v2.0 stage ratings. Update on whatever cadence the board requests a posture view.
- `Examples/Exec-Committee-Quarterly.md` — executive committee quarterly review. Investment-approval and risk-acceptance decisions. Sits between the CISO Monthly and Board Quarterly.
- `Examples/SOC-Lead-Weekly.md` — SOC lead weekly report. MTTD/MTTR trend, Copilot investigation summary coverage, top 5 false-positive tuning candidates, exception backlog, and Agent ID risk detection metrics.
- `Examples/Audit-Attestation.md` — audit attestation template. Maps Defender XDR severity-tier metrics and Entra ID Access Review outputs to SOC 2 CC controls and ISO 27001:2022 controls.

### Integration guide

- `Design/SENTINEL-COPILOT-INTEGRATION.md` — how to build Sentinel workbooks for each audience, KQL query library (SOC lead / CISO / exec committee / board), and Security Copilot prompt patterns for auto-drafting executive narrative sections.

### Business case

- `Business-Case/ROI-REPORTING-RUBRIC.md` — executive business case. Cost of undifferentiated reporting, kill-list ROI, audience-scoped cadence value, adoption timeline, compliance alignment (SOC 2, ISO 27001:2022, NIST SP 800-53).

## How to use it

1. For each existing report in your environment, run it through the 4-question decision flow in REPORTING-DECISION-RUBRIC.md. If it fails any question, it is a kill candidate.
2. Use the audience matrix to pick the right cadence and severity floor for each surviving report.
3. Replace alert volume metrics with the outcome metrics listed for that audience.
4. Adopt the example templates as starting points. They are not finished products. Cut what does not apply to your environment.
5. Build Sentinel workbooks using the KQL queries in Design/SENTINEL-COPILOT-INTEGRATION.md to automate data retrieval.
6. Use the Security Copilot prompt patterns to automate executive narrative drafting.

## Companion content

This rubric pairs with the article "If Every Alert Is Important, None Are: Designing Security Reports That Drive Decisions" on the Cloud Harbor Consulting blog.

## License

MIT. Use it, fork it, cut it apart. Attribution appreciated, not required.
