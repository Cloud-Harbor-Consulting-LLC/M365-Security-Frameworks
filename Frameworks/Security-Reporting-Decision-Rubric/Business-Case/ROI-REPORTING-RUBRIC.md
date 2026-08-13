# Security Reporting Decision Rubric — Business Case

A plain-language business case for security architects, CISO teams, and IT leaders defending the investment in audience-scoped security reporting to executive stakeholders or a board.

## Executive summary

Most security reporting fails not because the data is wrong, but because the wrong data goes to the wrong person at the wrong cadence. A board member receiving the same 40-page alert export as an analyst cannot make a strategy decision from it. An analyst receiving a quarterly dwell-time summary cannot triage an active incident from it. The rubric fixes the architecture of the reporting layer, not the underlying data.

The return on the rubric is primarily measured in 3 ways: analyst time recovered from producing and receiving reports that drive no decisions, decision latency reduced because stakeholders get the right cut of data at the right frequency, and audit evidence quality improved because example templates produce consistent, audit-ready output by design.

The cost to adopt is the time to run existing reports through the 4-question decision flow and retire the ones that fail. For most organizations, that audit takes 1 to 2 hours per report owner per quarter.

## The cost of undifferentiated reporting

An undifferentiated reporting layer — one where the same data goes to every audience — creates 4 predictable failure modes.

**Analyst time on reports that drive no decisions.** Producing a report that fails question 2 of the 4-question test (What decision does the reader make from it?) takes the same analyst time as producing a report that drives a real decision. The cost is not the data — it is the preparation, formatting, distribution, and follow-up time for a report that no one acts on.

Estimate the internal cost using this formula:

```
(Reports produced per month that fail the 4-question test)
× (Average hours per report: preparation + distribution + follow-up)
× (Analyst hourly fully-loaded cost)
= Monthly cost of reports that drive no decisions
```

Insert the organization's figures. A typical security team discovers 3 to 8 kill-list-eligible reports per audit.

**Decision latency from audience mismatch.** A CISO who receives a raw alert volume report instead of a top-3-incident narrative has to translate the data before making a decision. That translation takes time, introduces interpretation risk, and delays approval of the spend or exception the decision would have authorized.

**Board disengagement.** A board that consistently receives data-dense reports without a clear ask of the board will disengage from the security agenda. Boards approve strategy and accept risk. A report that asks them to "be aware" of the alert count is not a governance artifact — it is overhead.

**Audit evidence gaps.** Ad-hoc reporting produces inconsistent evidence packets. The Audit-Attestation template (Examples/Audit-Attestation.md) produces consistent, auditor-readable output aligned to SOC 2 CC controls and ISO 27001:2022 controls by design. A team that adopts the template spends less time translating security telemetry into compliance language at audit time.

## The value of the rubric

**Kill-list discipline — recovered analyst time.** The rubric's kill list names 9 report types that consistently fail the 4-question test. Retiring each one recovers the time that was spent producing it. For a report that takes 2 hours to prepare and distribute monthly, retiring it recovers 24 hours per year per analyst.

Run the 4-question test on every current report. Any report that cannot answer all 4 questions in 1 sentence each is a kill candidate. Document the decision in the report inventory.

**Audience-scoped cadence — reduced decision latency.** The rubric's audience-by-cadence matrix assigns each audience the cut of data that matches the decision they are accountable for:

| Audience | Cadence | Decision type |
|---|---|---|
| SOC analyst | Real time | Triage and contain |
| SOC lead | Daily / weekly | Reassign work, tune detections |
| CISO | Monthly | Adjust controls, approve exceptions |
| Executive committee | Quarterly | Approve investment, accept risk |
| Board | Quarterly or biannual | Approve strategy, accept residual risk |

Delivering data at the right cadence removes the translation step. The CISO gets a top-3-incidents narrative, not an alert volume export. The board gets a posture summary with a single ask, not a 15-slide deck.

**Example templates — consistent, audit-ready output.** The 6 example templates in `Examples/` produce structurally consistent output. An auditor who reviews a SOC 2 evidence package built on the Audit-Attestation template can read the evidence without a briefer. The same template used across 4 quarters produces a comparable time series. Custom ad-hoc reports rarely achieve either.

**Sentinel and Security Copilot integration — automation of report production.** The KQL query library in `Design/SENTINEL-COPILOT-INTEGRATION.md` automates the data retrieval for each audience. The Security Copilot prompt patterns automate the narrative drafting for executive sections. An operator who builds the Sentinel workbooks and configures the Copilot prompts removes the manual data-pull step from the weekly and monthly reporting cycle.

## Adoption cost and timeline

| Activity | Estimated time | Owner |
|---|---|---|
| Run 4-question test on all current reports | 1 to 2 hours per report owner | SOC lead + CISO |
| Retire kill-list-eligible reports | 30 minutes per report (stakeholder notification, archive) | SOC lead |
| Adopt example templates | 2 to 4 hours per template (customize to environment) | Security analyst |
| Build Sentinel workbooks | 4 to 8 hours per audience workbook | SOC lead or Sentinel engineer |
| Configure Security Copilot prompts | 1 to 2 hours per audience | SOC lead |

Total one-time adoption cost for a team adopting all 6 templates and 4 workbooks: approximately 40 to 80 hours depending on environment complexity.

## Compliance alignment

Adopting audience-scoped cadence and example templates supports the following compliance requirements directly:

| Standard | Control | How the rubric supports it |
|---|---|---|
| SOC 2 | CC7.2 | System components are monitored for anomalies indicative of malicious acts, and those anomalies are analyzed to determine whether they represent security events — detection and response metrics are reported on a defined cadence by audience |
| SOC 2 | CC7.4 | Incident response reporting with defined severity floor and decision-maker |
| ISO 27001:2022 | A.5.25 | Assessment and decision on information security events — audience-scoped cadence ensures the right decision-maker receives event information |
| ISO 27001:2022 | A.5.26 | Response to information security incidents — Audit-Attestation template produces auditor-readable incident response evidence |
| NIST SP 800-53 | IR-6 | Incident reporting — defined reporting cadence and escalation path per audience |

## Cross-references

- `Frameworks/Conditional-Access-Baseline/Business-Case/ROI-CONDITIONAL-ACCESS.md` — business case for the Conditional Access Baseline. The CISO Monthly and Board Quarterly templates are the reporting layer for the access-control risk reduction this baseline delivers.
- `Frameworks/Entra-ID-Governance-Toolkit/Business-Case/ROI-ENTRA-GOVERNANCE.md` — business case for the EIG Toolkit. The SOC Lead Weekly and Audit-Attestation templates produce the evidence the EIG Toolkit's Access Reviews generate.
