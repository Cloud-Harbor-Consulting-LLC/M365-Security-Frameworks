# Policy Translation Worksheet

**Control:** [Control name / ID]
**Source framework:** [Conditional Access Baseline / Intune Compliance Baseline / Purview DLP / other]
**Prepared by:** [Name]
**Date:** [YYYY-MM-DD]

One control per worksheet. If you are translating a set, run each one through separately and roll the results up afterward.

## 1. Technical form

Paste the control's technical summary as an engineer would state it: what it targets, what it enforces, and what state it is deployed in. This section is scratch space. Nothing from it reaches the executive reader.

> [Technical summary]

**Reference example — CA-COV002:**

> CA-COV002 (`AllUsers-RequireMFA`): all cloud apps, all users except emergency access and workload identity accounts, browser and mobile/desktop clients, grant control MFA, deployed report-only first.

## 2. The 3-line executive translation

Exactly three lines. Each one does a different job, and the third closes the loop the second opens.

**Line 1 — What the control does.** Plain language. No policy IDs, no product names, no JSON keys.

> [Line 1]

**Line 2 — What it prevents.** State the risk in the reader's terms, not the industry's. Not a CVE number, not a MITRE technique name, not a threat-actor alias.

> [Line 2]

**Line 3 — What it changes.** State what the control's absence or misconfiguration costs the business: a dollar figure, a named consequence, or the contrast that answers the risk raised in Line 2. Never an unanchored percentage — a number with no target is not a decision input.

> [Line 3]

**Reference example — CA-COV002:**

> Requires a second proof of identity for every sign-in across the company. Without it, a single stolen password is enough to reach company data. With it, a stolen password alone isn't enough.

## 3. Route it

A translation is not yet a report. Before deciding where this lands, take it back through the 4-question decision flow in [`REPORTING-DECISION-RUBRIC.md`](../REPORTING-DECISION-RUBRIC.md): who reads it, what decision they make from it, what cadence matches that decision, and what severity floor that audience needs.

The answers place the translation, and the same translation routes differently depending on them:

- A control change an executive committee must fund lands in the **exec committee quarterly**.
- A control change the CISO is adjusting or granting an exception against lands in the **CISO monthly**.
- A control change that moves a pillar's posture lands in the next **board posture summary**, as a stage movement rather than as a control.

If the translation cannot answer question 2 — what decision the reader makes from it — the control does not belong in that report. That is a kill-list outcome, not a writing problem.

**Routing decision:** [Report and cadence]

## 4. Second worked example — ICB-WIN001

The pattern is not identity-specific. The same three lines carry a device compliance control:

**Technical form:**

> ICB-WIN001: verifies BitLocker, TPM, Microsoft Defender Antivirus, and the firewall are active, and that the Defender for Endpoint threat signal is medium or better, before Intune marks a Windows device compliant. Surfaces `deviceComplianceState` only; does not configure the device.

**Executive translation:**

> Confirms a laptop is encrypted and actively protected before it is allowed to reach company data. Without it, a single lost or unprotected laptop is a direct path to everything that laptop can open. With it, the unprotected ones are flagged so IT can fix them before they become the entry point.

Note what survived the translation and what did not. `deviceComplianceState`, the Defender for Endpoint signal threshold, and the distinction between verifying and configuring are all load-bearing for the engineer deploying the control. None of them reach the executive reader, because none of them change the decision that reader makes.

---

## Format rules for this template

- Exactly 3 lines in the executive translation. No 4th line, no bullet sub-lists, no parentheticals carrying a fourth idea.
- No product-internal jargon in the translation. No policy IDs, no JSON keys, no CVE numbers, no MITRE technique names.
- The cost line ties to a dollar figure or a named business consequence. Never an unanchored percentage.
- One worksheet per control. Do not batch multiple controls into one worksheet.
- Sections 1 and 3 are working notes. Only section 2 is written for the executive reader.
- If the translation cannot pass the 4-question flow in `REPORTING-DECISION-RUBRIC.md`, the control does not go in the report. Fix the routing, not the wording.
