# Security Audit Attestation Report

**Attestation period:** [Quarter / FY / specific dates]
**Prepared by:** [CISO or compliance lead name]
**Frameworks attested:** [SOC 2 Type II / ISO 27001:2022 / both]
**Reading time:** under 15 minutes

## Purpose

This report provides audit-ready evidence that security monitoring and access governance controls operated effectively during the attestation period. Each row maps a control requirement to the observable metric or artifact that demonstrates compliance.

Auditors: all metrics reference Microsoft Defender XDR and Microsoft Entra ID logs, which are retained per the organization's log retention policy. Raw log export is available on request.

## SOC 2 control evidence

| CC control | Control description | Evidence metric | Source | Value for period | Status |
|---|---|---|---|---|---|
| CC6.1 | Logical access controls restrict access to authorized users | Privileged role assignments reviewed and recertified | EIG-AR002 output, Entra ID Access Reviews | [X roles reviewed, Y removed] | [Met / Not met] |
| CC6.3 | Authorized personnel access restricted to what is required for their job function | Guest access reviewed and recertified | EIG-AR001 output, Entra ID Access Reviews | [X guests reviewed, Y removed] | [Met / Not met] |
| CC6.7 | Access restrictions enforced to prevent unauthorized access | Conditional Access policy coverage, report-only baseline vs enforced | Defender XDR CA policy report | [X% of sign-ins covered by enforcing CA policies] | [Met / Not met] |
| CC7.1 | Security events are detected | Mean time to detect (MTTD) — High and Medium incidents | Defender XDR incident queue | [X minutes median MTTD] | [Met / Not met] |
| CC7.2 | Security monitoring of system components | Defender XDR coverage — endpoints, identity, email, cloud apps | Defender XDR coverage report | [X% of in-scope assets covered] | [Met / Not met] |
| CC7.3 | Evaluation of security events to identify incidents | Confirmed true positive rate — Medium and above | Defender XDR incident classification | [X% confirmed true positive] | [Met / Not met] |
| CC7.4 | Incident response | Mean time to respond (MTTR) — High incidents | Defender XDR incident queue | [X hours median MTTR] | [Met / Not met] |

## ISO 27001:2022 control evidence

| Control | Description | Evidence metric | Source | Value for period | Status |
|---|---|---|---|---|---|
| A.5.15 | Access control | Conditional Access policy coverage rate | Defender XDR CA policy report | [X% of sign-ins covered] | [Met / Not met] |
| A.5.18 | Access rights | Periodic access rights review completed; removals documented | EIG-AR001 and EIG-AR002 outputs | [X reviews completed, Y excess rights removed] | [Met / Not met] |
| A.5.25 | Assessment and decision on information security events | Incident classification rate (events triaged and classified within SLA) | Defender XDR incident queue | [X% classified within [X hours]] | [Met / Not met] |
| A.5.26 | Response to information security incidents | Confirmed incidents remediated within MTTR SLA | Defender XDR incident queue | [X% closed within SLA] | [Met / Not met] |
| A.8.15 | Logging | Log retention confirmed for all in-scope systems | Defender XDR, Entra ID, Sentinel log retention settings | [X days retained; meets [Y day] policy requirement] | [Met / Not met] |
| A.8.16 | Monitoring activities | Continuous monitoring active for all in-scope systems | Defender XDR coverage report | [X% of in-scope assets with active monitoring] | [Met / Not met] |

## Evidence package index

List the artifacts attached to or referenced by this attestation. Auditors will request at least items 1 through 4.

1. Defender XDR incident export — [date range]
2. Entra ID Access Reviews completion report — EIG-AR001, [date]
3. Entra ID Access Reviews completion report — EIG-AR002, [date]
4. Conditional Access policy report-only evaluation export — [date]
5. Log retention configuration screenshot — [date]
6. [Additional artifacts]

## Attestation sign-off

**Prepared by:** [name, title, date]
**Reviewed by:** [name, title, date]
**Approved by:** [CISO name, date]

---

## Format rules for this template

- Populate every row. A blank "Value for period" cell is an open finding, not a skipped row.
- ISO 27001 control numbers follow the 2022 revision. The 2013 equivalents for reference, per the mapping in Annex B of ISO/IEC 27002:2022: A.5.15 = A.9.1.1 and A.9.1.2; A.5.18 = A.9.2.2, A.9.2.5, and A.9.2.6; A.5.25 = A.16.1.4; A.5.26 = A.16.1.5; A.8.15 = A.12.4.1, A.12.4.2, and A.12.4.3. A.8.16 is one of the controls introduced in the 2022 revision and has no 2013 equivalent, so a prior 2013 assessment cannot be used as evidence for it.
- Status column: "Met" requires a populated evidence metric with a value. "Not met" requires a remediation note added below the table. "Not applicable" requires a written justification.
- Retain this document and its evidence package for the minimum period required by the applicable compliance framework (SOC 2: 1 year; ISO 27001: per organization's retention schedule).
