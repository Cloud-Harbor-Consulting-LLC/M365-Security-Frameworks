# Zero Trust Readiness Assessment Framework

> **Status:** 🔬 In Development — `ztra-v0.1.0-preview` shipping July 2026

Assesses an M365 tenant's Zero Trust posture across Microsoft's 6 ZT pillars, scores each pillar against CISA ZTMM v2.0's 4 maturity stages, and produces three audience-scoped output reports: a technical detail report for security engineers, an executive summary for the CISO, and a board 1-pager.

The scoring rubric is usable as a standalone assessment instrument — no scripts required. The collector script automates evidence gathering via read-only Microsoft Graph calls and feeds the formatter, which generates all three outputs in a single run.

---

## Assessment structure

| Dimension | Choice | Authority |
|---|---|---|
| Assessment domains | Microsoft's 6 ZT pillars: Identities, Endpoints, Applications, Data, Infrastructure, Networks | [Microsoft ZT deployment guide](https://learn.microsoft.com/en-us/security/zero-trust/deploy/overview) |
| Maturity scale | CISA ZTMM v2.0 — 4 stages: Traditional, Initial, Advanced, Optimal | [CISA ZTMM v2.0 (April 2023)](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf) |
| Control citations | NIST SP 800-207 tenets (T1–T7) per control row | [NIST SP 800-207](https://doi.org/10.6028/NIST.SP.800-207) |
| Pillar weighting | Equal (16.67% per pillar) — aligned with CISA ZTMM v2.0's horizontal progress design | CISA ZTMM v2.0 §2 |

Per-pillar stage = median of all control row scores within the pillar. Overall tenant stage = median of the 6 pillar scores. Both round down on ties.

---

## Framework contents

| Artifact | Description |
|---|---|
| `Design/SCORING-RUBRIC.md` | Full assessment rubric — 6 pillars × 4 CISA ZTMM stages. Each control row includes NIST tenet citations, the observable M365 configuration signal used to score it, and a cross-reference to a deployed repo artifact where applicable. Usable without the collector script. |
| `Scripts/Get-ZTReadinessScore.ps1` | Read-only Microsoft Graph collector. Runs against a live tenant using 6 delegated/application scopes (no write permissions) and returns a structured object consumed by the formatter. |
| `Scripts/Format-ZTReadinessReport.ps1` | Accepts the collector output and generates three Markdown reports: technical detail, executive summary, and board 1-pager. |
| `Scripts/README.md` | Prerequisites, authentication setup, and end-to-end usage examples for both scripts. |
| `Examples/Board-Summary-Template.md` | Blank board 1-pager template for practitioners who run the assessment manually against the rubric. |
| `Examples/Sample-Tenant-Report.md` | All three output shapes populated with fictional Contoso Ltd data (Overall: Stage 2 — Initial). Illustrates the framework's output before running it against a real tenant. |
| `Business-Case/ROI-ZT-READINESS.md` | Business case for Zero Trust investment: risk reduction framing, cost of breach benchmarks, and the case for running a readiness assessment before committing budget to remediation. |

---

## Required Graph scopes

The collector script uses read-only scopes only:

| Scope | Pillars covered |
|---|---|
| `Policy.Read.All` | Identities, Endpoints, Networks |
| `IdentityRiskyUser.Read.All` | Identities |
| `AuditLog.Read.All` | Identities, cross-pillar telemetry |
| `Device.Read.All` | Endpoints |
| `RoleManagement.Read.Directory` | Identities, Infrastructure |
| `Reports.Read.All` | Cross-pillar |

---

## Prerequisites

- PowerShell 7+
- `Microsoft.Graph.Authentication` module
- An Entra ID account with the scopes above granted (delegated) or an app registration with those scopes (application)
- Microsoft 365 tenant with Entra ID P1 minimum; P2 required for full Identity pillar signal coverage (Identity Protection, PIM)

---

## How to use this framework

**Option A — Manual assessment against the rubric (no scripts required)**

1. Open `Design/SCORING-RUBRIC.md`.
2. Work through each pillar section. For each control row, identify which maturity stage description matches your tenant's current configuration.
3. Record scores in your own tracking sheet. Compute pillar medians and overall median.
4. Use `Examples/Board-Summary-Template.md` to present findings.

**Option B — Automated assessment**

# Step 1 — Collect tenant signals
.\Scripts\Get-ZTReadinessScore.ps1 -TenantId <your-tenant-id> -OutputPath .\Results\

# Step 2 — Generate all three output reports
.\Scripts\Format-ZTReadinessReport.ps1 -InputPath .\Results\<assessment-file>.json -OutputPath .\Reports\

Both scripts require prior authentication via `Connect-MgGraph` with the scopes listed above. See `Scripts/README.md` for the full walkthrough.

---

## Repo cross-references

Controls in the scoring rubric cross-reference deployed artifacts from this repo where those artifacts serve as evidence of a control being in place. Key references:

| Control | Repo artifact |
|---|---|
| Admin MFA (phishing-resistant) | `Frameworks/Conditional-Access-Baseline/Policies/CA-AUT001-*` |
| Sign-in and user risk CA | `Frameworks/Conditional-Access-Baseline/Policies/CA-SIG005-010-*` |
| Block legacy authentication | `Frameworks/Conditional-Access-Baseline/Policies/CA-SIG001-*` |
| CA for Agent identities | `Frameworks/Conditional-Access-Baseline/Policies/CA-COV012-015-*` |
| Guest access lifecycle review | `Frameworks/Entra-ID-Governance-Toolkit/` (EIG-AR001) |
| Dormant admin role review | `Frameworks/Entra-ID-Governance-Toolkit/` (EIG-AR002) |

---

## Related frameworks

- [Conditional Access Baseline v1.4.0](../Conditional-Access-Baseline/) — 28 CA policies across 8 personas; deployed controls here satisfy multiple Identity and Networks pillar controls in the ZTRA rubric.
- [Entra ID Governance Toolkit v0.1.0-preview](../Entra-ID-Governance-Toolkit/) — Access review automations; deployed controls satisfy Identity pillar governance controls.
- [Intune Compliance Baseline](../Intune-Compliance-Baseline/) — Device compliance policies; when deployed, satisfies Endpoints pillar controls that the ZTRA collector checks via `Device.Read.All`.

---

## About

Maintained by **Derek Morgan**, Founder & Principal Consultant/Architect at [Cloud Harbor Consulting](https://cloudharborconsulting.cloud). Connect on [LinkedIn](https://www.linkedin.com/in/derek-morgan-ii-14370775/).
