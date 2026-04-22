# Defender XDR Detection Rules

> **Status:** Planned — targeted for **Q1 2027**
> Part of the [M365-Security-Frameworks](../../README.md) project by [Cloud Harbor Consulting](https://www.cloudharborconsulting.cloud).

---

## What this framework will deliver

A curated library of **custom detection rules** for Microsoft Defender XDR — written in KQL, mapped to MITRE ATT&CK, and tuned for signal-to-noise in real tenants rather than lab environments.

The Conditional Access Baseline and Intune Compliance Baseline **prevent and gate**. This framework answers: "When prevention fails or is bypassed, how do I know?"

## Design principles (draft)

1. **Every rule cites its threat** — detections map to MITRE ATT&CK techniques, not generic anomalies
2. **Signal over noise** — published rules have been tuned against real tenants; alert fatigue is treated as a bug
3. **Context beats count** — enrichment and correlation are part of the rule, not a downstream SOC problem
4. **Rules explain themselves** — every detection ships with a runbook: what triggered, what to check, what to do

## Planned scope

- Custom detection rules (KQL) across the Defender XDR surface:
  - Identity (Entra ID, Defender for Identity)
  - Endpoint (Defender for Endpoint)
  - Email & collaboration (Defender for Office 365)
  - Cloud apps (Defender for Cloud Apps)
- MITRE ATT&CK mapping for every rule
- Per-rule runbook (triage steps, false-positive patterns, response actions)
- Deployment scripts for bulk rule import/update
- Tuning guide — noise reduction patterns that have worked in production
- Executive ROI document tied to mean-time-to-detect and SOC efficiency
- Compliance mapping (SOC 2, ISO 27001, NIST 800-53, NIST CSF)

## Out of scope

- Sentinel analytics rules — Defender XDR custom detections only (Sentinel is a separate framework candidate)
- Threat intelligence feed integration — rules are self-contained
- Incident response playbooks beyond per-rule triage — that's a SOC runbook project

## Prerequisites (anticipated)

- Microsoft 365 E5, E5 Security, or equivalent Defender XDR licensing
- Defender XDR unified portal (`security.microsoft.com`) enabled
- Security Administrator or Security Operator role for rule management
- Familiarity with KQL (Kusto Query Language)

## Follow along

This framework is in the roadmap stage. Watch or star the repo to be notified when v1.0.0 ships.

Questions, use cases, or detection patterns you'd like to see covered? [Open an issue](https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/issues) — early input shapes the library.

---

*Maintained by [Derek Morgan](https://www.linkedin.com/in/derek-morgan-ii-14370775/), Cloud Harbor Consulting.*
