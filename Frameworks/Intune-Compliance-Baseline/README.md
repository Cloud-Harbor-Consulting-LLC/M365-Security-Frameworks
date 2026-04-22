# Intune Compliance Baseline

> **Status:** Planned — targeted for **Q3 2026**
> Part of the [M365-Security-Frameworks](../../README.md) project by [Cloud Harbor Consulting](https://www.cloudharborconsulting.cloud).

---

## What this framework will deliver

A defensible, opinionated Microsoft Intune compliance baseline that defines **what "trusted device" actually means** before Conditional Access enforces it.

The Conditional Access Baseline ([`CA-SIG001`](../Conditional-Access-Baseline/Policies/)) requires a compliant or hybrid-joined device for sensitive apps — but that guarantee is only as strong as the compliance policy behind it. This framework fills that gap.

## Design principles (draft)

1. **Compliance is a contract, not a checklist** — every rule maps to a specific threat it mitigates
2. **Platform parity where it matters** — Windows, macOS, iOS, Android treated as first-class, not afterthoughts
3. **Grace periods with teeth** — non-compliance has a defined path to remediation or access loss
4. **Signals feed Conditional Access** — every compliance outcome is consumable by CA policies

## Planned scope

- Compliance policy templates (Windows, macOS, iOS, Android)
- Device configuration profiles for baseline hardening
- Enrollment restrictions and platform guardrails
- Scripts for bulk deployment and drift detection
- Executive ROI document tied to endpoint risk reduction
- Compliance mapping (SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST 800-53)

## Out of scope

- Full MDM/MAM deployment guidance (that's a book, not a framework)
- App protection policies — planned for a separate Intune App Protection framework
- Autopilot provisioning — covered elsewhere in the Microsoft ecosystem

## Prerequisites (anticipated)

- Microsoft Intune Plan 1 (included in most M365 E3/E5 and Business Premium SKUs)
- Entra ID P1 or higher for Conditional Access integration
- PowerShell 7+ and Microsoft Graph PowerShell SDK 2.x

## Follow along

This framework is in the roadmap stage. Watch or star the repo to be notified when v1.0.0 ships.

Questions, use cases, or requirements you'd like to see covered? [Open an issue](https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/issues) — early input shapes the baseline.

---

*Maintained by [Derek Morgan](https://www.linkedin.com/in/derek-morgan-ii-14370775/), Cloud Harbor Consulting.*
