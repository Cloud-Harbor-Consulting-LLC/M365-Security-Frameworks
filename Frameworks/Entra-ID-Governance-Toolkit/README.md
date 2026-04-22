# Entra ID Governance Toolkit

> **Status:** Planned — targeted for **Q4 2026**
> Part of the [M365-Security-Frameworks](../../README.md) project by [Cloud Harbor Consulting](https://www.cloudharborconsulting.cloud).

---

## What this framework will deliver

A practical governance toolkit for Entra ID — covering **access lifecycle, privileged identity, and standing-access reduction** — built on the same principle-first approach as the Conditional Access Baseline.

The Conditional Access Baseline locks the **front door**. This toolkit addresses the harder problem behind it: ensuring the right people have the right access for the right duration, and that privileged access is time-bound by default.

## Design principles (draft)

1. **Just-in-time beats just-in-case** — standing privileged access is the exception, not the default
2. **Access has an expiration date** — every grant answers "when does this end?"
3. **Reviews that actually change state** — access reviews drive removal, not just acknowledgment
4. **Separation of duties is encoded, not assumed** — incompatible role combinations blocked by policy

## Planned scope

- **Privileged Identity Management (PIM)** — role activation policies, approval workflows, break-glass patterns
- **Access Packages** — entitlement management templates for common access bundles
- **Access Reviews** — recurring review templates for privileged roles, guest access, and group membership
- **Lifecycle Workflows** — joiner/mover/leaver automation patterns
- **Guest access governance** — B2B invitation policies, expiration, and cleanup
- Executive ROI document tied to insider risk and audit readiness
- Compliance mapping (SOC 2, ISO 27001, HIPAA, SOX, NIST 800-53)

## Out of scope

- Full Identity Governance deployment playbook (that's a multi-month engagement, not a framework)
- HR-system-specific inbound provisioning — that's tenant-specific
- Entitlement management for external tenants (covered under multi-tenant governance, separately)

## Prerequisites (anticipated)

- Microsoft Entra ID P2 (required for PIM, Access Reviews, Identity Governance)
- Global Administrator or Privileged Role Administrator for initial configuration
- PowerShell 7+ and Microsoft Graph PowerShell SDK 2.x

## Follow along

This framework is in the roadmap stage. Watch or star the repo to be notified when v1.0.0 ships.

Questions, use cases, or requirements you'd like to see covered? [Open an issue](https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/issues) — early input shapes the toolkit.

---

*Maintained by [Derek Morgan](https://www.linkedin.com/in/derek-morgan-ii-14370775/), Cloud Harbor Consulting.*
