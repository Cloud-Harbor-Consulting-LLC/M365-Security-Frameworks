# M365-Security-Frameworks

> Practical Microsoft 365 security frameworks for identity, endpoint, and Defender XDR — with the business case built in.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Last Commit](https://img.shields.io/github/last-commit/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks)
![Stars](https://img.shields.io/github/stars/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks)

> **Release history:** see [CHANGELOG.md](./CHANGELOG.md).

## Why this repo exists

Most Microsoft 365 security frameworks in the community answer **how** to configure a control. Very few answer **why** the business should allow it, fund it, and measure its return. This repo pairs production-grade technical artifacts — Conditional Access policies, Intune compliance baselines, Defender XDR detection rules — with a plain-language business case for each, so security architects can deploy the control *and* defend the investment to executive leaders, the C-suite, and board members.

Every framework in this repo includes:

- **Design doc** — the architecture decisions and trade-offs
- **Deployable artifacts** — JSON, PowerShell, or KQL you can use today
- **Business case** — the ROI, risk reduction, and audit implications in language a non-technical executive can act on

## Frameworks

| Framework | Status | Latest | Notes |
|-----------|--------|--------|-------|
| [Conditional Access Baseline](./Frameworks/Conditional-Access-Baseline/) | Released | v1.4.0 (2026-06-10) | 28 policies across 8 personas plus workload identities and Sensitive-Apps scope; agent identity coverage with an approved-agent allow-list and agent user account coverage (block risky, require compliant device, block non-compliant network); all-beta endpoint; report-only by default |
| [Intune Compliance Baseline](./Frameworks/Intune-Compliance-Baseline/) | Preview | v0.1.0-preview (2026-05-15) | First Windows 10/11 compliance template + framework design spec; macOS, iOS, Android, Linux templates and Deploy-ICBaseline.ps1 land toward Q3 2026 full-framework completion |
| [Security Reporting Decision Rubric](./Frameworks/Security-Reporting-Decision-Rubric/) | Preview | v0.1.0-preview (pending) | 4-question decision flow for designing audience-scoped security reports; severity floor guidance grounded in Defender XDR's severity model; 2 starter templates (board quarterly, CISO monthly) |
| [Entra ID Governance Toolkit](./Frameworks/Entra-ID-Governance-Toolkit/) | Preview | v0.1.0-preview (2026-06-05) | 2 Access Reviews automations: quarterly guest access review and monthly dormant admin role review; PowerShell 7 against Microsoft Graph Identity Governance; deny-by-default with a reviewer chain and retained audit evidence |
| [Zero Trust Readiness Assessment](./Frameworks/Zero-Trust-Readiness-Assessment/) | Planned | — | 6-pillar M365 ZT posture assessment aligned to CISA ZTMM v2.0 (Traditional → Optimal); collector script reads tenant config via read-only Graph scopes; produces technical detail, executive summary, and board 1-pager outputs; ships as ztra-v0.1.0-preview July 2026 |
| Defender XDR Detection Rules | Planned | — | First custom KQL queries Month 7 Week 2 (Oct 2026); full framework Q1 2027 |

## Quickstart

```powershell
# Clone the repo
git clone https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks.git
cd M365-Security-Frameworks

# Navigate to the framework you want to deploy
cd frameworks/conditional-access-baseline

# Follow the framework's own README for deployment steps
```

Each framework has its own README with prerequisites, deployment steps, and a rollback plan.

## Who this is for

- **Security architects** designing M365 tenant baselines from scratch
- **Independent consultants** who need repeatable artifacts across clients
- **IT leaders** who need to justify security investments to finance and the board

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md) for how to propose changes, report issues, or submit a new framework.

## Security

If you discover a security issue in any script or template in this repo, please see [SECURITY.md](./SECURITY.md) for responsible disclosure.

## License

This project is licensed under the MIT License — see [LICENSE](./LICENSE) for details.

## About

Maintained by **Derek Morgan**, Founder & Principal Consultant/Architect at [Cloud Harbor Consulting](https://cloudharborconsulting.cloud). Connect on [LinkedIn](https://www.linkedin.com/in/derek-morgan-ii-14370775/) or read more at [cloudharborconsulting.cloud/blog](https://cloudharborconsulting.cloud/blog).
