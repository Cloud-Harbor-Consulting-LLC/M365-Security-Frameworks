# M365-Security-Frameworks

> Practical Microsoft 365 security frameworks for identity, endpoint, and Defender XDR — with the business case built in.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Last Commit](https://img.shields.io/github/last-commit/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks)
![Stars](https://img.shields.io/github/stars/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks?style=social)

> **Release history:** see [CHANGELOG.md](./CHANGELOG.md).

## Why this repo exists

Most Microsoft 365 security frameworks in the community answer **how** to configure a control. Very few answer **why** the business should allow it, fund it, and measure its return. This repo pairs production-grade technical artifacts — Conditional Access policies, Intune compliance baselines, Defender XDR detection rules — with a plain-language business case for each, so security architects can deploy the control *and* defend the investment to executive leaders, the C-suite, and board members.

Every framework in this repo includes:

- **Design doc** — the architecture decisions and trade-offs
- **Deployable artifacts** — JSON, PowerShell, or KQL you can use today
- **Business case** — the ROI, risk reduction, and audit implications in language a non-technical executive can act on

## Frameworks

| Framework | Focus Area | Status |
|-----------|------------|--------|
| [Conditional Access Baseline](./Frameworks/Conditional-Access-Baseline/) | Entra ID, Zero Trust | 🟢 Released -- v1.1.0 |
| [Intune Compliance Baseline](./Frameworks/Intune-Compliance-Baseline/) | Endpoint Management | ⚪ Planned (Q3 2026) |
| [Entra ID Governance Toolkit](./Frameworks/Entra-ID-Governance-Toolkit/) | Identity Governance | ⚪ Planned (Q4 2026) |
| [Defender XDR Detection Rules](./Frameworks/Defender-XDR-Detection-Rules/) | SIEM & XDR | ⚪ Planned (Q1 2027) |

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
