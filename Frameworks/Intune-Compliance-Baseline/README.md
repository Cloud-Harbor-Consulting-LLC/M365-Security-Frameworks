# Intune Compliance Baseline (ICB)

> **Status:** v0.1.0-preview shipped Fri May 15, 2026. Framework skeleton, design principles, and first Windows 10/11 template are public. Release history is tracked in the [root CHANGELOG](../../CHANGELOG.md) under v1.2.0.

The Intune Compliance Baseline (ICB) is a public, opinionated set of Microsoft Intune device compliance policy templates and the design principles behind them. It is the second framework in the [M365-Security-Frameworks](../../README.md) repo, alongside the Conditional Access Baseline.

ICB defines what "compliant" means at the device layer. The Conditional Access Baseline consumes that signal via the compliant-device grant control. The two frameworks are deliberately separable: an organization can adopt ICB without CA, or CA without ICB, but the combination is where the zero-trust story lands.

## Scope (v0.1.0-preview)

- Framework skeleton and design principles.
- First Windows 10/11 compliance policy template (ICB-WIN001), modeled after a real production tenant export and reproducing 9 active settings.
- Public-facing v0.1.0-preview release tag (`icb-v0.1.0-preview`).

## Out of scope (v0.1.0-preview)

- macOS, iOS, Android, and Linux compliance templates.
- Deployment script (Deploy-ICBaseline.ps1).
- Cross-framework integration doc covering the Conditional Access "require compliant device" plus ICB handoff.

These items land between v0.1.0-preview and the Q3 2026 framework-completion target. The signal contract with Conditional Access v1.2 CA-SIG-* policies is documented in [POLICY-DESIGN.md](./POLICY-DESIGN.md) but remains advisory until ICB v0.1.0 GA.

## Naming convention

Templates use a platform-led prefix:

- ICB-WIN### for Windows 10/11
- ICB-MAC### for macOS
- ICB-IOS### for iOS and iPadOS
- ICB-AND### for Android
- ICB-LIN### for Linux

Numbering starts at 001 per platform. Each template covers one logical compliance posture. Multi-posture stacks are layered via separate template numbers, not via combined templates.

## Roadmap

| Template | Status |
|----------|--------|
| ICB-WIN001 | Shipped (v0.1.0-preview) |
| ICB-WIN002 onward | Secure Boot, Code Integrity, OS-version floor, password requirements, EALAM driver, Healthy Device Report. Called out as roadmap items in [POLICY-DESIGN.md](./POLICY-DESIGN.md). |
| ICB-MAC001, ICB-IOS001, ICB-AND001, ICB-LIN001 | Post-v0.1.0-preview, before Q3 2026 framework completion |

Release-level milestones:

- **v0.1.0-preview** (2026-05-15, shipped): Skeleton + design doc + ICB-WIN001.
- **v0.2.0-preview** (target Q3 2026): macOS + Linux templates + Deploy-ICBaseline.ps1.
- **v0.3.0-preview** (target Q4 2026): iOS + Android templates + CA signal-contract enforcement tests.
- **v0.1.0 GA** (target Q1 2027): All five platforms + CA signal contract becomes binding.

## Design principles

See [POLICY-DESIGN.md](./POLICY-DESIGN.md) for device personas, platform scope, action-for-noncompliance defaults, and the signal-handoff contract with the Conditional Access Baseline.

## Contributing

Standard repo contribution conventions apply. See the root [CONTRIBUTING.md](../../CONTRIBUTING.md) and the [PR template](../../.github/pull_request_template.md).
