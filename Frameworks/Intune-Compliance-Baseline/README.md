# Intune Compliance Baseline (ICB)

> **Status:** Scaffolding. Framework folder, design principles, and first template land across this week. Tagged release v0.1.0-preview is scheduled for Fri May 15, 2026.

The Intune Compliance Baseline (ICB) is a public, opinionated set of Microsoft Intune device compliance policy templates and the design principles behind them. It is the second framework in the [M365-Security-Frameworks](../../README.md) repo, alongside the Conditional Access Baseline.

ICB defines what "compliant" means at the device layer. The Conditional Access Baseline consumes that signal via the compliant-device grant control. The two frameworks are deliberately separable: an organization can adopt ICB without CA, or CA without ICB, but the combination is where the zero-trust story lands.

## Scope (week 1)

- Framework skeleton and design principles.
- First Windows 10/11 compliance policy template (ICB-WIN001), modeled after a real production tenant export and reproducing 9 active settings.
- Public-facing v0.1.0-preview release tag.

## Out of scope (week 1, deferred)

- macOS, iOS, Android, and Linux compliance templates.
- Deployment script (Deploy-ICBaseline.ps1).
- Cross-framework integration doc covering the Conditional Access "require compliant device" plus ICB handoff.

These items land between the v0.1.0-preview release and the Q3 2026 framework-completion target.

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
| ICB-WIN001 | Targeted for this week (PR C) |
| ICB-WIN002 onward | Secure Boot, Code Integrity, OS-version floor, password requirements, EALAM driver, Healthy Device Report. Called out as roadmap items in POLICY-DESIGN.md. |
| ICB-MAC001, ICB-IOS001, ICB-AND001, ICB-LIN001 | Post-v0.1.0-preview, before Q3 2026 framework completion |

## Design principles

See POLICY-DESIGN.md (lands in PR B) for device personas, platform scope, action-for-noncompliance defaults, and the signal-handoff contract with the Conditional Access Baseline.

## Contributing

Standard repo contribution conventions apply. See the root [CONTRIBUTING.md](../../CONTRIBUTING.md) and the [PR template](../../.github/pull_request_template.md).
