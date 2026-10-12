# Intune Compliance Baseline (ICB)

> **Status:** Preview. v0.1.0-preview shipped Fri May 15, 2026, with the framework skeleton, design principles and the first Windows template. **v1.0 is in development for Q4 2026** and ships as a single release: 11 templates across Windows 11, macOS, iOS/iPadOS, Android and Linux, plus a deployer. The v1.0 design is complete in [POLICY-DESIGN.md](./Design/POLICY-DESIGN.md). Release history is tracked in the [root CHANGELOG](../../CHANGELOG.md).

The Intune Compliance Baseline (ICB) is a public, opinionated set of Microsoft Intune device compliance policy templates and the design principles behind them. It is the second framework in the [M365-Security-Frameworks](../../README.md) repo, alongside the Conditional Access Baseline.

ICB defines what "compliant" means at the device layer. The Conditional Access Baseline consumes that signal via the compliant-device grant control. The two frameworks are deliberately separable: an organization can adopt ICB without CA, or CA without ICB, but the combination is where the zero-trust story lands.

## Shipped today (v0.1.0-preview)

- Framework skeleton and design principles.
- ICB-WIN001, the first Windows compliance template. It is rebuilt for v1.0 (see below).

## Coming in v1.0

- **11 compliance templates**, each specified in [POLICY-DESIGN.md](./Design/POLICY-DESIGN.md) section 8. Values follow Microsoft's Zero Trust recommended compliance settings and its security configuration frameworks, cross-checked against the CIS Benchmarks for each platform.
- **Deploy-ICBaseline.ps1**, a PowerShell 7 deployer on Microsoft Graph beta. It deploys in observation mode by default: devices report real compliance results while Conditional Access still treats them as compliant. `-Enforce` applies each template's designed schedule.
- **An executive business case** for the baseline.
- **Validation labels.** Every template is validated against a test tenant. The Windows and Linux templates are also validated on real devices; device validation for macOS, iOS and Android follows in v1.0.1.

## Naming convention

Templates use a platform-led prefix:

- ICB-WIN### for Windows 11
- ICB-MAC### for macOS
- ICB-IOS### for iOS and iPadOS
- ICB-AND### for Android
- ICB-LIN### for Linux

Numbering starts at 001 per platform. Each template covers one logical compliance posture. Multi-posture stacks are layered via separate template numbers, not via combined templates.

## Roadmap

| Template | Verifies | Status |
|----------|----------|--------|
| ICB-WIN001-Baseline-DefenderAndBitLocker | BitLocker, encryption, firewall, TPM, antivirus, antispyware, Defender Antivirus and its version, signatures, real-time protection | Shipped in v0.1.0-preview; rebuilt for v1.0 |
| ICB-WIN002-Hardening-SecureBoot | Secure Boot | v1.0 |
| ICB-WIN003-Hardening-CodeIntegrity | Code integrity | v1.0 |
| ICB-WIN004-Baseline-OSVersionFloor | Windows 11 build in servicing | v1.0 |
| ICB-WIN005-Hardening-PasswordPIN | Device unlock credential (the Windows Hello PIN) | v1.0 |
| ICB-WIN008-Threat-DefenderRiskScore | Defender for Endpoint machine risk, noncompliant immediately | v1.0 |
| ICB-MAC001-Baseline-EncryptionAndIntegrity | FileVault, System Integrity Protection, firewall, Gatekeeper, macOS version | v1.0 |
| ICB-IOS001-Baseline-PasscodeAndIntegrity | Passcode, jailbreak, iOS version | v1.0 |
| ICB-AND001-Corporate-IntegrityAndPasscode | Play Integrity, root, passcode, encryption on corporate Android | v1.0 |
| ICB-AND002-PersonalWorkProfile-IntegrityAndPasscode | Play Integrity, root, passcode on personally owned work profiles | v1.0 |
| ICB-LIN001-Baseline-EncryptionAndPassword | Disk encryption, distribution and version, password length | v1.0 |

ICB-WIN006 (ELAM) and ICB-WIN007 (Healthy Device Report), listed on earlier versions of this roadmap, do not ship; POLICY-DESIGN section 9.2 explains why. Windows virtualization-based security checks and the Linux AppArmor/SELinux and firewall checks are deferred to v1.1 (section 9.3).

Release-level milestones:

- **v0.1.0-preview** (2026-05-15, shipped): Skeleton + design doc + ICB-WIN001.
- **v1.0.0** (target Q4 2026): All 11 templates, Deploy-ICBaseline.ps1 and the business case.
- **v1.0.1**: Device validation for the macOS, iOS and Android templates.

## Design principles

See [POLICY-DESIGN.md](./Design/POLICY-DESIGN.md) for device personas, platform scope and version floors, actions for noncompliance and observation mode, tenant prerequisites, and the signal handoff to the Conditional Access Baseline.

## Contributing

Standard repo contribution conventions apply. See the root [CONTRIBUTING.md](../../CONTRIBUTING.md) and the [PR template](../../.github/pull_request_template.md).
