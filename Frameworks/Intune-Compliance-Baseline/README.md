# Intune Compliance Baseline (ICB)

> **Status:** Released, **v1.0.0** (Tue Nov 24, 2026), tag `icb-v1.0.0`. 11 compliance templates across Windows 11, macOS, iOS/iPadOS, Android and Linux, a deployer that defaults to observation mode, and an executive business case. The design is in [POLICY-DESIGN.md](./Design/POLICY-DESIGN.md). Release history is tracked in the [root CHANGELOG](../../CHANGELOG.md).

The Intune Compliance Baseline (ICB) is a public, opinionated set of Microsoft Intune device compliance policy templates and the design principles behind them. It is the second framework in the [M365-Security-Frameworks](../../README.md) repo, alongside the Conditional Access Baseline.

ICB defines what "compliant" means at the device layer. The Conditional Access Baseline consumes that signal via the compliant-device grant control. The two frameworks are deliberately separable: an organization can adopt ICB without CA, or CA without ICB, but the combination is where the zero-trust story lands.

## What v1.0.0 contains

- **11 compliance templates** in [Policies/](./Policies/), each specified in [POLICY-DESIGN.md](./Design/POLICY-DESIGN.md) section 8. Values follow Microsoft's Zero Trust recommended compliance settings and its security configuration frameworks, cross-checked against the CIS Benchmarks for each platform.
- **[Deploy-ICBaseline.ps1](./Scripts/README.md)**, a PowerShell 7 deployer on Microsoft Graph beta. It deploys in observation mode by default: devices report real compliance results while Conditional Access still treats them as compliant. `-Enforce` applies each template's designed schedule.
- **[An executive business case](./Business-Case/ROI-INTUNE-COMPLIANCE.md)**: licensing, the signal ICB gives the Conditional Access Baseline, implementation and operating cost, and compliance mapping.
- **Validation labels.** Every template is validated against a test tenant. The 6 Windows templates and the Linux template are also validated on real devices. The 4 macOS, iOS/iPadOS and Android templates are tenant-validated, not device-validated; device validation for them follows in v1.0.1.

v1.0 contains only generally available Intune settings. Preview capabilities announced at Microsoft Ignite 2026 are not part of it (see the roadmap below).

## Deploying

1. Read [POLICY-DESIGN.md](./Design/POLICY-DESIGN.md) sections 5 and 7: the actions for noncompliance, the tenant prerequisites and the rollout order.
2. Create the persona groups (section 3) and the notification message template, and set the tenant-wide compliance settings (section 7.1). Retire or exclude any existing compliance policy that targets the same devices.
3. Run `Deploy-ICBaseline.ps1 -WhatIf`, then deploy in observation mode ([Scripts/README.md](./Scripts/README.md)).
4. Review each template's results for its observation period (section 7.2), then promote it with `-Enforce`.
5. If a template causes unexpected noncompliance, re-run the deployer for it without `-Enforce`. That returns it to observation mode in place, keeping the policy, its assignments and its reporting history.

Conditional Access consumes the result through four Conditional Access Baseline policies; see [CA-ICB-INTEGRATION.md](../Conditional-Access-Baseline/Design/CA-ICB-INTEGRATION.md) for the joint rollout.

## Previous release (v0.1.0-preview)

- Framework skeleton and design principles.
- ICB-WIN001, the first Windows compliance template, rebuilt for v1.0.

## Naming convention

Templates use a platform-led prefix:

- ICB-WIN### for Windows 11
- ICB-MAC### for macOS
- ICB-IOS### for iOS and iPadOS
- ICB-AND### for Android
- ICB-LIN### for Linux

Numbering starts at 001 per platform. Each template covers one logical compliance posture. Multi-posture stacks are layered via separate template numbers, not via combined templates.

## Templates and roadmap

| Template | Verifies | Status |
|----------|----------|--------|
| ICB-WIN001-Baseline-DefenderAndBitLocker | BitLocker, encryption, firewall, TPM, antivirus, antispyware, Defender Antivirus and its version, signatures, real-time protection | v1.0.0, device-validated (rebuilt from v0.1.0-preview) |
| ICB-WIN002-Hardening-SecureBoot | Secure Boot | v1.0.0, device-validated |
| ICB-WIN003-Hardening-CodeIntegrity | Code integrity | v1.0.0, device-validated |
| ICB-WIN004-Baseline-OSVersionFloor | Windows 11 build in servicing | v1.0.0, device-validated |
| ICB-WIN005-Hardening-PasswordPIN | Device unlock credential (the Windows Hello PIN) | v1.0.0, device-validated |
| ICB-WIN008-Threat-DefenderRiskScore | Defender for Endpoint machine risk, noncompliant immediately | v1.0.0, device-validated |
| ICB-MAC001-Baseline-EncryptionAndIntegrity | FileVault, System Integrity Protection, firewall, Gatekeeper, macOS version | v1.0.0, tenant-validated |
| ICB-IOS001-Baseline-PasscodeAndIntegrity | Passcode, jailbreak, iOS version | v1.0.0, tenant-validated |
| ICB-AND001-Corporate-IntegrityAndPasscode | Play Integrity, root, passcode, encryption on corporate Android | v1.0.0, tenant-validated |
| ICB-AND002-PersonalWorkProfile-IntegrityAndPasscode | Play Integrity, root, passcode on personally owned work profiles | v1.0.0, tenant-validated |
| ICB-LIN001-Baseline-EncryptionAndPassword | Disk encryption, distribution and version, password length | v1.0.0, device-validated |

ICB-WIN006 (ELAM) and ICB-WIN007 (Healthy Device Report), listed on earlier versions of this roadmap, do not ship; POLICY-DESIGN section 9.2 explains why. Windows virtualization-based security checks and the Linux AppArmor/SELinux and firewall checks are deferred to v1.1 (section 9.3).

Release-level milestones:

- **v0.1.0-preview** (2026-05-15, shipped): Skeleton + design doc + ICB-WIN001.
- **v1.0.0** (2026-11-24, shipped): All 11 templates, Deploy-ICBaseline.ps1 and the business case.
- **Ignite 2026 AI-agent addendum** (planned, target 2026-12-04):
  - A documentation-only release, `Preview/IGNITE-2026-AI-AGENT-ADDENDUM.md`. It covers how Intune helps discover, restrict, contain and evidence supported local AI agents on managed Windows devices.
  - It covers the software compliance (restricted software) policy and app inventory, both in public preview as of 2026-11-20, and Microsoft Execution Containers.
  - Each capability carries its Microsoft source, release status and test status.
  - It does not change the v1.0 templates. Preview controls stay out of the stable baseline.
- **v1.0.1**: Device validation for the macOS, iOS and Android templates.

## Design principles

See [POLICY-DESIGN.md](./Design/POLICY-DESIGN.md) for device personas, platform scope and version floors, actions for noncompliance and observation mode, tenant prerequisites, and the signal handoff to the Conditional Access Baseline.

## Contributing

Standard repo contribution conventions apply. See the root [CONTRIBUTING.md](../../CONTRIBUTING.md) and the [PR template](../../.github/pull_request_template.md).
