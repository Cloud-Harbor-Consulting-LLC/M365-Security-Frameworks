# Intune Compliance Baseline — Policy Design

This document specifies the design philosophy, naming convention, device persona model, action-for-noncompliance defaults, signal handoff to the Conditional Access Baseline, and rollout sequence for the Intune Compliance Baseline (ICB) framework. It is the prerequisite reading for anyone deploying, extending, or auditing the baseline.

The per-template design specifications (one subsection for each ICB-* template) are appended in the following section of this document. The first such specification — ICB-WIN001 — is included; subsequent templates are added in their own PRs as they ship.

---

## 1. Design philosophy

A compliance baseline is the verification layer beneath every "require compliant device" Conditional Access decision. Without a defensible compliance baseline, the CA grant control `compliantDevice` either lets through devices that should not pass, or blocks devices that should — neither is acceptable.

Four principles anchor every design decision in this framework:

### 1.1 Platform-led scope

**What it means:** Compliance evaluation differs fundamentally across platforms. Windows has TPM, BitLocker, Defender, and Group Policy / CSP. macOS has Secure Enclave, FileVault, XProtect, and MDM-only enforcement. iOS / Android / Linux each have their own primitives. A "unified compliance policy" abstraction across platforms either weakens to the lowest common denominator or creates silent blind spots where a platform-specific control is omitted because no cross-platform equivalent exists.

**How this baseline implements it:** Every policy template is platform-specific. The naming convention enforces it: ICB-WIN###, ICB-MAC###, ICB-IOS###, ICB-AND###, ICB-LIN###. There is no ICB-ALL### or ICB-ANY### in this framework, by design. A device with two operating systems (a Windows / Linux dual-boot engineering workstation, an iPad with macOS Sidecar) is two compliance evaluations, not one.

### 1.2 Verify, don't enforce

**What it means:** Intune Compliance Policies evaluate that an OS-native or vendor-native control is *active and reporting healthy*. They do not implement the control. BitLocker is enforced by Windows. Microsoft Defender Antivirus is enforced by Defender. The Firewall is enforced by the OS. Conflating verification with enforcement creates two failure modes: adopters skip the underlying configuration step because they think the compliance policy "enables" the control, and remediation effort lands on Intune when the actual problem is at the OS / AV vendor / firewall layer.

**How this baseline implements it:** Every setting in every ICB-* template names the vendor / OS control it verifies, not the control itself. ICB-WIN001's `bitLockerEnabled` setting verifies that BitLocker is enabled and reporting; it does not encrypt the disk. ICB-WIN001's `defenderEnabled` setting verifies that the Defender service is running; it does not install Defender. Per-template specs cite the upstream enforcement layer for every setting.

### 1.3 Compliance as a graded scale

**What it means:** Intune's compliance model is not binary. It includes evaluated states (Compliant, NotCompliant, InGracePeriod, ConfigManager, Error, NotEvaluated) and time-windowed evaluation through `scheduledActionsForRule`. Collapsing this to a binary "pass / fail" the moment a setting evaluates as non-compliant creates avoidable user-impacting outages — a transient eval miss, a device that just woke from sleep, a signature file that updates in the next 15 minutes, all become Conditional Access blocks rather than soft notifications.

**How this baseline implements it:** Action-for-noncompliance defaults use a graduated response (Section 5). The first action on detection is `notification` (push and email) with no CA impact. The `block` action — which is what flips `deviceComplianceState` to `noncompliant` for CA evaluation — fires only after a 7-day grace window. The retire action is reserved for BYOD only and triggers no earlier than 30 days. This is configurable per template; the defaults can be tightened for high-assurance device classes once the baseline is established.

### 1.4 Signal-clean handoff to Conditional Access

**What it means:** Compliance and access are separate concerns operated by separate frameworks. The Intune Compliance Baseline owns *what makes a device compliant*. The Conditional Access Baseline owns *what compliance unlocks*. Mixing them — putting access decisions inside compliance policies, or putting compliance criteria inside Conditional Access — produces two systems that contradict each other under change.

**How this baseline implements it:** ICB produces exactly one signal that CA consumes: `deviceComplianceState` on the user's device object, surfaced to CA via the `compliantDevice` built-in grant control. ICB's surface to CA is documented in Section 6. The CA baseline's CA-SIG001-SensApps-RequireCompliantDevice (v1.0.0) is the canonical consumer today; future CA policies that consume the same signal cite this handoff. No CA policy enforces a compliance setting directly; no ICB template references a CA policy or a CA grant control.

---

## 2. Naming convention

Every policy in this baseline follows the format:

```
ICB-[PlatformPrefix][Number]-[Scope]-[Action]
```

### 2.1 Platform prefixes

| Prefix | Platform | Operating systems in scope |
|--------|----------|-----------------------------|
| WIN | Windows | Windows 10 (22H2 supported channel), Windows 11 |
| MAC | macOS | macOS 13 Ventura and newer |
| IOS | iOS / iPadOS | iOS 16 and newer; iPadOS 16 and newer |
| AND | Android | Android 11 and newer (Android Enterprise; Device Owner or Work Profile) |
| LIN | Linux | Ubuntu 22.04 LTS and newer; RHEL 9 and newer (Microsoft-supported channels) |

Platforms outside this list (Windows Server, ChromeOS, embedded / kiosk devices, point-of-sale terminals) are out of scope for this framework and are handled by adjacent frameworks (Defender for Servers, dedicated kiosk management) or left to platform-specific tooling.

### 2.2 Rules

- **One platform prefix per template.** A device that runs two operating systems is two compliance evaluations.
- **Numbers are sequential within a prefix.** ICB-WIN001 comes before ICB-WIN002; retired templates keep their number permanently.
- **Scope and action are hyphen-separated.** Use CamelCase within each segment (e.g. `Baseline`, `DefenderAndBitLocker`) — no spaces, no underscores.
- **File names mirror template names.** JSON template for ICB-WIN001-Baseline-DefenderAndBitLocker is `ICB-WIN001-Baseline-DefenderAndBitLocker.json`.

---

## 3. Device persona model

This baseline is deployed around the device populations it protects. Each persona maps to one or more Intune-assigned device categories or Entra ID device-attribute groups that serve as scope targets for templates.

| Persona | Suggested grouping | Typical scope | Notes |
|---------|-------------------|---------------|-------|
| Corporate Windows Workstations | `ICB-Persona-CorpWindows` (dynamic on `deviceOwnership eq 'Company'` + `operatingSystem startsWith 'Windows'` excluding Server SKUs) | Employee laptops and desktops | Primary scope for ICB-WIN001+ |
| Corporate macOS Workstations | `ICB-Persona-CorpMac` (dynamic on `deviceOwnership eq 'Company'` + `operatingSystem startsWith 'macOS'`) | Employee laptops | Primary scope for ICB-MAC001+ (roadmap) |
| Corporate Mobile Devices | `ICB-Persona-CorpMobile` (dynamic on `deviceOwnership eq 'Company'` + `operatingSystem in ('iOS','iPadOS','Android')`) | Phones and tablets issued by the org | Primary scope for ICB-IOS001+ / ICB-AND001+ (roadmap) |
| BYOD Mobile Devices | `ICB-Persona-BYODMobile` (dynamic on `deviceOwnership eq 'Personal'` + mobile OS) | Personal phones enrolled for email and Teams | Same templates as Corp mobile, with retire-on-noncompliance enabled (Section 5) |
| Corporate Linux Workstations | `ICB-Persona-CorpLinux` (manual or dynamic on engineering-team membership) | Engineering laptops, build hosts | Primary scope for ICB-LIN001+ (roadmap) |
| Out-of-scope devices | not grouped | Servers, kiosks, lab / test devices, embedded | Excluded from ICB. Handled by adjacent frameworks or platform-specific tooling. |

### 3.1 Persona naming

The `ICB-Persona-` prefix on groups is intentional: it makes persona groups sortable, searchable, and unambiguous in the Entra admin center, and distinguishes them from the CA framework's `CA-Persona-*` groups, which scope users rather than devices. Avoid reusing business groups (e.g., "All Engineering") as persona scopes — compliance scope and HR scope should not be conflated.

---

## 4. Out-of-scope devices

Compliance baselining is not a universal control. Several device classes are explicitly out of scope:

1. **Servers.** Windows Server, Linux server workloads, and any device managed via System Center / Azure Arc rather than Intune are handled by Defender for Servers or a dedicated server-compliance framework.
2. **Kiosks, point-of-sale, shared single-purpose devices.** Compliance policies designed for general-purpose user endpoints produce noise on devices that are intentionally locked down. Use device configuration profiles and Autopilot self-deploying profiles instead.
3. **Test and lab devices.** Excluded from ICB scope by attribute (suggested: device category `Lab`). These devices need flexibility to install untrusted software for evaluation; subjecting them to the baseline produces false-positive non-compliance with no remediation value.
4. **Devices outside the supported OS version floors** (Section 2.1). Devices on unsupported OS versions are excluded by dynamic group filter, not by per-template exclusion. The OS-version floor enforcement is itself a compliance setting in ICB-WIN002+ (roadmap, Section 8).

---

## 5. Action-for-noncompliance defaults

Every ICB template ships with a `scheduledActionsForRule.scheduledActionConfigurations` block that defines the graduated response when a device evaluates as non-compliant. The default sequence applied to all ICB-WIN001+ templates:

| Order | Action | Grace period | Effect |
|-------|--------|--------------|--------|
| 1 | `notification` (push + email) | 0 days (immediate on detection) | User-visible alert; `deviceComplianceState` remains `inGracePeriod` for CA consumption; no CA impact |
| 2 | `block` | 7 days from detection | `deviceComplianceState` flips to `noncompliant`; CA `compliantDevice` grants begin denying |
| 3 | `retire` (BYOD personas only) | 30 days from detection | Selective wipe of corporate data; device is unenrolled |

The 7-day block window is the self-remediation grace period defended by Principle 1.3 (Compliance as a graded scale). It can be tightened on a per-template basis for high-assurance device classes — for example, an ICB-WIN-PRIV### template targeting workstations used by privileged admins might use a 24-hour window. Templates that tighten the default must justify the tighter window in the template's per-spec section in this document.

The retire action is intentionally never applied to corporate-owned devices via the compliance path. Corporate-device retirement is a separate operational decision made by IT, not an automated consequence of a compliance miss.

---

## 6. Signal handoff to the Conditional Access Baseline

ICB produces exactly one signal that the CA framework consumes:

- **Object:** Device (per-user, per-device)
- **Field:** `deviceComplianceState`
- **Values:** `compliant`, `noncompliant`, `inGracePeriod`, `configManager`, `error`, `notEvaluated`
- **Consumer in the CA framework today:** `CA-SIG001-SensApps-RequireCompliantDevice` (v1.0.0), via the `compliantDevice` built-in grant control in `grantControls.builtInControls`.

### 6.1 Mapping table

| ICB signal value | CA grant control evaluation |
|-------------------|-----------------------------|
| `compliant` | Grants `compliantDevice`. Access allowed (subject to other CA conditions). |
| `inGracePeriod` | Grants `compliantDevice`. Access allowed. This is the operational implementation of Principle 1.3 — the 7-day grace window is what makes the graded scale visible to CA. |
| `noncompliant` | Denies `compliantDevice`. CA-SIG001 blocks; other CA policies that consume the same control deny their grant. |
| `error`, `notEvaluated`, `configManager` | Denies `compliantDevice` in the default CA evaluation. Investigate before enforcement — these states indicate Intune-side health issues, not device-side non-compliance. |

### 6.2 What this framework deliberately does NOT do

- **ICB does not reference CA grant controls or CA policy IDs anywhere in its templates.** The handoff is one-way (ICB produces; CA consumes) and stateless.
- **ICB does not implement access controls of its own.** A device evaluated as non-compliant is non-compliant for CA's purposes; it is not blocked by Intune from anything Intune itself does not gate (app deployments, configuration profile delivery). Those continue to flow.
- **ICB does not consume Conditional Access signals.** Compliance evaluation is independent of where, when, or how the user signed in.

---

## 7. Rollout sequence

Templates are staged, evaluated against the production fleet, and promoted in the following order. Each step has a minimum observation period before the action-for-noncompliance escalates to `block` at +7 days per Section 5.

| Order | Template | Minimum observation period | Why this order |
|-------|----------|----------------------------|----------------|
| 1 | ICB-WIN001-Baseline-DefenderAndBitLocker | 14 days | Highest-impact platform (largest fleet for most adopters), all-OS-native controls, minimal user-facing friction |
| 2 | ICB-WIN002+ hardenings (Secure Boot, Code Integrity, OS version floor, password / PIN, EALAM, Healthy Device Report — see Section 8 roadmap) | per-template; 14 days minimum | Built atop WIN001; each hardening has different fleet-readiness implications |
| 3 | ICB-MAC001+ (roadmap) | 14 days | macOS fleet typically smaller than Windows; sequencing after WIN allows lessons from WIN rollout |
| 4 | ICB-IOS001+ / ICB-AND001+ (roadmap) | 14 days | Mobile fleet includes BYOD; retire-on-noncompliance flow requires extra adopter coordination |
| 5 | ICB-LIN001+ (roadmap) | 21 days | Linux fleet typically smallest, most heterogeneous; longer observation window |

**The observation period is not a Conditional Access concept** — there is no `enabledForReportingButNotEnforced` equivalent in Intune compliance policies. The observation period is implemented operationally: deploy the policy with the action-for-noncompliance sequence in Section 5 in effect, monitor `deviceComplianceState` across the fleet for 14 days *before* the CA `compliantDevice` grant control is enforced (i.e., before the corresponding CA-SIG001-class policy moves out of report-only). Adopters who already enforce CA-SIG001 in production must coordinate the two timelines carefully: turning on a new ICB template against an already-enforced CA-SIG001 means non-compliance produces immediate CA denial after the 7-day grace window with no buffer for the adopter to inventory non-compliant devices.

---

## 8. Per-template design specifications

Each ICB-* template is specified below. Every spec follows the same structure: intent, principle mapping, scope, evaluated settings, action-for-noncompliance, license requirements, validation steps, and the JSON template path.

The first specification — ICB-WIN001 — is included. Subsequent templates are added in their own PRs as they ship.

---

### 8.1 ICB-WIN001-Baseline-DefenderAndBitLocker

**Intent:** Verify that the foundational Windows device-security controls are active and reporting healthy on every corporate Windows workstation. Establishes the minimum compliance floor that `CA-SIG001-SensApps-RequireCompliantDevice` consumes via the `compliantDevice` grant control.

**Principle mapping:** Primary — 1.2 Verify, don't enforce. Every setting in this template verifies an OS-native or Defender-native control; none of them implement the control themselves. Secondary — 1.1 Platform-led scope: Windows-specific evaluations, no cross-platform abstraction.

#### Scope

- Included devices: `ICB-Persona-CorpWindows` (Section 3)
- Excluded devices: Lab category, devices outside supported OS version floor (handled by group filter)
- Platforms: Windows 10 (22H2 supported channel), Windows 11

#### Evaluated settings

The template reproduces the nine active settings from the production source-of-truth export (committed Tue May 12, 2026), each citing the upstream enforcement layer:

| Setting | Verifies | Upstream enforcement layer |
|---------|----------|----------------------------|
| `bitLockerEnabled` | BitLocker is enabled and the system drive is being protected | Windows (BitLocker Drive Encryption) |
| `storageRequireEncryption` | System drive encryption is reporting active to the Windows Security Center | Windows (BitLocker, evaluated via WSC) |
| `activeFirewallRequired` | Windows Defender Firewall is enabled across all three profiles (Domain / Private / Public) | Windows (Defender Firewall) |
| `tpmRequired` | TPM 1.2 or newer is present and reporting active | Windows (TPM 2.0 hardware on Win 11 baseline) |
| `antivirusRequired` | An AV product registered with the Windows Security Center is reporting healthy | Vendor AV (Defender or third-party, registered via WSC) |
| `defenderEnabled` | Microsoft Defender Antivirus service is running | Microsoft Defender Antivirus |
| `signatureOutOfDate` | Defender signature definitions are within the configured tolerance (default: 1 day) | Microsoft Defender Antivirus signature update channel |
| `rtpEnabled` | Defender real-time protection is enabled | Microsoft Defender Antivirus |
| `deviceThreatProtectionEnabled` with `deviceThreatProtectionRequiredSecurityLevel=medium` | Microsoft Defender for Endpoint is reporting machine-risk score at or below `medium` | Microsoft Defender for Endpoint (mobile-threat-defense connector path) |

#### Action-for-noncompliance

Default sequence from Section 5 (notify at 0, block at +7 days, no retire — corporate-owned). No template-specific tightening.

**License requirements:** Microsoft Intune (Plan 1 minimum). Settings 8.1.5 through 8.1.8 require Microsoft Defender Antivirus (in-box on Windows 10 22H2 and Windows 11; no additional license). Setting 8.1.9 requires Microsoft Defender for Endpoint Plan 1 minimum, configured as the Mobile Threat Defense connector in Intune.

#### Validation in observation period

- Confirm every device in `ICB-Persona-CorpWindows` reports `deviceComplianceState` of `compliant` or `inGracePeriod` for 14 consecutive days before the corresponding CA-SIG001 policy is promoted out of report-only (or, if CA-SIG001 is already enforced in production, before this template is deployed at fleet scale)
- Run Intune's compliance reporting dashboard; identify any device returning `error` or `notEvaluated` and remediate the Intune-side health issue before the action-for-noncompliance escalates
- Validate the Defender for Endpoint MTD connector is enabled and the device-risk signal is flowing — without it, setting 8.1.9 evaluates as `notEvaluated` rather than `compliant`
- Coordinate with the CA framework owner before promoting: the handoff to CA-SIG001 is the moment ICB-WIN001 starts producing user-visible access decisions

**JSON template:** `../Policies/ICB-WIN001-Baseline-DefenderAndBitLocker.json` (ships in PR C, paired with this PR)

---

## 9. Roadmap

The following ICB-WIN### hardenings are scoped for delivery between week 1 and Q3 2026 framework completion. They are deliberately deferred from ICB-WIN001 to keep the first template a faithful mirror of the production source-of-truth export (Option A decision, Tue May 12, 2026) and to limit the surface that has to soak during initial rollout.

| Planned template | Verifies | Notes |
|------------------|----------|-------|
| ICB-WIN002-Hardening-SecureBoot | Secure Boot is enabled in firmware | UEFI / firmware dependency; fleet-readiness gating |
| ICB-WIN003-Hardening-CodeIntegrity | Memory Integrity (HVCI) is enabled | Driver-compatibility implications; vendor coordination |
| ICB-WIN004-Baseline-OSVersionFloor | OS build is at or above the supported floor | Windows 10 22H2 supported channel; Windows 11 23H2 minimum |
| ICB-WIN005-Hardening-PasswordPIN | Local password / PIN complexity meets configured threshold | Coordinates with Windows Hello for Business deployment status |
| ICB-WIN006-Hardening-EALAM | Early-launch anti-malware driver is loaded | Boot-time integrity signal |
| ICB-WIN007-Attestation-HealthyDeviceReport | Device Health Attestation reports the device as healthy | TPM-attested boot state; requires DHA service |

Corresponding ICB-MAC###, ICB-IOS###, ICB-AND###, and ICB-LIN### roadmap templates are scoped per platform and will be added to this section in their own PRs.

---
