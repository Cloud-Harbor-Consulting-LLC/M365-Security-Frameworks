# Intune Compliance Baseline — Policy Design

This document specifies the design philosophy, naming convention, device persona model, actions for noncompliance, signal handoff to the Conditional Access Baseline, prerequisites, and rollout sequence for the Intune Compliance Baseline (ICB) framework. It is the prerequisite reading for anyone deploying, extending, or auditing the baseline.

Section 8 specifies all 11 templates in the v1.0 set. Until v1.0.0 ships, a specification whose JSON template has not yet been added to `Policies/` says so.

---

## 1. Design philosophy

A compliance baseline is the verification layer beneath every "require compliant device" Conditional Access decision. Without a defensible compliance baseline, the CA grant control `compliantDevice` either lets through devices that should not pass, or blocks devices that should — neither is acceptable.

Six principles anchor every design decision in this framework. Section 1.7 records where the baseline departs from its sources, and why.

### 1.1 Platform-led scope

**What it means:** Compliance evaluation differs fundamentally across platforms. Windows has TPM, BitLocker, Defender, and Group Policy / CSP. macOS has Secure Enclave, FileVault, XProtect, and MDM-only enforcement. iOS / Android / Linux each have their own primitives. A "unified compliance policy" abstraction across platforms either weakens to the lowest common denominator or creates silent blind spots where a platform-specific control is omitted because no cross-platform equivalent exists.

**How this baseline implements it:** Every policy template is platform-specific. The naming convention enforces it: ICB-WIN###, ICB-MAC###, ICB-IOS###, ICB-AND###, ICB-LIN###. There is no ICB-ALL### or ICB-ANY### in this framework, by design. A device with two operating systems (a Windows / Linux dual-boot engineering workstation, an iPad with macOS Sidecar) is two compliance evaluations, not one. Android goes one step further: Intune treats corporate-owned devices and personally owned work profiles as separate profile types with different settings, so ICB ships a template for each.

### 1.2 Verify, don't enforce

**What it means:** Intune Compliance Policies evaluate that an OS-native or vendor-native control is *active and reporting healthy*. They do not implement the control. BitLocker is enforced by Windows. Microsoft Defender Antivirus is enforced by Defender. The Firewall is enforced by the OS. Conflating verification with enforcement creates two failure modes: adopters skip the underlying configuration step because they think the compliance policy "enables" the control, and remediation effort lands on Intune when the actual problem is at the OS / AV vendor / firewall layer.

**How this baseline implements it:** Every setting in every ICB-* template names the vendor / OS control it verifies, not the control itself. ICB-WIN001's `bitLockerEnabled` setting verifies that BitLocker is enabled and reporting; it does not encrypt the disk. ICB-WIN001's `defenderEnabled` setting verifies that the Defender service is running; it does not install Defender. Per-template specs cite the upstream enforcement layer for every setting.

### 1.3 Compliance as a graded scale

**What it means:** Intune's compliance model is not binary. It includes evaluated states (Compliant, NotCompliant, InGracePeriod, ConfigManager, Error, NotEvaluated) and time-windowed evaluation through `scheduledActionsForRule`. Collapsing this to a binary "pass / fail" the moment a setting evaluates as non-compliant creates avoidable user-impacting outages — a signature file a few hours stale, a device that finished encrypting but has not restarted, all become Conditional Access blocks rather than soft notifications.

**How this baseline implements it:** Hygiene settings on Windows, macOS and Linux — the settings that fluctuate in normal operation — carry a 7-day grace period before the device is marked noncompliant (Section 5). The user is emailed when the device first fails. Two classes of template get no grace period: risk signals (Principle 1.4) and the mobile templates, which follow Microsoft's mobile security configuration frameworks and the CIS iOS benchmark in marking a device noncompliant immediately.

### 1.4 Risk signals carry no grace period

**What it means:** A grace period exists so a user can fix a setting that drifted. A threat verdict is different: when Microsoft Defender for Endpoint rates a device high-risk, the device is likely compromised, and nothing the user does in the next week changes that. Intune treats a device in its grace period as compliant, and Conditional Access does the same, so a grace period on a risk signal keeps a likely-compromised device inside Conditional Access for the length of the window.

**How this baseline implements it:** Risk and threat signals live in their own templates, separate from hygiene settings, and mark the device noncompliant at 0 hours. ICB-WIN008 is the first. Any template that adds a risk signal later follows the same rule.

### 1.5 Unlock credentials and account passwords

**What it means:** "Password" in an Intune compliance policy means different things on different platforms. On Entra-joined Windows 11 the password rules set the device unlock credential, which is the Windows Hello PIN: Microsoft merged the device PIN and the Windows Hello PIN into one, and the password rules in a compliance policy set it. On iOS/iPadOS and Android they set the device passcode. On Linux they govern local account passwords.

**How this baseline implements it:** Device unlock credentials (the Windows Hello PIN, mobile passcodes) follow Microsoft's security configuration frameworks: a minimum of 6, simple sequences blocked. Account passwords (Linux local accounts) follow Microsoft's password guidance: a minimum of 14 characters with no composition rules. **Neither expires**, following NIST SP 800-63B, which advises against periodic changes to memorized secrets, and Microsoft's password guidance.

### 1.6 Signal-clean handoff to Conditional Access

**What it means:** Compliance and access are separate concerns operated by separate frameworks. The Intune Compliance Baseline owns *what makes a device compliant*. The Conditional Access Baseline owns *what compliance unlocks*. Mixing them — putting access decisions inside compliance policies, or putting compliance criteria inside Conditional Access — produces two systems that contradict each other under change.

**How this baseline implements it:** ICB produces exactly one signal that CA consumes: the device's compliance state, surfaced to CA through the `compliantDevice` built-in grant control and the `device.isCompliant` device filter. Section 6 lists the CA policies that consume it. No CA policy enforces a compliance setting directly; no ICB template references a CA policy or a CA grant control.

### 1.7 Sources, and where ICB departs from them

ICB's values come from Microsoft's published guidance: the recommended compliance settings in Microsoft's Zero Trust identity and device access policies (Enterprise protection level), and Level 2 ("enhanced") of Microsoft's security configuration frameworks for iOS/iPadOS and Android Enterprise, which that guidance maps to the Enterprise level. Each value was cross-checked against the CIS Benchmarks for the same platforms: Microsoft Intune for Windows 11, Apple macOS 26 Tahoe Intune, Apple iOS 26 and iPadOS 26 Intune, Google Android, Ubuntu Linux 24.04 LTS, and Red Hat Enterprise Linux 9, with the CIS Red Hat Enterprise Linux 9 STIG Benchmark as a stricter reference. Most CIS benchmarks are configuration benchmarks, so they confirm the device state ICB verifies rather than the compliance policy itself; the iOS benchmark is the exception, with a compliance-policy section.

ICB departs from these sources deliberately in the following places:

| Where | Source says | ICB does | Why |
|---|---|---|---|
| Template structure | Microsoft: one compliance policy for each platform | Splits Windows into six templates | Each control soaks and rolls out on its own timeline (Section 7). Cost: a device failing several Windows templates gets one email per template. |
| Credential expiry | Microsoft's Windows compliance table: 41 days. Android fully managed, Level 2: 365 days. CIS Ubuntu 24.04 and RHEL 9: 365 days (5.4.1.1). RHEL 9 STIG: 60 days. | No expiry on any template | Principle 1.5. CIS itself recommends never-expiring passwords for Microsoft 365 cloud accounts (CIS Microsoft 365 Foundations 1.3.1). |
| Grace period on desktop hygiene settings | Intune's default schedules "Mark device noncompliant" at 0 days | 7 days on WIN001–WIN005, MAC001 and LIN001 | Principle 1.3. Risk signals and the mobile templates stay at 0 hours. |
| Linux disk encryption | CIS Ubuntu 24.04 and RHEL 9 have no disk-encryption recommendation | LIN001 requires encryption | The RHEL 9 STIG requires it at CAT I (RHEL-09-231190), and Intune's Linux compliance evaluates it natively. |
| Android security patch level | — | Left unset, as Microsoft's frameworks leave it at every level | Patch delivery depends on the device maker and carrier. Section 8.9 explains how to add it for fleets that receive monthly patches. |

---

## 2. Naming convention

Every policy in this baseline follows the format:

```
ICB-[PlatformPrefix][Number]-[Scope]-[Action]
```

### 2.1 Platform prefixes

| Prefix | Platform | Operating systems in scope |
|--------|----------|-----------------------------|
| WIN | Windows | Windows 11. Windows 10, including devices on Extended Security Updates, is out of scope and evaluates noncompliant (Section 4.4). |
| MAC | macOS | macOS 15 and newer |
| IOS | iOS / iPadOS | iOS 18 and newer; iPadOS 18 and newer |
| AND | Android | Android 10 and newer, Android Enterprise. Corporate-owned (fully managed, dedicated, corporate-owned work profile) and personally owned work profile are separate templates. |
| LIN | Linux | Ubuntu Desktop 24.04 LTS and newer; RHEL 9 and newer |

Platforms outside this list (Windows Server, ChromeOS, embedded / kiosk devices, point-of-sale terminals) are out of scope for this framework and are handled by adjacent frameworks (Defender for Servers, dedicated kiosk management) or left to platform-specific tooling.

### 2.2 Rules

- **One platform prefix per template.** A device that runs two operating systems is two compliance evaluations.
- **Numbers are sequential within a prefix.** ICB-WIN001 comes before ICB-WIN002; retired templates keep their number permanently. Numbers that appeared on the public roadmap but never shipped are not reused (Section 9.2).
- **Scope and action are hyphen-separated.** Use CamelCase within each segment (e.g. `Baseline`, `DefenderAndBitLocker`) — no spaces, no underscores.
- **File names mirror template names.** JSON template for ICB-WIN001-Baseline-DefenderAndBitLocker is `ICB-WIN001-Baseline-DefenderAndBitLocker.json`.

### 2.3 OS version floors

Every floor follows one rule, reviewed annually: **the oldest version still in vendor servicing for the edition in use, and within Intune's Supported tier.** Each template carries the value that rule produces at its ship date, and the CHANGELOG records each annual change.

| Platform | Floor at v1.0 | How the rule produced it |
|---|---|---|
| Windows 11 | Build 26200 (25H2) | 24H2 Home and Pro servicing ends 2026-10-13. The floor follows the Home/Pro timeline, which also covers Windows 11 Business on Microsoft 365 Business Premium (a Pro-edition upgrade). |
| macOS | 15.0 | Intune's Supported tier starts at macOS 15 |
| iOS / iPadOS | 18.0 | Intune's Supported tier starts at iOS 18 |
| Android | 10.0 | Intune's Supported tier for user-based Android Enterprise starts at Android 10. Fleets of current devices should raise it. |
| Linux | Ubuntu 24.04, RHEL 9 | Intune supports Ubuntu Desktop 24.04 and 26.04 LTS, and RHEL 9 and 10 |

**Windows Enterprise, Education and LTSC fleets** get 36 months of servicing rather than 24, so build 26100 (24H2, and Windows 11 LTSC 2024) remains serviced for them after the Home/Pro date. A fleet made up only of those editions can lower ICB-WIN004's floor to `10.0.26100.0`. A single build floor cannot tell editions apart, so the shipped value follows the shorter timeline and never admits a build that is out of servicing.

### 2.4 Graph beta endpoint commitment

Every template targets the Microsoft Graph **beta** endpoint, because 7 of ICB-WIN001's original 9 settings exist only on beta. Rather than maintain two endpoint paths, the framework commits every template to beta, as the Conditional Access Baseline does.

Templates follow the wire format Intune writes, captured from a live tenant, wherever it differs from the documentation. Two examples: Android Play Integrity is still written as `SafetyNet` properties, and Microsoft Defender for Endpoint risk is `deviceThreatProtection*` on Windows but `advancedThreatProtectionRequiredSecurityLevel` on Android, macOS and iOS.

---

## 3. Device persona model

This baseline is deployed around the device populations it protects. Each persona maps to one or more Intune-assigned device categories or Entra ID device-attribute groups that serve as scope targets for templates.

| Persona | Suggested grouping | Typical scope | Templates |
|---------|-------------------|---------------|-------|
| Corporate Windows Workstations | `ICB-Persona-CorpWindows` (dynamic on `deviceOwnership eq 'Company'` + `operatingSystem startsWith 'Windows'` excluding Server SKUs) | Employee laptops and desktops | ICB-WIN001 to WIN005, WIN008 |
| Corporate macOS Workstations | `ICB-Persona-CorpMac` (dynamic on `deviceOwnership eq 'Company'` + `operatingSystem startsWith 'macOS'`) | Employee laptops | ICB-MAC001 |
| Corporate Mobile Devices | `ICB-Persona-CorpMobile` (dynamic on `deviceOwnership eq 'Company'` + `operatingSystem in ('iOS','iPadOS','Android')`) | Phones and tablets issued by the org | ICB-IOS001, ICB-AND001 |
| BYOD Mobile Devices | `ICB-Persona-BYODMobile` (dynamic on `deviceOwnership eq 'Personal'` + mobile OS) | Personal phones enrolled for email and Teams | ICB-IOS001, ICB-AND002 (with the retire-list action, Section 5.3) |
| Corporate Linux Workstations | `ICB-Persona-CorpLinux` (manual or dynamic on engineering-team membership) | Engineering laptops, build hosts | ICB-LIN001 |
| Out-of-scope devices | not grouped | Servers, kiosks, lab / test devices, embedded | Excluded from ICB. Handled by adjacent frameworks or platform-specific tooling. |

The grouping expressions are shorthand for the intent. Write each one in Entra ID's dynamic membership rule syntax, using the operating-system values your tenant's device objects actually report. Android dedicated devices are an exception to user-affinity grouping: Microsoft recommends assigning their compliance policy to device groups, and users on dedicated devices enrolled without Microsoft Entra shared device mode cannot reach Conditional Access-protected resources even when the device is compliant.

### 3.1 Persona naming

The `ICB-Persona-` prefix on groups is intentional: it makes persona groups sortable, searchable, and unambiguous in the Entra admin center, and distinguishes them from the CA framework's `CA-Persona-*` groups, which scope users rather than devices. Avoid reusing business groups (e.g., "All Engineering") as persona scopes — compliance scope and HR scope should not be conflated.

---

## 4. Out-of-scope devices

Compliance baselining is not a universal control. Several device classes are explicitly out of scope. Under the tenant prerequisite in Section 7.1, any enrolled device that no compliance policy targets is marked **Not compliant**, so an out-of-scope device that also needs to reach Conditional Access-protected resources needs its own compliance policy or a deliberate Conditional Access exclusion. That is the intended result: a device should not reach protected data because nothing evaluated it.

1. **Servers.** Windows Server, Linux server workloads, and any device managed via System Center / Azure Arc rather than Intune are handled by Defender for Servers or a dedicated server-compliance framework.
2. **Kiosks, point-of-sale, shared single-purpose devices.** Compliance policies designed for general-purpose user endpoints produce noise on devices that are intentionally locked down. Use device configuration profiles and Autopilot self-deploying profiles instead.
3. **Test and lab devices.** Excluded from ICB scope by attribute (suggested: device category `Lab`). These devices need flexibility to install untrusted software for evaluation; subjecting them to the baseline produces false-positive non-compliance with no remediation value.
4. **Devices below the OS version floors stay in scope.** They are not excluded by group filter. Excluding them would take them out of every compliance policy, and under Intune's default tenant setting a device with no compliance policy is treated as compliant, so the oldest devices would pass Conditional Access. Instead they stay in their persona group and the platform's floor setting (ICB-WIN004 on Windows; the OS minimum in each other platform's template) marks them noncompliant. Windows 10 devices, including those on Extended Security Updates, are treated this way. Inventory them in observation mode before enforcing (Section 7).

---

## 5. Actions for noncompliance

Every ICB template ships with a `scheduledActionsForRule.scheduledActionConfigurations` block that defines the response when a device evaluates as noncompliant. Intune calls the actions ICB uses "Send email to end user" (`notification`), "Mark device noncompliant" (`block`) and "Add device to retire list". The mark-noncompliant action cannot be removed from a policy; only its schedule can change, from 0 to 365 days. Until it fires, the device is in its grace period and both Intune and Conditional Access treat it as compliant.

### 5.1 Designed schedules (`-Enforce`)

| Templates | Email the user | Mark noncompliant | Add to retire list |
|---|---|---|---|
| ICB-WIN001 to WIN005, ICB-MAC001, ICB-LIN001 | 0 hours | 168 hours (7 days) | — |
| ICB-WIN008 | 0 hours | 0 hours | — |
| ICB-IOS001, ICB-AND001 | 0 hours | 0 hours | — |
| ICB-AND002 | 0 hours | 0 hours | 30 days |

The 7-day window is the self-remediation grace period defended by Principle 1.3. It applies only to desktop hygiene settings. A template that tightens or loosens its schedule justifies the change in its specification in Section 8.

The email action needs an Intune notification message template, which must exist before deployment (Section 7.1).

### 5.2 Observation mode (the deployer's default)

Deploy-ICBaseline deploys every template in **observation mode** unless it is run with `-Enforce`. In observation mode each template marks noncompliant at 365 days, the maximum Intune allows, and sends no email. Devices report real compliance results in Intune, while Conditional Access still treats every device as compliant. `-Enforce` applies the schedules in Section 5.1.

Observation mode is the Intune counterpart of the Conditional Access Baseline's report-only default. Intune compliance policies have no report-only state, and a policy cannot be deployed without its mark-noncompliant action, so a long grace period is the only way to observe without blocking anyone.

### 5.3 The retire list

ICB-AND002's third action is "Add device to retire list". Microsoft implements it as a list, not a wipe: the device is not retired, and no data is removed, until an administrator retires it from the list. Retiring a personally owned work-profile device removes the work profile and its corporate data and leaves the user's personal data in place.

The retire-list action is never applied to corporate-owned devices through the compliance path. Corporate-device retirement is an operational decision made by IT, not an automated consequence of a compliance miss. ICB-IOS001 has no retire-list action because one template serves both corporate and personal iOS devices, and Intune applies a policy's actions to every device the policy targets.

---

## 6. Signal handoff to the Conditional Access Baseline

ICB produces exactly one signal that the CA framework consumes:

- **Object:** Device (per-user, per-device)
- **Field:** the device's compliance state, which Microsoft Entra exposes to Conditional Access as `isCompliant`
- **Intune states:** `compliant`, `noncompliant`, `inGracePeriod`, `configManager`, `error`, `notEvaluated`

Four policies in the Conditional Access Baseline consume it:

| CA policy | How it uses the signal | Scope |
|---|---|---|
| `CA-COV008-Internal-RequireCompliantDeviceOnDesktops` | Grant: `compliantDevice` or `domainJoinedDevice` | Internal users, all applications, Windows, macOS and Linux |
| `CA-SIG001-SensitiveApps-RequireCompliantDevice` | Grant: `compliantDevice` or `domainJoinedDevice` | Internal users, Azure Service Management, every platform |
| `CA-COV014-AgentUsers-RequireCompliantDevice` | Grant: `compliantDevice` | Agent user accounts on Windows 365 Cloud PCs for Agents |
| `CA-COV003-Global-NoPersistentBrowserSessionOnNonCorpDevices` | Device filter: a compliant (or hybrid-joined) device is excluded from the 4-hour browser session limit | All users, browser sessions, every platform except iOS and Android |

Two consequences for adopters:

- **Hybrid-joined devices bypass the signal in CA-COV008 and CA-SIG001.** Both grant access to a compliant device *or* a hybrid Microsoft Entra joined one, so a hybrid-joined Windows device passes them whatever its ICB result. ICB's evaluation still applies to hybrid-joined devices that are enrolled in Intune; it gates access only where Conditional Access requires compliance alone.
- **On iOS and Android, ICB gates Azure Service Management only.** CA-COV008 covers desktop platforms, so in the baseline as shipped, mobile compliance results reach access decisions only through CA-SIG001. They are still the evidence that mobile devices meet the baseline, and an adopter who wants mobile compliance to gate Microsoft 365 apps adds a policy that requires it.

### 6.1 Mapping table

| ICB signal value | CA grant control evaluation |
|-------------------|-----------------------------|
| `compliant` | Grants `compliantDevice`. Access allowed (subject to other CA conditions). |
| `inGracePeriod` | Grants `compliantDevice`. Access allowed. This is how the hygiene templates' 7-day grace period and the deployer's observation mode work: the device fails a setting, Intune reports it, and Conditional Access still lets it through. |
| `noncompliant` | Denies `compliantDevice`. CA-COV008 and CA-SIG001 block unless the device is hybrid-joined; CA-COV014 blocks. |
| `error`, `notEvaluated`, `configManager` | Denies `compliantDevice` in the default CA evaluation. Investigate before enforcement — these states indicate Intune-side health issues, not device-side non-compliance. |

A device that no compliance policy targets has no ICB result at all. What Conditional Access sees then depends on the tenant setting in Section 7.1: under Intune's default it is reported compliant, which is why ICB requires that setting be changed.

### 6.2 What this framework deliberately does NOT do

- **ICB does not reference CA grant controls or CA policy IDs anywhere in its templates.** The handoff is one-way (ICB produces; CA consumes) and stateless.
- **ICB does not implement access controls of its own.** A device evaluated as non-compliant is non-compliant for CA's purposes; it is not blocked by Intune from anything Intune itself does not gate (app deployments, configuration profile delivery). Those continue to flow.
- **ICB does not consume Conditional Access signals.** Compliance evaluation is independent of where, when, or how the user signed in.

---

## 7. Prerequisites and rollout sequence

### 7.1 Prerequisites

Tenant-wide settings (Intune admin center, Endpoint security > Device compliance > Compliance policy settings). They apply to every compliance policy in the tenant, so Deploy-ICBaseline checks them and warns but never changes them.

- **Mark devices with no compliance policy assigned as: Not compliant.** Intune's default is Compliant, which lets an enrolled device that no compliance policy targets pass Conditional Access's "require compliant device". Microsoft recommends Not compliant wherever Conditional Access consumes compliance; so do the CIS Microsoft 365 Foundations Benchmark (4.1) and the CIS iOS Intune Benchmark (4.6). With it set, the Company Portal tells an affected user "No compliance policies have been assigned". Side effect: devices deliberately kept out of ICB become noncompliant (Section 4).
- **Compliance status validity period: 7 days or fewer** (Intune default 30, range 1 to 120), per the CIS iOS Intune Benchmark (4.7). A device that has not reported its compliance within the period is marked noncompliant, so a lost or abandoned device stops counting as compliant within a week rather than a month. A device that returns after a longer absence is re-evaluated when it next checks in.
- **A notification message template** for the email action, created under the compliance policy notifications in the Intune admin center. Deploy-ICBaseline resolves it by name.

Windows:

- **Microsoft Azure Attestation endpoints are reachable.** On Windows 11, any of the device health settings (BitLocker, Secure Boot, code integrity) attests through Microsoft Azure Attestation endpoints for the tenant's region (`intunemaape*.attest.azure.net`), over HTTPS with no SSL inspection. A device that cannot reach them falls out of compliance on WIN001, WIN002 and WIN003. Find the region under Tenant administration › Tenant status, and allow every endpoint Microsoft lists for it.
- **Microsoft Defender Antivirus is the active antivirus.** WIN001's Defender settings read Defender Antivirus; with a third-party antivirus, Defender runs in passive mode and those settings fail.
- **Microsoft Defender for Endpoint is connected to Intune** for ICB-WIN008 (Section 8.6).

### 7.2 Rollout sequence

Templates are deployed in observation mode (Section 5.2), evaluated against the fleet, and then enforced, in the following order. Each step has a minimum observation period before `-Enforce`.

| Order | Template | Minimum observation period | Why this order |
|-------|----------|----------------------------|----------------|
| 1 | ICB-WIN001, ICB-WIN008 | 14 days | Highest-impact platform (largest fleet for most adopters), all-OS-native controls, minimal user-facing friction |
| 2 | ICB-WIN002 to WIN005 | 14 days each | Built atop WIN001. Each has its own fleet-readiness question: Secure Boot and firmware, code integrity, devices below the build floor, and the PIN change at next sign-in. |
| 3 | ICB-MAC001 | 14 days | macOS fleet typically smaller than Windows; sequencing after WIN allows lessons from WIN rollout |
| 4 | ICB-IOS001, ICB-AND001, ICB-AND002 | 14 days | Mobile fleet includes personal devices, and these templates mark noncompliant immediately once enforced |
| 5 | ICB-LIN001 | 21 days | Linux fleet typically smallest, most heterogeneous; longer observation window |

Observation mode makes the observation period a real state of the policy rather than a convention. During it, review Intune's compliance reports for every assigned device: which settings fail, which devices return `error` or `notEvaluated`, and which devices sit below the floor. Enforce a template only once its failures are understood.

**Coordinate with Conditional Access.** An adopter whose CA-COV008 or CA-SIG001 is already enforced must deploy ICB in observation mode first: enforcing a template against an enforced CA policy turns every failing device into a sign-in block as soon as the template's schedule fires, immediately for WIN008 and the mobile templates.

---

## 8. Per-template design specifications

Each ICB-* template is specified below. Every spec follows the same structure: intent, scope, evaluated settings, actions for noncompliance, license requirements, validation, and the JSON template path. Setting names are the Graph property names Intune writes, captured from a live tenant. Specifications whose templates have not yet been added to `Policies/` are marked as such.

---

### 8.1 ICB-WIN001-Baseline-DefenderAndBitLocker

**Intent:** Verify that the foundational Windows device-security controls are active and reporting healthy on every corporate Windows workstation. The settings are Microsoft's recommended Windows compliance settings for the Zero Trust Enterprise protection level, less those that ICB-WIN002 to WIN005 and WIN008 verify.

**Principle mapping:** Primary — 1.2 Verify, don't enforce. Secondary — 1.3 Compliance as a graded scale: every setting here is a hygiene setting that can drift and be fixed.

**Scope:** `ICB-Persona-CorpWindows`. Windows 11.

#### Evaluated settings

| Setting | Verifies | Upstream enforcement layer |
|---------|----------|----------------------------|
| `bitLockerEnabled` | BitLocker is on, as attested at boot | Windows (BitLocker Drive Encryption) |
| `storageRequireEncryption` | Data storage on the device is encrypted | Windows (BitLocker) |
| `activeFirewallRequired` | Microsoft Defender Firewall is on | Windows (Defender Firewall) |
| `tpmRequired` | A TPM is present | Device hardware |
| `antivirusRequired` | An antivirus product registered with Windows Security is on and monitoring | Defender Antivirus or another registered product |
| `antiSpywareRequired` | An antispyware product registered with Windows Security is on and monitoring | Defender Antivirus or another registered product |
| `defenderEnabled` | Microsoft Defender Antivirus is on | Microsoft Defender Antivirus |
| `defenderVersion` | Defender's antimalware platform is no more than five versions behind the current release | Microsoft Defender Antivirus platform updates |
| `signatureOutOfDate` | Defender's security intelligence is up to date | Microsoft Defender Antivirus update channel |
| `rtpEnabled` | Defender real-time protection is on | Microsoft Defender Antivirus |

`tpmRequired` is not in Microsoft's table. ICB keeps it because, with Windows 10 out of scope, it catches Windows 11 installed on hardware with no TPM through the installation requirements bypass.

`bitLockerEnabled` is measured at boot, so a device that finishes encrypting reports compliant only after a restart. That is one reason this template keeps a grace period.

**Maintenance:** `defenderVersion` is set at each release to the current Defender platform version minus five, following Microsoft's "no more than five versions behind" recommendation. Defender's platform updates monthly, so the value loosens over time without ever causing an outage. Review it quarterly.

**Why five and not two:** Microsoft fully supports only the latest platform release and the two before it; older versions get technical upgrade support only (Microsoft Defender Antivirus security intelligence and product updates and support). Platform releases roll out gradually, so a floor of N-2 would mark healthy devices noncompliant during normal update lag. ICB keeps Microsoft's compliance guidance of five versions, and treats a device more than two behind as an update problem to investigate, not a compliance failure.

**Actions for noncompliance:** email at 0 hours; mark noncompliant at 168 hours (Section 5.1).

**License requirements:** Microsoft Intune Plan 1. The Defender settings need Microsoft Defender Antivirus as the active antivirus (in-box on Windows 11; no additional license).

**Validation:** device-validated on a Windows 11 device in the demo tenant: compliant as designed, and noncompliant with the firewall turned off.

**JSON template:** `../Policies/ICB-WIN001-Baseline-DefenderAndBitLocker.json`. It replaces the v0.1.0-preview template, which also carried the Defender for Endpoint risk setting now in ICB-WIN008 and wrote `signatureOutOfDate` as a number where Graph's type is Boolean.

---

### 8.2 ICB-WIN002-Hardening-SecureBoot

**Intent:** Verify that Secure Boot is enabled, so the boot chain runs only signed components.

**Scope:** `ICB-Persona-CorpWindows`. Windows 11.

**Evaluated settings:** `secureBootEnabled`, attested at boot through Microsoft Azure Attestation (Section 7.1). Upstream: device firmware (UEFI Secure Boot).

**Actions for noncompliance:** email at 0 hours; mark noncompliant at 168 hours.

**License requirements:** Microsoft Intune Plan 1.

**Validation:** device-validated.

**JSON template:** `../Policies/ICB-WIN002-Hardening-SecureBoot.json`

---

### 8.3 ICB-WIN003-Hardening-CodeIntegrity

**Intent:** Verify that Windows code integrity is enabled, so the operating system loads only signed drivers and system files.

**Scope:** `ICB-Persona-CorpWindows`. Windows 11.

**Evaluated settings:** `codeIntegrityEnabled`, attested at boot through Microsoft Azure Attestation (Section 7.1). Upstream: Windows code integrity.

This is not Memory Integrity (hypervisor-protected code integrity, HVCI), which earlier versions of this document planned for WIN003. HVCI is a separate setting, available only on the Graph beta endpoint and not shown in the Intune admin center, so it is deferred with the other virtualization-based security settings (Section 9.3).

**Actions for noncompliance:** email at 0 hours; mark noncompliant at 168 hours.

**License requirements:** Microsoft Intune Plan 1.

**Validation:** device-validated.

**JSON template:** `../Policies/ICB-WIN003-Hardening-CodeIntegrity.json`

---

### 8.4 ICB-WIN004-Baseline-OSVersionFloor

**Intent:** Verify that the device runs a Windows 11 build still in servicing (Section 2.3).

**Scope:** `ICB-Persona-CorpWindows`. Windows 10 devices stay in scope and evaluate noncompliant (Section 4.4).

**Evaluated settings:** `osMinimumVersion` = `10.0.26200.0` (Windows 11 25H2). Enterprise, Education and LTSC 2024 fleets can lower it to `10.0.26100.0` (Section 2.3). The value is re-checked against Microsoft's Windows 11 release information at each release and reviewed annually.

**Actions for noncompliance:** email at 0 hours; mark noncompliant at 168 hours, which gives a device a week to install the feature update.

**License requirements:** Microsoft Intune Plan 1.

**Validation:** device-validated.

**JSON template:** `../Policies/ICB-WIN004-Baseline-OSVersionFloor.json`

---

### 8.5 ICB-WIN005-Hardening-PasswordPIN

**Intent:** Verify that the device unlock credential meets Microsoft's Zero Trust settings. On Entra-joined Windows 11 that credential is the Windows Hello PIN (Principle 1.5).

**Scope:** `ICB-Persona-CorpWindows`. Windows 11.

**Evaluated settings:**

| Setting | Value |
|---|---|
| `passwordRequired` | true |
| `passwordBlockSimple` | true |
| `passwordMinimumLength` | 6 |
| `passwordRequiredType` | `deviceDefault` |
| `passwordMinutesOfInactivityBeforeLock` | 15 |
| `passwordPreviousPasswordBlockCount` | 5 |
| Expiration | not set (Principle 1.5) |

**Coexistence with Windows Hello for Business:** keep these values aligned with the tenant's Windows Hello for Business PIN policy. If both set the PIN, the Windows Hello for Business policy wins, and a compliance rule stricter than it would mark devices noncompliant that the user cannot fix.

**Rollout note:** when the rule first applies, local accounts are prompted to change their password at next sign-in, even when the existing password already meets it.

**Actions for noncompliance:** email at 0 hours; mark noncompliant at 168 hours.

**License requirements:** Microsoft Intune Plan 1.

**Validation:** device-validated.

**JSON template:** `../Policies/ICB-WIN005-Hardening-PasswordPIN.json`

---

### 8.6 ICB-WIN008-Threat-DefenderRiskScore

**Intent:** Mark a device noncompliant as soon as Microsoft Defender for Endpoint rates its machine risk above medium (Principle 1.4).

**Scope:** `ICB-Persona-CorpWindows`. Windows 11.

**Evaluated settings:** `deviceThreatProtectionEnabled` = true; `deviceThreatProtectionRequiredSecurityLevel` = `medium`. Upstream: Microsoft Defender for Endpoint machine risk, through the Intune connector.

**Why medium:** Medium is the level in Microsoft's Zero Trust compliance settings for the Enterprise protection level, which ICB follows. Intune's Defender for Endpoint integration guide recommends Low for most organizations. Because WIN008 has no grace period, Low would mark a device noncompliant, and block it wherever Conditional Access requires compliance, on any medium-severity alert. Tenants that accept that trade can set `low`; the deployer reports the change as drift unless the template is edited.

Split from ICB-WIN001 for v1.0. Under WIN001's 7-day grace period, a device Defender rated high-risk stayed compliant to Conditional Access for a week.

**Actions for noncompliance:** email at 0 hours; mark noncompliant at 0 hours.

**License requirements:** Microsoft Intune Plan 1 and Microsoft Defender for Endpoint, with the Intune connection on in the Defender portal and "Connect Windows devices to Defender for Endpoint" on in Intune (Endpoint security › Microsoft Defender for Endpoint).

**Defender for Business (Microsoft 365 Business Premium): not verified.** WIN008 is validated with Defender for Endpoint Plan 2. Microsoft describes Defender for Business as based on Defender for Endpoint, with endpoint detection and response included, but no Microsoft documentation states that it supplies the machine risk score Intune evaluates, and ICB has not tested it. Business Premium tenants should deploy WIN008 in observation mode and run `-Enforce` only once Intune's device compliance report shows WIN008's risk setting as Compliant or Not compliant, not Not evaluated.

**Validation:** device-validated. Without the connector the setting evaluates as `notEvaluated`, not compliant; confirm the risk signal is flowing before enforcing.

**JSON template:** `../Policies/ICB-WIN008-Threat-DefenderRiskScore.json`

---

### 8.7 ICB-MAC001-Baseline-EncryptionAndIntegrity

**Intent:** Verify the macOS platform protections: FileVault, System Integrity Protection, the firewall and Gatekeeper.

**Scope:** `ICB-Persona-CorpMac`. macOS 15 and newer. Intune does not evaluate compliance on userless macOS devices.

**Evaluated settings:**

| Setting | Value | CIS macOS 26 Tahoe Intune |
|---|---|---|
| `storageRequireEncryption` (FileVault) | true | 2.3.2.1 assumes FileVault is on |
| `systemIntegrityProtectionEnabled` | true | — |
| `firewallEnabled` | true | 2.6.2.2 |
| `firewallEnableStealthMode` | true | 2.6.2.1 |
| `gatekeeperAllowedAppSource` | `macAppStoreAndIdentifiedDevelopers` | 2.12.1.2 |
| `osMinimumVersion` | `15.0` | — |

**Left unset, deliberately:**

- `firewallBlockAllIncoming`: Microsoft warns it blocks all sharing services, including screen sharing and remote access. CIS macOS has no recommendation to block all incoming connections.
- Gatekeeper stays at identified developers (CIS 2.12.1.2). CIS lists blocking all user application installs (2.12.1.3) as a separate, stricter item, which ICB does not adopt.
- **Password settings:** Microsoft warns that requiring a password in a macOS compliance policy expires the existing password of every account on the device, including accounts created by LAPS and Platform SSO. Manage the macOS password with a Settings Catalog configuration policy instead; CIS macOS lists the values for it.

**Actions for noncompliance:** email at 0 hours; mark noncompliant at 168 hours.

**License requirements:** Microsoft Intune Plan 1.

**Validation:** tenant-validated, not device-validated. Device validation is a v1.0.1 follow-up.

**JSON template:** not yet added to `Policies/`.

---

### 8.8 ICB-IOS001-Baseline-PasscodeAndIntegrity

**Intent:** Verify the iOS/iPadOS passcode, which also turns on the device's data encryption, and block jailbroken devices.

**Scope:** `ICB-Persona-CorpMobile` and `ICB-Persona-BYODMobile`. iOS and iPadOS 18 and newer.

**Evaluated settings:**

| Setting | Value |
|---|---|
| `passcodeRequired` | true |
| `passcodeBlockSimple` | true |
| `passcodeMinimumLength` | 6 |
| `passcodeRequiredType` | `numeric` |
| `passcodeMinutesOfInactivityBeforeLock` | 5 |
| `passcodeMinutesOfInactivityBeforeScreenTimeout` | 5 |
| `securityBlockJailbrokenDevices` | true |
| `osMinimumVersion` | `18.0` |

Values follow the passcode baseline in Microsoft's iOS/iPadOS security configuration framework. Encryption has no separate setting: iOS encrypts the device whenever a passcode is set. CIS iOS Intune 4.1 (jailbroken devices blocked) and 4.2 (minimum OS defined) are met.

**Actions for noncompliance:** email at 0 hours (CIS iOS Intune 4.4 asks for an email within 3 days); mark noncompliant at 0 hours, per CIS iOS Intune 4.3 and Microsoft's mobile frameworks. No retire-list action (Section 5.3).

**License requirements:** Microsoft Intune Plan 1.

**Validation:** tenant-validated, not device-validated. Device validation is a v1.0.1 follow-up.

**JSON template:** not yet added to `Policies/`.

---

### 8.9 ICB-AND001-Corporate-IntegrityAndPasscode

**Intent:** Verify device integrity, the passcode and encryption on corporate-owned Android Enterprise devices, at Level 2 of Microsoft's Android Enterprise fully managed security configuration framework.

**Scope:** `ICB-Persona-CorpMobile`. Android Enterprise fully managed, dedicated and corporate-owned work profile devices, Android 10 and newer.

**Evaluated settings:**

| Setting | Value |
|---|---|
| `securityRequireSafetyNetAttestationCertifiedDevice` | true (Play Integrity basic and device integrity) |
| `securityRequiredAndroidSafetyNetEvaluationType` | `hardwareBacked` (strong integrity) |
| `securityBlockJailbrokenDevices` | true |
| `securityRequireIntuneAppIntegrity` | true |
| `storageRequireEncryption` | true |
| `passwordRequired` | true |
| `passwordRequiredType` | `numericComplex` |
| `passwordMinimumLength` | 6 |
| `passwordMinutesOfInactivityBeforeLock` | 5 |
| `passwordPreviousPasswordCountToBlock` | 5 |
| `osMinimumVersion` | `10.0` |

Play Integrity is written as `SafetyNet` properties (Section 2.4). Strong integrity requires hardware-backed attestation; Intune marks devices that do not support it noncompliant, and it requires Google Mobile Services. Corporate Android profiles have no password-complexity property, so the passcode is set by type and length.

**Security patch level, left unset:** Microsoft's frameworks leave the minimum security patch level unset at every level, because patch delivery depends on the device maker and carrier. A fleet whose devices do receive monthly patches can add `minAndroidSecurityPatchLevel` (format `YYYY-MM-DD`), reviewed monthly.

**Actions for noncompliance:** email at 0 hours; mark noncompliant at 0 hours, per Microsoft's Android Enterprise framework.

**License requirements:** Microsoft Intune Plan 1.

**Validation:** tenant-validated, not device-validated. Device validation is a v1.0.1 follow-up.

**JSON template:** not yet added to `Policies/`.

---

### 8.10 ICB-AND002-PersonalWorkProfile-IntegrityAndPasscode

**Intent:** Verify device integrity and the passcode on personally owned Android devices with a work profile, at Level 2 of Microsoft's personally owned work profile framework.

**Scope:** `ICB-Persona-BYODMobile`. Android Enterprise personally owned work profile, Android 10 and newer.

**Evaluated settings:**

| Setting | Value |
|---|---|
| `securityRequireSafetyNetAttestationBasicIntegrity` | true |
| `securityRequireSafetyNetAttestationCertifiedDevice` | true |
| `securityRequiredAndroidSafetyNetEvaluationType` | `hardwareBacked` (strong integrity) |
| `securityBlockJailbrokenDevices` | true |
| `securityRequireGooglePlayServices` | true |
| `securityRequireUpToDateSecurityProviders` | true |
| `securityRequireCompanyPortalAppIntegrity` | true |
| `securityDisableUsbDebugging` | true |
| `storageRequireEncryption` | true |
| `passwordRequired` | true |
| `requiredPasswordComplexity` | `high` (Android 12 and newer) |
| `passwordRequiredType` | `numericComplex` (Android 11 and earlier) |
| `passwordMinimumLength` | 6 (Android 11 and earlier) |
| `passwordMinutesOfInactivityBeforeLock` | 5 |
| `osMinimumVersion` | `10.0` |

Google deprecated password type and minimum length for personally owned work profiles on Android 12 and newer, which use password complexity instead. High is the only complexity level at or above Microsoft's Level 2 minimum of 6; Medium allows 4. Blocking USB debugging also stops users gathering device logs for support.

**Security patch level:** left unset, as in ICB-AND001 (Section 8.9).

**Actions for noncompliance:** email at 0 hours; mark noncompliant at 0 hours; add to retire list at 30 days (Section 5.3).

**License requirements:** Microsoft Intune Plan 1.

**Validation:** tenant-validated, not device-validated. Device validation is a v1.0.1 follow-up.

**JSON template:** not yet added to `Policies/`.

---

### 8.11 ICB-LIN001-Baseline-EncryptionAndPassword

**Intent:** Verify disk encryption, the distribution and version, and the local account password policy on Linux workstations.

**Scope:** `ICB-Persona-CorpLinux`. Ubuntu Desktop 24.04 LTS and newer; RHEL 9 and newer.

**Policy shape:** Linux compliance uses Intune's Settings Catalog, not the classic compliance policy, so this template is a `compliancePolicies` object whose settings are keyed by setting definition ID.

**Evaluated settings:**

| Setting definition | Value | CIS / STIG reference |
|---|---|---|
| `linux_distribution_alloweddistros` | Ubuntu, minimum 24.04; RHEL, minimum 9 | — |
| `linux_deviceencryption_required` | true | No CIS recommendation; RHEL 9 STIG RHEL-09-231190 (CAT I) |
| `linux_passwordpolicy_minimumlength` | 14 | CIS Ubuntu 24.04 and RHEL 9 5.3.3.2.2 (14); RHEL 9 STIG 15 |
| Composition minimums (digits, lowercase, uppercase, symbols) | not set | Principle 1.5 |
| Expiry | not set (no Intune setting; Principle 1.5) | CIS 5.4.1.1 sets 365 days, the STIG 60; see Section 1.7 |

Intune recognizes dm-crypt encryption, with LUKS through cryptsetup as the preferred setup, and ignores read-only, pseudo-filesystem, `/boot` and `/boot/efi` partitions.

**Not evaluated in v1.0:** mandatory access control (AppArmor on Ubuntu, SELinux on RHEL) and the host firewall (ufw, firewalld). The CIS benchmarks and the STIG all cover them, but Intune's Linux compliance settings cannot evaluate them; they need custom compliance scripts and are deferred to v1.1 (Section 9.3).

**Actions for noncompliance:** email at 0 hours; mark noncompliant at 168 hours.

**License requirements:** Microsoft Intune Plan 1.

**Validation:** device-validated on an Ubuntu 24.04 Desktop virtual machine under Hyper-V, a target Intune supports for Linux enrollment.

**JSON template:** not yet added to `Policies/`.

---

## 9. Roadmap

### 9.1 v1.0 template set

| Template | Platform | Validation at v1.0 |
|---|---|---|
| ICB-WIN001-Baseline-DefenderAndBitLocker | Windows 11 | Device |
| ICB-WIN002-Hardening-SecureBoot | Windows 11 | Device |
| ICB-WIN003-Hardening-CodeIntegrity | Windows 11 | Device |
| ICB-WIN004-Baseline-OSVersionFloor | Windows 11 | Device |
| ICB-WIN005-Hardening-PasswordPIN | Windows 11 | Device |
| ICB-WIN008-Threat-DefenderRiskScore | Windows 11 | Device |
| ICB-MAC001-Baseline-EncryptionAndIntegrity | macOS | Tenant |
| ICB-IOS001-Baseline-PasscodeAndIntegrity | iOS / iPadOS | Tenant |
| ICB-AND001-Corporate-IntegrityAndPasscode | Android corporate | Tenant |
| ICB-AND002-PersonalWorkProfile-IntegrityAndPasscode | Android personal work profile | Tenant |
| ICB-LIN001-Baseline-EncryptionAndPassword | Ubuntu, RHEL | Device |

**Tenant-validated** templates are deployed to a test tenant, read back from Graph and compared with the template, with no property dropped or altered. **Device-validated** templates are also shown to evaluate compliant and noncompliant on a real device. The macOS, iOS and Android templates are device-validated in a v1.0.1 follow-up.

### 9.2 Planned, not shipped

ICB-WIN006-Hardening-EALAM and ICB-WIN007-Attestation-HealthyDeviceReport appeared on earlier versions of this roadmap. Neither ships:

- **WIN006 (Early Launch Anti-Malware):** Intune stopped including ELAM in its health-attestation compliance check in 2017, after a Windows defect reported ELAM as disabled following hibernation, and the setting is not in the Intune admin center.
- **WIN007 (Healthy Device Report):** the original single setting covering code integrity, BitLocker, Secure Boot and ELAM, superseded by the individual BitLocker, Secure Boot and code integrity settings that WIN001, WIN002 and WIN003 use.

Their numbers stay unused (Section 2.2), and the Defender for Endpoint risk template is ICB-WIN008 rather than a reused 006.

### 9.3 Deferred to v1.1

- **Windows virtualization-based security:** Memory Integrity (HVCI), virtualization-based security, Kernel DMA protection and firmware protection. Graph exposes them only on beta, and the Intune admin center does not show them, so administrators could neither see nor edit them there. Revisit if Microsoft surfaces them.
- **Linux mandatory access control and firewall:** AppArmor or SELinux enforcing, and ufw or firewalld active. No native Intune setting exists; they need custom compliance scripts.
