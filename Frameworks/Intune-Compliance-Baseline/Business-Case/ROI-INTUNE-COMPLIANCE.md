# Intune Compliance Baseline — Business Case and ROI

> A plain-language business case for security architects defending an Intune device compliance baseline to executive leaders, the C-suite and board members. It stands alone; no other document in this repository is needed to read it.

## Executive summary

Every "require a compliant device" rule in Conditional Access depends on one question: what makes a device compliant? If nobody has answered it, or Intune's defaults answer it, the rule lets through devices it was meant to stop. The Intune Compliance Baseline (ICB) answers it with 11 compliance policy templates across Windows 11, macOS, iOS/iPadOS, Android and Linux. Each template checks the controls that keep a device and its data safe: disk encryption, antivirus, the firewall, a supported operating system, a device passcode, and, on Windows, Microsoft Defender for Endpoint's risk rating.

Three points define this baseline for an executive audience:

**It turns an existing licence into a working control.** Microsoft Intune Plan 1 is included in Microsoft 365 Business Premium, E3 and E5. For most organizations on those plans, 10 of the 11 templates need no new licence; the 11th, ICB-WIN008, needs Microsoft Defender for Endpoint (see Licensing).

**It makes Conditional Access's device check mean something.** Four Conditional Access Baseline policies rely on the compliance result ICB produces, including the one that requires a compliant device for every internal user on Windows, macOS and Linux. Intune's default tenant setting reports a device with no compliance policy as compliant; ICB's prerequisites close that gap.

**It deploys without blocking anyone.** The deployer runs in observation mode by default. Devices report real results in Intune, while Conditional Access still treats them as compliant, so the organization sees which devices would fail before any user is affected. Enforcement follows per template, on a documented schedule.

The ask of executive leadership is threefold:

1. **Endorse a phased rollout** in which every template runs in observation mode for at least 14 days (21 for Linux) before it is enforced.
2. **Confirm licensing:** Intune Plan 1 for every in-scope user, and Microsoft Defender for Endpoint wherever ICB-WIN008 is used.
3. **Approve one tenant-wide setting change and a review cadence.** Devices with no compliance policy are marked Not compliant instead of Compliant, and Security and IT Operations review the baseline quarterly.

In return, the organization gets a defined, auditable standard for device health that every Conditional Access device decision rests on, and evidence for the endpoint requirements in SOC 2, ISO 27001, HIPAA and NIST SP 800-53.

## The business risk this addresses

### Unmanaged and unhealthy devices are how attacks spread

Microsoft's *Digital Defense Report 2024* found that in more than 90% of the attacks it observed that reached the ransom stage, the attacker used unmanaged devices, either for initial access or to encrypt data remotely. A device the organization cannot see, or cannot prove is healthy, is where an attack takes hold.

A compliance baseline is the proof. It checks, on every device, that encryption is on, antivirus is running and current, the operating system is still receiving security updates, and the device locks with a passcode. A device that fails is marked noncompliant, and Conditional Access keeps it away from company data until it is fixed.

### The financial exposure is substantial

The IBM Cost of a Data Breach 2025 report studied 600 organizations that experienced a breach between March 2024 and February 2025, across 17 industries and 16 countries and regions. The figures below are reused from the repository's verified rows in `ROI-ZT-READINESS.md`.

| Metric | IBM 2025 finding |
|---|---|
| Global average breach cost | $4.44M (down 9% from $4.88M in 2024, the first decrease in 5 years) |
| United States average breach cost | $10.22M (up 9% from $9.36M, an all-time high for any region) |
| Healthcare average breach cost | $7.42M (highest of any industry for the 12th consecutive year) |
| Average days to identify and contain | 241 days (181 to identify, 60 to contain), a 9-year low |
| Extensive use of security AI and automation | $1.9M lower cost and 80 fewer days per breach |

IBM's study measures what breaches cost, not how likely they are, and it does not isolate the effect of device compliance. This document therefore makes no claim that ICB reduces breach cost by a given percentage. To quantify the case for a specific organization, populate:

- [INSERT: ORGANIZATION'S ESTIMATED ANNUAL BREACH-RISK EXPOSURE]
- [INSERT: ORGANIZATION'S CURRENT CYBER-INSURANCE PREMIUM]
- [INSERT: NUMBER OF DEVICES THAT FAIL ICB IN OBSERVATION MODE]

The third figure comes from the organization's own tenant during the observation period, and it is usually the most persuasive number in the room: it counts the devices that reach company data today without meeting the standard.

### Why "require a compliant device" fails without a baseline

Organizations that already require compliant devices in Conditional Access often assume the control is working. Three gaps found while building and validating ICB show why it may not be:

- **No policy, no problem — by default.** Intune's default tenant setting reports a device that no compliance policy targets as compliant. Every enrolled device that falls outside a policy's scope passes Conditional Access's device check. ICB requires the setting to be changed to Not compliant, as Microsoft recommends wherever Conditional Access relies on compliance.
- **A grace period on a threat verdict.** A grace period lets a user fix a setting that drifted. Applied to a Defender for Endpoint risk rating, it keeps a likely compromised device inside Conditional Access for the length of the window. ICB separates risk signals into their own template, ICB-WIN008, which marks the device noncompliant immediately.
- **Overlapping policies.** Intune combines every compliance policy that targets a device, and the strictest result wins. A leftover policy can override a planned rollout or stop a check from evaluating at all. ICB makes "no other compliance policy targets ICB's devices" a prerequisite.

## What the baseline delivers

Eleven templates, each one platform and one purpose, so each can be observed and enforced on its own timeline. Validation labels record how each was tested: *device-validated* templates were shown to evaluate compliant and noncompliant on a real device; *tenant-validated* templates were deployed to a test tenant and read back unchanged, with device validation to follow in v1.0.1.

| Template | Platform | What it checks | License floor | Validation | Business outcome |
|---|---|---|---|---|---|
| ICB-WIN001 | Windows 11 | BitLocker, encryption, firewall, TPM, antivirus and antispyware, Defender Antivirus version, signatures and real-time protection | Intune Plan 1 | Device | A stolen laptop does not expose data, and malware protection is on and current |
| ICB-WIN002 | Windows 11 | Secure Boot | Intune Plan 1 | Device | The device starts only signed boot components, which blocks boot-level malware |
| ICB-WIN003 | Windows 11 | Code integrity | Intune Plan 1 | Device | Windows loads only signed drivers and system files |
| ICB-WIN004 | Windows 11 | A Windows 11 build still receiving security updates | Intune Plan 1 | Device | Unsupported Windows builds, including Windows 10, cannot reach company data once enforced |
| ICB-WIN005 | Windows 11 | The device PIN (Windows Hello): at least 6, no simple sequences, 15-minute lock | Intune Plan 1 | Device | An unattended or stolen device is locked |
| ICB-WIN008 | Windows 11 | Defender for Endpoint risk at or below medium, noncompliant immediately | Intune Plan 1 + Defender for Endpoint | Device | A device Defender rates high-risk loses access at once, not after a week |
| ICB-MAC001 | macOS | FileVault, System Integrity Protection, firewall, Gatekeeper, macOS 15 or later | Intune Plan 1 | Tenant | Mac laptops meet the same encryption and integrity bar as Windows |
| ICB-IOS001 | iOS / iPadOS | 6-digit passcode, jailbreak block, iOS 18 or later | Intune Plan 1 | Tenant | Phones and tablets that hold company email are locked, unmodified and current |
| ICB-AND001 | Android (corporate) | Play Integrity, root block, passcode, encryption, Android 10 or later | Intune Plan 1 | Tenant | Company-owned Android devices are genuine, unmodified and locked |
| ICB-AND002 | Android (personal work profile) | Play Integrity, root block, passcode complexity, USB debugging block | Intune Plan 1 | Tenant | Personal phones can carry company data only while they meet the bar; the work profile goes on a retire list after 30 days noncompliant |
| ICB-LIN001 | Linux (Ubuntu 24.04+, RHEL 9+) | Supported distribution and version, disk encryption, 14-character password | Intune Plan 1 | Device | Engineering workstations are encrypted and supported |

No template sets password expiry. Following NIST SP 800-63B and Microsoft's password guidance, forced periodic changes are not required.

## The signal ICB gives the Conditional Access Baseline

ICB produces one result per device, compliant or not, and Conditional Access consumes it. ICB owns what makes a device compliant; Conditional Access owns what compliance unlocks. Four Conditional Access Baseline policies rely on it:

| Conditional Access policy | What compliance unlocks |
|---|---|
| CA-COV008 | Every application, for internal users on Windows, macOS and Linux |
| CA-SIG001 | Azure Service Management, for internal users on every platform |
| CA-COV014 | Sign-in for agent user accounts on Windows 365 Cloud PCs for Agents |
| CA-COV003 | Exemption from the 4-hour browser session limit |

Two consequences belong in the business case:

- **Hybrid-joined Windows devices bypass the check in CA-COV008 and CA-SIG001,** which accept a compliant device or a hybrid Microsoft Entra joined one. Where an organization relies on hybrid join, ICB still evaluates the device but gates access only where compliance alone is required.
- **On iOS and Android, ICB's result gates Azure Service Management only** in the baseline as shipped, because CA-COV008 covers desktop platforms. The mobile templates are still the evidence that mobile devices meet the standard; an organization that wants mobile compliance to gate Microsoft 365 apps adds a policy that requires it.

Without ICB, these four policies evaluate whatever compliance definition the tenant happens to have, including the default that treats a device with no policy as compliant.

## Licensing

| Component | Required by | Note |
|---|---|---|
| Microsoft Intune Plan 1 | All 11 templates | $8.00 per user per month standalone, paid yearly. Included in Microsoft 365 Business Premium ($22.00), Microsoft 365 E3 ($39.00) and Microsoft 365 E5 ($60.00), each per user per month, paid yearly. |
| Microsoft Defender for Endpoint | ICB-WIN008 | Supplies the device risk rating. Plan 2 is included in Microsoft 365 E5 and is the plan ICB-WIN008 was validated with. Plan 1 is included in Microsoft 365 E3. |
| Microsoft Defender for Business | ICB-WIN008 (not verified) | Included in Microsoft 365 Business Premium. Microsoft describes it as including the features of Defender for Endpoint Plan 1 and some from Plan 2, but does not state that it supplies the risk rating ICB-WIN008 checks, and ICB has not tested it. Deploy ICB-WIN008 in observation mode and enforce it only once Intune reports its risk setting as Compliant or Not compliant. |
| Microsoft Defender Antivirus | ICB-WIN001 | Built into Windows 11; no additional licence. |
| Microsoft Entra ID P1 | Conditional Access consumption of the result | Required by the Conditional Access Baseline, not by ICB itself. Included in Business Premium, E3 and E5. |

Prices are US list prices from Microsoft's Intune, Business Premium and Microsoft 365 pricing pages, checked 2026-11-16. Volume and Enterprise Agreement pricing varies. Microsoft does not publish standalone list prices for Defender for Endpoint Plan 1 or Plan 2 on its pricing pages; obtain them from the organization's licensing partner.

**Incremental cost.** For an organization already on Business Premium, E3 or E5, the licence cost of 10 templates is $0. ICB-WIN008 adds cost only where Defender for Endpoint is not already licensed, or where Defender for Business proves not to supply the risk rating. For an organization buying Intune only for this baseline:

- [INSERT: IN-SCOPE USERS x $8.00 x 12 = ANNUAL INTUNE PLAN 1 COST]

## Implementation prerequisites

Before the first template is deployed in observation mode:

- **Tenant-wide compliance settings** in the Intune admin center: mark devices with no compliance policy assigned as **Not compliant**, and set the compliance status validity period to 7 days or fewer. The deployer checks both and warns; it never changes a tenant-wide setting.
- **Overlapping compliance policies retired**, or the ICB persona groups excluded from them.
- **Five device persona groups** (corporate Windows, corporate Mac, corporate mobile, BYOD mobile, corporate Linux), preferably dynamic, so a new device reaches its group as it enrolls.
- **A notification message template** for the user email.
- **Windows 11 network access** to Microsoft Azure Attestation for the tenant's region, without SSL inspection, and Microsoft Defender Antivirus as the active antivirus.
- **Defender for Endpoint connected to Intune**, for ICB-WIN008.
- **PowerShell 7** and the `Microsoft.Graph.Authentication` module on the deployer workstation.

## Implementation cost estimate

One-time effort, in hours, for the organization's own IT and security staff in one tenant. These are planning estimates, not measurements, sized for an organization of about 50 to 300 users (the range of Microsoft 365 Business Premium, whose Defender for Business supports up to 300 users). Replace them with the organization's own.

| Activity | Estimated hours |
|---|---|
| Prerequisites: tenant settings, persona groups, notification template, Defender connector | 8 to 16 |
| Inventory and retire or exclude overlapping compliance policies | 4 to 8 |
| Deploy all 11 templates in observation mode with Deploy-ICBaseline | 2 |
| Weekly observation reviews over the rollout | 20 to 30 |
| Enforcement, in 5 steps, with a check of each step | 5 |
| User and help-desk communication (passcode changes, Windows 10 replacement) | 4 to 8 |
| **Total** | **43 to 69** |

The estimate covers rolling out the baseline itself. It does not include fixing the devices that fail it, such as turning on BitLocker or Secure Boot or replacing Windows 10 hardware; that work depends on the size of the fleet and on what observation mode finds.

**Elapsed time.** Templates are enforced in 5 steps, and each step's minimum observation period is counted from the previous step's enforcement. The periods add up to 77 days, about 11 weeks, when Windows 11's four hardening templates are enforced together, and to 119 days, about 17 weeks, when they are enforced one at a time. Organizations whose Conditional Access device policies are already enforced should not shorten them: enforcing a template turns every failing device into a sign-in block when its schedule fires, immediately for ICB-WIN008 and the mobile templates.

## Operational cost estimate

Annualized hours to run the baseline at steady state, after rollout, sized as above. These are planning estimates. Most lines are fixed overhead whatever the fleet size. The cadences of the Defender version update, the overlapping-policy check and the floor review come from the baseline's design. Noncompliant-device triage and the compliance report review grow with the number of devices, so larger fleets should scale those two lines.

| Activity | Frequency | Hours per cycle | Annual total |
|---|---|---|---|
| Noncompliant-device triage with the help desk | Weekly | 1 hour | 52 hours |
| Compliance report review (errors, not evaluated, grace period) | Monthly | 2 hours | 24 hours |
| Persona group membership attestation | Quarterly | 2 hours | 8 hours |
| Defender Antivirus minimum version update (ICB-WIN001) | Quarterly | 1 hour | 4 hours |
| Overlapping-policy check | Quarterly | 1 hour | 4 hours |
| BYOD retire-list review (ICB-AND002) | Monthly | 30 minutes | 6 hours |
| OS version floor review against vendor servicing | Annually | 4 hours | 4 hours |

**Total at steady state: approximately 102 hours per year,** most of it triage that a help desk already performs for device issues. The floor review is what keeps the baseline current: every version floor set in May 2026 was out of date by October, so ICB states each floor as a rule (the oldest version still in vendor servicing) and records each annual change.

## Compliance mapping

The rows below map ICB to endpoint-related requirements. Where a row already exists in the repository's verified documents, its description is copied from there (see `CONTRIBUTING.md`). The other rows come from the published texts listed in References:

- SOC 2 CC6.7 and CC6.8 from the AICPA Trust Services Criteria;
- HIPAA from 45 CFR Part 164;
- NIST SP 800-53 from NIST's control catalog.

The new ISO 27001 rows use NIST's official crosswalk from SP 800-53 Rev 5 to ISO/IEC 27001:2022, which maps the NIST controls in the SP 800-53 table below to these ISO controls. The crosswalk gives control numbers only, and ISO's text is not freely published, so their titles were checked against published certification guidance rather than the standard itself. Organizations should validate control numbers against current framework revisions with their audit team.

### SOC 2 Trust Services Criteria

| CC control | Description | How ICB supports it |
|---|---|---|
| CC6.1 | Logical access controls restrict access to authorized users based on authorized user roles | ICB's compliance result is the device condition CA-COV008 and CA-SIG001 enforce; only a device that meets the baseline reaches company data |
| CC6.6 | Logical access security measures protect against threats from sources outside the entity's system boundaries | Devices that fail encryption, antivirus, firewall or OS-version checks are kept from Conditional Access-protected resources once enforced |
| CC6.7 | The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal | Addresses the criterion's "Protects Endpoint Devices" point of focus: every laptop, desktop and mobile device is checked for encryption, a device lock and a supported OS |
| CC6.8 | The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software | ICB-WIN001 requires antivirus with real-time protection and current signatures, addressing the "Uses Antivirus and Anti-Malware Software" point of focus. ICB-WIN002 and ICB-WIN003 require Secure Boot and code integrity, so only signed boot components and drivers load |
| CC7.2 | System components are monitored for anomalies indicative of malicious acts; anomalies are analyzed to determine whether they represent security events | ICB-WIN008 turns Defender for Endpoint's risk rating into an immediate compliance result, and Intune's compliance reports record every device's state |

### ISO 27001:2022

| Control | Description | How ICB supports it |
|---|---|---|
| A.5.15 (was A.9.1.1, A.9.1.2) | Access control | Access to company data depends on the device meeting the baseline, through the Conditional Access policies that consume ICB's result |
| A.8.16 (no 2013 equivalent — introduced in the 2022 revision) | Monitoring activities | Intune evaluates every in-scope device continuously, and ICB-WIN008 brings Defender for Endpoint's risk monitoring into the compliance result |
| A.8.1 | User endpoint devices | Every endpoint platform has a template, covering a device lock, encryption and a supported OS (NIST crosswalk: AC-11, AC-19) |
| A.8.7 | Protection against malware | ICB-WIN001 verifies antivirus, real-time protection and current signatures (NIST crosswalk: SI-3) |
| A.8.8 | Management of technical vulnerabilities | OS version floors, reviewed annually, keep devices on releases that still receive security updates (NIST crosswalk: SI-2) |
| A.8.9 (new in the 2022 revision) | Configuration management | The templates are a documented, version-controlled security configuration, and Intune reports every device that drifts from it (NIST crosswalk: CM-2, CM-6, CM-8) |

### HIPAA Security Rule

| Section | Title | How ICB supports it |
|---|---|---|
| §164.310(b) | Workstation use (standard) | The templates define the required state of every workstation that accesses company systems |
| §164.310(c) | Workstation security (standard) | Alongside physical safeguards, the device lock and encryption checks limit what an unauthorized person can reach on a lost or unattended workstation |
| §164.312(a)(2)(iii) | Automatic logoff (addressable) | ICB-WIN005 and the mobile templates require the device to lock after inactivity (15 minutes on Windows, 5 on mobile) |
| §164.312(a)(2)(iv) | Encryption and decryption (addressable) | ICB-WIN001, ICB-MAC001, ICB-AND001, ICB-AND002 and ICB-LIN001 require disk encryption; on iOS a passcode enables data protection |

### NIST SP 800-53 Rev 5

| Control | Title | How ICB supports it |
|---|---|---|
| AC-11 | Device lock | ICB-WIN005, ICB-IOS001, ICB-AND001 and ICB-AND002 require a passcode with an inactivity lock |
| AC-19 | Access control for mobile devices | ICB-IOS001, ICB-AND001 and ICB-AND002 set the conditions a mobile device must meet before it is compliant |
| CM-2 | Baseline configuration | The 11 templates are a documented, version-controlled baseline for device security |
| CM-6 | Configuration settings | Each template verifies the required settings on every in-scope device and reports deviations |
| CM-8 | System component inventory | Persona groups and Intune's compliance reports identify every device in scope and its state |
| SC-28 | Protection of information at rest | Disk encryption is required on Windows, macOS, Android and Linux |
| SI-2 | Flaw remediation | OS version floors keep devices on releases that still receive security updates |
| SI-3 | Malicious code protection | ICB-WIN001 requires antivirus, real-time protection and current signatures |
| SI-4 | System monitoring | ICB-WIN008 acts on Defender for Endpoint's monitoring of the device |

Beyond compliance, device management and endpoint protection are among the controls cyber-insurance carriers ask about in underwriting questionnaires. ICB's compliance reports are the evidence that the controls are in force on every device, not only configured somewhere.

## Recommended investment approach

### Phase 1 — Prerequisites (weeks 1 to 2)

Change the two tenant-wide compliance settings. Retire or exclude overlapping compliance policies. Create the five persona groups and the notification message template. Connect Defender for Endpoint to Intune. Inventory Windows 10 devices, which ICB-WIN004 will mark noncompliant, and plan their replacement or upgrade.

### Phase 2 — Observation (weeks 3 to 4)

Deploy all 11 templates with Deploy-ICBaseline in observation mode. Review Intune's compliance reports weekly: which settings fail, which devices return errors or are not evaluated, which sit below a version floor. Fix the causes before any enforcement.

### Phase 3 — Staged enforcement (weeks 5 to 14, or to 20)

Enforce in the documented order, each step after its observation period, finishing in week 14 when the Windows hardening templates are enforced together and in week 20 when they are enforced one at a time: Windows foundation and risk (ICB-WIN001, ICB-WIN008), then the Windows hardening templates, then macOS, then mobile, then Linux. Coordinate each step with the help desk.

### Phase 4 — Steady state

Run the review cadence in the Operational cost estimate. Pair with the Conditional Access Baseline so that CA-COV008 and CA-SIG001 are enforced only after ICB's results are clean.

## CFO-ready summary

**The investment.** Microsoft Intune Plan 1, $8.00 per user per month standalone, is already included in Microsoft 365 Business Premium, E3 and E5. For those organizations, 10 of the 11 templates add no licence cost. ICB-WIN008 needs Microsoft Defender for Endpoint, included in E5. One-time effort is estimated at 43 to 69 hours; steady-state operation at about 102 hours per year.

**What it buys.** A defined, tested standard for device health on five platforms, and the evidence that every device reaching company data meets it. It closes the default setting that lets a device with no compliance policy pass Conditional Access.

**The risk it reduces.** Unmanaged and unhealthy devices: in more than 90% of the ransom-stage attacks Microsoft observed in its 2024 report, attackers used them. A US breach averages $10.22M (IBM 2025).

**The rollout risk.** Low. Observation mode shows every failing device before anyone is blocked, and each template is enforced on its own schedule.

## Cross-references

- [`ROI-CONDITIONAL-ACCESS.md`](../../Conditional-Access-Baseline/Business-Case/ROI-CONDITIONAL-ACCESS.md) — the business case for the Conditional Access Baseline, whose device policies consume ICB's result. Read both: ICB defines compliance, the CA Baseline decides what it unlocks.
- [`CA-ICB-INTEGRATION.md`](../../Conditional-Access-Baseline/Design/CA-ICB-INTEGRATION.md) — the technical handoff between the two frameworks, its failure modes and rollout sequence.
- [`ROI-ZT-READINESS.md`](../../Zero-Trust-Readiness-Assessment/Business-Case/ROI-ZT-READINESS.md) — the Zero Trust Readiness Assessment business case. ICB with the CA Baseline satisfies its EP-03 control, Conditional Access enforcement of device compliance.
- [`POLICY-DESIGN.md`](../Design/POLICY-DESIGN.md) — per-template specifications, observation mode, prerequisites and the rollout sequence.

## References

- IBM. *Cost of a Data Breach Report 2025*.
- Microsoft. *Microsoft Digital Defense Report 2024*, and [10 essential insights from the Microsoft Digital Defense Report 2024](https://www.microsoft.com/en-us/security/security-insider/threat-landscape/10-essential-insights-from-the-microsoft-digital-defense-report-2024).
- Microsoft. [Microsoft Intune pricing](https://www.microsoft.com/en-us/security/business/microsoft-intune-pricing).
- Microsoft. [Microsoft 365 Business Premium](https://www.microsoft.com/en-us/security/business/microsoft365-business-premium).
- Microsoft Learn. [Microsoft 365 for business security overview](https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/m365b-security-overview).
- Microsoft Learn. [Microsoft Defender service description](https://learn.microsoft.com/en-us/office365/servicedescriptions/microsoft-365-service-descriptions/microsoft-365-tenantlevel-services-licensing-guidance/microsoft-defender-service-description).
- Microsoft Learn. [Microsoft Defender for Business overview](https://learn.microsoft.com/en-us/defender-business/mdb-overview).
- Microsoft Learn. [Integrate Microsoft Defender for Endpoint with Intune for device compliance](https://learn.microsoft.com/en-us/intune/device-security/microsoft-defender/overview).
- AICPA. [2017 Trust Services Criteria (With Revised Points of Focus – 2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022).
- NIST. [SP 800-53 Rev 5, Release 5.2.0, in the Cybersecurity and Privacy Reference Tool](https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_2_0/home).
- NIST. [SP 800-53 Rev 5 to ISO/IEC 27001:2022 crosswalk](https://csrc.nist.gov/projects/olir/informative-reference-catalog/details?referenceId=155), National Online Informative References Program.
- NIST. SP 800-63B, *Digital Identity Guidelines: Authentication and Lifecycle Management*.
- U.S. Code of Federal Regulations. [45 CFR 164.310](https://www.law.cornell.edu/cfr/text/45/164.310) and [45 CFR 164.312](https://www.law.cornell.edu/cfr/text/45/164.312).
