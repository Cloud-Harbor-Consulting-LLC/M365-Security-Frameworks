# Intune Compliance Baseline — Policies

This folder contains the platform-scoped compliance policy templates that make up the Intune Compliance Baseline (ICB). Each template is a Microsoft Graph beta compliance policy body, plus the actions for noncompliance its design calls for and the persona group it is assigned to.

For the design philosophy, the persona model, the actions for noncompliance and the rollout sequence, read [../Design/POLICY-DESIGN.md](../Design/POLICY-DESIGN.md) first. Section 8 specifies every template.

## Deploying

Use [`../Scripts/Deploy-ICBaseline.ps1`](../Scripts/README.md). It resolves the placeholders, deploys in observation mode by default (mark noncompliant after 365 days, no email), reads every policy back and compares it with the template, and is safe to re-run:

```powershell
Connect-MgGraph -Scopes DeviceManagementConfiguration.ReadWrite.All, Group.Read.All
..\Scripts\Deploy-ICBaseline.ps1 -WhatIf                      # preview
..\Scripts\Deploy-ICBaseline.ps1 -Template 'ICB-WIN*'         # deploy the Windows templates in observation mode
..\Scripts\Deploy-ICBaseline.ps1 -Template 'ICB-WIN001*' -Enforce   # promote one after its observation period
```

The templates target the Graph **beta** endpoint (POLICY-DESIGN.md section 2.4). Microsoft Graph's own documentation is not always what Intune does, so the deployer follows what a live tenant was observed to return; its README describes the differences.

## Templates in this folder

| Template | Platform | Persona group | Verifies | Mark noncompliant (with `-Enforce`) |
|---|---|---|---|---|
| `ICB-WIN001-Baseline-DefenderAndBitLocker.json` | Windows 11 | `ICB-Persona-CorpWindows` | BitLocker, encryption, firewall, TPM, antivirus, antispyware, Defender Antivirus with its platform version, current security intelligence and real-time protection | 7 days |
| `ICB-WIN002-Hardening-SecureBoot.json` | Windows 11 | `ICB-Persona-CorpWindows` | Secure Boot | 7 days |
| `ICB-WIN003-Hardening-CodeIntegrity.json` | Windows 11 | `ICB-Persona-CorpWindows` | Windows code integrity | 7 days |
| `ICB-WIN004-Baseline-OSVersionFloor.json` | Windows 11 | `ICB-Persona-CorpWindows` | Build 26200 (25H2) or later | 7 days |
| `ICB-WIN005-Hardening-PasswordPIN.json` | Windows 11 | `ICB-Persona-CorpWindows` | Device unlock credential (the Windows Hello PIN) | 7 days |
| `ICB-WIN008-Threat-DefenderRiskScore.json` | Windows 11 | `ICB-Persona-CorpWindows` | Defender for Endpoint machine risk at or below medium | Immediately |

Every template also emails the user at 0 hours in enforce mode. In observation mode there is no email. The macOS, iOS/iPadOS, Android and Linux templates are added before v1.0.0 (POLICY-DESIGN.md section 9.1).

## Placeholders

Templates carry placeholders, never tenant IDs. The deployer resolves them by name.

| Placeholder | Resolved from | Deployer parameter |
|---|---|---|
| `REPLACE_WITH_ICB_PERSONA_CORPWINDOWS_GROUP_OBJECT_ID` | Group `ICB-Persona-CorpWindows` | `-CorpWindowsGroupName` |
| `REPLACE_WITH_ICB_PERSONA_CORPMAC_GROUP_OBJECT_ID` | Group `ICB-Persona-CorpMac` | `-CorpMacGroupName` |
| `REPLACE_WITH_ICB_PERSONA_CORPMOBILE_GROUP_OBJECT_ID` | Group `ICB-Persona-CorpMobile` | `-CorpMobileGroupName` |
| `REPLACE_WITH_ICB_PERSONA_BYODMOBILE_GROUP_OBJECT_ID` | Group `ICB-Persona-BYODMobile` | `-BYODMobileGroupName` |
| `REPLACE_WITH_ICB_PERSONA_CORPLINUX_GROUP_OBJECT_ID` | Group `ICB-Persona-CorpLinux` | `-CorpLinuxGroupName` |
| `REPLACE_WITH_NOTIFICATION_TEMPLATE_ID` | Notification message template `ICB - Device noncompliant`, used only with `-Enforce` | `-NotificationTemplateName` |

## Importing without the deployer

To create a policy by hand, substitute the placeholders yourself and keep these points, each learned from a live tenant:

- POST classic templates to `https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies` without the `assignments` property, then assign with `POST …/{id}/assign`.
- For observation, replace the template's actions with a single `block` action at `gracePeriodHours: 8760` and no `notification` action.
- Graph's create response does not include the actions for noncompliance. Read the policy back with `?$expand=scheduledActionsForRule($expand=scheduledActionConfigurations)` to confirm them.

In the Intune admin center the equivalent is Devices › Compliance › Create policy, platform Windows 10 and later, transcribing the settings and actions from the template and assigning the persona group.

## Validation after deployment

- Devices › Compliance › Policies › each template › Device status: assigned devices evaluate within about 8 hours of check-in. BitLocker, Secure Boot and code integrity are measured at boot, so a device reports them only after a restart.
- In observation mode a failing device shows **In grace period**, and Conditional Access still treats it as compliant. Review the failures before promoting a template with `-Enforce` (POLICY-DESIGN.md section 7.2).
- WIN008 needs the Microsoft Defender for Endpoint connector. Without it the setting reports **Not evaluated** rather than Compliant (POLICY-DESIGN.md section 8.6).
