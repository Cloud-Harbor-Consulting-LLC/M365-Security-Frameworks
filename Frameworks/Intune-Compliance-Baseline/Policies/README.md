# Intune Compliance Baseline — Policies

This folder contains the platform-scoped compliance policy templates that make up the Intune Compliance Baseline (ICB). Each template is a Microsoft Graph deviceCompliancePolicy JSON object that can be imported directly into a tenant.

For the design philosophy, naming convention, persona model, and rollout sequence, read [../Design/POLICY-DESIGN.md](../Design/POLICY-DESIGN.md) first.

## Week 1 import model — manual

ICB ships in week 1 without a deployer script. The template count is small (one Windows template at v0.1.0-preview), and a hand-imported policy gives the adopter an unambiguous read on what the baseline actually enforces. A deployer script is on the roadmap but deferred until the template count justifies the orchestration layer (see POLICY-DESIGN.md section 4 out-of-scope list).

Two supported import paths.

### Option 1 — Microsoft Graph PowerShell

```powershell
Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All","Group.Read.All"

$policy = Get-Content -Raw -Path ".\ICB-WIN001-Baseline-DefenderAndBitLocker.json" `
  | ConvertFrom-Json `
  | ConvertTo-Json -Depth 20

Invoke-MgGraphRequest `
  -Method POST `
  -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" `
  -Body $policy `
  -ContentType "application/json"
```

The Graph beta endpoint is intentional — the scheduledActionsForRule shape on v1.0 lags the beta surface, and the baseline's graduated-response model relies on the beta payload.

### Option 2 — Intune portal

1. Sign in to <https://intune.microsoft.com>
2. Devices → Compliance policies → Create policy
3. Platform: Windows 10 and later. Profile type: Windows 10/11 compliance policy.
4. Transcribe the settings from the JSON template (BitLocker, storage encryption, firewall, TPM, antivirus, Defender, signature freshness, real-time protection, Defender for Endpoint at medium).
5. Actions for noncompliance: notify at 0 days, mark noncompliant at 7 days (no retire on corporate Windows).
6. Assignments: include the ICB-Persona-CorpWindows group.

## Placeholder substitution

Templates ship with REPLACE_WITH_* placeholders rather than real tenant IDs. Substitute before import.

| Placeholder | Source |
|---|---|
| REPLACE_WITH_ICB_PERSONA_CORPWINDOWS_GROUP_OBJECT_ID | Entra ID group object ID for the persona group (see POLICY-DESIGN.md section 3) |
| REPLACE_WITH_NOTIFICATION_TEMPLATE_ID | Intune notification message template ID (Devices → Compliance policies → Notifications). Leave the JSON empty-string-equivalent if the tenant has no template yet; the policy will still grade compliance, just without the email step. |

## Validation after import

- Devices → Compliance policies → ICB-WIN001 → Device status: every assigned device evaluates to compliant, noncompliant, inGracePeriod, or notEvaluated within roughly 8 hours of check-in.
- Devices → Monitor → Noncompliant devices: confirm the noncompliant list matches expectations for the assigned persona before letting the 7-day block grace period expire.
- Cross-check the deviceComplianceState field on the Graph /deviceManagement/managedDevices endpoint to confirm the Conditional Access signal handoff (see POLICY-DESIGN.md section 6).

## Templates in this folder

| ID | Platform | Scope | Status |
|---|---|---|---|
| ICB-WIN001-Baseline-DefenderAndBitLocker.json | Windows 10/11 | ICB-Persona-CorpWindows | v0.1.0-preview |
