# Conditional Access Baseline — Supporting Artifacts

Tenant-scoped artifacts that CA policy templates depend on. These are not Conditional Access policies; they are prerequisites that must exist in the tenant before the policies that reference them can be deployed.

Each artifact is shipped as a Graph-API-shaped JSON template, parallel to the CA policy templates in `../Policies/`.

## Authentication strengths (v1.2)

Three custom authentication strengths that the v1.2 policy slate binds via `grantControls.authenticationStrength`:

| Artifact | Allowed combinations | Purpose |
|----------|----------------------|---------|
| CA-AUTH-STRENGTH-StandardAuth.json | Windows Hello for Business, FIDO2, password + Microsoft Authenticator push | Default strength for general user populations. Phishing-resistant first, with a password-backed fallback for rollout periods. |
| CA-AUTH-STRENGTH-StrongAuth.json | Windows Hello for Business, FIDO2 | Phishing-resistant only. No password-backed factors. Use for sensitive scenarios where the rollout to phishing-resistant credentials is complete. |
| CA-AUTH-STRENGTH-AdminAuth.json | FIDO2 only | The narrowest strength in the baseline. Use for privileged accounts and admin roles. No Windows Hello, no password-backed factors. |

## Named locations (v1.2)

| Artifact | Type | Purpose |
|----------|------|---------|
| CA-LOCATION-TrustedCountries.json | `countryNamedLocation` | Country-based named location used by location-pinning policies (`CA-COV008` BlockByLocation; `CA-COV010` ServiceAccounts BlockUntrustedLocations). Default scope: US, `clientIpAddress` lookup, unknown countries excluded. Customize the `countriesAndRegions` list to match your organization's trust posture before bootstrapping. |

## Resolution by Deploy-CABaseline.ps1

`Deploy-CABaseline.ps1` resolves each placeholder (`REPLACE_WITH_*_GROUP_OBJECT_ID`, `REPLACE_WITH_*_STRENGTH_ID`, `REPLACE_WITH_*_LOCATION_ID`) in the policy templates against the tenant at deploy time, matching by **display name**. The deployer does not create the supporting artifacts themselves; operators provision them in the tenant once before running the script. The JSON templates in this folder document the exact shape each artifact should take.

## Bootstrapping artifacts

For each artifact in this folder, create it in the tenant once using the Graph API. Run from a PowerShell 7 session connected with `Connect-MgGraph -Scopes Policy.ReadWrite.ConditionalAccess`.

### Custom authentication strengths (run once per template)

```powershell
$body = Get-Content -Path .\CA-AUTH-STRENGTH-StandardAuth.json -Raw
Invoke-MgGraphRequest -Method POST `
    -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationStrengthPolicies' `
    -Body $body -ContentType 'application/json'
```

Repeat for `CA-AUTH-STRENGTH-StrongAuth.json` and `CA-AUTH-STRENGTH-AdminAuth.json`.

### Country named location

```powershell
$body = Get-Content -Path .\CA-LOCATION-TrustedCountries.json -Raw
Invoke-MgGraphRequest -Method POST `
    -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations' `
    -Body $body -ContentType 'application/json'
```

## Schema

### Authentication strengths

Templates follow the Microsoft Graph `authenticationStrengthPolicy` schema:

- `displayName` — exact name the deployer matches against
- `description` — repo-side commentary explaining when to use the strength
- `policyType` — always `custom` for templates in this folder
- `allowedCombinations` — list of allowed authentication method combinations
- `requirementsSatisfied` — always `mfa`

Server-side fields (`id`, `createdDateTime`, `modifiedDateTime`, `combinationConfigurations`) are omitted from templates.

### Named locations

Templates follow the Microsoft Graph `namedLocation` schema:

- `displayName` — exact name the deployer matches against
- `@odata.type` — discriminator (`#microsoft.graph.countryNamedLocation` or `#microsoft.graph.ipNamedLocation`)
- Type-specific properties: for country locations, `countriesAndRegions`, `countryLookupMethod`, `includeUnknownCountriesAndRegions`; for IP locations, `ipRanges`, `isTrusted`

Server-side fields (`id`, `createdDateTime`, `modifiedDateTime`) are omitted from templates.

## Adding a new artifact

1. Add the JSON template to this folder using the appropriate prefix (`CA-AUTH-STRENGTH-*`, `CA-LOCATION-*`, etc.).
2. Reference the artifact by display name from any CA policy template that uses it.
3. Update this README with an entry for the new artifact.
4. Add a CHANGELOG entry under `[Unreleased]`.
