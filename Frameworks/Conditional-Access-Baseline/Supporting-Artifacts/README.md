# Conditional Access Baseline — Supporting Artifacts

Tenant-scoped artifacts that CA policy templates depend on. These are not Conditional Access policies; they are prerequisites that must exist (or be created) in the tenant before the policies that reference them can be deployed.

Each artifact is shipped as a Graph-API-shaped JSON template, parallel to the CA policy templates in `../Policies/`.

## Authentication strengths (v1.2)

Three custom authentication strengths that the v1.2 policy slate binds via `grantControls.authenticationStrength`:

| Artifact | Allowed combinations | Purpose |
|----------|----------------------|---------|
| CA-AUTH-STRENGTH-StandardAuth.json | Windows Hello for Business, FIDO2, password + Microsoft Authenticator push | Default strength for general user populations. Phishing-resistant first, with a password-backed fallback for rollout periods. |
| CA-AUTH-STRENGTH-StrongAuth.json | Windows Hello for Business, FIDO2 | Phishing-resistant only. No password-backed factors. Use for sensitive scenarios where the rollout to phishing-resistant credentials is complete. |
| CA-AUTH-STRENGTH-AdminAuth.json | FIDO2 only | The narrowest strength in the baseline. Use for privileged accounts and admin roles. No Windows Hello, no password-backed factors. |

`Deploy-CABaseline.ps1` (extended in a later v1.2 PR) will resolve each `REPLACE_WITH_AUTH_STRENGTH_*_ID` placeholder in the policy templates against the tenant's `/policies/authenticationStrengthPolicies` collection, matching by `displayName`. If a custom strength does not exist, the deployer creates it from the template before policy deployment.

## Schema

Authentication-strength templates follow the Microsoft Graph schema for `authenticationStrengthPolicy`:

- `displayName` — exact name the deployer matches against
- `description` — repo-side commentary explaining when to use the strength
- `policyType` — always `custom` for templates in this folder
- `allowedCombinations` — list of allowed authentication method combinations
- `requirementsSatisfied` — always `mfa`

Server-side fields (`id`, `createdDateTime`, `modifiedDateTime`, `combinationConfigurations`) are omitted from templates.

## Adding a new artifact

1. Add the JSON template to this folder using the appropriate prefix (`CA-AUTH-STRENGTH-*`, `CA-LOCATION-*`, etc.).
2. Reference the artifact by display name from any CA policy template that uses it.
3. Update this README with an entry for the new artifact.
4. Add a CHANGELOG entry under `[Unreleased]`.
