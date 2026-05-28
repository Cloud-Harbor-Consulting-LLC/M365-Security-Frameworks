# Workload Identity IP Allow-Listing Patterns and CI/CD Examples

Baseline supplement to `CA-COV010-WorkloadIdentities-TrustedLocations`. Read [`Policies/CA-COV010-WorkloadIdentities.md`](../Policies/CA-COV010-WorkloadIdentities.md) first — it covers the policy mechanics, the Workload Identities Premium SKU prerequisite, the Trusted IPs named location creation procedure, and the per-SPN exclusion model. This supplement starts where that document ends: operational patterns for adopters running the policy in production.

---

## 1. Introduction

Workload identities — service principals, managed identities, federated credential consumers — authenticate from machines, not humans. A stolen client secret or certificate is redeemable from anywhere on the public internet unless something constrains the egress. `CA-COV010-WorkloadIdentities-TrustedLocations` provides that constraint via a Trusted IPs named location. Every service-principal sign-in outside the allowed IP ranges is blocked, regardless of what credential was presented.

The operational challenge is that the constraint must stay accurate. Modern CI/CD platforms rotate their egress IPs continuously. A named location that was correct last month may be stale today. A stale named location means pipeline failures, not security improvements — and the operational friction of recurring failures drives adopters to leave the policy in report-only indefinitely, which defeats its purpose.

This supplement covers:

- How to scope each CI/CD pipeline to its own service principal rather than sharing one broad SPN, bounding the blast radius per pipeline.
- How to keep the Trusted IPs named location accurate against rotating CI runner egress, per runner class.
- How to recover when pipelines start failing because the egress IPs drifted out of the allow-list.

This document does not repeat content in [`Policies/CA-COV010-WorkloadIdentities.md`](../Policies/CA-COV010-WorkloadIdentities.md). Cross-references throughout this document point back to that paired contract when the paired contract is the authoritative source.

---

## 2. The Trusted IPs Model

### 2.1 Named location types in Microsoft Entra

Microsoft Entra Conditional Access supports two named-location types:

- **IP ranges (`ipNamedLocation`)** — a set of IPv4 and IPv6 CIDR ranges. These are evaluated against the `clientIpAddress` field of the sign-in event. This is the type used by `CA-COV010`.
- **Countries/regions (`countryNamedLocation`)** — a set of ISO 3166-1 alpha-2 country codes. These are evaluated against the country inferred from the sign-in IP via geo-IP mapping.

`CA-COV010` uses the IP ranges type because workload identity egress is infrastructure-defined: a specific NAT gateway, a CI runner address range, a cloud instance IP. Country-level resolution is too coarse to be meaningful for service principal access control.

### 2.2 The clientIpAddress matching mechanic

At sign-in time, Microsoft Entra captures the `clientIpAddress` from the incoming connection. For a Conditional Access policy scoped to a named location:

- If the `clientIpAddress` falls within any CIDR range in the named location, the location condition evaluates as "inside the named location."
- If the `clientIpAddress` does not fall within any CIDR range, the location condition evaluates as "outside the named location."

`CA-COV010` uses the inverse pattern: `includeLocations: ["All"]`, `excludeLocations: [<TrustedIPsNamedLocationId>]`. A sign-in from inside the named location passes because the exclusion removes it from the block scope. A sign-in from outside the named location is blocked.

The `clientIpAddress` is the IP that reached the Microsoft Entra token endpoint — the outermost observable source. For pipeline runners behind a NAT gateway or a corporate proxy, this will be the gateway or proxy IP, not the runner's internal address. For GitHub Actions or Azure DevOps Microsoft-hosted runners, this is one of the egress IPs in the published platform ranges.

Reference: [Microsoft Learn — Conditional Access named locations and network assignment](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network)

### 2.3 IPv4 and IPv6 support

The `ipNamedLocation` type supports both IPv4 and IPv6 CIDR ranges within the same named location object. Adopt this when your runner infrastructure has IPv6 egress. Most CI platform-published IP ranges (as of 2026) are IPv4, but the named location schema accommodates dual-stack environments without requiring two separate named locations.

### 2.4 CIDR notation requirements

As of 2026, Microsoft Entra accepts:

- IPv4: `/8` through `/32`
- IPv6: `/8` through `/128`

The accepted prefix-length bounds may change. Verify current requirements against the [Microsoft Learn named locations documentation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network) before provisioning. Attempting to add a CIDR outside the accepted range produces a Graph API validation error at named-location creation or update time.

### 2.5 Trusted location flag

The `ipNamedLocation` object has an `isTrusted` boolean field. For the `CA-COV010` use case, mark the named location as trusted. This ensures the location appears in the "Trusted IPs" filter in the Entra sign-in logs, which simplifies diagnostic correlation when investigating a block event.

---

## 3. SPN Per-Pipeline Scoping Pattern

### 3.1 The recommendation

Each CI/CD pipeline should have its own dedicated service principal. Do not share a single "CI/CD SPN" across multiple pipelines.

Rationale: blast-radius bounding. When one SPN is shared across pipelines, a credential compromise in any one pipeline exposes the role assignments, access history, and permitted egress ranges of every other pipeline sharing that identity. Isolating SPNs isolates the damage surface.

### 3.2 Anti-pattern: shared CI/CD SPN

The shared-SPN pattern looks like this:

- One SPN: `SPN-CI-Pipeline-Shared`
- Role assignments: Contributor at subscription scope, broad permissions to multiple resource groups
- Named location: a wide IP range covering all runner pools
- Usage: all pipelines across all services authenticate as this SPN

Problems with this pattern:

- **Wide attack surface.** A compromised credential grants access to everything the SPN can reach across all pipelines.
- **Lossy attribution.** The sign-in log shows `SPN-CI-Pipeline-Shared` authenticating, not which pipeline, which job, or which repository triggered the sign-in. Forensic attribution after a compromise event is difficult or impossible.
- **No per-pipeline egress scoping.** A single named location must cover all runners used by all pipelines, making the allow-list broad by necessity.
- **Change blast radius.** Rotating credentials for the shared SPN requires coordinating the update across every pipeline that uses it simultaneously.

### 3.3 Pattern: one SPN per pipeline

The per-pipeline pattern:

- One SPN per pipeline: `SPN-Frameworks-Deploy-Prod`, `SPN-Frameworks-Deploy-Dev`, `SPN-API-Test-Staging`
- Role assignments: scoped to the minimum role at the resource group or workspace level for that pipeline's target
- Named location: an IP range sized to the egress of that pipeline's specific runner pool
- Credential: federated credential (recommended) or a secret/certificate scoped to that SPN only

Benefits:

- **Isolation.** A compromised `SPN-Frameworks-Deploy-Dev` credential exposes only the development resource group, not production.
- **Attribution.** Sign-in logs show the specific SPN, making forensic correlation to the pipeline straightforward.
- **Minimal named location.** Each SPN's allow-list is scoped to exactly the runners its pipeline uses. A pipeline running on a self-hosted runner with a known NAT IP has a single-range allow-list.
- **Independent rotation.** Credential rotation for one pipeline SPN does not affect any other pipeline.

### 3.4 Naming convention recommendation

Use the format:

```text
SPN-<Service>-<Pipeline>-<Environment>
```

Examples:

| SPN name | Service | Pipeline | Environment |
|---|---|---|---|
| `SPN-Frameworks-Deploy-Prod` | Frameworks | Deploy | Production |
| `SPN-Frameworks-Deploy-Dev` | Frameworks | Deploy | Development |
| `SPN-API-IntegrationTest-Staging` | API | IntegrationTest | Staging |
| `SPN-Infra-Provision-Prod` | Infra | Provision | Production |

The naming convention should be codified in the tenant's identity register (an inventory document or the Notes field on each SPN in the Entra admin center) so that sign-in log entries can be resolved to an owner and a pipeline without manual lookup.

### 3.5 Role-assignment hygiene

Apply the minimum role required for the pipeline's target:

- Use resource-group scope or workspace scope, not subscription scope, unless the pipeline explicitly requires subscription-wide access.
- Document the role assignment per SPN in a tenant-side register. The register should record: SPN display name, object ID, assigned role, assignment scope, pipeline owner, and review date.
- Review the register quarterly alongside the CA-EXC001 and CA-EXC002 attestation cadence.
- Avoid Contributor at subscription scope unless the pipeline deploys infrastructure that spans resource groups by design. Even then, prefer the more granular role.

---

## 4. Trusted IPs Refresh Cadence

`CA-COV010` evaluates the named location at every service-principal sign-in. If the named location is stale — if the runner's egress IP has changed and the new IP is not in the allow-list — the sign-in is blocked and the pipeline fails with `AADSTS53003`.

Maintaining the named location is an ongoing operational responsibility. The effort required depends on the runner class.

### 4.1 GitHub Actions hosted runners

GitHub Actions Microsoft-hosted runners have dynamic egress IPs. The current published IP ranges are available at the GitHub meta API:

```text
https://api.github.com/meta
```

The `actions` key in the JSON response contains the current egress ranges for the Actions platform. GitHub updates this list continuously as infrastructure changes. As of 2026, this means the range list can change week to week without advance notice.

**Recommended cadence:** Refresh weekly. Additionally, monitor every `CA-COV010` block event tagged to a GitHub Actions SPN. A block event that did not occur previously is a leading indicator that the named location is stale before the weekly refresh cycle catches it.

Reference: [About GitHub-hosted runners — IP addresses](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners#ip-addresses)

**Operational note:** The GitHub meta API returns a large range list. As of 2026, the `actions` array contains over 100 CIDR entries. Adding every entry to the named location is the safe approach but results in a broad allow-list. For tighter control, route GitHub Actions sign-ins through a self-hosted runner or a proxy with a known egress IP. See Section 4.3 and Section 8.

### 4.2 Azure DevOps Microsoft-hosted agents

Microsoft-hosted Azure DevOps agents also use rotating egress IPs. Microsoft publishes the current IP ranges in a regularly updated file. The current URL and download instructions are at:

Reference: [Azure DevOps — Allow-list IP addresses and URLs](https://learn.microsoft.com/en-us/azure/devops/organizations/security/allow-list-ip-url)

**Recommended cadence:** Refresh weekly, aligned with the Microsoft publication cadence.

The Azure DevOps range list is segmented by region and agent pool. If your pipelines use agents in a specific region, you can scope the named location to that region's ranges rather than the full global list. This reduces the allow-list size and improves the precision of the egress constraint.

### 4.3 Self-hosted runners

Self-hosted runners — GitHub Actions self-hosted, Azure DevOps self-hosted, or any CI platform running on tenant-owned infrastructure — have tenant-controlled egress.

The recommended model: route all self-hosted runner outbound traffic through a NAT gateway or a transparent proxy with a static IP or small, stable CIDR range. The named location is configured once with that range and updated only when the infrastructure changes.

**Recommended cadence:** Update on infrastructure changes only. There is no recurring operational refresh obligation. The egress range is under the tenant's control and changes only when the NAT gateway or proxy is provisioned, scaled, or migrated.

Self-hosted runners are strongly preferred for high-security or audit-sensitive workloads because the named location becomes a one-time setup rather than a recurring operational tax. See Section 8 for a full comparison.

### 4.4 Refresh automation

The named location can be updated programmatically via the Microsoft Graph API. The endpoint is:

```text
PATCH https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations/{namedLocationId}
```

The request body must include the full `ipRanges` array. The API does not support incremental adds — the full list replaces the prior list on every PATCH.

Outline of an automation pattern (outline only; not shipped in this PR):

```powershell
# Outline only; not shipped in this PR.
# Reads source-of-truth IP ranges, computes diff against the named location, applies via Graph.
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

$gh = Invoke-RestMethod "https://api.github.com/meta"
$actionsRanges = $gh.actions

$existing = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations/<NamedLocationId>"

# Compute diff between $actionsRanges and $existing.ipRanges[].cidrAddress.
# Build the updated ipRanges array.
# PATCH the namedLocation with the updated ipRanges array.
```

Adopters may write their own automation against this pattern or use the manual refresh path. A named-location refresh utility may ship in `Scripts/` in a future release if adopter demand warrants. See Section 10.

**Important:** Any automated refresh must enforce the principle that the allow-list contains only what is currently needed. Do not automate an expand-only pattern that never removes stale ranges. An expand-only pattern grows the allow-list indefinitely and eventually spans ranges that the runner infrastructure no longer uses.

---

## 5. Rollback Procedure When CI Runners Change Egress

### 5.1 Detection

When a runner's egress IP is not in the named location, the sign-in is blocked. The observable signals are:

- **Microsoft Entra sign-in logs** — the blocked sign-in event shows `AADSTS53003` (access blocked by Conditional Access policy), the policy name `CA-COV010-WorkloadIdentities-TrustedLocations`, and the source IP of the runner that attempted authentication.
- **Pipeline logs** — the pipeline step that authenticates (Azure login, Azure CLI token acquisition, GitHub OIDC token exchange) fails. The error message contains a Graph or ARM error code, commonly a `403` with a message referencing Conditional Access, or an AADSTS code surfaced by the identity library.

The sign-in log is the authoritative diagnostic source. The pipeline error is the first observable signal, but it does not contain the blocked IP. Correlating the pipeline failure timestamp with the sign-in log gives both the error code and the source IP.

### 5.2 Diagnosis

1. Open the Microsoft Entra admin center and navigate to Identity > Monitoring and health > Sign-in logs.
2. Filter by: Application type = Service principal, Date = failure window, Status = Failure.
3. Locate the blocked sign-in for the affected SPN. The `IP address` field shows the runner's egress IP at the time of the attempt.
4. Compare that IP against the CIDR ranges in the named location. The mismatch identifies the drift — the runner is now using an IP not covered by the current named location.
5. Determine whether the new IP is a transient runner address or a permanent infrastructure change. For GitHub Actions and Azure DevOps Microsoft-hosted agents, check the current published range list to confirm the new IP falls within the published set.

### 5.3 Rollback path A — temporary widening

Add the new IP range to the named location. This restores pipeline access immediately.

Steps:

1. In the Entra admin center, open the Trusted IPs named location.
2. Add the new CIDR range (or ranges) covering the runner's new egress IP.
3. Save. Named location updates take effect within a few minutes; no policy republish is required.
4. Re-run the failed pipeline job to confirm access is restored.
5. Schedule a follow-up to re-scope the named location after verifying the runner's new range is stable. If the old range is no longer in use, remove it during the follow-up update.

**Blast-radius note:** Temporarily widening the named location reduces the security margin of `CA-COV010` for the affected SPN. Document the widening in a change record, with a follow-up task to re-scope. Do not leave widened ranges in the named location indefinitely.

### 5.4 Rollback path B — emergency exclusion

If path A is not immediately available (for example, the named location is managed by a separate team and the update will take hours to process), temporarily add the SPN to the `excludeServicePrincipals` list on `CA-COV010-WorkloadIdentities-TrustedLocations`.

Steps:

1. Via the Entra admin center or via Graph, add the affected SPN's object ID to `excludeServicePrincipals` on `CA-COV010-WorkloadIdentities-TrustedLocations`.
2. The policy update removes the Trusted IPs constraint for that SPN. Pipeline access is restored immediately.
3. Treat this as a break-glass action. The SPN now has no egress constraint. Escalate to the named-location update as quickly as possible.

**Risk:** Path B removes the Trusted IPs guarantee for the affected SPN for the duration of the emergency exclusion. A credential compromise during this window is redeemable from any IP. Use path B only when path A is not executable within an acceptable time window.

### 5.5 Promotion back to baseline

After the named location is updated and verified:

1. If path B was used: remove the SPN from `excludeServicePrincipals`. Confirm that sign-ins from the updated named location pass — the sign-in log shows `CA-COV010` as `success` for the SPN.
2. If path A was used: re-scope the named location to remove any ranges that are no longer accurate. Confirm that sign-ins pass from the current runner egress and that no additional widening is in place.
3. Update the tenant-side SPN register with the current named location ranges for each affected SPN.

---

## 6. GitHub Actions Example

The recommended authentication pattern for GitHub Actions pipelines authenticating to Azure is Workload Identity Federation. A federated credential on the SPN trusts the GitHub OIDC issuer for a specific repository and branch. No client secret or certificate is stored in the pipeline.

### 6.1 Federated credential configuration

On the SPN, configure a federated credential with:

- **Issuer:** `https://token.actions.githubusercontent.com`
- **Subject:** `repo:<org>/<repo>:ref:refs/heads/<branch>` (for branch-scoped trust) or `repo:<org>/<repo>:environment:<env>` (for environment-scoped trust)
- **Audience:** `api://AzureADTokenExchange`

The GitHub Actions workflow presents an OIDC token from the Actions token service. Microsoft Entra validates the token against the federated credential trust and exchanges it for an Entra access token. The SPN authenticates without a stored secret.

### 6.2 Workflow example

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Authenticate to Azure
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Deploy
        run: |
          az deployment group create \
            --resource-group rg-frameworks-prod \
            --template-file ./infra/main.bicep
```

`permissions.id-token: write` enables the OIDC token request within the workflow. The `azure/login@v2` action exchanges the OIDC token for an Entra access token using the SPN identified by `client-id`. No `client-secret` input is present.

### 6.3 What CA-COV010 evaluates

The runner's egress IP — the IP of the GitHub Actions Microsoft-hosted runner that executes the `azure/login` step — is the `clientIpAddress` that `CA-COV010` evaluates at sign-in time.

**Federated credentials do not bypass Conditional Access.** The OIDC token exchange is how the SPN authenticates; Conditional Access still evaluates the resulting sign-in event. The policy applies to the service-principal sign-in that results from the token exchange. If the runner's egress IP is not in the named location, `CA-COV010` blocks the sign-in before the access token is issued.

The named location for this SPN must cover the egress IP ranges of GitHub Actions Microsoft-hosted runners for the runner types used by the workflow (`ubuntu-latest`, `windows-latest`, etc.). See Section 4.1 for the IP range source and refresh cadence.

---

## 7. Azure DevOps Example

The recommended authentication pattern for Azure DevOps pipelines is a Workload Identity Federation service connection. The service connection uses federated credentials on the SPN, trusting the Azure DevOps issuer. No secret is stored in the service connection.

### 7.1 Service connection configuration

In Azure DevOps:

1. Open **Project settings > Service connections > New service connection > Azure Resource Manager**.
2. Select **Workload Identity Federation (automatic)** or **Workload Identity Federation (manual)**.
   - The automatic path creates the SPN and federated credential in one step.
   - The manual path requires the SPN to be pre-created with a federated credential trusting the Azure DevOps issuer:
     - **Issuer:** `https://vstoken.dev.azure.com/<organization-id>`
     - **Subject:** `sc://<organization>/<project>/<service-connection-name>`
     - **Audience:** `api://AzureADTokenExchange`

### 7.2 Pipeline step example

```yaml
steps:
  - task: AzureCLI@2
    displayName: Deploy to Azure
    inputs:
      azureSubscription: 'SPN-Frameworks-Deploy-Prod'
      scriptType: 'bash'
      scriptLocation: 'inlineScript'
      inlineScript: |
        az deployment group create \
          --resource-group rg-frameworks-prod \
          --template-file ./infra/main.bicep
```

`azureSubscription` references the service connection name. The pipeline task uses the federated token exchange to authenticate as the SPN before running the Azure CLI command.

### 7.3 What CA-COV010 evaluates

As with GitHub Actions, the egress IP of the Microsoft-hosted Azure DevOps agent running the `AzureCLI@2` task is the `clientIpAddress` evaluated by `CA-COV010`.

**Federated credentials do not bypass Conditional Access.** The Workload Identity Federation token exchange results in a service-principal sign-in event that Conditional Access evaluates normally. If the agent's egress IP is not in the named location, the sign-in is blocked and the pipeline step fails.

The named location for this SPN must cover the egress IP ranges for the Azure DevOps region and agent pool hosting the pipeline. See Section 4.2 for the IP range source and refresh cadence.

---

## 8. Microsoft-Hosted vs Self-Hosted Considerations

| Runner type | Egress IP volatility | Refresh cadence | Operational overhead |
|---|---|---|---|
| GitHub Actions hosted | High (continuous rotation) | Weekly | High |
| Azure DevOps Microsoft-hosted | Medium (documented periodic file) | Weekly | Medium |
| Self-hosted (any) | Low (tenant-owned NAT or proxy) | On infrastructure changes only | Low |

### 8.1 High-security workloads

For high-security or audit-sensitive workloads, self-hosted runners behind a known NAT gateway or transparent proxy are strongly preferred. The rationale:

- The named location becomes a one-time setup. The egress IP is under the tenant's control and changes only when infrastructure changes deliberately.
- The allow-list can be a single `/32` or a small `/29` or `/28` CIDR. This is a materially tighter constraint than the hundred-plus entries required to cover GitHub Actions hosted runner ranges.
- Forensic correlation is more precise. A sign-in from the NAT IP can be correlated to the runner host via infrastructure logs, not just the runner pool identifier.
- No dependency on a third party to publish accurate and timely IP range updates.

### 8.2 Trade-offs of hosted runners

The trade-off of using hosted runners is lower infrastructure management burden offset by higher named-location management burden. Hosted runners:

- Require no runner infrastructure provisioning or maintenance.
- Provide automatic updates and security patches.
- Scale elastically with parallel jobs.
- Require ongoing named-location refresh to keep `CA-COV010` accurate. An outdated named location causes pipeline failures that interrupt delivery.

The operational tax of named-location refresh for hosted runners is non-trivial at scale. A tenant with ten pipelines on GitHub Actions hosted runners has ten SPNs whose named locations need regular verification against the current GitHub meta API output.

### 8.3 Hybrid approach

A common hybrid: use hosted runners for non-privileged pipelines (test, lint, documentation build) and self-hosted runners for privileged pipelines (infrastructure provisioning, production deployments, secrets access). The privileged pipelines use SPNs with tight, stable egress constraints. The non-privileged pipelines have less sensitive role assignments and a broader but still bounded named location.

---

## 9. Coverage Seams and Trade-Offs

The Trusted IPs named-location pattern provides strong egress-scoping for workload identities. The following scenarios fall outside its protection boundary.

### 9.1 Pre-auth IP capture

An attacker who exfiltrates SPN credentials and runs the authentication from within the allow-list — for example, from a compromised cloud instance in the same region as the CI runner — will pass the `CA-COV010` check. The named location validates the source IP, not the identity of the machine at that IP.

Mitigations outside this pattern:

- Prefer federated credentials (Sections 6 and 7) over client secrets. Federated credentials cannot be exfiltrated as static secrets.
- Entra ID Identity Protection for workload identities monitors for anomalous SPN sign-in patterns and can surface risk signals via `servicePrincipalRiskLevels`.
- Rotate client secrets on a defined cadence if federated credentials are not available for a given pipeline.

### 9.2 Token replay from inside the allow-list

The named location is evaluated at sign-in time (token issuance). It does not bind the issued access token to the source IP at redemption time. If an access token is exfiltrated after issuance — from memory on the runner, from a log file, or from a CI artifact — the token can be replayed from any IP until it expires.

For service-principal tokens, Continuous Access Evaluation does not apply (see the paired contract for the full CAE limitation). Token expiry is the enforcement boundary.

Mitigations:

- Keep access token lifetime at the platform default; do not configure extended token lifetimes for pipeline SPNs.
- Log access to sensitive resources, not just authentication events. A token replay will not appear in the Entra sign-in log but will appear in the resource access log (Azure Monitor, resource audit log).

### 9.3 SPN credential rotation hygiene

Credential rotation for pipeline SPNs — frequency, automation, secret-scanning integration — is out of scope for this document. Federated credentials (OIDC) eliminate stored secrets entirely and are the preferred path. If client secrets are used, the tenant-level credential lifecycle policy governs rotation.

### 9.4 Managed identities and other workload identity classes

`CA-COV010` targets service principals via the `clientApplications.includeServicePrincipals` condition. Managed identities (system-assigned and user-assigned) do not authenticate via the same flow and are not in scope for this policy.

Federated credential scenarios that use external IdPs other than GitHub and Azure DevOps — for example, GitLab, Bitbucket, or custom OIDC providers — follow the same pattern as Sections 6 and 7. The named location applies to whatever IP the federated credential exchange originates from. The pattern generalizes to any OIDC issuer configured as a federated credential on the SPN.

---

## 10. Cross-References

- **Paired contract:** [`Policies/CA-COV010-WorkloadIdentities.md`](../Policies/CA-COV010-WorkloadIdentities.md) — policy mechanics, Workload Identities Premium SKU prerequisite, Trusted IPs named location creation, per-SPN exclusion model, SPN discovery query, CAE limitation.
- **Policy template:** [`Policies/CA-COV010-WorkloadIdentities-TrustedLocations.json`](../Policies/CA-COV010-WorkloadIdentities-TrustedLocations.json) — the deployable policy JSON.
- **Policy design spec:** [`Design/POLICY-DESIGN.md`](POLICY-DESIGN.md) section 6.13 — per-policy intent, principle mapping, scope, grant control, license requirements.
- **Workload Identities Premium SKU:** documented in the paired contract. Required before enforcing `CA-COV010` past report-only.
- **Microsoft Entra named location documentation:** [Conditional Access — named locations and network assignment](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network).
- **GitHub Actions IP ranges:** [About GitHub-hosted runners — IP addresses](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners#ip-addresses). Current ranges available at `https://api.github.com/meta` (the `actions` key). Verify against current sources before provisioning; the range list is updated continuously as of 2026.
- **Azure DevOps IP ranges:** [Allow-list IP addresses and URLs](https://learn.microsoft.com/en-us/azure/devops/organizations/security/allow-list-ip-url). Verify against current sources before provisioning; Microsoft updates the published file periodically as of 2026.
- **Future v1.4 candidate:** a named-location refresh utility script in `Scripts/` if adopter demand warrants. See the v1.4 roadmap in [`README.md`](../README.md).
