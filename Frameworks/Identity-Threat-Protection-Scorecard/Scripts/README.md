# ITPS Scripts

Two scripts for the Identity Threat Protection Scorecard.

- **Get-ITPScorecard.ps1** — collector: reads Microsoft Graph and returns an `ITPSResult` object
- **Format-ITPScorecardReport.ps1** — formatter: converts an `ITPSResult` into 3 report shapes

---

## Prerequisites

| Requirement | Detail |
|---|---|
| PowerShell | 7.0 or later |
| Module | `Microsoft.Graph.Authentication` — install via `Install-Module Microsoft.Graph.Authentication` |
| Permissions | Global Reader or Security Reader, plus a role or app registration granting the 6 scopes below |
| License | Entra ID P2 for the Governance dimension (Access Reviews, PIM). Defender for Identity for the Detection dimension |

---

## Required Graph scopes

All read-only. The collector requests no write permission.

| Scope | Dimension | What it reads |
|---|---|---|
| `SecurityEvents.Read.All` | Prevention | `GET /security/secureScores` — tenant Secure Score and Identity-category control breakdown |
| `Policy.Read.All` | Prevention | `GET /identity/conditionalAccess/policies` — Conditional Access configuration |
| `SecurityIdentitiesHealth.Read.All` | Detection | `GET /security/identities/healthIssues` — Defender for Identity deployment health |
| `AccessReview.Read.All` | Governance | `GET /identityGovernance/accessReviews/definitions` — access review definitions |
| `RoleManagement.Read.Directory` | Governance | PIM eligible and active role assignment schedule instances |
| `Application.Read.All` | Governance | `GET /applications` — workload identity credential expiry |

`SecurityEvents.Read.All` and `SecurityIdentitiesHealth.Read.All` are the least-privileged permissions documented for their respective endpoints.

---

## Authentication

**Interactive (recommended for a first assessment):**

```powershell
.\Get-ITPScorecard.ps1 -TenantId '<your-tenant-id>'
```

A browser sign-in prompt appears. Sign in with an account holding the scopes above.

**Service principal (unattended):**

```powershell
Connect-MgGraph -TenantId '<tenant-id>' -ClientId '<app-id>' -CertificateThumbprint '<thumbprint>'
.\Get-ITPScorecard.ps1 -TenantId '<tenant-id>'
```

Grant the 6 application permissions to the app registration and obtain admin consent before running.

---

## Usage

```powershell
# Collect, result returned to the pipeline
$result = .\Get-ITPScorecard.ps1 -TenantId '<tenant-id>'

# Collect and export JSON for archiving
.\Get-ITPScorecard.ps1 -TenantId '<tenant-id>' -ExportJson -OutputPath '.\Results'

# Format all 3 reports from the object
.\Format-ITPScorecardReport.ps1 -Result $result -OutputPath '.\Reports' -TenantName 'Fabrikam'

# Or format from a previously exported JSON file
.\Format-ITPScorecardReport.ps1 -InputPath '.\Results\ITPSResult-20260813-090000.json' -OutputPath '.\Reports'
```

### Parameters

**Get-ITPScorecard.ps1**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `TenantId` | String | Yes | — | Entra tenant ID to assess |
| `OutputPath` | String | No | `.` | Directory for JSON export |
| `ExportJson` | Switch | No | Off | Export the result to a timestamped JSON file |

**Format-ITPScorecardReport.ps1**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `Result` | PSCustomObject | Yes (Object set) | — | The `ITPSResult` object, accepts pipeline input |
| `InputPath` | String | Yes (File set) | — | Path to an exported `ITPSResult` JSON file |
| `OutputPath` | String | No | `.` | Directory for the 3 Markdown reports |
| `TenantName` | String | No | TenantId | Display name used in filenames and headers |

Output files are named `<TenantName>-<date>-technical.md`, `-exec-summary.md`, and `-board.md`.

---

## Output object shape

```
ITPSResult
├── TenantId            (string)
├── AssessmentDate      (ISO 8601 string)
├── CollectorVersion    (string)
├── OverallScore        (int 0-100, nullable)
├── MaturityTier        (string: Connected | Protected | Fortified | Resilient | Not scored)
├── IsPartialScore      (bool — true when any dimension could not be scored)
├── UnscoredDimensions  (string[])
├── ManualReviewCount   (int)
├── TotalCheckCount     (int)
├── GraphScopesUsed     (string[])
├── TierBandSource      (string — the tier-threshold disclosure)
└── Dimensions[]
    ├── Name            (string: Prevention | Detection | Governance | Ownership)
    ├── Score           (int 0-100, nullable — null when every check is manual)
    ├── Weight          (int — 25 for all four)
    └── Checks[]
        ├── Id               (string, e.g. "P-01")
        ├── Name             (string)
        ├── Points           (double — earned)
        ├── MaxPoints        (double — available)
        ├── ManualReview     (bool)
        ├── ManualReviewNote (string — portal navigation)
        ├── RepoXRef         (string — related repo artifact)
        └── Signal           (hashtable — raw values observed)
```

---

## Manual review guidance

The collector never scores a check it could not assess. Manual checks are excluded from the dimension denominator, so a partial assessment produces an honest partial score rather than an artificially depressed one.

| Check | Why it is manual | Where to assess it |
|---|---|---|
| D-05 | The Defender Coverage and maturity composite score has no API | Defender portal > Identities > Coverage and maturity |
| O-01 to O-06 | Ownership is an organisational fact, not tenant configuration | `Examples/Ownership-Matrix-Template.md` |

### Absent versus unassessable

The collector distinguishes 3 outcomes per Graph call, and they are scored differently:

| Outcome | Meaning | Scoring |
|---|---|---|
| Call succeeds, records returned | The control exists and can be evaluated | Scored on its merits |
| Call succeeds, **zero records** | The control is genuinely **absent** | **Scored zero** and counted in the denominator |
| Call fails | The control **could not be assessed** | `ManualReview`, excluded from the denominator |

The middle row matters. A tenant with no access reviews configured, or no Conditional Access policies, has genuinely absent controls — those score zero rather than being excluded, because excluding them would inflate the dimension.

When a call does fail, the `ManualReviewNote` carries **the actual error message returned by Graph**. Earlier versions asserted a probable cause (usually licensing) without evidence; the note now reports what happened and flags the common cause as a hypothesis to confirm rather than a conclusion.

**Always report an automated-only run as a partial score.** The collector sets `IsPartialScore` and lists `UnscoredDimensions` so the formatter can label it, and all 3 reports carry the label automatically. Ownership is manual in full, so every automated-only run is partial by definition.

---

## Scoring logic

**Check** — earns `Points` out of `MaxPoints`.

**Dimension score** — sum of earned points over sum of available points across scored checks, normalised to 0-100. Manual checks are excluded from both sums.

**Overall score** — the mean of the scored dimension scores, rounded to the nearest whole number. Dimensions with no scored checks are excluded from the mean and listed in `UnscoredDimensions`.

**Maturity tier** — 0-39 Connected, 40-64 Protected, 65-84 Fortified, 85-100 Resilient.

These tier bands are a Cloud Harbor Consulting scoring convention. Microsoft does not publish numeric thresholds for its Connected, Protected, Fortified, and Resilient tiers, and an ITPS tier will not necessarily match the tier on the Defender Coverage and maturity page. See `Design/SCORING-METHODOLOGY.md` for the full disclosure and the reasoning behind the band boundaries.

---

## Testing status

The formatter has been exercised end-to-end against synthetic `ITPSResult` data on both parameter sets, including a JSON round-trip.

**The collector has not been run against a live Microsoft 365 tenant.** It is written to the same standard as the Zero Trust Readiness Assessment collector and passes static analysis, but Graph response shapes are only fully proven by execution. Run it against a lab tenant before relying on it in a client engagement, and expect the same kind of shake-out the ZTRA collector required on first live run.
