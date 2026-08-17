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
| `TenantId` | String | Yes | — | Entra tenant **GUID**. Used to authenticate |
| `TenantName` | String | No | empty | Friendly organisation name, carried into `ITPSResult` so the formatter inherits it |
| `OutputPath` | String | No | `.` | Directory for JSON export |
| `ExportJson` | Switch | No | Off | Export the result to a timestamped JSON file |

**Format-ITPScorecardReport.ps1**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `Result` | PSCustomObject | Yes (Object set) | — | The `ITPSResult` object, accepts pipeline input |
| `InputPath` | String | Yes (File set) | — | Path to an exported `ITPSResult` JSON file |
| `OutputPath` | String | No | `.` | Directory for the 3 Markdown reports |
| `TenantName` | String | No | inherited | Overrides the `TenantName` carried in the result object |

Output files are named `<TenantName>-<date>-technical.md`, `-exec-summary.md`, and `-board.md`.

### How the display name is resolved

`TenantId` is the tenant GUID and is what the collector authenticates with. `TenantName` is presentation only. The formatter resolves the label in this order:

1. `-TenantName` passed to the formatter (explicit override)
2. `TenantName` carried in the `ITPSResult` from the collector
3. the tenant GUID

Supplying `-TenantName` on the **collector** is usually enough — the name travels with the result object, so the JSON export is self-describing and the formatter picks it up without repeating it:

```powershell
.\Get-ITPScorecard.ps1 -TenantId '<tenant-guid>' -TenantName 'Cloud Harbor Demo' -ExportJson -OutputPath '.\reports'
.\Format-ITPScorecardReport.ps1 -InputPath '.\reports\ITPSResult-<timestamp>.json' -OutputPath '.\reports'
```

Result files produced before the collector carried `TenantName` still format correctly and fall back to the GUID.

---

## Output object shape

```
ITPSResult
├── TenantId            (string — tenant GUID)
├── TenantName          (string — friendly name, empty when not supplied)
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

Two Governance checks add a fourth outcome: **the call succeeded, records came back, and the records do not answer the question.**

| Check | When it happens | Why it is not scored |
|---|---|---|
| G-02 Guest access reviewed | Review definitions exist, but none exposes a scope filter the collector can read | Guest coverage cannot be determined either way. Scoring zero would understate a tenant that does review guests; scoring full marks is the defect this replaces. A tenant with **no** review definitions at all still scores zero, because that is a genuine absence rather than an unknown |
| G-04 Standing privilege minimised | Both PIM endpoints answer but return no role assignments at all | Every tenant holds at least one privileged assignment, so an empty set is an unreadable signal rather than zero standing privilege. Scoring it would award full points for missing data |
| D-01 to D-04 Detection health | No open health issues **and** no evidence that Defender for Identity sensors are deployed | A tenant with healthy sensors and a tenant with no sensors both return an empty collection. Full marks would certify a detection capability that may not exist |

**How sensor deployment is evidenced.** The collector reads the `AATP_Sensor` Secure Score control from the `controlScores` payload it already retrieves for P-01 — no extra request, no extra scope. Its `implementationStatus` names the domain controller count and how many carry a sensor; `scoreInPercentage` reaches 100 at full coverage. The similarly-named `AATP_DefenderForIdentityIsNotInstalled` is **not** used: on a tenant with sensors on all 3 domain controllers it scored 0 with an empty status, so treating it as an installed flag misreports a fully deployed tenant. When health issues are returned, sensors demonstrably exist and the evidence check is skipped.

G-02 records the review names it evaluated, the scope queries it found, and the pattern it matched on, so a disputed result can be checked against the tenant rather than taken on trust.

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

## Troubleshooting

**Repeated authentication prompts, or the collector appears to hang.**
The collector authenticates exactly once, via a single `Connect-MgGraph` call. If Windows Web Account Manager prompts more than once in a single run, the run is taking long enough to cross a token-refresh boundary, which means something is issuing far more Graph requests than it should.

Measure the request count for a suspect endpoint before assuming a credential problem:

```powershell
$u = 'https://graph.microsoft.com/v1.0/<endpoint>'
$n = 0; $sw = [Diagnostics.Stopwatch]::StartNew()
do {
  $r = Invoke-MgGraphRequest -Method GET -Uri $u -OutputType PSObject; $n++
  $u = if ($r.PSObject.Properties.Name -contains '@odata.nextLink') { $r.'@odata.nextLink' } else { $null }
} while ($u -and $n -lt 500)
"pages: $n   elapsed: $($sw.Elapsed)"
```

In Microsoft Graph, **`$top` sets the page size, not a result limit.** A URI such as `secureScores?$top=1` returns one record per page plus a `nextLink`, so paging it to exhaustion issues one request per record. Where only the newest record is wanted, the collector passes `-FirstPageOnly`.

**A run that pauses with a throttling message.**
Microsoft Graph throttles **per service, not per tenant**, so one endpoint can return `429 TooManyRequests` while every other call in the same run succeeds. The Identity Governance endpoints have tighter limits than most, and repeated assessments of the same tenant within an hour can reach them.

The collector retries transient failures (429, 500, 502, 503, 504) up to `-MaxRetry` times, honouring the `Retry-After` header where Graph sends one and falling back to exponential backoff where it does not, capped at 60 seconds per wait. Each wait prints a line naming the status code, the endpoint, and the retry number, so a pause is never silent:

```
  [!] Graph returned 429 for identityGovernance/accessReviews/definitions. Waiting 12s, then retry 1 of 5.
```

If the retries are exhausted the affected checks fall to `ManualReview` and are excluded from the denominator, so a transient throttle produces an honest partial score rather than a wrong one. Re-running after a few minutes usually clears it.

Non-transient failures — `403`, `404` — are not retried and fail immediately with the status code and the message Graph returned.

**A hidden sign-in window.** The Graph SDK warns that WAM sign-in may open behind other windows when run from an embedded terminal. If the first prompt never appears, check for a window behind the console before assuming the script is stuck.

## Testing status

The formatter has been exercised end-to-end against synthetic `ITPSResult` data on both parameter sets, including a JSON round-trip, and against live collector output.

**The collector has been run against a live Microsoft 365 tenant.** That first live run produced a complete assessment across all 4 dimensions, and surfaced 3 defects that static analysis could not reach:

- a successful Graph call returning **zero records** was treated as a failed call and excluded from the dimension denominator, rather than scored as a genuinely absent control
- a dimension with no gaps crashed report generation in the formatter
- the Secure Score request paged the tenant's entire retained Secure Score history to obtain a single record

All 3 are fixed. The CHANGELOG carries the root cause and the verification method for each.

**Validation so far is a single tenant.** Controls that were absent from that tenant exercised the absent-control path but not the populated-control path, and checks that returned `ManualReview` were not scored at all. Run it against a lab tenant that resembles your target environment before relying on it in a client engagement.
