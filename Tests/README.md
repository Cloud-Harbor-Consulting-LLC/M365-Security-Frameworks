# Tests

Offline checks for the repository. Nothing here signs in to a tenant or calls a live API. The harnesses mock Microsoft Graph, and the other checks read only the files in the repository. CI runs all of them on every push and pull request (`.github/workflows/ci.yml`).

## Running them

From the repository root, with PowerShell 7:

```powershell
./Tests/Invoke-Tests.ps1          # every *.Harness.ps1 under Tests/
./Tests/Invoke-ScriptAnalysis.ps1 # parse errors and Error-severity PSScriptAnalyzer findings
./Tests/Test-Repository.ps1       # JSON, relative links, documented invariants
```

`Invoke-ScriptAnalysis.ps1` needs PSScriptAnalyzer (`Install-Module PSScriptAnalyzer -Scope CurrentUser`). CI pins version 1.25.0.

## What is covered

| Harness | Script under test | Covers |
|---|---|---|
| `Conditional-Access-Baseline/Deploy-CABaseline.Harness.ps1` | `Deploy-CABaseline.ps1` | Default policy path; every placeholder in the 28 templates has a resolver; expansion over all templates with the unresolved-placeholder guard; the Trusted IPs resolver's not-found, duplicate and found cases; the CA policy cross-references printed by the ITPS and ZTRA collectors |
| `Conditional-Access-Baseline/Deploy-CABPolicyPlans.Harness.ps1` | `Preview/Policy-Plans/Scripts/Deploy-CABPolicyPlans.ps1` | Runs the deployer end to end against a stateful fake of the Graph calls it makes: `-WhatIf` writes nothing; all 3 plans posted with rules inline, placeholders resolved and every rule report-only; existing plans skipped; missing groups and Terms of Use stop it before any write, and the Terms of Use is only needed for P6; plan files that aren't report-only or carry an unknown placeholder are refused; read-back reports values the service changed and ignores values it only added |
| `Conditional-Access-Baseline/Policy-Plans.Harness.ps1` | `Preview/Policy-Plans/Scripts/Export-CABPolicyPlans.ps1` | The rule-versus-policy comparison against sanitized exports of 3 demo-tenant plans (`Fixtures/Plans/`): 8 rules match and CA-SIG006 differs only in its 3 guest-type paths; mutations that must and must not produce a difference; and the reference plans in `Preview/Policy-Plans/Plans/` reproducing their templates |
| `Conditional-Access-Baseline/Compare-CABPlanRuleSignIns.Harness.ps1` | `Preview/Policy-Plans/Scripts/Compare-CABPlanRuleSignIns.ps1` | Decision comparison (a report-only `interrupted` equals the enforced `failure`), pairing rules with same-named policies, the would-fail list and policies seen without their rule, over constructed sign-ins in the shape the demo tenant returned |
| `Identity-Threat-Protection-Scorecard/Get-ITPScorecard.Harness.ps1` | `Get-ITPScorecard.ps1` | Governance and Detection scoring, scope-filter matching for access reviews, sensor-deployment evidence |
| `Identity-Threat-Protection-Scorecard/Get-ITPScorecard.Throttle.Harness.ps1` | `Get-ITPScorecard.ps1` | Retry on 429 and 5xx with `Retry-After`, immediate failure on 403, paging under throttling |
| `Identity-Threat-Protection-Scorecard/Get-ITPScorecard.Evidence.Harness.ps1` | `Get-ITPScorecard.ps1` | `-IncludeEvidence` output, CA policy matching, phishing-resistant authentication strength classification |
| `Intune-Compliance-Baseline/Deploy-ICBaseline.Harness.ps1` | `Deploy-ICBaseline.ps1` | Runs the deployer end to end against a stateful fake of both Intune compliance APIs, built from responses recorded on a live tenant (`Fixtures/Live/`): observation and enforce schedules, promotion in place, the Linux schedule that Graph silently replaces on create, read-back mismatches, drift with and without `-UpdateExisting`, assignment merging, missing groups and templates, tenant-setting warnings, `-WhatIf`, throttling and paging |
| `Zero-Trust-Readiness-Assessment/Get-ZTReadinessScore.Harness.ps1` | `Get-ZTReadinessScore.ps1`, `Format-ZTReadinessReport.ps1` | Collection outcomes (data, empty, failed), the request layer, scoring precision, the formatter end to end across six result shapes, and version consistency across the framework |

`Test-Repository.ps1` checks that:

- every JSON file parses;
- every relative Markdown link resolves;
- every Conditional Access template ships report-only, with a `displayName` matching its file name;
- the Board & Executive Policy Kit's copy of `Board-Posture-Summary.md` matches the canonical one in `Examples/`;
- the policy plans fixtures and preview files carry no tenant identifiers: every GUID is sanitized or already published in the CA templates, and there's no email address or `onmicrosoft.com` domain;
- every Intune Compliance Baseline template meets the invariants `Deploy-ICBaseline.ps1` relies on, and classic Windows, macOS, iOS and Android templates use only properties and value types that a live tenant's read-back for that platform contains (`classic-readback.json`, `macos-readback.json`, `ios-readback.json`, `android-deviceowner-readback.json` and `android-workprofile-readback.json` in `Intune-Compliance-Baseline/Fixtures/Live/`).

## Harness conventions

A harness is a plain PowerShell 7 script named `*.Harness.ps1`, kept in a folder named after its framework. `Invoke-Tests.ps1` runs each one in its own process and requires all of the following:

- **Exit 0 and a closing `passed: N   failed: 0` line, with N greater than 0.** A harness that crashes, exits non-zero, or never prints its summary counts as failed.
- **Test the shipped code, not a copy of it.** Extract functions from the script under test via the PowerShell AST and run them; do not re-implement them in the harness.
- **Locate the repository from the harness's own path** (`$PSScriptRoot`), never from an absolute path.
- **A harness may instead run the whole script.** When the logic under test lives in the script's main body, as in `Deploy-ICBaseline.ps1`, run the shipped file unmodified with the Graph cmdlets replaced by functions of the same name.
- **Mock what was observed, not what was assumed.** When a script talks to Graph, the mock returns the shapes a real tenant returned, error responses included. Several defects in this repository were invisible to mocks built from documentation and surfaced only against a live tenant.
- **Watch for unrolled and double-wrapped arrays.** A helper that returns `, @(...)` must not be wrapped in `@()` again: the result is an array inside an array, its `.Count` is 1 even when empty, and an assertion such as "created exactly once" passes when nothing was created.
- **Prove each assertion can fail.** Before relying on a new assertion, run it against the code with the defect still present, or against a deliberately broken copy, and confirm it fails.
