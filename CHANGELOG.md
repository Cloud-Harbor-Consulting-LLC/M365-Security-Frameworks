# Changelog

All notable changes to **M365-Security-Frameworks** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Frameworks/Zero-Trust-Readiness-Assessment/README.md — skeleton landing page for the Zero Trust Readiness Assessment Framework (ZTRA). The framework assesses an M365 tenant's Zero Trust posture across Microsoft's 6 ZT pillars (Identities, Endpoints, Applications, Data, Infrastructure, Networks) scored against CISA ZTMM v2.0's 4 maturity stages (Traditional, Initial, Advanced, Optimal), with NIST SP 800-207 tenet citations per control row. Per-pillar and overall tenant stage use equal pillar weighting (16.67% each), aligned with CISA ZTMM v2.0's horizontal progress design. Assessment outputs include a technical detail report, an executive summary, and a board 1-pager, generated from a single read-only Microsoft Graph collector run. The scoring rubric (Design/SCORING-RUBRIC.md) is usable as a standalone assessment instrument independent of the collector. Scoring rubric, collector, formatter, examples, and ROI document follow in PRs B–F this week. Targets ztra-v0.1.0-preview.
- Frameworks/Zero-Trust-Readiness-Assessment/Design/SCORING-RUBRIC.md — full Zero Trust readiness scoring rubric. Covers all 6 Microsoft ZT pillars (Identities, Endpoints, Applications, Data, Infrastructure, Networks) with 40 assessment controls (6–8 per pillar) scored against CISA ZTMM v2.0's 4 maturity stages (Traditional, Initial, Advanced, Optimal). Each control includes NIST SP 800-207 tenet citations (T1–T7), an observable M365 configuration signal, and a repo artifact cross-reference where a deployed CA Baseline or Entra ID Governance Toolkit artifact serves as evidence. Per-pillar stage = median of control scores within the pillar; overall tenant stage = median of the 6 pillar scores; both round down on ties; equal pillar weighting (16.67%) aligned with CISA ZTMM v2.0 horizontal progress design. Infrastructure and Networks pillar controls that require Azure Management API signals are annotated in the rubric. Rubric is usable as a standalone assessment instrument without the collector script.
- `Frameworks/Zero-Trust-Readiness-Assessment/Scripts/Get-ZTReadinessScore.ps1` —
  read-only Microsoft Graph collector assessing all 40 ZTRA controls across 6 pillars;
  controls outside Graph scope flagged `ManualReview = $true` with portal navigation
  notes; outputs structured `ZTRAResult` PSCustomObject consumed by
  `Format-ZTReadinessReport.ps1`
- `Frameworks/Zero-Trust-Readiness-Assessment/Scripts/README.md` — collector
  prerequisites, required Graph scope table, authentication options (interactive and
  service principal), parameter reference, output object shape, manual review guidance
  table, and scoring logic explanation
- `Frameworks/Zero-Trust-Readiness-Assessment/Scripts/Format-ZTReadinessReport.ps1` —
  ZTRA formatter; accepts a `ZTRAResult` PSCustomObject (via `-Result` parameter) or a
  JSON file (via `-InputPath`); generates three audience-scoped Markdown reports in a
  single run: technical detail (`-technical.md`) for security engineers, executive summary
  (`-exec-summary.md`) for CISO and security leadership, and board 1-pager (`-board.md`)
  for board and audit committee; output files named `<TenantName>-<date>-<shape>.md`
- `Frameworks/Zero-Trust-Readiness-Assessment/Examples/Board-Summary-Template.md` —
  blank board 1-pager template for practitioners running the assessment manually against
  the scoring rubric without the collector script
- `Frameworks/Zero-Trust-Readiness-Assessment/Examples/Sample-Tenant-Report.md` —
  all three output shapes populated with fictional Contoso Ltd data (Overall: Stage 2 —
  Initial; Identities, Endpoints, Applications, and Data at Stage 2; Infrastructure and
  Networks at Stage 1); illustrates the framework's output before running against a real tenant

### Fixed

- Corrected a misattributed breach-cost statistic in the ZTRA board report output
  (`Frameworks/Zero-Trust-Readiness-Assessment/Scripts/Format-ZTReadinessReport.ps1`) and in
  `Examples/Sample-Tenant-Report.md`. Both stated that "organizations with a mature Zero Trust
  program average $1.76M less per breach" and attributed it to the IBM Cost of a Data Breach 2024
  report. That report publishes no Zero Trust-specific breakdown; in the 2024 edition $1.76M is the
  additional cost borne by organizations with severe security staffing shortages. The $1.76M Zero
  Trust figure is genuine but originates in IBM's 2021 report (mature Zero Trust $3.28M per breach
  versus $5.04M for organizations that had not deployed Zero Trust). The board report now cites the
  2021 edition explicitly and states both underlying figures, while continuing to source the current
  $4.88M global / $9.36M US averages from the 2024 report. The 2021 edition is the most recent to
  publish a Zero Trust-specific cut.
- Corrected the PIM data-collection endpoints in `Frameworks/Zero-Trust-Readiness-Assessment/Scripts/Get-ZTReadinessScore.ps1`
  (controls ID-02, ID-06). The collector called the deprecated Azure AD PIM API
  `GET /beta/privilegedAccess/aadRoles/resources/{tenantId}/roleAssignments`, which no longer
  resolves and always fell through to `ManualReview`. Replaced with the current PIM v3 unified
  role-management endpoints (v1.0 GA): eligible assignments via
  `GET /roleManagement/directory/roleEligibilityScheduleInstances` and permanent standing
  assignments via `GET /roleManagement/directory/roleAssignmentScheduleInstances` filtered to
  `assignmentType eq 'Assigned'` with a null `endDateTime`. IN-01 (PIM for Azure resource roles)
  is Azure Resource Manager-only — not exposed by Microsoft Graph — so its dead beta call was
  removed and the control is now a direct `ManualReview`. Dropped the now-unused
  `PrivilegedAccess.Read.AzureAD` scope (the collector runs on 6 read-only scopes; the new
  endpoints are covered by the existing `RoleManagement.Read.Directory`). Updated the framework
  README, Scripts/README, and the SCORING-RUBRIC M365 Signal fields (ID-02, ID-06, IN-01, IN-04)
  to cite the correct endpoints.
- Fixed a runtime failure in `Frameworks/Zero-Trust-Readiness-Assessment/Scripts/Get-ZTReadinessScore.ps1`
  where three `New-ZTControl` calls (ID-02, ID-06, IN-01) passed an `if`/`else` statement to
  `-ManualReviewNote` using grouping parentheses — `(if ... { } else { })`. In argument position
  PowerShell parses `if` as a command name (so the file parses cleanly) but fails at runtime with
  "The term 'if' is not recognized as a name of a cmdlet". Replaced with the subexpression operator
  `$(if ... { } else { })`. Surfaced against `cloudharbordemo.onmicrosoft.com` once the paging and
  strict-mode fixes let execution reach the PIM controls.
- Fixed strict-mode property access across the scoring predicates and inline accessors in
  `Frameworks/Zero-Trust-Readiness-Assessment/Scripts/Get-ZTReadinessScore.ps1`. Under
  `Set-StrictMode -Version Latest`, the CA-policy filter predicates (and several inline
  accessors) read optional nested Graph properties directly — e.g. `$p.grantControls.builtInControls`
  on a session-only or authentication-strength-only policy whose `grantControls` object has no
  `builtInControls` member — throwing `PropertyNotFoundException` and aborting the assessment on the
  first policy evaluated. Added a `Get-ZTProp` helper that walks a dotted property path and returns a
  default when any segment is missing or null, and routed ~40 fragile accesses through it (CA-policy
  predicates plus device, PIM assignment, OAuth grant, access-review, app-credential, and named-location
  accessors). Collection checks use `Measure-Object` so a missing property counts as zero rather than
  throwing on `.Count`. Confirmed against `cloudharbordemo.onmicrosoft.com` (27 CA policies of mixed
  types): the collector previously exited with `PropertyNotFoundException` on the first CA policy;
  the fix allows all six pillars to score.
- Fixed `Invoke-ZTGraphRequest` in `Frameworks/Zero-Trust-Readiness-Assessment/Scripts/Get-ZTReadinessScore.ps1`:
  direct property access on `$response.'@odata.nextLink'` and `$response.value` threw
  `PropertyNotFoundException` under `Set-StrictMode -Version Latest` when the API response
  contained no next-page link or no `.value` collection (single-object endpoints). Both
  replaced with `PSObject.Properties.Name -contains` guards. Confirmed against
  `cloudharbordemo.onmicrosoft.com`: previously exited on first CA policy fetch; now proceeds.
- Synced stale policy counts and a version string in Frameworks/Conditional-Access-Baseline docs to the v1.4.0 surface (28 policies): Design/AGENTS-PERSONA-MODEL.md (version header and beta-endpoint count), Scripts/README.md (deployer table and usage counts), and Policies/CA-EXC003-Agents-Persona.md (beta-endpoint count).
- Corrected repo-wide documentation consistency issues outside the Conditional Access Baseline: the three broken POLICY-DESIGN.md links in Frameworks/Intune-Compliance-Baseline/README.md now point to Design/POLICY-DESIGN.md, the four malformed CHANGELOG footer link definitions (1.2.0, 1.1.0, 1.0.1, 1.0.0) no longer carry a space before the colon, the Entra ID Governance Toolkit row in the root README Frameworks table now carries its 2026-06-05 release date, and the Security Reporting Decision Rubric status banner now reflects the pending, not-yet-tagged state to match the root README table.
- Cleared stale v1.3-era references left over after the v1.4 release in Frameworks/Conditional-Access-Baseline docs: Scripts/README.md (example deployer output and Policies/ reference line still said 23 templates), Design/AGENTS-PERSONA-MODEL.md (Pattern 3 coverage now points to CA-COV013 through CA-COV015 instead of a planned later PR, and the shipped WORKLOAD-IDENTITY-IP-PATTERNS and CA-ICB-INTEGRATION design docs are no longer described as future work), Design/POLICY-DESIGN.md (intro version label), Business-Case/ROI-CONDITIONAL-ACCESS.md (current-baseline version labels), and Design/CA-ICB-INTEGRATION.md (current-baseline version labels).

---

## [1.4.0] - 2026-06-10

The v1.4 release closes the Conditional Access for Agents development cycle. It extends agent coverage from a single risk-based policy on the agent identity (CA-COV011, shipped in v1.3) to a four-policy agent surface across two personas. The Agents persona gains CA-COV012, an allow-only-approved-agents governance control that blocks every agent identity except an approved set selected by the `agentIdServicePrincipalFilter` custom security attribute exclude. A new AgentUsers persona covers the agent user account identity sub-class (Pattern 3: agent acting as a user, the digital worker) with three policies: CA-COV013 blocks agent user account sign-ins at medium and high agent risk, CA-COV014 requires a compliant device on Intune-managed Windows 365 Cloud PCs for Agents, and CA-COV015 blocks agent user account sign-ins from outside the compliant network. All four ship report-only. The release grounds the agent field shapes in verified Microsoft Graph beta JSON, documents the three Microsoft agent access patterns, and records the Conditional Access boundaries that agent policies do not close. The deployable baseline now totals 28 policies across 8 personas plus a Sensitive-Applications scope. This release prep folds the agent slate into the executive ROI document, the framework README, and POLICY-DESIGN, cuts this dated CHANGELOG section, and tags v1.4.0.

### Added

- Documented Microsoft's agent Conditional Access limitations and the `agentType` sign-in-log investigation guidance. CA-EXC003-Agents-Persona.md gains a Limitations section (the targeting gaps between the agent identity and the agent user account, plus the authentication surfaces where Conditional Access does not apply: the Microsoft Entra Token Exchange Endpoint, blueprint token acquisition for creating agents, tenants with Security Defaults enabled, and API-key access) and a Report-only rollout section covering CA-COV011 through CA-COV015; its incident response runbook now uses the `agentType` sign-in-log filter to confirm whether an agent policy applied, noting the enumerated value list is confirm-in-tenant. AGENTS-PERSONA-MODEL.md gains a Boundaries and limitations subsection mirroring the full list and the `agentType` investigation reference. POLICY-DESIGN.md adds a limitations and report-only rollout note to the Agents (CA-COV011/CA-COV012) and AgentUsers (CA-COV013 through CA-COV015) per-policy sections. Cites <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id>.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV013-AgentUsers-BlockMediumAndHighRisk.json, CA-COV014-AgentUsers-RequireCompliantDevice.json, and CA-COV015-AgentUsers-RequireCompliantNetwork.json — new AgentUsers persona policies covering the agent user account identity sub-class (Pattern 3: agent acting as a user / digital worker), distinct from the agent identity covered by CA-COV011 and CA-COV012. CA-COV013 blocks agent user account sign-ins at `agentIdRiskLevels = "medium,high"` (Microsoft recommends medium and high for agent users, distinct from the high-only recommendation for agent identities). CA-COV014 requires a compliant device (evaluated only on Intune-managed Windows 365 Cloud PCs for Agents). CA-COV015 requires a compliant network (the Microsoft Entra Global Secure Access network control, which is not a builtInControls value). All 3 ship report-only. Three confirm-in-tenant fields ship as REPLACE_WITH_VERIFIED_* placeholders: the All agent users selector (conditionalAccessUsers has no documented agent value), the Require compliant network control representation, and the Agent execution environments condition. The Agent execution environments condition scopes the device and network policies to endpoint-initiated agent user sessions so cloud-native agents with no device or no Global Secure Access client are excluded rather than blocked with no path to compliance; because the condition property is unverified the JSON ships without it, and CA-COV014 and CA-COV015 must stay report-only until adopters add the condition in the portal. CA-COV015 requires Microsoft Entra Internet Access with the Global Secure Access client deployed on the endpoint. Documented in CA-EXC003-Agents-Persona.md (new Agent user accounts coverage section), POLICY-DESIGN.md (section 6a AgentUsers per-policy specs), CA-ICB-INTEGRATION.md (CA-COV014 consumes the Intune device-compliance signal on Windows 365 Cloud PCs for Agents), and the framework README (new AgentUsers persona table). Cites <https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-autonomous-agents> and <https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id>.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV012-Agents-AllowOnlyApprovedAgents.json and its paired contract CA-COV012-Agents-AllowOnlyApprovedAgents.md — new Agents persona allow-only policy. Includes all agent identities, excludes an approved set via `excludeAgentIdServicePrincipals` (the `REPLACE_WITH_APPROVED_AGENT_ID_OBJECT_IDS` placeholder), and blocks, so only sanctioned agents operate. The contract documents the deny-by-default-except-approved design, the two selection methods (enhanced object picker with the All / Agent blueprint principals / Agent identities tabs, and the custom security attribute method using AgentAttributes/AgentApprovalStatus and ResourceAttributes/Department with the Contains operator), the required roles (Conditional Access Administrator, plus Attribute Assignment Reader for the attribute method), and a confirm-in-tenant note that the includeAgentIdServicePrincipals "All" literal and the attribute-based targeting JSON are not yet published in the Microsoft Graph reference. Ships in report-only.

### Changed

- Documented the three Microsoft agent access patterns (on-behalf-of with the user as subject, application-only with the agent identity as subject, and agent-acting-as-a-user with the agent user account as subject), replacing the single-class agent model.
- Verified the Agent ID Conditional Access field set against the Microsoft Graph beta reference (2026-06-03 refresh); reaffirmed the beta-endpoint commitment and flagged the unpublished AllAgentIdResources and includeAgentIdServicePrincipals All tokens as confirm-in-tenant.
- Documented the expanded agent-identity targeting options (the enhanced object picker tabs All / Agent blueprint principals / Agent identities, individual agent identities, and custom security attributes) in POLICY-DESIGN.md and AGENTS-PERSONA-MODEL.md, correcting the prior "All-only, no inclusion list" framing of the Agents persona.
- Documented the CA-COV011 risk-threshold posture: the baseline deliberately keeps `agentIdRiskLevels = "medium,high"` as a stricter-than-recommended CHC default, noting Microsoft recommends `high` for agent-identity policies and how an adopter can align to it.
- Expanded the Admins persona (CA-AUT003-Admins-RequireAdminAuthOnAdminPortals and CA-SIG005-Admins-BlockMediumAndHighSignInRisk) from 14 to the 39-role privileged set aligned to Microsoft's `isPrivileged` classification confirmed against the tenant role catalog plus a few defense-in-depth roles. Both policies carry byte-identical `includeRoles` arrays of the same 39 role template IDs in the same order. POLICY-DESIGN.md section 1.6 rebuilds the role table to all 39 rows, adds an Optional additional privileged-adjacent roles (not deployed by default) subsection listing 13 workload-specific roles for backup, AI agents, and Global Secure Access adopters, and records that Directory Synchronization Accounts and the On-Premises Directory Sync Account are intentionally excluded. The Admins count is synced to 39 in the section 1.6 prose, the section 3 persona table, the CA-AUT003 and CA-SIG005 per-policy specs, and the framework README persona list. Both policies stay report-only.

### Fixed

- Corrected the Admins persona directory-role name labels in POLICY-DESIGN.md section 1.6, which were mismatched to the role template IDs actually deployed (for example `158c047a` is Cloud Application Administrator not Exchange Administrator, `fe930be7` is User Administrator not Helpdesk Administrator, and `729827e3` is Helpdesk Administrator not Reports Reader). The authoritative name-to-GUID mapping is verified against the tenant role catalog.
- Corrected the CA-COV015 deployer to resolve the "All Compliant Network locations" named location on the Microsoft Graph beta endpoint (it is a beta-only Global Secure Access location), fixing a not-found error during deployment.
- Corrected the CA-COV015 deployer lookup to the actual Conditional Access named-location display name "All Compliant Network locations" so the compliant-network location resolves and deploys.
- Grounded CA-COV012 through CA-COV015 in verified Microsoft Graph beta JSON (`GET /beta/policies/conditionalAccessPolicies`), replacing the REPLACE_WITH_VERIFIED_* placeholders: the agent-user subject is `conditions.agents.includeAgentUsers`, the execution-environments condition is `conditions.agentContext.includeAgentContexts` with value `agentUserSessionsInitiatedFromEndpoints`, agent risk is the comma-string `conditions.agentIdRiskLevels`, and CA-COV012 uses the `agentIdServicePrincipalFilter` rule (`CustomSecurityAttribute.AgentIdAttributes_AgentIdApprovedForUse -eq "yes"`, mode exclude) for the approved set in place of the earlier AgentApprovalStatus / Contains scheme. Set CA-COV012 to target All resources (an empty target leaves the allow-list inert). Renamed CA-COV015 from RequireCompliantNetwork to BlockNonCompliantNetwork, redesigned as a location block (include All locations, exclude the compliant-network named location, block). Added the `-CompliantNetworkLocationName` compliant-network location resolver to Deploy-CABaseline.ps1 (resolves `REPLACE_WITH_COMPLIANT_NETWORK_LOCATION_ID`). Marked the agent field shapes tenant-verified in AGENTS-PERSONA-MODEL.md.
- Corrected the Agents persona licensing to Microsoft Entra ID P1 or P2 plus a Microsoft Agent 365 license per user, added Microsoft Entra Internet Access for agent network controls, and documented the Conditional Access Administrator and Attribute Assignment Reader roles.

---

## [eig-v0.1.0-preview] - 2026-06-05

The v0.1.0-preview release establishes the Entra ID Governance Toolkit (EIG) as a Preview-stage framework and delivers its Access Reviews automation foundation. EIG ships two self-invoking PowerShell 7 scripts against the Microsoft Graph Identity Governance API: EIG-AR001 stands up a recurring quarterly access review over B2B guest membership across all Microsoft 365 groups, and EIG-AR002 stands up a recurring monthly review over dormant administrative role assignments using a verified 30-day inactivity look-back. Both controls default decisions to deny, auto-apply the resulting removals, route to a named reviewer chain with a fallback reviewer, and retain decision evidence for audit. The release also includes the framework landing page, the POLICY-DESIGN specification, paired contract documents for each script, the Scripts/ index, and the executive ROI business case. This release prep flips the framework README, its design spec, and the repo Frameworks table from Planned to Preview.

### Added

- Entra ID Governance Toolkit framework skeleton at `Frameworks/Entra-ID-Governance-Toolkit/`. Replaces the stub README with a framework landing page covering scope (Access Reviews now, Lifecycle Workflows and PIM governance as the v1.0 target), the EIG-AR / EIG-LW / EIG-PIM naming convention, the planned scripts inventory, the self-invoking deployment model, and Entra ID P2 prerequisites. No scripts and no tag in this change.
- Entra ID Governance Toolkit: policy design specification (Design/POLICY-DESIGN.md) defining the 4 framework principles, the EIG naming convention, the persona model, the rollout sequence, and the per-script design specs for EIG-AR001 and EIG-AR002.
- Frameworks/Entra-ID-Governance-Toolkit/Scripts/EIG-AR001-QuarterlyGuestAccessReview.ps1 and its paired contract EIG-AR001-QuarterlyGuestAccessReview.md: first Access Reviews automation for the Entra ID Governance Toolkit. Creates a recurring quarterly access review over B2B guest membership across all Microsoft 365 groups, with deny-by-default decisions, auto-applied removal of denied guests, and a named fallback reviewer. Implements design spec section 7.1. The sponsor reviewer query ships as a confirm-in-tenant placeholder.
- Frameworks/Entra-ID-Governance-Toolkit/Scripts/EIG-AR002-DormantAdminRoleReview.ps1 and its paired contract EIG-AR002-DormantAdminRoleReview.md: second Access Reviews automation for the Entra ID Governance Toolkit. Creates a recurring monthly access review over dormant administrative role assignments, using a verified 30-day inactivity look-back (`recommendationLookBackDuration` of `P30D`) so assignments not exercised in the prior 30 days are recommended for denial, with deny-by-default decisions and auto-applied removal of denied assignments. Scopes the review with the verified `principalResourceMembershipsScope` shape (`/users` principals against a `/roleManagement/directory/roleDefinitions/{role id}` resource) and requires the added `RoleManagement.ReadWrite.Directory` scope. Implements design spec section 7.2. The role definition ID ships as a tenant-value placeholder and the primary (role owner / delegated governance) reviewer query ships as a confirm-in-tenant placeholder.
- Frameworks/Entra-ID-Governance-Toolkit/Scripts/README.md — adopter-facing index for the Scripts/ folder. Covers both EIG-AR001 (quarterly guest access review) and EIG-AR002 (monthly dormant admin role review) with per-script purpose, recurrence, required scopes, and a pointer to each paired contract. States the shared prerequisites (Entra ID P2, PowerShell 7, Microsoft.Graph.Authentication, operator scope consent) and the self-invoking deployment model with no unified deployer at v0.1.0-preview.
- Frameworks/Entra-ID-Governance-Toolkit/Business-Case/ROI-ENTRA-GOVERNANCE.md — executive business case for the toolkit aimed at CFO, board, and security leadership. Frames the standing-access risk (guest sprawl and dormant admin access), explains how EIG-AR001 and EIG-AR002 close the orphaned-access window with deny-by-default plus auto-applied removal, and includes an explicit assumptions-based operational cost model that states every assumption inline, computes every total with the arithmetic shown, and labels all figures as illustrative. Covers the Entra ID P2 prerequisite and maps the controls to SOC 2, ISO 27001, HIPAA, PCI-DSS, and NIST SP 800-53. Mirrors the structure and executive voice of the Conditional Access Baseline ROI document.

### Changed

- Frameworks/Entra-ID-Governance-Toolkit/README.md — status line flipped from "in development, targeting v0.1.0-preview" to a "Status: Preview (v0.1.0-preview)" banner. Scripts inventory updated: EIG-AR001 and EIG-AR002 changed from "Planned for v0.1.0-preview" to "Available (v0.1.0-preview)". Added a Business case section pointing to Business-Case/ROI-ENTRA-GOVERNANCE.md.
- Frameworks/Entra-ID-Governance-Toolkit/Design/POLICY-DESIGN.md — status line flipped from "in development, targeting v0.1.0-preview" to "Status: Preview (v0.1.0-preview)". No other content changes.
- Top-level README.md — Frameworks table row for the Entra ID Governance Toolkit updated from Planned to Preview, Latest set to v0.1.0-preview, and the Notes column refreshed to describe the two Access Reviews automations (quarterly guest access review and monthly dormant admin role review), the PowerShell 7 against Microsoft Graph Identity Governance implementation, and the deny-by-default reviewer chain with retained audit evidence.

---

## [1.3.0] - 2026-05-28

The v1.3 release closes the Conditional Access Baseline development cycle that began with the wholesale stack adoption sourced from Derek's demo tenant. Twenty-four starter policies now cover seven identity personas — Global, Internal, Admins, Guests, ServiceAccounts, WorkloadIdentities, and Agents — plus a Sensitive-Applications scope, bringing the baseline to full defensible coverage of every identity class that Conditional Access can reach in a Microsoft Entra ID tenant. The headline addition is the Agents persona: Microsoft Agent ID is a distinct identity class for AI agents and Copilot agents in Entra, and CA-COV011 is the first policy in this baseline to explicitly cover that surface — one that most community CA baselines still leave unaddressed as of 2026. The full stack targets the Microsoft Graph beta endpoint for all 24 policies, with three policies requiring beta for features Microsoft has not yet promoted to v1.0 (`signInFrequency: everyTime` and the Agent ID condition family), and a documented migration commitment when GA promotion completes. Four new design documents ship with this release: AGENTS-PERSONA-MODEL.md, CAE-TOKEN-PROTECTION-LAYERING.md, WORKLOAD-IDENTITY-IP-PATTERNS.md, and CA-ICB-INTEGRATION.md. The CA-SIG010-Guests-RequireToU policy adds a Terms of Use consent gate for all six B2B guest user types. All policy JSON was normalized from PascalCase SDK format to the documented REST API camelCase wire format.

### Added

- Frameworks/Conditional-Access-Baseline/Design/CA-ICB-INTEGRATION.md — cross-framework integration doc covering how the v1.3 Conditional Access Baseline consumes the Intune Compliance Baseline compliance signal. Signal flow narrative with a Mermaid diagram. Documents the three CA policies that depend on ICB (CA-COV008, CA-SIG001, CA-SIG007) with per-policy ICB requirements. Failure-mode matrix covering 7 common adopter scenarios (noncompliant device, unmanaged device, lag, mid-session revocation, legacy clients, Linux gap, mobile out-of-scope). CAE interaction documented for compliance state changes during active sessions. CA-to-ICB rollout sequence in 9 steps. Cross-framework testing procedure with 5 concrete test cases. Out-of-scope disclosure.

- Frameworks/Conditional-Access-Baseline/ — v1.3 stack adoption. 23-policy baseline replacing the prior Unreleased state. Targets Microsoft Graph beta endpoint to cover three policies that use features currently in beta as of May 2026 (CA-SIG003 and CA-SIG004 use `signInFrequency.frequencyInterval: "everyTime"`; CA-COV011 uses the Microsoft Agent ID condition family). Adds the Agents persona as a first-class persona class via CA-EXC003-Agents-Persona.md and Design/AGENTS-PERSONA-MODEL.md. Retains CA-COV010-WorkloadIdentities-TrustedLocations from prior Unreleased state, renumbered from CA-COV003. Wholesale rewrite of Design/POLICY-DESIGN.md, framework README.md, Scripts/Deploy-CABaseline.ps1 (single Microsoft.Graph.Authentication module dependency, beta endpoint via Invoke-MgGraphRequest). Updates Scripts/Get-CABaselineImpact.ps1 to beta endpoint. Updates Scripts/README.md to document the beta-endpoint commitment.

- Frameworks/Security-Reporting-Decision-Rubric/ — v0.1.0-preview rubric for designing audience scoped security reports. Includes the 4 question decision flow, audience by cadence by decision type matrix, severity floor guidance grounded in Microsoft Defender XDR severity model, recommended outcome metrics by audience, a kill list of common reports that name no decision, and two starter templates (board quarterly readout, CISO monthly review). Pairs with the Cloud Harbor Consulting blog article "If Every Alert Is Important, None Are: Designing Security Reports That Drive Decisions."
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG009-AllUsers-BlockHighUserRisk.json — Global persona user-risk hard-block policy. Blocks all users when Entra ID Identity Protection detects user risk at the "high" level. Replaces the graduated medium-risk response with a zero-tolerance high-risk control for user risk signals. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts personas per CA-EXC001 and CA-EXC002. Complements CA-SIG004 (medium user-risk graduated response). Requires Entra ID P2 (Identity Protection). Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG010-AllUsers-BlockHighSignInRisk.json — Global persona sign-in-risk hard-block policy. Blocks all users when Entra ID Identity Protection detects sign-in risk at the "high" level. Replaces the step-up-on-risk control (retired CA-SIG002) with a zero-tolerance high-risk response for sign-in-risk signals. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts personas per CA-EXC001 and CA-EXC002. Complements CA-SIG005 (medium sign-in-risk graduated response). Requires Entra ID P2 (Identity Protection). Ships in report-only.

- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG010-Guests-RequireToU.json — new Guests persona policy requiring acceptance of a tenant-defined Terms of Use before B2B guest access is granted. Targets all 6 external user types (internalGuest, b2bCollaborationGuest, b2bCollaborationMember, b2bDirectConnectUser, otherExternalUser, serviceProvider) across all applications. Excludes EmergencyAccess per CA-EXC001. Grant control: `termsOfUse` with `REPLACE_WITH_TERMS_OF_USE_ID` placeholder. Requires Microsoft Entra ID Premium P2 for the Terms of Use feature. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG010-Guests-RequireToU.md — paired contract doc covering the ToU lifecycle (drafting, version pinning, re-consent triggers, removal), the Entra ID Premium P2 prerequisite, the adopter checklist for publishing and capturing the agreement ID, and the 14-day report-only validation procedure.
- Frameworks/Conditional-Access-Baseline/Design/CAE-TOKEN-PROTECTION-LAYERING.md — deep-dive design doc covering how Continuous Access Evaluation and Token Protection layer together on the v1.3 baseline. Threat model summary (AiTM, infostealer, post-MFA token theft surface). CAE signal model and critical event flow. Token Protection device-binding mechanism. Complementary-control analysis with 4 threat scenarios. Client matrix for the Office 365 bundle (Outlook, OneDrive Sync, Teams, browser-based access) with minimum client versions as of 2026. Replay-resistance trade-offs. Recommended layering order (legacy auth blocking first, CAE strict enforcement, then Token Protection soak). 14-day operational soak procedure for CA-SIG007. Coverage-seam disclosure for what the layering does not protect against.
- Frameworks/Conditional-Access-Baseline/Design/WORKLOAD-IDENTITY-IP-PATTERNS.md — baseline supplement to CA-COV010-WorkloadIdentities-TrustedLocations. Covers SPN per-pipeline scoping pattern (one SPN per pipeline, scoped role assignments, naming convention). Trusted IPs named-location refresh cadence per runner class (GitHub Actions hosted, Azure DevOps Microsoft-hosted, self-hosted). Rollback procedure when CI runners change egress (detection via AADSTS53003 logs, diagnosis via egress-vs-allowlist diff, recovery paths A and B). GitHub Actions example with OIDC federated credentials. Azure DevOps example with Workload Identity Federation service connection. Microsoft-hosted vs self-hosted runner trade-off table. Coverage-seam disclosure.

### Changed

- Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md — added cross-references from the CA-COV008, CA-SIG001, and CA-SIG007 per-policy specs to the new CA-ICB-INTEGRATION.md integration doc.
- Frameworks/Conditional-Access-Baseline/README.md — Roadmap section updated to mark the CA-ICB integration doc as shipped under v1.3.

- Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md — added Section 6.24 per-policy spec for CA-SIG010-Guests-RequireToU. Section 6 intro count updated from "twenty-three" to "twenty-four" starter policies. Rollout sequence extended to position 24. Beta endpoint paragraph count updated from 23 to 24.
- Frameworks/Conditional-Access-Baseline/README.md — policy count updated from 23 to 24. Guests persona table gains a new row for CA-SIG010. Guests persona count updated from "(3)" to "(4)". Prerequisites section adds Entra ID Premium P2 ToU feature requirement. v1.3 roadmap entry added for CA-SIG010.
- Frameworks/Conditional-Access-Baseline/Scripts/Deploy-CABaseline.ps1 — new `-TermsOfUseName` parameter (default "CHC Guest Terms of Use"). New `Resolve-TermsOfUseId` helper queries `https://graph.microsoft.com/beta/identityGovernance/termsOfUse/agreements` by display name. New `REPLACE_WITH_TERMS_OF_USE_ID` substitution in the placeholder-resolution loop. Resolver result cached in `$script:TermsOfUseId` so subsequent policies needing the same value do not re-query.

- Frameworks/Conditional-Access-Baseline/Policies/ — REPLACED. Every policy JSON except the EXC contracts. New stack is sourced from Derek's demo tenant after a CA architecture restructure. JSON format normalized from PowerShell SDK PascalCase to documented REST API camelCase wire format. All tenant GUIDs replaced with REPLACE_WITH_*_OBJECT_ID placeholders.

- Frameworks/Conditional-Access-Baseline/Scripts/Deploy-CABaseline.ps1 — REWRITTEN. Single Microsoft.Graph.Authentication module dependency replaces dual SDK module dependency from v1.2. Endpoint URL pinned to `https://graph.microsoft.com/beta/identity/conditionalAccess/policies`. Single Policies/ folder iteration. Placeholder resolver pattern preserved. -WhatIf and -Enforce switches preserved. -Enforce remains opt-in; report-only is the default state for all policies. Removed GlobalAdminsGroupName parameter (CA-Persona-GlobalAdmins group dependency was retired in prior Unreleased; now fully removed across the stack).

- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG002-AllUsers-RequireStepUpOnRisk.json — **REMOVED** (replaced by CA-SIG009 and CA-SIG010). The step-up-on-risk (MFA re-challenge on medium/high sign-in risk) control has been superseded by two more granular, signal-specific policies that hard-block on high risk (CA-SIG009 for user risk, CA-SIG010 for sign-in risk) rather than requiring step-up authentication. Adopters who used CA-SIG002 should promote CA-SIG004 (graduated medium user-risk) and CA-SIG005 (graduated medium sign-in-risk) to enforcement, then layer CA-SIG009 and CA-SIG010 for high-risk hard blocks per the updated rollout sequence.
- Frameworks/Conditional-Access-Baseline/Policies/CA-AUT001-PrivAccounts-RequirePhishResistantMFA.json — **REFACTORED** to eliminate the CA-Persona-GlobalAdmins group dependency. Policy now targets 14 highly-privileged Entra ID directory roles directly via `includeRoles` (Global Administrator, Privileged Role Administrator, Security Administrator, Exchange Administrator, SharePoint Administrator, Teams Administrator, Dynamics Administrator, Power Platform Administrator, Authentication Administrator, Compliance Administrator, Helpdesk Administrator, Directory Synchronization Administrator, Cloud Application Administrator, Reports Reader) instead of the static CA-Persona-GlobalAdmins group. Functionally equivalent but removes the group management overhead and aligns with Admins-scope policies (CA-AUT005, CA-SIG006) that already target the same 14 roles. Break-glass exclusion on EmergencyAccess unchanged.
- Frameworks/Conditional-Access-Baseline/Scripts/Deploy-CABaseline.ps1 — **REMOVED** `GlobalAdminsGroupName` parameter and its associated `Resolve-GroupId` call for the `REPLACE_WITH_GLOBAL_ADMINS_GROUP_OBJECT_ID` placeholder. Deployment script no longer resolves the GlobalAdmins group; only resolves EmergencyAccess, WorkloadIdentities, InternalUsers, ServiceAccounts, GuestUsers groups, plus Supporting Artifacts (authentication strengths, named locations). CA-AUT001 now ships with 14 hard-coded role template IDs that require no runtime resolution.
- Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md — **MAJOR UPDATE**: (1) Section 1.3 (Layered signals) revised examples to reference CA-SIG004 instead of CA-SIG002. (2) Section 1.5 (v1.2 refinements) updated to reference CA-SIG009/CA-SIG010 for high-risk hard blocks instead of CA-SIG002 step-up. (3) Section 1.6 (Global and Admins scope) refactored to remove CA-Persona-GlobalAdmins from the Admins scope definition; now reads "Admins means the 14 highly-privileged Entra ID directory roles by template ID." (4) Section 3 (Persona model) table REMOVED the "Global & Privileged Administrators" row for CA-Persona-GlobalAdmins and replaced with "Privileged Roles (Directory Roles)" targeting the 14 template IDs. (5) Section 6 intro count updated from "twenty-three" to "twenty-four" starter policies. (6) Added sections 6.6 and 6.7 (CA-SIG009 and CA-SIG010 per-policy specs). (7) Shifted all subsequent section numbers (6.7 through 6.23 now 6.8 through 6.24) to accommodate. (8) Updated CA-AUT001 per-policy spec (section 6.3) to document the 14 directory roles inclusion list and remove CA-Persona-GlobalAdmins group reference. (9) Updated rollout sequence table: removed CA-SIG002 at position 6, added CA-SIG009 at position 18, added CA-SIG010 at position 19, shifted Admins/Guests/ServiceAccounts policies to positions 20–24.
- Frameworks/Conditional-Access-Baseline/README.md — Updated "The twenty-three starter policies" header to "The twenty-four starter policies". Global persona table updated from 12 to 13 rows to include CA-SIG009 and CA-SIG010; CA-SIG002 removed. Persona model section updated: removed the CA-Persona-GlobalAdmins row; added "Privileged Roles (Directory Roles)" row with 14 template IDs.
- Frameworks/Conditional-Access-Baseline/Scripts/README.md — (1) Prerequisites section updated from "Four persona groups" to "Three persona groups" (removed CA-Persona-GlobalAdmins). (2) Persona group list updated: removed CA-Persona-GlobalAdmins, kept CA-Persona-EmergencyAccess, CA-Persona-WorkloadIdentities, CA-Persona-InternalUsers. (3) Custom parameter override example changed from `GlobalAdminsGroupName 'Tier0-Admins'` to `InternalUsersGroupName 'InternalUsers'` to reflect the removal of the GlobalAdmins parameter. (4) Expected output example updated to remove the REPLACE_WITH_GLOBAL_ADMINS_GROUP_OBJECT_ID resolution line.
- Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md — added cross-reference from the CA-SIG007-Internal-TokenProtection per-policy spec to the new CAE-TOKEN-PROTECTION-LAYERING.md design doc.
- Frameworks/Conditional-Access-Baseline/README.md — Roadmap section updated to mark the CAE and Token Protection layering doc as shipped under v1.3.
- Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md — added cross-reference from the CA-COV010-WorkloadIdentities-TrustedLocations per-policy spec to the new WORKLOAD-IDENTITY-IP-PATTERNS.md supplement.
- Frameworks/Conditional-Access-Baseline/README.md — Roadmap section updated to mark the Workload identity IP patterns doc as shipped under v1.3.
- Frameworks/Conditional-Access-Baseline/Business-Case/ROI-CONDITIONAL-ACCESS.md — wholesale rewrite for v1.3. Policy count updated from 23 to 24 (including CA-SIG010 ToU). New Agents persona business case section (executive-novel content). New AuthN strength enforcement-model section replacing the v1.2 always-on PrivAccounts framing. New beta-endpoint commitment section in plain language. Annual operational hours estimate updated from approximately 52 to approximately 112 hours per year, driven by the new Agents persona attestation, the Workload Identities trusted-IPs cadence, and ToU lifecycle management. Phased investment approach extended from 12 to 20 weeks.
- Frameworks/Conditional-Access-Baseline/README.md — status banner flipped to Released v1.3.0. Roadmap section restructured: v1.3 candidates moved to Shipped; v1.4 candidates seeded.
- Top-level README.md — Frameworks table row for Conditional Access Baseline updated from v1.2.0 (2026-05-15) to v1.3.0 (2026-05-28). Notes column refreshed for the v1.3 surface.

### Fixed

- Top-level `README.md` — Frameworks table updated to add the Security Reporting Decision Rubric Preview row. Documentation-only correction; missed when the framework was added earlier in this Unreleased cycle.
- Frameworks/Conditional-Access-Baseline/README.md — Prerequisites line updated to remove `CA-SIG002` (removed in this same Unreleased cycle) and add `CA-SIG009` and `CA-SIG010` to the P2 Identity Protection required-for list. Documentation-only correction; missed when CA-SIG002 was removed and CA-SIG009 and CA-SIG010 were added earlier in this Unreleased cycle.

---

## [1.2.0] - 2026-05-15

### Added

- Frameworks/Intune-Compliance-Baseline/Policies/ICB-WIN001-Baseline-DefenderAndBitLocker.json — first ICB Windows 10/11 compliance template. Reproduces the 9 active settings from the May 12 source-of-truth export (BitLocker, storage encryption, firewall, TPM, antivirus, Defender enabled, signature freshness at 1 day, real-time protection, Defender for Endpoint MTD at medium). Includes the graduated-response scheduledActionsForRule block — notify at 0 days, mark noncompliant at 7 days; no retire on corporate Windows per POLICY-DESIGN section 5. Assigns to the ICB-Persona-CorpWindows persona group.
- Frameworks/Intune-Compliance-Baseline/Policies/README.md — folder README documenting the week-1 manual import model (Microsoft Graph PowerShell and Intune portal paths), placeholder substitution, post-import validation steps, and the template inventory. Notes that the deployer script is deferred per POLICY-DESIGN section 4.
- Frameworks/Intune-Compliance-Baseline/Design/POLICY-DESIGN.md — Intune Compliance Baseline design specification. Establishes four framework design principles (1.1 Platform-led scope, 1.2 Verify don't enforce, 1.3 Compliance as a graded scale, 1.4 Signal-clean handoff to Conditional Access), platform-led naming convention (ICB-WIN###, ICB-MAC###, ICB-IOS###, ICB-AND###, ICB-LIN###), device persona model (CorpWindows, CorpMac, CorpMobile, BYODMobile, CorpLinux), out-of-scope device classes, action-for-noncompliance graduated-response defaults (notify at 0, block at 7 days, retire at 30 days for BYOD only), signal-handoff-to-CA mapping table (deviceComplianceState → compliantDevice grant), rollout sequence, and per-template design specifications. Includes the ICB-WIN001-Baseline-DefenderAndBitLocker per-template spec (9 settings reproducing the production source-of-truth export from May 12, 2026: bitLockerEnabled, storageRequireEncryption, activeFirewallRequired, tpmRequired, antivirusRequired, defenderEnabled, signatureOutOfDate, rtpEnabled, deviceThreatProtectionEnabled with required security level medium) and the ICB-WIN002 through ICB-WIN007 hardening roadmap (Secure Boot, Code Integrity / HVCI, OS version floor, password / PIN complexity, EALAM driver, Device Health Attestation).
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG008-Internal-TokenProtection.json — Internal persona session-hardening policy. Enables Token Protection (`sessionControls.secureSignInSession.isEnabled=true`) for Windows sign-ins to the Office 365 application bundle. Cryptographically binds refresh tokens and Primary Refresh Tokens to the issuing device's TPM-protected key, blocking redemption of stolen tokens from any other device. This is the only policy in the baseline that operates at token-redemption time rather than sign-in time. Scoped to `platforms.includePlatforms=["windows"]` and `clientAppTypes=["all"]`. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG008-Internal-TokenProtection.md — paired design doc covering the post-MFA token-replay threat surface (AiTM session-token capture, infostealer token theft, cookie redemption replay), how Token Protection layers with Continuous Access Evaluation (CAE) without redundancy, current coverage seams (Windows-only, Exchange Online + SharePoint Online sign-in paths within the Office365 bundle, modern-auth-only, client-version dependency), the rollout-sequence position 9 slot, and the 14-day report-only validation procedure including the non-supporting-client inventory step.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV010-ServiceAccounts-BlockUntrustedLocations.json — ServiceAccounts persona compensating control. Blocks service-account sign-ins originating outside the CA-LOCATION-TrustedCountries named-location set (`locations.includeLocations=["All"]`, `locations.excludeLocations=["REPLACE_WITH_TRUSTED_COUNTRIES_LOCATION_ID"]`). Closes the coverage gap created by CA-EXC002, which exempts the ServiceAccounts persona from every human-targeted CA policy. Inverse of the standard pattern: ServiceAccounts is the inclusion target; only EmergencyAccess and WorkloadIdentities are excluded (WorkloadIdentities sit on the separate CA-COV003 code path). `clientAppTypes=["all"]` to capture varied service-account authentication paths. Ships in report-only; adopters use the 14-day soak to inventory legitimate service-account sign-in geographies before enforcement.
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG007-Guests-BlockNonGuestAppAccess.json — Guests persona application-scope policy. Blocks guest sign-ins to any application outside the Microsoft 365 collaboration set (`includeApplications=["All"]`, `excludeApplications=["Office365"]`). Closes the gap where a B2B guest token issued for a collaboration app could be re-used against unrelated registered applications in the tenant. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Adopters extend `excludeApplications` with their own guest-shared line-of-business apps during the report-only soak. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG006-Admins-BlockMediumAndHighSignInRisk.json — Admins persona ID Protection sign-in risk policy. Blocks admin sign-ins (`grantControls.builtInControls=["block"]`, `operator=OR`) when `signInRiskLevels=["medium","high"]`. Scope mirrors CA-AUT005 (PR 11): `CA-Persona-GlobalAdmins` plus the 14 highly-privileged Entra ID directory roles by template ID. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Distinct from CA-SIG002 (all-users; MFA step-up fallback): SIG006 hard-blocks because admin credentials in a risk-flagged session do not get a re-challenge path. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-AUT005-Admins-RequireAdminAuthOnAdminPortals.json — Admins persona app-scoped authentication-strength policy. Requires the AdminAuth custom authentication strength (FIDO2 only) for sign-ins from the admin scope (`CA-Persona-GlobalAdmins` plus the 14 highly-privileged Entra ID directory roles by template ID) when accessing Microsoft Azure Management (`797f4846-ba00-4fd7-ba43-dac1f8f63013`) or Microsoft Admin Portals (`MicrosoftAdminPortals`). Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Layers on top of CA-AUT001 / CA-AUT002 (StrongAuth = WHfB or FIDO2) by narrowing to FIDO2-only on the highest-value admin surfaces. Auth-strength ID resolved at deploy time via `REPLACE_WITH_ADMIN_AUTH_STRENGTH_ID`. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV009-Internal-RequireCompliantDeviceOnDesktops.json — Internal persona desktop-platform policy. Requires compliant device or hybrid Azure AD joined device (`grantControls.builtInControls=["compliantDevice","domainJoinedDevice"]`, `operator=OR`) for sign-ins from Windows, macOS, and Linux platforms. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Scoped to `clientAppTypes=["browser","mobileAppsAndDesktopClients"]`. Mobile platforms (iOS, Android) are handled separately and out of scope for this policy. Closes the desktop-side gap where Internal users could sign in from unmanaged devices. Ships in report-only.
- Intune Compliance Baseline (ICB) framework skeleton: framework README at Frameworks/Intune-Compliance-Baseline/README.md, platform-led naming convention (ICB-WIN###, ICB-MAC###, ICB-IOS###, ICB-AND###, ICB-LIN###), scope, and roadmap. POLICY-DESIGN.md and the first Windows 10/11 compliance template land in subsequent PRs this week, with the v0.1.0-preview tag scheduled for Fri May 15, 2026.
- CA-SIG004-Global-MediumUserRisk: graduated medium User Risk response requiring StandardAuth and a password change, with sign-in frequency set to every time. Global persona with the standard Emergency Access / Workload Identities / Service Accounts excludes.
- CA-SIG005-Global-MediumSignInRisk: graduated medium Sign-In Risk response requiring StandardAuth, with sign-in frequency set to every time. Global persona with the standard Emergency Access / Workload Identities / Service Accounts excludes.
- CA-AUT003-Global-RegisterDevice policy template (Global persona; userAction urn:user:registerdevice; requires StandardAuth authentication strength; report-only on first deployment; excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts groups).
- CA-AUT004-Global-RegisterSecurityInfo policy template (Global persona; userAction urn:user:registersecurityinfo; requires StandardAuth authentication strength; report-only on first deployment; excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts groups).
- CA-COV008-Global-BlockByLocation policy template (Global persona; blocks sign-ins from locations outside the CA-LOCATION-TrustedCountries named-location set; report-only on first deployment; excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts groups).
- Frameworks/Conditional-Access-Baseline/Policies/CA-EXC002-ServiceAccounts-Exclusion.md — written contract documenting that every human-targeted CA-* policy excludes the ServiceAccounts persona via `users.excludeGroups`, and that the persona is the inclusion target for the v1.2 compensating control (CA-COV010-ServiceAccounts-BlockUntrustedLocations). Defines persona membership rules, monthly attestation, quarterly sign-in review, and credential rotation procedure. Parallel in structure to CA-EXC001-EmergencyAccess-Exclusion.md.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/ — new folder for tenant-scoped artifacts that CA policy templates depend on (custom authentication strengths, named locations). Includes a README documenting the schema and how `Deploy-CABaseline.ps1` will resolve placeholder IDs against the tenant.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/CA-AUTH-STRENGTH-StandardAuth.json — custom authentication strength: Windows Hello for Business, FIDO2, or password + Microsoft Authenticator push. Default strength for general user populations during the rollout to phishing-resistant credentials.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/CA-AUTH-STRENGTH-StrongAuth.json — custom authentication strength: Windows Hello for Business or FIDO2. Phishing-resistant only.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/CA-AUTH-STRENGTH-AdminAuth.json — custom authentication strength: FIDO2 only. Narrowest strength in the baseline; for privileged accounts and admin roles.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/CA-LOCATION-TrustedCountries.json — country-based named location template (`countryNamedLocation`). Default scope: US, `clientIpAddress` lookup, unknown countries excluded. Adopters customize the `countriesAndRegions` list to match their organization's trust posture before bootstrapping.
- Frameworks/Conditional-Access-Baseline/Scripts/Deploy-CABaseline.ps1 — added `Resolve-NamedLocationId` resolver, new `-SupportingArtifactsPath` and `-TrustedCountriesLocationName` parameters, and a new `REPLACE_WITH_TRUSTED_COUNTRIES_LOCATION_ID` substitution. The deployer now resolves named-location placeholders against `/identity/conditionalAccess/namedLocations` by display name.
- Frameworks/Conditional-Access-Baseline/Supporting-Artifacts/README.md — added named-locations section and a bootstrapping-artifacts section with the Graph API calls operators run once per tenant to provision custom authentication strengths and named locations before deployment.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV004-Global-NoPersistentBrowserSession.json — Global persona session-hardening policy. Disables persistent browser sessions (`persistentBrowser.mode=never`) and enforces a 4-hour browser sign-in frequency for all users. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts personas per CA-EXC001 and CA-EXC002. Scoped to `clientAppTypes=["browser"]`; excludes iOS and Android platforms where OS-level session handling makes the control redundant. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV005-Global-BlockDeviceCodeFlow.json — Global persona auth-flow policy. Blocks sign-ins that use OAuth 2.0 device code flow (`conditions.authenticationFlows.transferMethods="deviceCodeFlow"`) for all users on all applications. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Closes a phishing-friendly grant flow rarely used outside legitimate device-pairing scenarios. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV006-Global-BlockAuthenticationTransfer.json — Global persona auth-flow policy. Blocks Authentication Transfer (cross-device authentication initiated on one device and completed on another, `conditions.authenticationFlows.transferMethods="authenticationTransfer"`) for all users on all applications. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Ships in report-only.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV007-Global-BlockUnknownPlatforms.json — Global persona platform-hygiene policy. Blocks sign-ins from device platforms not in the named set (`includePlatforms=["all"]`, `excludePlatforms=["windows","macOS","iOS","android","linux","windowsPhone"]`) for all users on all applications. Excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts per CA-EXC001 and CA-EXC002. Catches sign-ins from spoofed, headless, or obsolete device platforms that fall outside the tenant's supported fleet. Ships in report-only.

### Changed

- Frameworks/Conditional-Access-Baseline/Business-Case/ROI-CONDITIONAL-ACCESS.md — folded the v1.2 slate into the executive ROI document. Policy count changed from "eight" to "twenty-three". Five-persona model (Global, Internal, Admins, Guests, ServiceAccounts) noted in the executive summary alongside the workload-identity policy. Expanded "What the baseline delivers" table with 15 new rows covering the v1.2 policies (CA-AUT003, CA-AUT004, CA-COV004 through CA-COV010, CA-SIG004 through CA-SIG008), grouped by persona segment. Expanded "Risk reduction framing" table to mirror. Added Token Protection client-version note and ServiceAccounts operational note to the licensing section. Added Trusted Countries named-location provisioning, three custom authentication strength provisioning steps (StandardAuth, StrongAuth, AdminAuth), and the ServiceAccounts persona group to the implementation prerequisites. Quarterly operational estimate updated from approximately 40 hours to approximately 52 hours per year to cover ServiceAccounts geography review, admin-context risk review, and expanded risk-detection tuning. Recommended investment approach Phase 3 window extended from weeks 9 to 12 to weeks 9 to 14 to accommodate the larger enforcement surface.
- Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md — documented sections 6.9 through 6.23 (`CA-COV004`, `CA-COV005`, `CA-COV006`, `CA-COV007`, `CA-AUT003`, `CA-AUT004`, `CA-COV008`, `CA-COV009`, `CA-SIG004`, `CA-SIG005`, `CA-AUT005`, `CA-SIG006`, `CA-SIG007`, `CA-COV010`, `CA-SIG008`) per-policy specs; added rollout-sequence rows 9 through 23; added the Service Accounts persona row to section 3 and the `CA-EXC002` reference under section 4.1 (permanent exclusions count updated from 2 to 3); added section 1.5 (v1.2 design refinements) and section 1.6 (Global and Admins scope definitions); updated section 6 intro count from "eight" to "twenty-three" starter policies.

### Fixed

- Top-level `README.md` — Frameworks table status for the Conditional Access Baseline updated from `v1.0.0` to `v1.1.0` to match the v1.1.0 release. Documentation-only correction; missed during the v1.1.0 release prep.

### Note on Intune Compliance Baseline timing

The original repo roadmap targeted the Intune Compliance Baseline at Q3 2026 for framework completion. The MVP Strategy publishing calendar (Month 2 Week 2, May 2026) calls for the first Intune compliance policy templates earlier. This release reconciles the two: the framework skeleton and first Windows 10/11 template ship now under the v0.1.0-preview tag (2026-05-15); full framework completion (macOS, iOS, Android, Linux templates, Deploy-ICBaseline.ps1, cross-framework integration doc with the Conditional Access Baseline) remains targeted at Q3 2026.

---

## [1.1.0] — 2026-05-01

Operational maturity and persona completeness release for the **Conditional Access Baseline**. Adds the External Guests and Workload Identities personas, a written Emergency Access exclusion contract, a report-only telemetry script, repo governance scaffolding, and a hardened deployer.

### Added

- Scripts/Get-CABaselineImpact.ps1 — report-only telemetry tool: analyzes sign-in logs and summarizes what each report-only CA policy would have done if enforced.
- Scripts/README.md — documentation and promotion rubric for Get-CABaselineImpact.ps1.
- .github/ISSUE_TEMPLATE/ — bug report, policy request, and documentation fix issue templates.
- .github/pull_request_template.md — PR checklist aligned to the four design principles.
- .github/CODEOWNERS — auto-review routing on every PR.
- Frameworks/Conditional-Access-Baseline/Policies/CA-EXC001-EmergencyAccess-Exclusion.md — written contract documenting that every CA-* policy excludes the Emergency Access persona, plus the operational runbook (alerting, monthly attestation, quarterly recovery drill, rotation).
- Frameworks/Conditional-Access-Baseline/Policies/CA-SIG003-Guests-RequireMFA.json — requires MFA for all external users (B2B collaboration guests, direct-connect users, internal guests, service providers, and other external users) on all applications. Honors CA-EXC001 by excluding the Emergency Access persona.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV003-WorkloadIdentities-TrustedLocations.json — blocks service principal sign-ins from outside a tenant-defined Trusted IPs named location. Requires Microsoft Entra Workload Identities Premium SKU; CAE does not apply to workload identity tokens.
- Frameworks/Conditional-Access-Baseline/Policies/CA-COV003-WorkloadIdentities.md — design doc covering hard prerequisites (Workload Identities Premium, Trusted IPs named location), per-SPN exclusion model (distinct from user-targeted CA-EXC001), SPN discovery query, and CAE limitations for workload identities.

### Changed

- Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md — documented section 6.7 (`CA-COV003-WorkloadIdentities-TrustedLocations`) and section 6.8 (`CA-SIG003-Guests-RequireMFA`) per-policy specs; added rollout-sequence rows 7 and 8; added `CA-EXC001` reference under section 4.1; updated section 6 intro count from "six" to "eight" starter policies.
- Frameworks/Conditional-Access-Baseline/Business-Case/ROI-CONDITIONAL-ACCESS.md — updated executive summary, "What the baseline delivers" table, "Risk reduction framing" table, licensing section, implementation prerequisites, and quarterly cadence to cover `CA-COV003` (workload identities — trusted locations) and `CA-SIG003` (guests — require MFA). Policy count changed from "six" to "eight". Workload Identities Premium add-on noted as a licensing line item. Quarterly operational estimate updated from ~32 hours to ~40 hours per year.

### Fixed

- Deploy-CABaseline.ps1 — hardened `Write-Status` against empty-string messages by adding `[AllowEmptyString()]` to the `$Message` parameter. Prevents the StrictMode regression that surfaced in v1.0.1 where `Write-Status ""` (used for blank-line spacing) threw a parameter validation error.
- Get-CABaselineImpact.ps1 — StrictMode-safe check for `@odata.nextLink` so the script doesn't error on the final page of sign-in results.
- Get-CABaselineImpact.ps1 — force array semantics around `.Count` accesses so the script works when 0 or 1 sign-ins / records / unique users exist (StrictMode correctness).

---

## [1.0.1] — 2026-04-23

Stability and accuracy fixes for the **Conditional Access Baseline**.

### Fixed

- **Deploy-CABaseline.ps1** — script no longer terminates with `Cannot bind argument to parameter 'Message' because it is an empty string` after a successful deployment. Replaced the empty-string `Write-Status ""` call before the summary table with a direct `Write-Host ""` for visual spacing.
- **Deploy-CABaseline.ps1** — added `Application.Read.All` to the required Graph scopes. Without it, `CA-SIG001-SensApps-RequireCompliantDevice` could not resolve the Azure Management application reference and policy creation failed. Updated the connection guidance, prerequisite check, and inline error messages to reflect the additional scope.
- **Deploy-CABaseline.ps1** — corrected the authentication strength Graph endpoint: `authenticationStrengths` (plural) → `authenticationStrength` (singular). This fixes `Resolve-AuthStrengthId` failing to return the tenant's `Phishing-resistant MFA` policy ID for the CA-AUT001 and CA-AUT002 templates.
- **Frameworks/Conditional-Access-Baseline/Scripts/README.md** — same Graph endpoint typo corrected in the documentation so the README matches the working script.

### Changed

- **Frameworks/Conditional-Access-Baseline/README.md** — updated component statuses from `Planned` to `Released` to reflect v1.0.0 availability.
- **.markdownlint.json** — added `MD040` (fenced-code-language) to the disabled-rules list so code blocks without language identifiers (commit message examples, shell prompts) no longer trigger warnings.

---

## [1.0.0] — 2026-04-22

First public release of the **Conditional Access Baseline** framework.

### Added

- **Framework landing page** at `Frameworks/Conditional-Access-Baseline/README.md` — scope, principles, six-policy table, prerequisites, and deployment workflow.
- **Design document** (`Frameworks/Conditional-Access-Baseline/Design/POLICY-DESIGN.md`) — four defensible-baseline principles, principle-coded naming convention, persona model, exclusion strategy, staged rollout sequence, and per-policy design specifications.
- **Six Conditional Access policy templates** in `Frameworks/Conditional-Access-Baseline/Policies/`, all shipped in report-only (`enabledForReportingButNotEnforced`):
  - `CA-COV001-AllUsers-BlockLegacyAuth.json`
  - `CA-COV002-AllUsers-RequireMFA.json`
  - `CA-SIG001-SensApps-RequireCompliantDevice.json`
  - `CA-AUT001-PrivAccounts-RequirePhishResistantMFA.json`
  - `CA-AUT002-PrivRoles-RequirePhishResistantMFA.json`
  - `CA-SIG002-AllUsers-RequireStepUpOnRisk.json`
- **Deployment script** `Frameworks/Conditional-Access-Baseline/Scripts/Deploy-CABaseline.ps1` — PowerShell 7, Microsoft Graph SDK 2.x, placeholder resolution, `-WhatIf` support, report-only default, confirmation-gated `-Enforce` switch.
- **Scripts usage guide** (`Frameworks/Conditional-Access-Baseline/Scripts/README.md`) — prerequisites, usage examples, expected output, troubleshooting.
- **Executive ROI document** (`Frameworks/Conditional-Access-Baseline/Business-Case/ROI-CONDITIONAL-ACCESS.md`) — business risk framing, investment model, risk reduction narrative, and compliance mapping (SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST SP 800-53).

### Added (repository foundation)

- Top-level `README.md` with Frameworks roadmap table.
- MIT `LICENSE`.
- `CONTRIBUTING.md` and `SECURITY.md`.
- `.gitignore` covering secrets, PowerShell artifacts, editor noise, and logs.
- `.markdownlint.json` disabling MD013, MD033, MD041, and MD060 for pragmatic Markdown style.
- Roadmap stub READMEs for:
  - Intune Compliance Baseline (Q3 2026)
  - Entra ID Governance Toolkit (Q4 2026)
  - Defender XDR Detection Rules (Q1 2027)

### Security

- All CA policy templates ship in report-only by default. Operators must explicitly opt in to enforcement via the `-Enforce` switch on the deployment script.
- Private vulnerability reporting enabled on the repository.
- Emergency access group exclusion placeholder documented across all applicable policies.

### Acknowledgments

This framework was shaped by the public work of Joey Verlinden, Daniel Chronlund, and Claus Jespersen on Conditional Access design patterns.

---

[Unreleased]: <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.4.0...HEAD>

[1.4.0]: <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/eig-v0.1.0-preview...v1.4.0>

[eig-v0.1.0-preview]: <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.3.0...eig-v0.1.0-preview>

[1.3.0]: <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.2.0...v1.3.0>

[1.2.0]: <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.1.0...v1.2.0>

[1.1.0]: <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.0.1...v1.1.0>

[1.0.1]: <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/compare/v1.0.0...v1.0.1>

[1.0.0]: <https://github.com/Cloud-Harbor-Consulting-LLC/M365-Security-Frameworks/releases/tag/v1.0.0>
