# Conditional Access Baseline — Business Case and ROI

> A plain-language business case for security architects defending Conditional Access investment to executive leaders, the C-suite, and board members.

## Executive summary

Identity is the modern enterprise perimeter. Over the last five years, industry data from Verizon's annual *Data Breach Investigations Report (DBIR)*, IBM's annual *Cost of a Data Breach Report*, and the *Microsoft Digital Defense Report* consistently ranks stolen or misused credentials as the leading initial access vector for enterprise breaches. Organizations that deploy a mature Conditional Access baseline materially reduce the probability of credential-driven incidents, without adding meaningful user friction when scoped correctly.

This baseline delivers twenty-three Conditional Access policies across five user personas (Global, Internal, Admins, Guests, ServiceAccounts), plus a workload-identity policy that closes the machine-sign-in coverage gap. Policies are designed to close the access paths attackers exploit most frequently: legacy authentication, unprotected privileged accounts, unmanaged endpoints accessing sensitive data, high-risk sign-ins, post-MFA token replay, untrusted geographies, and orphaned service-account credentials. Routine user workflows remain untouched.

The ask of executive leadership is threefold:

1. **Endorse a phased deployment** that runs each policy in report-only mode for 7 to 14 days before enforcement.
2. **Fund or confirm Entra ID P1 (minimum) or P2 (recommended)** licensing for all in-scope users, plus Microsoft Entra Workload Identities Premium for the workload-identity policy.
3. **Authorize a quarterly review cadence** for the baseline, led jointly by Security and IT Operations.

In return, the organization gets a defensible, auditable identity security posture that addresses the single highest-probability breach vector and aligns with SOC 2, ISO 27001, HIPAA, and PCI-DSS access control requirements.

## The business risk this addresses

### Identity compromise is the dominant breach vector

Every year since the publication of the Verizon DBIR began tracking credential-based attacks as a distinct category, stolen or misused credentials have ranked among the top initial access vectors across industries and organization sizes. Phishing, password spray, adversary-in-the-middle (AiTM) token theft, and re-use of credentials exposed in third-party breaches all converge on the same point of failure: an identity that authenticates successfully with insufficient verification.

### The financial exposure is substantial

IBM's *Cost of a Data Breach Report* has consistently found that the global average cost of a data breach is measured in millions of US dollars, with breaches involving stolen or compromised credentials taking longer to identify and contain than average. For organizations in regulated industries (healthcare, financial services, critical infrastructure), the per-breach cost is materially higher.

For this baseline's ROI calculation, the organization should reference its own most recent cyber-insurance questionnaire, internal risk register, or the latest published figures from IBM and Verizon to populate:

- [INSERT: ORGANIZATION'S ESTIMATED ANNUAL BREACH-RISK EXPOSURE]
- [INSERT: ORGANIZATION'S CURRENT CYBER-INSURANCE PREMIUM]
- [INSERT: INDUSTRY AVERAGE BREACH COST FROM LATEST IBM REPORT]

### Legacy MFA does not close the gap alone

MFA is necessary but no longer sufficient. Attackers using AiTM proxy kits (readily available on criminal marketplaces) can phish a valid MFA-protected session token in minutes and replay it to the target service. Microsoft's own guidance has shifted to phishing-resistant methods (FIDO2 security keys, Windows Hello for Business, certificate-based authentication) for privileged identities and high-value workloads. This baseline enforces that shift for the accounts attackers target first, and the v1.2 expansion binds tokens to issuing Windows devices to defeat replay even when phishing-resistant MFA was not in play.

## What the baseline delivers

Twenty-three policies, each addressing a specific business risk. The table below summarizes each one in non-technical language, grouped by the persona the policy targets.

| Policy | Business risk addressed | User impact |
|--------|------------------------|-------------|
| **Global persona** | | |
| Block legacy authentication | Eliminates authentication protocols that cannot enforce MFA and are the primary vector for password-spray attacks. | None for users on modern clients (Outlook, Teams, Microsoft 365 apps). |
| Require MFA for all users | Ensures no identity authenticates with a password alone. Establishes the floor beneath every other control. | A second authentication step on unfamiliar devices or sessions. |
| Step-up MFA on medium or high sign-in risk | Automatically challenges sign-ins that Entra ID Protection scores as risky (impossible travel, unfamiliar location, leaked credentials, anonymous proxy). | An additional MFA prompt during anomalous sessions. |
| Require step-up and password change on medium user risk | Forces remediation when Identity Protection flags account-level compromise indicators. | A password reset prompt the next time the affected user signs in. |
| Require strong authentication at device registration | Prevents an attacker who phished a password from registering a new device as a trusted enrollment point. | A strong-authentication prompt the first time a user enrolls a new device. |
| Require strong authentication at security info registration | Prevents an attacker from swapping in a phone number or authenticator they control after stealing a password. | A strong-authentication prompt when adding or removing an MFA method. |
| Disable persistent browser sessions | Bounds the validity of stolen browser cookies by enforcing a 4-hour browser re-authentication window. | Users re-authenticate in the browser every 4 hours. |
| Block OAuth device code flow | Removes a phishing-friendly grant flow rarely used outside legitimate device-pairing scenarios. | None for typical user workflows. |
| Block authentication transfer | Removes a cross-device authentication flow attackers can social-engineer into approving on the wrong endpoint. | None in normal workflows. |
| Block sign-ins from unknown device platforms | Catches sign-ins from spoofed, headless, or obsolete platforms outside the tenant's supported fleet. | None on Windows, macOS, iOS, Android, Linux. |
| Block sign-ins from untrusted countries | Removes geographies the business does not operate in from the attack surface. | Travelers register their location ahead of time or use approved access methods. |
| **Internal persona** | | |
| Require compliant or hybrid-joined device for sensitive apps | Ensures access to admin portals, email, and crown-jewel SaaS originates from a managed, healthy endpoint. | Users access sensitive apps only from organization-managed or hybrid-joined devices. |
| Require compliant device on internal desktop platforms | Extends device-health-as-a-gate from sensitive apps to all internal sign-ins on Windows, macOS, and Linux. | Internal users sign in from organization-managed desktops. |
| Bind tokens to the issuing Windows device (Token Protection) | Cryptographically ties refresh tokens and Primary Refresh Tokens to the device's TPM, defeating AiTM token replay and infostealer token theft. | None for users on supported Windows clients with modern auth. |
| **Admins persona** | | |
| Require phishing-resistant MFA for privileged accounts | Protects the accounts attackers target first against AiTM credential phishing. | Privileged users sign in with a hardware security key or Windows Hello instead of SMS. |
| Require phishing-resistant MFA for privileged role activations | Extends the protection above to just-in-time privilege elevation via Privileged Identity Management. | Administrators activate elevated roles with phishing-resistant credentials. |
| Require FIDO2-only authentication on admin portals | Narrows the highest-value admin surfaces (Azure portal, Microsoft Admin Portals) to phishing-resistant authentication only. | Admins use a FIDO2 key when opening admin portals. |
| Block admin sign-ins flagged medium or high risk | Hard-blocks privileged sessions Entra ID Protection scores as risky rather than offering a step-up path. | Blocked admin sessions are remediated via a clean re-authentication. |
| **Guests persona** | | |
| Require MFA for guest users | Closes the gap where home-tenant authentication assurance for guest users may be weaker than the resource tenant's internal-user standard. | External collaborators complete MFA when accessing tenant resources. |
| Block guest access to non-collaboration apps | Constrains B2B authorization scope to the apps that were shared, preventing token replay against unrelated tenant applications. | External collaborators access only the apps they were invited to. |
| **ServiceAccounts persona** | | |
| Block service-account sign-ins from untrusted countries | Closes the workload coverage gap created by excluding ServiceAccounts from human-targeted policies. | Service accounts authenticate only from registered egress geographies. |
| **Workload identities** | | |
| Block workload identity sign-ins from untrusted locations | Restricts service principal sign-ins to a defined egress, closing the workload-identity coverage gap left by user-scoped policies. | None for legitimate automation; vendor or cloud-resident workloads need their egress IPs registered. |

## Investment required

### Licensing

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Entra ID plan | P1 | P2 |
| Why P2 is recommended | N/A | Unlocks Identity Protection (required for sign-in and user-risk policies) and Privileged Identity Management (required for privileged-role JIT activation) |
| Microsoft Entra Workload Identities Premium | Required for the workload-identity policy (CA-COV003) | Required for the workload-identity policy (CA-COV003) |

**If P1 is already in place for all users,** the incremental licensing cost of this baseline covers the policies that require Identity Protection (sign-in risk and user-risk policies) and PIM (privileged role activation). Most of the v1.2 expansion uses P1 features.

**If P2 is not yet in place,** the incremental cost per user can be calculated against the organization's existing Microsoft 365 agreement:

- [INSERT: CURRENT USERS AT P1 × COST-PER-USER DELTA FROM P1 TO P2]

Additional notes:

- The Token Protection policy (Windows-only token binding) requires modern-auth clients and supported Windows 10/11 builds. No additional SKU is required; deploy after inventorying client versions in the tenant.
- The ServiceAccounts persona policy requires an inventory of legitimate service-account sign-in geographies. This is an operational input, not a licensing line item.

### Implementation (one-time)

Implementation time varies by organization size and operational maturity. Typical engagement components:

- Persona group design and creation (Global, Internal, Admins, Guests, ServiceAccounts)
- Emergency access account provisioning and documentation
- Device compliance baseline in Microsoft Intune (prerequisite for compliant-device policies)
- MFA registration campaign (prerequisite for the all-users MFA policy)
- Phishing-resistant method rollout to privileged users (prerequisite for the admin AUT-series policies)
- Trusted Countries named location provisioning, populated with the organization's operating geographies
- Three custom authentication strengths provisioned: StandardAuth (WHfB, FIDO2, or Password + Authenticator push), StrongAuth (WHfB or FIDO2), AdminAuth (FIDO2 only)
- ServiceAccounts persona group provisioning, with documented membership rules and a monthly attestation
- Report-only soak and validation (minimum 7 to 14 days per policy, parallelized)
- Tuning and enforcement

A representative estimate for a mid-market organization (500 to 5,000 users) is measured in tens of hours of security-architect time, not hundreds. For organizations above 10,000 users or with complex hybrid identity architectures, scope accordingly.

### Ongoing (quarterly)

- Baseline review and tuning (approximately 6 hours per quarter, expanded to cover the larger v1.2 surface)
- Temporary exclusion audit (approximately 2 hours per quarter)
- Risk detection tuning for sign-in and user-risk policies (approximately 3 hours per quarter, expanded for the medium-risk additions)
- ServiceAccounts sign-in geography review (approximately 1 hour per quarter)
- Admin-context risk and authentication-strength review (approximately 1 hour per quarter)

**Total annualized operational cost after deployment:** approximately 52 hours of security-architect time per year.

## Risk reduction framing

The baseline does not eliminate breach risk. No single control does. It does materially reduce the probability of the highest-frequency attack paths. Each policy maps to a specific reduction:

| Policy | Primary threat reduced | Secondary benefit |
|--------|----------------------|-------------------|
| **Global persona** | | |
| Block legacy authentication | Password-spray attacks against IMAP, POP, SMTP AUTH endpoints | Removes an entire unauthenticated-by-MFA surface |
| Require MFA for all users | Credential stuffing from third-party breaches | Forces MFA registration across the user base |
| Step-up MFA on medium or high sign-in risk | Anomalous sessions flagged by Identity Protection | Creates adaptive, signal-driven defense |
| Require step-up and password change on medium user risk | Compromised credentials in active circulation | Forces a password rotation tied to the risk event |
| Require strong authentication at device registration | Adversary-led device registration after a password phish | Creates an authentication-strength signal at the enrollment moment |
| Require strong authentication at security info registration | MFA method takeover (swap to attacker-controlled number or authenticator) | Hardens the security info surface that is itself the recovery path |
| Disable persistent browser sessions | Stolen browser cookie replay on persistent sessions | Bounds session validity to a defensible window |
| Block OAuth device code flow | OAuth device code phishing | Removes a low-friction grant flow attackers favor |
| Block authentication transfer | Cross-device authentication social engineering | Eliminates a transfer flow attackers can redirect |
| Block sign-ins from unknown device platforms | Sign-ins from spoofed, headless, or obsolete platforms | Catches non-business device platforms outside the supported set |
| Block sign-ins from untrusted countries | Sign-ins from geographies the business does not operate in | Removes whole attacker origins from the surface area |
| **Internal persona** | | |
| Require compliant or hybrid-joined device for sensitive apps | Data exfiltration from unmanaged endpoints | Establishes device health as an access condition for high-value apps |
| Require compliant device on internal desktop platforms | Sign-ins to internal apps from unmanaged desktops | Extends device-health-as-a-gate beyond sensitive apps |
| Bind tokens to the issuing Windows device (Token Protection) | Post-MFA token replay (AiTM, infostealer, cookie redemption) | TPM-bound tokens are non-portable |
| **Admins persona** | | |
| Require phishing-resistant MFA for privileged accounts | AiTM token phishing of privileged identities | Creates audit evidence of strong admin auth |
| Require phishing-resistant MFA for privileged role activations | PIM activation with phishable MFA | Closes the JIT-elevation gap |
| Require FIDO2-only authentication on admin portals | Admin sign-ins to high-value portals with phishable MFA | Narrows admin authentication to FIDO2 on the riskiest surfaces |
| Block admin sign-ins flagged medium or high risk | Admin credentials in a risk-flagged session | Hard-blocks rather than re-challenges privileged identities |
| **Guests persona** | | |
| Require MFA for guest users | Weak home-tenant MFA on guest identities | Establishes a resource-tenant authentication floor for B2B |
| Block guest access to non-collaboration apps | Guest token replay against unrelated tenant apps | Constrains B2B authorization scope to the apps that were shared |
| **ServiceAccounts persona** | | |
| Block service-account sign-ins from untrusted countries | Service-account sign-ins from non-business geographies | Closes the workload coverage gap from the human-policy exclusion |
| **Workload identities** | | |
| Block workload identity sign-ins from untrusted locations | Service principal sign-ins from non-business egress IPs | Closes the workload-identity exclusion gap in the user-scoped baseline |

## Compliance and audit alignment

This baseline supports the access control requirements in every major compliance framework the organization is likely to operate under. The mapping below is representative. Organizations should validate specific control numbers against current framework revisions with their audit team.

| Framework | Relevant control family | How this baseline supports it |
|-----------|------------------------|------------------------------|
| SOC 2 (Trust Services Criteria) | CC6.1, CC6.2, CC6.3 (Logical and Physical Access) | Enforces authentication, identity access, and access restrictions based on role and context |
| ISO/IEC 27001:2022 | A.5.15, A.5.17, A.8.2, A.8.5 (Access Control, Authentication Information, Privileged Access Rights, Secure Authentication) | Formalizes privileged access requirements and secure authentication patterns |
| HIPAA Security Rule | §164.312(a)(1) (Access Control), §164.312(d) (Person or Entity Authentication) | Enforces authentication, authorization, and access restriction for systems handling ePHI |
| PCI-DSS 4.0 | Requirement 7 (Restrict Access), Requirement 8 (Identify Users and Authenticate Access) | Multi-factor authentication for all users, phishing-resistant MFA for privileged users |
| NIST SP 800-53 rev. 5 | AC-2, AC-3, IA-2, IA-5 (Account Management, Access Enforcement, Identification and Authentication, Authenticator Management) | Formalized account scoping, enforced access control, strong authenticator requirements |

Beyond compliance, the baseline also satisfies the identity-related controls cyber-insurance carriers increasingly require as a precondition for coverage or favorable premium pricing.

## Recommended investment approach

### Phase 1 — Foundation (week 1 to 4)

- Create persona groups (Global, Internal, Admins, Guests, ServiceAccounts) and emergency access accounts
- Deploy Intune device compliance baseline (if not already in place)
- Provision the three custom authentication strengths (StandardAuth, StrongAuth, AdminAuth)
- Provision the Trusted Countries named location with the organization's operating geographies
- Import all twenty-three policies in report-only mode
- Begin MFA registration campaign

### Phase 2 — Soak and validation (weeks 5 to 8)

- Monitor report-only results for each policy
- Remediate any findings (users without MFA, services using legacy auth, non-compliant devices, service accounts authenticating from unregistered IPs)
- Complete phishing-resistant method rollout to privileged users
- Inventory Token Protection client compatibility (Windows build, modern auth confirmed)

### Phase 3 — Staged enforcement (weeks 9 to 14)

- Promote policies from report-only to enforced in the sequence defined in POLICY-DESIGN.md section 5
- Monitor helpdesk and Entra sign-in logs for friction
- Declare baseline v1.2 complete

### Phase 4 — Steady state (ongoing)

- Quarterly review per the cadence defined above
- Extend the baseline with additional frameworks (Intune Compliance Baseline, Entra ID Governance Toolkit, Defender XDR Detection Rules) from this same repository

## The investment recommendation

Adopt this Conditional Access baseline as the identity security floor for the organization. The incremental cost is modest when P1 is already licensed, the operational burden is measured in a few dozen hours per year, and the risk reduction addresses the single most common initial-access vector in contemporary breach data.

Conditional Access is Microsoft's Zero Trust policy engine. Deploying a defensible baseline is a decision that can be audited, defended, and amended. Choosing to defer it is also a decision, and one that should be made with full awareness of the risk being accepted.

## References

- Verizon. *Data Breach Investigations Report* (annual).
- IBM Security. *Cost of a Data Breach Report* (annual).
- Microsoft. *Microsoft Digital Defense Report* (annual).
- Microsoft Learn. [Conditional Access architecture](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies).
- Cloud Harbor Consulting. [Why Entra ID Conditional Access Fails in Practice (And How to Fix It)](https://www.cloudharborconsulting.cloud/post/why-entra-id-conditional-access-fails-in-practice-and-how-to-fix-it).

## Notes on bracketed placeholders

Three bracketed placeholders in this document should be populated by the deploying organization before this business case is presented to executive leadership:

- Estimated annual breach-risk exposure (from the organization's risk register or cyber-insurance questionnaire)
- Current cyber-insurance premium (from the organization's insurance renewal data)
- Industry average breach cost (from the most recent IBM *Cost of a Data Breach Report*)
- Incremental P1-to-P2 licensing cost per user (from the organization's Microsoft licensing agreement)

These numbers convert a directional business case into a quantified ROI specific to the organization. A template with named industry references ages better than a template with specific percentages that drift as new reports are published.
