# Conditional Access Baseline — Business Case and ROI

> A plain-language business case for security architects defending Conditional Access investment to executive leaders, the C-suite, and board members.

## Executive summary

Identity is the modern enterprise perimeter. Over the last five years, industry data from Verizon's annual *Data Breach Investigations Report (DBIR)*, IBM's annual *Cost of a Data Breach Report*, and the *Microsoft Digital Defense Report* consistently ranks stolen or misused credentials as the leading initial access vector for enterprise breaches. Organizations that deploy a mature Conditional Access baseline materially reduce the probability of credential-driven incidents — without adding meaningful user friction when scoped correctly.

This baseline delivers six foundational Conditional Access policies. They are designed to close the access paths attackers exploit most frequently — legacy authentication, unprotected privileged accounts, unmanaged endpoints accessing sensitive data, and high-risk sign-ins — while leaving routine user workflows untouched.

The ask of executive leadership is threefold:

1. **Endorse a phased deployment** that runs each policy in report-only mode for 7 to 14 days before enforcement.
2. **Fund or confirm Entra ID P1 (minimum) or P2 (recommended)** licensing for all in-scope users.
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

MFA is necessary but no longer sufficient. Attackers using AiTM proxy kits (readily available on criminal marketplaces) can phish a valid MFA-protected session token in minutes and replay it to the target service. Microsoft's own guidance has shifted to phishing-resistant methods — FIDO2 security keys, Windows Hello for Business, certificate-based authentication — for privileged identities and high-value workloads. This baseline enforces that shift for the accounts attackers target first.

## What the baseline delivers

Six policies, each addressing a specific business risk. The table below summarizes each one in non-technical language.

| Policy | Business risk addressed | User impact |
|--------|------------------------|-------------|
| Block legacy authentication | Eliminates authentication protocols that cannot enforce MFA and are the primary vector for password-spray attacks. | None for users on modern clients (Outlook, Teams, Microsoft 365 apps). |
| Require MFA for all users | Ensures no identity authenticates with a password alone. Establishes the floor beneath every other control. | A second authentication step on unfamiliar devices or sessions. |
| Require phishing-resistant MFA for privileged accounts | Protects the accounts attackers target first against AiTM credential phishing. | Privileged users sign in with a hardware security key or Windows Hello instead of SMS. |
| Require phishing-resistant MFA for privileged role activations | Extends the protection above to just-in-time privilege elevation via Privileged Identity Management. | Administrators activate elevated roles with phishing-resistant credentials. |
| Require compliant or hybrid-joined device for sensitive apps | Ensures access to admin portals, email, and crown-jewel SaaS originates from a managed, healthy endpoint. | Users access sensitive apps only from organization-managed or hybrid-joined devices. |
| Step-up MFA on medium or high-risk sign-ins | Automatically challenges sign-ins that Entra ID Protection scores as risky (impossible travel, unfamiliar location, leaked credentials, anonymous proxy). | An additional MFA prompt when Entra ID detects anomalous behavior — transparent in normal conditions. |

## Investment required

### Licensing

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Entra ID plan | P1 | P2 |
| Why P2 is recommended | N/A | Unlocks Identity Protection (required for risk-based step-up, policy 6) and Privileged Identity Management (required for privileged-role JIT activation) |

**If P1 is already in place for all users,** the incremental licensing cost of this baseline is zero to deploy five of the six policies. Policy 6 (risk-based step-up) requires P2.

**If P2 is not yet in place,** the incremental cost per user can be calculated against the organization's existing Microsoft 365 agreement:

- [INSERT: CURRENT USERS AT P1 × COST-PER-USER DELTA FROM P1 TO P2]

### Implementation (one-time)

Implementation time varies by organization size and operational maturity. Typical engagement components:

- Persona group design and creation
- Emergency access account provisioning and documentation
- Device compliance baseline in Microsoft Intune (prerequisite for policy 5)
- MFA registration campaign (prerequisite for policy 2)
- Phishing-resistant method rollout to privileged users (prerequisite for policies 3 and 4)
- Report-only soak and validation (minimum 7–14 days per policy, parallelized)
- Tuning and enforcement

A representative estimate for a mid-market organization (500–5,000 users) is measured in tens of hours of security-architect time, not hundreds. For organizations above 10,000 users or with complex hybrid identity architectures, scope accordingly.

### Ongoing (quarterly)

- Baseline review and tuning (~4 hours per quarter)
- Temporary exclusion audit (~2 hours per quarter)
- Risk detection tuning for policy 6 (~2 hours per quarter)

**Total annualized operational cost after deployment:** ~32 hours of security-architect time per year.

## Risk reduction framing

The baseline does not eliminate breach risk — no single control does. It does materially reduce the probability of the highest-frequency attack paths. Each policy maps to a specific reduction:

| Policy | Primary threat reduced | Secondary benefit |
|--------|----------------------|-------------------|
| Block legacy authentication | Password-spray attacks against IMAP, POP, SMTP AUTH endpoints | Removes an entire unauthenticated-by-MFA surface |
| Require MFA for all users | Credential stuffing from third-party breaches | Forces MFA registration across the user base |
| Require phishing-resistant MFA for privileged accounts | AiTM token phishing of privileged identities | Creates audit evidence of strong admin auth |
| Require phishing-resistant MFA for privileged role activations | PIM activation with phishable MFA | Closes the JIT-elevation gap |
| Require compliant/hybrid-joined device for sensitive apps | Data exfiltration from unmanaged endpoints | Establishes device health as an access condition |
| Step-up MFA on risky sign-ins | Novel attack patterns (impossible travel, new country, AiTM indicators) | Creates adaptive, signal-driven defense |

## Compliance and audit alignment

This baseline supports the access control requirements in every major compliance framework the organization is likely to operate under. The mapping below is representative — organizations should validate specific control numbers against current framework revisions with their audit team.

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

- Create persona groups and emergency access accounts
- Deploy Intune device compliance baseline (if not already in place)
- Import all six policies in report-only mode
- Begin MFA registration campaign

### Phase 2 — Soak and validation (weeks 5 to 8)

- Monitor report-only results for each policy
- Remediate any findings (users without MFA, services using legacy auth, non-compliant devices)
- Complete phishing-resistant method rollout to privileged users

### Phase 3 — Staged enforcement (weeks 9 to 12)

- Promote policies from report-only to enforced in the sequence defined in Policy-Design.md section 5
- Monitor helpdesk and Entra sign-in logs for friction
- Declare baseline v1.0 complete

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
