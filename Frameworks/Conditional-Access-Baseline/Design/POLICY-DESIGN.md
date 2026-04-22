# Conditional Access Baseline — Policy Design

This document specifies the design philosophy, naming convention, persona model, and exclusion strategy for the Conditional Access Baseline framework. It is the prerequisite reading for anyone deploying, extending, or auditing the baseline.

The per-policy design specifications (one subsection for each of the six starter policies) are appended in the following section of this document.

---

## 1. Design philosophy

Conditional Access is Microsoft's Zero Trust policy engine, not a collection of feature toggles. This baseline is built around the thesis that **until a defensible baseline exists, adding more Conditional Access policies increases complexity without materially reducing risk.**

Four principles anchor every design decision in this framework:

### 1.1 Identity-wide coverage

**What it means:** No orphaned identities, applications, or legacy protocols should be able to authenticate outside the scope of Conditional Access. Every user, every guest, every workload identity, and every cloud app must be covered by at least one evaluated policy.

**How this baseline implements it:** Policies `CA-COV001` (Block legacy authentication) and `CA-COV002` (Require MFA for all users) are scoped to "All users" and "All cloud apps" — with controlled exclusions for emergency access accounts and workload identities that have their own hardened paths.

### 1.2 No standing exclusions

**What it means:** Exclusions are a common attack path. An exclusion group that persists indefinitely becomes a backdoor — one compromised member, and the entire baseline can be bypassed. Exclusions must be time-bound, auditable, and reviewed.

**How this baseline implements it:** Only two exclusion groups are considered permanent: emergency access accounts (two total, monitored by alert) and workload identities governed by a separate workload-identity policy set. All other exclusions are temporary, tracked by owner and expiration date, and reviewed quarterly.

### 1.3 Layered signals

**What it means:** Strong security emerges from combining signals — identity risk, device state, location, application sensitivity — not from any single control. A policy that evaluates only one signal is a single point of failure.

**How this baseline implements it:** Policies in the `CA-SIG` series evaluate multiple signals in combination. `CA-SIG001` layers application sensitivity with device compliance; `CA-SIG002` layers sign-in risk with step-up authentication. This is the difference between "require MFA" and "require MFA *because we detected risk*."

### 1.4 Authentication Strengths

**What it means:** Not all MFA is equal. SMS and voice-call MFA are phishable via AiTM (adversary-in-the-middle) proxies; FIDO2, Windows Hello for Business, and certificate-based authentication are not. Privileged identities and high-value workloads must be protected by phishing-resistant methods.

**How this baseline implements it:** Policies in the `CA-AUT` series use Entra ID Authentication Strengths to require phishing-resistant MFA for privileged accounts (`CA-AUT001`) and privileged role activations (`CA-AUT002`). No privileged action clears the baseline without a phishing-resistant credential.

---

## 2. Naming convention

Every policy in this baseline follows the format:

```
CA-[PrinciplePrefix][Number]-[Persona]-[Action]
```

### 2.1 Principle prefixes

| Prefix | Principle | Use when the policy primarily enforces... |
|--------|-----------|-------------------------------------------|
| `COV` | Identity-wide coverage | Blanket coverage of users, apps, or protocols |
| `EXC` | No standing exclusions | Time-bound access paths, JIT elevation, guest lifecycle |
| `SIG` | Layered signals | Device, location, or risk signals shaping access decisions |
| `AUT` | Authentication Strengths | Phishing-resistant MFA requirements |

### 2.2 Rules

- **One prefix per policy.** When a policy could fit two prefixes, use the one that reflects its primary intent. Document the secondary intent in the policy's design spec.
- **Numbers are sequential within a prefix.** `CA-SIG001` comes before `CA-SIG002`; retired policies keep their number permanently.
- **Persona and action are hyphen-separated.** Use CamelCase within each segment (`PrivAccounts`, `BlockLegacyAuth`) — no spaces, no underscores.
- **File names mirror policy names.** JSON template for `CA-COV001-AllUsers-BlockLegacyAuth` is `CA-COV001-AllUsers-BlockLegacyAuth.json`.

---

## 3. Persona model

This baseline is deployed around the people it protects. Each persona maps to one or more Entra ID groups that serve as scope targets for policies.

| Persona | Suggested Entra Group | Typical Size | Notes |
|---------|----------------------|--------------|-------|
| Global & Privileged Administrators | `CA-Persona-GlobalAdmins` | 2–5 members | Break-glass accounts are NOT members |
| Privileged Roles (PIM-activated) | Dynamic, driven by PIM activation | Varies | Scoped via directory roles, not a static group |
| Internal Users | `CA-Persona-InternalUsers` | All employees | Dynamic group based on `userType eq 'Member'` recommended |
| Guest Users | `CA-Persona-GuestUsers` | Varies | Dynamic group based on `userType eq 'Guest'` recommended |
| Workload Identities | `CA-Persona-WorkloadIdentities` | Inventory-dependent | Scoped via the Workload Identities blade, not a user group |
| Emergency Access Accounts | `CA-Persona-EmergencyAccess` | Exactly 2 | Monitored by alert rule; never members of any other group |

### 3.1 Persona naming

The `CA-Persona-` prefix on groups is intentional: it makes persona groups sortable, searchable, and unambiguous in the Entra admin center. Avoid reusing existing business groups (e.g., "All Employees") as persona scopes — policy scope and HR scope should not be conflated.

---

## 4. Exclusion group strategy

Exclusions are the single most dangerous element of any Conditional Access baseline. This framework treats them with corresponding rigor.

### 4.1 Permanent exclusions (2 total)

1. **Emergency access accounts** (`CA-Persona-EmergencyAccess`) — excluded from every policy. Two accounts, cloud-only, stored offline in a sealed envelope, monitored by a sign-in alert rule that pages the security team on any use.
2. **Workload identities** — excluded from user-scoped policies and governed by a separate workload-identity policy set.

### 4.2 Temporary exclusions

All other exclusions are temporary and tracked in a single location (`exclusions.md` in this framework, forthcoming) with:

- **Exclusion owner** — the person who requested it
- **Justification** — the business reason
- **Expiration date** — no longer than 90 days without renewal
- **Reviewer** — who reviews at expiration

Quarterly, the baseline's maintainer audits all temporary exclusions and either renews (with re-justification) or removes them.

### 4.3 Anti-patterns to avoid

- ❌ "Helpdesk exclusion" groups that accumulate members over time
- ❌ Service account exclusions that aren't tied to a hardened workload identity policy
- ❌ Long-lived "pilot" exclusions that outlast the pilot
- ❌ Executive exclusions (executives are the highest-value targets — strengthen, don't exclude)

---

## 5. Rollout sequence

Policies should be staged, enforced, and promoted in the following order. Each step has a minimum soak period in report-only mode.

| Order | Policy | Minimum report-only soak | Why this order |
|-------|--------|-------------------------|----------------|
| 1 | `CA-COV001-AllUsers-BlockLegacyAuth` | 14 days | Highest impact, lowest user-facing friction — establishes the floor |
| 2 | `CA-COV002-AllUsers-RequireMFA` | 14 days | Builds on CA-COV001; flushes out accounts missing MFA registration |
| 3 | `CA-AUT001-PrivAccounts-RequirePhishResistantMFA` | 7 days | Small, high-trust scope — easy to validate |
| 4 | `CA-AUT002-PrivRoles-RequirePhishResistantMFA` | 7 days | PIM-path parallel to CA-AUT001 |
| 5 | `CA-SIG001-SensApps-RequireCompliantDevice` | 14 days | Requires device compliance maturity — soak longer |
| 6 | `CA-SIG002-AllUsers-RequireStepUpOnRisk` | 14 days | Requires Entra ID P2 + Identity Protection tuning — soak longer |

**Do not skip report-only.** Every policy must be validated in report-only mode before enforcement, no matter how confident the reviewer is in its scope.

---

## 6. What's next

The following section of this document specifies the full design for each of the six starter policies: `CA-COV001`, `CA-COV002`, `CA-SIG001`, `CA-AUT001`, `CA-AUT002`, and `CA-SIG002`. Each spec covers intent, scope, conditions, grant/block controls, exclusions, validation steps, and the corresponding JSON template path.

*(Per-policy specifications to be added in the next commit.)*
