# CAE and Token Protection Layering — Design Document

This document covers how Continuous Access Evaluation (CAE) and Token Protection layer together on the v1.3 Conditional Access Baseline. It is a deep-dive companion to the CA-SIG007-Internal-TokenProtection paired contract (`Policies/CA-SIG007-Internal-TokenProtection.md`) and the per-policy spec in `Design/POLICY-DESIGN.md` Section 6.21.

---

## 1. Introduction

Post-MFA token theft is a real and growing attack surface in 2026. Completing MFA does not guarantee that the resulting session is safe. Two attack classes operate after MFA succeeds and are responsible for a growing share of Microsoft 365 compromise incidents.

**AiTM (adversary-in-the-middle) phishing.** Modern phishing kits — Evilginx, Modlishka, and purpose-built variants distributed as phishing-as-a-service — proxy the real Microsoft sign-in flow. The user is directed to a phishing URL that sits transparently between the user's browser and Microsoft Entra ID. The user sees a pixel-perfect sign-in page, enters their credentials, and completes MFA. The proxy captures the resulting session token (the cookie or access token that Microsoft issues after successful authentication) and forwards it to attacker-controlled infrastructure. The user sees a normal, successful sign-in. The attacker has a fully authenticated session. MFA was completed — against the proxy. The resulting token is legitimate from Microsoft's perspective.

**Infostealer token exfiltration.** Infostealers — RedLine, Lumma, RisePro, Vidar, and dozens of variants distributed via malvertising and cracked software — run on the user's endpoint and exfiltrate token stores from multiple locations: browser profiles (Chrome, Edge, Firefox token caches), the Windows Credential Manager, the Primary Refresh Token store in the Entra ID Broker plugin, and application-specific token caches. A refresh token or Primary Refresh Token extracted from a compromised endpoint can be redeemed against Microsoft Graph and the Office 365 application group from the attacker's infrastructure. Because the token already carries a satisfied MFA claim from when it was originally issued, no MFA prompt is triggered on redemption.

**Why MFA alone does not close the gap.** MFA proves that the user authenticated at token issuance time. It does not prove that the resulting token is being used by the same user, on the same device, at the same time. Once a token exists in memory or on disk, it is portable. In both attack scenarios above, MFA was satisfied. The token is legitimate. The gap is that nothing in the standard token model prevents the token from being redeemed elsewhere, by someone else, from different infrastructure.

**Why a single defensive control does not close the gap.** CAE responds to revocation events — it handles the scenario where the account should no longer have access: password changed, account disabled, risk detected. Token Protection prevents stolen tokens from being redeemed on a different device — it handles the scenario where the token was stolen but no revocation event has occurred yet. Neither control alone covers both halves of the attack surface. Each compensates for the other's structural gap.

This document covers:

- What CAE is and what it does and does not cover.
- What Token Protection is and what it does and does not cover.
- How the two controls complement each other across four documented threat scenarios.
- The client matrix for Token Protection in the Office 365 bundle as of 2026.
- Replay-resistance trade-offs and the coverage gaps that persist at full enforcement.
- Recommended enforcement sequencing for this baseline.
- The 14-day operational soak procedure for CA-SIG007.
- Coverage seams that remain even when both controls are fully enforced.

---

## 2. Continuous Access Evaluation (CAE)

### 2.1 What CAE is

Continuous Access Evaluation replaces the standard Microsoft Entra token lifetime model with near-instant revocation for a defined set of services and event types. Under the standard token model, an access token is valid for approximately 60 minutes from the time it was issued. A revocation event — password change, account disable, MFA registration change — does not take effect for the current session until the existing token expires and the client requests a new one. The attacker or compromised session has up to 60 minutes of continued access even after a remediation action has been taken.

CAE breaks this model. When a CAE-aware service receives a token and a revocation event has occurred for the token's subject, the service issues a claims challenge back to the client: a 401 HTTP response with a `WWW-Authenticate: Bearer` header containing a `claims` parameter. The claims challenge instructs the client to return to Microsoft Entra ID and obtain a new token with the required claims. If the revocation condition is still in effect, the new token is denied. The effective revocation window shrinks from up to 60 minutes to seconds — the time it takes for the event to propagate from the Entra ID event publisher to the service endpoint.

### 2.2 CAE signals

The following events trigger a CAE revocation challenge when the client is connected to a CAE-aware service:

| Signal | Description |
|---|---|
| Account disabled or deleted | The user account has been disabled or removed in Entra ID. |
| Password change or reset | The user's password was changed by the user or by an admin. |
| MFA registration change | A new MFA method was added to or an existing method removed from the user's security info. |
| Group membership change | The user was added to or removed from a group that is in scope of an evaluated Conditional Access policy. |
| Location change | Sign-in activity is detected from a country or IP range substantially different from the previous session, triggering a location-based CAE challenge. |
| Conditional Access policy change | A policy covering the user's session was enabled, modified, or deleted in a way that changes the access decision for the session. |
| Risky sign-in detected | Microsoft Identity Protection raises a risk signal for the user's current session. |

**Critical event flow:**

1. A CAE-aware service — Exchange Online, SharePoint Online, Teams — caches the access token for the user's current session.
2. A revocation-triggering event occurs in Entra ID (password change, account disable, risk detection).
3. Entra ID propagates the event to all subscribed CAE-aware services for that user.
4. On the next API request from the client to the service, the service issues a 401 with a claims challenge header.
5. A CAE-capable client receives the 401, parses the `claims` parameter from the `WWW-Authenticate` header, and initiates a new token request to Entra ID, presenting the claims requirement.
6. Entra ID evaluates the new token request against the current policy state. If the revocation condition is still in effect (account still disabled, password not yet changed by user, risk not yet dismissed), the new token request is denied and the client session ends.

If the client is not CAE-capable, it does not understand the 401 claims challenge format. It falls back to the standard token lifetime model. The revocation event takes effect when the existing token expires, which may be up to 60 minutes later.

### 2.3 CAE-aware services (as of May 2026)

| Service | CAE support |
|---|---|
| Exchange Online | Yes — including Outlook rich client and Outlook on the web |
| SharePoint Online | Yes — including OneDrive for Business |
| Microsoft Teams | Yes — desktop and web clients |
| Microsoft Graph | Yes — for a defined subset of endpoints |
| Office.com | Yes |
| Outlook.com | Yes |

Services outside this set continue to use the standard token lifetime model regardless of whether CAE is configured. Tokens issued to non-CAE services are not subject to event-driven revocation.

### 2.4 Client requirements for CAE

CAE requires that the client application implements claims-challenge handling: the ability to receive a 401 with a `claims` header, parse the claims requirement, and initiate a new token request with the encoded claims. Clients that do not implement this fall back to the standard token lifetime silently — there is no error; the client simply ignores the challenge header and eventually re-authenticates when its cached token expires.

Modern Microsoft 365 clients support claims-challenge handling:

- Microsoft 365 Apps for Enterprise (Office builds from 2021 onwards)
- New Outlook for Windows (replacing the classic Win32 Outlook)
- New Teams desktop for Windows
- Microsoft Graph SDK 5.0 and later
- Edge and Chrome via the Windows Authentication Manager (WAM) broker

Older clients, third-party mail clients using IMAP or Exchange ActiveSync, and most automation frameworks that call Microsoft Graph directly without using an official SDK do not implement claims-challenge handling. These clients fall back to the standard token lifetime model.

### 2.5 What CAE does not cover

**Tokens already redeemed before the event.** If an attacker redeems a stolen token and establishes a downstream application session before the revocation event propagates, the established session may persist. CAE revokes the token; it does not guarantee that all derived sessions created before the revocation event are immediately terminated.

**Pre-event token theft with immediate redemption.** If the stolen token is presented within seconds of theft — before any revocation event propagates — CAE provides no protection for that specific redemption attempt. The protection window is bounded by the propagation delay.

**Out-of-CAE-scope services.** Applications outside the CAE-aware service set listed in Section 2.3 operate on the standard 60-minute token lifetime. A token stolen for a non-CAE service is valid for up to 60 minutes with no event-driven revocation path.

**Exfiltration without a triggering event.** Infostealer exfiltration does not itself trigger a CAE event. The stolen token is valid until some independent event — password change, risk detection, admin-initiated revocation — triggers a CAE revocation challenge. In a low-visibility environment where the infostealer goes undetected and no other events occur, the stolen token remains valid for its full lifetime.

**Reference:** Microsoft Learn. [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation).

---

## 3. Token Protection

### 3.1 What Token Protection is

Token Protection cryptographically binds the refresh token and the Primary Refresh Token (PRT) to the TPM-protected private key on the device that originally received and stored the token. The binding is established at token issuance time: when the client authenticates and receives a new token, the token is cryptographically signed against the TPM-resident key. At token redemption time — when the client presents the refresh token to exchange it for a new access token — the Microsoft Entra token endpoint validates that the incoming token is signed by the key that matches the record for the registered device.

A token that has been exfiltrated from the issuing device and presented from a different device will fail the signature validation. The attacker's infrastructure does not have the device's TPM private key. The redemption is rejected. The token is structurally intact and would pass every other validation check (audience, expiry, claims) — only the device-binding signature validation fails.

Token Protection is the only control in the v1.3 baseline that operates at token-redemption time rather than at sign-in time. Grant controls and session controls such as MFA, device compliance, and sign-in frequency are evaluated at sign-in. Token Protection's enforcement is deferred to every subsequent token redemption.

### 3.2 Scope as of v1.3

Token Protection in the v1.3 baseline is constrained to a specific intersection of conditions:

| Dimension | Constraint in v1.3 |
|---|---|
| Platform | Windows only. TPM-based token binding is not yet supported on macOS, iOS, Android, or Linux as of May 2026. |
| Application scope | Office 365 application bundle (Exchange Online, SharePoint Online, Teams, and other apps in the Office365 application group). |
| Authentication path | Modern authentication only. Legacy authentication paths do not carry the TPM binding mechanism. |
| Client requirements | Specific client versions that support token binding via the Windows Authentication Manager. See Section 5. |
| Policy scope | Internal persona. CA-SIG007 targets `CA-Persona-InternalUsers` and excludes EmergencyAccess, WorkloadIdentities, and ServiceAccounts. |

The v1.3 baseline implements Token Protection via CA-SIG007-Internal-TokenProtection. The scope is deliberately narrow: it targets the highest-value combination of identity class (Internal users), platform (Windows with TPM), and application sensitivity (Office 365 suite where the token-theft surface is largest).

### 3.3 Session control mechanism

Token Protection is enforced via the `sessionControls.secureSignInSession.isEnabled: true` property on a Conditional Access policy. This is not a grant control. It does not present a challenge to the user, require additional authentication, or produce a visible prompt. It is a session-level annotation on the token that instructs the token endpoint to enforce device-binding validation on every redemption of that token.

The enforcement point is token redemption, not sign-in time. This distinction has operational consequences:

- Users with tokens in flight when CA-SIG007 moves to enforcement are not immediately affected. Their existing tokens are not retroactively bound. The binding applies to new token issuances after the policy enters enforcement.
- A user on a non-supporting client version (see Section 5) may experience a session break when their current token expires and a new bound token is requested, because the non-supporting client cannot satisfy the binding requirement.
- The policy is applied silently on supporting clients. Users do not see a new prompt.

### 3.4 What Token Protection does not cover

**Full endpoint compromise.** Token Protection binds the token to the specific device's TPM key. If the attacker compromises the issuing device itself — via remote code execution, kernel-level malware, or physical access — they can operate from that device or extract the TPM-protected material via platform-level attacks. The device-binding guarantee depends on the device not being compromised. Device-level endpoint protection (Microsoft Defender for Endpoint, Intune compliance policy enforcing device health attestation) is the compensating control for full-device compromise.

**Pre-redemption capture and immediate same-device replay.** If the attacker captures a token before the binding is established, or operates on the issuing device at the time of capture, the binding mechanism either does not apply or can be satisfied from the compromised device.

**Non-Windows platforms.** macOS, iOS, Android, and Linux clients cannot participate in TPM-based token binding as of May 2026. Tokens issued for users on these platforms are not device-bound under the v1.3 baseline, regardless of CA-SIG007 being enforced.

**Applications outside the Office 365 bundle.** Refresh tokens issued for applications not included in the `Office365` application group are not bound by CA-SIG007. Tokens for custom registered applications, third-party SaaS, or Microsoft Graph applications outside the bundle scope are out of scope.

**Legacy auth paths.** Clients authenticating via legacy protocols (Exchange ActiveSync with basic auth, IMAP, POP3, SMTP AUTH) do not participate in the token binding mechanism. CA-COV001 blocking legacy auth is the prerequisite that closes this bypass path.

**Tokens issued before enforcement.** Tokens in flight when CA-SIG007 moves from report-only to enforcement are not retroactively bound. The binding applies to token issuances after enforcement.

**Reference:** Microsoft Learn. [Token Protection in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection).

---

## 4. How CAE and Token Protection Layer

### 4.1 The complementary model

CAE and Token Protection address different halves of the post-MFA token-theft attack surface. They are not redundant. They are structurally complementary.

- **CAE** responds to events that warrant revocation. It answers the question: "Should this user's token still be valid, given what has happened to the account since the token was issued?" CAE requires a triggering event — something must change in the account state to initiate a revocation.

- **Token Protection** prevents stolen tokens from being redeemed on a different device. It answers the question: "Is this token being presented from the specific device that originally received it?" Token Protection does not require any event. It enforces device binding on every redemption, regardless of whether the account state has changed.

The gap each control leaves is exactly what the other control addresses:

| Coverage dimension | CAE | Token Protection |
|---|---|---|
| Account state has changed (password reset, account disabled, risk detected) | Covered — revokes within seconds | Not applicable |
| Token stolen but no account state change has occurred | Not covered — no event to trigger revocation | Covered — redemption fails without device key |
| Short attack window before event propagation | Partial — vulnerable to immediate redemption | Covered — binding enforced at every redemption |
| Non-CAE services within token lifetime | Not covered | Covered if within Office365 bundle scope |

### 4.2 Threat scenarios

#### Scenario A: Account compromise, admin-triggered password reset

An attacker obtains the user's credentials and signs in from an anomalous location. Identity Protection raises a risk signal and the security team resets the user's password.

- **CAE response:** The password reset triggers a revocation event. Entra ID propagates the event to Exchange Online, SharePoint Online, and Teams. Both the attacker's active session and the legitimate user's active sessions receive claims challenges. The attacker cannot satisfy the re-authentication because the new password is not known to them. The session ends within seconds of the password reset.
- **Token Protection response:** Not directly applicable to this scenario. The attacker authenticated with the user's actual credentials and received tokens legitimately issued to the attacker's device (or to the victim's device if the attacker used phishing to initiate the session). Token Protection validates the issuing device; it cannot distinguish a token issued through phishing from a legitimately issued token.
- **Outcome:** CAE provides the revocation. Token Protection is not relevant to this scenario.

#### Scenario B: AiTM phishing captures a session token post-MFA

A user authenticates through an AiTM phishing proxy. The user completes MFA normally. The proxy captures the resulting session token. The attacker presents the captured token to Exchange Online from their own infrastructure. No password reset or account state change has occurred.

- **CAE response:** No revocation event has occurred. The account is active, the password is unchanged, the MFA method is unchanged. There is nothing for CAE to revoke. The attacker's session proceeds through CAE without interruption.
- **Token Protection response:** The token was originally issued to the victim's Windows device with TPM binding. When the attacker attempts to redeem the token from their device, the token endpoint validates the device-binding signature. The attacker's device does not have the victim's TPM key. The redemption is rejected. The attacker cannot use the captured token.
- **Outcome:** Token Protection provides the protection. CAE has no applicable signal until a subsequent event occurs.

#### Scenario C: Infostealer exfiltrates refresh tokens from the browser cache

An infostealer executes on the victim's Windows device, extracts the refresh token from the browser's token cache, and transmits it to the attacker's infrastructure. The attacker attempts to redeem the refresh token against Microsoft Graph to obtain a new access token for Exchange Online.

- **CAE response:** No revocation event has occurred at the time of the initial redemption attempt. The account is active. If the attacker's redemption attempt generates an anomalous sign-in signal (unusual IP, device, location), Identity Protection may raise a risk signal after the fact, which would then trigger a CAE revocation. However, the initial redemption attempt is not blocked by CAE.
- **Token Protection response:** The refresh token carries TPM binding from the issuing Windows device. The attacker's infrastructure does not have the victim device's TPM private key. The redemption attempt fails signature validation at the token endpoint. The attacker cannot obtain a new access token from the stolen refresh token.
- **Outcome:** Token Protection provides immediate protection at the first redemption attempt. CAE provides a secondary defense if the attacker's activity generates risk signals.

#### Scenario D: Stolen token presented from a different Windows device

A rarer scenario: the attacker has compromised a Windows device and attempts to replay a stolen token from a separate Windows device that they also control, hoping that the same platform class bypasses the binding check.

- **CAE response:** No revocation event; no protection.
- **Token Protection response:** Token Protection binds to the cryptographic identity of the specific TPM chip on the specific issuing device — not to the Windows platform class. A different Windows device has a different TPM and therefore a different key. The redemption from the attacker's Windows device fails signature validation exactly as it would from any non-Windows device.
- **Outcome:** Token Protection provides the protection. Platform-class matching is not sufficient to bypass the device-specific key binding.

### 4.3 Why not just one or the other

**Token Protection alone** covers stolen-token scenarios but cannot respond to account state changes. If the attacker authenticates with the user's actual credentials (password spray, credential stuffing, brute force), no token theft has occurred. The tokens are legitimately issued to the attacker's session. Token Protection does not help. Additionally, Token Protection's v1.3 scope is narrow: Windows only, Office 365 only, modern auth only. A significant fraction of the attack surface (macOS users, mobile users, legacy auth clients, non-Office 365 applications) falls outside the coverage perimeter.

**CAE alone** covers account state changes but provides no protection for token theft when the account state has not changed and no event has triggered revocation. The stolen token is valid until something external happens to the account. For an infostealer that operates silently and never triggers a risk signal, a stolen refresh token could remain valid and usable for its full lifetime (up to 90 days under the default refresh token policy) with no CAE revocation.

The v1.3 baseline includes both controls because each compensates for the exact gap that the other leaves open. The combination does not achieve 100% coverage — Section 9 documents the seams that remain — but it closes the two largest and most practically exploited gaps in the post-MFA token-theft surface.

---

## 5. Client Matrix for Token Protection (as of 2026)

The following table documents the Token Protection client requirements for each service in the Office 365 bundle. Version requirements evolve as Microsoft ships new client releases. The versions below reflect Microsoft's published requirements as of May 2026. Adopters must verify minimum version requirements against current Microsoft Learn documentation at deployment time.

| Service | Client | Minimum version (as of 2026) | Non-supporting client behavior |
|---|---|---|---|
| Exchange Online | Outlook for Windows (new Outlook) | 1.2024.0316.0 or later | Falls back to standard unbound token; if policy is in enforcement with blocking enabled, the session is rejected. |
| Exchange Online | Outlook on the web | Microsoft Edge 116 or later, Chrome 116 or later | Browser-side enforcement via Windows Authentication Manager (WAM). |
| SharePoint Online | OneDrive Sync Client | 23.066.0316.0001 or later | Falls back to standard token; non-supporting sync client versions are blocked on enforcement. |
| SharePoint Online | SharePoint in browser | Microsoft Edge 116 or later, Chrome 116 or later | Browser-side enforcement via WAM. |
| Teams | New Teams desktop (Windows) | 24.x or later | Falls back; classic Teams for Windows is retired and does not support token binding. |
| Teams | Teams in browser | Microsoft Edge 116 or later, Chrome 116 or later | Browser-side enforcement via WAM. |
| Teams | Teams mobile (iOS, Android) | Not supported in v1.3 | Out of scope for v1.3 Token Protection. These platforms are excluded at the `includePlatforms: ["windows"]` condition. |

**Notes on reading this table:**

**Browser enforcement via WAM.** Browser-side Token Protection (the Edge and Chrome rows) does not enforce binding inside the browser itself. The enforcement happens via the Windows Authentication Manager broker, which runs on the Windows device alongside the browser. The browser communicates with WAM to satisfy the device-binding requirement during token operations. This means that browser-based access to Exchange Online, SharePoint, and Teams on Windows benefits from Token Protection via WAM even though the browser itself is not the binding point.

**Classic Teams retirement.** Classic Teams for Windows was retired by Microsoft. The Teams row reflects new Teams only. Tenants with users still on classic Teams cannot satisfy Token Protection for Teams sessions from those clients.

**OneDrive Sync vs. browser SharePoint.** The OneDrive Sync Client and browser-based SharePoint access are distinct paths with distinct version requirements. Both must be inventoried during the pre-enforcement soak.

**Version requirements move.** The version numbers in this table will change as Microsoft ships new client releases and updates the Token Protection prerequisites. Before enforcing CA-SIG007 in any tenant, verify the current minimum versions against Microsoft Learn at the time of deployment.

---

## 6. Replay-Resistance Trade-offs

### 6.1 Where Token Protection is insufficient

**Full endpoint compromise.** Token Protection's binding guarantee depends on the TPM private key being inaccessible to the attacker. If the attacker has compromised the issuing device at a level that allows operation from that device (remote code execution, an active malicious agent running on the endpoint), they can satisfy the device-binding requirement by simply using the compromised device to redeem tokens. The TPM key is present on the device; the signature validation succeeds. Token Protection provides no protection in the full-device-compromise scenario. Endpoint detection and response (Microsoft Defender for Endpoint) and device compliance enforcement (Intune) are the compensating controls.

**Non-Windows platforms.** Tokens issued to macOS, iOS, Android, and Linux clients are not subject to TPM binding under v1.3. An infostealer running on a macOS endpoint can exfiltrate and replay Exchange Online or SharePoint tokens without any Token Protection barrier. This represents a significant gap for organizations with a mixed-platform workforce. The gap remains until Microsoft ships TPM-equivalent token binding for non-Windows platforms, which is a roadmap item outside the v1.3 scope.

**Applications outside the Office 365 bundle.** CA-SIG007 scopes to `includeApplications: ["Office365"]`. Tokens issued for registered applications outside that bundle are not bound. An attacker targeting a custom line-of-business application or a third-party SaaS application registered in the tenant is outside the Token Protection perimeter.

**Pre-enforcement tokens.** Tokens in flight when CA-SIG007 is promoted to enforcement are not retroactively bound. The standard refresh token lifetime is 90 days under the default Entra ID token policy (subject to organizational override). Operators who are concerned about the pre-enforcement window can coordinate a tenant-wide refresh token revocation at enforcement time, which forces all users to re-authenticate and receive new bound tokens.

### 6.2 Where CAE is insufficient

**Short attack window before the first revocation event.** The stolen token is valid from the moment of theft until the first CAE-triggering event occurs and propagates. For an infostealer that exfiltrates tokens, reports them silently to a threat actor, and then is detected and the password is reset, the window between theft and revocation may be hours, days, or longer. During that window, the stolen token is fully valid from the CAE perspective.

**No triggering event.** CAE is reactive. If the threat actor uses a stolen token but the underlying account never triggers a revocation event, CAE never fires. A low-volume attacker who uses stolen tokens sparingly, from IPs that do not trigger Identity Protection risk signals, and never causes the account password to be reset, can use the token for its full lifetime with no CAE intervention.

**Session state after revocation.** CAE revokes the token. However, the downstream session state — an Outlook on the Web session cookie, a Teams client session, a cached SharePoint authentication context — may persist briefly after the token revocation, depending on how the application manages its own session layer. CAE does not guarantee immediate termination of all application-level sessions; it guarantees that the next token redemption attempt fails.

**Non-CAE services during the token lifetime window.** Applications outside the CAE-aware service set (Section 2.3) are not notified of revocation events. A stolen token for a non-CAE service remains valid for up to 60 minutes after any revocation action, regardless of CAE configuration.

### 6.3 Where both controls are insufficient

**Legacy authentication not yet blocked.** Legacy auth clients (Exchange ActiveSync with basic auth, IMAP, POP3, SMTP AUTH) cannot carry TPM binding and do not implement the CAE claims-challenge protocol. If CA-COV001-AllUsers-BlockLegacyAuth has not yet been enforced, legacy auth clients bypass both controls entirely. This is not a gap in CAE or Token Protection — it is a prerequisite enforcement gap. The recommended layering order in Section 7 addresses this explicitly.

**Non-supporting client versions in the Internal persona.** A user whose Outlook for Windows build is older than the Token Protection minimum version, and whose client predates CAE support, benefits from neither control. The operational soak procedure in Section 8 addresses client inventory before enforcement.

**Tokens issued before CA-SIG007 enforcement.** Tokens in flight at enforcement time are neither bound by Token Protection nor subject to any new revocation event from the enforcement action itself. The existing tokens remain valid until they expire or are explicitly revoked. New tokens issued after enforcement will be bound.

**Fail-open CAE configuration.** If `disableResilienceDefaults` is left at its default value (`false`), the tenant is in CAE fail-open mode: when CAE propagation fails due to a service outage or delay, the system falls back to the standard 60-minute token lifetime rather than denying access. During a CAE outage window, the revocation guarantee is suspended. Operators who set `disableResilienceDefaults: true` on their Conditional Access policies accept access interruption during CAE outages in exchange for eliminating the fallback window.

---

## 7. Recommended Layering Order

The v1.3 baseline rollout sequence (documented in `Design/POLICY-DESIGN.md` Section 5) places the relevant policies at specific positions. The layering order below follows that sequence and explains the dependencies.

### Step 1 — Enforce CA-COV001-AllUsers-BlockLegacyAuth (rollout position 1)

This is the hard prerequisite for everything in this layering. Legacy authentication protocols bypass both CAE and Token Protection. An active legacy auth path renders both controls partially inoperative. CA-COV001 must be in enforcement — not just report-only — before the Token Protection soak has any meaningful value.

Validation: Run `Get-CABaselineImpact.ps1 -PolicyNameFilter CA-COV001 -DaysBack 14`. The would-have-blocked count must be zero before promoting CA-COV001 to enforcement.

### Step 2 — Confirm CAE is active (not a CA policy — tenant configuration)

Modern Microsoft 365 tenants have CAE enabled by default via the global CA policies service. Operators should verify two things:

1. That no legacy or custom Conditional Access policies are configured with `sessionControls.disableResilienceDefaults: true` in an unexpected place, which would suppress CAE for those policies.
2. Whether to explicitly opt into CAE strict enforcement by setting `sessionControls.disableResilienceDefaults: true` on the existing policies. Strict enforcement means that if CAE event propagation fails (service outage), access is denied rather than falling back to the 60-minute token lifetime. This is a fail-closed posture. The default is fail-open.

CAE strict enforcement is not a standalone policy template in the v1.3 baseline. It is a session control property added to existing policies. A v1.4 candidate exists for a dedicated CAE enforcement policy template if Microsoft introduces a standalone Conditional Access control surface for this setting.

### Step 3 — Soak CA-SIG007 in report-only for 14 days (rollout position 19)

Deploy CA-SIG007-Internal-TokenProtection in `enabledForReportingButNotEnforced` state (the default deployment state from `Deploy-CABaseline.ps1`). The 14-day window has a specific purpose: inventorying clients that cannot yet satisfy Token Protection. See Section 8 for the full soak procedure.

### Step 4 — Promote CA-SIG007 to enforcement

After the soak window closes and the non-supporting-client inventory is at zero or within the organization's accepted residual, promote CA-SIG007 from report-only to enforcement:

```powershell
.\Scripts\Deploy-CABaseline.ps1 -Enforce -PolicyNameFilter "CA-SIG007-Internal-TokenProtection"
```

Promote one policy at a time. Do not batch CA-SIG007 enforcement with other policies.

### Step 5 — Monitor for platform coverage expansion (v1.4 and later)

Microsoft is shipping Token Protection support for macOS, iOS, and Android on an evolving timeline. The v1.3 baseline does not include platform expansion beyond Windows. When Microsoft ships macOS support, extend the `includePlatforms` condition on CA-SIG007 to include `macOS`. Monitor Microsoft Learn and the Entra ID release notes for platform support announcements. This is captured as a v1.4 roadmap candidate.

---

## 8. Operational Soak Procedure for CA-SIG007

### 8.1 Pre-soak checklist

Before beginning the 14-day soak, confirm the following conditions are met:

- [ ] CA-COV001-AllUsers-BlockLegacyAuth is in enforcement state (not report-only). Token Protection soak data is not meaningful if legacy auth remains as a bypass path.
- [ ] CAE is confirmed active for the tenant. Review the Entra admin center sign-in logs for the CAE-specific detail columns (`isCaeMandated`, `claimsInAccessToken`).
- [ ] CA-Persona-InternalUsers group membership is current. CA-SIG007 targets this group. Stale membership skews the soak data in both directions (missing users who should be inventoried, including users who are not in scope).
- [ ] CA-SIG007 is deployed in report-only state via `Deploy-CABaseline.ps1`. Confirm the policy exists in the tenant in `enabledForReportingButNotEnforced` state.
- [ ] Windows TPM availability has been reviewed. CA-SIG007 requires TPM for token binding. Intune device compliance reporting can surface Windows devices without TPM. Those devices will not support Token Protection regardless of client version.

### 8.2 Day 0

Deploy CA-SIG007 in report-only if not already deployed:

```powershell
.\Scripts\Deploy-CABaseline.ps1
```

Establish the Day 0 baseline:

```powershell
.\Scripts\Get-CABaselineImpact.ps1 -PolicyName "CA-SIG007-Internal-TokenProtection" -DaysBack 1
```

Note the initial would-have-blocked count. Any non-zero count on Day 0 identifies users with clients that cannot yet satisfy Token Protection. Export the full sign-in log for the past 14 days filtered to the Internal persona on the Windows platform:

```powershell
# Via Microsoft Graph sign-in log API
# Filter: userDisplayName in CA-Persona-InternalUsers, deviceDetail.operatingSystem startsWith "Windows"
# Columns: userPrincipalName, deviceDetail.browser, deviceDetail.operatingSystem, conditionalAccessStatus
```

Use this export to build the client version inventory that will guide the upgrade work over the soak window.

### 8.3 Days 1 through 13

Review sign-in logs at least twice per week (daily monitoring is recommended) for:

- CA-SIG007 appearing in the `Conditional Access` policy column with `reportOnlyInterrupted` status. These are users who would be blocked if CA-SIG007 were enforced today.
- The `ClientAppUsed` and `DeviceDetail` columns to identify specific client versions for users in the would-have-blocked set.

For each user in the would-have-blocked set, work with the endpoint management team to:

- Update Outlook for Windows (new Outlook) to version 1.2024.0316.0 or later.
- Update the OneDrive Sync Client to version 23.066.0316.0001 or later.
- Migrate any remaining classic Teams users to new Teams 24.x or later.
- Confirm browser access is via Edge 116+ or Chrome 116+ for browser-based Exchange Online, SharePoint, and Teams sessions.

Re-run the impact script weekly to track progress:

```powershell
.\Scripts\Get-CABaselineImpact.ps1 -PolicyName "CA-SIG007-Internal-TokenProtection" -DaysBack 7
```

Track the week-over-week reduction in the would-have-blocked count. A flat or non-decreasing count after week 1 indicates that client update deployment is stalled and needs escalation before the enforcement decision.

### 8.4 Day 14 — Enforcement decision

At the end of the 14-day soak window, run the final impact assessment:

```powershell
.\Scripts\Get-CABaselineImpact.ps1 -PolicyName "CA-SIG007-Internal-TokenProtection" -DaysBack 14
```

**If the would-have-blocked count is zero:** Proceed to enforcement.

**If the would-have-blocked count is non-zero:** Decision point — extend the soak or accept the residual as an operational risk acceptance. Extending the soak is recommended if the non-zero count represents users who are in active remediation (client update pending, device enrollment in progress). Accepting the residual is appropriate only if the remaining users are known, documented, and their devices are covered by a compensating control.

To promote to enforcement once the decision is made:

```powershell
.\Scripts\Deploy-CABaseline.ps1 -Enforce -PolicyNameFilter "CA-SIG007-Internal-TokenProtection"
```

Monitor sign-in logs for 48 hours post-enforcement. Any unexpected blocks in the first 48 hours indicate users who were missed in the soak inventory (new device enrolled after the soak window opened, onboarded user not yet in the Internal persona group, client version rollback triggered by an automated update tool).

### 8.5 Post-enforcement monitoring cadence

| Frequency | Action |
|---|---|
| Weekly (first 4 weeks) | Review CA-SIG007 blocks in the sign-in log for unexpected new blocks. |
| Monthly (ongoing) | Review client version distribution against current Microsoft Learn minimum requirements. Requirements move with Microsoft client releases. |
| On client major-version updates | Re-run the impact script against the new client version before broad deployment to confirm Token Protection compatibility is preserved. |
| On new user onboarding | Confirm new devices satisfy TPM and client version requirements before the user account is added to CA-Persona-InternalUsers. |

---

## 9. Coverage Seams Documented

The following coverage gaps persist at full enforcement of the v1.3 layering: CA-COV001 enforced, CAE active, CA-SIG007 enforced. Operators should document these seams in their risk register and identify compensating controls where applicable.

**Full-device endpoint compromise.** Token Protection binds tokens to the issuing device's TPM key. An attacker who has compromised the endpoint and can operate from that device satisfies the binding requirement. Endpoint detection and response (Microsoft Defender for Endpoint), device health attestation (Intune), and CA-COV008-Internal-RequireCompliantDeviceOnDesktops (which enforces Intune compliance as a Conditional Access grant control) are the compensating controls. CA-SIG007 and CA-COV008 should be co-enforced for the Internal persona on Windows.

**Non-Windows platforms.** macOS, iOS, Android, and Linux Internal users are not protected by Token Protection under v1.3. Their tokens can be exfiltrated and replayed without device-binding enforcement. CAE remains active for these users, but the no-event scenario leaves the stolen-token window open. This gap remains until Microsoft ships Token Protection for non-Windows platforms.

**Applications outside the Office 365 bundle.** Refresh tokens issued for applications not in the `Office365` bundle are not bound. An attacker targeting custom registered applications or third-party SaaS registered in the tenant operates outside the Token Protection perimeter.

**Pre-enforcement tokens in flight.** Tokens issued before CA-SIG007 moved to enforcement are not retroactively bound. The standard refresh token lifetime (90 days by default under Entra ID's configurable token lifetime policy) defines the maximum duration of this window. Operators concerned about this window can issue a coordinated refresh token revocation at enforcement time to force re-authentication and re-issuance of bound tokens for all Internal users.

**Legacy authentication if CA-COV001 is not enforced.** Any tenant that has not fully enforced CA-COV001 retains a bypass path where neither control applies. This seam is closed by CA-COV001 enforcement, not by CA-SIG007 or CAE configuration.

**CAE propagation delay window.** Even with CAE active, the revocation propagation from Entra ID to a CAE-aware service is not instantaneous. In normal operations, propagation is measured in seconds. During service incidents or high-load conditions, propagation may lag. The fail-open CAE default (`disableResilienceDefaults: false`) means that during outages, the effective revocation window reverts to up to 60 minutes. Setting `disableResilienceDefaults: true` on Conditional Access policies eliminates the fallback window at the cost of access denial during CAE outages.

---

## 10. Cross-References

### Direct policy pairing

**CA-SIG007-Internal-TokenProtection paired contract.** `Policies/CA-SIG007-Internal-TokenProtection.md` covers the post-MFA token-replay threat surface, the coverage seams specific to CA-SIG007, and the validation procedure for the policy in isolation. This design document extends that treatment with the full CAE and Token Protection layering analysis, the detailed client matrix, replay-resistance trade-offs, and the end-to-end enforcement sequencing guidance.

**POLICY-DESIGN.md Section 6.21.** The per-policy design specification for CA-SIG007-Internal-TokenProtection covers scope, session control, license requirements, exclusion rationale, and rollout position. The per-policy spec is the authoritative definition of what the policy does. This document explains why it is layered with CAE and how to sequence and soak it correctly.

### Prerequisite policy

**CA-COV001-AllUsers-BlockLegacyAuth.** The per-policy spec is in `Design/POLICY-DESIGN.md` Section 6.1. Blocking legacy authentication is the unconditional prerequisite for the Token Protection and CAE layering documented here. A tenant where legacy authentication is still permitted has bypass paths that invalidate both controls.

### Related design documents

**Design/AGENTS-PERSONA-MODEL.md.** Covers the Microsoft Agent ID persona, which operates under a different authentication flow and token model. Agent ID tokens are out of scope for the CAE and Token Protection layering documented here.

**Design/POLICY-DESIGN.md Section 1.3 (Layered signals).** The design principle that this layering implements. Token Protection and CAE are the primary example of the layered-signals principle applied to the token-theft attack surface.

### v1.4 roadmap candidates related to this document

The following items are captured in the v1.4 candidates list in the framework README:

- A dedicated CAE strict-enforcement policy template, if Microsoft introduces a Conditional Access control surface for `sessionControls.disableResilienceDefaults` as a standalone policy setting rather than a per-policy session control property.
- Token Protection policy extension to macOS (and subsequently iOS and Android) when Microsoft ships TPM-equivalent device-binding support for those platforms.
