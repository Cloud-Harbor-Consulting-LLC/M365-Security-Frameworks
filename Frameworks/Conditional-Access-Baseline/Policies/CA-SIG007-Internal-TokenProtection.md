# CA-SIG007-Internal-TokenProtection — design and layering with CAE

This document explains the threat that `CA-SIG007-Internal-TokenProtection` addresses, how it differs from every other policy in the Conditional Access Baseline, and how Token Protection layers with Continuous Access Evaluation (CAE) to close coverage seams.

This is paired documentation for the policy template `CA-SIG007-Internal-TokenProtection.json` in the same folder. The two ship and are deployed as one unit.

---

## 1. The threat

Every other policy in the baseline evaluates at sign-in. Once the sign-in succeeds, the issued refresh token and Primary Refresh Token (PRT) are bearer tokens — anyone who possesses the token can use it from any device, until expiry or revocation.

This creates a post-MFA attack class that has grown in volume as phishing-resistant MFA reduces the value of AiTM credential capture:

- **Infostealer token theft.** Malware on a compliant device exfiltrates tokens from browser storage or the Web Account Manager (WAM) cache. The attacker replays the tokens from infrastructure of their choice.
- **AiTM token relay.** An adversary-in-the-middle proxy completes the MFA flow on behalf of the victim and captures the post-MFA session token rather than the password. Phishing-resistant credentials defeat the password-capture path but not the post-issuance token-capture path unless the token itself is bound to the originating device.
- **Cookie / token redemption replay.** A token harvested via any of the above is redeemed against the resource tenant from a different machine, geography, or device posture than the one the user signed in from.

Sign-in-time controls cannot see any of these — they have already passed.

---

## 2. What Token Protection does

Token Protection cryptographically binds the refresh token and PRT to a device-resident key (TPM-protected on supporting Windows hardware). When the token is presented for redemption:

- If the request originates from the same device that holds the binding key, the token is honored.
- If the request originates from any other device, the binding signature fails and the token is rejected.

The attacker who extracts a token cannot use it from their own infrastructure, even if the token has not yet expired and even if the user's account has not yet been disabled.

This is the only control in the baseline that operates on the redemption-time threat surface.

---

## 3. What CAE does

Continuous Access Evaluation operates on a different axis: it propagates revocation events (password change, account disable, location-policy change, token revocation, risky-user detection) to participating resource providers in near real time, replacing the up-to-one-hour token lifetime with a sub-minute reaction window.

CAE addresses the question "how fast does a revocation event invalidate an existing token." Token Protection addresses the question "can a stolen token be used at all from another device."

They are not redundant. They are layered.

---

## 4. How they layer

| Threat | Sign-in-time MFA (CA-COV002, CA-AUT003) | CAE | Token Protection |
|---|---|---|---|
| Password compromise without MFA | Blocks at sign-in | n/a | n/a |
| AiTM credential phish, weak MFA | Phishing-resistant MFA blocks at sign-in | n/a | n/a |
| AiTM session-token capture (post-MFA) | Does not see | Limits exposure window on revocation | **Blocks redemption from attacker device** |
| Infostealer extracts token from compliant device | Does not see | Limits exposure window on revocation | **Blocks redemption from attacker device** |
| Stolen token, attacker uses before revocation propagates | Does not see | Reduces propagation window to under a minute on supporting resources | **Blocks redemption from attacker device** |
| Account disabled mid-session | Does not see | **Terminates active sessions on supporting resources within ~1 minute** | Allows redemption from the original device until token expiry |
| Risky-user detection during active session | Does not see | **Terminates active sessions on supporting resources within ~1 minute** | Allows redemption from the original device until token expiry |

The two controls cover different cells. Deploying only CAE leaves the post-MFA token-replay class open. Deploying only Token Protection leaves the mid-session revocation propagation slow on resources that haven't already enforced CAE.

---

## 5. Coverage seams

Token Protection has explicit scope limits that adopters must understand before promoting to enforced:

- **Windows only.** macOS, iOS, Android, Linux do not currently issue device-bound tokens. The `CA-SIG007` policy explicitly scopes `platforms.includePlatforms=["windows"]` so non-Windows clients pass through. Adopters needing comparable coverage on macOS should track Microsoft's roadmap; until then, those platforms rely on CAE alone for the post-MFA window.
- **Exchange Online and SharePoint Online sign-in.** Current GA enforcement is on the Exchange Online and SharePoint Online sign-in paths within the Office365 application bundle. Other applications inside the bundle pass through. Microsoft expands coverage incrementally — the Office365 bundle scope in the template picks up new apps automatically.
- **Modern auth required.** Clients still on legacy authentication paths do not present bindable tokens. CA-COV001-AllUsers-BlockLegacyAuth (v1.0.0) is the prerequisite control here; legacy auth is blocked before Token Protection evaluates.
- **Client version dependency.** Token Protection requires the client to know how to present a bound token. Older Outlook builds, legacy OneDrive sync clients, and some third-party mail clients via EWS will degrade to a sign-in challenge rather than honor the bound token. The 14-day report-only soak is the inventory window for these clients.

CAE has different but overlapping scope limits. Notably:

- **Workload identities are out of scope for both controls.** CAE does not apply to workload identity tokens; Token Protection is user-scoped. The workload-identity threat surface is handled by `CA-COV010-WorkloadIdentities-TrustedLocations` (v1.3.0) on a separate code path.
- **CAE-aware resources only.** CAE propagates revocation only to resource providers that have integrated the CAE protocol (Exchange Online, SharePoint Online, Microsoft Graph, Teams). Resources outside this set continue to honor tokens until expiry.

---

## 6. Validation in report-only

- Enumerate Windows-device sign-ins to Exchange Online and SharePoint Online for the prior 14 days. Confirm the population is hybrid-joined or Entra-joined with a TPM-attested device key — the Token Protection enforcement signal requires this posture.
- Inventory non-supporting clients in the fleet: Outlook builds below the Token Protection-supporting version, OneDrive sync client builds below the supporting version, third-party mail clients via EWS or IMAP. These clients fall back to a sign-in challenge under enforcement.
- Confirm CA-COV001 (Block legacy authentication) is enforced, not just report-only — legacy auth paths bypass Token Protection by definition.
- Confirm CAE is enabled at the tenant level. Token Protection does not depend on CAE, but the layering described in section 4 assumes both are active. If CAE is disabled, the revocation-propagation row of the matrix in section 4 reverts to the up-to-one-hour token lifetime.
- Review report-only logs for `Sign-in token protection — token binding required` reasons. These are the events that would become user-visible sign-in challenges under enforcement.

---

## 7. Rollout sequence position

Token Protection is added to the rollout-sequence table as a late-sequence entry, after the risk policies (CA-SIG003 through CA-SIG005). Minimum report-only soak: 14 days, driven by the client-version inventory requirement in section 5.

This document is paired with the JSON template in `CA-SIG007-Internal-TokenProtection.json`. Both ship as one unit; the deployer treats them as a single policy artifact.
