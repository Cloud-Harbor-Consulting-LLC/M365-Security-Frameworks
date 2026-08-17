# Identity Attack Paths

The threat model behind the Identity Threat Protection Scorecard. This document explains what the 4 dimensions are defending against, and why a scorecard that measured only authentication would miss most of it.

**Companion reading:** Part 1 and Part 2 of The Security Bridge™ Series: Identity Threat Protection in Microsoft 365. See the framework README for links.

---

## The premise: authentication proves identity, not trust

A successful sign-in establishes one fact — that whoever is at the keyboard presented credentials the tenant accepted. It does not establish that the person is who the credential belongs to, that the device is healthy, that the session should have the privileges attached to it, or that the account should still exist.

Most identity security investment concentrates on the authentication moment, because that is the moment with a clear product surface: Conditional Access, MFA, authentication strength. The attack paths below all begin *after* that moment. This is the reason ITPS scores Detection, Governance, and Ownership alongside Prevention rather than treating Prevention as the whole problem.

---

## Path 1 — Credential compromise to standing privilege

The most common path, and the shortest.

1. An attacker obtains valid credentials through phishing, password spray, token theft, or a credential dump from an unrelated breach.
2. Authentication succeeds. If MFA is enforced, the attacker satisfies it via a phishing proxy, MFA fatigue, or a stolen session token, and none of those trip a policy that only evaluates at sign-in.
3. The compromised account holds a permanent, active administrative role assignment.
4. The attacker now has persistent privilege with no further exploitation required.

**Where each dimension intervenes.** Prevention makes step 2 harder through phishing-resistant authentication strength and risk-based policy. Detection surfaces the anomalous sign-in in step 2 if identity detection is deployed and healthy. Governance removes step 3 entirely: with no standing assignment, the compromised account has nothing to inherit. Ownership determines whether anyone acts on the step 2 alert.

The Governance intervention is the strongest of the four, and it is the one most tenants skip, because eliminating standing privilege is organisational work rather than a policy toggle.

---

## Path 2 — Application consent to persistent data access

1. A user grants OAuth consent to an application, either through a targeted consent-phishing lure or through routine self-service consent.
2. The application receives delegated permissions — mail, files, directory reads — that persist independently of the user's session.
3. The user later changes their password, or their session is revoked, or they leave the organisation.
4. The application's access continues, because an application's token lifecycle is not tied to the user's.

This path defeats credential-centric defences entirely. Resetting the password does not revoke the grant. Blocking the user's sign-in does not revoke the grant. Conditional Access evaluates user sign-ins, and the application is no longer signing in as the user.

**Where each dimension intervenes.** Prevention restricts who may consent and to which permission scopes. Governance recertifies existing grants and removes ones no longer justified. Detection surfaces anomalous application activity. Ownership answers the question of who reviews the OAuth grant inventory, which is a task that belongs to nobody by default.

---

## Path 3 — Workload identity as an unattended door

Service principals, managed identities, and application registrations authenticate without a human, without MFA, and frequently without expiry.

1. An application registration holds a client secret with a multi-year expiry or no expiry at all.
2. The secret is committed to a repository, embedded in a pipeline variable, or stored in a configuration file.
3. The secret is exposed — through a repository leak, an over-permissioned pipeline, or a departing contractor.
4. The attacker authenticates as the workload identity. There is no MFA to satisfy and no user to alert.

Workload identities are the clearest example of why an identity scorecard has to count non-human identities. A tenant can enforce phishing-resistant MFA on every human account and still hold a decade-old client secret with `Directory.ReadWrite.All`.

**Where each dimension intervenes.** Governance is the primary control: credential hygiene checks (ITPS check G-05) find long-lived and non-expiring secrets before an attacker does. Detection covers anomalous service principal sign-ins. Prevention applies where Conditional Access supports workload identities. Ownership matters more here than anywhere else, because workload identities are typically created by a project that has since ended and are owned, in practice, by nobody.

---

## Path 4 — Unmanaged device as a session foothold

1. A user authenticates successfully from a personal or unmanaged device.
2. The device is compromised — infostealer malware, a malicious browser extension, or simply an unpatched browser.
3. The session token is extracted from the device.
4. The attacker replays the token. The authentication already happened, so there is nothing left to challenge.

Token theft converts a device compromise into an identity compromise. The identity controls were not bypassed; they were satisfied legitimately and then the result was stolen.

**Where each dimension intervenes.** Prevention requires device compliance as a grant condition and can bind tokens to the device. Detection surfaces the replay if the sign-in pattern is anomalous. Governance is largely absent here, which is worth noting: not every path is defended by every dimension.

---

## Path 5 — Lateral movement through hybrid identity

In hybrid tenants, on-premises Active Directory and Entra ID are a single trust surface with two very different control planes.

1. An attacker compromises an on-premises account through a path that has nothing to do with the cloud tenant.
2. The account synchronises to Entra ID.
3. Cloud resources are reachable using on-premises-derived credentials.
4. Cloud-side detection sees a normal sign-in from a legitimate synchronised identity.

The reverse direction is equally viable — cloud compromise to on-premises movement through hybrid join, Entra Connect service accounts, or a password writeback path.

**Where each dimension intervenes.** Detection is the primary control, and specifically Defender for Identity sensor coverage on domain controllers. This is exactly what ITPS checks D-01 through D-04 measure: a tenant with unhealthy or undeployed sensors has no visibility into the on-premises half of its own identity surface. Ownership determines whether sensor health degradation is noticed, since an unhealthy sensor fails quietly.

---

## How the paths combine

The paths above are rarely used in isolation. A realistic intrusion chains them:

> Consent phishing (Path 2) grants an application persistent mail access. Mail access yields credentials for a service account (Path 3). The service account holds a permanent role assignment (Path 1). The role assignment enables reconnaissance of the hybrid environment (Path 5).

No single dimension interrupts that chain. Prevention does not stop Path 2's consent grant if consent is unrestricted. Detection does not help if nobody owns the alert queue. Governance would have caught the standing assignment and the stale secret, but only if a review actually ran.

This is the argument for equal weighting in `SCORING-METHODOLOGY.md`, restated as a threat model: the chain breaks at whichever link is defended, and an attacker chooses the chain that avoids your strongest dimension.

---

## What this means for scoring

Three consequences follow from the paths above, and each shaped a specific decision in the scoring methodology:

1. **Non-human identities are counted.** Path 3 is invisible to any scorecard that only measures human MFA coverage. Check G-05 exists because of it.
2. **Detection is scored on health, not licensing.** Path 5 is defeated by a deployed and healthy sensor, not by a purchased license. Checks D-01 through D-04 measure health.
3. **Ownership is a scored dimension.** Every path above includes at least one step that only fails closed if a human notices something and acts. That human has to be named somewhere.

---

*Identity Threat Protection Scorecard v0.1.1-preview — Cloud Harbor Consulting LLC*
