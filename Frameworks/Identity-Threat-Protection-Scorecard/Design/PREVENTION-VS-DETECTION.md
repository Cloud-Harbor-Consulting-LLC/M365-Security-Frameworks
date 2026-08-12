# Prevention vs Detection

Where Conditional Access's job ends and detection's job begins, and why this framework is not fully automated.

**Companion reading:** Part 3 of The Security Bridge™ Series: Identity Threat Protection in Microsoft 365. See the framework README for links.

---

## The boundary

Conditional Access is an authorisation gate. It evaluates a set of conditions at the moment access is requested and returns an allow, a block, or a requirement to satisfy something further. That is the entire scope of what it does, and within that scope it is very effective.

The boundary is a matter of timing rather than capability:

| | Conditional Access | Identity detection |
|---|---|---|
| Evaluates | At the access request | Continuously, including after access is granted |
| Acts on | Conditions known at that moment | Behaviour observed over time |
| Fails when | The condition set does not describe the attack | The signal is not collected, or nobody acts on it |
| Answers | "Should this request be allowed?" | "Was that request what it appeared to be?" |

A policy cannot evaluate a condition it was not written to consider, and it cannot re-evaluate a session it already permitted unless it is explicitly configured to do so. Both limits are structural, not defects.

---

## Three gaps that Prevention cannot close

**The session that was legitimate at sign-in.** Conditional Access grants access to a session that satisfied every condition. If the token is stolen afterwards, the authentication decision was correct and is now being used by someone else. Detection is the only control that observes what the session does next.

**The identity that is not a user.** Service principals and managed identities authenticate without MFA, without a device, and often from anywhere. Conditional Access support for workload identities exists but is narrower than for users. Most of what a workload identity does after authenticating is observable only through detection.

**The behaviour that is individually permitted.** Enumerating a directory, reading mail, enrolling an authentication method — each is a legitimate operation that a policy will allow. The sequence is the attack, and no single gate decision sees a sequence.

Each gap maps to an attack path in `IDENTITY-ATTACK-PATHS.md`: token theft is Path 4, workload identity is Path 3, and post-authentication sequencing runs through Paths 1, 2, and 5.

---

## What detection is worth only if it is healthy

Detection is bought as a license and delivered as a deployment. The gap between those two is where most tenants lose the value.

A Defender for Identity sensor that is not installed on a domain controller, or is installed and unhealthy, produces no signal from that domain controller. Nothing alerts, because the absence of a signal is not itself an event. The tenant's dashboards look calm for exactly the same reason a disconnected smoke detector does.

This is why ITPS scores Detection on deployment health — checks D-01 through D-04 read `GET /security/identities/healthIssues` — rather than on whether the product is licensed. A licensed, undeployed product scores the same as no product, because operationally it is no product.

---

## Why this framework is not fully automated

The Detection dimension has a manual component, and the Ownership dimension is entirely manual. Both are real product and domain limits rather than scoping shortcuts, and it is worth being precise about which is which.

### The Coverage and maturity page has no API

Microsoft's Defender portal includes a **Coverage and maturity** page that produces exactly the kind of composite identity coverage score this framework is built around. It is the closest first-party equivalent to an ITPS Detection score.

It is portal-only. Per [Microsoft Learn — View your identity coverage and maturity (Preview)](https://learn.microsoft.com/en-us/defender-xdr/identity-security/coverage-maturity), the documented access path is to sign in to the Microsoft Defender portal and select **Identities → Coverage and maturity**. The page's prerequisites are a Microsoft Defender for Cloud Apps or Microsoft Defender for Identity license and at least the Security Reader role. The documentation describes no Graph endpoint, no REST API, and no export path for the composite score or the tier. The feature is in Preview and is being rolled out gradually, so it may not yet be present in a given tenant.

The consequence for this framework is narrow and specific: **ITPS check D-05 is manual because the data has no programmatic surface, not because automating it was out of scope.** An operator reads the composite score and tier from the portal and records them alongside the ITPS score. If Microsoft ships an API for this, D-05 becomes automatable without any change to the scoring model.

This is a genuine product gap, and it is worth saying plainly rather than papering over: a first-party maturity score that cannot be retrieved programmatically cannot be tracked over time, cannot be diffed between assessments, and cannot appear in an automated report. Manual transcription is the only available path today.

### Ownership has no API because it is not tenant configuration

The Ownership dimension is manual for a different and more permanent reason. Who owns a control when it degrades is an organisational fact. It does not live in the tenant, so no tenant API can return it. No future Microsoft release will change this, and a framework that waited for one would simply never score the dimension.

`Examples/Ownership-Matrix-Template.md` is the instrument for scoring it.

---

## Reading a scorecard with this in mind

Two rules follow, and both are enforced by the collector rather than left to the reader:

**A high Prevention score is not a high Detection score.** They measure different halves of the problem, and the scorecard reports them separately precisely so that a strong Prevention number cannot mask an absent Detection capability. A tenant at Prevention 90 and Detection 30 is a tenant that will block the attacks it anticipated and never learn about the rest.

**A partial score is an upper bound.** An automated-only run leaves D-05 and all of Ownership unscored. The collector excludes unscored checks from the denominator rather than counting them as zero, which keeps the partial score honest — but it means the number can only move down as the manual work is completed. Never present an automated-only ITPS score as a final result.

---

*Identity Threat Protection Scorecard v0.1.0-preview — Cloud Harbor Consulting LLC*
