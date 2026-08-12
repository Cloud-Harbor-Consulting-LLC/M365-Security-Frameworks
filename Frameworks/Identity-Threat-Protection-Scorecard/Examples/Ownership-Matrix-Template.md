# Identity Control Ownership Matrix

Blank template for scoring the ITPS Ownership dimension (checks O-01 through O-06). Copy this file, fill every cell, and keep it current. This is the only artifact the Ownership dimension is scored against.

**Organization:** [Organization name]
**Last updated:** [YYYY-MM-DD]
**Maintained by:** [name, role]

---

## How to use this template

One row per control area. A row is complete when every column is filled with a specific answer.

- **Owner** and **Backup owner** must name a *role*, not a team alias and not a vacant position. "Identity Engineering" is not an owner. "Senior Identity Engineer" is.
- **Review cadence** must be a stated interval, and the interval must be one the owner has actually agreed to.
- **Last reviewed** must fall within the stated cadence. A row whose last-reviewed date is older than its cadence scores zero on check O-05 regardless of what the other columns say.
- **Escalation path** names who is contacted when the owner cannot resolve a degradation within the cadence.

---

## Prevention controls

| Control area | Owner (role) | Backup owner (role) | Review cadence | Last reviewed | Escalation path |
|---|---|---|---|---|---|
| Conditional Access policy set | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| MFA and authentication strength | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| Legacy authentication block | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| Risk-based policy enforcement state | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| Secure Score remediation backlog | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |

## Detection controls

| Control area | Owner (role) | Backup owner (role) | Review cadence | Last reviewed | Escalation path |
|---|---|---|---|---|---|
| Defender for Identity sensor health | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| Identity alert triage queue | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| Coverage and maturity score tracking | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| Detection rule tuning | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |

## Governance controls

| Control area | Owner (role) | Backup owner (role) | Review cadence | Last reviewed | Escalation path |
|---|---|---|---|---|---|
| Guest access reviews | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| Privileged role reviews | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| PIM eligible assignment hygiene | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| Standing privilege reduction | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| App registration credential expiry | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |
| Workload identity inventory | [role] | [role] | [interval] | [YYYY-MM-DD] | [role] |

---

## Scoring this matrix

| Check | Points | Earned when |
|---|---|---|
| O-01 Ownership matrix exists | 20 | This document exists and covers every control area above |
| O-02 Named owner per control area | 20 | Every Owner cell names a specific role |
| O-03 Backup owner named | 15 | Every Backup owner cell names a specific role, different from the Owner |
| O-04 Review cadence defined | 15 | Every Review cadence cell states an interval |
| O-05 Last reviewed within cadence | 15 | Every Last reviewed date falls within its row's stated cadence |
| O-06 Escalation path defined | 15 | Every Escalation path cell names who is contacted on an unresolved degradation |

Total: 100. Award points proportionally where a check is partly met — if 12 of 15 rows name an owner, O-02 earns 16 of 20.

---

## Two failure modes this template is designed to expose

**The alias owner.** Writing a team name in the Owner column feels like an answer and is not one. When a control degrades, a team does not notice; a person does. If the honest answer is that no individual is accountable, leave the cell blank and score it zero. A blank cell is useful information. A team alias is a blank cell that looks filled.

**The stale date.** A row with a named owner, a defined quarterly cadence, and a last-reviewed date from 14 months ago describes a control that is formally owned and functionally unmonitored. O-05 exists specifically to catch this, because it is the most common state of a matrix that was built once for an audit and never revisited.
