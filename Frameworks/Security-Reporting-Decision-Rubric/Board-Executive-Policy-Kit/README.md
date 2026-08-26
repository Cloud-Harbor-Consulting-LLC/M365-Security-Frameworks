# Board & Executive Policy Kit

Two templates for the moment a technical control has to survive contact with a non-technical reader. The **Policy Translation Worksheet** converts a single control — a Conditional Access policy, an Intune compliance baseline, a Purview DLP rule — into three plain-language lines an executive can act on. The **Board Posture Summary** carries the accumulated result of those decisions to a board in one page. It is built for security architects and CISOs preparing board or executive materials, and it assumes the reader already knows the controls cold and needs help with the translation, not the technology.

Neither template is a reporting framework of its own. Both route through the same 4-question decision flow in [`REPORTING-DECISION-RUBRIC.md`](../REPORTING-DECISION-RUBRIC.md) — they just answer it at different altitudes.

## How the two templates answer the same 4 questions

| | Policy Translation Worksheet | Board Posture Summary |
|---|---|---|
| **Altitude** | Per-control translation | Ongoing state |
| **Who reads it?** | Whoever the routing step lands on — CISO, exec committee, or board. The worksheet does not assume. | Board member |
| **What decision?** | Whether this control's change is worth a reader's attention, and which report it belongs in | Approve strategy, accept residual risk, fund the next cycle |
| **What cadence?** | Event-driven — run it when a control is new, changed, or newly exempted | Quarterly, or whenever the board requests a posture view |
| **What severity floor?** | Inherited from wherever it routes | Material incidents only |

The worksheet's fourth question is deliberately unanswered on the form. A control translation is not tied to an audience until the routing step in section 3 assigns one, and the same three lines land differently depending on that answer.

## How to use these together

1. **Run the new or changed control through the worksheet first.** One control, one worksheet. Produce the three lines before deciding who sees them.
2. **Route it.** Take the translation back through the 4-question flow. If it cannot name the decision its reader makes, it does not go in a report — that is a kill-list outcome, and the fix is the routing, not the wording.
3. **Roll the outcome into the next posture summary.** Controls that moved a pillar's stage belong in section 1 of the Board Posture Summary as a stage movement, with the worksheet's Line 1 supplying the narrative sentence. Controls that did not move a stage stay in the CISO monthly.

The sequence matters. A posture summary assembled without the translation step tends to report control names to an audience that cannot act on them, which fails question 2 of the rubric.

## Files in this kit

- `Policy-Translation-Worksheet.md` — per-control translation template, with worked examples for CA-COV002 (Conditional Access) and ICB-WIN001 (Intune compliance).
- `Board-Posture-Summary.md` — 1-page board posture summary across 6 pillars, using CISA ZTMM v2.0 stage language.

`Board-Posture-Summary.md` is a copy, kept here so the kit can be taken as a self-contained folder. The canonical version is [`../Examples/Board-Posture-Summary.md`](../Examples/Board-Posture-Summary.md) — edit that one and re-copy, so the two do not drift.

## License

MIT. Use it, fork it, cut it apart. Attribution appreciated, not required.
