# Team model turn ceilings

Live team assessments and evidence-only `native_team` nodes reserve a combined
SDK turn ceiling before dispatch. HTTP/TCP operation accounting and CLI launch
accounting remain separate. A model turn is an SDK runner iteration; this is
neither token accounting nor a price estimate.

| Setting | Live `engine: "team"` | `native_team` node data |
| --- | --- | --- |
| `team_max_turns` | 48 by default; integer 1–144 | 60 by default; integer 1–144, per node |
| `member_max_turns` | 8 by default; integer 1–24 | 12 by default; integer 1–24 |
| Optional synthesis | Included in the shared allocation; at most 8 turns | No synthesis pass |
| Worker ceiling | `member_workers`, default 3 | `max_workers`, default 3 |

Older callers and workflows retain their previous member ceilings through these
defaults. No database migration is required. The coordinator records
`team.turn_budget` before calling analysts, so cancellation does not erase the
original reservation. Completed runs and node artifacts also carry
`model_turn_budget` and each member's assigned `max_turns`.

Allocation is deterministic round-robin in selected-role order, with synthesis
last. Each role receives one turn before any gets a second. For five roles and
an optional synthesis:

| Combined limit | Surface | Transport | Auth/session | Injection | Logic | Synthesis |
| --- | --- | --- | --- | --- | --- | --- |
| 2 | 1 | 1 | 0 | 0 | 0 | 0 |
| 9 | 2 | 2 | 2 | 1 | 1 | 1 |
| 48 | 8 | 8 | 8 | 8 | 8 | 8 |

A zero allocation skips that pass without calling a model and creates an explicit
coverage note. Adaptive selection runs before allocation; pinned roles override
adaptive selection as before. Failures and early completion do not return turns
to other passes. Reusing reservations without measuring actual usage would risk
double spending while other analysts are still running.

The UI labels allocations as **reserved upper bounds**, displays them in the run
report or node evidence, and exposes both total and per-member controls. A small
budget can cause an analyst to hit its SDK turn cap without finishing a report;
that is a coverage gap. Completed members' evidence is retained. Synthesis never
confirms findings and still receives no target tools.

## Next improvements

1. Record actual model turns and token usage across isolated workers, preserving
   an atomic run-wide ledger before allowing unused allowances to be reclaimed.
2. Add checkpointed workflow recovery that reuses immutable upstream artifacts
   and requires a fresh review for requests that will be repeated.
3. Add named test identities and request-bound paired comparisons for authorized
   access-control review, with separate credential snapshots and evidence.
4. Import Burp/burpaderp and Strix evidence through versioned integration contracts
   before introducing additional live agent tools.
