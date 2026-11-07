# Model usage accounting

The **Usage** tab shows a durable workspace ledger; every run also has a **Model
usage** panel. The ledger records model adapter passes, admitted call attempts,
successful provider responses and token counts reported by the provider.
Existing team turn reservations remain separate ceilings. Unused reservations
are not automatically reassigned by this increment.

## What the counters mean

| Field | Meaning |
| --- | --- |
| Invocation / pass | One analyst, synthesizer or model-planning adapter call |
| Attempt | A committed admission immediately before one chat-completion client request |
| Response | A successful provider-client response; later output/schema validation can still fail |
| Input / output / total tokens | The provider's respective reported counts; missing/invalid fields remain `null` |
| Cached input / reasoning tokens | Optional provider details, retained independently without adding them to total tokens |
| Unknown attempt | An admitted call that failed, was cancelled/interrupted or has no completed response record |

An attempt can fail before reaching the provider, or the provider may process a
request whose response never arrives. These counters cannot determine invoices
or charges for those cases. No token counts, prices or billing estimates are
invented. A genuine reported zero is retained as zero; absent usage is unknown.
Aggregate token totals sum only known reports and are labelled partial when core
reports or outcomes are missing, or when an injected adapter has no meter support.

Model pass status describes adapter completion. A completed model response can
still produce an invalid plan or unsupported finding; usage never confirms a
finding or relaxes scope, evidence validation or provider selection.

## Accounting boundaries

- Live CAI assessments, each team member, optional lead synthesis and workflow
  evidence analysts record usage against their run. Workflow passes also bind
  node IDs and specialist roles.
- Model workflow planning, the canvas assistant and evidence-guided proposals
  have distinct purposes. Planning does not create an assessment run. Evidence
  follow-up planning records a related source run separately, without adding
  that cost to the original run's execution counters.
- Deterministic planning and native/CLI adapters produce no model calls.
- Recovery counts only new model calls. Reused analysis artifacts retain their
  original usage references and are not charged again in the recovery ledger.
- Historical runs without the new recording marker show usage unavailable;
  old reports are not mined to fabricate historical token counts.

## Isolation, persistence and failure

The parent application owns invocation IDs, scope/run/node/role context and
SQLite records. The adapter records admission before the provider request and
records reported usage before parsing its response. In an isolated CAI worker,
typed usage frames share the existing serialized private protocol and wait for
a durable parent acknowledgement. They add no target tools, HTTP listeners or
model capabilities. Accounting is available during evidence-only review too.

The parent validates frame shape, sequence and per-pass turn limits. Worker
frames cannot select another run or role or supply prompts, URLs, commands,
arbitrary fields or exception bodies. Reported counts must be nonnegative
integers of at most one billion per field per response; malformed values on the
provider path become unknown, while malformed protocol frames are rejected.
Duplicate persistence events do not double count; duplicate worker admissions
are rejected. Existing target-tool message limits remain independent.

A recorder failure before admission acknowledgement stops the request. Failures
after admission retain that attempt, with unknown usage when no report could be
saved. Process restart marks unfinished passes and attempts interrupted, keeping
all already recorded token reports. SQL summary and page reads share one read
transaction so exported values correspond to one ledger snapshot.

The ledger persists only identifiers, purpose/provider/model labels, execution
mode, timestamps, statuses and numeric usage. It stores no prompts, response
content, endpoint URLs, credentials, provider exception messages or prices.
Run events contain bounded accounting metadata. Adapters injected without an
explicit `usage_callback` parameter remain compatible and are labelled unmetered.

## API and export

| Endpoint | Result |
| --- | --- |
| `GET /api/model-usage?limit=50&offset=0` | Workspace totals and paginated model passes |
| `GET /api/runs/{id}/model-usage?limit=50&offset=0` | Execution usage for one existing run |

Limits are bounded to 1–100 passes per page. Totals cover all matching recorded
passes, independently of pagination. Exports identify their run, offset and
snapshot time and contain the displayed page plus aggregate totals. The schema
is `ai-tricky.model-usage/v1`. Coverage is `complete`, `partial`, `in_progress`
or `unavailable`.

## Verification

Core tests cover persistence, restart, cancellation, idempotence, concurrent
passes, null/zero token semantics, protocol forgery/reordering, acknowledgement
before dispatch, role/node attribution, separate planning and recovery reuse.
The optional supported CAI SDK suite exercises the real Runner and provider
client against loopback fixtures in both in-process and isolated modes, including
two-turn tool use, missing usage, turn exhaustion and provider errors. The
optional CI job runs this suite with the SDK environment's interpreter.
