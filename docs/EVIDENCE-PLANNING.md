# Evidence-guided planning — 0.7

Open **Local workspace → Agent desk → Evidence follow-ups**. Choose a recorded run, select 1–24 current observations, enter an objective and choose the maximum proposed risk. The default rules planner calls no model. The optional CAI planner uses the configured endpoint with no target tools attached. Its mode and model use are recorded explicitly; model errors never silently fall back to rules.

## Proposal contract

The server constructs eligible actions from registered adapter profiles and captured locations. The model can select an action ID and cite observations associated with that action. It cannot supply commands, flags, new adapters, targets, credentials, input paths or workflow JSON. The server builds and validates the typed graph independently.

Each proposed test records its hypothesis, rationale, expected signal, negative/inconclusive interpretation, supporting observation and artifact IDs, exact input binding, risk, known operation accounting and missing prerequisites. These are proposed tests, not findings, live verification results or execution grants. Contract validation checks supported bindings and provenance; it does not establish that the model's hypothesis or reasoning is factually correct.

The initial profiles cover `native_http`, `whatweb`, `getjs`, `katana`, `httpx`, `nuclei`, `tlsx`, `testssl`, `dnsx`, `subfinder`, `assetfinder`, `urlfinder` and `nmap`. Other migrated catalog tools remain available through normal workflow planning. Profile compatibility is not a claim that every upstream binary/version is validated.

URL-only authorization produces native HTTP follow-ups. Active external CLI proposals require entered domain/IP/CIDR authorization because their input checks do not enforce the native pinned HTTP transport's origin/path policy. Passive discoveries do not authorize subsequent active requests. Nmap proposals from service observations bind the already observed TCP port. A native HTTP proposal accounts for one admission; a CLI proposal accounts for one launch, with internal request count explicitly unknown.

Missing binaries, credentials, resolver inputs or reviewed template folders are reported as prerequisites. A proposal may be loaded for configuration while those prerequisites remain unresolved; live preflight is still required. No binaries are executed during planning or readiness inspection.

## Persistence and stale bindings

Plans and proposal IDs persist in SQLite, along with the source scope, selected observation/value hashes, original artifact hashes, parser generation and adapter/profile contract hash. Recorded plans can be reopened and exported. If those bindings change, the plan remains inspectable but its workflow-load endpoint returns 409 until a new plan is generated.

“Current” means the saved evidence and adapter bindings still match. It does not mean the target is unchanged or that the old evidence was collected recently. In-progress/failed source runs retain explicit coverage limits.

Loading a proposed workflow is a canvas operation. Its source contains the exact proposed input, and the original scope is selected in run setup. Existing workflow controls still govern manual execution. Users can edit the canvas after loading; proposal IDs on nodes are provenance labels, not authorization. A separate **Review execution** flow now binds the canonical proposal, scope, budgets, inputs and executable pins before explicit single-use operator approval. See [execution contracts and limits](PROPOSAL-EXECUTION.md).

## Model data and limits

The model receives the objective, recorded scope, selected URLs, bounded normalized metadata and the eligible action list. Raw bodies, extracted secret values, registered files and runtime credentials are excluded from planning context. Target-derived metadata is explicitly untrusted. Remote inference remains an explicit configuration and UI choice; the selected metadata goes to that provider when enabled.

The action pool is capped at 64, selected observations at 24, returned proposals at eight and prompt bytes at 150,000. Truncated action coverage is disclosed. The model is asked to prefer 1–3 concise tests and may return an empty list when evidence is insufficient. Proposals with invented IDs, duplicate actions, cross-run/out-of-context citations, extra execution fields or malformed output are rejected before persistence. Semantic assessment quality still needs evaluation against controlled labs.

## API

All endpoints retain the existing local API boundary checks.

| Method | Route | Behavior |
| --- | --- | --- |
| POST | `/api/agent/proposals` | Requires `run_id`, `observation_ids`, `goal`; optional `use_model` and `max_risk` (`passive`, `low`, `medium`) |
| GET | `/api/agent/proposals?run_id={id}` | Lists the latest 50 recorded plans for a run |
| GET | `/api/agent/proposals/{id}` | Returns the recorded plan and current binding status |
| GET | `/api/agent/proposals/{plan}/{proposal}/workflow` | Rechecks bindings and returns a server-built workflow for canvas loading |

Planning, workflow loading and execution-review preparation send no target requests, change no finding review state and consume no native/CLI run budget. Dispatch requires a separate explicit operator approval of a saved execution snapshot. Model inference is separate and uses the existing bounded CAI adapter.
