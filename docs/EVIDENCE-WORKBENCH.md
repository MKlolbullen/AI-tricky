# Evidence workbench — 0.5.1

The workbench indexes captured artifacts on the same local SQLite database. It does not run tools, make target requests or call a model. Original evidence is retained; unsupported formats remain available as raw artifacts.

## Observations and provenance

Supported inputs are native HTTP responses and TCP inventories, plus the default output formats of httpx, dnsx, Naabu, Nmap, Katana and Nuclei (including the nuclei-takeover catalog adapter). The CLI parsers accept the supported text and/or JSONL variants exercised by the parser tests. Nmap support covers its current adapter's normal text output, not arbitrary XML output. File-only JSON/XML output and all other tool families remain raw evidence until a dedicated parser is added.

Each observation records its run, node, original artifact, canonical asset, source, kind, parser version, normalized value hash and timestamp. URL normalization preserves path case and query order/values; it folds hostname spelling and default HTTP ports. Source, kind, asset and a detector/service key identify comparable observations. Distinct sources remain distinct; matching tool output is not independent verification.

HTTP comparison values include the status, selected stable headers, available structured metadata and a hash of the captured body. Date headers and cookies are excluded. A body hash covers captured bytes only; truncated responses are explicitly marked. New artifacts have capture timestamps. Legacy artifact timestamps fall back to the run's creation time and are labelled `run-start (legacy)`.

Indexing is incremental and transactionally idempotent, including concurrent reads. Opening the workbench indexes previously recorded runs without replaying requests or modifying artifact content. Generated binary/file payloads are not loaded merely to populate this index.

## Parser upgrades

Parser generation 2 accepts dnsx responses both with and without `[TYPE]` groups. On upgrade, artifact generation membership is backfilled for existing v0.5 observations. Reindexing is atomic per artifact: unchanged observations reuse their IDs and join the new generation, while changed normalizations create additional immutable rows. Observation queries and comparisons select only the current generation. Old rows, finding IDs, review references and occurrence snapshots remain stored. Failed reindexing rolls back the new generation for that artifact and can be retried.

Observation `parser_version` identifies the selected generation; `origin_parser_version` identifies the generation that originally created an unchanged row. Finding occurrences expose `parser_versions` and `active`; superseded occurrences remain visible in review history but do not enter current comparisons. Findings themselves remain reviewable even when all their occurrences are historical. Review status is never reset by reindexing.

## Durable findings and review

Nuclei detections and structured CAI evidence candidates become findings in `candidate` status with `unknown` confidence. Inventory alone never creates a vulnerability finding. CAI candidates must reference captured HTTP artifacts from the same run; an analysis artifact alone cannot be used to verify a finding.

Nuclei finding fingerprints include source, canonical location, template ID, matcher, type and method. CAI fingerprints use normalized candidate title and the referenced asset set. These are deliberately conservative deduplication rules, not semantic equivalence across scanners, renamed templates or differently worded model hypotheses. Multi-identity findings require a future identity contract.

Every finding retains immutable occurrence snapshots and original evidence references across runs. Operator status, severity and confidence are independent fields. Supported review states are `candidate`, `triaged`, `verified`, `rejected` and `resolved`. A nonempty note is required for every review. The API supplies eligible artifacts as `verification_evidence`, and the selector excludes model analysis artifacts. Verification also requires an attached captured HTTP/CLI artifact; it records the operator's judgment and does not itself reproduce an issue. These single-user reviews are not multi-user attestations.

Reviews require the current revision. Stale submissions return HTTP 409 and append no history. New occurrences cannot overwrite a review decision or reviewed severity/confidence. The detail view flags evidence captured after the most recent review. Resolution is an explicit operator decision; absence from a later scan never resolves a finding automatically.

## Run comparisons

Choose a baseline and a current run in **Local workspace → Compare runs**. The comparison groups normalized values by observation fingerprint and shows `new`, `changed`, `unchanged` and `not_observed`. Findings use their recorded occurrence snapshots and show `new`, `changed`, `recurring` and `not_observed`. Later operator severity changes do not rewrite earlier results. Both sides retain evidence links and can be exported as JSON.

Scope changes, workflow/limit changes, incomplete runs, disabled execution, recorded node errors and partial captures produce coverage notices. Parser coverage reports retain unsupported formats and unparsed-line counts. Equal normalized values do not establish equal assessment coverage or that the underlying systems are identical. A record missing from the current run means only that it was not observed there.

Comparisons support up to 10,000 normalized observations per selected run and reject larger comparisons explicitly. Observation/finding lists are paginated; API pages are capped at 200 records. The run selectors use the existing recent-run list; older artifacts and findings remain indexed and accessible through the APIs.

## API

All routes retain the existing loopback, Host, Origin and JSON-write checks.

| Method | Route | Behavior |
| --- | --- | --- |
| GET | `/api/observations` | Filters: `run_id`, `kind`, `q`, `limit`, `offset`; returns `items` and `total` |
| GET | `/api/findings` | Filters: `run_id`, `status`, `severity`, `q`, `limit`, `offset` |
| GET | `/api/findings/{id}` | Finding, evidence occurrences, review history and post-review evidence flag |
| POST | `/api/findings/{id}/reviews` | Requires `expected_revision`, `status`, `severity`, `confidence`, `note`; optional `evidence_id` |
| GET | `/api/runs/{current}/compare?baseline={baseline}` | Recorded observations, finding occurrences and coverage notices |

Review writes return 422 for invalid decisions or evidence bindings, 409 for stale revisions and 404 for unknown findings. Comparison requires two existing, different runs. No API in this release dispatches a verification/replay request.

## Runtime compatibility

The main API uses FastAPI 0.162.0 and Starlette 1.3.1. CAI 0.5.10 requires OpenAI 1.75.0 and LiteLLM proxy dependencies that cannot share a clean installation with that API stack. Install its original pinned snapshot into a separate `.venv-cai` and select its Python executable through `CAI_PYTHON`. Do not install `requirements-cai.lock` into the main API environment.

The private worker communicates over bounded stdin/stdout frames and never starts a proxy or HTTP listener. Its only exposed target operations are parent-owned scoped HTTP GET and optional TCP checks; evidence-only runs reject all target-tool requests. Cancellation/timeout terminates the worker process group on POSIX. Unrelated ambient credentials and SDK stderr are not forwarded into evidence. Model endpoints retain their explicit local/remote configuration. Dependency isolation is not an OS sandbox; existing external-CLI network limitations are unchanged.
