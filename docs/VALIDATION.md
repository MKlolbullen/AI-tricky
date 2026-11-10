# 0.8 verification — 2026-11-04

- Python: **351 passed, 1 skipped** locally, including **30 controlled-verification cases**. Tests cover exact paired requests, native budgets, retained captures, stability differences, CORS origin/wildcard/header-case interpretation, duplicate headers, truncation, redirects/denial, failed baselines, cancellation between requests, profile upgrades, capture tampering, strict finding links and independent operator reviews. The URO smoke test skipped locally.
- Backend CI: **344 passed, 8 skipped**. URO is installed in CI; the eight optional CAI SDK fixture cases skip in that job and passed in the full local suite through both SDK interpreters.
- JavaScript: **12 passed**; production build, existing Sites packaging checks and catalog drift check (**151 tools / 57 workflows**) passed.
- Chromium: **12 passed in GitHub CI**. New cases restore a paired profile with approval unset, inspect both exact requests before dispatch, observe exactly two loopback requests, inspect/export captures and show linked results without changing finding status or revision.
- Built-UI fixture server/profile endpoint smoke passed; read-only profile inspection sent no fixture target requests. The interactive session browser still cannot access the workspace loopback service, so manual visual QA remains open.
- Only loopback targets and local executable/model fixtures were used. CORS results are narrow response-header observations; no browser exploit, authenticated data-access proof, external engagement or remote-provider assessment is claimed.

## Historical 0.7 verification — 2026-11-04

- Python: **321 passed, 1 skipped** locally, including **27 proposal-execution cases**. Coverage includes exact snapshots, explicit approval, strict options, scope/evidence/parser/catalog staleness, expiry, revocation, runtime restart, concurrent retries, transactional rollback, binary/template content changes, copied-input rechecks, capacity handling, pause/resume/cancel and a client disconnect during consume/start. The URO smoke test skipped locally.
- Backend CI: **314 passed, 8 skipped**. URO is installed in CI; the eight optional CAI SDK fixture cases skip in the regular job and passed in the full local suite, including both selected SDK interpreters.
- JavaScript: **12 passed**; production build, existing Sites packaging checks and catalog drift check (**151 tools / 57 workflows**) passed.
- Chromium: **10 passed in GitHub CI** against the built UI and disposable fixture server. Execution cases cover persisted reviews, explicit approval, one loopback run, idempotent dispatch, revoking a prior budget snapshot and fresh review requirements. Each browser case resets its fixture data independently.
- Real target I/O in these tests is limited to loopback HTTP fixtures; external CLI tests use local executable fixtures. No external target or remote provider was contacted. These results do not establish broad upstream binary compatibility, semantic proposal quality or authenticated multi-user approval.
- Built-UI fixture server startup, initial run ordering and the test-only reset route passed a local API smoke. Manual visual inspection remains unavailable through the session browser's loopback connection.

## Historical 0.6 verification — 2026-11-04

- Python: **294 passed, 1 skipped** locally, including 24 proposal cases covering strict model contracts, evidence references, scope and risk limits, prerequisites, persistence and stale bindings. The real URO smoke test skipped because the binary is unavailable locally. The 24 proposal cases also passed after the final async API change.
- Backend CI: **287 passed, 8 skipped**. CI includes the installed URO binary; its eight optional CAI SDK cases skip in the regular job and were exercised locally as described below.
- JavaScript: **12 passed**; production build and catalog drift check (**151 tools / 57 workflows**) passed.
- Real CAI SDK: **8 loopback fixture cases passed**, including evidence-guided proposals in-process and through the separate SDK interpreter. No external provider or target was contacted. Fixture output does not establish proposal quality on real engagements.
- Chromium: **8 passed in GitHub CI** against the production build and a disposable local fixture server. Tests cover the existing workbench plus proposal persistence, restoring saved plans, stale-plan blocking, empty results and loading a workflow without dispatch.
- Proposal loading is not execution authorization. There is no proposal dispatch endpoint; request-bound execution is a later increment.

## Historical 0.5.1 verification — 2026-11-04

- Python: full-suite validation includes parser-generation migration, unchanged-row reuse, superseded normalization exclusion, review preservation, scoped SDK RPC, protocol failure handling and process cleanup. The URO smoke test remains unavailable locally.
- JavaScript: **12 passed**, production frontend build and existing Sites packaging checks passed.
- Chromium browser regression tests: **5 passed in GitHub CI** against the built UI and a disposable local fixture server. Tests cover late run loading, selection locking and exported IDs, complete parser coverage, pagination after review, verification capture eligibility and capture failure states.
- Real CAI SDK: **6 local fixture cases passed**, including HTTP/TCP delegation and evidence-only review both in-process and through a separately selected SDK interpreter. The main interpreter used FastAPI 0.162.0 / Starlette 1.3.1; the SDK interpreter retained its pinned 0.115.14 / 0.46.2 stack. No SDK HTTP listener or proxy service was started.
- Dependency checks: main `pip check` passed; the standalone original CAI snapshot resolved successfully. It must be installed into the separate SDK environment, not combined with the main API requirements.
- Catalog drift check: **151 tools / 57 workflows**, unchanged. No external engagement, remote model or broad real-binary compatibility validation is claimed.
- The interactive cloud browser still could not reach the workspace's loopback URL. The Chromium interaction results above were obtained by the committed CI test suite, not that browser session.

## Historical 0.5 verification — 2026-11-04

- Python suite: **248 passed, 1 skipped**. The real URO smoke test skipped because URO is unavailable in this environment. Optional CAI SDK tests ran against local fixtures; no external model was called.
- Added 28 evidence tests covering default text/JSONL parser contracts, malformed and non-finite output, canonical asset identity, concurrent/idempotent indexing, retained raw evidence, legacy SQLite migration, review persistence and conflicts, same-run candidate provenance, comparison snapshots and incomplete coverage notices.
- JavaScript suite: **12 passed**; production frontend build and existing Sites packaging checks passed.
- Catalog migration drift check: **151 tools / 57 workflows**, unchanged.
- Rendering smoke: Observations, Findings and Compare runs render through React's server renderer. Live native HTTP integration tests verify that evidence indexing and comparisons send no extra target traffic.
- Interactive browser QA remains unverified: the local server started successfully, but the available cloud browser returned `ERR_CONNECTION_REFUSED` for its loopback URL. Rendering and API checks are not a substitute for browser interaction testing.
- Parser fixture coverage does not establish compatibility with every upstream binary version. No external engagement or live vulnerability verification is claimed.

## Historical 0.4 verification — 2026-11-04

- Python suite: 221 tests, including the installed CAI 0.5.10 Runner against loopback model fixtures.
- JavaScript suite: 12 tests, including all 57 migrated workflows and the 151-tool socket contracts.
- Reproducible migration check: generated JSON matches the committed, pinned source YAML.
- Production frontend build: catalog code split into a separate chunk; original build handoff files retained.
- React rendering smoke: canvas, run setup, migrated template library, tool inspector and agent planner render successfully.
- Real local-server smoke: loaded the 151-tool / 57-workflow catalog, imported a raw mini-tricky graph, saved it, passed preflight, ran the actual URO 1.0.2 binary, persisted all three completed nodes and reported one CLI launch / zero native requests. The built UI was served by the same local server.

## Catalog execution coverage

The matrix covers every source tool: 141 adapters are exercised through temporary executable fixtures; ten entries assert their explicit context restrictions. These fixtures verify argv, stdin, typed outputs, file artifacts, isolated environment and lifecycle behavior. They are not substitutes for installing and compatibility-testing all third-party binaries.

Additional tests cover multi-output socket selection, registered file hashes, same-run file artifact forwarding, rejection of cross-run artifact references, executable changes after preflight, command/environment/flag injection rejection, scalar fan-out budgets, preflight failures without starting a run, partial logs on cancellation/timeout, bounded output termination, POSIX pause/resume and cancellation of a tested child-process group. Literal selected provider secrets are redacted and model keys are not inherited.

Existing native scope tests cover URL paths, redirects, logical operation budgets, CIDRs, pinned transport, persistence and cancellation during DNS. The real evidence-only CAI test verifies that no tools are attached to the model request. AI responses in tests are fixtures, not an assessment-quality benchmark.

## Limits

The interactive session browser could not reach the workspace server. Browser regression coverage comes from the committed Chromium CI suite; manual visual inspection remains open. Windows process behavior, deliberately daemonized children, broad real-binary version compatibility, external engagements and Burp/Strix integration were not validated. CLI-internal network requests do not use the native request counter or pinned HTTP transport.

## Reproduce

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python scripts/migrate-catalog.py --check
.venv/bin/python -m pytest backend/tests -q
npm run build
npm test
```

Install `requirements-cai.lock` into a separate environment, then set `CAI_TEST_PYTHON` to its Python executable to include the eight optional CAI SDK fixture cases. The real URO test runs when URO is installed beside the main Python interpreter; external security binaries are not bundled. `npm run test:browser` runs the Chromium regression suite after installing Playwright's Chromium browser and building the frontend.

## Team budgets and cache isolation — 2026-11-07

- Added coordinator allocation coverage for combined/per-member caps, synthesis inclusion, adaptive/explicit role selection, tiny budgets and skipped roles, and SDK failures that preserve other members' evidence.
- API tests verify durable budget metadata and events, strict limit validation, and evidence-only workflow tool isolation.
- Passive-cache regressions cover API-key rotation with separate provenance, all declared account variables, unrelated-key changes, TTL expiry, TTL zero, LRU eviction and pagination changes.
- The production build and 12 JavaScript contract/packaging tests pass locally. Both new Chromium interaction regressions are discovered by Playwright and run in the existing browser CI job.
- Local browser execution remains blocked: system Chromium cannot create its process socket (`Operation not permitted`); the shared browser cannot reach the workspace loopback server (`ERR_CONNECTION_REFUSED`); Playwright's headless-shell download returned invalid ZIP data. These observations do not establish a browser pass. No external target or paid provider was queried for this change.

## Workflow recovery — 2026-11-07

Added recovery API/coordinator tests covering preserved source runs, reuse without repeated HTTP capture, unchanged observation age, strict options, altered scope/graph/node/artifact bindings, expiry/revocation/restart, concurrent idempotent dispatch, branch expansion, excluded unrelated branches, registered input and binary changes, same-run copied file artifacts, credential/model rotation, and existing pause/resume/cancel controls. The complete suite passed with 456 cases before five additional targeted recovery cases; all 30 recovery cases passed afterward. The build, 12 JavaScript checks and migration check passed locally. Two browser regressions cover restore-without-approval, exact-once loopback dispatch and revoked settings changes. The shared browser still cannot reach the workspace loopback server; GitHub Chromium CI passed all 16 interaction cases on the first recovery commit. A final regression also blocks recovery while cancelled source workers are still stopping.

## Actual model usage — 2026-11-07

- Full main-environment suite: 493 passed, 16 optional SDK cases skipped. All 32 targeted accounting and worker-protocol cases also passed after the snapshot-read refinement.
- Real CAI SDK: 16 passed using `.venv-cai/bin/python` against loopback model fixtures, covering both in-process and isolated execution, tool turns, missing reports, turn exhaustion and provider failures. No paid provider or external assessment target was queried.
- The production build, 12 JavaScript tests and pinned catalog check passed. Usage and recovery UI modules load separately; the main bundle remains below the existing 500 kB warning threshold.
- Two new Chromium interactions cover partial totals/export, unavailable historical runs and persistent per-run totals. The browser suite now contains 18 cases. Local shared-browser loopback access remains environment-blocked; GitHub CI supplies interaction validation.

## Support data packs — 2026-11-08

- The support-data suite passes 21 tests: offline/idempotent installation, pinned data tampering, exact archive hash checks, safe extraction limits, helpers/licenses, private Nuclei home, automatic binding preservation, PureDNS regular/trusted resolvers, rooted paths, and binding metadata version changes.
- Verified the complete pinned Nuclei and Jaeles archives through the installer using locally cached upstream ZIPs. Nuclei produces 18 bounded HTTP category inputs with helpers; Jaeles produces one separate signatures input. No assessment target was contacted.
- All 12 JavaScript checks, production build, and the unchanged pinned catalog migration check pass. Two support-data browser regressions are included. Local browser attempts are blocked: the Playwright download is absent and system Chromium cannot create a process socket (Operation not permitted). GitHub CI is the browser validation source.

## Role model routing and specialist handoffs — 2026-11-09

- Full local backend suite passed 578 cases with 18 optional SDK cases skipped before the last checkpoint-remapping regression. Targeted routing/credential cases pass after that addition.
- All 18 real CAI SDK cases passed in the supported optional interpreter, including in-process and isolated-worker availability fallback, separate attempt IDs, retained failed usage, OpenAI completion limits and default sampling. Fixtures are loopback-only; no paid provider was queried.
- Production build, 12 JavaScript checks and the pinned catalog check pass. Team settings and route history load separately, keeping the main bundle below 500 kB.
- Added browser checks for mixed providers, exact model IDs, complex-task overrides, availability fallback configuration and handoff inspection. The browser suite contains 24 cases. Local execution remains blocked by the missing Playwright binary; GitHub CI verifies interactions.


## HTTP routing and retained exchanges — 2026-11-09

- Full local backend suite: 601 passed, 18 optional SDK cases skipped. Targeted transport/history tests also pass after the cancellation race refinement. Loopback fixtures cover direct/proxy HTTP, trusted/untrusted HTTPS CONNECT with original SNI, binary bodies/duplicate headers, capture limits, no redirect following, no direct fallback, strict settings, CA approval binding, restart/cancellation retention, model tool output boundaries and scoped/idempotent Burp XML import without replay or finding changes.
- CLI executable fixtures check owned proxy flags, independent capture accounting and absence of ambient proxy variables; broad upstream binary compatibility is not claimed.
- Added three Chromium regressions for routing payloads, persisted native request/response inspection, binary downloads/HAR and idempotent XML import. Local system Chromium still fails at process socket creation (Operation not permitted); Playwright execution and CI results are recorded in the PR.
- No external assessment targets, paid model calls or running Burp instance were used. Proxy behavior is validated against an HTTP/CONNECT loopback fixture. CLI full exchanges require external proxy export/import; there is no live extension synchronization.


## AD and Entra identity workflows — 2026-11-10

- Full backend suite passed 623 cases with 18 optional SDK cases skipped before the final recovery/cancellation/credential-file regressions. The targeted identity suite passes after those refinements.
- Identity tests cover candidate/provenance boundaries, explicit endpoints/depth, cycles, foreign scopes, BloodHound ZIP membership and paired replication rights, AzureHound v5 nested membership and active tenant-wide role assignments, excluded PIM/narrow scopes, malformed JSON/ZIP, token tenant/audience/expiry, private credentials and redaction, fixed argv/environment, shared launch accounting, input/executable changes, offline agent handoffs, recovery and cancellation cleanup.
- All 12 JavaScript checks, the unchanged 151-tool/57-workflow catalog check and the production build pass locally. Identity UI modules load separately; the main bundle remains below 500 kB. Two Chromium regressions cover offline import/path inspection and explicit Entra canvas configuration without dispatch.
- Local Playwright lacks its browser binary; system Chromium fails creating a process socket (Operation not permitted). GitHub CI is used for browser interaction results, recorded in the PR. No live AD/Entra environment, real credential, external collection or paid model was used. Executable fixtures do not establish broad upstream binary compatibility.


## Identity CLI compatibility and producer diagnostics — 2026-11-10

- Tested the actual Impacket 0.13.1 commands and checksummed AzureHound 3.1.3 release with their owned argv plus help. Seven real-tool tests pass: four command contracts and three guarded Impacket zero-exit failures. No directory/tenant was contacted.
- Coverage regressions exercise fatal and partial Impacket output, structured AzureHound errors/warnings, unknown stderr, Graph application-ID audience rejection and diagnostic propagation into saved analysis and bounded agent evidence.
- A dedicated CI job installs isolated test tools and repeats real command checks; these results do not establish live authentication, upstream scope enforcement or complete collection.
