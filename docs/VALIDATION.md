# 0.4 verification — 2026-11-04

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

Interactive browser QA remains open because the session browser could not reach the workspace server. Rendering smoke tests and API/process integration checks passed; no browser-driven success is claimed. Windows process behavior, deliberately daemonized children, broad real-binary version compatibility, external engagements and Burp/Strix integration were not validated. CLI-internal network requests do not use the native request counter or pinned HTTP transport.

## Reproduce

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python scripts/migrate-catalog.py --check
.venv/bin/python -m pytest backend/tests -q
npm run build
npm test
```

Install `requirements-cai.lock` to include the three optional CAI SDK tests. The real URO test runs when URO is installed beside the selected Python interpreter; external security binaries are not bundled.
