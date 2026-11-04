# mini-tricky → Offsecs-u-AI

Reference inspected: [MKlolbullen/mini-tricky](https://github.com/MKlolbullen/mini-tricky), commit `96971000b0058423da52884d9028250ab76b0633`, 2026-11-04.

This increment extends the supplied Offsecs-u-AI application. It uses mini-tricky as the architectural reference; it is not a port of its full executor or catalog, and its graphs are not interchangeable.

The relevant source seams are mini-tricky's `backend/src/capabilities.py` (typed capability paths), `backend/src/llm.py` (generation/explanation/provider helpers), `backend/src/catalog_extensions.py` (composed catalogs) and `backend/src/secure_entry.py` (local application boundary).

| mini-tricky foundation | Offsecs-u-AI 0.3 implementation | Follow-on migration |
|---|---|---|
| Typed tool transitions | Server-owned native adapter registry and live DAG validation | Preserve real tool sockets while migrating reviewed CLI adapters |
| Capability and LLM planning | Local rules planner and optional configured CAI model planner; both produce validated native graphs | Cost/risk scoring across the broader tool catalog |
| Per-node execution artifacts | Immutable graph/scope snapshots, node state, artifact provenance, shared operation budgets | Replay using artifact hashes and explicit upstream dependency selection |
| Optional LLM helpers | Evidence-only CAI review with structured candidates, permitted artifact IDs and coverage limits | Rank follow-up proposals and compare results across runs |
| Local desktop/API boundary | Existing loopback/Host/Origin checks retained | Desktop session authentication when Electron is introduced |

## What “more agent intelligence” means here

1. A planner converts an operator goal into a typed graph built only from supported adapters.
2. The runner validates scope, topology, adapter contracts, budgets and node deadlines independently of the model.
3. An optional evidence analyst reviews captured HTTP records without target tools. It returns structured candidates and suggested next tests.
4. The application rejects malformed reports and citations outside the analyst's supplied evidence. A valid citation establishes provenance, not that the model's claim is correct.
5. The operator reviews candidates, artifact content and coverage. Suggested next tests are text proposals, not automatically executed actions.

There is no hidden fallback that labels deterministic planning as AI. The interface identifies local rules versus CAI model planning. The evidence analyst uses at most 12 upstream HTTP records, 1,200 body characters per record, and selected headers. Full captured responses remain in local artifacts.

## Migration update — 0.4

The complete source catalog is now available: 151 contracts and 57 converted workflows, with 141 CLI adapters and ten explicit context restrictions. See [the full matrix and execution boundaries](CATALOG-MIGRATION.md). Native model tools remain separate from CLI process execution.

## Remaining work

- Expand real-binary compatibility tests and add account/callback/notification contracts for restricted entries. Keep arbitrary shell commands outside model tools.
- Expand the 0.5 findings workbench with additional format-specific parsers and controlled verification/replay.
- Introduce a typed proposal execution contract with exact request binding before allowing an agent's suggested test to dispatch.
- Add authenticated identity profiles and controlled multi-identity evidence comparison for BOLA/IDOR reviews.
- Connect Burp/burpaderp and Strix through their integration contracts; these are not connected by this increment.
- Complete interactive browser QA on a machine that can reach the loopback application. The browser available during this session could not connect to the workspace server.

No changes were pushed to mini-tricky as part of this increment.

## Evidence workbench update — 0.5

Structured native/CLI observations, durable candidate findings, revision-checked operator reviews and run comparisons are implemented. Existing artifacts are indexed without rewriting their content. Comparisons retain per-run detection snapshots and never infer resolution from absence. See [contracts and limits](EVIDENCE-WORKBENCH.md).
