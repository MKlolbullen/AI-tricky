# Prototype Instructions

Run the local server yourself and open the preview in the browser available to this environment. Do not give the user server-start instructions when you can run it.

Before making substantial visual changes, use the Product Design plugin's `get-context` skill when the visual source is unclear or no longer matches the current goal. When the user gives durable prototype-specific design feedback, preferences, or decisions, record them in `AGENTS.md`.

When implementing from a selected generated mock, treat that image as the source of truth for layout, component anatomy, density, spacing, color, typography, visible content, and hierarchy.

Build app UI in `src/`. Keep `.openai/hosting.json`, `worker/index.js`, `scripts/prepare-sites-build.mjs`, and `tests/sites-worker.test.mjs` intact so the same local prototype can be handed to Sites. Before a Sites handoff, run `npm run build` and `npm run test:sites`; the build must leave `dist/client/index.html`, `dist/server/index.js`, and `dist/.openai/hosting.json`.

## Selected design
The user approved a combination of Workflow Studio and Engagement Desk, inspired by Trickest's node workflow interaction. Use the combined source image `exec-82208d21-49b8-46b8-93e7-8fbc1da7945c.png` as the visual target. Keep a central typed DAG, left node library, right node/evidence inspector and bottom console/artifact dock. Preserve local execution preferences and distinguish fixture simulation from actual backend integrations.

## Hosting and targets — clarified 2026-10-31
Local means locally hosted UI/API/workers/storage, not loopback-only assessment targets. Support domains, IPv4/IPv6, CIDRs and URLs. Remote model providers are independently configurable; do not confuse inference location with platform hosting. Never publish this platform without an explicit user request. Keep real local-native/CAI assessments distinct from canvas fixture simulations.

## Product name and template scope — 2026-10-31
The product is AI-tricky. Keep legacy ReconForge exports, environment variables and existing databases readable. Add searchable offline workflow/tool templates; use independently authored descriptors or licensed examples with provenance. Do not imply full Trickest catalog parity or live execution for unimplemented adapters. Preserve the approved canvas layout.

## Source direction — 2026-11-04
The user identified MKlolbullen/mini-tricky as their source project and wants a distinct rebuild with substantially more agent intelligence. Use its typed execution, capability planning and artifact contracts as architectural references. Keep the approved workflow-studio layout and local hosting. Distinguish deterministic planning, real model reasoning, captured observations and proposed tests. Native DAG adapters and the migrated CLI catalog execute under separate accounting. The 151-tool/57-workflow catalog is pinned to the upstream commit in third-party/mini-tricky/SOURCE.json. Preserve explicit context restrictions, typed input registration, shell-free argv, executable pins and CLI/native budget separation.

## Repository publication — 2026-11-04
The user authorized creating the public MKlolbullen/AI-tricky repository and publishing this project with a proper README. Use AI-tricky for visible branding and package metadata. Preserve Offsecs-u-AI/ReconForge environment and workflow-schema compatibility. Source publication does not authorize deploying the running assessment service or publishing engagement data.

## Release direction — 2026-11-04
The user selected structured observations, a durable findings workbench and run comparisons for the next release. Preserve original evidence and existing databases. Keep severity, confidence and operator review state independent. Compare captured run snapshots; absence is “not observed”, never automatic resolution. Scanner/model output must not overwrite operator reviews or automatically verify a finding.

## Improvement sequence — 2026-11-04
Work through the agenda one release at a time. Complete v0.5.1 correctness, parser-upgrade and browser regression coverage before beginning adaptive agent planning. Preserve evidence and operator review history across parser generations.

## Evidence-guided planning — 2026-11-04
The next authorized increment is evidence-guided proposals. Model planning must use captured observation references and server-owned actions; scope, risk and adapter validation remain independent of model output. Persist provenance, expected and negative signals, and flag stale evidence/contract bindings. Loading a proposal is a canvas operation; request-bound dispatch is a separate next increment. Keep deterministic suggestions explicitly labelled and never use them as a hidden model fallback.

## Proposal execution — 2026-11-04
The user authorized the next increment: explicit execution approval bound to a canonical proposal, original entered scope, budgets, executable hashes and input contents. Prepare reviews without target traffic. Persist approvals and run provenance, consume each review once, reject changed/stale/expired bindings and invalidate pending reviews at runtime restart. Reuse the existing run controls and accounting. Manual canvas runs remain independent and must not claim recorded proposal approval.

## Controlled verification — 2026-11-04
The next authorized increment compares a baseline and reviewed variant under the same proposal approval and scope. Use versioned server-owned GET profiles, exact request bindings, bounded captures and explicit native cost. Preserve both captures, partial/interrupted results and comparison provenance. Profile observations must not automatically change finding review state; only supported findings may receive linked verification evidence. Keep generic replay and authenticated identity profiles separate.

## Passive-source credentials — 2026-11-04
The user authorized a Credentials settings tab (Local workspace) to enter and store API keys for passive data sources. Keys are held in a server-owned vault persisted to `local-data/credentials.json` with owner-only permissions (the save fails rather than leaving the file group/world-readable). The vault is the source of truth and does not mutate the process environment; `effective()` reads the store and falls back to an ambient environment variable of the same name read-only, with the stored value taking precedence. Values are never returned to the client (only presence, source and length) and are redacted in tool output. Run-time injection stays gated: a key reaches a tool only when the tool declares the variable and a run selects its credential binding, and each run snapshots the selected credentials server-side at start so a concurrent settings change cannot mix identities mid-run. Curated provider set: Shodan, Censys and ProjectDiscovery/Chaos (consumed by catalog tools today) plus SecurityTrails, Netlas, urlscan, VirusTotal, BinaryEdge and GitHub (storable for future adapters). Keep the credential registry curated and provider additions provenance-checked.
