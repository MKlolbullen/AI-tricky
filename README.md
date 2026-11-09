<p align="center">
  <img src="docs/assets/ai-tricky-banner.svg" alt="AI-tricky — Local-first AI-assisted security workflows" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/MKlolbullen/AI-tricky/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/MKlolbullen/AI-tricky/actions/workflows/ci.yml/badge.svg" /></a>
  <img alt="Version 0.8.0" src="https://img.shields.io/badge/version-0.8.0-02d0e5" />
  <img alt="Python 3.12" src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&amp;logoColor=white" />
  <img alt="React and React Flow" src="https://img.shields.io/badge/React-React_Flow-61DAFB?logo=react&amp;logoColor=111827" />
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-b66cf3" /></a>
</p>

**AI-tricky is a locally hosted workbench for authorized penetration testing, ethical bug bounty work, and evidence-driven security assessment.** Build typed visual workflows, run native checks or installed CLI tools, and use an optional CAI analyst to plan assessments and review captured evidence.

The interface, API, SQLite history and execution jobs run on your machine. Assessment targets can be remote domains, IPs, CIDRs or HTTP(S) URLs. Model inference is configured separately: use a local OpenAI-compatible endpoint or explicitly enable a remote provider.

> **Current stage: functional beta.** The migrated catalog contains 151 tool contracts and 57 workflows. 141 entries have CLI adapters; ten require additional context contracts. External binaries are not bundled, and a migrated adapter is not a claim of compatibility with every upstream release.

[Quick start](#quick-start) · [What works](#what-works) · [Interface tour](#interface-tour) · [AI integration](#ai-integration) · [Execution boundaries](#execution-boundaries) · [Development](#development) · [Roadmap](#roadmap)

## Interface tour

<p align="center">
  <img src="docs/assets/screenshots/01-design-overview.png" alt="AI-tricky workflow studio: typed DAG canvas, node library, evidence inspector and run console" width="100%" />
</p>
<p align="center"><em>Workflow studio — typed DAG canvas, node library, evidence inspector and run console.</em></p>

Selected views and tabs from v0.8.0 are shown below. Canvas output is explicit fixture simulation; the local workspace reflects real backend-backed state (shown here with sample scope and no recorded runs).

<details>
<summary><strong>Workflow studio — views, inspector and console</strong></summary>

<br/>

| | |
| --- | --- |
| <img src="docs/assets/screenshots/06-runs-view.png" alt="Runs view" width="100%" /><br/><sub>**Runs** view — read-only run mode</sub> | <img src="docs/assets/screenshots/02-inspector-configure.png" alt="Inspector Configure tab" width="100%" /><br/><sub>Inspector — **Configure** tab</sub> |
| <img src="docs/assets/screenshots/03-inspector-evidence.png" alt="Inspector Evidence tab" width="100%" /><br/><sub>Inspector — **Evidence** tab (candidate finding)</sub> | <img src="docs/assets/screenshots/04-dock-artifacts.png" alt="Console dock Artifacts tab" width="100%" /><br/><sub>Console dock — **Artifacts** tab</sub> |
| <img src="docs/assets/screenshots/05-dock-findings.png" alt="Console dock Findings tab" width="100%" /><br/><sub>Console dock — **Findings** tab</sub> | |

</details>

<details>
<summary><strong>Dialogs &amp; actions</strong></summary>

<br/>

| | |
| --- | --- |
| <img src="docs/assets/screenshots/11-templates.png" alt="Template and tool catalog" width="100%" /><br/><sub>**Templates** — workflow &amp; tool catalog</sub> | <img src="docs/assets/screenshots/07-preview-run.png" alt="Preview run dialog" width="100%" /><br/><sub>**Preview run** — dry-run plan</sub> |
| <img src="docs/assets/screenshots/12-review-request.png" alt="Review proposed request dialog" width="100%" /><br/><sub>**Review request** — proposed replay (not dispatched)</sub> | <img src="docs/assets/screenshots/13-artifact-viewer.png" alt="Artifact viewer dialog" width="100%" /><br/><sub>**Artifact** viewer</sub> |
| <img src="docs/assets/screenshots/08-run-history.png" alt="Run history dialog" width="100%" /><br/><sub>**Run history**</sub> | <img src="docs/assets/screenshots/09-runtime-settings.png" alt="Runtime settings dialog" width="100%" /><br/><sub>**Runtime settings** — adapter readiness</sub> |
| <img src="docs/assets/screenshots/10-workflow-actions.png" alt="Workflow actions dialog" width="100%" /><br/><sub>**Workflow actions**</sub> | |

</details>

<details>
<summary><strong>Local workspace — all 11 tabs</strong></summary>

<br/>

| | |
| --- | --- |
| <img src="docs/assets/screenshots/14-local-targets.png" alt="Local workspace Targets tab" width="100%" /><br/><sub>**Targets** — entered scope</sub> | <img src="docs/assets/screenshots/15-local-assets.png" alt="Local workspace Assets tab" width="100%" /><br/><sub>**Assets** — observed inventory</sub> |
| <img src="docs/assets/screenshots/16-local-observations.png" alt="Local workspace Observations tab" width="100%" /><br/><sub>**Observations**</sub> | <img src="docs/assets/screenshots/17-local-findings.png" alt="Local workspace Findings tab" width="100%" /><br/><sub>**Findings** workbench</sub> |
| <img src="docs/assets/screenshots/18-local-compare-runs.png" alt="Local workspace Compare runs tab" width="100%" /><br/><sub>**Compare runs**</sub> | <img src="docs/assets/screenshots/19-local-inputs.png" alt="Local workspace Inputs tab" width="100%" /><br/><sub>**Inputs** manager</sub> |
| <img src="docs/assets/screenshots/26-local-credentials-providers.png" alt="Local workspace Credentials tab" width="100%" /><br/><sub>**Credentials** — passive sources &amp; model providers</sub> | <img src="docs/assets/screenshots/20-local-workflows.png" alt="Local workspace Workflows tab" width="100%" /><br/><sub>**Workflows** — saved graphs</sub> |
| <img src="docs/assets/screenshots/21-local-agent-desk.png" alt="Local workspace Agent desk tab" width="100%" /><br/><sub>**Agent desk** — planning &amp; proposals</sub> | <img src="docs/assets/screenshots/22-local-run-setup.png" alt="Local workspace Run setup tab" width="100%" /><br/><sub>**Run setup** — engine, scope &amp; budgets</sub> |
| <img src="docs/assets/screenshots/23-local-runs.png" alt="Local workspace Runs tab" width="100%" /><br/><sub>**Runs** — local run detail</sub> | |

</details>

## Why AI-tricky?

A useful assessment platform needs more than a canvas that launches commands and a chat box that sounds confident. AI-tricky gives each assessment an explicit graph, an immutable scope snapshot, bounded execution and inspectable evidence.

- **Typed workflow studio:** drag nodes, connect named sockets, configure adapters and inspect node output.
- **Local execution:** FastAPI, SQLite and private job directories; no Docker, Redis, hosted account or cloud deployment is required.
- **Broad catalog:** the complete MIT-licensed tool/workflow catalog from [mini-tricky](https://github.com/MKlolbullen/mini-tricky), with provenance and explicit readiness states.
- **AI-assisted reasoning:** optional CAI workflow planning and structured evidence review, alongside clearly labelled deterministic capability planning.
- **Durable run history:** saved graph/scope snapshots, per-node states, events, CLI invocation records and evidence artifacts.
- **Honest evidence handling:** model candidates must cite supplied artifact IDs; suggested follow-up tests are proposals, not automatic dispatch or confirmed vulnerabilities.

## What works

| Surface | Current behavior |
| --- | --- |
| Native inventory | Domain resolution, bounded TCP connect checks, and scoped HTTP GET evidence collection |
| Web recon | Explicit `*.example.com` scope, discovery → httprobe → katana starter, optional wordlist-bound path fuzzing, and bounded JS/TS/chunk/source-map capture manifests ([details](docs/WEB-RECON.md)) |
| Support data | Bundled Nuclei HTTP templates, Trickest resolvers and starter wordlists; pinned full Nuclei/Jaeles downloads with typed input bindings ([setup](docs/SUPPORT-DATA.md)) |
| Specialist teams | Per-role primary/complex-task/fallback model routes, staged evidence handoffs, PoC validation plans and recorded usage ([routing](docs/TEAM-MODEL-ROUTING.md)) |
| Workflow runner | Executes validated native and catalog DAGs; independent branches share configured run limits |
| Migrated catalog | 151 tool contracts and 57 typed workflows; searchable by source, category, input type and readiness |
| CLI adapters | 141 application-owned, shell-free adapters with executable preflight, typed files/stdin and scalar fan-out |
| Registered inputs | Local files/folders, uploaded text inputs, wordlists, SBOMs, resolver lists and reviewed template/signature folders |
| Provider credentials | Store API keys locally: passive data sources (Shodan, Censys, ProjectDiscovery, SecurityTrails, Netlas, urlscan, VirusTotal, BinaryEdge, GitHub, FOFA) injected only into tools that declare them, plus model providers (Anthropic, OpenAI, xAI/Grok, Gemini, Venice.ai) for agents and template planning |
| Agent desk | Native/catalog workflow planning plus persisted, evidence-guided follow-up proposals using rules or a model; choose the model provider (local endpoint or a configured remote provider) for model-backed planning |
| Evidence review | Optional CAI analysis of captured HTTP evidence with structured candidates, references and coverage limits |
| Evidence workbench | Structured observations, persistent candidate IDs, operator review history and run comparisons |
| Run controls | Pause/resume, cancellation, node deadlines, separate native-operation and CLI-launch budgets |
| Artifact routing | Named multi-output sockets, same-run file references, merge/dedupe, payload sources and collectors |
| Canvas preview | Explicit fixture simulation, separate from real execution |

The ten context-restricted entries concern account/cluster scope, callbacks, notifications or arbitrary command strings. Preflight reports these restrictions; installing a binary does not remove them. See the [complete migration matrix](docs/CATALOG-MIGRATION.md).

Burp/burpaderp and Strix adapters and broad real-binary version validation remain unfinished.

## Quick start

### Automated setup

The `installation.sh` script sets up the platform and, optionally, the external
CLI tools used by the catalog:

```bash
git clone https://github.com/MKlolbullen/AI-tricky.git
cd AI-tricky

./installation.sh                 # platform + install all catalog tools
./installation.sh --project-only  # just the UI + backend
./installation.sh --with-cai      # also create the optional CAI SDK venv
./start-local.sh                  # http://127.0.0.1:8787
```

The tool installer can also be run on its own and is idempotent, continues past
individual failures, and prints a summary:

```bash
scripts/install-tools.sh --list              # show every tool and how it installs
scripts/install-tools.sh --tools=recon,dns   # install by category
scripts/install-tools.sh --tools=httpx,ffuf  # install specific tools
scripts/install-tools.sh --skip-toolchains   # don't auto-install Go/Rust/pipx
```

It installs tools across their native ecosystems (Go, Rust, Python/pipx, Ruby,
npm, system packages, Git builds and GitHub release binaries) into
`~/.local/bin` by default. A small number of large or vendor-specific tools are
reported as *manual* with a pointer rather than installed automatically. Review
the script before running it on a shared host; it installs software only and
never contacts an assessment target. After installing, add the locations to your
`PATH` and use the Templates catalog or **Local workspace → Run setup → Check
workflow readiness** to confirm which binaries are detected.

The steps below show the equivalent manual setup.

### Requirements

- **Python 3.12**
- **Node.js 20.19+ or 22.12+**; Node 22 is used in CI
- npm
- The external security binaries required by the CLI workflows you choose

Linux/macOS:

```bash
git clone https://github.com/MKlolbullen/AI-tricky.git
cd AI-tricky

python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
npm ci
npm run build

./start-local.sh
```

Open **http://127.0.0.1:8787**. The Python backend intentionally binds to loopback. Run history, registered inputs and evidence are stored under `local-data/` by default, which is excluded from git.

Native inventory works without installing the optional CAI SDK or any CLI scanners.

### First workflow

1. Open **Local workspace → Targets** and enter the authorized domains, IPs, CIDRs or URL path scopes.
2. Choose **Workflow actions → Load runnable native workflow**, or load a migrated graph from **Templates → mini-tricky**.
3. Register any required files/folders under **Local workspace → Inputs**, then bind them in the node inspector.
4. Open **Run workflow**, select targets and limits, and run **Check workflow readiness**.
5. Enable execution when ready. Catalog workflows also require the explicit CLI execution setting.
6. Inspect **Runs**, node evidence, invocation logs and artifacts. A successful tool exit remains an observation, not proof of a vulnerability.

Nuclei and Jaeles require a registered, reviewed template/signature folder. DNS adapters that require resolver files use registered resolver inputs. Missing binaries and missing context are reported before a live run starts.

## Evidence workbench — 0.5.1

Open **Local workspace → Observations**, **Findings** or **Compare runs** after recording assessments.

- **Observations:** native HTTP/TCP captures and versioned parsers for the default outputs of httpx, dnsx, Naabu, Nmap, Katana and Nuclei. Every normalized record links to the original artifact, run and node. Unsupported formats remain raw evidence.
- **Findings:** Nuclei matches and structured CAI evidence candidates receive durable IDs, deduplicated occurrences and first/last seen timestamps. Filter by run, title/asset, severity and review status. Severity, confidence and status remain independent.
- **Review:** record candidate, triaged, verified, rejected or resolved decisions with an explanatory note. Verification requires an attached HTTP/CLI capture. Reviews are revision checked and retained in history; new scanner/model output preserves operator decisions and flags evidence captured after the latest review.
- **Compare runs:** inspect new, changed, unchanged/recurring and not-observed records, with baseline/current values, evidence links and JSON export. Scope, configuration, partial captures and failed checks remain visible. Not observed does **not** mean resolved.

Existing runs are indexed locally when these views or APIs are read; original artifacts remain intact. Parser generation 2 reindexes old captures, retains review history, and excludes superseded normalizations from observations and comparisons. New captures record capture timestamps; legacy artifacts explicitly use their run-start timestamp. Comparisons use recorded occurrence snapshots, so a later severity review does not rewrite what an earlier run reported. See [contracts and limits](docs/EVIDENCE-WORKBENCH.md).

## Evidence-guided follow-ups and execution — 0.8

Open **Local workspace → Agent desk → Evidence follow-ups**, select a run and supporting observations, then generate proposed tests. Each proposal explains its hypothesis, supporting captures, expected evidence, negative/inconclusive result, registered adapter, exact input and prerequisites.

The optional CAI model selects from server-built actions with no target tools attached. Scope, risk and typed graph validation remain independent of the model. The rules mode is explicitly labelled. Plans persist across restarts, can be reopened/exported, and become stale when their evidence or adapter bindings change.

The initial profiles cover 13 reviewed adapters. You can load a proposal onto the canvas for manual configuration, or choose **Review execution** to bind its exact workflow, scope, budgets, binary hashes and registered input contents. Preparation runs preflight without target traffic. Inspect the saved snapshot, explicitly approve it and start it once. Retries return the same run; changed/stale bindings, expired reviews and restarted runtimes require a new review. Pause, resume and cancel use the existing run controls.

Plans, execution receipts and approval audit events persist locally. Approval applies to a server-built proposal execution, not later canvas edits; ordinary manual runs remain a separate flow. CLI-internal requests remain uncounted by the native budget. See [planning contracts](docs/EVIDENCE-PLANNING.md) and [execution bindings and limits](docs/PROPOSAL-EXECUTION.md).

Native HTTP proposals also offer **Repeat GET stability** and **CORS response policy** profiles. Each binds a baseline and variant to the same URL, requires explicit approval for two native operations and retains both captures plus a versioned comparison. Runs and supported linked findings show the evidence, differences and coverage limits. A profile signal never automatically verifies or resolves a finding. See [controlled verification](docs/CONTROLLED-VERIFICATION.md).

## AI integration

Install the optional, pinned CAI dependency snapshot in a separate local interpreter:

```bash
python3 -m venv .venv-cai
.venv-cai/bin/python -m pip install -r requirements-cai.lock
export CAI_PYTHON="$PWD/.venv-cai/bin/python"
```

CAI 0.5.10 pins an older OpenAI/LiteLLM/web dependency stack. Keeping it separate lets the API use its supported FastAPI/Starlette versions without dependency conflicts. The SDK worker opens no HTTP listener or proxy service. Model inference uses the configured endpoint; target HTTP/TCP calls are delegated back to the parent application's scope and budget checks. Worker messages and lifetime are bounded. This isolates dependencies, not operating-system network access.

### Local model endpoint

For a tool-capable model served through a local OpenAI-compatible API:

```bash
export CAI_MODEL_BASE_URL=http://127.0.0.1:11434/v1
export CAI_MODEL=your-installed-model
./start-local.sh
```

### Remote model endpoint

Remote inference is a separate, explicit choice:

```bash
export CAI_ALLOW_REMOTE_MODEL=1
export CAI_MODEL_BASE_URL=https://your-provider.example/v1
export CAI_MODEL=your-model-id
# Set CAI_MODEL_API_KEY securely in your server-side environment if required.
./start-local.sh
```

When enabled, the configured provider receives the goal and selected evidence. Credentials remain server-side. Model names cannot silently route to another provider; the adapter uses the configured endpoint. SDK tracing is disabled.

The **CAI evidence analyst** and **evidence-guided proposal planner** have no target tools. The evidence analyst reviews at most 12 supplied HTTP records, with selected metadata and up to 1,200 body characters per record. Full captured responses remain in local artifacts. Schema validation and artifact-reference checks establish provenance, not the factual correctness of a model's claim.

The separate CAI assessment preset uses application-owned scoped HTTP/TCP tools. No arbitrary CAI shell or browser tools are attached.

## Architecture

```mermaid
flowchart TD
    UI["React workflow studio"] --> API["Local FastAPI"]
    API --> DAG["Validated DAG runner"]
    DAG --> N["Native HTTP / TCP"]
    DAG --> C["CLI adapters"]
    DAG --> A["CAI evidence review"]
    N --> DB["SQLite and artifacts"]
    C --> DB
    A --> DB
```

| Path | Purpose |
| --- | --- |
| `src/` | React UI, typed canvas, catalog browser, node inspector and agent desk |
| `backend/app.py` | Local API, run admission, controls and native target tools |
| `backend/workflows.py` | DAG validation, scheduling, node state and evidence linkage |
| `backend/cli_runner.py` | Argument construction, process lifecycle and bounded CLI artifacts |
| `backend/catalog*.py` | Catalog contracts, import, preflight and capability planning |
| `backend/cai_adapter.py` | Explicit-endpoint CAI SDK integration |
| `third-party/mini-tricky/` | Pinned MIT source catalog, attribution and wordlists |
| `scripts/migrate-catalog.py` | Reproducible offline conversion and drift checks |
| `backend/tests/`, `tests/` | Python integration and JavaScript contract/build tests |

## Execution boundaries

### Scope

| Entered target | Native authorization boundary |
| --- | --- |
| `example.com` | Exact host; discovered subdomains need separate active authorization |
| `192.168.1.10` or an IPv6 address | Exact IP |
| `10.10.0.0/24` | Addresses inside the CIDR, subject to host limits |
| `https://app.example.com/api` | HTTPS, exact host/port, `/api` and descendants; no general port enumeration |

Native HTTP requests validate and pin the resolved destination, preserve Host/TLS naming and never automatically follow redirects. Special-use destinations such as metadata/link-local addresses are blocked. Explicit loopback and LAN labs are supported.

### Native tools and external binaries have different accounting

**`max_requests` counts native HTTP/TCP admissions. `max_cli_invocations` counts CLI process launches.** The native request cap does not count or constrain network requests inside a binary.

CLI adapters screen inputs against the selected run scope and use application-owned argument vectors. They do not use the native pinned-address HTTP transport. A binary may resolve destinations, follow links, contact providers or update its own data internally. This is application-level control, **not an OS network sandbox**.

Processes use private working directories, bounded stdout/stderr and file artifacts, node deadlines and executable hash checks. POSIX pause/resume and cleanup operate on process groups. Windows behavior and deliberately daemonized children have not been validated here; see the [migration notes](docs/CATALOG-MIGRATION.md).

The local API checks loopback peers, Host, Origin and JSON writes. It has no multi-user authentication and is intended for a single-user machine. Publishing this source repository does not deploy the running service.

## Development

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
npm ci

npm run dev                       # Python API + Vite, local development
.venv/bin/python -m pytest backend/tests -q
.venv/bin/python scripts/migrate-catalog.py --check
npm run build
npm test
npx playwright install chromium  # one-time browser test setup
npm run test:browser             # disposable local fixture server
```

To regenerate the committed catalog after editing the pinned source descriptors:

```bash
.venv/bin/python scripts/migrate-catalog.py
```

Runtime catalog reads use generated JSON; PyYAML is only needed for migration/development checks.

### Verification status

The historical 0.4 baseline and the current 0.5 checks are documented in [the validation record](docs/VALIDATION.md). The 0.5 suite adds evidence parsing, migration, persistence, concurrency, review and comparison coverage.

The adapter matrix uses executable fixtures across all 151 entries: 141 exercise execution contracts and ten assert their explicit restrictions. Those fixtures do not establish compatibility with every external tool version. CAI tests use local model fixtures; the three SDK tests skip when the optional SDK is absent. The URO test skips if that binary is unavailable beside the selected Python interpreter.

Chromium workbench and evidence-guided planning interaction regressions run in CI. Broader desktop/platform QA and real-binary version validation remain open. See [the validation record](docs/VALIDATION.md).

### Team budgets and passive cache reliability

Multi-agent assessments now have a combined model-turn ceiling, including the
optional lead synthesizer. Configure **Total team model turns** in Run setup or
on a CAI team analyst node. Reports show each pass's reserved ceiling and explicit
coverage gaps for skipped or incomplete analysts. See [defaults, API fields and
allocation semantics](docs/TEAM-BUDGETS.md).

Passive response caching is isolated by the selected provider credentials.
Changing an API key or a pagination limit triggers a fresh fetch. The in-memory
LRU expires old entries and bounds retained queries; setting the TTL to zero
disables cache reads and writes. Each enrichment still creates its own evidence
artifacts and run provenance.

### Checkpointed workflow recovery

Recover selected branches from a stopped workflow through **Local workspace →
Runs → Recover workflow branches**. Review which steps execute again and which
upstream outputs are reused, then approve a new run bound to the original scope,
budgets, input hashes and executable pins. Reused captures retain their original
age and provenance. See [recovery contracts and limits](docs/WORKFLOW-RECOVERY.md).

### Actual model usage

The **Usage** tab and per-run panels show admitted model call attempts, responses
and provider-reported tokens, with per-node and specialist-role attribution.
Missing reports stay unknown, and old runs show usage unavailable. Planning and
recovery have separate accounting. Records survive failures and runtime restarts,
including isolated CAI workers. See [counter definitions and API](docs/MODEL-USAGE.md).

## Configuration and compatibility

| Variable | Purpose |
| --- | --- |
| `AI_TRICKY_DATA_DIR` | Override the local database, input and evidence directory |
| `CAI_PYTHON` | Python executable in the separate optional CAI environment |
| `CAI_MODEL_BASE_URL` | Explicit local or permitted remote model endpoint |
| `CAI_MODEL` | Model identifier at that endpoint |
| `CAI_MODEL_API_KEY` | Optional server-side provider credential |
| `CAI_ALLOW_REMOTE_MODEL=1` | Permit a remote HTTPS model endpoint |
| `AI_TRICKY_ALLOW_PASSIVE=1` | Enable explicit passive-provider enrichment |
| `AI_TRICKY_PASSIVE_MAX_PAGES` | Provider pagination ceiling: default 3, range 1–10 |
| `AI_TRICKY_PASSIVE_CACHE_TTL` | In-memory cache lifetime in seconds: default 900, range 0–86400; zero disables caching |
| `AI_TRICKY_PASSIVE_CACHE_ENTRIES` | In-memory LRU query capacity: default 128, range 1–1024 |

AI-tricky continues the Offsecs-u-AI prototype. Existing `OFFSECS_U_AI_*` and `RECONFORGE_*` environment names remain supported. Existing database selection and the `offsecs-u-ai.workflow/v1` interchange schema are retained; legacy `reconforge.prototype.workflow/v1` imports remain readable. These identifiers are compatibility details, not separate products.

## Roadmap

- Dedicated account, cluster, callback and notification contracts for restricted catalog entries.
- Real-binary compatibility coverage across supported tool versions and platforms.
- Additional controlled replay profiles and evidence-age policies for recovery.
- Controlled multi-identity testing and reviewed reuse of unused model-turn allowances.
- Burp/burpaderp and Strix integration through their own policy and evidence contracts.
- Broader desktop/platform QA and refinement of the workflow studio.

## Attribution and license

Created by [Victor Åhgren / MKlolbullen](https://github.com/MKlolbullen), building on the architecture and catalog of [mini-tricky](https://github.com/MKlolbullen/mini-tricky).

Application code is licensed under [MIT](LICENSE). The mini-tricky catalog is pinned to commit `96971000b0058423da52884d9028250ab76b0633`, with its MIT license retained. Other curated examples and descriptors are documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). This is not the complete hosted Trickest service or its proprietary wrappers.

External binaries, model providers and SDKs retain their own licenses. The optional CAI 0.5.10 package has mixed MIT/proprietary terms and is not bundled. Use AI-tricky only for systems and data you are authorized to assess.
