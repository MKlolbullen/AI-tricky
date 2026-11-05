# Passive-source ingestion — design

**Status:** draft for review · **Date:** 2026-11-05 · **Author:** (proposed)

Enrich the asset graph with **third-party passive intelligence** — Shodan,
Censys, VirusTotal, FOFA, BeVigil, Netlas, Hunter.io, ZoomEye — to add hosts,
IPs, services, technologies, certificates, netblocks/ASNs, contacts and
**vulnerability claims** with their relationships. Every passive record is
**provenance-tagged to its provider** and treated as a third-party *claim*,
never as a locally captured fact and never as a confirmed finding.

This is the v2 of the asset graph (`docs/design/evidence-asset-graph.md`), and
it crosses a boundary the graph has not crossed before: **outbound calls to
provider APIs**. It must be gated, bounded and clearly sourced.

---

## 1. What changes, and the trust boundary

Today the asset graph is built only from locally captured artifacts and makes
**no network calls**. Passive ingestion adds:

- **Outbound HTTPS to provider APIs** (api.shodan.io, search.censys.io, …) —
  *not* to the assessment target. These are a distinct allowlist from target
  scope, and this traffic is the thing to gate.
- **Credential injection** from the server-owned vault (the keys already stored
  under the `passive` category), snapshotted per enrichment like a run.
- **Third-party claims.** Passive data is what a provider *asserts*, not what we
  observed. Each entity/edge carries `source=<provider>` (the graph already keys
  provenance by source), and the raw provider response is stored as a
  provenance artifact so the claim is auditable.

Three hard rules:

1. **Passive ≠ captured.** Provider records never merge into or overwrite
   capture-derived (`scoped-http`/`native-tcp`) entities; they coexist with
   their own source. The UI shows the source on every node/edge.
2. **Vulnerabilities are claims, not findings.** Shodan/ZoomEye/etc. report CVEs.
   These become `vulnerability` **graph entities** labelled with their provider,
   never `findings`, never `verified`, never auto-confirmed — consistent with
   "scanner/model output must not overwrite operator reviews or automatically
   verify a finding."
3. **Opt-in and bounded.** Outbound passive queries happen only on explicit
   request, only for providers with a stored key, within a per-enrichment query
   budget, for an entered-scope target.

---

## 2. Providers (v1)

Each adapter is declarative: a credential variable (reused from the vault), the
base URL, the query shapes it supports, and a pure `map(response, query)` that
emits typed graph records with `source=<provider>`. New providers to add to the
credential registry: **BeVigil, Hunter.io, ZoomEye** (the rest already exist).

| Provider | Credential | Query by | Contributes |
| -------- | ---------- | -------- | ----------- |
| Shodan | `SHODAN_API_KEY` | ip, domain | services, technologies, **vulns (CVEs)**, netblock/ASN |
| Censys | `CENSYS_API_ID`+`CENSYS_API_SECRET` | ip, domain | services, certificates, technologies, ASN |
| VirusTotal | `VIRUSTOTAL_API_KEY` | domain, ip | subdomains, resolutions, detected technologies |
| FOFA | `FOFA_EMAIL`+`FOFA_KEY` | domain, ip | hosts, services, technologies, certificates |
| BeVigil | `BEVIGIL_API_KEY` *(new)* | domain | subdomains, mobile-app-derived hosts/URLs |
| Netlas | `NETLAS_API_KEY` | domain, ip | hosts, services, certificates, tech |
| Hunter.io | `HUNTER_API_KEY` *(new)* | domain | **contacts/emails**, email patterns |
| ZoomEye | `ZOOMEYE_API_KEY` *(new)* | ip, domain | services, technologies, **vulns**, netblock |

---

## 3. New entity & edge kinds

Extends the v1 entity set (host, ip, service, technology, file):

| Entity | Identity | From |
| ------ | -------- | ---- |
| `netblock` | CIDR or ASN | Shodan, Censys, ZoomEye |
| `certificate` | cert SHA-256 | Censys, FOFA, Netlas |
| `vulnerability` | CVE id (+ provider) | Shodan, ZoomEye |
| `contact` | email / email-pattern | Hunter.io |

New edges: `member_of` (ip → netblock), `covers` (certificate → host),
`reported_vulnerable` (service/host → vulnerability, carrying the asserting
provider), `has_contact` (host/domain → contact). Each edge keeps the existing
`(rel, src, dst, source)` identity, so the same CVE asserted by two providers is
two sourced edges, not a silent merge.

---

## 4. Framework

- `backend/passive_sources.py` — the adapter registry: one entry per provider
  with `{credential_vars, base_url, supports:[by_domain,by_ip], request(query,
  creds)->(url,headers,params), map(response, query)->records}`. `map` is pure
  and unit-testable; `request` builds the call but performs no I/O.
- `backend/passive_ingest.py` — `PassiveIngestor(store, asset_graph, vault)`:
  given a target + selected providers + a credential snapshot, it calls each
  provider through a single injected `http` fetcher (so it is fully mockable and
  outbound I/O is centralized behind one allowlisted client), stores each raw
  response as a provenance artifact (`passive-<provider>-<n>.json`), maps it to
  records, and writes entities/edges into the `AssetGraph` with
  `source=<provider>`. Per-provider failures are coverage gaps, not a failed
  enrichment.
- Reuses `AssetGraph` storage/versioning and `canonical_asset`/`digest`. The raw
  response artifact gives the same artifact-id provenance chain capture evidence
  has, so `GET /api/assets/{id}` shows which provider asserted each node.

### Outbound fetcher & gating (the security-critical piece)

A single `passive_http` client that:
- only reaches the **provider API allowlist** (never target scope, never
  arbitrary URLs), enforced like `model_base_url` enforces the model endpoint;
- attaches the vault credential for that provider from the per-run snapshot;
- is disabled unless passive outbound is explicitly enabled (see decision #1),
  returning a clear 409 otherwise — the same opt-in philosophy as remote model
  use (`CAI_ALLOW_REMOTE_MODEL`).

---

## 5. API

- `POST /api/assets/enrich` — `{target, providers:[...], query_types?}`. Resolves
  each provider's key from the vault (409 if missing), snapshots credentials,
  runs the ingestor under the passive budget, returns a per-provider summary
  (added entities/edges, claims, coverage gaps). No target traffic; provider
  traffic only.
- `GET /api/runtime` gains `passive_providers` (each passive credential + its
  configured/enabled state) for the UI, mirroring `model_providers`.
- The graph reads (`/api/assets/graph`, `/api/assets/{id}`) already carry
  `source`; the UI surfaces it.

---

## 6. UI

- In the **Asset graph** tab: an "Enrich from passive sources" panel — pick a
  target and the providers that have a stored key (others shown disabled with
  "add key in Credentials"), run, and watch the graph gain source-badged nodes.
- Every entity/edge shows a **source badge**; a filter to show capture-only vs a
  given provider. `vulnerability` and `contact` nodes are clearly tagged as
  third-party claims.

---

## 7. Invariants preserved

- [x] Passive data is sourced and never merged into capture-derived facts.
- [x] Vulnerabilities/claims are graph entities, never findings, never verified.
- [x] Outbound is opt-in, allowlisted to provider APIs, bounded, credentialed
      from the per-run snapshot; keys never returned to the client.
- [x] Provenance preserved (raw response artifact + source + version);
      append-only; existing DBs unchanged.
- [x] Platform hosting stays local; this adds provider egress only.
- [x] Deterministic — no model involvement in ingestion.

---

## 8. Phasing

- **v1 — framework + adapters + mock-tested ingestion.** `passive_sources.py`
  (all eight adapters, declarative + pure mappers), `passive_ingest.py`, the
  gated outbound client, `POST /api/assets/enrich`, the three new credential
  providers, the new entity/edge kinds, and the Asset graph enrich UI. Mappers
  are unit-tested against recorded/sample response fixtures; the end-to-end path
  is tested with an injected fetcher. Real provider calls require stored keys +
  passive outbound enabled.
- **v2 — robustness.** Pagination, provider rate-limit/quota handling, response
  caching/TTL, and graph diffing across enrichment runs.

---

## 9. Decisions needed before coding

1. **Outbound gating (security-critical).** Passive queries egress to provider
   APIs. Gate them behind an explicit opt-in (an env flag like
   `AI_TRICKY_ALLOW_PASSIVE=1`, plus a stored key) — recommended, mirrors the
   remote-model gate — or treat a stored key as sufficient intent?
2. **v1 provider breadth.** Ship all eight adapters in v1 (declarative + pure
   mappers, mock-tested), or a core subset (Shodan/Censys/VirusTotal/Netlas)
   fully wired first with the rest following? Recommended: all eight, since each
   is a small declarative adapter and mappers are independently testable.
3. **Vulnerability representation.** `vulnerability` entity keyed by CVE with
   per-provider `reported_vulnerable` edges (recommended), confirming these are
   claims only and never feed the findings workbench automatically.
4. **Enrichment target.** Enrich only an entered-scope target (recommended), or
   allow enriching any host already present in the graph?
