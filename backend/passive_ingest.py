"""Passive-source ingestion: query provider APIs (gated, allowlisted, read-only)
and fold the responses into the asset graph as provenance-tagged third-party
claims. The outbound client is the only place that performs network I/O and is
the single enforcement point for the opt-in gate and the provider allowlist."""
import os
from urllib.parse import urlsplit

from .passive_sources import ADAPTERS, ALLOWED_HOSTS, query_types


def passive_enabled():
    """Passive outbound egress is opt-in, like remote model use."""
    return os.environ.get('AI_TRICKY_ALLOW_PASSIVE') == '1'


async def default_passive_http(req):
    """Perform one provider request (GET or POST). Enforces HTTPS, the provider
    allowlist and the opt-in gate; target scope is irrelevant here — these are
    provider endpoints, never the assessment target."""
    import httpx
    parts = urlsplit(req['url'])
    if parts.scheme != 'https' or parts.hostname not in ALLOWED_HOSTS:
        raise RuntimeError('Passive request blocked: not an allowed provider endpoint.')
    if not passive_enabled():
        raise RuntimeError('Passive outbound is disabled.')
    async with httpx.AsyncClient(trust_env=False, timeout=20, follow_redirects=False) as client:
        method = (req.get('method') or 'GET').upper()
        response = await client.request(method, req['url'], headers=req.get('headers') or {}, json=req.get('json'))
        response.raise_for_status()
        return response.json()


class PassiveIngestor:
    def __init__(self, store, asset_graph):
        self.store = store
        self.asset_graph = asset_graph

    async def enrich(self, target, target_kind, providers, credentials, http):
        """Query each provider for `target`, persist each raw response as a
        provenance artifact, and index the artifacts into the asset graph. A
        provider failure is a coverage gap, not an aborted enrichment."""
        run = self.store.new_run({'engine': 'passive', 'targets': [target], 'providers': providers,
                                  'max_requests': 0, 'max_cli_invocations': 0})
        rid = run['id']
        summary = []
        for pid in providers:
            adapter = ADAPTERS[pid]
            report = {'provider': pid, 'name': adapter['name'], 'queries': 0, 'status': 'ok'}
            for qt in query_types(pid, target_kind):
                try:
                    # A provider may define `collect` to orchestrate a multi-step
                    # flow (still through the gated, allowlisted `http`); simple
                    # providers just issue the single request `build` describes.
                    if 'collect' in adapter:
                        response = await adapter['collect'](http, qt, target, credentials)
                    else:
                        response = await http(adapter['build'](qt, target, credentials))
                    # Store only provider/query/response — never the request URL,
                    # which may carry the key for providers that authenticate by
                    # query parameter.
                    self.store.artifact(rid, f'passive-{pid}-{qt}.json',
                                        {'provider': pid, 'query_type': qt, 'query': target, 'response': response})
                    report['queries'] += 1
                except Exception as exc:  # noqa: BLE001 - surface as a coverage gap, no secrets
                    report['status'] = 'failed'
                    report['reason'] = (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__)[:200]
                    break
            summary.append(report)
        # Build the graph from the new passive artifacts (idempotent).
        self.asset_graph.index_pending(rid)
        completed = sum(r['status'] == 'ok' for r in summary)
        self.store.status(rid, 'completed', {'engine': 'passive', 'evidence_status': 'OBSERVATION',
                                             'report': f'Passive enrichment of {target}: {completed}/{len(summary)} provider(s) completed. Third-party claims, not confirmed findings.',
                                             'summary': summary})
        return {'run_id': rid, 'target': target, 'summary': summary}
