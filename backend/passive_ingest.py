"""Passive-source ingestion: query provider APIs (gated, allowlisted, read-only)
and fold the responses into the asset graph as provenance-tagged third-party
claims. The outbound client is the only place that performs network I/O and is
the single enforcement point for the opt-in gate and the provider allowlist.

Robustness: bounded pagination (adapters that set `pages` are fetched page by
page until a page yields no records or the page cap is hit), explicit rate-limit
and quota handling (surfaced as clear coverage gaps), and an in-process TTL cache
so repeated enrichment of the same target does not re-spend provider quota.
"""
from collections import OrderedDict
import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import urlsplit

from .passive_sources import ADAPTERS, ALLOWED_HOSTS, parse_response, query_types


def passive_enabled():
    """Passive outbound egress is opt-in, like remote model use."""
    return os.environ.get('AI_TRICKY_ALLOW_PASSIVE') == '1'


def _bounded(name, default, low, high):
    try:
        return max(low, min(int(os.environ.get(name, str(default))), high))
    except (TypeError, ValueError):
        return default


def max_pages():
    return _bounded('AI_TRICKY_PASSIVE_MAX_PAGES', 3, 1, 10)


def cache_ttl():
    return _bounded('AI_TRICKY_PASSIVE_CACHE_TTL', 900, 0, 86400)


async def default_passive_http(req):
    """Perform one provider request (GET or POST). Enforces HTTPS, the provider
    allowlist and the opt-in gate; target scope is irrelevant here — these are
    provider endpoints, never the assessment target. Rate-limit and quota
    responses become clear, non-secret errors the ingestor records as gaps."""
    import httpx
    parts = urlsplit(req['url'])
    if parts.scheme != 'https' or parts.hostname not in ALLOWED_HOSTS:
        raise RuntimeError('Passive request blocked: not an allowed provider endpoint.')
    if not passive_enabled():
        raise RuntimeError('Passive outbound is disabled.')
    async with httpx.AsyncClient(trust_env=False, timeout=20, follow_redirects=False) as client:
        method = (req.get('method') or 'GET').upper()
        response = await client.request(method, req['url'], headers=req.get('headers') or {}, json=req.get('json'))
        if response.status_code == 429:
            raise RuntimeError('Provider rate limit reached (HTTP 429); try again later.')
        if response.status_code in (402, 403):
            raise RuntimeError(f'Provider refused the request (HTTP {response.status_code}): quota exhausted or key not authorized.')
        response.raise_for_status()
        return response.json()


class PassiveIngestor:
    def __init__(self, store, asset_graph):
        self.store = store
        self.asset_graph = asset_graph
        # Memory-only, bounded LRU. Identity uses a per-process keyed digest of
        # the adapter's declared credentials; no raw keys or stable key hashes
        # enter the cache index, events, artifacts or public summaries.
        self._cache = OrderedDict()
        self._cache_salt = secrets.token_bytes(32)

    def _cache_key(self, pid, qt, query, credentials):
        identity = json.dumps([(v, credentials.get(v)) for v in ADAPTERS[pid]['vars']],
                              separators=(',', ':')).encode()
        digest = hmac.new(self._cache_salt, identity, hashlib.sha256).digest()
        return pid, qt, query, digest, max_pages(), cache_ttl()

    def _prune_cache(self):
        now = time.monotonic()
        for key, (expires, _) in list(self._cache.items()):
            if expires <= now or not cache_ttl():
                del self._cache[key]
        capacity = _bounded('AI_TRICKY_PASSIVE_CACHE_ENTRIES', 128, 1, 1024)
        while len(self._cache) > capacity:
            self._cache.popitem(last=False)

    async def _fetch(self, http, adapter, pid, qt, query, credentials):
        """Return the list of raw page responses for one provider query. A
        `collect` adapter drives its own (possibly multi-step) flow; a paginated
        adapter is fetched page by page until an empty page or the cap; a simple
        adapter issues one request."""
        if 'collect' in adapter:
            return [await adapter['collect'](http, qt, query, credentials)]
        if adapter.get('pages'):
            pages = []
            for page in range(1, max_pages() + 1):
                resp = await http(adapter['build'](qt, query, credentials, page=page))
                pages.append(resp)
                if not parse_response(pid, qt, query, resp):
                    break
            return pages
        return [await http(adapter['build'](qt, query, credentials))]

    async def enrich(self, target, target_kind, providers, credentials, http):
        """Query each provider for `target`, persist each raw response as a
        provenance artifact, and index the artifacts into the asset graph. A
        provider failure (including rate-limit/quota) is a coverage gap, not an
        aborted enrichment."""
        run = self.store.new_run({'engine': 'passive', 'targets': [target], 'providers': providers,
                                  'max_requests': 0, 'max_cli_invocations': 0})
        rid = run['id']
        summary = []
        for pid in providers:
            adapter = ADAPTERS[pid]
            report = {'provider': pid, 'name': adapter['name'], 'queries': 0, 'status': 'ok'}
            for qt in query_types(pid, target_kind):
                try:
                    self._prune_cache()
                    key = self._cache_key(pid, qt, target, credentials)
                    cached = self._cache.get(key)
                    if cached and cached[0] > time.monotonic():
                        responses = cached[1]
                        self._cache.move_to_end(key)
                        report['source'] = 'cache'
                    else:
                        responses = await self._fetch(http, adapter, pid, qt, target, credentials)
                        if cache_ttl():
                            self._cache[key] = (time.monotonic() + cache_ttl(), responses)
                            self._prune_cache()
                        report['source'] = 'live'
                    # Store only provider/query/response — never the request URL,
                    # which may carry the key for query-parameter auth.
                    for i, response in enumerate(responses):
                        self.store.artifact(rid, f'passive-{pid}-{qt}-{i}.json',
                                            {'provider': pid, 'query_type': qt, 'query': target, 'response': response})
                    report['queries'] += len(responses)
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
