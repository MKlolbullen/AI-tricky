import asyncio
import json

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.asset_graph import AssetGraph
from backend.passive_ingest import PassiveIngestor
from backend.store import Store


def test_key_rotation_fetches_fresh_evidence_instead_of_reusing_another_identity(tmp_path):
    calls = []

    async def http(req):
        calls.append(req['headers']['x-apikey'])
        return {'data': [{'id': ('first' if len(calls) == 1 else 'second') + '.example.com'}]}

    with TestClient(create_app(tmp_path, passive_http=http)) as c:
        c.post('/api/targets', json={'value': 'example.com'})
        c.post('/api/credentials', json={'updates': {'VIRUSTOTAL_API_KEY': 'old-private-key'}})
        body = {'target': 'example.com', 'providers': ['virustotal']}
        first = c.post('/api/assets/enrich', json=body).json()
        assert first['summary'][0]['source'] == 'live'
        c.post('/api/credentials', json={'updates': {'VIRUSTOTAL_API_KEY': 'new-private-key'}})
        second = c.post('/api/assets/enrich', json=body).json()
        assert second['summary'][0]['source'] == 'live'
        third = c.post('/api/assets/enrich', json=body).json()
        assert third['summary'][0]['source'] == 'cache'
        assert calls == ['old-private-key', 'new-private-key']
        entities = c.get('/api/assets/graph?run_id=' + second['run_id']).json()['entities']
        hosts = {e['canonical'] for e in entities if e['kind'] == 'host'}
        assert 'second.example.com' in hosts and 'first.example.com' not in hosts
        for result in (first, second, third):
            for a in c.get('/api/runs/' + result['run_id'] + '/artifacts').json():
                content = c.get('/api/artifacts/' + a['id']).text
                assert 'private-key' not in content
            assert 'private-key' not in json.dumps(result)


def test_cache_identity_uses_all_and_only_declared_provider_credentials(tmp_path):
    store = Store(tmp_path)
    ingestor = PassiveIngestor(store, AssetGraph(store))
    creds = {'CENSYS_API_ID': 'id-one', 'CENSYS_API_SECRET': 'private-secret', 'SHODAN_API_KEY': 'unrelated'}
    original = ingestor._cache_key('censys', 'ip', '192.0.2.1', creds)
    assert original != ingestor._cache_key('censys', 'ip', '192.0.2.1', {**creds, 'CENSYS_API_ID': 'id-two'})
    assert original != ingestor._cache_key('censys', 'ip', '192.0.2.1', {**creds, 'CENSYS_API_SECRET': 'different'})
    assert original == ingestor._cache_key('censys', 'ip', '192.0.2.1', {**creds, 'SHODAN_API_KEY': 'changed'})
    assert original != PassiveIngestor(store, AssetGraph(store))._cache_key('censys', 'ip', '192.0.2.1', creds)
    assert all(value not in repr(original) for value in creds.values())


def test_cache_expiry_zero_ttl_and_capacity_do_not_retain_unbounded_responses(tmp_path, monkeypatch):
    store = Store(tmp_path)
    ingestor = PassiveIngestor(store, AssetGraph(store))
    clock = [100.0]
    monkeypatch.setattr('backend.passive_ingest.time.monotonic', lambda: clock[0])
    monkeypatch.setenv('AI_TRICKY_PASSIVE_CACHE_ENTRIES', '2')
    monkeypatch.setenv('AI_TRICKY_PASSIVE_CACHE_TTL', '60')
    seen = []

    async def http(req):
        seen.append(req)
        return {'data': []}

    async def enrich(target):
        return await ingestor.enrich(target, 'domain', ['virustotal'], {'VIRUSTOTAL_API_KEY': 'key'}, http)

    async def exercise():
        await enrich('a.example.com')
        await enrich('b.example.com')
        assert (await enrich('a.example.com'))['summary'][0]['source'] == 'cache'  # a is now most recent
        await enrich('c.example.com')
        assert len(ingestor._cache) == 2
        assert (await enrich('b.example.com'))['summary'][0]['source'] == 'live'  # b was evicted
        clock[0] += 61
        assert (await enrich('b.example.com'))['summary'][0]['source'] == 'live'
        assert len(ingestor._cache) == 1  # expired entries are pruned too
        monkeypatch.setenv('AI_TRICKY_PASSIVE_CACHE_TTL', '0')
        for _ in range(2):
            assert (await enrich('b.example.com'))['summary'][0]['source'] == 'live'
            assert not ingestor._cache

    asyncio.run(exercise())
    assert len(seen) == 7


def test_pagination_configuration_is_bound_to_cache_results(tmp_path, monkeypatch):
    store = Store(tmp_path)
    ingestor = PassiveIngestor(store, AssetGraph(store))
    monkeypatch.setenv('AI_TRICKY_PASSIVE_MAX_PAGES', '1')
    seen = []

    async def http(req):
        seen.append(req)
        return {'results': [['192.0.2.1', '443', 'api.example.com', 'nginx']]}

    async def exercise():
        args = ('example.com', 'domain', ['fofa'], {'FOFA_EMAIL': 'a@b.c', 'FOFA_KEY': 'private'}, http)
        assert (await ingestor.enrich(*args))['summary'][0]['queries'] == 1
        monkeypatch.setenv('AI_TRICKY_PASSIVE_MAX_PAGES', '2')
        result = await ingestor.enrich(*args)
        assert result['summary'][0]['source'] == 'live'
        assert result['summary'][0]['queries'] == 2

    asyncio.run(exercise())
    assert len(seen) == 3
