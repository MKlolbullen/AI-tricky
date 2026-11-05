from fastapi.testclient import TestClient

from backend.app import create_app
from backend.asset_graph import AssetGraph
from backend.store import Store
from backend.tests.test_local import target_server, wait_done


def _seed(store):
    run = store.new_run({'engine': 'inventory', 'targets': ['https://api.example.com/app']})
    rid = run['id']
    store.artifact(rid, 'http-1.json', {'url': 'https://api.example.com/app', 'status': 200,
                                        'connected_ip': '93.184.216.34',
                                        'headers': {'Server': 'nginx', 'X-Powered-By': 'PHP/8.1'}})
    store.artifact(rid, 'tcp-inventory.json', [
        {'host': 'api.example.com', 'ip': '93.184.216.34', 'port': 443, 'state': 'open'},
        {'host': 'api.example.com', 'port': 22, 'state': 'closed_or_filtered'}])
    return rid


def test_extractors_build_a_provenance_bound_host_graph(tmp_path):
    store = Store(tmp_path)
    rid = _seed(store)
    g = AssetGraph(store)
    graph = g.graph(run_id=rid)
    canon = {(e['kind'], e['canonical']) for e in graph['entities']}
    assert {'host', 'ip', 'service', 'technology', 'file'} <= {k for k, _ in canon}
    assert ('host', 'api.example.com') in canon and ('host', 'example.com') in canon  # subdomain_of parent
    assert ('ip', '93.184.216.34') in canon
    assert ('service', 'api.example.com:443/tcp') in canon
    assert ('technology', 'nginx') in canon and ('technology', 'php/8.1') in canon
    assert ('file', 'https://api.example.com/app') in canon
    rels = {e['rel'] for e in graph['edges']}
    assert {'subdomain_of', 'resolves_to', 'exposes', 'runs', 'serves'} <= rels
    # A closed port is never exposed.
    assert ('service', 'api.example.com:22/tcp') not in canon


def test_entity_detail_carries_edges_and_provenance(tmp_path):
    store = Store(tmp_path)
    rid = _seed(store)
    g = AssetGraph(store)
    host = next(e for e in g.graph(run_id=rid)['entities'] if e['kind'] == 'host' and e['canonical'] == 'api.example.com')
    detail = g.entity(host['id'])
    assert detail['provenance'] and all(p['run_id'] == rid for p in detail['provenance'])
    rels = {(e['rel'], e['other_kind']) for e in detail['edges']}
    assert ('exposes', 'service') in rels and ('resolves_to', 'ip') in rels and ('runs', 'technology') in rels
    assert ('subdomain_of', 'host') in rels


def test_indexing_is_idempotent(tmp_path):
    store = Store(tmp_path)
    rid = _seed(store)
    g = AssetGraph(store)
    first = g.graph(run_id=rid)
    g.index_pending(rid)
    g.index_pending()
    second = g.graph(run_id=rid)
    assert len(first['entities']) == len(second['entities'])
    assert len(first['edges']) == len(second['edges'])


def _seed_shodan(store, cve):
    rid = store.new_run({'engine': 'passive', 'targets': ['1.2.3.4']})['id']
    store.artifact(rid, 'passive-shodan-ip-0.json',
                   {'provider': 'shodan', 'query_type': 'ip', 'query': '1.2.3.4',
                    'response': {'ip_str': '1.2.3.4', 'data': [{'port': 443, 'product': 'nginx', 'vulns': {cve: {}}}]}})
    AssetGraph(store).index_pending(rid)
    return rid


def test_graph_diff_classifies_new_unchanged_and_not_observed(tmp_path):
    store = Store(tmp_path)
    ra = _seed_shodan(store, 'CVE-2021-1')
    rb = _seed_shodan(store, 'CVE-2021-2')
    diff = AssetGraph(store).diff(ra, rb)
    states = {(e['kind'], e['canonical']): e['state'] for e in diff['entities']}
    assert states[('ip', '1.2.3.4')] == 'unchanged'
    assert states[('service', '1.2.3.4:443/tcp')] == 'unchanged'
    assert states[('vulnerability', 'CVE-2021-1')] == 'not_observed'
    assert states[('vulnerability', 'CVE-2021-2')] == 'new'
    assert diff['summary']['new'] >= 1 and diff['summary']['not_observed'] >= 1
    # Edges are classified too (the CVE-A link disappears, CVE-B appears).
    edge_states = {(e['rel'], e['dst_canonical']): e['state'] for e in diff['edges']}
    assert edge_states[('reported_vulnerable', 'CVE-2021-1')] == 'not_observed'
    assert edge_states[('reported_vulnerable', 'CVE-2021-2')] == 'new'


def test_asset_diff_api_and_validation(tmp_path):
    store = Store(tmp_path)
    ra = _seed_shodan(store, 'CVE-2021-1')
    rb = _seed_shodan(store, 'CVE-2021-2')
    with TestClient(create_app(tmp_path)) as c:
        r = c.get(f'/api/assets/diff?baseline={ra}&current={rb}')
        assert r.status_code == 200, r.text
        states = {(e['kind'], e['canonical']): e['state'] for e in r.json()['entities']}
        assert states[('vulnerability', 'CVE-2021-1')] == 'not_observed'
        assert states[('vulnerability', 'CVE-2021-2')] == 'new'
        assert 'absence_means' in r.json()
        assert c.get(f'/api/assets/diff?baseline={ra}&current={ra}').status_code == 422
        assert c.get(f'/api/assets/diff?baseline={ra}&current=missing').status_code == 404


def test_asset_graph_api_end_to_end(tmp_path, target_server):
    base, _ = target_server
    with TestClient(create_app(tmp_path)) as c:
        tid = c.post('/api/targets', json={'value': base}).json()['id']
        rid = c.post('/api/runs', json={'engine': 'inventory', 'target_ids': [tid], 'allow_http': True, 'max_requests': 4}).json()['id']
        assert wait_done(c, rid)['status'] == 'completed'
        graph = c.get('/api/assets/graph?run_id=' + rid).json()
        assert graph['entities'] and 'absence_means' in graph
        eid = graph['entities'][0]['id']
        assert c.get('/api/assets/' + eid).json()['id'] == eid
        assert c.get('/api/assets/does-not-exist').status_code == 404
        assert c.get('/api/assets/graph?kind=bogus').status_code == 422
        # kind filter returns only that kind.
        hosts = c.get('/api/assets/graph?run_id=' + rid + '&kind=service').json()
        assert all(e['kind'] == 'service' for e in hosts['entities'])
