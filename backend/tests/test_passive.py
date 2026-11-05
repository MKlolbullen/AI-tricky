import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.passive_sources import parse_response, query_types, ADAPTERS, ALLOWED_HOSTS

SHODAN_IP = {'ip_str': '93.184.216.34', 'asn': 'AS15133', 'org': 'Edgecast',
             'data': [{'port': 443, 'product': 'nginx', 'vulns': {'CVE-2021-23017': {}}},
                      {'port': 80, 'product': 'nginx'}]}
VT_SUBS = {'data': [{'id': 'api.example.com'}, {'id': 'dev.example.com'}, {'id': 'example.com'}]}


# -- pure mappers -------------------------------------------------------------
def test_shodan_ip_mapper_builds_services_tech_vuln_and_netblock():
    recs = parse_response('shodan', 'ip', '93.184.216.34', SHODAN_IP)
    ents = {(r['kind'], r['canonical']) for r in recs if r['t'] == 'e'}
    rels = {r['rel'] for r in recs if r['t'] == 'x'}
    assert ('ip', '93.184.216.34') in ents
    assert ('service', '93.184.216.34:443/tcp') in ents
    assert ('technology', 'nginx') in ents
    assert ('vulnerability', 'CVE-2021-23017') in ents
    assert ('netblock', 'AS15133') in ents
    assert {'exposes', 'runs', 'reported_vulnerable', 'member_of'} <= rels


def test_virustotal_mapper_builds_subdomain_edges():
    recs = parse_response('virustotal', 'domain', 'example.com', VT_SUBS)
    ents = {(r['kind'], r['canonical']) for r in recs if r['t'] == 'e'}
    assert ('host', 'api.example.com') in ents and ('host', 'dev.example.com') in ents
    subs = {tuple(r['src']) for r in recs if r['t'] == 'x' and r['rel'] == 'subdomain_of'}
    assert ('host', 'api.example.com') in subs
    # The apex itself is not its own subdomain.
    assert ('host', 'example.com') not in subs


def test_parse_response_is_defensive_and_scoped_to_supported_queries():
    assert parse_response('shodan', 'ip', 'x', 'not-a-dict') == []
    assert parse_response('virustotal', 'ip', 'x', {}) == []       # VT supports domain only
    assert query_types('shodan', 'ip') == ['ip'] and query_types('virustotal', 'ip') == []
    assert all('://' not in h for h in ALLOWED_HOSTS)


# -- endpoint gating ----------------------------------------------------------
def _fake_http():
    async def http(req):
        if 'api.shodan.io/shodan/host/' in req['url']:
            return SHODAN_IP
        if 'virustotal.com' in req['url']:
            return VT_SUBS
        raise RuntimeError('unexpected provider URL')
    return http


def test_enrich_requires_stored_key(tmp_path):
    with TestClient(create_app(tmp_path, passive_http=_fake_http())) as c:
        c.post('/api/targets', json={'value': '93.184.216.34'})
        r = c.post('/api/assets/enrich', json={'target': '93.184.216.34', 'providers': ['shodan']})
        assert r.status_code == 409 and 'SHODAN_API_KEY' in r.json()['detail']


def test_enrich_requires_passive_outbound_enabled_on_the_real_path(tmp_path, monkeypatch):
    monkeypatch.delenv('AI_TRICKY_ALLOW_PASSIVE', raising=False)
    with TestClient(create_app(tmp_path)) as c:  # no injected http -> real gate applies
        c.post('/api/targets', json={'value': '93.184.216.34'})
        c.post('/api/credentials', json={'updates': {'SHODAN_API_KEY': 'k'}})
        r = c.post('/api/assets/enrich', json={'target': '93.184.216.34', 'providers': ['shodan']})
        assert r.status_code == 409 and 'AI_TRICKY_ALLOW_PASSIVE' in r.json()['detail']


def test_enrich_rejects_unknown_provider_and_out_of_scope_target(tmp_path):
    with TestClient(create_app(tmp_path, passive_http=_fake_http())) as c:
        c.post('/api/targets', json={'value': 'example.com'})
        c.post('/api/credentials', json={'updates': {'VIRUSTOTAL_API_KEY': 'k'}})
        assert c.post('/api/assets/enrich', json={'target': 'example.com', 'providers': ['nope']}).status_code == 422
        assert c.post('/api/assets/enrich', json={'target': 'notentered.com', 'providers': ['virustotal']}).status_code == 422


def test_enrich_ingests_provenance_tagged_claims_into_the_graph(tmp_path):
    with TestClient(create_app(tmp_path, passive_http=_fake_http())) as c:
        c.post('/api/targets', json={'value': '93.184.216.34'})
        c.post('/api/credentials', json={'updates': {'SHODAN_API_KEY': 'k'}})
        r = c.post('/api/assets/enrich', json={'target': '93.184.216.34', 'providers': ['shodan']})
        assert r.status_code == 201, r.text
        rid = r.json()['run_id']
        assert r.json()['summary'][0]['status'] == 'ok'
        graph = c.get('/api/assets/graph?run_id=' + rid).json()
        canon = {(e['kind'], e['canonical']) for e in graph['entities']}
        assert ('vulnerability', 'CVE-2021-23017') in canon and ('netblock', 'AS15133') in canon
        # Every edge is sourced to the provider (a third-party claim).
        assert graph['edges'] and all(e['source'] == 'shodan' for e in graph['edges'])
        ip = next(e for e in graph['entities'] if e['kind'] == 'ip')
        detail = c.get('/api/assets/' + ip['id']).json()
        assert 'shodan' in detail['sources']


def test_runtime_lists_passive_providers(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        passive = c.get('/api/runtime').json()['passive_providers']
    ids = {p['id'] for p in passive['providers']}
    assert {'shodan', 'censys', 'virustotal', 'netlas', 'fofa', 'bevigil', 'hunter', 'zoomeye', 'intelx'} <= ids
    assert passive['enabled'] in (True, False) and all(p['configured'] is False for p in passive['providers'])


# -- additional providers (FOFA, BeVigil, Hunter.io, ZoomEye, IntelX) ---------
def test_fofa_mapper_builds_ip_service_tech_and_host():
    recs = parse_response('fofa', 'domain', 'example.com',
                          {'error': False, 'results': [['1.2.3.4', '443', 'www.example.com', 'nginx']]})
    ents = {(r['kind'], r['canonical']) for r in recs if r['t'] == 'e'}
    assert {('ip', '1.2.3.4'), ('service', '1.2.3.4:443/tcp'), ('technology', 'nginx'), ('host', 'www.example.com')} <= ents
    assert {r['rel'] for r in recs if r['t'] == 'x'} >= {'exposes', 'runs', 'subdomain_of', 'resolves_to'}


def test_bevigil_mapper_builds_subdomains():
    recs = parse_response('bevigil', 'domain', 'example.com', {'subdomains': ['m.example.com', 'api.example.com']})
    ents = {(r['kind'], r['canonical']) for r in recs if r['t'] == 'e'}
    assert ('host', 'm.example.com') in ents and ('host', 'api.example.com') in ents


def test_hunter_mapper_builds_contacts_and_pattern():
    recs = parse_response('hunter', 'domain', 'example.com',
                          {'data': {'domain': 'example.com', 'pattern': '{first}', 'emails': [{'value': 'Jane@Example.com'}]}})
    ents = {(r['kind'], r['canonical']) for r in recs if r['t'] == 'e'}
    assert ('contact', 'jane@example.com') in ents and ('contact', 'pattern:{first}') in ents
    assert any(r['rel'] == 'has_contact' for r in recs if r['t'] == 'x')


def test_zoomeye_ip_mapper_builds_service_and_tech():
    recs = parse_response('zoomeye', 'ip', '1.2.3.4', {'matches': [{'ip': '1.2.3.4', 'portinfo': {'port': 22, 'app': 'OpenSSH'}}]})
    ents = {(r['kind'], r['canonical']) for r in recs if r['t'] == 'e'}
    assert ('service', '1.2.3.4:22/tcp') in ents and ('technology', 'openssh') in ents


def test_intelx_collect_runs_two_steps_and_parse_builds_hosts_and_contacts():
    import asyncio
    calls = []
    async def http(req):
        calls.append(req)
        if (req.get('method') or 'GET').upper() == 'POST':
            return {'id': 'abc-123'}
        return {'selectors': [{'selectorvalue': 'api.example.com', 'selectortype': 1},
                              {'selectorvalue': 'jane@example.com', 'selectortype': 2}]}
    resp = asyncio.run(ADAPTERS['intelx']['collect'](http, 'domain', 'example.com', {'INTELX_API_KEY': 'k'}))
    assert calls[0]['method'] == 'POST' and 'phonebook/search' in calls[0]['url']
    assert calls[1]['url'].startswith('https://2.intelx.io/phonebook/search/result?id=abc-123')
    recs = parse_response('intelx', 'domain', 'example.com', resp)
    ents = {(r['kind'], r['canonical']) for r in recs if r['t'] == 'e'}
    assert ('host', 'api.example.com') in ents and ('contact', 'jane@example.com') in ents


def test_enrich_hunter_adds_sourced_contacts_to_the_graph(tmp_path):
    async def http(req):
        return {'data': {'domain': 'example.com', 'pattern': '{f}{last}', 'emails': [{'value': 'jane@example.com'}]}}
    with TestClient(create_app(tmp_path, passive_http=http)) as c:
        c.post('/api/targets', json={'value': 'example.com'})
        c.post('/api/credentials', json={'updates': {'HUNTER_API_KEY': 'k'}})
        r = c.post('/api/assets/enrich', json={'target': 'example.com', 'providers': ['hunter']})
        assert r.status_code == 201, r.text
        graph = c.get('/api/assets/graph?run_id=' + r.json()['run_id']).json()
        canon = {(e['kind'], e['canonical']) for e in graph['entities']}
        assert ('contact', 'jane@example.com') in canon
        assert any(e['rel'] == 'has_contact' and e['source'] == 'hunter' for e in graph['edges'])


def test_enrich_intelx_two_step_flow_end_to_end(tmp_path):
    async def http(req):
        if (req.get('method') or 'GET').upper() == 'POST':
            return {'id': 'id-9'}
        return {'selectors': [{'selectorvalue': 'vpn.example.com', 'selectortype': 1}]}
    with TestClient(create_app(tmp_path, passive_http=http)) as c:
        c.post('/api/targets', json={'value': 'example.com'})
        c.post('/api/credentials', json={'updates': {'INTELX_API_KEY': 'k'}})
        r = c.post('/api/assets/enrich', json={'target': 'example.com', 'providers': ['intelx']})
        assert r.status_code == 201, r.text
        graph = c.get('/api/assets/graph?run_id=' + r.json()['run_id']).json()
        assert ('host', 'vpn.example.com') in {(e['kind'], e['canonical']) for e in graph['entities']}
