import json

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.api_surface import analyze_surface
from backend.http_journal import HTTPJournal, request_message
from backend.store import Store
from backend.tests.test_local import wait_done
from backend.tests.test_workflows import graph, launch
from backend.tests.test_web_recon import web_server


def test_analysis_uses_saved_sources_and_only_matches_method_and_route(tmp_path):
    store = Store(tmp_path)
    journal = HTTPJournal(store)
    base = 'https://app.example.test'
    run_id = store.new_run({'targets': [base + '/app']})['id']
    other_run = store.new_run({'targets': [base + '/app']})['id']
    bundle, sourcemap = base + '/app/static/bundle.js', base + '/app/static/bundle.js.map'
    body = """// fetch('/app/comment');
const text = "fetch('/app/in-a-string')";
fetch('api/users?account=SECRET&sort=asc');
fetch('/app/api/users', {method: 'POST'});
fetch(`/app/api/${dynamic}`);
fetch('/app/api/' + dynamic);
fetch('/app/api/dynamic-method', {method: someMethod});
fetch('/app/api/spread', {...dynamic});
fetch('https://outside.test/elsewhere');
fetch('/outside');
axios.get('/projects?view=SECRET', {baseURL: '/app/api', params: {accountId: 'VALUE', page}});
axios.request({url: '/app/api/report', method: 'PATCH'});
"""
    map_body = json.dumps({'version': 3, 'sources': ['webpack:///src/client.ts', 'skip.ts'], 'sourcesContent': [
        "export const load = (n: number) => axios.post<{ok: boolean}>('/app/api/jobs', {n});", None,
    ]})
    source_id = store.artifact(run_id, 'http-1.json', {'url': bundle, 'body': body}, node_id='sources')
    map_id = store.artifact(run_id, 'http-2.json', {'url': sourcemap, 'body': map_body}, node_id='sources')
    foreign_id = store.artifact(other_run, 'http-3.json', {'url': bundle, 'body': "fetch('/app/api/private')"})
    manifest = {'manifest': [
        {'url': base + '/app/', 'kind': 'page', 'status': 200},
        {'url': bundle, 'kind': 'js', 'status': 200, 'discovered_from': base + '/app/', 'artifact_id': source_id},
        {'url': sourcemap, 'kind': 'map', 'status': 200, 'discovered_from': bundle, 'artifact_id': map_id},
        {'url': bundle, 'kind': 'js', 'status': 200, 'artifact_id': foreign_id},
    ]}
    for rid, url in [(run_id, base + '/app/api/users?account=SECRET'), (other_run, base + '/app/api/report')]:
        exchange = journal.begin(rid, 'source', 1, url, {'mode': 'direct'}, request_message(url))
        journal.finish(exchange, response={'status': 200})
    result = analyze_surface(store, run_id, [manifest], [base + '/app'], journal.endpoint_exchanges)
    routes = {(row['method'], row['url'].removeprefix(base)): row for row in result['endpoints']}
    assert set(routes) == {('GET', '/app/api/users'), ('POST', '/app/api/users'), ('GET', '/app/api/projects'),
                           ('PATCH', '/app/api/report'), ('POST', '/app/api/jobs')}
    assert routes['GET', '/app/api/users']['status'] == 'observed'
    assert routes['POST', '/app/api/users']['status'] == 'inferred'
    assert routes['PATCH', '/app/api/report']['status'] == 'inferred'
    assert routes['GET', '/app/api/projects']['parameters'] == ['accountId', 'page', 'view']
    assert routes['GET', '/app/api/users']['sources'][0]['line'] == 3
    assert routes['POST', '/app/api/jobs']['sources'][0]['embedded_source'] == 'webpack:///src/client.ts'
    assert result['counts']['out_of_scope'] == 2 and result['counts']['missing'] == 1
    assert 'SECRET' not in json.dumps(result) and 'VALUE' not in json.dumps(result)


def test_api_surface_node_and_saved_run_use_the_same_offline_analysis(tmp_path, web_server):
    base, handler = web_server
    with TestClient(create_app(tmp_path)) as client:
        g = graph('native_scope', 'native_http', 'native_web_assets', 'native_api_surface')
        response = launch(client, base + '/app/', g, max_requests=12)
        assert response.status_code == 201, response.text
        rid = response.json()['id']
        run = wait_done(client, rid)
        assert run['status'] == 'completed', run
        nodes = client.get(f'/api/runs/{rid}/nodes').json()
        artifact = client.get('/api/artifacts/' + nodes[-1]['result']['artifact_id']).json()[0]
        before = list(handler.calls)
        surface = client.get(f'/api/runs/{rid}/api-surface')
        assert surface.status_code == 200, surface.text
        assert surface.json() == artifact and handler.calls == before
        assert artifact['counts']['documents'] > 0
        assert artifact['endpoints'][0]['url'] == base + '/app/next'
        assert artifact['endpoints'][0]['status'] == 'observed'
        starter = client.get('/api/workflow-starters/web-recon?surface=true').json()
        assert any(node['data']['kind'] == 'native_api_surface' for node in starter['nodes'])
