import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.delta_recon import baseline_key
from backend.tests.test_local import wait_done
from backend.tests.test_workflows import graph, launch
from backend.tests.test_proposal_execution import prepare, dispatch


@pytest.fixture
def delta_lab():
    class Handler(BaseHTTPRequestHandler):
        generation = 1
        calls = []

        def do_GET(self):
            self.calls.append(self.path)
            self.send_response(200)
            self.send_header('Content-Type', 'text/html' if self.path == '/app/' else 'application/javascript')
            self.end_headers()
            if self.path == '/app/':
                extra = 'removed.js' if self.generation == 1 else 'new.js'
                body = '<script src="stable.js"></script><script src="changed.js"></script><script src="' + extra + '"></script>'
            else:
                body = 'const fixture = ' + str(self.generation if 'changed' in self.path else 1)
                if 'changed' in self.path:
                    body += '; fetch("/app/api/v' + str(self.generation) + '");'
            self.wfile.write(body.encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/app/', Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def collect(client, url):
    response = launch(client, url, graph('native_scope', 'native_http', 'native_web_assets', 'native_api_surface'), max_requests=12)
    assert response.status_code == 201, response.text
    rid = response.json()['id']
    assert wait_done(client, rid)['status'] == 'completed'
    return rid


def save(client, rid, revision=0):
    response = client.post('/api/recon/baselines', json={'run_id': rid, 'expected_revision': revision})
    assert response.status_code == 201, response.text
    return response.json()


def compare(client, rid, baseline):
    response = client.get(f'/api/runs/{rid}/delta', params={'baseline_id': baseline['id']})
    assert response.status_code == 200, response.text
    return response.json()


def plan_changes(client, rid, baseline, report, rows):
    response = client.post(f'/api/runs/{rid}/delta/proposals', json={
        'baseline_id': baseline['id'], 'expected_hash': report['comparison_hash'],
        'fingerprints': [row['fingerprint'] for row in rows],
    })
    assert response.status_code == 201, response.text
    return response.json()


def test_delta_baseline_to_approved_changed_only_dispatch_and_restart(tmp_path, delta_lab):
    url, handler = delta_lab
    with TestClient(create_app(tmp_path)) as client:
        first = collect(client, url)
        baseline = save(client, first)
        before = list(handler.calls)
        assert client.get('/api/recon/baselines', params={'run_id': first}).json()[0]['revision'] == 1
        handler.generation = 2
        current = collect(client, url)
        captured = list(handler.calls)
        report = compare(client, current, baseline)
        files = {row['asset'].rsplit('/', 1)[-1]: row for row in report['entries'] if row['kind'] == 'file'}
        assert {name: row['state'] for name, row in files.items()} == {
            'stable.js': 'unchanged', 'changed.js': 'changed', 'new.js': 'new', 'removed.js': 'not_observed',
        }
        api_endpoints = {r['asset']: r['state'] for r in report['entries'] if r['source'] == 'api-surface'}
        assert api_endpoints == {url + 'api/v1': 'not_observed', url + 'api/v2': 'new'}
        assert report['evidence_current'] and report['coverage']['current']['nodes']
        assert all(node['input_receipt'] for node in report['coverage']['current']['nodes'])
        plan = plan_changes(client, current, baseline, report, [files['changed.js'], files['new.js']])
        action = plan['proposals'][0]['action']
        assert action['targets'] == [url + 'changed.js', url + 'new.js']
        assert action['cost']['native_operations'] == 2
        assert handler.calls == captured and captured != before
        proposal = plan['proposals'][0]
        assert prepare(client, plan, proposal, max_requests=1).status_code == 422
        assert prepare(client, plan, proposal, max_requests=2, verification_profile='repeat_get').status_code == 422
        response = prepare(client, plan, proposal, max_requests=2)
        assert response.status_code == 201, response.text
        review = response.json()
        assert review['snapshot']['config']['workflow']['nodes'][0]['data']['value'].splitlines() == action['targets']
        assert dispatch(client, review, approve=False).status_code == 422
        assert handler.calls == captured
        rid = dispatch(client, review).json()['run']['id']
        run = wait_done(client, rid)
        assert run['status'] == 'completed' and run['result']['request_count'] == 2
        assert handler.calls[len(captured):] == ['/app/changed.js', '/app/new.js']
        assert dispatch(client, review).json()['created'] is False
        assert len(handler.calls) == len(captured) + 2
    with TestClient(create_app(tmp_path)) as client:
        assert compare(client, current, baseline)['comparison_hash'] == report['comparison_hash']
        assert client.get('/api/recon/baselines', params={'run_id': current}).json()[0]['id'] == baseline['id']


def test_delta_rejects_unchanged_removed_foreign_and_stale_selections(tmp_path, delta_lab):
    url, handler = delta_lab
    app = create_app(tmp_path)
    with TestClient(app) as client:
        baseline = save(client, collect(client, url))
        handler.generation = 2
        current = collect(client, url)
        report = compare(client, current, baseline)
        rows = report['entries']
        files = [r for r in rows if r['kind'] == 'file']
        for fingerprint in [next(r['fingerprint'] for r in files if r['state'] == 'unchanged'),
                            next(r['fingerprint'] for r in files if r['state'] == 'not_observed'), 'foreign']:
            response = client.post(f'/api/runs/{current}/delta/proposals', json={
                'baseline_id': baseline['id'], 'expected_hash': report['comparison_hash'], 'fingerprints': [fingerprint],
            })
            assert response.status_code == 422, response.text
        selected = [r for r in files if r['state'] == 'new']
        plan = plan_changes(client, current, baseline, report, selected)
        review = prepare(client, plan, plan['proposals'][0]).json()
        app.state.store.artifact(current, 'extra.json', {'additional': 'capture'})
        assert dispatch(client, review).status_code == 409
        assert not client.get('/api/agent/proposals/' + plan['id']).json()['current']
        assert client.post(f'/api/runs/{current}/delta/proposals', json={
            'baseline_id': baseline['id'], 'expected_hash': report['comparison_hash'],
            'fingerprints': [selected[0]['fingerprint']],
        }).status_code == 422
        aid = next(iter(baseline['snapshot']['artifact_hashes']))
        with app.state.store.connect() as c:
            c.execute("UPDATE artifacts SET content='{}' WHERE id=?", (aid,))
        result = compare(client, current, baseline)
        assert not result['evidence_current']


def test_baseline_revision_concurrency_and_scope_workflow_binding(tmp_path, delta_lab):
    url, handler = delta_lab
    with TestClient(create_app(tmp_path)) as client:
        rid = collect(client, url)
        with ThreadPoolExecutor(max_workers=2) as workers:
            statuses = list(workers.map(lambda _: client.post('/api/recon/baselines', json={'run_id': rid}).status_code, range(2)))
        assert sorted(statuses) == [201, 409]
        baseline = save(client, rid, 1)
        assert baseline['revision'] == 2
        current = collect(client, url)
        run = client.get('/api/runs/' + current).json()
        config = copy.deepcopy(run['config'])
        key = baseline_key(config)
        config['workflow']['nodes'][0]['position']['x'] += 30
        config['workflow']['nodes'][0]['data']['title'] = 'Presentation only'
        assert baseline_key(config) == key
        config['workflow']['nodes'][-1]['data']['max_pages'] = 2
        assert baseline_key(config) != key
        config['targets'] = [url + '/other']
        assert baseline_key(config) != key


def test_failed_node_and_changed_limits_show_explicit_coverage_gaps(tmp_path, delta_lab):
    url, handler = delta_lab
    app = create_app(tmp_path)
    with TestClient(app) as client:
        baseline = save(client, collect(client, url))
        handler.generation = 2
        current = collect(client, url)
        store = app.state.store
        node = store.nodes(current)[-1]
        store.node_status(current, node['node_id'], 'skipped', {'reason': 'Upstream scan failed'})
        config = store.run(current)['config']
        config['max_requests'] = 1
        with store.connect() as c:
            c.execute('UPDATE runs SET config=? WHERE id=?', (json.dumps(config), current))
        result = compare(client, current, baseline)
        assert any('skipped' in note for note in result['warnings'])
        assert any('budgets differs' in note for note in result['warnings'])
        assert result['coverage']['current']['nodes'][-1]['status'] == 'skipped'
