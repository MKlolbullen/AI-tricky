import copy
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.proposals import ProposalPlanner
from backend.scope import ScopeError, fetch_scoped, parse_target
from backend.verification import contract, evaluate, TEST_ORIGIN
from backend.tests.test_evidence import run, capture, nuclei
from backend.tests.test_local import wait_done
from backend.tests.test_proposal_execution import prepare, dispatch, plan_for


@pytest.fixture
def verification_target():
    class Handler(BaseHTTPRequestHandler):
        calls = []
        def do_GET(self):
            self.calls.append({'path': self.path, 'headers': dict(self.headers)})
            if self.path == '/error':
                self.connection.close(); return
            self.send_response(302 if self.path == '/redirect' else 403 if self.path == '/denied' else 200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Set-Cookie', 'never-forward-this=secret')
            if self.path == '/redirect':self.send_header('Location', '/outside-profile')
            origin = self.headers.get('Origin')
            if self.path in ('/cors', '/upper', '/duplicate') and origin:
                self.send_header('Access-Control-Allow-Origin', origin)
                if self.path == '/duplicate':self.send_header('Access-Control-Allow-Origin', origin)
                self.send_header('Access-Control-Allow-Credentials', 'True' if self.path == '/upper' else 'true')
            elif self.path == '/wildcard':
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Credentials', 'true')
            self.end_headers()
            self.wfile.write(b'x' * 140000 if self.path == '/truncate' else str(len(self.calls)).encode() if self.path == '/changing' else b'controlled verification fixture')
        def log_message(self, *args):pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f'http://127.0.0.1:{server.server_port}', Handler
    server.shutdown(); server.server_close()


def make_plan(app, client, url, finding=False):
    client.post('/api/targets', json={'value': url}).raise_for_status()
    store = app.state.store
    rid = run(store, targets=[url], max_hosts=1)
    nuclei(store, rid, url=url) if finding else capture(store, rid, url=url)
    planner = ProposalPlanner(store)
    oid = planner.evidence.observations(run_id=rid)['items'][0]['id']
    plan = planner.save('Inspect the captured location', planner.context(rid, [oid], 'Capture HTTP evidence'))
    fid = planner.evidence.findings(run_id=rid)['items'][0]['id'] if finding else None
    return plan, plan['proposals'][0], fid


def check_pair(client, plan, proposal, profile='repeat_get', **options):
    response = prepare(client, plan, proposal, verification_profile=profile, max_requests=2, **options)
    assert response.status_code == 201, response.text
    review = response.json()
    response = dispatch(client, review)
    assert response.status_code == 200, response.text
    rid = response.json()['run']['id']
    result = wait_done(client, rid)
    report = client.get(f'/api/runs/{rid}/verification')
    assert report.status_code == 200, report.text
    return review, result, report.json()


@pytest.mark.parametrize('profile,path,outcome', [
    ('repeat_get', '/stable', 'signal_observed'), ('repeat_get', '/changing', 'signal_not_observed'),
    ('cors_origin', '/cors', 'signal_observed'), ('cors_origin', '/stable', 'signal_not_observed'),
    ('cors_origin', '/wildcard', 'signal_observed'), ('cors_origin', '/upper', 'signal_observed'),
    ('cors_origin', '/duplicate', 'inconclusive'), ('repeat_get', '/truncate', 'inconclusive'),
    ('repeat_get', '/redirect', 'inconclusive'), ('repeat_get', '/denied', 'inconclusive'),
])
def test_live_profile_pair_scope_accounting_evidence_and_outcomes(tmp_path, verification_target, profile, path, outcome):
    base, handler = verification_target
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = make_plan(app, client, base + path)
        preview = prepare(client, plan, proposal, verification_profile=profile, max_requests=2)
        assert preview.status_code == 201 and not handler.calls
        assert preview.json()['snapshot']['config']['verification']['native_operations'] == 2
        review, result, report = check_pair(client, plan, proposal, profile)
        assert result['status'] == 'completed' and result['result']['request_count'] == 2
        assert result['result']['cli_invocation_count'] == 0 and report['outcome'] == outcome
        assert report['comparison_artifact_id'] and report['evidence_current']
        assert [c['request']['role'] for c in report['captures']] == ['baseline', 'variant']
        assert [r['path'] for r in handler.calls] == [path, path]
        assert all(not r['headers'].get('Cookie') and not r['headers'].get('Authorization') for r in handler.calls)
        assert handler.calls[0]['headers'].get('Origin') is None
        assert handler.calls[1]['headers'].get('Origin') == (TEST_ORIGIN if profile == 'cors_origin' else None)
        for row in report['captures']:
            raw = client.get('/api/artifacts/' + row['artifact_id']).json()
            assert raw['verification_request'] == row['request']
            assert 'set-cookie' not in raw['headers']
        if path in ('/wildcard', '/upper'):
            assert report['facts']['credential_permission_header_pair'] is False
        retry = dispatch(client, review).json()
        assert not retry['created'] and len(handler.calls) == 2
    with TestClient(create_app(tmp_path)) as client:
        assert client.get(f'/api/runs/{result["id"]}/verification').json()['outcome'] == outcome


@pytest.mark.parametrize('options', [
    {'verification_profile': 'arbitrary'}, {'verification_profile': 'repeat_get', 'max_requests': 1},
    {'verification_profile': 'cors_origin', 'headers': {'Origin': 'https://evil.invalid'}},
    {'verification_profile': 'cors_origin', 'method': 'POST'}, {'finding_id': 'unrelated'},
    {'verification_profile': 'repeat_get', 'max_requests': 2, 'finding_id': 'unrelated'},
])
def test_profile_contract_rejects_unsupported_requests_and_bindings(tmp_path, options):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = make_plan(app, client, 'https://example.com/api')
        assert prepare(client, plan, proposal, **options).status_code == 422
        assert len(client.get('/api/runs').json()) == 1


def test_profile_contract_upgrade_invalidates_pending_approval(tmp_path, monkeypatch):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = make_plan(app, client, 'https://example.com/api')
        review = prepare(client, plan, proposal, verification_profile='repeat_get', max_requests=2).json()
        monkeypatch.setattr('backend.verification.VERSION', 'next-evaluator')
        assert dispatch(client, review).status_code == 409
        assert client.get('/api/agent/executions/' + review['id']).json()['status'] == 'invalidated'


def test_linked_finding_keeps_operator_state_until_an_explicit_review(tmp_path, verification_target):
    base, _ = verification_target
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, fid = make_plan(app, client, base + '/cors', finding=True)
        before = client.get('/api/findings/' + fid).json()
        eligible = client.get(f'/api/agent/proposals/{plan["id"]}/{proposal["id"]}/verification-findings').json()
        assert [f['id'] for f in eligible] == [fid]
        _, result, report = check_pair(client, plan, proposal, 'cors_origin', finding_id=fid)
        after = client.get('/api/findings/' + fid).json()
        for key in ('status', 'severity', 'confidence', 'revision', 'reviews', 'first_seen', 'last_seen'):
            assert after[key] == before[key]
        assert client.get(f'/api/findings/{fid}/verification').json()[0]['run_id'] == result['id']
        aid = report['captures'][1]['artifact_id']
        assert aid in {a['id'] for a in after['verification_evidence']}
        response = client.post(f'/api/findings/{fid}/reviews', json={'expected_revision': after['revision'],
            'status': 'triaged', 'severity': after['severity'], 'confidence': 'low',
            'note': 'Operator assessed the linked paired captures; no automatic verification.', 'evidence_id': aid})
        assert response.status_code == 200 and response.json()['status'] == 'triaged'


def test_changed_capture_flags_saved_comparison_and_removes_it_from_review_choices(tmp_path, verification_target):
    base, _ = verification_target
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, fid = make_plan(app, client, base + '/stable', finding=True)
        _, result, report = check_pair(client, plan, proposal, finding_id=fid)
        aid = report['captures'][0]['artifact_id']
        with app.state.store.connect() as c:
            c.execute('UPDATE artifacts SET content=? WHERE id=?', (json.dumps({'changed': True}), aid))
        changed = client.get(f'/api/runs/{result["id"]}/verification').json()
        assert changed['outcome'] == 'inconclusive' and changed['recorded_outcome'] == 'signal_observed'
        assert changed['evidence_current'] is False
        current = client.get('/api/findings/' + fid).json()
        assert not {a['id'] for a in current['verification_evidence']} & {c['artifact_id'] for c in report['captures']}
        assert client.get('/api/artifacts/' + report['comparison_artifact_id']).json()['outcome'] == 'signal_observed'


def test_failed_baseline_is_inconclusive_and_does_not_send_variant(tmp_path, verification_target):
    base, handler = verification_target
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = make_plan(app, client, base + '/error')
        _, result, report = check_pair(client, plan, proposal)
        assert result['result']['request_count'] == 1 and len(handler.calls) == 1
        assert report['outcome'] == 'inconclusive' and not report['captures'][0]['artifact_id']


def test_transport_rejects_arbitrary_headers_before_any_target_io(verification_target):
    base, handler = verification_target
    for headers in ({'Authorization': 'secret'}, {'Cookie': 'secret'}, {'Origin': 'https://other.invalid'}, {'Host': 'elsewhere.invalid'}):
        with pytest.raises(ScopeError):
            fetch_scoped(base, [parse_target(base)], controlled_headers=headers)
    assert not handler.calls


@pytest.mark.parametrize('change', ['ip', 'missing', 'request', 'error', 'truncated'])
def test_offline_evaluator_treats_incomplete_or_confounded_pairs_as_inconclusive(change):
    binding = contract('repeat_get', 'https://example.com/')
    captures = [{'request': request, 'artifact_id': str(i), 'status': 200, 'headers': {},
                 'body_sha256': hashlib.sha256(b'fixture').hexdigest(), 'body_bytes': 7, 'connected_ip': '127.0.0.1'}
                for i, request in enumerate(copy.deepcopy(binding['requests']))]
    if change == 'ip':captures[1]['connected_ip'] = '127.0.0.2'
    elif change == 'missing':captures.pop()
    elif change == 'request':captures[1]['request']['url'] = 'https://other.invalid/'
    elif change == 'error':captures[1]['error'] = 'budget exhausted'
    else:captures[1]['truncated'] = True
    assert evaluate(binding, captures)['outcome'] == 'inconclusive'


def test_catalog_proposals_cannot_select_native_verification_profiles(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = plan_for(app, client, scope='example.com', url='https://example.com/api', adapter='whatweb')
        response = prepare(client, plan, proposal, verification_profile='repeat_get', max_requests=2, allow_cli=True)
        assert response.status_code == 422 and 'native HTTP' in response.text


def test_a_different_findings_captures_cannot_be_linked(tmp_path, verification_target):
    base, _ = verification_target
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = make_plan(app, client, base + '/cors', finding=True)
        _, _, foreign = make_plan(app, client, base + '/other', finding=True)
        response = prepare(client, plan, proposal, verification_profile='cors_origin', max_requests=2, finding_id=foreign)
        assert response.status_code == 422
        assert client.get('/api/findings/' + foreign + '/verification').json() == []


def test_cancel_between_pair_requests_retains_baseline_and_reports_inconclusive(tmp_path, verification_target, monkeypatch):
    from backend import app as app_module
    base, handler = verification_target
    original = app_module.fetch_scoped
    captured, release = threading.Event(), threading.Event()
    def hold_baseline(*args, **kwargs):
        result = original(*args, **kwargs)
        captured.set(); release.wait(3)
        return result
    monkeypatch.setattr(app_module, 'fetch_scoped', hold_baseline)
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, fid = make_plan(app, client, base + '/cors', finding=True)
        review = prepare(client, plan, proposal, verification_profile='cors_origin', max_requests=2, finding_id=fid).json()
        rid = dispatch(client, review).json()['run']['id']
        assert captured.wait(2)
        assert client.post(f'/api/runs/{rid}/pause', json={}).status_code == 200
        release.set()
        for _ in range(100):
            if any(a['name'].startswith('http-') for a in client.get(f'/api/runs/{rid}/artifacts').json()):break
            time.sleep(.02)
        assert client.post(f'/api/runs/{rid}/cancel', json={}).status_code == 200
        for _ in range(100):
            report = client.get(f'/api/runs/{rid}/verification').json()
            if report.get('comparison_artifact_id'):break
            time.sleep(.02)
        assert report['outcome'] == 'inconclusive' and len(report['captures']) == 1
        assert report['captures'][0]['request']['role'] == 'baseline'
        assert len(handler.calls) == 1
        assert client.get('/api/findings/' + fid).json()['status'] == 'candidate'


def test_ordinary_run_cannot_forge_verification_configuration(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = make_plan(app, client, 'https://example.com/api')
        response = client.post('/api/runs', json={'engine': 'workflow', 'workflow': proposal['graph'],
                                                'verification': contract('cors_origin', 'https://example.com/api')})
        assert response.status_code == 201 and 'verification' not in response.json()['config']
        assert client.get('/api/runs/' + response.json()['id'] + '/verification').status_code == 404
