"""End-to-end access matrix regressions against a loopback lab."""

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

from fastapi.testclient import TestClient
import pytest

from backend.app import create_app
from backend.tests.test_local import wait_done
from backend.tests.test_object_access import identity
from backend.tests.test_proposal_execution import dispatch, plan_for, prepare

TOKENS = ('matrix-owner-token', 'matrix-peer-token', 'matrix-expired-token')


@pytest.fixture
def matrix_lab():
    class Handler(BaseHTTPRequestHandler):
        calls = []
        owner_failed = False
        only_expected_access = False

        def do_GET(self):
            token = self.headers.get('Authorization', '').removeprefix('Bearer ')
            self.calls.append((self.path, token))
            status = 401 if token == TOKENS[2] else 200
            if self.path == '/objects/b' and token == TOKENS[2]:
                status = 403  # A stale session can also look like a denial.
            if self.only_expected_access:
                status = 404 if (self.path, token) in (('/objects/a', TOKENS[1]), ('/objects/b', TOKENS[2])) else 200
            if self.owner_failed and self.path == '/objects/a' and token == TOKENS[0]:
                status = 302
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Set-Cookie', 'secret=' + token)
            self.send_header('Location', '/out-of-scope')
            self.end_headers()
            # Representations can differ by role. Both still carry the object ID.
            self.wfile.write(json.dumps({'id': self.path[-1] if status == 200 else 'error',
                                         'private': 'fixture-sensitive-body', 'reflect': token}).encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def settings(app, client, base):
    plan, proposal, _ = plan_for(app, client, scope=base + '/objects', url=base + '/objects/a')
    ids = [identity(client, base, label, token) for label, token in zip(('Owner', 'Peer', 'Read-only'), TOKENS)]
    return plan, proposal, {
        'verification_profile': 'access_matrix', 'max_requests': 6,
        'access_matrix': {
            'rows': [{'identity_id': identity_id, 'expected': expected}
                     for identity_id, expected in zip(ids, [['allow', 'allow'], ['deny', 'allow'], ['allow', 'deny']])],
            'second_url': base + '/objects/b', 'first_object': 'a', 'second_object': 'b',
        },
    }


def test_access_matrix_distinguishes_intentional_sharing_unexpected_read_and_expiry(tmp_path, matrix_lab):
    base, lab = matrix_lab
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, options = settings(app, client, base)
        response = prepare(client, plan, proposal, **options)
        assert response.status_code == 201, response.text
        review = response.json()
        binding = review['snapshot']['config']['verification']
        assert binding['native_operations'] == 6
        assert not lab.calls
        assert dispatch(client, review, approve=False).status_code == 422
        assert dispatch(client, review, expected_hash='0' * 64).status_code == 409
        assert not lab.calls

        started = dispatch(client, review).json()
        rid = started['run']['id']
        run = wait_done(client, rid)
        assert run['status'] == 'completed' and run['result']['request_count'] == 6, run
        assert lab.calls == [(f'/objects/{path}', TOKENS[index]) for path, index in (
            ('a', 0), ('b', 1), ('b', 0), ('a', 1), ('a', 2), ('b', 2),
        )]
        report = client.get(f'/api/runs/{rid}/verification').json()
        cells = {c['request']['role']: c for c in report['cells']}
        assert report['outcome'] == 'signal_observed'
        assert report['facts'] == {'matched': 3, 'unexpected': 1, 'inconclusive': 2}
        assert cells['identity-1-object-2']['observed'] == 'allow'
        unexpected = cells['identity-2-object-1']
        assert (unexpected['outcome'], unexpected['observed'], unexpected['owner_body_matched']) == ('unexpected', 'allow', False)
        assert cells['identity-3-object-1']['status'] == 401
        assert cells['identity-3-object-2']['status'] == 403
        assert cells['identity-3-object-2']['outcome'] == 'inconclusive'
        assert report['evidence_current']
        assert {c['exchange_id'] for c in cells.values()} == {
            r['id'] for r in client.get('/api/http-history', params={'run_id': rid}).json()['items']
        }
        receipts = [review, run, report, client.get('/api/http-history/har', params={'run_id': rid}).json()]
        for cell in cells.values():
            exchange = client.get('/api/http-history/' + cell['exchange_id']).json()
            receipts.append(exchange)
            assert exchange['request']['representation'] == 'authenticated_metadata_only'
            assert exchange['response']['headers'] == [] and exchange['response']['body_base64'] == ''
        for secret in (*TOKENS, 'fixture-sensitive-body'):
            assert secret not in json.dumps(receipts)
            assert secret.encode() not in app.state.store.db.read_bytes()
        assert not dispatch(client, review).json()['created'] and len(lab.calls) == 6

        # Losing an owner control invalidates the decisions which depended on it.
        with app.state.store.connect() as connection:
            connection.execute("UPDATE artifacts SET content='{}' WHERE id=?",
                               (cells['identity-1-object-1']['artifact_id'],))
        changed = client.get(f'/api/runs/{rid}/verification').json()
        assert changed['outcome'] == 'inconclusive' and not changed['evidence_current']
        changed_cells = {c['request']['role']: c for c in changed['cells']}
        changed_peer = changed_cells['identity-2-object-1']
        assert changed_peer['outcome'] == 'inconclusive' and changed_peer['recorded_outcome'] == 'unexpected'
        assert changed_cells['identity-1-object-2']['outcome'] == 'matched'


def test_failed_owner_control_skips_only_its_object(tmp_path, matrix_lab):
    base, lab = matrix_lab
    lab.owner_failed = True
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, options = settings(app, client, base)
        review = prepare(client, plan, proposal, **options).json()
        rid = dispatch(client, review).json()['run']['id']
        assert wait_done(client, rid)['result']['request_count'] == 4
        assert [path for path, _ in lab.calls] == ['/objects/a', '/objects/b', '/objects/b', '/objects/b']
        report = client.get(f'/api/runs/{rid}/verification').json()
        assert report['outcome'] == 'inconclusive'
        cells = {c['request']['role']: c for c in report['cells']}
        assert cells['identity-1-object-2']['outcome'] == 'matched'
        assert not cells['identity-2-object-1']['artifact_id']
        assert 'skipped' in cells['identity-2-object-1']['reason']


def test_denial_requires_a_confirmed_session_and_can_match_policy(tmp_path, matrix_lab):
    base, lab = matrix_lab
    lab.only_expected_access = True
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, options = settings(app, client, base)
        review = prepare(client, plan, proposal, **options).json()
        rid = dispatch(client, review).json()['run']['id']
        wait_done(client, rid)
        report = client.get(f'/api/runs/{rid}/verification').json()
        assert report['outcome'] == 'signal_not_observed'
        assert report['facts'] == {'matched': 6, 'unexpected': 0, 'inconclusive': 0}
        assert [cell['status'] for cell in report['cells'] if cell['observed'] == 'deny'] == [404, 404]


def test_matrix_rejects_invalid_bindings_and_removal_invalidates_review(tmp_path, matrix_lab):
    base, lab = matrix_lab
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, options = settings(app, client, base)
        matrix = options['access_matrix']
        wrong_control = copy.deepcopy(matrix)
        wrong_control['rows'][0]['expected'][0] = 'deny'
        duplicate = copy.deepcopy(matrix)
        duplicate['rows'][2]['identity_id'] = duplicate['rows'][0]['identity_id']
        for override in (
            {'max_requests': 5},
            {'http_routing': {'mode': 'proxy'}},
            {'access_matrix': wrong_control},
            {'access_matrix': duplicate},
            {'access_matrix': {**matrix, 'second_url': base + '/out-of-scope'}},
            {'access_matrix': {**matrix, 'second_url': base + '/objects/a'}},
            {'access_matrix': {**matrix, 'rows': matrix['rows'][:2]}},
            {'access_matrix': {**matrix, 'json_pointer': '/bad~pointer'}},
        ):
            response = prepare(client, plan, proposal, **{**options, **override})
            assert response.status_code == 422, response.text
        review = prepare(client, plan, proposal, **options).json()
        removed = client.post('/api/verification/identities/' + matrix['rows'][2]['identity_id'] + '/remove', json={})
        assert removed.status_code == 200
        assert dispatch(client, review).status_code == 409
        assert not lab.calls
