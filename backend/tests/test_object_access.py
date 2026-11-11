import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import subprocess
import threading

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.tests.test_local import wait_done
from backend.tests.test_proposal_execution import dispatch, plan_for, prepare

OWNER = 'owner-only-fixture-token-502'
OTHER = 'other-only-fixture-token-644'
PRIVATE_BODY = 'private-resource-content-fixture'


@pytest.fixture
def object_server(tmp_path, request):
    class Handler(BaseHTTPRequestHandler):
        requests = []

        def do_GET(self):
            auth = self.headers.get('Authorization')
            self.requests.append((self.path, auth, self.headers.get('Cookie')))
            _, _, case, resource = self.path.split('/')
            status = 200
            body = {'object': {'id': 'owner'}, 'value': PRIVATE_BODY, 'echo': OWNER}
            if resource == 'control':
                if case == 'bad_control':
                    body = {'object': {'id': 'unexpected'}}
                else:
                    body = {'object': {'id': 'control'}, 'echo': OTHER}
            elif auth == 'Bearer ' + OTHER:
                status = {'forbidden': 403, 'hidden': 404, 'expired': 401, 'redirect': 302}.get(case, 200)
                if status != 200:
                    body = {'error': 'unavailable'}
                if case == 'different':
                    body['value'] = 'another representation'
                if case == 'deny_with_data':
                    status = 403
            if case == 'owner_failed' and resource == 'owner':
                status = 401
            # Reflect credentials in headers, the reason phrase and response
            # bodies to exercise the protected capture path.
            self.send_response(status, auth or 'missing')
            self.send_header('Content-Type', 'application/json')
            self.send_header('Set-Cookie', 'reflected=' + (auth or 'missing'))
            if status == 302:
                self.send_header('Location', '/objects/redirect/unexpected')
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    scheme = 'https' if getattr(request, 'param', False) else 'http'
    if scheme == 'https':
        cert, key = tmp_path / 'object-ca.pem', tmp_path / 'object-key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'{scheme}://127.0.0.1:{server.server_port}', Handler.requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def identity(client, origin, label, token):
    response = client.post('/api/verification/identities', json={'origin': origin, 'label': label, 'token': token})
    assert response.status_code == 201, response.text
    public = response.json()
    assert set(public) == {'id', 'origin', 'label'}
    assert token not in response.text
    return public['id']


def setup_check(app, client, origin, case='leak'):
    plan, proposal, _ = plan_for(app, client, scope=origin + '/objects', url=f'{origin}/objects/{case}/owner')
    options = {
        'owner_identity_id': identity(client, origin, 'Owner account', OWNER),
        'other_identity_id': identity(client, origin, 'Second account', OTHER),
        'control_url': f'{origin}/objects/{case}/control',
        'json_pointer': '/object/id',
        'owner_object': 'owner',
        'control_object': 'control',
    }
    return plan, proposal, options


@pytest.mark.parametrize('case,outcome,count', [
    ('leak', 'signal_observed', 3),
    ('forbidden', 'signal_not_observed', 3),
    ('hidden', 'signal_not_observed', 3),
    ('expired', 'inconclusive', 3),
    ('different', 'inconclusive', 3),
    ('redirect', 'inconclusive', 3),
    ('deny_with_data', 'inconclusive', 3),
    ('bad_control', 'inconclusive', 2),
    ('owner_failed', 'inconclusive', 1),
])
def test_object_access_compares_only_after_controls(tmp_path, object_server, case, outcome, count):
    base, calls = object_server
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, options = setup_check(app, client, base, case)
        response = prepare(client, plan, proposal, verification_profile='object_access',
                           object_access=options, max_requests=3)
        assert response.status_code == 201, response.text
        review = response.json()
        binding = review['snapshot']['config']['verification']
        assert binding['native_operations'] == 3
        assert [r['role'] for r in binding['requests']] == ['owner', 'control', 'other']
        assert all(r['headers'] == {} for r in binding['requests'])
        assert not calls
        assert dispatch(client, review, approve=False).status_code == 422
        assert not calls
        response = dispatch(client, review)
        assert response.status_code == 200, response.text
        rid = response.json()['run']['id']
        run = wait_done(client, rid)
        assert run['status'] == 'completed', run
        assert run['result']['request_count'] == count
        report = client.get(f'/api/runs/{rid}/verification').json()
        assert report['outcome'] == outcome, report
        assert report['evidence_current'] and len(report['captures']) == count
        assert calls == [(f'/objects/{case}/{resource}', 'Bearer ' + token, None)
                         for resource, token in [('owner', OWNER), ('control', OTHER), ('owner', OTHER)][:count]]
        again = dispatch(client, review).json()
        assert again['run']['id'] == rid and not again['created']
        assert len(calls) == count

        # Durable records preserve enough evidence for a comparison while
        # keeping bearer values and protected content out of all exports.
        history = client.get('/api/http-history', params={'run_id': rid}).json()['items']
        assert len(history) == count
        har = client.get('/api/http-history/har', params={'run_id': rid}).json()
        assert all(entry['_ai_tricky']['capture_mode'] == 'authenticated_metadata_only'
                   for entry in har['log']['entries'])
        outputs = [review, run, report, client.get('/api/verification/identities').json(), har]
        for row in history:
            exchange = client.get('/api/http-history/' + row['id']).json()
            outputs.append(exchange)
            request, response = exchange['request'], exchange['response']
            assert request['representation'] == response['representation'] == 'authenticated_metadata_only'
            assert ['Authorization', 'Bearer [redacted]'] in request['headers']
            assert response['headers'] == [] and response['body_base64'] == ''
            for item in (request, response):
                raw = base64.b64decode(item['raw_headers_base64'])
                assert OWNER.encode() not in raw and OTHER.encode() not in raw
        for capture in report['captures']:
            assert capture['body_fingerprint'] and capture['exchange_id']
            outputs.append(client.get('/api/artifacts/' + capture['artifact_id']).json())
        for value in (OWNER, OTHER, PRIVATE_BODY):
            assert value not in json.dumps(outputs)
            assert value.encode() not in app.state.store.db.read_bytes()
        assert not (tmp_path / 'credentials.json').exists()


@pytest.mark.parametrize('problem', ['budget', 'proxy', 'wrong_origin', 'out_of_scope', 'same_token',
                                    'same_object', 'same_url', 'anonymous_profile'])
def test_object_access_prepare_rejects_unbound_checks(tmp_path, object_server, problem):
    base, calls = object_server
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, options = setup_check(app, client, base)
        settings = {'verification_profile': 'object_access', 'object_access': options, 'max_requests': 3}
        if problem == 'budget':
            settings['max_requests'] = 2
        elif problem == 'proxy':
            settings['http_routing'] = {'mode': 'proxy'}
        elif problem == 'wrong_origin':
            options['other_identity_id'] = identity(client, 'https://different.test', 'Foreign', 'foreign-token')
        elif problem == 'out_of_scope':
            options['control_url'] = base + '/elsewhere'
        elif problem == 'same_token':
            options['other_identity_id'] = identity(client, base, 'Duplicate token', OWNER)
        elif problem == 'same_object':
            options['control_object'] = 'owner'
        elif problem == 'same_url':
            options['control_url'] = proposal['action']['target']
        elif problem == 'anonymous_profile':
            settings['verification_profile'] = 'repeat_get'
        response = prepare(client, plan, proposal, **settings)
        assert response.status_code == 422, response.text
        assert not calls


def test_removing_identity_invalidates_pending_execution(tmp_path, object_server):
    base, calls = object_server
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, options = setup_check(app, client, base)
        review = prepare(client, plan, proposal, verification_profile='object_access',
                         object_access=options, max_requests=3).json()
        assert review['status'] == 'pending'
        response = client.post('/api/verification/identities/' + options['other_identity_id'] + '/remove', json={})
        assert response.status_code == 200
        identity(client, base, 'Second account', 'replacement-fixture-token')
        assert dispatch(client, review).status_code == 409
        assert client.get('/api/agent/executions/' + review['id']).json()['status'] == 'invalidated'
        assert not calls


def test_identity_registration_rejects_unsafe_inputs_and_tokens_expire_on_restart(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        for origin in ('http://example.test', 'https://example.test/path', 'https://user@example.test'):
            response = client.post('/api/verification/identities', json={'origin': origin, 'label': 'Test', 'token': OWNER})
            assert response.status_code == 422 and OWNER not in response.text
        invalid = client.post('/api/verification/identities',
                              json={'origin': 'https://example.test', 'label': 'Test', 'token': OWNER + '\r\n'})
        assert invalid.status_code == 422 and OWNER not in invalid.text
        identity(client, 'https://example.test', 'Test', OWNER)
        assert len(client.get('/api/verification/identities').json()) == 1
    with TestClient(create_app(tmp_path)) as client:
        assert client.get('/api/verification/identities').json() == []


@pytest.mark.parametrize('object_server', [True], indirect=True)
def test_authenticated_checks_use_verified_tls_and_approved_ca(tmp_path, object_server):
    base, calls = object_server
    app = create_app(tmp_path / 'state')
    with TestClient(app) as client:
        plan, proposal, options = setup_check(app, client, base)
        common = {'verification_profile': 'object_access', 'object_access': options, 'max_requests': 3}
        untrusted = prepare(client, plan, proposal, **common).json()
        failed = wait_done(client, dispatch(client, untrusted).json()['run']['id'])
        assert not calls
        report = client.get(f'/api/runs/{failed["id"]}/verification').json()
        assert report['outcome'] == 'inconclusive'
        assert report['captures'][0]['error'] == 'SSLCertVerificationError'
        ca = client.post('/api/inputs', json={'name': 'Fixture CA', 'path': str(tmp_path / 'object-ca.pem')})
        assert ca.status_code == 201
        review = prepare(client, plan, proposal, **common,
                         http_routing={'mode': 'direct', 'ca_input_id': ca.json()['id']})
        assert review.status_code == 201 and not calls
        completed = wait_done(client, dispatch(client, review.json()).json()['run']['id'])
        report = client.get(f'/api/runs/{completed["id"]}/verification').json()
        assert report['outcome'] == 'signal_observed' and len(calls) == 3
        journal = client.get('/api/http-history/' + report['captures'][0]['exchange_id']).json()
        assert journal['route']['tls_verified'] and journal['route']['ca_sha256']
