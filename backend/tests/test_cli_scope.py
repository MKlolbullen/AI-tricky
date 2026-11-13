"""Relay contract and Linux integration tests for enforced CLI scope."""

import asyncio
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from backend import cli_scope
from backend.app import RunControl, create_app
from backend.cli_runner import digest, execute_cli
from backend.proposals import ProposalPlanner
from backend.scope import ScopeError
from backend.store import Store
from backend.tests.test_evidence import capture, run as source_run
from backend.tests.test_proposal_execution import prepare
from backend.tests.test_proposals import report

BIN_DIR = os.environ.get('AI_TRICKY_SCOPE_BIN')


@pytest.fixture
def gateway():
    store = Mock()
    store.content.return_value = {'http_exchange': {'response': {
        'status': 200, 'headers': [['Content-Type', 'text/plain']],
        'body_base64': base64.b64encode(b'fixture').decode(),
    }}}
    calls = []

    async def fetch(url, *, node_id):
        calls.append((url, node_id))
        return {'http_exchange_id': 'exchange', 'artifact_id': 'capture'}

    return cli_scope.ScopedGateway('run', 'fuzz', {}, SimpleNamespace(cancelled=False), store, fetch,
                                   {'/allowed': 'https://example.test/app/allowed'}), calls


def test_relay_only_dispatches_bound_get_routes(gateway):
    relay, calls = gateway

    async def run():
        async def request(head):
            reader = asyncio.StreamReader()
            reader.feed_data(head + b'\r\n\r\n')
            reader.feed_eof()
            return await relay.response(reader)

        for request_head in (
            b'CONNECT example.test:443 HTTP/1.1',
            b'GET https://example.test/allowed HTTP/1.1',
            b'GET /allowed?extra=true HTTP/1.1',
            b'GET /%61llowed HTTP/1.1',
            b'GET /outside HTTP/1.1',
            b'GET /allowed HTTP/1.1\r\nTransfer-Encoding: chunked',
        ):
            assert (await request(request_head))[0] == 403
        assert not calls
        assert await request(b'GET http://127.0.0.1:28080/allowed HTTP/1.1\r\nAuthorization: secret') == (
            200, [['Content-Type', 'text/plain']], b'fixture',
        )
        assert (await request(b'GET /allowed HTTP/1.1'))[0] == 403

    asyncio.run(run())
    assert calls == [('https://example.test/app/allowed', 'fuzz')]
    assert relay.requests == 1
    assert relay.denied == 7
    assert relay.store.event.call_count == 7
    assert json.loads(relay.remap_stdout('{"url":"http://127.0.0.1:28080/allowed"}')) == {
        'url': 'https://example.test/app/allowed', 'http_exchange_id': 'exchange',
    }


@pytest.mark.parametrize('value', ['../outside', 'a//b', '/absolute', '%2e%2e', 'q?x=1', 'a\\b', 'å'])
def test_wordlist_only_accepts_literal_relative_paths(tmp_path, value):
    words = tmp_path / 'words.txt'
    words.write_text(value + '\n', encoding='utf-8')
    with pytest.raises(ScopeError):
        cli_scope.path_words(words)


def payload(client, base, words='ok\nredirect\nmissing\n'):
    target = client.post('/api/targets', json={'value': base}).json()['id']
    starter = client.get('/api/workflow-starters/enforced-ffuf')
    assert starter.status_code == 200, starter.text
    graph = starter.json()
    wordlist = client.post('/api/inputs', json={'name': 'paths.txt', 'content': words}).json()['id']
    fuzz = next(node['data'] for node in graph['nodes'] if node['id'] == 'fuzz')
    fuzz.update(inputRefs={'wordlist': wordlist}, params={'-mc': '200,302'})
    return {'engine': 'workflow', 'workflow': graph, 'target_ids': [target], 'max_requests': 2,
            'allow_cli': True, 'allow_http': True, 'cli_scope': 'enforced'}


def test_preflight_rejects_unsupported_modes_and_bindings(tmp_path):
    with TestClient(create_app(tmp_path / 'state')) as client:
        options = payload(client, 'http://localhost/app')
        options['http_routing'] = {'mode': 'proxy', 'proxy_url': 'http://127.0.0.1:8080'}
        check = client.post('/api/runs/preflight', json=options).json()
        assert not check['ready']
        assert 'Direct HTTP routing' in str(check['issues'])
        options = payload(client, 'http://localhost/app', '../outside\n')
        check = client.post('/api/runs/preflight', json={**options, 'allow_http': False}).json()
        assert not check['ready']
        assert 'literal relative paths' in str(check['issues'])
        graph = client.get('/api/workflow-starters/web-recon').json()
        options = {**options, 'workflow': graph, 'allow_http': False}
        check = client.post('/api/runs/preflight', json=options).json()
        assert not check['ready']
        assert 'supports only ffuf' in str(check['issues'])


def fixture_executable(path, marker):
    path.write_text(f'#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).write_text("launched")\n')
    path.chmod(0o755)
    return path


@pytest.mark.skipif(sys.platform != 'linux', reason='Enforced CLI scope is Linux-only')
def test_helper_change_while_launch_waits_blocks_admission(tmp_path, monkeypatch):
    store = Store(tmp_path / 'state')
    launched = tmp_path / 'launched'
    ffuf, bwrap, relay = (fixture_executable(tmp_path / name, launched) for name in ('ffuf', 'bwrap', 'relay'))
    words = tmp_path / 'paths.txt'
    words.write_text('ok\n')
    entry = store.add_input('paths', 'file', words.resolve(), digest(words))
    config = {'targets': ['https://example.test/app'], 'max_hosts': 1, 'allow_cli': True,
              'max_cli_invocations': 1, 'max_seconds': 5, 'cli_scope': 'enforced',
              'http_routing': {'mode': 'direct'},
              'cli_binaries': {'ffuf': {'path': str(ffuf), 'sha256': digest(ffuf)}},
              'cli_sandbox': {'bwrap': cli_scope.executable_pin(str(bwrap)),
                              'relay': cli_scope.executable_pin(str(relay))}}
    data = {'toolId': 'ffuf', 'inputRefs': {'wordlist': entry['id']}, 'params': {}, 'require_cli_scope': True}
    rid = store.new_run(config)['id']
    ctl = RunControl()
    ctl.gate.clear()
    checks = []
    verify = cli_scope.verify_pins

    def recorded(pins):
        checks.append(pins)
        verify(pins)

    monkeypatch.setattr(cli_scope, 'verify_pins', recorded)

    async def fetch(url, *, node_id):
        raise AssertionError('No target request is expected.')

    async def exercise():
        task = asyncio.create_task(execute_cli(rid, 'fuzz', data, {'targets': ['https://example.test/app']},
                                               config, ctl, store, fetch=fetch))
        for _ in range(100):
            if checks:
                break
            await asyncio.sleep(.01)
        await asyncio.sleep(.05)
        assert len(checks) == 1 and not task.done()
        relay.write_text(relay.read_text() + '# replaced while the launch was paused\n')
        ctl.gate.set()
        with pytest.raises(ScopeError, match='helpers changed'):
            await task

    asyncio.run(exercise())
    assert len(checks) == 2
    assert ctl.cli_invocations == 0 and not launched.exists()
    assert not any(event['kind'] == 'cli.admitted' for event in store.events(rid))


def enforced_plan(app, client, scope, url, adapter):
    client.post('/api/targets', json={'value': scope}).raise_for_status()
    store = app.state.store
    rid = source_run(store, targets=[scope], max_hosts=8, cli_scope='enforced')
    capture(store, rid, url=url)
    planner = ProposalPlanner(store)
    oid = planner.evidence.observations(run_id=rid)['items'][0]['id']
    context = planner.context(rid, [oid], 'Collect follow-up evidence', 'medium')
    return planner.save('Collect follow-up evidence', context, json.dumps(report(context, adapter)))


def test_proposal_reviews_keep_enforced_source_scope(tmp_path, monkeypatch):
    executable = tmp_path / 'nuclei'
    executable.write_text(f'#!{sys.executable}\nprint("fixture output")\n')
    executable.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ.get('PATH', ''))
    folder = tmp_path / 'templates'
    folder.mkdir()
    (folder / 'reviewed.yaml').write_text('id: fixture-review\n')
    app = create_app(tmp_path / 'data')
    with TestClient(app) as client:
        templates = client.post('/api/inputs', json={'name': 'Reviewed fixtures', 'path': str(folder)}).json()['id']
        plan = enforced_plan(app, client, '127.0.0.1', 'http://127.0.0.1:8000/api', 'nuclei')
        proposal = plan['proposals'][0]
        assert any('supports only ffuf' in reason for reason in proposal['requirements'])
        response = prepare(client, plan, proposal, allow_cli=True, input_refs={'templates': templates})
        assert response.status_code == 422 and 'supports only ffuf' in response.text
        assert prepare(client, plan, proposal, allow_cli=True, input_refs={'templates': templates},
                       cli_scope='standard').status_code == 422
        native = enforced_plan(app, client, 'https://example.com/api', 'https://example.com/api', 'native_http')
        response = prepare(client, native, native['proposals'][0])
        assert response.status_code == 201, response.text
        assert response.json()['snapshot']['config']['cli_scope'] == 'enforced'
        assert len(client.get('/api/runs').json()) == 2


@pytest.mark.skipif(not BIN_DIR, reason='Requires pinned Linux isolation binaries')
def test_namespace_blocks_direct_network_and_exposes_only_bound_gateway(tmp_path, monkeypatch, gateway):
    monkeypatch.setenv('PATH', os.pathsep.join((BIN_DIR, os.environ['PATH'])))
    pins = cli_scope.preflight_sandbox({'path': str(Path(BIN_DIR) / 'ffuf')})
    probe = Path(BIN_DIR) / 'isolation-probe'
    marker = tmp_path / 'host-only.txt'
    marker.write_text('host only')
    relay, calls = gateway

    async def run(address):
        path = str(tmp_path / 'gateway.sock')
        server = await asyncio.start_unix_server(relay.accept, path=path, limit=cli_scope.MAX_HEADER)
        async with server:
            proc = await asyncio.create_subprocess_exec(
                *cli_scope.sandbox_prefix(pins), '--ro-bind', str(probe), '/scanner',
                '--ro-bind', path, '/gateway', '--', '/relay', '/scanner', address, str(marker),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env={},
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), 10)
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
            assert proc.returncode == 0, (stdout, stderr)

    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        host, port = listener.getsockname()
        with socket.create_connection((host, port), timeout=1):
            asyncio.run(run(f'{host}:{port}'))
    assert calls == [('https://example.test/app/allowed', 'fuzz')]
    assert relay.denied == 1


@pytest.mark.skipif(not BIN_DIR, reason='Requires pinned Linux isolation binaries')
def test_real_ffuf_journals_only_in_scope_requests_within_budget(tmp_path, monkeypatch):
    monkeypatch.setenv('PATH', os.pathsep.join((BIN_DIR, os.environ['PATH'])))
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            status = {'/app/ok': 200, '/app/redirect': 302}.get(self.path, 404)
            self.send_response(status)
            if status == 302:
                self.send_header('Location', '/outside')
            self.end_headers()
            self.wfile.write(b'fixture')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with TestClient(create_app(tmp_path / 'state')) as client:
            base = f'http://127.0.0.1:{server.server_port}/app'
            options = payload(client, base, 'ok\nredirect\n')
            check = client.post('/api/runs/preflight', json=options).json()
            assert check['ready'] and check['cli_scope']['sandbox_verified'], check
            response = client.post('/api/runs', json=options)
            assert response.status_code == 201, response.text
            rid = response.json()['id']
            for _ in range(150):
                run = client.get('/api/runs/' + rid).json()
                if run['status'] in ('completed', 'failed', 'cancelled'):
                    break
                time.sleep(.1)
            artifacts = client.get(f'/api/runs/{rid}/artifacts').json()
            cli = next(item for item in artifacts if item['name'] == 'cli-1-ffuf.json')
            record = client.get('/api/artifacts/' + cli['id']).json()
            nodes = client.get(f'/api/runs/{rid}/nodes').json()
            assert run['status'] == 'completed' and all(n['status'] == 'completed' for n in nodes), (nodes, record)
            assert sorted(requests) == ['/app/ok', '/app/redirect']
            history = client.get('/api/http-history', params={'run_id': rid}).json()['items']
            assert {row['url'] for row in history} == {base + '/ok', base + '/redirect'}
            assert {row['id'] for row in history} == set(record['cli_scope']['exchange_ids'])
            matched = [json.loads(row) for row in record['stdout'].splitlines()]
            assert {row['url'] for row in matched} == {base + '/ok', base + '/redirect'}
            assert {row['http_exchange_id'] for row in matched} == {row['id'] for row in history}
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.skipif(not os.environ.get('AI_TRICKY_FFUF_BIN'), reason='Requires pinned ffuf')
def test_real_ffuf_absolute_proxy_request_and_jsonl(tmp_path, gateway):
    relay, calls = gateway
    words = tmp_path / 'wordlist.txt'
    words.write_text('allowed\nblocked\n')

    async def run():
        server = await asyncio.start_server(relay.accept, '127.0.0.1', 0, limit=cli_scope.MAX_HEADER)
        async with server:
            address = f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}'
            proc = await asyncio.create_subprocess_exec(
                os.environ['AI_TRICKY_FFUF_BIN'], '-w', str(words), '-u', cli_scope.RELAY_TARGET,
                '-x', address, '-noninteractive', '-s', '-json', '-mc', 'all',
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env={'HOME': str(tmp_path)},
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), 10)
            assert proc.returncode == 0, stderr
            assert len(stdout.splitlines()) == 2
            mapped = json.loads(relay.remap_stdout(stdout.decode()))
            assert mapped['url'] == 'https://example.test/app/allowed'
            assert mapped['http_exchange_id'] == 'exchange'

    asyncio.run(run())
    assert calls == [('https://example.test/app/allowed', 'fuzz')]
    assert relay.denied == 1
