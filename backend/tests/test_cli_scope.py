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
    # The admission test only verifies executable changes. The real
    # namespace test separately exercises Unix sockets and the kernel.
    async def listener(*args, **kwargs):
        async def closed():
            pass
        return SimpleNamespace(close=lambda: None, wait_closed=closed)

    monkeypatch.setattr(asyncio, 'start_unix_server', listener)

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
    # httpx has no enforced profile, so its proposal must fail review rather than run in standard mode.
    executable = tmp_path / 'httpx'
    executable.write_text(f'#!{sys.executable}\nprint("fixture output")\n')
    executable.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ.get('PATH', ''))
    app = create_app(tmp_path / 'data')
    with TestClient(app) as client:
        plan = enforced_plan(app, client, '127.0.0.1', 'http://127.0.0.1:8000/api', 'httpx')
        proposal = plan['proposals'][0]
        assert any('supports only ffuf' in reason for reason in proposal['requirements'])
        response = prepare(client, plan, proposal, allow_cli=True)
        assert response.status_code == 422 and 'supports only ffuf' in response.text
        assert prepare(client, plan, proposal, allow_cli=True, cli_scope='standard').status_code == 422
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
            endpoints = client.get('/api/observations', params={'run_id': rid, 'kind': 'endpoint'}).json()['items']
            assert {row['exchange_id'] for row in endpoints} == {row['id'] for row in history}
            assert all(row['source'] == 'ffuf' for row in endpoints)
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


def test_probe_targets_expand_only_authorized_concrete_hosts_and_exact_urls():
    scope = {'targets': ['*.example.test', 'https://fixture.test:8443/app']}
    assert cli_scope.probe_urls(['child.example.test', 'https://fixture.test:8443/app/next?q=1'], scope) == [
        'https://child.example.test/', 'http://child.example.test/', 'https://fixture.test:8443/app/next?q=1',
    ]
    for target in ('example.test', '*.example.test', 'https://fixture.test:8443/outside'):
        with pytest.raises(ScopeError):
            cli_scope.probe_urls([target], scope)


@pytest.mark.skipif(not BIN_DIR, reason='Requires pinned Linux isolation binaries')
def test_real_httprobe_uses_scoped_get_and_journal(tmp_path, monkeypatch):
    monkeypatch.setenv('PATH', os.pathsep.join((BIN_DIR, os.environ['PATH'])))
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(302)
            self.send_header('Location', '/outside')
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with TestClient(create_app(tmp_path / 'state')) as client:
            url = f'http://127.0.0.1:{server.server_port}/app/probe'
            target = client.post('/api/targets', json={'value': url}).json()
            graph = client.get('/api/workflow-starters/enforced-httprobe').json()
            options = {'engine': 'workflow', 'workflow': graph, 'target_ids': [target['id']],
                       'cli_scope': 'enforced', 'allow_cli': True, 'allow_http': True, 'max_requests': 1}
            check = client.post('/api/runs/preflight', json=options).json()
            assert check['ready'] and check['cli_scope']['sandbox_verified'], check
            assert not requests
            response = client.post('/api/runs', json=options)
            assert response.status_code == 201, response.text
            rid = response.json()['id']
            from backend.tests.test_local import wait_done
            run = wait_done(client, rid)
            assert run['status'] == 'completed', run
            assert run['result']['request_count'] == run['result']['cli_invocation_count'] == 1
            assert requests == ['/app/probe']
            exchange, = client.get('/api/http-history', params={'run_id': rid}).json()['items']
            endpoint, = client.get('/api/observations', params={'run_id': rid, 'kind': 'endpoint'}).json()['items']
            assert (endpoint['source'], endpoint['asset'], endpoint['exchange_id']) == ('httprobe', url, exchange['id'])
            assert endpoint['data'] == {'status': 302}
            nodes = client.get(f'/api/runs/{rid}/nodes').json()
            probe = next(n for n in nodes if n['node_id'] == 'probe')
            output = client.get('/api/artifacts/' + probe['result']['artifact_id']).json()
            assert output[0]['catalog_streams']['url'] == [url]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


# ---- scanners that choose their own URLs (katana, nuclei) ------------------------------------

@pytest.fixture
def scoped():
    """A gateway that authorizes each request against one entered URL scope."""
    store = Mock()
    store.content.side_effect = lambda artifact: {'http_exchange': {'response': {
        'status': 200, 'headers': [['Content-Type', 'text/html']],
        'body_base64': base64.b64encode(artifact.encode()).decode(),
    }}}
    calls, failing = [], set()

    async def fetch(url, *, node_id):
        calls.append(url)
        if url in failing:
            return {'error': 'budget_exhausted'}
        return {'http_exchange_id': 'exchange-' + str(len(calls)), 'artifact_id': 'capture:' + url}

    relay = cli_scope.ScopedGateway('run', 'crawl', {}, SimpleNamespace(cancelled=False), store, fetch, None,
                                    tool_id='katana', scope=[cli_scope.parse_target('https://example.test/app')])
    return relay, calls, failing


def ask(relay, head):
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(head + b'\r\n\r\n')
        reader.feed_eof()
        return await relay.response(reader)
    return asyncio.run(run())


def test_scoped_gateway_authorizes_each_request_and_fetches_every_url_once(scoped):
    relay, calls, failing = scoped
    for refused in (
        b'CONNECT example.test:443 HTTP/1.1',
        b'POST https://example.test/app/login HTTP/1.1',
        b'GET /app/relative HTTP/1.1',
        b'GET https://example.test/outside HTTP/1.1',
        b'GET https://other.test/app/x HTTP/1.1',
        b'GET http://example.test/app/x HTTP/1.1',
        b'GET https://example.test/app/x#fragment HTTP/1.1',
        b'GET https://example.test/app/' + b'a' * cli_scope.MAX_URL + b' HTTP/1.1',
        b'GET https://example.test/app/x HTTP/1.1\r\nTransfer-Encoding: chunked',
    ):
        assert ask(relay, refused)[0] == 403, refused
    assert not calls and relay.denied == 9
    # Katana's proxy self-check is refused without being recorded as a scope denial.
    assert ask(relay, b'GET http://burpsuite/ HTTP/1.1')[0] == 403 and relay.denied == 9
    first = ask(relay, b'GET https://example.test/app/page?id=1 HTTP/1.1\r\nCookie: scanner=1\r\nX-Injected: yes')
    assert first == (200, [['Content-Type', 'text/html']], b'capture:https://example.test/app/page?id=1')
    # A repeat is answered from the saved exchange without a second target request.
    assert ask(relay, b'GET https://example.test/app/page?id=1 HTTP/1.1') == first
    assert calls == ['https://example.test/app/page?id=1'] and relay.requests == 1
    failing.add('https://example.test/app/over-budget')
    assert ask(relay, b'GET https://example.test/app/over-budget HTTP/1.1')[0] == 503
    assert 'https://example.test/app/over-budget' not in relay.captures and relay.denied == 10
    relay.ctl.cancelled = True
    assert ask(relay, b'GET https://example.test/app/later HTTP/1.1')[0] == 503
    assert len(calls) == 2


def test_scoped_gateway_serves_concurrent_duplicates_from_one_fetch(scoped):
    relay, calls, _ = scoped

    async def run():
        async def request():
            reader = asyncio.StreamReader()
            reader.feed_data(b'GET https://example.test/app/same HTTP/1.1\r\n\r\n')
            reader.feed_eof()
            return await relay.response(reader)
        return await asyncio.gather(*(request() for _ in range(5)))

    assert {status for status, _, _ in asyncio.run(run())} == {200}
    assert calls == ['https://example.test/app/same']


def test_scoped_output_keeps_only_in_scope_urls_and_detections_with_saved_responses(scoped):
    relay, _, _ = scoped
    listed = relay.remap_stdout('https://example.test/app/a\nhttps://other.test/app/a\nnot a url\n'
                                'https://example.test/outside\nhttps://example.test/app/a\n')
    assert listed == 'https://example.test/app/a'
    ask(relay, b'GET https://example.test/app/.git/config HTTP/1.1')
    relay.tool_id = 'nuclei'
    rows = [
        {'template-id': 'git-config', 'type': 'http', 'matched-at': 'https://example.test/app/.git/config'},
        {'template-id': 'never-fetched', 'type': 'http', 'matched-at': 'https://example.test/app/other'},
        {'template-id': 'outside', 'type': 'http', 'matched-at': 'https://other.test/app/.git/config'},
        {'template-id': 'dns', 'type': 'dns', 'matched-at': 'https://example.test/app/.git/config'},
    ]
    kept = relay.remap_stdout('\n'.join(json.dumps(row) for row in rows) + '\nhoneypot-detected hosts: 0\n')
    assert [json.loads(line)['template-id'] for line in kept.splitlines()] == ['git-config']


@pytest.mark.parametrize('tool,data,accepted', [
    ('katana', {'params': {'-d': 3, '-jc': True}}, True),
    ('katana', {'params': {'-d': '5'}}, True),
    ('katana', {'params': {'-d': 6}}, False),
    ('katana', {'params': {'-d': 0}}, False),
    ('katana', {'params': {'-d': True}}, False),
    ('katana', {'params': {'-d': '2 -ns'}}, False),
    ('katana', {'params': {'-kf': 'all'}}, False),
    ('katana', {'params': {'-e': 'cdn'}}, False),
    ('katana', {'inputRefs': {'wordlist': 'input'}}, False),
    ('nuclei', {'params': {'-severity': 'high,critical', '-tags': 'exposure'}, 'inputRefs': {'templates': 'input'}}, True),
    ('nuclei', {'params': {'-rl': 500}}, False),
    ('nuclei', {'params': {'-eh': '10.0.0.1'}}, False),
    ('nuclei', {'inputRefs': {'templates': 'input', 'file': 'other'}}, False),
    ('httpx', {}, False),
])
def test_enforced_profile_owns_crawler_and_scanner_arguments(tool, data, accepted):
    config = {'targets': ['https://example.test/app'], 'http_routing': {'mode': 'direct'}}
    node = {'toolId': tool, **data}
    if accepted:
        cli_scope.validate_node(node, config)
    else:
        with pytest.raises(ScopeError):
            cli_scope.validate_node(node, config)


@pytest.mark.skipif(not BIN_DIR, reason='Requires pinned Linux isolation binaries')
def test_real_katana_reaches_https_targets_only_through_the_relay(tmp_path, monkeypatch):
    """The scanner has no network: an https crawl is terminated in the relay and authorized at the gateway."""
    monkeypatch.setenv('PATH', os.pathsep.join((BIN_DIR, os.environ['PATH'])))
    pins = cli_scope.preflight_sandbox({'path': str(Path(BIN_DIR) / 'katana')}, 'katana')
    pages = {
        'https://app.example.test/': '<a href="/docs/a.html">a</a> <a href="https://app.example.test/docs/b.html">b</a>'
                                     ' <a href="https://outside.example.test/x">x</a>',
        'https://app.example.test/docs/a.html': '<a href="c.html">c</a>',
        'https://app.example.test/docs/b.html': 'leaf b',
        'https://app.example.test/docs/c.html': 'leaf c',
    }
    store = Mock()
    store.content.side_effect = lambda url: {'http_exchange': {'response': {
        'status': 200 if url in pages else 404, 'headers': [['Content-Type', 'text/html']],
        'body_base64': base64.b64encode(pages.get(url, 'missing').encode()).decode()}}}
    calls = []

    async def fetch(url, *, node_id):
        calls.append(url)
        return {'http_exchange_id': 'exchange-' + str(len(calls)), 'artifact_id': url}

    relay = cli_scope.ScopedGateway('run', 'crawl', {}, SimpleNamespace(cancelled=False), store, fetch, None,
                                    tool_id='katana', scope=[cli_scope.parse_target('app.example.test')])
    seeds = tmp_path / 'targets.txt'
    seeds.write_text('https://app.example.test/\n')

    async def run():
        path = str(tmp_path / 'gateway.sock')
        server = await asyncio.start_unix_server(relay.accept, path=path, limit=cli_scope.MAX_HEADER)
        async with server:
            proc = await asyncio.create_subprocess_exec(
                *cli_scope.sandbox_prefix(pins), '--ro-bind', str(Path(BIN_DIR) / 'katana'), '/scanner',
                '--ro-bind', str(seeds), '/targets', '--ro-bind', path, '/gateway', '--', '/relay', '/scanner',
                '-silent', '-list', '/targets', '-duc', '-dr', '-fs', 'fqdn', '-proxy', cli_scope.PROXY,
                '-c', '2', '-timeout', '8', '-retry', '0', '-d', '3',
                stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env={})
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), 60)
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
            assert proc.returncode == 0, stderr
            return stdout.decode()

    found = set(relay.remap_stdout(asyncio.run(run())).splitlines())
    expected = {'https://app.example.test/', 'https://app.example.test/docs/a.html',
                'https://app.example.test/docs/b.html', 'https://app.example.test/docs/c.html'}
    assert expected <= found and all(url.startswith('https://app.example.test/') for url in found)
    assert expected <= set(calls) and len(calls) == len(set(calls))
    assert all(url.startswith('https://app.example.test/') for url in calls)


def scoped_recon(client, base, templates):
    target = client.post('/api/targets', json={'value': base}).json()['id']
    graph = client.get('/api/workflow-starters/enforced-web-recon').json()
    folder = client.post('/api/inputs', json={'name': 'Fixture templates', 'path': str(templates)}).json()['id']
    next(node['data'] for node in graph['nodes'] if node['id'] == 'scan')['inputRefs'] = {'templates': folder}
    return {'engine': 'workflow', 'workflow': graph, 'target_ids': [target], 'max_requests': 40, 'max_seconds': 240,
            'allow_cli': True, 'allow_http': True, 'cli_scope': 'enforced'}


@pytest.mark.skipif(not BIN_DIR, reason='Requires pinned Linux isolation binaries')
def test_real_scoped_recon_crawls_and_scans_only_inside_the_entered_scope(tmp_path, monkeypatch):
    monkeypatch.setenv('PATH', os.pathsep.join((BIN_DIR, os.environ['PATH'])))
    requests, outside = [], []

    def fixture(log, pages):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                log.append(self.path)
                body = pages.get(self.path)
                self.send_response(200 if body is not None else 404)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write((body or 'missing').encode())

            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    other, other_thread = fixture(outside, {'/': 'outside'})
    pages = {
        '/app': f'<a href="/app/docs/a.html">a</a> <a href="/admin">admin</a>'
                f' <a href="http://127.0.0.1:{other.server_port}/">elsewhere</a>',
        '/app/docs/a.html': '<a href="b.html">b</a>',
        '/app/docs/b.html': 'leaf',
        '/app/.git/config': '[core]\n\trepositoryformatversion = 0\n',
        '/admin': 'outside the entered path',
    }
    server, thread = fixture(requests, pages)
    templates = tmp_path / 'templates'
    templates.mkdir()
    (templates / 'git-config.yaml').write_text(
        'id: fixture-git-config\ninfo:\n  name: Fixture git config\n  author: fixture\n  severity: medium\n'
        'http:\n  - method: GET\n    path:\n      - "{{BaseURL}}/.git/config"\n    matchers:\n'
        '      - type: word\n        words:\n          - "repositoryformatversion"\n')
    # This template asks for a path above the entered prefix; only the gateway can stop it.
    (templates / 'escape.yaml').write_text(
        'id: fixture-escape\ninfo:\n  name: Fixture scope escape\n  author: fixture\n  severity: high\n'
        'http:\n  - method: GET\n    path:\n      - "{{RootURL}}/admin"\n    matchers:\n'
        '      - type: word\n        words:\n          - "outside the entered path"\n')
    try:
        with TestClient(create_app(tmp_path / 'state')) as client:
            base = f'http://127.0.0.1:{server.server_port}/app'
            options = scoped_recon(client, base, templates)
            check = client.post('/api/runs/preflight', json=options).json()
            assert check['ready'] and check['cli_scope']['sandbox_verified'], check
            assert {row['http_capture'] for row in check['capture_coverage']} == {'scoped_gateway'}
            response = client.post('/api/runs', json=options)
            assert response.status_code == 201, response.text
            rid = response.json()['id']
            for _ in range(1500):
                run = client.get('/api/runs/' + rid).json()
                if run['status'] in ('completed', 'failed', 'cancelled'):
                    break
                time.sleep(.1)
            nodes = client.get(f'/api/runs/{rid}/nodes').json()
            artifacts = client.get(f'/api/runs/{rid}/artifacts').json()
            records = {item['name'].split('-', 2)[2].removesuffix('.json'): client.get('/api/artifacts/' + item['id']).json()
                       for item in artifacts if item['name'].startswith('cli-')}
            assert run['status'] == 'completed' and all(n['status'] == 'completed' for n in nodes), (nodes, records)
            assert set(records) == {'httprobe', 'katana', 'nuclei'}
            # Nothing left the entered path prefix, and the other origin saw no traffic at all.
            assert not outside and '/admin' not in requests
            assert all(path == '/app' or path.startswith('/app/') for path in requests), requests
            history = client.get('/api/http-history', params={'run_id': rid}).json()['items']
            assert history and all(row['url'] == base or row['url'].startswith(base + '/') for row in history)
            assert {row['id'] for row in history} == set().union(*(r['cli_scope']['exchange_ids'] for r in records.values()))
            assert all(r['http_capture'] == 'scoped_gateway' and r['native_requests_counted'] for r in records.values())
            crawled = set(records['katana']['stdout'].splitlines())
            assert {base + '/docs/a.html', base + '/docs/b.html'} <= crawled
            assert all(url == base or url.startswith(base + '/') for url in crawled)
            detections = [json.loads(line) for line in records['nuclei']['stdout'].splitlines()]
            assert [row['template-id'] for row in detections] == ['fixture-git-config']
            assert detections[0]['matched-at'] == base + '/.git/config'
            assert records['nuclei']['cli_scope']['denied'] >= 1
            denials = [event for event in client.get(f'/api/runs/{rid}/events').json()
                       if event['kind'] == 'cli.scope_denied' and event['data']['tool_id'] == 'nuclei']
            assert any(event['data']['reason'] == 'Request was outside the entered scope.' for event in denials)
            assert run['result']['request_count'] == len(history) <= 40
    finally:
        for instance, worker in ((server, thread), (other, other_thread)):
            instance.shutdown()
            instance.server_close()
            worker.join()
