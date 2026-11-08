import asyncio
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from backend.app import RunControl, create_app
from backend.catalog import scoped_lines
from backend.catalog_execution import source_values, preflight
from backend.cli_runner import digest, execute_cli
from backend.scope import ScopeError, authorize, network_hosts, parse_target
from backend.store import Store
from backend.tests.test_local import wait_done
from backend.tests.test_workflows import graph, launch
from backend.web_recon import collect_assets, crawler_scope, limits, recon_workflow
from backend.workflows import validate_workflow


@pytest.mark.parametrize('value,canonical', [('*.Example.COM.', '*.example.com'), ('*.bücher.test', '*.xn--bcher-kva.test')])
def test_wildcard_normalization(value, canonical):
    assert parse_target(value).url == canonical
    assert parse_target(value).kind == 'wildcard'


@pytest.mark.parametrize('value', ['*example.com', 'foo.*.example.com', '*.*.example.com', '*.127.0.0.1',
                                   '*.example.com/path', 'https://*.example.com/', '*.example.com:443', '*.example..com'])
def test_invalid_wildcards(value):
    with pytest.raises(ScopeError):
        parse_target(value)


@pytest.mark.parametrize('value', ['https://example.com/', 'https://example.com.evil.test/',
                                   'https://badexample.com/', 'https://127.0.0.1/', 'https://a.example.com@evil.test/'])
def test_wildcard_never_authorizes_apex_lookalikes_or_ips(value):
    with pytest.raises(ScopeError):
        authorize(value, [parse_target('*.example.com')])


def test_exact_and_wildcard_are_independent_for_http_and_tcp():
    wildcard, exact = parse_target('*.example.com'), parse_target('example.com')
    for host in ('a.example.com', 'nested.a.example.com'):
        assert authorize('https://' + host + '/', [wildcard]).host == host
        assert network_hosts(host, [wildcard], 1) == [host]
        with pytest.raises(ScopeError):
            authorize('https://' + host + '/', [exact])
    with pytest.raises(ScopeError):
        network_hosts('*.example.com', [wildcard], 1)
    assert authorize('https://example.com/', [exact, wildcard])
    assert authorize('https://deep.xn--bcher-kva.test/', [parse_target('*.bücher.test')])


def test_passive_seed_is_not_active_authorization():
    config = {'targets': ['*.example.com'], 'max_hosts': 10}
    source = {'sourceType': 'domain', 'value': ''}
    assert source_values(source, config) == ['example.com']
    candidates = ['example.com', 'api.example.com', 'deep.api.example.com', 'external.test']
    assert scoped_lines(candidates, 'targets', config)[0] == candidates[1:3]
    assert scoped_lines(candidates, 'targets', config, discovery=True)[0] == candidates[:3]
    exact = {**config, 'targets': ['example.com']}
    assert scoped_lines(candidates, 'targets', exact)[0] == ['example.com']
    assert scoped_lines(candidates, 'targets', exact, discovery=True)[0] == candidates[:3]
    with pytest.raises(ScopeError):
        source_values({**source, 'value': '*.external.test'}, config)
    with pytest.raises(ScopeError):
        source_values({'sourceType': 'targets', 'value': ''}, config)


def test_scalar_cli_filters_before_fanout_and_ffuf_adds_scoped_path(tmp_path):
    store = Store(tmp_path / 'state')
    config = {'targets': ['*.example.com'], 'max_hosts': 4, 'allow_cli': True, 'max_cli_invocations': 4, 'max_seconds': 5}
    binary = tmp_path / 'fakeffuf'
    binary.write_text(f'#!{sys.executable}\nimport sys\nprint(sys.argv[sys.argv.index("-u")+1])\n')
    binary.chmod(0o755)
    config['cli_binaries'] = {'ffuf': {'path': str(binary), 'sha256': digest(binary)}}
    wordlist = tmp_path / 'wordlist'; wordlist.write_text('admin\n')
    entry = store.add_input('words', 'file', wordlist.resolve(), digest(wordlist))
    data = {'toolId': 'ffuf', 'inputRefs': {'wordlist': entry['id']}, 'params': {}}
    rid = store.new_run(config)['id']; ctl = RunControl()
    result = asyncio.run(execute_cli(rid, 'fuzz', data, {'targets': ['https://example.com/', 'https://api.example.com/app']}, config, ctl, store))
    assert ctl.cli_invocations == 1
    artifact = store.content(result[0]['invocation_artifact_ids'][0])
    assert 'https://api.example.com/app/FUZZ' in artifact['command']
    assert any(e['kind'] == 'cli.inputs_filtered' for e in store.events(rid))


def test_recon_starters_are_typed_and_missing_wordlist_is_visible(tmp_path):
    config = {'targets': ['*.example.com'], 'max_hosts': 10, 'allow_cli': True}
    store = Store(tmp_path / 'state')
    for fuzz in (False, True):
        g = recon_workflow(fuzz=fuzz)
        validate_workflow(g, live=True)
        check = preflight(g, config, store, check_binaries=False)
        assert check['ready'] is (not fuzz)
        if fuzz:
            assert check['issues'] == [{'node_id': 'fuzz', 'reasons': ['Requires a connected or registered wordlist input.']}]
    with TestClient(create_app(tmp_path / 'api')) as c:
        assert c.get('/api/workflow-starters/web-recon').json() == recon_workflow()
        assert c.get('/api/workflow-starters/web-recon?fuzz=true').json() == recon_workflow(fuzz=True)
        assert c.get('/api/runs').json() == []


@pytest.mark.parametrize('scope,allowed,denied', [
    ('example.com', 'https://example.com:8443/api', 'https://api.example.com/'),
    ('*.example.com', 'https://deep.api.example.com/app', 'https://example.com/'),
    ('https://example.com/app', 'https://example.com:443/app/a', 'https://example.com/application'),
    ('https://example.com:8443/app', 'https://example.com:8443/app?q=1', 'https://example.com/app'),
    ('https://[::1]/app', 'https://[::1]/app/a', 'https://[::1]/other'),
])
def test_katana_scope_patterns(scope, allowed, denied):
    patterns = crawler_scope({'targets': [scope], 'max_hosts': 5})
    assert any(re.search(p, allowed) for p in patterns)
    assert not any(re.search(p, denied) for p in patterns)


@pytest.fixture
def web_server():
    class Handler(BaseHTTPRequestHandler):
        calls = []
        def do_GET(self):
            self.calls.append(self.path)
            pages = {
                '/app/': ('text/html', '<script src="main.js"></script><script src="https://external.test/evil.js"></script><a href="next">Next</a><a href="/outside.ts">Outside URL path scope</a><script src="bundle.webchunk"></script>'),
                '/app/main.js': ('application/javascript', 'x' * 17000 + ';import("./lazy.ts");\n//# sourceMappingURL=main.js.map'),
                '/app/main.js.map': ('application/json', json.dumps({'version': 3, 'sources': ['webpack:///src/index.ts'], 'sourcesContent': ['const ok=true;']})),
                '/app/bundle.webchunk': ('application/javascript', 'import("./lazy.ts");'),
                '/app/lazy.ts': ('text/plain', 'const ok: boolean = true;'),
                '/app/next': ('text/html', '<a href="redirect">Redirect</a>'),
            }
            if self.path == '/app/redirect':
                self.send_response(302); self.send_header('Location', '/outside.ts'); self.end_headers(); return
            mime, body = pages.get(self.path, ('text/plain', 'unexpected'))
            self.send_response(200); self.send_header('Content-Type', mime); self.end_headers(); self.wfile.write(body.encode())
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f'http://127.0.0.1:{server.server_port}', Handler
    server.shutdown(); server.server_close()


def test_collector_uses_full_capture_scope_and_provenance(tmp_path, web_server):
    base, handler = web_server
    g = graph('native_scope', 'native_http', 'native_web_assets', 'native_summary')
    g['nodes'][2]['data']['max_depth'] = 3
    with TestClient(create_app(tmp_path)) as c:
        rid = launch(c, base + '/app/', g, max_requests=20).json()['id']
        done = wait_done(c, rid)
        assert done['status'] == 'completed', done
        node = c.get(f'/api/runs/{rid}/nodes').json()[2]
        result = c.get('/api/artifacts/' + node['result']['artifact_id']).json()[0]
        manifest = result['manifest']
        assert {m['kind'] for m in manifest} >= {'page', 'js', 'ts', 'map', 'webchunk'}
        sourcemap = next(m for m in manifest if m['kind'] == 'map')
        assert sourcemap['discovered_from'] == base + '/app/main.js'
        assert sourcemap['map_sources'] == ['webpack:///src/index.ts']
        assert sourcemap['map_sources_content'] is True
        assert all(m['artifact_id'] and m['body_sha256'] for m in manifest)
        assert result['counts']['out_of_scope'] >= 2
        assert '/outside.ts' not in handler.calls
        assert handler.calls.count('/app/') == 1  # upstream capture reused, no extra GET
        assert done['result']['request_count'] == len(handler.calls) == len(manifest)
        raw = c.get('/api/artifacts/' + next(m['artifact_id'] for m in manifest if m['kind'] == 'js')).json()
        assert len(raw['body']) > 16000


def test_collector_budget_and_plan_only(tmp_path, web_server):
    base, handler = web_server
    g = graph('native_scope', 'native_http', 'native_web_assets')
    with TestClient(create_app(tmp_path)) as c:
        rid = launch(c, base + '/app/', g, max_requests=2).json()['id']; done = wait_done(c, rid)
        assert done['result']['request_count'] == len(handler.calls) == 2
        nodes = c.get(f'/api/runs/{rid}/nodes').json()
        result = c.get('/api/artifacts/' + nodes[2]['result']['artifact_id']).json()[0]
        assert result['counts']['errors'] == 1 and result['counts']['not_attempted'] > 0
        rid = launch(c, base + '/app/', g, allow_http=False).json()['id']
        assert wait_done(c, rid)['result']['request_count'] == 0
        assert len(handler.calls) == 2


@pytest.mark.parametrize('scope,expected', [('example.test', 'example.test'), ('*.example.test', 'app.example.test')])
def test_whole_recon_pipeline_routes_only_authorized_hosts(tmp_path, web_server, monkeypatch, scope, expected):
    base, handler = web_server
    port = base.rsplit(':', 1)[1]
    scripts = {
        'subfinder': 'print("example.test\\napp.example.test\\nexternal.test")',
        'assetfinder': 'print("app.example.test")',
        'httprobe': f'import sys\nfor host in sys.stdin.read().splitlines(): print("http://"+host+":{port}/app/")',
        'katana': 'pass',
    }
    for name, script in scripts.items():
        binary = tmp_path / name
        binary.write_text(f'#!{sys.executable}\n{script}\n'); binary.chmod(0o755)
    monkeypatch.setenv('PATH', str(tmp_path))
    resolved = []
    def resolve(host, port):
        resolved.append(host)
        assert host == expected
        return '127.0.0.1'
    monkeypatch.setattr('backend.scope.resolve_target', resolve)
    with TestClient(create_app(tmp_path / 'state')) as c:
        r = launch(c, scope, recon_workflow(), allow_cli=True, max_requests=20)
        assert r.status_code == 201, r.text
        rid = r.json()['id']; done = wait_done(c, rid)
        assert done['status'] == 'completed', done
        nodes = c.get(f'/api/runs/{rid}/nodes').json()
        assert {n['status'] for n in nodes} == {'completed'}
        assert resolved and set(resolved) == {expected}
        records = [c.get('/api/artifacts/'+a['id']).json() for a in c.get(f'/api/runs/{rid}/artifacts').json() if a['name'].endswith('-httprobe.json')]
        assert records[0]['stdout'].strip() == f'http://{expected}:{port}/app/'
        assert '/outside.ts' in handler.calls  # allowed with a whole-host scope


def test_collector_bounds_and_truncated_source_are_explicit(tmp_path):
    store = Store(tmp_path / 'state'); calls = []
    async def fetch(url, **kwargs):
        calls.append(url)
        return {'status': 200, 'body': '<script src="one.js"></script><script src="two.js"></script><a href="next">next</a>',
                'headers': {'content-type': 'text/html'}, 'truncated': True}
    values = [{'catalog_streams': {'url': ['https://api.example.com/']}}]
    config = {'targets': ['*.example.com']}
    result = asyncio.run(collect_assets(values, config, {'max_pages': 1, 'max_assets': 1, 'max_depth': 1}, fetch, store, 'source'))[0]
    assert len(calls) == 2
    assert result['counts']['truncated'] == 2
    assert result['counts']['page_limited'] >= 1 and result['counts']['asset_limited'] >= 1
    calls.clear()
    result = asyncio.run(collect_assets(values, config, {'max_depth': 0}, fetch, store, 'source'))[0]
    assert len(calls) == 1 and result['counts']['depth_limited'] == 3


def test_wildcard_selector_native_inventory_does_not_resolve(tmp_path, monkeypatch):
    def forbidden(*args):
        raise AssertionError('A selector must never reach DNS')
    monkeypatch.setattr('backend.scope.resolve_target', forbidden)
    with TestClient(create_app(tmp_path)) as c:
        r = launch(c, '*.example.test', graph('native_scope', 'native_tcp', 'native_http'), max_requests=1)
        assert r.status_code == 201, r.text
        done = wait_done(c, r.json()['id'])
        assert done['status'] == 'completed' and done['result']['request_count'] == 0


@pytest.mark.parametrize('key,value', [('max_pages', True), ('max_assets', 201), ('max_depth', -1), ('max_pages', '10')])
def test_collector_limit_validation(key, value):
    with pytest.raises(ScopeError):
        limits({key: value})
