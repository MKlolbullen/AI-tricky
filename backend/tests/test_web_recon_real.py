"""Real pinned binaries against a loopback fixture, with recorded passive discovery."""

import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.recon_tools import PROFILES, tool_check
from backend.team import SPECIALIST_ROLES
from backend.tests.test_team_routing import specialist_fixture

BINARIES = os.environ.get('AI_TRICKY_RECON_BIN')
pytestmark = pytest.mark.skipif(not BINARIES, reason='Install the pinned web recon tools first')


@pytest.mark.parametrize(('tool', 'flags'), [
    ('subfinder', ('-silent', '-d', '-duc')),
    ('assetfinder', ('-subs-only',)),
    ('httprobe', ('-p',)),
    ('katana', ('-silent', '-list', '-jc', '-dr', '-fs', '-duc', '-cs')),
    ('nuclei', ('-silent', '-list', '-jsonl', '-dr', '-ni', '-duc', '-t')),
])
def test_real_tool_version_and_help(tmp_path, tool, flags):
    binary = Path(BINARIES) / tool
    check = tool_check(tool, binary)
    assert check['status'] == 'tested_version', check
    assert check['installed_version'] == PROFILES[tool][1]
    result = subprocess.run([str(binary), '-h'], capture_output=True, text=True, timeout=20,
                            cwd=tmp_path, env={'HOME': str(tmp_path), 'PATH': os.defpath})
    output = result.stdout + result.stderr
    for flag in flags:
        assert flag in output, (flag, output[:1500])


@pytest.fixture
def local_web():
    class Handler(BaseHTTPRequestHandler):
        requests = []

        def do_GET(self):
            path = self.path.split('?', 1)[0]
            self.requests.append(path)
            outside = f'http://127.0.0.1:{self.server.server_port}/outside.js'
            pages = {
                '/': ('text/html', '<script src="/main.js"></script><script src="/bundle.webchunk"></script>'
                      f'<a href="/jump">Redirect</a><a href="{outside}">Outside</a>'),
                '/main.js': ('application/javascript', 'import("./lazy.ts");\n//# sourceMappingURL=main.js.map'),
                '/bundle.webchunk': ('application/javascript', 'const fixture = true;'),
                '/lazy.ts': ('text/plain', 'const fixture: boolean = true;'),
                '/main.js.map': ('application/json', '{"version":3,"file":"main.js","sources":["src/main.ts"]}'),
                '/package.json': ('application/json', '{"name":"local-recon-fixture","version":"1.0.0"}'),
            }
            if path == '/jump':
                self.send_response(302)
                self.send_header('Location', outside)
                self.end_headers()
                return
            page = pages.get(path)
            self.send_response(200 if page else 404)
            if page:
                self.send_header('Content-Type', page[0])
            self.end_headers()
            if page:
                self.wfile.write(page[1].encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, Handler.requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_real_probe_crawl_scan_and_source_evidence(tmp_path, local_web, monkeypatch):
    # The real passive binaries are checked separately. Replay recorded
    # discoveries so this test needs no third-party discovery API.
    port, requests = local_web
    discovery = tmp_path / 'discovery'
    discovery.mkdir()
    for name in ('subfinder', 'assetfinder'):
        executable = discovery / name
        executable.write_text(f'#!{sys.executable}\nprint("localhost\\noutside.invalid")\n')
        executable.chmod(0o700)
    monkeypatch.setenv('PATH', os.pathsep.join((str(discovery), BINARIES, os.defpath)))
    calls = []
    origin = f'http://localhost:{port}'
    with TestClient(create_app(tmp_path / 'state', assessor=specialist_fixture(calls, origin + '/'))) as client:
        response = client.post('/api/support-data/install/bundled', json={})
        assert response.status_code == 200, response.text
        graph = client.get('/api/workflow-starters/web-recon?scan=true&review=true').json()
        scan = next(node for node in graph['nodes'] if node['id'] == 'scan')
        assert scan['data']['inputRefs']['templates']
        next(node for node in graph['nodes'] if node['id'] == 'probe')['data']['params'] = {
            '-p': f'http:{port}',
        }
        target = client.post('/api/targets', json={'value': 'localhost'}).json()
        payload = {'engine': 'workflow', 'workflow': graph, 'target_ids': [target['id']],
                   'allow_cli': True, 'allow_http': True, 'max_seconds': 90, 'max_requests': 24}
        check = client.post('/api/runs/preflight', json=payload).json()
        assert check['ready'], check
        assert {entry['tool_id'] for entry in check['tool_checks'] if entry['status'] == 'tested_version'} == {
            'httprobe', 'katana', 'nuclei',
        }
        response = client.post('/api/runs', json=payload)
        assert response.status_code == 201, response.text
        rid = response.json()['id']
        for _ in range(450):
            run = client.get('/api/runs/' + rid).json()
            if run['status'] in ('completed', 'failed', 'cancelled'):
                break
            time.sleep(.2)
        nodes = client.get(f'/api/runs/{rid}/nodes').json()
        artifacts = client.get(f'/api/runs/{rid}/artifacts').json()
        captures = {a['name']: client.get('/api/artifacts/' + a['id']).json()
                    for a in artifacts if a['name'].startswith('cli-')}
        assert run['status'] == 'completed', (run, nodes)
        assert all(n['status'] == 'completed' for n in nodes), (nodes, captures)
        assert {record['tool_id'] for record in captures.values()} >= {'httprobe', 'katana', 'nuclei'}
        crawler = next(record for record in captures.values() if record['tool_id'] == 'katana')
        assert '/main.js' in crawler['stdout'], crawler
        source_node = next(node for node in nodes if node['node_id'] == 'sources')
        report = client.get('/api/artifacts/' + source_node['result']['artifact_id']).json()[0]
        manifest = report['manifest']
        assert {entry['kind'] for entry in manifest} >= {'js', 'ts', 'webchunk', 'map'}
        for entry in manifest:
            assert entry['url'].startswith(origin + '/')
            assert entry['artifact_id'] and entry['body_sha256']
            capture = client.get('/api/artifacts/' + entry['artifact_id']).json()
            assert capture['http_exchange_id']
        findings = client.get('/api/findings', params={'run_id': rid}).json()['items']
        assert any(f['title'] == 'NPM package.json Disclosure' and f['status'] == 'candidate' for f in findings), captures
        assert [role for role, _ in calls] == SPECIALIST_ROLES
        review = next(node for node in nodes if node['node_id'] == 'review')
        team = client.get('/api/artifacts/' + review['result']['artifact_id']).json()[0]
        assert all(member['status'] == 'ok' for member in team['members']), team
        plan = team['members'][-1]['analysis']
        assert plan['execution'] == 'not_executed' and plan['validations']
        capture_ids = {a['id'] for a in artifacts if a['node_id'] == 'capture' and a['name'].startswith('http-')}
        assert set(plan['validations'][0]['evidence_ids']) <= capture_ids
        assert '/outside.js' not in requests
