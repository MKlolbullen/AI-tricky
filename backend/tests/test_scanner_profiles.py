"""Scanner setup diagnostics and exchange provenance."""

import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.evidence import EvidenceIndex
from backend.http_journal import HTTPJournal, message, request_message
from backend.recon_tools import resolve_tool
from backend.store import Store
from backend.tests.test_evidence import run


def test_installer_directory_and_path_diagnostics(tmp_path, monkeypatch):
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('PATH', os.defpath)
    app_bin = tmp_path / '.local/share/ai-tricky/enforced-cli/bin'
    override = tmp_path / 'override'
    override.mkdir()
    app_bin.mkdir(parents=True)
    fallback = app_bin / 'ffuf'
    fallback.write_text('fixture')
    fallback.chmod(0o700)

    assert resolve_tool('ffuf') == str(fallback)
    alternate = override / 'ffuf'
    alternate.write_text('fixture')
    alternate.chmod(0o700)
    monkeypatch.setenv('PATH', str(override))
    assert resolve_tool('ffuf') == str(alternate)
    with TestClient(create_app(tmp_path / 'state')) as client:
        profile = next(p for p in client.get('/api/scanner-profiles').json()['profiles'] if p['id'] == 'enforced-cli')
        tool = next(t for t in profile['tools'] if t['tool_id'] == 'ffuf')
        assert tool['path'] == str(alternate) and tool['status'] == 'unverified'
        assert tool['capture'] == 'scoped_gateway'
        assert profile['inputs'][0]['state'] == 'missing'
        assert client.post('/api/support-data/install/bundled', json={}).status_code == 200
        profile = next(p for p in client.get('/api/scanner-profiles').json()['profiles'] if p['id'] == 'enforced-cli')
        assert profile['inputs'][0]['state'] == 'installed'
        assert not client.get('/api/runs').json()


def test_exchange_provenance_is_verified_without_changing_observation_comparison(tmp_path):
    store = Store(tmp_path)
    journal = HTTPJournal(store)
    evidence = EvidenceIndex(store)
    url = 'https://example.com/api/known'

    def observed(rid, node='fuzz'):
        eid = journal.begin(rid, node, 1, url, {'mode': 'direct'}, request_message(url))
        journal.finish(eid, response=message('HTTP/1.1 200 OK', [], status=200))
        return eid

    def write_cli(rid, exchange, extra=()):
        pairs = [(url, exchange), *extra]
        store.artifact(rid, 'cli-1-ffuf.json', {
            'tool_id': 'ffuf', 'http_capture': 'scoped_gateway', 'exit_code': 0,
            'cli_scope': {'mode': 'enforced', 'exchange_ids': [eid for _, eid in pairs]},
            'stdout': '\n'.join(json.dumps({'url': asset, 'http_exchange_id': eid, 'status': 599}) for asset, eid in pairs),
        }, node_id='fuzz')

    old, new = run(store), run(store)
    prior, current = observed(old), observed(new)
    write_cli(old, prior)
    write_cli(new, current, [(url, prior), (url, observed(new, 'other')), (url + '/different', current)])
    item, = evidence.observations(run_id=new)['items']
    assert item['exchange_id'] == current and item['data'] == {'status': 200}
    assert not evidence.findings()['items']
    change, = evidence.compare(old, new)['observations']
    assert change['state'] == 'unchanged'
