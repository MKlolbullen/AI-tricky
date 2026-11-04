import concurrent.futures
import json

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.evidence import EvidenceIndex, ReviewConflict
from backend.observations import canonical_asset, parse_cli
from backend.store import Store
from backend.tests.test_local import target_server, wait_done
from backend.tests.test_workflows import graph, launch


def run(store, **config):
    r = store.new_run({'targets': ['https://example.com/'], 'allow_http': True, 'engine': 'workflow', **config})
    store.status(r['id'], 'completed')
    return r['id']


def capture(store, rid, url='https://example.com/', status=200, body='hello'):
    return store.artifact(rid, 'http-1.json', {'url': url, 'status': status, 'body': body,
                                             'headers': {'Date': 'volatile', 'Server': 'test'}}, node_id='http')


def nuclei(store, rid, *, severity='high', url='https://example.com/api', extracted=None):
    row = {'template-id': 'example-exposure', 'matched-at': url, 'matcher-name': 'body', 'type': 'http',
           'info': {'name': 'Example exposure', 'severity': severity}, 'extracted-results': extracted or []}
    return store.artifact(rid, 'cli-1-nuclei.json', {'tool_id': 'nuclei', 'stdout': json.dumps(row), 'exit_code': 0}, node_id='scanner')


@pytest.mark.parametrize('tool,output,kind,asset', [
    ('httpx', 'https://EXAMPLE.com:443/api', 'endpoint', 'https://example.com/api'),
    ('httpx', '{"url":"https://example.com/","status_code":200,"title":"Hello"}', 'http', 'https://example.com/'),
    ('dnsx', 'EXAMPLE.com [192.0.2.2,192.0.2.1]', 'dns', 'example.com'),
    ('dnsx', '{"host":"example.com","a":["192.0.2.1"]}', 'dns', 'example.com'),
    ('naabu', 'example.com:443', 'service', 'example.com'),
    ('naabu', '[2001:db8::1]:443', 'service', '2001:db8::1'),
    ('katana', '{"request":{"endpoint":"https://example.com/api"}}', 'endpoint', 'https://example.com/api'),
    ('nmap', 'Nmap scan report for example.com (192.0.2.1)\n443/tcp open https', 'service', '192.0.2.1'),
])
def test_common_tool_output_contracts(tool, output, kind, asset):
    rows, report = parse_cli(tool, output)
    assert len(rows) == 1
    assert rows[0]['kind'] == kind and rows[0]['asset'] == asset
    assert report['supported'] and report['parser_version'] == '1'


@pytest.mark.parametrize('tool', ['httpx', 'dnsx', 'naabu', 'nmap', 'katana', 'nuclei', 'unimplemented'])
def test_malformed_output_never_becomes_a_confirmed_finding(tool):
    text = '\n'.join(['null', '[]', 'not a record', '{"host":[]}',
                      '{"template-id":"test","info":{"name":"test","severity":[]},"matched-at":[]}',
                      '{"request":null}', '{"host":"example.com","port":true}'])
    records, report = parse_cli(tool, text)
    assert all(not r.get('finding') or r['finding']['evidence_status'] == 'CANDIDATE' for r in records)
    assert report['unparsed_lines'] > 0


def test_canonical_assets_preserve_path_query_and_identity_boundaries():
    assert canonical_asset('https://EXAMPLE.com:443/Api?x=2&x=1#f') == 'https://example.com/Api?x=2&x=1'
    assert canonical_asset('http://[2001:0db8::1]:80/') == 'http://[2001:db8::1]/'
    assert canonical_asset('https://example.com/Api') != canonical_asset('https://example.com/api')
    assert canonical_asset('https://secret@example.com/') is None
    assert canonical_asset('file:///etc/passwd') is None
    assert canonical_asset('https://example.com:0/') is None


def test_historical_index_is_idempotent_and_does_not_rewrite_evidence(tmp_path):
    store = Store(tmp_path); rid = run(store); aid = capture(store, rid)
    original = store.content(aid)
    index = EvidenceIndex(store)
    assert index.observations()['total'] == 1
    assert index.observations()['total'] == 1
    assert store.content(aid) == original
    restarted = EvidenceIndex(Store(tmp_path))
    assert restarted.observations()['items'][0]['artifact_id'] == aid
    assert restarted.observations(run_id=rid)['items'][0]['node_id'] == 'http'
    assert restarted.findings()['total'] == 0  # A successful HTTP response is not a vulnerability.


def test_index_concurrency_deduplicates_and_retains_all_evidence(tmp_path):
    store = Store(tmp_path); rid = run(store)
    aids = [nuclei(store, rid), nuclei(store, rid)]
    index = EvidenceIndex(store)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda _: index.index_pending(), range(3)))
    assert index.observations()['total'] == 2
    findings = index.findings()
    assert findings['total'] == 1
    detail = index.finding(findings['items'][0]['id'])
    assert {o['artifact_id'] for o in detail['occurrences']} == set(aids)
    assert detail['status'] == 'candidate' and detail['confidence'] == 'unknown'


def test_review_history_conflicts_and_new_output_preserves_operator_decisions(tmp_path):
    store = Store(tmp_path); first = run(store); aid = nuclei(store, first)
    index = EvidenceIndex(store); fid = index.findings()['items'][0]['id']
    review = dict(expected_revision=1, status='verified', severity='medium', confidence='high',
                  note='Reproduced against the captured request and response.', evidence_id=aid)
    detail = index.review(fid, **review)
    assert detail['revision'] == 2 and detail['reviews'][0]['previous']['status'] == 'candidate'
    with pytest.raises(ReviewConflict):
        index.review(fid, **review)
    second = run(store); second_aid = nuclei(store, second, severity='critical')
    detail = EvidenceIndex(Store(tmp_path)).finding(fid)
    assert detail['severity'] == 'medium' and detail['status'] == 'verified'
    assert detail['observed_after_review']
    assert len(detail['reviews']) == 1 and len(detail['occurrences']) == 2
    assert detail['first_seen'] == store.artifact_metadata(aid)['captured_at']
    assert detail['last_seen'] == store.artifact_metadata(second_aid)['captured_at']
    assert index.findings(run_id=second, status='verified', severity='medium', q='exposure')['total'] == 1


def test_model_candidates_require_same_run_captured_http_provenance(tmp_path):
    store = Store(tmp_path); first = run(store); aid = capture(store, first)
    second = run(store)
    candidate = {'title': 'Potential issue', 'severity': 'medium', 'rationale': 'Review this response',
                 'next_test': 'Compare behavior', 'evidence_ids': [aid]}
    content = [{'analysis': {'candidates': [candidate]}}]
    store.artifact(second, 'node-analysis.json', content, node_id='analysis')
    index = EvidenceIndex(store)
    assert index.findings()['total'] == 0
    model_aid = store.artifact(first, 'node-analysis.json', content, node_id='analysis')
    finding = index.findings()['items'][0]
    detail = index.finding(finding['id'])
    assert set(detail['occurrences'][0]['evidence_ids']) == {aid, model_aid}
    with pytest.raises(ValueError, match='rather than model analysis'):
        index.review(finding['id'], expected_revision=1, status='verified', severity='medium', confidence='high',
                     note='Model said so', evidence_id=model_aid)
    with pytest.raises(ValueError, match='Select evidence attached'):
        index.review(finding['id'], expected_revision=1, status='verified', severity='medium', confidence='high',
                     note='Unrelated evidence', evidence_id='outside')


def test_comparison_tracks_values_and_absence_without_changing_review_state(tmp_path):
    store = Store(tmp_path); first = run(store)
    capture(store, first, url='https://example.com/changed', status=200)
    capture(store, first, url='https://example.com/same')
    capture(store, first, url='https://example.com/missing')
    nuclei(store, first)
    second = run(store)
    capture(store, second, url='https://example.com/changed', status=403)
    capture(store, second, url='https://example.com/same')
    capture(store, second, url='https://example.com/new')
    index = EvidenceIndex(store)
    result = index.compare(first, second)
    assert result['summary'] == {'new': 1, 'changed': 1, 'unchanged': 1, 'not_observed': 2}
    assert result['findings'][0]['state'] == 'not_observed'
    assert index.finding(result['findings'][0]['id'])['status'] == 'candidate'
    changed = next(o for o in result['observations'] if o['state'] == 'changed')
    assert changed['before'][0]['data']['status'] == 200 and changed['after'][0]['data']['status'] == 403
    assert changed['after'][0]['evidence_ids']
    assert 'does not establish resolution' in result['absence_means']


def test_comparison_uses_observed_snapshots_not_current_review_severity(tmp_path):
    store = Store(tmp_path); first, second = run(store), run(store)
    aid = nuclei(store, first); nuclei(store, second, severity='critical')
    index = EvidenceIndex(store); fid = index.findings()['items'][0]['id']
    index.review(fid, expected_revision=1, status='resolved', severity='low', confidence='medium', note='Operator resolution', evidence_id=aid)
    changes = index.compare(first, second)['findings']
    assert changes[0]['state'] == 'changed'
    assert changes[0]['before'][0]['data']['severity'] == 'high' and changes[0]['after'][0]['data']['severity'] == 'critical'
    assert changes[0]['after'][0]['evidence_ids']


def test_comparison_reports_scope_planning_and_partial_output_limits(tmp_path):
    store = Store(tmp_path); first = run(store)
    second = run(store, targets=['https://other.example/'], allow_http=False)
    store.status(second, 'failed')
    store.artifact(second, 'cli-1-other.json', {'tool_id': 'other', 'stdout': 'raw only', 'exit_code': 1})
    comparison = EvidenceIndex(store).compare(first, second)
    assert len(comparison['warnings']) >= 4
    assert any(not c['report']['supported'] for c in comparison['coverage'])


def test_api_pagination_review_validation_and_missing_resources(tmp_path):
    store = Store(tmp_path); rid = run(store); aid = nuclei(store, rid)
    for i in range(3):
        capture(store, rid, url=f'https://example.com/{i}')
    with TestClient(create_app(tmp_path)) as client:
        page = client.get('/api/observations?limit=2&offset=1').json()
        assert len(page['items']) == 2 and page['total'] == 4
        finding = client.get('/api/findings?run_id=' + rid).json()['items'][0]
        endpoint = '/api/findings/' + finding['id'] + '/reviews'
        body = {'expected_revision': 1, 'status': 'verified', 'severity': 'high', 'confidence': 'high', 'note': ' '} 
        assert client.post(endpoint, json=body).status_code == 422
        body['note'] = 'Verified manually'
        assert client.post(endpoint, json=body).status_code == 422
        body['evidence_id'] = aid
        assert client.post(endpoint, json=body).status_code == 200
        assert client.post(endpoint, json=body).status_code == 409
        assert client.get('/api/findings/missing').status_code == 404
        assert client.get('/api/observations?run_id=missing').status_code == 404
        assert client.get(f'/api/runs/{rid}/compare?baseline={rid}').status_code == 422
        assert client.get(f'/api/runs/{rid}/compare?baseline=missing').status_code == 404


def test_live_native_workflow_populates_observations_and_comparison(tmp_path, target_server):
    base, handler = target_server
    with TestClient(create_app(tmp_path)) as client:
        first = launch(client, base, graph('native_scope', 'native_http')).json()['id']
        assert wait_done(client, first)['status'] == 'completed'
        second = launch(client, base, graph('native_scope', 'native_http')).json()['id']
        assert wait_done(client, second)['status'] == 'completed'
        observations = client.get('/api/observations?run_id=' + second).json()
        assert observations['total'] == 1 and observations['items'][0]['data']['status'] == 200
        assert client.get('/api/findings').json()['total'] == 0
        comparison = client.get(f'/api/runs/{second}/compare?baseline={first}').json()
        assert comparison['summary']['unchanged'] == 1
        assert len(handler.calls) == 2  # Indexing/review/comparison causes no additional target traffic.


def test_legacy_artifact_schema_migrates_without_losing_capture(tmp_path):
    import sqlite3
    with sqlite3.connect(tmp_path / 'reconforge.sqlite3') as c:
        c.executescript('''CREATE TABLE artifacts(id TEXT PRIMARY KEY,run_id TEXT,name TEXT,content TEXT);
                          CREATE TABLE runs(id TEXT PRIMARY KEY,status TEXT,created TEXT,updated TEXT,config TEXT,result TEXT);''')
        c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?)', ('legacy-run', 'completed', '2026-01-01T00:00:00+00:00',
                  '2026-01-01T00:00:00+00:00', '{"targets":["https://example.com/"],"allow_http":true}', None))
        content = json.dumps({'url': 'https://example.com/', 'status': 200, 'body': 'original'})
        c.execute('INSERT INTO artifacts VALUES(?,?,?,?)', ('legacy-artifact', 'legacy-run', 'http-1.json', content))
    store = Store(tmp_path)
    assert store.db.name == 'reconforge.sqlite3'
    page = EvidenceIndex(store).observations()
    assert page['items'][0]['time_basis'] == 'run-start (legacy)'
    assert page['items'][0]['observed_at'] == '2026-01-01T00:00:00+00:00'
    assert store.content('legacy-artifact')['body'] == 'original'


def test_failed_nodes_and_truncated_capture_are_visible_in_comparison(tmp_path):
    store = Store(tmp_path); first, second = run(store), run(store)
    store.artifact(second, 'http-1.json', {'url': 'https://example.com/', 'status': 200, 'body': 'prefix', 'truncated': True})
    store.node_status(second, 'http', 'completed', {'errors': 1})
    result = EvidenceIndex(store).compare(first, second)
    assert any('node errors' in w for w in result['warnings'])
    assert any('truncated' in w for w in result['warnings'])


def test_non_finite_json_and_generated_files_remain_raw_evidence(tmp_path):
    records, report = parse_cli('httpx', '{"url":"https://example.com/","status_code":200,"tech":NaN}')
    assert not records and report['unparsed_lines'] == 1
    store = Store(tmp_path); rid = run(store)
    store.artifact(rid, 'scanner/report.json', {'encoding': 'base64', 'bytes': 'arbitrary file content'})
    assert EvidenceIndex(store).observations()['total'] == 0
