import json

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.evidence import EvidenceIndex
from backend.tests.test_evidence import nuclei, run


def test_report_binds_current_review_and_only_selected_run_evidence(tmp_path):
    app = create_app(tmp_path)
    store = app.state.store
    index = EvidenceIndex(store)
    first = run(store)
    old_capture = nuclei(store, first)
    fid = index.findings()['items'][0]['id']
    detail = index.review(fid, expected_revision=1, status='verified', severity='low',
                          confidence='high', note='private review note', evidence_id=old_capture)
    second = run(store, targets=['*.example.com', '192.0.2.0/24', 'https://example.com/private-scope'])
    current = nuclei(store, second, extracted=['private capture'])
    nuclei(store, second, url='https://example.com/other')
    store.node_status(second, 'partial', 'completed', {'errors': 1})
    with TestClient(app) as client:
        response = client.get(f'/api/runs/{second}/assessment-report')
        assert response.status_code == 200
        report = response.json()
        assert report['run_id'] == second and report['unreviewed_count'] == 1
        assert report['scope'] == ['*.example.com', '192.0.2.0/24', 'https://example.com/[path withheld]']
        item, = report['findings']
        assert item['id'] == fid and item['artifact_ids'] == [current]
        assert item['observed_after_review']
        assert item['review'] == {
            'id': detail['reviews'][0]['id'], 'revision': 2, 'created': detail['reviews'][0]['created'],
            'status': 'verified', 'severity': 'low', 'confidence': 'high',
            'support_outside_run': True, 'artifact_id': None,
        }
        assert report['coverage_gaps']
        for secret in ('private review note', 'private capture', old_capture, 'private-scope'):
            assert secret not in response.text
        assert client.get(f'/api/runs/{first}/assessment-report').json()['findings'][0]['review']['artifact_id'] == old_capture
        assert 'private capture' in json.dumps(store.content(current))
        assert index.finding(fid)['reviews'] == detail['reviews']


def test_report_handles_empty_run_and_rejects_incomplete_or_missing_run(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        store = app.state.store
        rid = store.new_run({'targets': []})['id']
        assert client.get(f'/api/runs/{rid}/assessment-report').status_code == 409
        assert client.get('/api/runs/missing/assessment-report').status_code == 404
        store.status(rid, 'completed')
        report = client.get(f'/api/runs/{rid}/assessment-report').json()
        assert report['findings'] == [] and report['unreviewed_count'] == 0
