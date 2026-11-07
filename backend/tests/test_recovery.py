import base64
import copy
import json
import os
import sys
import threading
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.catalog import TOOLS
from backend.cli_runner import input_fingerprint, prepare_context
from backend.observations import digest
from backend.recovery import WorkflowRecoveries, checked_reused_content
from backend.scope import ScopeError
from backend.tests.test_catalog import data_for
from backend.tests.test_local import target_server, wait_done
from backend.tests.test_workflows import graph, launch


def seed_source(store, target, *, captured=False, status='failed', workflow=None):
    g = workflow or graph('native_scope', 'native_http', 'native_summary')
    tid = store.add_target(target)['id']
    config = {'engine': 'workflow', 'allow_http': True, 'workflow': g, 'targets': [target], 'target_ids': [tid],
              'goal': 'Recover loopback fixture', 'parallelism': 2, 'ports': [80, 443], 'max_hosts': 1,
              'max_requests': 1, 'max_cli_invocations': 1, 'max_seconds': 30, 'allow_cli': False,
              'cli_credential_keys': []}
    run = store.new_run(config)
    rid = run['id']
    output = store.artifact(rid, 'node-n0.json', [{'target': target, 'kind': 'url'}], node_id='n0')
    store.node_status(rid, 'n0', 'completed', {'artifact_id': output, 'records': 1, 'errors': 0})
    if captured:
        aid = store.artifact(rid, 'http-1.json', {'url': target, 'status': 200, 'body': 'original capture', 'headers': {}}, node_id='n1')
        output = store.artifact(rid, 'node-n1.json', [{'url': target, 'status': 200, 'artifact_id': aid}], node_id='n1')
        store.node_status(rid, 'n1', 'completed', {'artifact_id': output, 'records': 1, 'errors': 0})
    else:
        store.node_status(rid, 'n1', 'failed', {'error': 'Fixture interruption'})
    store.node_status(rid, 'n2', 'failed' if captured else 'skipped', {'reason': 'Fixture incomplete'})
    store.status(rid, status, {'failed_nodes': 1})
    return store.run(rid)


def prepare(client, source, nodes=None, **options):
    result = client.post('/api/runs/' + source['id'] + '/recoveries', json={
        'node_ids': nodes or ['n1'], 'max_requests': 2, 'max_hosts': 1, 'max_seconds': 30, **options})
    assert result.status_code == 201, result.text
    return result.json()


def dispatch(client, review, **options):
    return client.post('/api/recoveries/' + review['id'] + '/dispatch', json={
        'expected_hash': review['snapshot_hash'], 'approve': True, **options})


def test_failed_branch_recovery_requires_fresh_review_and_reuses_completed_scope(tmp_path, target_server):
    base, handler = target_server
    app = create_app(tmp_path)
    with TestClient(app) as client:
        source = seed_source(app.state.store, base + '/')
        before = app.state.store.nodes(source['id'])
        review = prepare(client, source)
        assert not handler.calls and len(client.get('/api/runs').json()) == 1
        assert review['snapshot']['rerun_ids'] == ['n1', 'n2']
        assert set(review['snapshot']['checkpoints']) == {'n0'}
        assert dispatch(client, review, approve=False).status_code == 422
        assert dispatch(client, review, expected_hash='0' * 64).status_code == 409
        assert dispatch(client, review, max_requests=200).status_code == 422
        receipt = dispatch(client, review).json()
        run = wait_done(client, receipt['run']['id'])
        assert run['status'] == 'completed' and run['result']['request_count'] == 1
        assert run['result']['reused_nodes'] == 1
        assert handler.calls == ['/']
        nodes = client.get('/api/runs/' + run['id'] + '/nodes').json()
        assert {n['node_id']: n['status'] for n in nodes} == {'n0': 'reused', 'n1': 'completed', 'n2': 'completed'}
        assert nodes[0]['result']['source_run_id'] == source['id']
        assert app.state.store.run(source['id']) == source
        assert app.state.store.nodes(source['id']) == before
        assert 'proposal_execution' not in run['config']
        assert run['config']['workflow_recovery']['snapshot_hash'] == review['snapshot_hash']
        replay = dispatch(client, review).json()
        assert replay['created'] is False and replay['run']['id'] == run['id']
        assert handler.calls == ['/']
        audit = client.get('/api/recoveries/' + review['id']).json()
        assert [event['kind'] for event in audit['events']] == ['prepared', 'approved', 'dispatched']


def test_retrying_local_analysis_does_not_recapture_http_or_refresh_observations(tmp_path, target_server):
    base, handler = target_server
    calls = []

    async def analyst(targets, goal, fetch):
        calls.append(goal)
        if len(calls) == 1:
            raise RuntimeError('Fixture analyst failed')
        assert targets == [] and 'no target access' in (await fetch(base + '/'))['error']
        return {'report': json.dumps({'summary': 'Review recovered capture', 'candidates': [], 'coverage_limits': []})}

    app = create_app(tmp_path, assessor=analyst)
    with TestClient(app) as client:
        g = graph('native_scope', 'native_http', 'native_cai', 'native_summary')
        source = wait_done(client, launch(client, base + '/', g).json()['id'])
        assert source['status'] == 'failed' and handler.calls == ['/']
        original = client.get('/api/observations?run_id=' + source['id']).json()
        review = prepare(client, source, ['n2'])
        run = wait_done(client, dispatch(client, review).json()['run']['id'])
        assert run['result']['reused_nodes'] == 2 and run['result']['request_count'] == 0
        assert handler.calls == ['/'] and len(calls) == 2
        assert client.get('/api/observations?run_id=' + run['id']).json()['total'] == 0
        assert client.get('/api/observations?run_id=' + source['id']).json() == original
        copies = client.get('/api/runs/' + run['id'] + '/artifacts').json()
        assert any(a['name'].startswith('reused/') for a in copies)
        for node in client.get('/api/runs/' + run['id'] + '/nodes').json():
            if node['status'] == 'reused':
                source_time = app.state.store.artifact_metadata(node['result']['source_artifact_id'])['captured_at']
                assert node['result']['captured_at'] == source_time


@pytest.mark.parametrize('options', [
    {'node_ids': []}, {'node_ids': ['missing']}, {'targets': ['https://outside.invalid/']},
    {'workflow': {}}, {'max_requests': 0}, {'max_requests': True}, {'max_requests': '2'},
    {'max_seconds': 3601}, {'allow_cli': 'true'}, {'cli_credential_keys': ['OPENAI_API_KEY']},
])
def test_recovery_options_cannot_inject_scope_graph_credentials_or_invalid_limits(tmp_path, options):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        source = seed_source(app.state.store, 'https://example.invalid/')
        result = client.post('/api/runs/' + source['id'] + '/recoveries', json={'node_ids': ['n1'], **options})
        assert result.status_code == 422, result.text


@pytest.mark.parametrize('mutation', ['artifact', 'graph', 'scope', 'node'])
def test_changed_source_or_checkpoint_invalidates_review_before_traffic(tmp_path, target_server, mutation):
    base, handler = target_server
    app = create_app(tmp_path)
    with TestClient(app) as client:
        source = seed_source(app.state.store, base + '/')
        review = prepare(client, source)
        with app.state.store.connect() as c:
            if mutation == 'artifact':
                aid = review['snapshot']['checkpoints']['n0']
                c.execute('UPDATE artifacts SET content=? WHERE id=?', (json.dumps([{'target': base + '/changed', 'kind': 'url'}]), aid))
            elif mutation == 'scope':
                c.execute('DELETE FROM targets')
            elif mutation == 'graph':
                config = copy.deepcopy(source['config']); config['goal'] = 'Changed goal'
                c.execute('UPDATE runs SET config=? WHERE id=?', (json.dumps(config), source['id']))
            else:
                c.execute("UPDATE run_nodes SET status='failed' WHERE run_id=? AND node_id='n0'", (source['id'],))
        result = dispatch(client, review)
        assert result.status_code == 409, result.text
        assert client.get('/api/recoveries/' + review['id']).json()['status'] == 'invalidated'
        assert not handler.calls and len(client.get('/api/runs').json()) == 1


def test_review_expiry_revoke_restart_and_dispatched_receipt_persistence(tmp_path, target_server):
    base, handler = target_server
    app = create_app(tmp_path)
    with TestClient(app) as client:
        source = seed_source(app.state.store, base + '/')
        expired = prepare(client, source)
        with app.state.store.connect() as c:
            past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            c.execute('UPDATE workflow_recoveries SET expires=? WHERE id=?', (past, expired['id']))
        assert dispatch(client, expired).status_code == 409
        assert client.get('/api/recoveries/' + expired['id']).json()['status'] == 'expired'
        revoked = prepare(client, source)
        assert client.post('/api/recoveries/' + revoked['id'] + '/revoke', json={'expected_hash': revoked['snapshot_hash']}).json()['status'] == 'revoked'
        assert dispatch(client, revoked).status_code == 409
        receipt_review = prepare(client, source)
        receipt = dispatch(client, receipt_review).json()
        wait_done(client, receipt['run']['id'])
        pending = prepare(client, source)
    with TestClient(create_app(tmp_path)) as client:
        assert client.get('/api/recoveries/' + pending['id']).json()['status'] == 'invalidated'
        assert dispatch(client, pending).status_code == 409
        replay = dispatch(client, receipt_review).json()
        assert replay['run']['id'] == receipt['run']['id'] and replay['created'] is False
        assert handler.calls == ['/']


def test_concurrent_dispatch_creates_one_run_and_one_target_request(tmp_path, target_server):
    base, handler = target_server
    app = create_app(tmp_path)
    with TestClient(app) as client:
        source = seed_source(app.state.store, base + '/')
        review = prepare(client, source)
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(lambda _: dispatch(client, review), range(4)))
        assert all(r.status_code == 200 for r in responses), [r.text for r in responses]
        receipts = [r.json() for r in responses]
        assert sum(r['created'] for r in receipts) == 1
        assert len({r['run']['id'] for r in receipts}) == 1
        wait_done(client, receipts[0]['run']['id'])
        assert handler.calls == ['/']


def test_unhealthy_ancestors_are_rerun_and_unrelated_failed_branch_is_excluded(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        g = graph('native_scope', 'native_http', 'native_summary')
        extra = copy.deepcopy(g['nodes'][1]); extra['id'] = 'unrelated'
        g['nodes'].append(extra); g['edges'].append({'id': 'extra', 'source': 'n0', 'target': 'unrelated'})
        source = seed_source(app.state.store, 'https://example.invalid/', workflow=g)
        app.state.store.node_status(source['id'], 'unrelated', 'failed')
        review = prepare(client, source, ['n2'])
        assert review['snapshot']['rerun_ids'] == ['n1', 'n2']
        assert {n['id'] for n in review['snapshot']['config']['workflow']['nodes']} == {'n0', 'n1', 'n2'}


@pytest.mark.parametrize('source_change', ['active', 'plan', 'paired'])
def test_active_planning_and_paired_verification_runs_are_not_recoverable(tmp_path, source_change):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        source = seed_source(app.state.store, 'https://example.invalid/')
        if source_change == 'active':
            app.state.store.status(source['id'], 'running')
        else:
            config = source['config']
            if source_change == 'plan': config['allow_http'] = False
            else: config['verification'] = {'profile_id': 'repeat_get'}
            with app.state.store.connect() as c:
                c.execute('UPDATE runs SET config=? WHERE id=?', (json.dumps(config), source['id']))
        assert client.get('/api/runs/' + source['id'] + '/recovery').status_code == 409


def file_source(store, target, *, reference, source_type='file'):
    src = {'id': 'source', 'type': 'tool', 'position': {'x': 0, 'y': 0},
           'data': {'kind': 'catalog_source', 'sourceType': source_type, 'inputs': [], 'outputs': [source_type], 'output': source_type}}
    if reference.startswith('input:'): src['data']['inputId'] = reference[6:]
    sink = {'id': 'sink', 'type': 'tool', 'position': {'x': 230, 'y': 0}, 'data': data_for(TOOLS['semgrep'])}
    g = {'schema': 'offsecs-u-ai.workflow/v1', 'nodes': [src, sink],
         'edges': [{'id': 'edge', 'source': 'source', 'target': 'sink'}]}
    config = {'engine': 'workflow', 'allow_http': True, 'allow_cli': True, 'workflow': g, 'targets': [target],
              'target_ids': [store.add_target(target)['id']], 'cli_credential_keys': [], 'parallelism': 1, 'ports': [443]}
    rid = store.new_run(config)['id']
    aid = store.artifact(rid, 'node-source.json', [{'catalog_streams': {source_type: [reference]}}], node_id='source')
    store.node_status(rid, 'source', 'completed', {'artifact_id': aid, 'records': 1, 'errors': 0})
    store.node_status(rid, 'sink', 'failed', {'error': 'fixture'})
    store.status(rid, 'failed')
    return store.run(rid)


@pytest.fixture
def semgrep_fixture(tmp_path, monkeypatch):
    binary = tmp_path / 'semgrep'
    binary.write_text(f'#!{sys.executable}\nimport sys\nfrom pathlib import Path\np=Path(sys.argv[-1])\nassert p.exists()\nprint("fixture finding")\n')
    binary.chmod(0o755)
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
    return binary


def test_cached_registered_input_is_fingerprinted_and_binary_changes_invalidate_review(tmp_path, semgrep_fixture):
    app = create_app(tmp_path / 'state')
    with TestClient(app) as client:
        path = tmp_path / 'source.js'; path.write_text('captured source')
        entry = app.state.store.add_input('source', 'file', path, __import__('hashlib').sha256(path.read_bytes()).hexdigest())
        source = file_source(app.state.store, 'https://example.invalid/', reference='input:' + entry['id'])
        for change in ('input', 'binary'):
            review = prepare(client, source, ['sink'], allow_cli=True)
            assert entry['id'] in review['snapshot']['config']['recovery_input_pins']
            if change == 'input': path.write_text('changed source')
            else: semgrep_fixture.write_text(semgrep_fixture.read_text() + '\n# changed\n')
            assert dispatch(client, review).status_code == 409
            if change == 'input':
                path.write_text('captured source')


def test_copied_file_artifacts_keep_same_run_boundary_and_original_timestamp(tmp_path, semgrep_fixture):
    app = create_app(tmp_path / 'state')
    with TestClient(app) as client:
        # A synthetic completed folder producer, followed by a failed local CLI.
        store = app.state.store
        source = file_source(store, 'https://example.invalid/', reference='placeholder', source_type='folder')
        raw = {'encoding': 'base64', 'bytes': base64.b64encode(b'captured source').decode(), 'size': 15}
        file_id = store.artifact(source['id'], 'source/source.js', raw, node_id='source')
        checkpoint = store.nodes(source['id'])[0]['result']['artifact_id']
        with store.connect() as c:
            c.execute('UPDATE artifacts SET content=? WHERE id=?', (json.dumps([{'catalog_streams': {'folder': ['artifact:' + file_id]}}]), checkpoint))
        review = prepare(client, source, ['sink'], allow_cli=True)
        assert file_id in review['snapshot']['artifacts']
        run = wait_done(client, dispatch(client, review).json()['run']['id'])
        assert run['status'] == 'completed', run
        assert run['result']['cli_invocation_count'] == 1 and run['result']['request_count'] == 0
        reused = next(n for n in store.nodes(run['id']) if n['status'] == 'reused')
        value = store.content(reused['result']['artifact_id'])[0]['catalog_streams']['folder'][0]
        copy_id = value[9:]
        assert copy_id != file_id and store.artifact_metadata(copy_id)['run_id'] == run['id']
        assert store.content(copy_id) == raw
        assert store.artifact_metadata(copy_id)['captured_at'] == store.artifact_metadata(file_id)['captured_at']
        with store.connect() as c:
            c.execute('UPDATE artifacts SET content=? WHERE id=?', (json.dumps({'encoding': 'base64', 'bytes': 'AA=='}), copy_id))
        with pytest.raises(ScopeError): checked_reused_content(store, copy_id)


def test_checkpoint_references_to_another_run_are_rejected(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        source = seed_source(app.state.store, 'https://example.invalid/')
        other = seed_source(app.state.store, 'https://example.invalid/other')
        foreign = app.state.store.nodes(other['id'])[0]['result']['artifact_id']
        own = app.state.store.nodes(source['id'])[0]['result']['artifact_id']
        with app.state.store.connect() as c:
            c.execute('UPDATE artifacts SET content=? WHERE id=?', (json.dumps([{'artifact_id': foreign}]), own))
        r = client.post('/api/runs/' + source['id'] + '/recoveries', json={'node_ids': ['n1']})
        assert r.status_code == 409 and 'reused source nodes' in r.text


def test_selected_cli_credential_rotation_invalidates_review_without_exposing_keys(tmp_path, monkeypatch):
    binary = tmp_path / 'shodan'
    binary.write_text(f'#!{sys.executable}\nprint("fixture")\n'); binary.chmod(0o755)
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
    app = create_app(tmp_path / 'state')
    with TestClient(app) as client:
        source = file_source(app.state.store, 'example.invalid', reference='example.invalid', source_type='domain')
        config = source['config']; config['workflow']['nodes'][-1]['data'] = data_for(TOOLS['shodan-cli'])
        config['cli_credential_keys'] = ['SHODAN_API_KEY']
        with app.state.store.connect() as c:
            c.execute('UPDATE runs SET config=? WHERE id=?', (json.dumps(config), source['id']))
        client.post('/api/credentials', json={'updates': {'SHODAN_API_KEY': 'old-private-key'}})
        review = prepare(client, source, ['sink'], allow_cli=True)
        assert 'old-private-key' not in json.dumps(review)
        client.post('/api/credentials', json={'updates': {'SHODAN_API_KEY': 'new-private-key'}})
        r = dispatch(client, review)
        assert r.status_code == 409 and 'private-key' not in r.text
        assert len(client.get('/api/runs').json()) == 1


def test_model_endpoint_and_key_are_bound_without_model_requests(tmp_path):
    app = create_app(tmp_path)
    source = seed_source(app.state.store, 'https://example.invalid/', captured=True,
                         workflow=graph('native_scope', 'native_http', 'native_cai'))
    model = {'base_url': 'http://127.0.0.1:11434/v1', 'model': 'fixture', 'api_key': 'private-model-key'}
    recoveries = WorkflowRecoveries(app.state.store, model_config=lambda: dict(model))
    options = {'node_ids': ['n2'], 'allow_cli': False, 'max_requests': 1, 'max_cli_invocations': 1, 'max_hosts': 1, 'max_seconds': 30}
    for field in ('api_key', 'base_url', 'model'):
        previous = dict(model)
        review = recoveries.prepare(source['id'], options)
        assert 'private-model-key' not in json.dumps(review)
        model[field] += '-changed'
        assert recoveries.get(review['id'])['status'] == 'invalidated'
        model.clear(); model.update(previous)


def test_recovery_reuses_existing_pause_resume_cancel_controls(tmp_path, target_server):
    base, handler = target_server
    started = threading.Event()

    async def analyst(*args, **kwargs):
        started.set()
        await asyncio.Event().wait()

    app = create_app(tmp_path, assessor=analyst)
    with TestClient(app) as client:
        source = seed_source(app.state.store, base + '/', captured=True,
                             workflow=graph('native_scope', 'native_http', 'native_cai'))
        review = prepare(client, source, ['n2'])
        rid = dispatch(client, review).json()['run']['id']
        assert started.wait(2)
        assert client.post('/api/runs/' + rid + '/pause', json={}).json()['status'] == 'paused'
        assert client.post('/api/runs/' + rid + '/resume', json={}).json()['status'] == 'running'
        assert client.post('/api/runs/' + rid + '/cancel', json={}).json()['status'] == 'cancelled'
        assert wait_done(client, rid)['result']['request_count'] == 0
        assert not handler.calls
        assert app.state.store.run(source['id']) == source


def test_registered_folder_is_rechecked_after_copying_for_a_recovery_invocation(tmp_path):
    app = create_app(tmp_path / 'state')
    folder = tmp_path / 'source'; folder.mkdir(); (folder / 'source.js').write_text('original')
    entry = app.state.store.add_input('source folder', 'folder', folder)
    pin = input_fingerprint(folder, 'folder')
    (folder / 'source.js').write_text('changed after approval')
    work = tmp_path / 'work'; work.mkdir()
    config = {'workflow_recovery': {'id': 'fixture'}, 'recovery_input_pins': {entry['id']: {'kind': 'folder', 'sha256': pin}}}
    with pytest.raises(ScopeError, match='Approved input contents changed'):
        prepare_context({'folder': ['input:' + entry['id']]}, data_for(TOOLS['semgrep']), work,
                        app.state.store, config, TOOLS['semgrep'], run_id='fixture')
