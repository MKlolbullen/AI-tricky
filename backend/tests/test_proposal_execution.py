import asyncio
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
import httpx
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.http_journal import message, request_message
from backend.proposal_execution import ExecutionOptions, ProposalExecutions
from backend.proposals import ProposalPlanner
from backend.store import Store
from backend.tests.test_evidence import run, capture
from backend.tests.test_local import target_server, wait_done
from backend.tests.test_proposals import report


def plan_for(app, client, scope='https://example.com/api', url=None, adapter='native_http'):
    client.post('/api/targets', json={'value': scope}).raise_for_status()
    store = app.state.store
    rid = run(store, targets=[scope], max_hosts=8)
    aid = capture(store, rid, url=url or scope)
    planner = ProposalPlanner(store)
    oid = planner.evidence.observations(run_id=rid)['items'][0]['id']
    context = planner.context(rid, [oid], 'Collect follow-up evidence', 'medium')
    plan = planner.save('Collect follow-up evidence', context, json.dumps(report(context, adapter)))
    return plan, plan['proposals'][0], aid


def prepare(client, plan, proposal, **options):
    return client.post(f'/api/agent/proposals/{plan["id"]}/{proposal["id"]}/executions', json=options)


def dispatch(client, review, **body):
    return client.post(f'/api/agent/executions/{review["id"]}/dispatch',
                       json={'expected_hash': review['snapshot_hash'], 'approve': True, **body})


def test_review_is_durable_and_only_explicit_approval_dispatches_exact_snapshot(tmp_path, target_server):
    base, handler = target_server
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = plan_for(app, client, scope=base + '/review')
        response = prepare(client, plan, proposal, max_requests=1, max_hosts=1, max_seconds=30)
        assert response.status_code == 201, response.text
        review = response.json()
        assert review['status'] == 'pending' and not handler.calls
        config = review['snapshot']['config']
        assert config['targets'] == [base + '/review']
        assert config['workflow']['nodes'][0]['data']['value'] == base + '/review'
        assert config['parallelism'] == 1 and config['max_requests'] == 1 and config['max_seconds'] == 30
        assert client.get('/api/runs').json()[0]['id'] == plan['run_id']
        assert dispatch(client, review, approve=False).status_code == 422
        assert dispatch(client, review, expected_hash='0' * 64).status_code == 409
        assert dispatch(client, review, max_requests=200).status_code == 422
        assert not handler.calls
        response = dispatch(client, review)
        assert response.status_code == 200, response.text
        receipt = response.json(); result = wait_done(client, receipt['run']['id'])
        assert receipt['created'] and result['status'] == 'completed'
        assert result['result']['request_count'] == 1 and result['result']['cli_invocation_count'] == 0
        assert handler.calls == ['/review']
        provenance = result['config']['proposal_execution']
        assert provenance['source_run_id'] == plan['run_id'] and provenance['proposal_id'] == proposal['id']
        assert provenance['snapshot_hash'] == review['snapshot_hash']
        events = client.get('/api/runs/' + result['id'] + '/events').json()
        assert any(e['kind'] == 'proposal.approved' and e['data']['snapshot_hash'] == review['snapshot_hash'] for e in events)
        artifacts = client.get('/api/runs/' + result['id'] + '/artifacts').json()
        assert any(a['name'].startswith('http-') for a in artifacts)
        retry = dispatch(client, review).json()
        assert retry['created'] is False and retry['run']['id'] == result['id']
        assert handler.calls == ['/review']
        stored = client.get('/api/agent/executions/' + review['id']).json()
        assert [e['kind'] for e in stored['events']] == ['prepared', 'approved', 'dispatched']
        assert client.get(f'/api/agent/proposals/{plan["id"]}/executions').json()[0]['run_id'] == result['id']
    with TestClient(create_app(tmp_path)) as client:
        assert client.get('/api/agent/executions/' + review['id']).json()['status'] == 'dispatched'
        assert dispatch(client, review).json()['run']['id'] == result['id']
        assert handler.calls == ['/review']


@pytest.mark.parametrize('options', [
    {'targets': ['https://other.invalid/']}, {'workflow': {}}, {'cli_credential_keys': ['OPENAI_API_KEY']},
    {'input_refs': {'file': 'anything'}}, {'allow_cli': True}, {'max_requests': 0}, {'max_requests': True},
    {'max_requests': '4'}, {'max_seconds': 3601}, {'allow_cli': 'true'},
])
def test_preview_rejects_scope_graph_environment_and_option_injection(tmp_path, options):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = plan_for(app, client)
        assert prepare(client, plan, proposal, **options).status_code == 422
        assert client.get(f'/api/agent/proposals/{plan["id"]}/executions').json() == []


@pytest.mark.parametrize('change', ['scope', 'artifact', 'parser', 'catalog'])
def test_stale_bindings_invalidate_pending_review_without_a_run(tmp_path, monkeypatch, change):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, aid = plan_for(app, client)
        review = prepare(client, plan, proposal).json()
        store = app.state.store
        if change == 'scope':
            with store.connect() as c:
                c.execute("UPDATE targets SET url='https://other.invalid/'")
        elif change == 'artifact':
            with store.connect() as c:
                c.execute('UPDATE artifacts SET content=? WHERE id=?', (json.dumps({'changed': True}), aid))
        elif change == 'parser':
            monkeypatch.setattr('backend.proposals.PARSER_VERSION', 'next-parser')
        else:
            monkeypatch.setattr('backend.proposals.catalog_hash', lambda: 'next-contract')
        response = dispatch(client, review)
        assert response.status_code == 409, response.text
        assert client.get('/api/agent/executions/' + review['id']).json()['status'] == 'invalidated'
        assert len(client.get('/api/runs').json()) == 1


def test_expiry_revocation_and_restart_require_new_review(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = plan_for(app, client)
        expired = prepare(client, plan, proposal).json()
        revoked = prepare(client, plan, proposal).json()
        pending = prepare(client, plan, proposal).json()
        with app.state.store.connect() as c:
            c.execute('UPDATE proposal_executions SET expires=? WHERE id=?',
                      ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), expired['id']))
        assert dispatch(client, expired).status_code == 409
        assert client.get('/api/agent/executions/' + expired['id']).json()['status'] == 'expired'
        response = client.post(f'/api/agent/executions/{revoked["id"]}/revoke', json={'expected_hash': revoked['snapshot_hash']})
        assert response.json()['status'] == 'revoked'
        assert dispatch(client, revoked).status_code == 409
    with TestClient(create_app(tmp_path)) as client:
        restored = client.get('/api/agent/executions/' + pending['id']).json()
        assert restored['status'] == 'invalidated' and 'restarted' in restored['reason']
        assert dispatch(client, pending).status_code == 409


def test_concurrent_approval_retries_share_one_run(tmp_path, target_server):
    base, handler = target_server
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = plan_for(app, client, scope=base + '/once')
        review = prepare(client, plan, proposal).json()
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(lambda _: dispatch(client, review), range(4)))
        assert all(r.status_code == 200 for r in responses)
        receipts = [r.json() for r in responses]
        assert sum(r['created'] for r in receipts) == 1
        assert len({r['run']['id'] for r in receipts}) == 1
        assert wait_done(client, receipts[0]['run']['id'])['status'] == 'completed'
        assert handler.calls == ['/once']


def cli_plan(tmp_path, monkeypatch, client, app):
    executable = tmp_path / 'nuclei'
    executable.write_text(f'#!{sys.executable}\nprint("fixture detection output")\n')
    executable.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ.get('PATH', ''))
    folder = tmp_path / 'templates'; folder.mkdir()
    (folder / 'reviewed.yaml').write_text('id: fixture-review\n')
    registered = client.post('/api/inputs', json={'name': 'Reviewed fixtures', 'path': str(folder)}).json()
    plan, proposal, _ = plan_for(app, client, scope='127.0.0.1', url='http://127.0.0.1:8000/api', adapter='nuclei')
    return plan, proposal, folder, executable, registered['id']


@pytest.mark.parametrize('changed', ['folder', 'binary'])
def test_cli_pins_reject_changed_binary_or_template_contents(tmp_path, monkeypatch, changed):
    app = create_app(tmp_path / 'data')
    with TestClient(app) as client:
        plan, proposal, folder, executable, iid = cli_plan(tmp_path, monkeypatch, client, app)
        assert prepare(client, plan, proposal).status_code == 422
        response = prepare(client, plan, proposal, allow_cli=True, input_refs={'templates': iid})
        assert response.status_code == 201, response.text
        review = response.json()
        config = review['snapshot']['config']
        assert config['cli_binaries']['nuclei']['sha256']
        assert config['proposal_input_pins'][iid]['sha256'] and config['cli_credential_keys'] == []
        path = folder / 'reviewed.yaml' if changed == 'folder' else executable
        path.write_text(path.read_text() + '# changed after review\n')
        assert dispatch(client, review).status_code == 409
        assert len(client.get('/api/runs').json()) == 1


def test_copied_cli_inputs_are_rechecked_before_any_process_launch(tmp_path, monkeypatch):
    from backend import cli_runner
    app = create_app(tmp_path / 'data')
    with TestClient(app) as client:
        plan, proposal, folder, _, iid = cli_plan(tmp_path, monkeypatch, client, app)
        review = prepare(client, plan, proposal, allow_cli=True, input_refs={'templates': iid}).json()
        original = cli_runner.prepare_context
        def change_before_copy(*args, **kwargs):
            (folder / 'reviewed.yaml').write_text('id: changed-after-dispatch\n')
            return original(*args, **kwargs)
        monkeypatch.setattr(cli_runner, 'prepare_context', change_before_copy)
        receipt = dispatch(client, review).json()
        result = wait_done(client, receipt['run']['id'])
        assert result['status'] == 'failed' and result['result']['cli_invocation_count'] == 0
        assert not any(e['kind'] == 'cli.admitted' for e in client.get('/api/runs/' + result['id'] + '/events').json())


def test_atomic_consume_rolls_back_if_run_creation_fails(tmp_path, monkeypatch):
    store = Store(tmp_path)
    store.add_target('https://example.com/api')
    rid = run(store, targets=['https://example.com/api'])
    capture(store, rid, url='https://example.com/api')
    planner = ProposalPlanner(store)
    oid = planner.evidence.observations(run_id=rid)['items'][0]['id']
    plan = planner.save('Capture evidence', planner.context(rid, [oid], 'Capture evidence'))
    executor = ProposalExecutions(store, planner)
    review = executor.prepare(plan['id'], plan['proposals'][0]['id'], ExecutionOptions().model_dump())
    original = store.new_run
    def fail_after_insert(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError('fixture transaction failure')
    monkeypatch.setattr(store, 'new_run', fail_after_insert)
    with pytest.raises(RuntimeError, match='fixture transaction failure'):
        executor.dispatch(review['id'], review['snapshot_hash'])
    assert len(store.runs()) == 1 and executor.get(review['id'])['status'] == 'pending'
    assert [e['kind'] for e in executor.get(review['id'])['events']] == ['prepared']


def test_cli_approval_executes_one_pinned_fixture_and_records_provenance(tmp_path, monkeypatch):
    app = create_app(tmp_path / 'data')
    with TestClient(app) as client:
        plan, proposal, _, _, iid = cli_plan(tmp_path, monkeypatch, client, app)
        review = prepare(client, plan, proposal, allow_cli=True, input_refs={'templates': iid}).json()
        result = wait_done(client, dispatch(client, review).json()['run']['id'])
        assert result['status'] == 'completed'
        assert result['result']['cli_invocation_count'] == 1 and result['result']['request_count'] == 0
        assert result['config']['proposal_execution']['proposal_id'] == proposal['id']
        assert len(client.get('/api/runs/' + result['id'] + '/nodes').json()) == 3


@pytest.mark.parametrize('action', ['resume', 'cancel'])
def test_proposal_runs_use_existing_pause_resume_cancel_controls(tmp_path, monkeypatch, action):
    started, release = threading.Event(), threading.Event()
    def delayed_fetch(url, scope, **kwargs):
        started.set(); release.wait(3)
        return {'url': url, 'status': 200, 'headers': {}, 'body': 'loopback execution fixture', 'connected_ip': '127.0.0.1', 'http_exchange':{'request':request_message(url),'response':message('HTTP/1.1 200 OK',[],b'loopback execution fixture',status=200,reason='OK',http_version='HTTP/1.1'),'route':{'mode':'direct'}}}
    monkeypatch.setattr('backend.app.fetch_scoped', delayed_fetch)
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = plan_for(app, client, scope='http://127.0.0.1/review')
        review = prepare(client, plan, proposal).json()
        rid = dispatch(client, review).json()['run']['id']
        assert started.wait(2)
        assert client.post(f'/api/runs/{rid}/pause', json={}).json()['status'] == 'paused'
        release.set()
        response = client.post(f'/api/runs/{rid}/{action}', json={})
        assert response.status_code == 200
        result = wait_done(client, rid)
        assert result['status'] == ('completed' if action == 'resume' else 'cancelled')
        assert result['result']['request_count'] == 1


def test_capacity_denial_does_not_consume_review(tmp_path, monkeypatch):
    started, release = threading.Event(), threading.Event()
    def delayed_fetch(url, scope, **kwargs):
        started.set(); release.wait(4)
        return {'url': url, 'status': 200, 'headers': {}, 'body': 'fixture', 'connected_ip': '127.0.0.1', 'http_exchange':{'request':request_message(url),'response':message('HTTP/1.1 200 OK',[],b'fixture',status=200,reason='OK',http_version='HTTP/1.1'),'route':{'mode':'direct'}}}
    monkeypatch.setattr('backend.app.fetch_scoped', delayed_fetch)
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = plan_for(app, client, scope='http://127.0.0.1/capacity')
        reviews = [prepare(client, plan, proposal).json() for _ in range(3)]
        first = dispatch(client, reviews[0]).json()['run']['id']
        assert started.wait(2)
        second = dispatch(client, reviews[1]).json()['run']['id']
        assert dispatch(client, reviews[2]).status_code == 409
        assert client.get('/api/agent/executions/' + reviews[2]['id']).json()['status'] == 'pending'
        # A lost response can still be retried while both slots are occupied.
        assert dispatch(client, reviews[0]).json()['run']['id'] == first
        release.set()
        wait_done(client, first); wait_done(client, second)
        assert dispatch(client, reviews[2]).status_code == 200


def test_manual_runs_cannot_forge_proposal_approval_provenance(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        plan, proposal, _ = plan_for(app, client)
        response = client.post('/api/runs', json={'engine': 'workflow', 'workflow': proposal['graph'],
                                               'proposal_execution': {'id': 'forged', 'snapshot_hash': '0' * 64}})
        assert response.status_code == 201
        assert 'proposal_execution' not in response.json()['config']


def test_client_disconnect_during_consumption_still_schedules_exactly_one_run(tmp_path, monkeypatch, target_server):
    async def exercise():
        base, handler = target_server
        app = create_app(tmp_path)
        store = app.state.store
        store.add_target(base + '/disconnect')
        rid = run(store, targets=[base + '/disconnect'])
        capture(store, rid, url=base + '/disconnect')
        planner = ProposalPlanner(store)
        oid = planner.evidence.observations(run_id=rid)['items'][0]['id']
        plan = planner.save('Capture evidence', planner.context(rid, [oid], 'Capture evidence'))
        started, release = threading.Event(), threading.Event()
        original = ProposalExecutions.dispatch
        def delayed_consume(self, *args):
            started.set(); release.wait(3)
            return original(self, *args)
        monkeypatch.setattr(ProposalExecutions, 'dispatch', delayed_consume)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
                review = (await client.post(f'/api/agent/proposals/{plan["id"]}/{plan["proposals"][0]["id"]}/executions', json={})).json()
                url = f'/api/agent/executions/{review["id"]}/dispatch'
                body = {'expected_hash': review['snapshot_hash'], 'approve': True}
                request = asyncio.create_task(client.post(url, json=body))
                assert await asyncio.to_thread(started.wait, 2)
                request.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await request
                release.set()
                for _ in range(150):
                    runs = store.runs()
                    if len(runs) == 2 and runs[0]['status'] == 'completed':break
                    await asyncio.sleep(.02)
                else:raise AssertionError('Approved execution was not scheduled after disconnect')
                retry = (await client.post(url, json=body)).json()
                assert retry['created'] is False and retry['run']['id'] == runs[0]['id']
                assert handler.calls == ['/disconnect']
    asyncio.run(exercise())
