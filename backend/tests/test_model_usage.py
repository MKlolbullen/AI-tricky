import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.model_usage import ModelUsage, TOKEN_FIELDS, provider_tokens, tracked_completion
from backend.store import Store
from backend.tests.test_local import target_server, wait_done
from backend.tests.test_workflows import graph, launch


TOKENS = dict(zip(TOKEN_FIELDS, (10, 5, 15, 3, 2)))


def test_provider_counts_preserve_missing_invalid_and_zero_values():
    assert all(v is None for v in provider_tokens(None).values())
    value = provider_tokens({'prompt_tokens': 0, 'completion_tokens': -1, 'total_tokens': True,
                             'prompt_tokens_details': {'cached_tokens': '7'},
                             'completion_tokens_details': {'reasoning_tokens': 2}})
    assert value == dict(zip(TOKEN_FIELDS, (0, None, None, None, 2)))
    assert provider_tokens(SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15,
        prompt_tokens_details=SimpleNamespace(cached_tokens=3), completion_tokens_details=SimpleNamespace(reasoning_tokens=2))) == TOKENS


def test_ledger_records_idempotent_attempts_without_double_counting_and_retains_unknowns(tmp_path):
    store = Store(tmp_path); usage = ModelUsage(store)
    rid = store.new_run({'engine': 'team'})['id']; usage.start_run(rid)
    identifier = usage.begin(run_id=rid, purpose='team_member', role='surface', node_id='n2')
    start = {'sequence': 1, 'phase': 'started'}
    response = {'sequence': 1, 'phase': 'response', 'tokens': TOKENS}
    usage.record(identifier, start); usage.record(identifier, start)
    usage.record(identifier, response); usage.record(identifier, response)
    usage.record(identifier, {'sequence': 2, 'phase': 'started'})
    usage.record(identifier, {'sequence': 2, 'phase': 'response', 'tokens': {key: None for key in TOKEN_FIELDS}})
    usage.finish(identifier, 'completed')
    summary = usage.summary(run_id=rid)
    assert summary['attempts'] == summary['responses'] == 2
    assert summary['input_tokens'] == 10 and summary['total_tokens'] == 15
    assert summary['coverage'] == 'partial' and summary['missing_usage_responses'] == 1
    events = store.events(rid)
    assert len(events) == 4 and events[0]['data']['role'] == 'surface' and events[0]['data']['node_id'] == 'n2'
    history = usage.history(run_id=rid, limit=1)
    assert history['total'] == 1 and history['items'][0]['usage']['cached_input_tokens'] == 3


@pytest.mark.parametrize('event', [
    {'sequence': True, 'phase': 'started'}, {'sequence': 25, 'phase': 'started'},
    {'sequence': 0, 'phase': 'started'}, {'sequence': 1, 'phase': 'started', 'run_id': 'spoof'},
    {'sequence': 1, 'phase': 'response', 'tokens': {'input_tokens': 1}},
    {'sequence': 1, 'phase': 'response', 'tokens': {**TOKENS, 'output_tokens': -1}},
    {'sequence': 1, 'phase': 'response', 'tokens': {**TOKENS, 'output_tokens': 'provider-secret'}},
    {'sequence': 1, 'phase': 'response', 'tokens': {**TOKENS, 'total_tokens': 10**20}},
    {'sequence': 1, 'phase': 'failed', 'detail': 'provider-secret'},
])
def test_invalid_or_spoofed_meter_events_are_rejected_without_persisting_payloads(tmp_path, event):
    store = Store(tmp_path); usage = ModelUsage(store); identifier = usage.begin()
    with pytest.raises(RuntimeError): usage.record(identifier, event)
    with store.connect() as c:
        assert c.execute('SELECT COUNT(*) FROM model_calls').fetchone()[0] == 0
    assert 'provider-secret' not in json.dumps(usage.history())


def test_missing_admission_conflicting_response_and_turn_cap_are_rejected(tmp_path):
    usage = ModelUsage(Store(tmp_path)); identifier = usage.begin(max_turns=1)
    with pytest.raises(RuntimeError): usage.record(identifier, {'sequence': 1, 'phase': 'response', 'tokens': TOKENS})
    usage.record(identifier, {'sequence': 1, 'phase': 'started'})
    usage.record(identifier, {'sequence': 1, 'phase': 'response', 'tokens': TOKENS})
    with pytest.raises(RuntimeError): usage.record(identifier, {'sequence': 1, 'phase': 'response', 'tokens': {**TOKENS, 'input_tokens': 11}})
    with pytest.raises(RuntimeError): usage.record(identifier, {'sequence': 2, 'phase': 'started'})
    assert usage.summary()['attempts'] == 1


def test_restart_preserves_counts_and_marks_unfinished_calls_unknown(tmp_path):
    store = Store(tmp_path); usage = ModelUsage(store)
    identifier = usage.begin()
    usage.record(identifier, {'sequence': 1, 'phase': 'started'})
    restored = ModelUsage(store)
    summary = restored.summary()
    assert summary['attempts'] == summary['interrupted_attempts'] == 1
    assert summary['coverage'] == 'partial' and summary['total_tokens'] is None
    assert restored.history()['items'][0]['status'] == 'interrupted'


def test_concurrent_passes_are_accounted_separately(tmp_path):
    usage = ModelUsage(Store(tmp_path))
    def member(index):
        identifier = usage.begin(role=str(index), purpose='team_member')
        usage.record(identifier, {'sequence': 1, 'phase': 'started'})
        usage.record(identifier, {'sequence': 1, 'phase': 'response', 'tokens': TOKENS})
        usage.finish(identifier, 'completed')
    with ThreadPoolExecutor(max_workers=5) as pool: list(pool.map(member, range(10)))
    summary = usage.summary()
    assert summary['attempts'] == summary['responses'] == summary['invocations'] == 10
    assert summary['total_tokens'] == 150 and summary['coverage'] == 'complete'
    assert len(usage.history(limit=3, offset=3)['items']) == 3


def test_tracking_commits_before_dispatch_and_after_response_without_storing_request_text(tmp_path):
    usage = ModelUsage(Store(tmp_path)); identifier = usage.begin()
    async def callback(event): usage.record(identifier, event)
    async def create(**request):
        assert usage.summary()['pending_attempts'] == 1
        return SimpleNamespace(usage={'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15})
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    asyncio.run(tracked_completion(client, callback, 1, messages=[{'content': 'private prompt'}], api_key='private-key'))
    usage.finish(identifier, 'completed')
    assert usage.summary()['total_tokens'] == 15
    assert 'private' not in json.dumps(usage.history())


def test_failed_or_cancelled_requests_keep_admitted_attempts_with_unknown_tokens(tmp_path):
    usage = ModelUsage(Store(tmp_path))
    async def assess(*args, usage_callback, **kwargs):
        async def create(**request): raise asyncio.CancelledError()
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        return await tracked_completion(client, usage_callback, 1)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(usage.assess(assess, [], 'Private goal', None))
    summary = usage.summary()
    assert summary['attempts'] == summary['unknown_attempts'] == 1
    assert summary['total_tokens'] is None and summary['coverage'] == 'partial'
    assert usage.history()['items'][0]['status'] == 'cancelled'


def test_meter_failure_prevents_provider_request(tmp_path):
    seen = []
    async def callback(event): raise RuntimeError('Recorder unavailable')
    async def create(**request): seen.append(request)
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    with pytest.raises(RuntimeError): asyncio.run(tracked_completion(client, callback, 1))
    assert not seen


def test_legacy_assessors_and_historical_runs_are_unavailable_instead_of_measured_zero(tmp_path):
    store = Store(tmp_path); usage = ModelUsage(store)
    rid = store.new_run({'engine': 'cai'})['id']
    assert usage.summary(run_id=rid)['coverage'] == 'unavailable'
    async def legacy(*args): return {'report': 'Unmetered injected analyst'}
    usage.start_run(rid)
    asyncio.run(usage.assess(legacy, [], 'g', None, run_id=rid))
    assert usage.summary(run_id=rid)['coverage'] == 'partial'
    assert usage.summary(run_id=rid)['unmetered_invocations'] == 1


def test_run_team_and_workflow_usage_are_durable_and_bound_to_server_context(tmp_path, target_server):
    base, _ = target_server
    async def analyst(targets, goal, fetch, *, usage_callback, **kwargs):
        await usage_callback({'sequence': 1, 'phase': 'started'})
        await usage_callback({'sequence': 1, 'phase': 'response', 'tokens': TOKENS})
        return {'report': json.dumps({'summary': 'Fixture evidence review', 'candidates': [], 'coverage_limits': []})}
    with TestClient(create_app(tmp_path, assessor=analyst)) as client:
        tid = client.post('/api/targets', json={'value': base}).json()['id']
        r = client.post('/api/runs', json={'engine': 'team', 'target_ids': [tid], 'allow_http': True, 'synthesize': True})
        run = wait_done(client, r.json()['id'])
        assert run['result']['model_usage']['attempts'] == 6
        ledger = client.get('/api/runs/' + run['id'] + '/model-usage').json()
        assert {p['role'] for p in ledger['items']} == {'surface', 'transport', 'authz', 'injection', 'logic', 'lead'}
        assert ledger['summary']['total_tokens'] == 90
        r = launch(client, base, graph('native_scope', 'native_http', 'native_team'))
        workflow = wait_done(client, r.json()['id'])
        ledger = client.get('/api/runs/' + workflow['id'] + '/model-usage').json()
        assert ledger['summary']['attempts'] == 5 and all(p['node_id'] == 'n2' for p in ledger['items'])
        assert workflow['result']['model_usage']['total_tokens'] == 75
    with TestClient(create_app(tmp_path)) as client:
        assert client.get('/api/runs/' + run['id'] + '/model-usage').json()['summary']['total_tokens'] == 90
        assert client.get('/api/model-usage?limit=2&offset=1').json()['total'] == 11


def test_model_planning_has_separate_usage_and_rules_do_not_create_model_calls(tmp_path):
    async def analyst(*args, usage_callback, **kwargs):
        await usage_callback({'sequence': 1, 'phase': 'started'})
        await usage_callback({'sequence': 1, 'phase': 'response', 'tokens': TOKENS})
        return {'report': '{"adapters":["native_scope","native_http","native_summary"]}'}
    with TestClient(create_app(tmp_path, assessor=analyst)) as client:
        assert client.post('/api/agent/plan', json={'goal': 'Review HTTP', 'use_model': False}).status_code == 200
        assert client.get('/api/model-usage').json()['summary']['attempts'] == 0
        result = client.post('/api/agent/plan', json={'goal': 'Review HTTP', 'use_model': True})
        assert result.status_code == 200 and result.json()['model_usage_id']
        ledger = client.get('/api/model-usage').json()
        assert ledger['summary']['attempts'] == 1 and ledger['items'][0]['run_id'] is None
        assert ledger['items'][0]['purpose'] == 'workflow_plan'


def test_recovery_does_not_recount_reused_model_passes(tmp_path, target_server):
    from backend.tests.test_recovery import prepare, dispatch
    base, handler = target_server
    async def analyst(*args, usage_callback, **kwargs):
        await usage_callback({'sequence': 1, 'phase': 'started'})
        await usage_callback({'sequence': 1, 'phase': 'response', 'tokens': TOKENS})
        return {'report': json.dumps({'summary': 'Fixture review', 'candidates': [], 'coverage_limits': []})}
    with TestClient(create_app(tmp_path, assessor=analyst)) as client:
        source = wait_done(client, launch(client, base, graph('native_scope', 'native_http', 'native_cai', 'native_summary')).json()['id'])
        assert source['result']['model_usage']['total_tokens'] == 15
        review = prepare(client, source, ['n3'])
        recovered = wait_done(client, dispatch(client, review).json()['run']['id'])
        assert recovered['result']['reused_nodes'] == 3
        usage = client.get('/api/runs/' + recovered['id'] + '/model-usage').json()['summary']
        assert usage['attempts'] == 0 and usage['invocations'] == 0
        assert client.get('/api/model-usage').json()['summary']['total_tokens'] == 15
        assert len(handler.calls) == 1
