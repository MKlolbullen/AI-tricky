import copy
import json

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.proposals import ProposalPlanner, ProposalError, StalePlan, action_graph, MAX_ACTIONS
from backend.scope import ScopeError
from backend.store import Store
from backend.tests.test_evidence import run, capture, nuclei
from backend.tests.test_local import target_server, wait_done
from backend.tests.test_workflows import graph, launch
from backend.workflows import validate_workflow


def setup(tmp_path, scope='example.com'):
    store = Store(tmp_path)
    rid = run(store, targets=[scope], max_hosts=8)
    aid = capture(store, rid, url='https://example.com/api')
    planner = ProposalPlanner(store)
    oid = planner.evidence.observations(run_id=rid)['items'][0]['id']
    context = planner.context(rid, [oid], 'Capture HTTP evidence')
    return store, planner, rid, oid, aid, context


def report(context, adapter='native_http'):
    action = next(a for a in context['actions'] if a['adapter_id'] == adapter)
    return {'summary': 'Collect additional evidence at the captured location.', 'coverage_limits': [], 'proposals': [
        {'action_id': action['id'], 'observation_ids': action['observation_ids'][:1],
         'hypothesis': 'The current response may clarify the earlier observation.',
         'rationale': 'The supplied capture identifies the exact URL to inspect.',
         'expected_signal': 'A captured response with status and headers.',
         'negative_signal': 'A failed or empty check leaves the hypothesis inconclusive.'}]}


def model_payload(prompt):
    return json.loads(prompt.split('UNTRUSTED EVIDENCE AND AVAILABLE ACTIONS:\n', 1)[1])


def test_url_scope_only_offers_native_http_and_preserves_exact_path(tmp_path):
    _, planner, _, _, _, context = setup(tmp_path, 'https://example.com/api')
    assert {a['adapter_id'] for a in context['actions']} == {'native_http'}
    result = planner.save('Capture HTTP evidence', context)
    assert result['planner'] == 'evidence-rules' and result['model_called'] is False
    assert result['proposals'][0]['action']['target'] == 'https://example.com/api'
    assert result['proposals'][0]['dispatch_allowed'] is False
    assert result['proposals'][0]['graph']['nodes'][0]['data']['value'] == 'https://example.com/api'
    validate_workflow(result['proposals'][0]['graph'], live=True)


def test_persisted_model_proposal_has_evidence_costs_and_stable_ids(tmp_path):
    _, planner, rid, oid, aid, context = setup(tmp_path)
    result = planner.save('Capture HTTP evidence', context, json.dumps(report(context)), {'model': 'fixture'})
    proposal = result['proposals'][0]
    assert proposal['observation_ids'] == [oid] and proposal['artifact_ids'] == [aid]
    assert proposal['action']['cost'] == {'native_operations': 1, 'cli_invocations': 0, 'cli_internal_requests': None}
    assert result['model_called'] and result['planner'] == 'cai-model'
    restored = ProposalPlanner(Store(tmp_path)).plan(result['id'])
    assert restored == result and restored['current']
    assert planner.plans(rid)[0]['id'] == result['id']


@pytest.mark.parametrize('change', [
    lambda r: r['proposals'][0].update(action_id='arbitrary-shell'),
    lambda r: r['proposals'][0].update(observation_ids=['outside-evidence']),
    lambda r: r['proposals'][0].update(observation_ids=[]),
    lambda r: r['proposals'][0].update(command='anything'),
    lambda r: r['proposals'][0].update(target='https://outside.invalid/'),
    lambda r: r['proposals'][0].update(rationale=' '),
    lambda r: r['proposals'].append(copy.deepcopy(r['proposals'][0])),
    lambda r: r.update(summary=' '),
])
def test_model_contract_rejects_fabricated_actions_evidence_and_execution_fields(tmp_path, change):
    _, planner, rid, _, _, context = setup(tmp_path)
    raw = report(context); change(raw)
    with pytest.raises(ProposalError):
        planner.save('Collect evidence', context, json.dumps(raw))
    assert planner.plans(rid) == []


def test_selected_evidence_must_be_current_and_same_run(tmp_path):
    store, planner, rid, oid, _, _ = setup(tmp_path)
    other = run(store)
    capture(store, other)
    outside = planner.evidence.observations(run_id=other)['items'][0]['id']
    for ids in ([outside], [oid, oid], [], ['missing']):
        with pytest.raises(ScopeError):
            planner.context(rid, ids, 'Review')


def test_known_action_cannot_cite_another_selected_location(tmp_path):
    store, planner, rid, oid, _, _ = setup(tmp_path)
    capture(store, rid, url='https://example.com/other')
    rows = planner.evidence.observations(run_id=rid)['items']
    context = planner.context(rid, [r['id'] for r in rows], 'Review')
    raw = report(context)
    action = next(a for a in context['actions'] if a['id'] == raw['proposals'][0]['action_id'])
    other_id = next(r['id'] for r in rows if r['id'] not in action['observation_ids'])
    raw['proposals'][0]['observation_ids'] = [other_id]
    with pytest.raises(ProposalError):
        planner.save('Review', context, json.dumps(raw))


def test_risk_cap_excludes_medium_checks_and_templates_are_explicit_prerequisites(tmp_path):
    _, planner, rid, oid, _, context = setup(tmp_path)
    assert not any(a['adapter_id'] in ('nuclei', 'testssl', 'nmap') for a in context['actions'])
    medium = planner.context(rid, [oid], 'Review nuclei detections', max_risk='medium')
    result = planner.save('Reviewed template checks', medium, json.dumps(report(medium, 'nuclei')))
    proposal = result['proposals'][0]
    assert proposal['action']['risk'] == 'medium'
    assert any('templates' in reason for reason in proposal['requirements'])
    assert proposal['action']['cost']['cli_internal_requests'] is None
    validate_workflow(proposal['graph'], live=True)


def test_observed_service_binding_limits_nmap_to_recorded_port(tmp_path):
    store = Store(tmp_path); rid = run(store, targets=['127.0.0.1'], max_hosts=1)
    store.artifact(rid, 'tcp-inventory.json', [{'host': '127.0.0.1', 'port': 8443, 'state': 'open'}])
    planner = ProposalPlanner(store)
    oid = planner.evidence.observations(run_id=rid)['items'][0]['id']
    context = planner.context(rid, [oid], 'nmap service identification', 'medium')
    action = next(a for a in context['actions'] if a['adapter_id'] == 'nmap')
    assert action['target'] == '127.0.0.1' and action['params'] == {'-p': '8443', '-sV': True}
    assert next(n for n in action_graph(action)['nodes'] if n['data']['kind'] == 'catalog_tool')['data']['params']['-p'] == '8443'


def test_unapproved_discovery_and_special_use_targets_do_not_create_active_actions(tmp_path):
    store = Store(tmp_path); rid = run(store, targets=['example.com'], max_hosts=8)
    capture(store, rid, url='https://new.example.com/api')
    planner = ProposalPlanner(store)
    oid = planner.evidence.observations(run_id=rid)['items'][0]['id']
    context = planner.context(rid, [oid], 'Inventory')
    assert context['actions'] == []
    assert planner.save('Inventory', context)['proposals'] == []


def test_prompt_excludes_raw_bodies_extracted_secrets_and_runtime_credentials(tmp_path, monkeypatch):
    store, planner, rid, _, _, _ = setup(tmp_path)
    capture(store, rid, body='RAW_BODY_SECRET_NOT_FOR_PLANNER')
    nuclei(store, rid, extracted=['EXTRACTED_SECRET_NOT_FOR_PLANNER'])
    monkeypatch.setenv('CAI_MODEL_API_KEY', 'RUNTIME_SECRET_NOT_FOR_PLANNER')
    ids = [r['id'] for r in planner.evidence.observations(run_id=rid)['items']]
    prompt = planner.prompt('Collect evidence', planner.context(rid, ids, 'Collect evidence'))
    assert all(s not in prompt for s in ['RAW_BODY_SECRET_NOT_FOR_PLANNER', 'EXTRACTED_SECRET_NOT_FOR_PLANNER', 'RUNTIME_SECRET_NOT_FOR_PLANNER'])
    assert 'UNTRUSTED EVIDENCE' in prompt and 'You have no target tools' in prompt


@pytest.mark.parametrize('mutation', ['artifact', 'observation', 'catalog', 'parser'])
def test_stale_bindings_are_reported_without_erasing_recorded_plan(tmp_path, monkeypatch, mutation):
    import backend.proposals as module
    store, planner, _, oid, aid, context = setup(tmp_path)
    saved = planner.save('Review', context)
    if mutation == 'artifact':
        with store.connect() as c:
            c.execute('UPDATE artifacts SET content=? WHERE id=?', ('{}', aid))
    elif mutation == 'observation':
        with store.connect() as c:
            c.execute('UPDATE observations SET value_hash=? WHERE id=?', ('changed', oid))
    elif mutation == 'catalog':
        monkeypatch.setitem(module.REGISTRY['native_http'], 'description', 'Changed contract')
    else:
        monkeypatch.setattr(module, 'PARSER_VERSION', 'next-version')
    restored = planner.plan(saved['id'])
    assert not restored['current'] and restored['stale_reason']
    assert restored['proposals'] == saved['proposals']
    with pytest.raises(StalePlan):
        planner.save('Review', context)


def test_action_search_is_bounded_and_discloses_truncation(tmp_path):
    store = Store(tmp_path); rid = run(store, targets=['example.com'], max_hosts=64)
    for i in range(24):
        capture(store, rid, url=f'https://example.com/{i}')
    planner = ProposalPlanner(store)
    ids = [r['id'] for r in planner.evidence.observations(run_id=rid)['items']]
    context = planner.context(rid, ids, 'Review metadata')
    assert len(context['actions']) == MAX_ACTIONS
    assert any('omitted' in limit for limit in context['coverage_limits'])
    assert len(planner.prompt('Review metadata', context).encode()) <= 150_000


def test_api_model_planning_is_evidence_only_and_persists_validated_output(tmp_path):
    _, _, rid, oid, _, _ = setup(tmp_path)
    calls = []
    async def model(targets, goal, fetch):
        calls.append(targets)
        assert 'error' in await fetch('https://outside.invalid/')
        payload = model_payload(goal)
        action = next(a for a in payload['available_actions'] if a['adapter_id'] == 'native_http')
        return {'report': json.dumps({'summary': 'Model-proposed follow-up', 'coverage_limits': [], 'proposals': [
            {'action_id': action['id'], 'observation_ids': [oid], 'hypothesis': 'A current response may differ.',
             'rationale': 'The cited capture supplies the URL.', 'expected_signal': 'Response headers',
             'negative_signal': 'Failure is inconclusive'}]}), 'model': 'local-fixture'}
    with TestClient(create_app(tmp_path, assessor=model)) as client:
        response = client.post('/api/agent/proposals', json={'run_id': rid, 'observation_ids': [oid], 'goal': 'Review', 'use_model': True})
        assert response.status_code == 201, response.text
        plan = response.json()
        assert plan['planner'] == 'cai-model' and plan['model_called'] and calls == [[]]
        assert client.get('/api/agent/proposals?run_id=' + rid).json()[0]['id'] == plan['id']
        assert client.get('/api/agent/proposals/' + plan['id']).json()['current']


def test_api_rejects_invalid_inputs_and_model_output_without_saving(tmp_path):
    _, _, rid, oid, _, _ = setup(tmp_path)
    async def invalid(*_):
        return {'report': '{"summary":"bad","proposals":[{"command":"anything"}],"coverage_limits":[]}'}
    with TestClient(create_app(tmp_path, assessor=invalid)) as client:
        body = {'run_id': rid, 'observation_ids': [oid], 'goal': 'Review'}
        assert client.post('/api/agent/proposals', json={**body, 'command': 'anything'}).status_code == 422
        assert client.post('/api/agent/proposals', json={**body, 'max_risk': 'critical'}).status_code == 422
        assert client.post('/api/agent/proposals', json={**body, 'observation_ids': [oid]*25}).status_code == 422
        assert client.post('/api/agent/proposals', json={**body, 'use_model': True}).status_code == 502
        assert client.get('/api/agent/proposals?run_id=' + rid).json() == []
        assert client.get('/api/agent/proposals/missing').status_code == 404
        assert client.get('/api/agent/proposals?run_id=missing').status_code == 404


def test_evidence_model_planning_provider_gating(tmp_path, monkeypatch):
    # Evidence follow-ups route model inference through the same provider gate as
    # Agent desk: a remote provider resolves only with a stored key AND remote
    # model use enabled, and the refusal fires before any SDK/model work.
    _, _, rid, oid, _, _ = setup(tmp_path)
    body = {'run_id': rid, 'observation_ids': [oid], 'goal': 'Review', 'use_model': True}
    monkeypatch.delenv('CAI_ALLOW_REMOTE_MODEL', raising=False)
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    with TestClient(create_app(tmp_path)) as client:
        # Remote provider with no stored key is refused.
        assert client.post('/api/agent/proposals', json={**body, 'provider': 'openai'}).status_code == 409
        client.post('/api/credentials', json={'updates': {'OPENAI_API_KEY': 'sk-test'}})
        # Key present but remote model use disabled is still refused.
        r = client.post('/api/agent/proposals', json={**body, 'provider': 'openai'})
        assert r.status_code == 409 and 'remote model use' in r.json()['detail']
        # Unknown provider is rejected.
        assert client.post('/api/agent/proposals', json={**body, 'provider': 'nope'}).status_code == 422
        # Deterministic planning never needs a provider and still saves.
        assert client.post('/api/agent/proposals', json={**body, 'use_model': False}).status_code == 201
    monkeypatch.setenv('CAI_ALLOW_REMOTE_MODEL', '1')
    with TestClient(create_app(tmp_path)) as client:
        # Remote enabled + key present but no model name is rejected before any call.
        assert client.post('/api/agent/proposals', json={**body, 'provider': 'openai'}).status_code == 422


def test_saved_workflow_loading_sends_no_target_traffic_and_blocks_stale_plans(tmp_path, target_server):
    base, handler = target_server
    with TestClient(create_app(tmp_path)) as client:
        rid = launch(client, base, graph('native_scope', 'native_http')).json()['id']
        assert wait_done(client, rid)['status'] == 'completed'
        oid = client.get('/api/observations?run_id=' + rid).json()['items'][0]['id']
        plan = client.post('/api/agent/proposals', json={'run_id': rid, 'observation_ids': [oid], 'goal': 'Review capture'}).json()
        proposal = plan['proposals'][0]
        url = f'/api/agent/proposals/{plan["id"]}/{proposal["id"]}/workflow'
        response = client.get(url)
        assert response.status_code == 200 and not response.json()['dispatch_allowed']
        assert response.json()['graph']['nodes'][0]['data']['value'] == base + '/'
        validate_workflow(response.json()['graph'], live=True)
        assert len(handler.calls) == 1
        assert client.get(f'/api/agent/proposals/{plan["id"]}/missing/workflow').status_code == 404
        aid = proposal['artifact_ids'][0]
        with client.app.state.store.connect() as c:
            c.execute('UPDATE artifacts SET content=? WHERE id=?', ('{}', aid))
        assert client.get(url).status_code == 409
        assert len(handler.calls) == 1
