import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.team import allocate_turns, run_team, DEFAULT_ROLES
from backend.tests.test_local import target_server, wait_done
from backend.tests.test_workflows import graph, launch


@pytest.mark.parametrize('synthesis', [False, True])
def test_allocations_bound_every_pass_and_are_fair(synthesis):
    for cap in (1, 8, 24):
        for total in range(1, 145):
            budget = allocate_turns(DEFAULT_ROLES, total, cap, synthesis=synthesis)
            limits = list(budget['member_limits'].values())
            assert sum(limits) + budget['synthesis_limit'] == budget['reserved'] <= total
            assert budget['unallocated'] == total - budget['reserved']
            assert all(0 <= value <= cap for value in limits)
            assert max(limits) - min(limits) <= 1
            assert 0 <= budget['synthesis_limit'] <= 8
    assert allocate_turns(DEFAULT_ROLES, 48, 8, synthesis=True)['reserved'] == 48


@pytest.mark.parametrize('invalid', [0, -1, 145, 1.5, True, '8', None])
def test_invalid_turn_limits_are_not_coerced(invalid):
    with pytest.raises(ValueError):
        allocate_turns(DEFAULT_ROLES, invalid, 8)
    with pytest.raises(ValueError):
        allocate_turns(DEFAULT_ROLES, 48, invalid)


def test_team_reserves_synthesis_and_does_not_reassign_failed_member_budget():
    seen = []

    async def assess(targets, goal, fetch, **kwargs):
        seen.append(kwargs['max_turns'])
        # Failure/early completion must not refund a reservation without actual
        # usage accounting: other passes may already be running concurrently.
        if len(seen) == 1:
            raise RuntimeError('member unavailable')
        return {'report': 'Candidate review'}

    async def synthesize(prompt, *, max_turns):
        seen.append(max_turns)
        return {'report': 'Candidate synthesis'}

    result = asyncio.run(run_team([], 'Review', None, None, assess,
                                  team_max_turns=9, synthesize=synthesize, max_workers=5))
    assert sorted(seen) == [1, 1, 1, 2, 2, 2]
    assert sum(seen) == result['model_turn_budget']['reserved'] == 9
    assert result['members'][0]['status'] == 'failed'
    assert result['synthesis']['max_turns'] == 1
    assert result['synthesis']['confirmed'] is False


def test_tiny_team_budget_reports_skipped_members_and_synthesis_without_calls():
    seen = []

    async def assess(*args, **kwargs):
        seen.append(kwargs['max_turns'])
        return {'report': 'Candidate review'}

    async def synthesize(*args, **kwargs):
        pytest.fail('Synthesis has no reserved turns')

    result = asyncio.run(run_team([], 'Review', None, None, assess,
                                  team_max_turns=2, synthesize=synthesize))
    assert seen == [1, 1]
    assert [m['status'] for m in result['members']] == ['ok', 'ok', 'skipped', 'skipped', 'skipped']
    assert len(result['coverage_limits']) == 4
    assert result['synthesis'] is None
    assert result['model_turn_budget']['reserved'] == 2


def test_adaptive_selection_and_explicit_roles_allocate_only_selected_passes():
    async def assess(*args, **kwargs):
        return {'report': 'Candidate review'}

    result = asyncio.run(run_team([], 'Review', None, None, assess, adaptive=True,
                                  evidence=[{'url': 'http://x/', 'status': 200}], team_max_turns=3))
    assert result['model_turn_budget']['member_limits'] == {'surface': 2, 'transport': 1}
    explicit = asyncio.run(run_team([], 'Review', None, None, assess, adaptive=True,
                                    roles=['logic', 'logic'], team_max_turns=3))
    assert explicit['model_turn_budget']['member_limits'] == {'logic': 3}


def test_team_run_api_persists_budget_and_audit_event(tmp_path, target_server):
    base, _ = target_server
    seen = []

    async def assess(targets, goal, fetch, **kwargs):
        seen.append(kwargs['max_turns'])
        return {'report': 'Candidate review'}

    with TestClient(create_app(tmp_path, assessor=assess)) as c:
        tid = c.post('/api/targets', json={'value': base}).json()['id']
        body = {'engine': 'team', 'target_ids': [tid], 'allow_http': True,
                'team_max_turns': 7, 'member_max_turns': 8, 'synthesize': True}
        r = c.post('/api/runs', json=body)
        assert r.status_code == 201, r.text
        run = wait_done(c, r.json()['id'])
        assert run['status'] == 'completed'
        assert sum(seen) == run['result']['model_turn_budget']['reserved'] == 7
        assert run['config']['team_max_turns'] == 7
        events = c.get('/api/runs/' + run['id'] + '/events').json()
        assert next(e['data'] for e in events if e['kind'] == 'team.turn_budget')['limit'] == 7
        for invalid in (0, 145, True, 1.5):
            assert c.post('/api/runs', json={**body, 'team_max_turns': invalid}).status_code == 422


def test_native_team_budget_is_validated_and_threaded_to_analyst(tmp_path, target_server):
    base, _ = target_server
    seen = []

    async def assess(targets, goal, fetch, **kwargs):
        seen.append(kwargs['max_turns'])
        assert not targets and 'no target access' in (await fetch('http://outside.invalid/'))['error']
        return {'report': json.dumps({'summary': 'Captured review', 'candidates': [], 'coverage_limits': []})}

    g = graph('native_scope', 'native_http', 'native_team')
    data = g['nodes'][-1]['data']
    data.update(team_max_turns=3, member_max_turns=12)
    with TestClient(create_app(tmp_path, assessor=assess)) as c:
        r = launch(c, base, g)
        assert r.status_code == 201, r.text
        run = wait_done(c, r.json()['id'])
        artifacts = {a['name']: a['id'] for a in c.get('/api/runs/' + run['id'] + '/artifacts').json()}
        team = c.get('/api/artifacts/' + artifacts['node-n2.json']).json()[0]
        assert team['model_turn_budget']['reserved'] == sum(seen) == 3
        assert sum(m['status'] == 'skipped' for m in team['members']) == 2
        assert len(team['coverage_limits']) == 2
        for key, value in [('team_max_turns', 0), ('team_max_turns', '8'), ('team_max_turns', 1.5),
                           ('member_max_turns', True), ('member_max_turns', 25), ('max_workers', 0)]:
            valid = dict(data)
            data[key] = value
            assert launch(c, base, g).status_code == 422
            data.clear(); data.update(valid)


def test_native_team_sdk_turn_exhaustion_keeps_other_member_evidence(tmp_path, target_server):
    base, _ = target_server
    calls = []

    class SDKTurnLimit(Exception):
        pass

    async def assess(*args, **kwargs):
        calls.append(kwargs['max_turns'])
        if len(calls) == 1:
            raise SDKTurnLimit('untrusted provider detail must not be persisted')
        return {'report': json.dumps({'summary': 'Captured review', 'candidates': [], 'coverage_limits': []})}

    g = graph('native_scope', 'native_http', 'native_team')
    g['nodes'][-1]['data']['team_max_turns'] = 5
    with TestClient(create_app(tmp_path, assessor=assess)) as c:
        run = wait_done(c, launch(c, base, g).json()['id'])
        assert run['result']['failed_nodes'] == 0
        artifacts = {a['name']: a['id'] for a in c.get('/api/runs/' + run['id'] + '/artifacts').json()}
        team = c.get('/api/artifacts/' + artifacts['node-n2.json']).json()[0]
        assert len([m for m in team['members'] if m['status'] == 'ok']) == 4
        assert team['members'][0]['reason'] == 'SDKTurnLimit'
        assert 'untrusted provider detail' not in json.dumps(team)
        assert calls == [1] * 5
