import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.cai_adapter import build_instructions, LIVE_INSTRUCTIONS, EVIDENCE_ONLY_INSTRUCTIONS
from backend.team import run_team, resolve_roles, ROLES, DEFAULT_ROLES
from backend.tests.test_local import target_server, wait_done
from backend.tests.test_workflows import graph, launch


# -- role-instruction composition ---------------------------------------------
def test_build_instructions_appends_role_focus_but_keeps_preamble():
    base = build_instructions()
    assert base == LIVE_INSTRUCTIONS
    withrole = build_instructions(role_instructions='Look only at TLS headers.')
    # The full safety preamble is preserved verbatim; the focus is additive.
    assert withrole.startswith(LIVE_INSTRUCTIONS)
    assert 'ROLE FOCUS' in withrole and 'Look only at TLS headers.' in withrole
    assert 'read-only' in withrole
    # Evidence-only keeps its own preamble, still additive.
    ev = build_instructions(evidence_only=True, role_instructions='x')
    assert ev.startswith(EVIDENCE_ONLY_INSTRUCTIONS) and 'ROLE FOCUS' in ev
    # A hostile role string cannot overflow the prompt or erase the preamble.
    assert build_instructions(role_instructions='A' * 5000).startswith(LIVE_INSTRUCTIONS)
    assert len(build_instructions(role_instructions='A' * 5000)) < len(LIVE_INSTRUCTIONS) + 700


# -- leader role resolution ---------------------------------------------------
def test_resolve_roles_defaults_dedupes_and_validates():
    assert resolve_roles([]) == DEFAULT_ROLES
    assert resolve_roles(['transport', 'transport', 'surface']) == ['transport', 'surface']
    with pytest.raises(ValueError):
        resolve_roles(['surface', 'nope'])


# -- leader fan-out over a shared fetch ---------------------------------------
def test_run_team_shares_tools_and_aggregates():
    fetch_calls, seen = [], []

    async def fetch(url):
        fetch_calls.append(url)
        return {'status': 200}

    async def probe(target, ports):
        return {'results': []}

    async def assess(targets, goal, f, *, network_tool=None, role_instructions=None, model=None, max_turns=8, timeout=180):
        seen.append({'role_focus': role_instructions, 'network': network_tool is not None, 'max_turns': max_turns})
        await f('http://scope.local/')  # every member draws on the one shared fetch
        return {'report': 'role report', 'model': 'm', 'engine': 'e', 'evidence_status': 'CANDIDATE'}

    result = asyncio.run(run_team(['http://scope.local/'], 'Assess', fetch, probe, assess,
                                  roles=['surface', 'transport'], member_max_turns=6))
    assert result['team'] is True and result['leader'] == 'deterministic'
    assert result['roles_requested'] == ['surface', 'transport']
    assert [m['role'] for m in result['members']] == ['surface', 'transport']
    assert all(m['status'] == 'ok' for m in result['members'])
    assert len(fetch_calls) == 2                     # shared ledger: one call per member
    assert all(s['max_turns'] == 6 for s in seen)    # per-member turn cap threaded
    # Only the surface role is granted the network probe.
    net_by_focus = {ROLES['surface']['focus']: None, ROLES['transport']['focus']: None}
    for s in seen:
        net_by_focus[s['role_focus']] = s['network']
    assert net_by_focus[ROLES['surface']['focus']] is True
    assert net_by_focus[ROLES['transport']['focus']] is False


def test_run_team_partial_failure_is_a_coverage_gap_not_a_crash():
    async def fetch(url):
        return {'status': 200}

    async def probe(target, ports):
        return {'results': []}

    async def assess(targets, goal, f, *, network_tool=None, role_instructions=None, model=None, max_turns=8, timeout=180):
        if role_instructions == ROLES['injection']['focus']:
            raise RuntimeError('provider unavailable')
        return {'report': 'ok', 'evidence_status': 'CANDIDATE'}

    result = asyncio.run(run_team(['http://x/'], 'Assess', fetch, probe, assess, roles=['surface', 'injection']))
    by_role = {m['role']: m for m in result['members']}
    assert by_role['surface']['status'] == 'ok'
    assert by_role['injection']['status'] == 'failed' and 'provider unavailable' in by_role['injection']['reason']
    assert any('Input & injection surface' in c for c in result['coverage_limits'])


# -- API: engine='team' end to end -------------------------------------------
def _assessor(base):
    async def model(targets, goal, fetch, *, network_tool=None, role_instructions=None, model=None, max_turns=8, timeout=180):
        await fetch(base + '/')  # consume the shared run budget
        return {'report': 'member candidate report', 'model': 'fixture', 'engine': 'cai/x', 'evidence_status': 'CANDIDATE'}
    return model


def test_team_run_shares_budget_and_reports_members(tmp_path, target_server):
    base, _ = target_server
    with TestClient(create_app(tmp_path, assessor=_assessor(base))) as c:
        tid = c.post('/api/targets', json={'value': base}).json()['id']
        r = c.post('/api/runs', json={'engine': 'team', 'target_ids': [tid], 'allow_http': True,
                                      'roles': ['surface', 'transport', 'authz'], 'max_requests': 50})
        assert r.status_code == 201, r.text
        rid = r.json()['id']
        done = wait_done(c, rid)
        assert done['status'] == 'completed', done
        result = done['result']
        assert result['team'] is True and result['leader'] == 'deterministic'
        assert [m['role'] for m in result['members']] == ['surface', 'transport', 'authz']
        assert all(m['status'] == 'ok' for m in result['members'])
        # One shared ledger across the three members.
        assert result['request_count'] == 3


def test_team_run_rejects_unknown_role(tmp_path, target_server):
    base, _ = target_server
    with TestClient(create_app(tmp_path, assessor=_assessor(base))) as c:
        tid = c.post('/api/targets', json={'value': base}).json()['id']
        assert c.post('/api/runs', json={'engine': 'team', 'target_ids': [tid], 'roles': ['nope']}).status_code == 422


def _analysis_assessor():
    import json
    async def model(targets, goal, fetch, *, role_instructions=None, **kw):
        # Evidence-only role review returns a valid, empty-candidate analysis so
        # validate_analysis accepts it without needing specific artifact ids.
        return {'report': json.dumps({'summary': f'Role review ({"team-role" if role_instructions else "base"}).',
                                      'candidates': [], 'coverage_limits': ['Evidence-only; no live verification.']})}
    return model


def test_native_team_node_reviews_evidence_across_all_roles(tmp_path, target_server):
    # The native_team workflow node runs the five roles over captured evidence
    # with no target tools, aggregating per-role results in one node output.
    base, _ = target_server
    g = graph('native_scope', 'native_tcp', 'native_http', 'native_team', 'native_summary')
    with TestClient(create_app(tmp_path, assessor=_analysis_assessor())) as c:
        r = launch(c, base, g)
        assert r.status_code == 201, r.text
        rid = r.json()['id']
        assert wait_done(c, rid)['status'] == 'completed'
        arts = {a['name']: a['id'] for a in c.get('/api/runs/' + rid + '/artifacts').json()}
        team = c.get('/api/artifacts/' + arts['node-n3.json']).json()
        assert team[0]['team'] is True
        assert [m['role'] for m in team[0]['members']] == ['surface', 'transport', 'authz', 'injection', 'logic']
        assert all(m['status'] == 'ok' and m['analysis']['confirmed'] is False for m in team[0]['members'])


def test_native_team_node_requires_the_model_sdk_on_the_real_path(tmp_path, target_server):
    base, _ = target_server
    g = graph('native_scope', 'native_http', 'native_team')
    with TestClient(create_app(tmp_path)) as c:
        r = launch(c, base, g)
        assert r.status_code == 409 and 'CAI SDK' in r.json()['detail']


def test_team_engine_requires_the_model_sdk_on_the_real_path(tmp_path, target_server):
    # With no injected assessor and the optional CAI SDK absent in CI, a team run
    # is refused up front — confirming team is wired into the model-required gate.
    base, _ = target_server
    with TestClient(create_app(tmp_path)) as c:
        tid = c.post('/api/targets', json={'value': base}).json()['id']
        r = c.post('/api/runs', json={'engine': 'team', 'target_ids': [tid], 'allow_http': True})
        assert r.status_code == 409 and 'CAI SDK' in r.json()['detail']


# -- optional lead synthesizer ------------------------------------------------
def test_run_team_synthesizes_role_reports_when_enabled():
    async def fetch(url):
        return {'status': 200}

    async def probe(target, ports):
        return {'results': []}

    async def assess(targets, goal, f, *, network_tool=None, role_instructions=None, model=None, max_turns=8, timeout=180):
        await f('http://scope.local/')
        return {'report': 'role report', 'evidence_status': 'CANDIDATE'}

    seen = {}
    async def synthesize(prompt):
        seen['prompt'] = prompt
        return {'report': 'Unified lead synthesis across roles.', 'model': 'synth'}

    result = asyncio.run(run_team(['http://scope.local/'], 'Assess', fetch, probe, assess,
                                  roles=['surface', 'transport'], synthesize=synthesize))
    syn = result['synthesis']
    assert syn and syn['label'] == 'CAI MODEL SYNTHESIS · CANDIDATES' and syn['model_called'] is True
    assert syn['confirmed'] is False and syn['report'] == 'Unified lead synthesis across roles.'
    # The synthesizer sees the role reports and nothing else (no target access).
    assert 'role_reports' in seen['prompt'] and 'role report' in seen['prompt']


def test_run_team_synthesis_failure_is_a_coverage_gap():
    async def fetch(url):
        return {'status': 200}

    async def probe(target, ports):
        return {'results': []}

    async def assess(targets, goal, f, **kw):
        return {'report': 'ok', 'evidence_status': 'CANDIDATE'}

    async def synthesize(prompt):
        raise RuntimeError('synth provider down')

    result = asyncio.run(run_team(['http://x/'], 'g', fetch, probe, assess, roles=['surface'], synthesize=synthesize))
    assert result['synthesis'] is None
    assert any('Lead synthesis did not complete' in c for c in result['coverage_limits'])


def test_run_team_synthesis_skipped_when_no_member_completed():
    async def fetch(url):
        return {'status': 200}

    async def probe(target, ports):
        return {'results': []}

    async def assess(targets, goal, f, **kw):
        raise RuntimeError('all roles down')

    called = {'n': 0}
    async def synthesize(prompt):
        called['n'] += 1
        return {'report': 'should not run'}

    result = asyncio.run(run_team(['http://x/'], 'g', fetch, probe, assess, roles=['surface'], synthesize=synthesize))
    assert result['synthesis'] is None and called['n'] == 0
    assert any('Lead synthesis skipped' in c for c in result['coverage_limits'])


def test_team_run_includes_labelled_synthesis_when_requested(tmp_path, target_server):
    base, _ = target_server
    async def model(targets, goal, fetch, *, network_tool=None, role_instructions=None, model=None, max_turns=8, timeout=180, evidence_only=False):
        if not targets:  # the synthesizer pass: no scope, disabled fetch
            return {'report': 'Unified lead synthesis across roles.', 'model': 'synth'}
        await fetch(base + '/')
        return {'report': 'member candidate report', 'model': 'fixture', 'engine': 'cai/x', 'evidence_status': 'CANDIDATE'}
    with TestClient(create_app(tmp_path, assessor=model)) as c:
        tid = c.post('/api/targets', json={'value': base}).json()['id']
        r = c.post('/api/runs', json={'engine': 'team', 'target_ids': [tid], 'allow_http': True,
                                      'roles': ['surface', 'transport'], 'synthesize': True, 'max_requests': 50})
        assert r.status_code == 201, r.text
        done = wait_done(c, r.json()['id'])
        assert done['status'] == 'completed', done
        syn = done['result']['synthesis']
        assert syn and syn['confirmed'] is False and 'synthesis' in syn['report'].lower()
        # The deterministic members are still present and distinct from the synthesis.
        assert all(m['status'] == 'ok' for m in done['result']['members'])
