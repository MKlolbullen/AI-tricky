import asyncio

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.cai_adapter import build_instructions, LIVE_INSTRUCTIONS, EVIDENCE_ONLY_INSTRUCTIONS
from backend.team import run_team, resolve_roles, ROLES, DEFAULT_ROLES
from backend.tests.test_local import target_server, wait_done


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


def test_team_engine_requires_the_model_sdk_on_the_real_path(tmp_path, target_server):
    # With no injected assessor and the optional CAI SDK absent in CI, a team run
    # is refused up front — confirming team is wired into the model-required gate.
    base, _ = target_server
    with TestClient(create_app(tmp_path)) as c:
        tid = c.post('/api/targets', json={'value': base}).json()['id']
        r = c.post('/api/runs', json={'engine': 'team', 'target_ids': [tid], 'allow_http': True})
        assert r.status_code == 409 and 'CAI SDK' in r.json()['detail']
