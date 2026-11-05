"""Deterministic multi-agent leader.

A server-owned, model-free leader that fans a single scoped run out to several
role-specialized CAI analysts. Every member shares the caller's `fetch` / `probe`
callbacks, so they draw on one run's budget ledger, scope enforcement and
credential snapshot — the leader adds no new target access of its own. Each
member is assessed independently (N aggregated runs) and the leader collects
their reports with per-role provenance; it never merges them into one
undifferentiated result and never confirms a finding.
"""
from __future__ import annotations

import asyncio

# Curated specialist roles. `network` decides whether the member receives the
# bounded TCP probe in addition to scoped HTTP. `focus` is appended after the
# adapter's fixed safety preamble — it narrows attention only, never scope or
# permissions.
ROLES: dict[str, dict] = {
    'surface': {
        'name': 'Surface & recon',
        'network': True,
        'focus': 'Map the exposed surface: reachable services, ports, endpoints and technologies. '
                 'Record what responds and how; do not probe beyond the entered scope.',
    },
    'transport': {
        'name': 'Transport & headers',
        'network': False,
        'focus': 'Examine transport posture and HTTP response headers: TLS behaviour, security headers '
                 'and cookie flags. Report missing or weak controls as candidates, never as confirmed findings.',
    },
    'authz': {
        'name': 'Auth & session',
        'network': False,
        'focus': 'Observe authentication and session handling and any access-control signals, read-only. '
                 'Do not attempt credentials, brute force or privilege changes.',
    },
    'injection': {
        'name': 'Input & injection surface',
        'network': False,
        'focus': 'Identify parameters and reflection points that form a candidate injection surface. '
                 'Describe where and why; do not send exploit payloads or destructive input.',
    },
    'logic': {
        'name': 'Business logic & misconfig',
        'network': False,
        'focus': 'Look for exposed configuration, verbose errors, debug surfaces and business-logic flaws. '
                 'Report observations and candidates with the evidence that supports them.',
    },
}

DEFAULT_ROLES: list[str] = ['surface', 'transport', 'authz', 'injection', 'logic']
MAX_ROLES = len(ROLES)


def resolve_roles(roles):
    """Return the ordered, de-duplicated, validated role keys (empty -> all)."""
    if not roles:
        return list(DEFAULT_ROLES)
    seen, out = set(), []
    for key in roles:
        if key not in ROLES:
            raise ValueError(f'Unknown team role: {key}')
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


async def run_team(targets, goal, fetch, probe, assess, *, roles=None, model=None,
                   member_max_turns=8, timeout=180, concurrency=3):
    """Dispatch one scoped run across the selected roles and aggregate reports.

    `assess` is the adapter's assess callable; `fetch`/`probe` are the run's own
    budget-enforcing tool callbacks, shared by every member. Member failures are
    captured as coverage gaps so a partial team still returns a result; a
    cancellation of the underlying run propagates and cancels the team.
    """
    selected = resolve_roles(roles)
    semaphore = asyncio.Semaphore(max(1, min(int(concurrency), MAX_ROLES)))

    async def member(key):
        spec = ROLES[key]
        async with semaphore:
            role_goal = f'{goal}\n\nYour assigned focus on this cooperating team: {spec["name"]}.'
            try:
                result = await assess(targets, role_goal, fetch,
                                      network_tool=probe if spec['network'] else None,
                                      role_instructions=spec['focus'], model=model,
                                      max_turns=member_max_turns, timeout=timeout)
                return {'role': key, 'name': spec['name'], 'status': 'ok',
                        'report': str(result.get('report', '')),
                        'model': result.get('model'), 'engine': result.get('engine')}
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - surface as a coverage gap, no secrets
                reason = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
                return {'role': key, 'name': spec['name'], 'status': 'failed', 'reason': reason[:300]}

    members = await asyncio.gather(*(member(key) for key in selected))
    completed = [m for m in members if m['status'] == 'ok']
    coverage_limits = [f'{m["name"]} role did not complete: {m["reason"]}'
                       for m in members if m['status'] != 'ok']
    summary = (f'Deterministic team leader dispatched {len(selected)} analyst role(s); '
               f'{len(completed)} completed, {len(members) - len(completed)} did not. '
               'Each report is a per-role candidate assessment, not a confirmed finding.')
    return {
        'report': summary,
        'engine': 'cai-team',
        'evidence_status': 'CANDIDATE',
        'team': True,
        'leader': 'deterministic',
        'roles_requested': selected,
        'members': members,
        'coverage_limits': coverage_limits,
    }
