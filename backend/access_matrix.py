"""Bounded access-policy checks for three bearer identities and two GET resources."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .access_verification import (IdentityIdentifier, JsonPointer, ObjectIdentifier,
                                  origin, successful_control, usable_access_capture, valid_transport)
from .scope import ScopeError, authorize

PROFILE_ID = 'access_matrix'
IDENTITIES = 3
OBJECTS = 2
OPERATIONS = IDENTITIES * OBJECTS


class MatrixRowInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    identity_id: IdentityIdentifier
    expected: list[Literal['allow', 'deny']] = Field(min_length=OBJECTS, max_length=OBJECTS)


class AccessMatrixInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    rows: list[MatrixRowInput] = Field(min_length=IDENTITIES, max_length=IDENTITIES)
    second_url: str = Field(min_length=1, max_length=2048)
    first_object: ObjectIdentifier
    second_object: ObjectIdentifier
    json_pointer: JsonPointer = '/id'


def prepare(options, target_url, scopes, identities):
    first, second = authorize(target_url, scopes), authorize(options['second_url'], scopes)
    valid_transport(first)
    if origin(first) != origin(second) or first.url == second.url:
        raise ScopeError('Choose two different resource URLs on the same authorized origin.')
    if options['first_object'] == options['second_object']:
        raise ScopeError('Choose two distinct expected resource IDs.')
    rows = options['rows']
    ids = [row['identity_id'] for row in rows]
    if len(set(ids)) != IDENTITIES:
        raise ScopeError('Choose three distinct test identities.')
    if any(rows[index]['expected'][index] != 'allow' for index in range(OBJECTS)):
        raise ScopeError('Each object owner control must expect allowed access.')
    return {'options': {**options, 'second_url': second.url}, 'identities': identities.bind(first, ids)}


def requests(url, access):
    options = access['options']
    targets = (url, options['second_url'])
    owners = [(index, index) for index in range(OBJECTS)]
    comparisons = [(row, column) for row in range(IDENTITIES) for column in range(OBJECTS)
                   if (row, column) not in owners]
    return [{
        'role': f'identity-{row + 1}-object-{column + 1}',
        'method': 'GET', 'url': targets[column], 'headers': {},
        'identity_id': options['rows'][row]['identity_id'], 'object_index': column,
        'expected': options['rows'][row]['expected'][column],
    } for row, column in owners + comparisons]


def evaluate(binding, captures, result, interruption):
    access = binding['access']
    expected_requests = binding['requests']
    by_role = {capture['request']['role']: capture for capture in captures if capture['request'] in expected_requests}
    controls = [by_role.get(request['role'], {}) for request in expected_requests[:OBJECTS]]
    # A peer credential that returns apparent denials everywhere may have
    # expired. Require a positive marker on the same peer before interpreting
    # a 403/404 as policy evidence for that identity.
    confirmed_sessions = {
        (request['identity_id'], capture['connected_ip'])
        for request in expected_requests
        if successful_control(capture := by_role.get(request['role'], {}))
        and capture['connected_ip'] == controls[request['object_index']].get('connected_ip')
        and successful_control(controls[request['object_index']])
    }
    cells = []
    for position, request in enumerate(expected_requests):
        capture = by_role.get(request['role'], {})
        control = controls[request['object_index']]
        control_succeeded = successful_control(control)
        observed = None
        same_body = None
        reason = None
        if position >= OBJECTS and not capture and not control_succeeded:
            reason = 'Owner control did not return the expected object. This check was skipped.'
        elif not capture:
            reason = 'Request was not completed.'
        elif capture.get('status') == 401:
            reason = 'The server returned HTTP 401. The session could not be verified.'
        elif not usable_access_capture(capture):
            reason = 'A complete capture is unavailable.'
        elif not control_succeeded:
            reason = 'Owner control did not return the expected object.'
        elif capture['connected_ip'] != control['connected_ip']:
            reason = 'This response came from a different peer than the owner control.'
        else:
            same_body = capture['body_fingerprint'] == control['body_fingerprint']
            if successful_control(capture):
                observed = 'allow'
            elif capture['status'] in (403, 404) and not capture['resource_marker_matched'] and not same_body:
                if (request['identity_id'], capture['connected_ip']) in confirmed_sessions:
                    observed = 'deny'
                else:
                    reason = 'A successful object read is needed to establish this identity’s session.'
            else:
                reason = 'The response did not establish allowed or denied access.'
        outcome = 'inconclusive' if observed is None else 'matched' if observed == request['expected'] else 'unexpected'
        cells.append({
            'request': request, 'owner_control': position < OBJECTS, 'observed': observed, 'outcome': outcome,
            'reason': reason, 'owner_body_matched': same_body, 'status': capture.get('status'),
            'artifact_id': capture.get('artifact_id'), 'exchange_id': capture.get('exchange_id'),
        })

    counts = {state: sum(cell['outcome'] == state for cell in cells)
              for state in ('matched', 'unexpected', 'inconclusive')}
    outcome = 'inconclusive'
    if not interruption:
        if counts['unexpected']:
            outcome = 'signal_observed'
        elif counts['matched'] == OPERATIONS:
            outcome = 'signal_not_observed'
    limits = [
        'The matrix compares the approved GETs to the operator’s expected access policy.',
        'An allow signal is a complete HTTP 200 carrying the expected object ID. Field-level exposure needs separate review.',
        'Denial requires a successful object read by that identity on the same peer and a distinct 403/404 without the marker.',
        'Saved evidence contains redacted request metadata, status, marker results and run-local fingerprints.',
    ]
    if interruption:
        limits.append('Execution stopped: ' + interruption + '.')
    result.update(outcome=outcome, identities=access['identities'], cells=cells, facts=counts, coverage_limits=limits,
                  summary=f'{counts["matched"]} matched expectations · {counts["unexpected"]} unexpected · '
                          f'{counts["inconclusive"]} inconclusive.')
    return result
