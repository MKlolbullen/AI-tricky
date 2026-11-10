"""Versioned, server-owned two-GET verification profiles and offline comparisons."""
import re

from .observations import digest

SCHEMA = 'ai-tricky.verification/v1'
VERSION = '1'
TEST_ORIGIN = 'https://ai-tricky.invalid'
PROFILES = {
    'repeat_get': {'title': 'Repeat GET stability',
                   'expected_signal': 'Two complete successful responses have matching status, selected headers and captured body hashes.'},
    'cors_origin': {'title': 'CORS response policy',
                    'expected_signal': 'The variant response permits the fixed test origin or anonymous wildcard access.'},
}
COMPARE_HEADERS = ('content-type', 'server', 'content-security-policy', 'strict-transport-security',
                   'x-content-type-options', 'access-control-allow-origin', 'access-control-allow-credentials', 'vary')


def profiles():
    return [{'id': key, 'version': VERSION, **value, 'native_operations': 2} for key, value in PROFILES.items()]


def contract(profile_id, url, node_id='followup-test', finding_id=None):
    if profile_id not in PROFILES:
        raise ValueError('Unsupported verification profile.')
    result = {'schema': SCHEMA, 'profile_id': profile_id, 'version': VERSION, **PROFILES[profile_id],
              'node_id': node_id, 'finding_id': finding_id, 'native_operations': 2,
              'follow_redirects': False, 'credentials': 'omit', 'max_body_bytes': 131072,
              'requests': [{'role': 'baseline', 'method': 'GET', 'url': url, 'headers': {}},
                           {'role': 'variant', 'method': 'GET', 'url': url,
                            'headers': {'Origin': TEST_ORIGIN} if profile_id == 'cors_origin' else {}}]}
    return {**result, 'contract_hash': digest(result)}


def check_contract(binding):
    if not isinstance(binding, dict) or binding != contract(binding['profile_id'], binding['requests'][0]['url'],
                                                           binding['node_id'], binding.get('finding_id')):
        raise ValueError('Verification profile contract changed. Prepare a new execution review.')


def request_spec(config, node_id, step, url):
    binding = config.get('verification')
    if not config.get('proposal_execution') or not binding:
        raise ValueError('Controlled verification requires a recorded proposal approval.')
    check_contract(binding)
    if type(step) is not int or step not in (0, 1) or node_id != binding['node_id']:
        raise ValueError('Request is outside the approved verification profile.')
    request = binding['requests'][step]
    if request['url'] != url:
        raise ValueError('Request URL differs from the approved verification binding.')
    return request


def capture_summary(store, response, request, run_id=None, node_id=None):
    aid = response.get('artifact_id')
    data = store.content(aid) if aid else response
    error = response.get('error')
    if aid:
        metadata = store.artifact_metadata(aid)
        if (run_id is not None and metadata['run_id'] != run_id or
                node_id is not None and metadata['node_id'] != node_id or
                data.get('verification_request') != request or data.get('url') != request['url']):
            error = 'Capture provenance does not match the approved request.'
    return {'request': request, 'artifact_id': aid, 'status': data.get('status'),
            'headers': {key: data.get('headers', {}).get(key) for key in COMPARE_HEADERS if key in data.get('headers', {})},
            'body_sha256': data.get('body_sha256'), 'body_bytes': data.get('body_bytes'),
            'truncated': data.get('truncated', False), 'connected_ip': data.get('connected_ip'),
            'ambiguous_headers': data.get('ambiguous_headers', []),
            'truncated_headers': data.get('truncated_headers', []), 'error': error,
            'capture_hash': digest(data) if aid else None}


def evaluate(binding, captures, *, interruption=None):
    result = {'schema': SCHEMA, 'profile_id': binding['profile_id'], 'profile_version': binding['version'],
              'contract_hash': binding['contract_hash'], 'title': binding['title'], 'finding_id': binding.get('finding_id'),
              'expected_signal': binding['expected_signal'], 'outcome': 'inconclusive',
              'summary': 'The paired check did not establish its expected signal.', 'captures': captures,
              'differences': [], 'facts': {}, 'coverage_limits': [
                  'This is a profile-specific observation, not a verified vulnerability or a finding review decision.',
                  'Only two unauthenticated GETs to the bound URL are covered; redirects are not followed.',
                  'No cookies, authorization credentials, browser execution or preflight requests are included.']}
    reasons = []
    if interruption:
        reasons.append('Execution stopped: ' + interruption + '.')
    if len(captures) != 2:
        reasons.append('Both baseline and variant captures are required.')
    for capture in captures:
        if capture.get('error') or not capture.get('artifact_id'):
            reasons.append('A request failed or has no persisted capture.')
        if type(capture.get('status')) is not int or not 200 <= capture['status'] < 300:
            reasons.append('A response was unsuccessful, redirected or denied.')
        if capture.get('truncated'):
            reasons.append('A response body was truncated.')
        if not isinstance(capture.get('body_sha256'), str) or not re.fullmatch(r'[a-f0-9]{64}', capture['body_sha256']):
            reasons.append('A captured byte hash is unavailable.')
        if capture.get('ambiguous_headers') or capture.get('truncated_headers'):
            reasons.append('Selected response headers were duplicated or truncated.')
    if len(captures) == 2:
        baseline, variant = captures
        if [c.get('request') for c in captures] != binding['requests']:
            reasons.append('Captured request bindings do not match the approved pair.')
        if not baseline.get('connected_ip') or baseline.get('connected_ip') != variant.get('connected_ip'):
            reasons.append('Responses did not establish the same connected IP.')
        fields = {'status': (baseline.get('status'), variant.get('status')),
                  'body_sha256': (baseline.get('body_sha256'), variant.get('body_sha256')),
                  'body_bytes': (baseline.get('body_bytes'), variant.get('body_bytes'))}
        fields.update({'header:' + key: (baseline.get('headers', {}).get(key), variant.get('headers', {}).get(key)) for key in COMPARE_HEADERS})
        result['differences'] = [{'field': key, 'baseline': values[0], 'variant': values[1]}
                                 for key, values in fields.items() if values[0] != values[1]]
    if reasons:
        result['coverage_limits'] += list(dict.fromkeys(reasons))
        return result
    if binding['profile_id'] == 'repeat_get':
        stable = not result['differences']
        result.update(outcome='signal_observed' if stable else 'signal_not_observed',
                      summary='The two captured responses matched.' if stable else 'The captured responses differed; repeatability was not established.')
    else:
        headers = captures[1]['headers']
        origin, credentials = headers.get('access-control-allow-origin'), headers.get('access-control-allow-credentials')
        allowed = origin in (TEST_ORIGIN, '*')
        result.update(outcome='signal_observed' if allowed else 'signal_not_observed',
                      summary='An allow-origin response rule for the test request was observed.' if allowed else 'No allow-origin response rule matching the test request was observed.')
        result['facts'] = {'tested_origin': TEST_ORIGIN, 'allow_origin': origin, 'allow_credentials': credentials,
                           'anonymous_allow_origin_rule': allowed,
                           'credential_permission_header_pair': origin == TEST_ORIGIN and credentials == 'true'}
        result['coverage_limits'] += [
            'Header observations do not establish browser-readable sensitive data or an authenticated cross-origin exploit.',
            'Wildcard allow-origin does not permit credentialed sharing; the credential header is case-sensitive.']
    return result


async def execute_pair(rid, node_id, config, urls, fetch, store):
    binding = config['verification']
    check_contract(binding)
    if list(dict.fromkeys(urls)) != [binding['requests'][0]['url']]:
        raise ValueError('Verification source differs from its approved URL.')
    captures, interruption = [], None
    try:
        for step, request in enumerate(binding['requests']):
            response = await fetch(request['url'], node_id=node_id, verification_step=step)
            captures.append(capture_summary(store, response, request, rid, node_id))
            if response.get('error'):
                break
    except BaseException as exc:
        interruption = type(exc).__name__
        raise
    finally:
        # The transport worker persists before returning to this coroutine.
        # Cancellation can land in that gap; retain captures already committed
        # to this run/node while keeping the stopped comparison inconclusive.
        if interruption:
            for artifact in store.artifacts(rid):
                if not artifact['name'].startswith('http-') or artifact['node_id'] != node_id:
                    continue
                data = store.content(artifact['id'])
                request = data.get('verification_request') if isinstance(data, dict) else None
                if request in binding['requests'] and not any(c['request'] == request for c in captures):
                    captures.append(capture_summary(store, {'artifact_id': artifact['id']}, request, rid, node_id))
            captures.sort(key=lambda c: binding['requests'].index(c['request']))
        comparison = {**evaluate(binding, captures, interruption=interruption), 'run_id': rid,
                      'approval': config['proposal_execution']}
        aid = store.artifact(rid, 'verification-comparison.json', comparison, node_id=node_id)
        store.event(rid, 'verification.result', {'profile_id': binding['profile_id'], 'outcome': comparison['outcome'], 'artifact_id': aid})
    rows = [{'url': c['request']['url'], 'artifact_id': c['artifact_id'], 'verification_role': c['request']['role'],
             **({'status': c['status']} if c['status'] is not None else {'error': c['error'] or 'Missing capture'})} for c in captures]
    return rows + [{'verification': {**comparison, 'comparison_artifact_id': aid}, 'evidence_status': 'OBSERVATION'}]


def read_result(store, rid):
    run = store.run(rid)
    binding = run['config'].get('verification')
    if not binding:
        raise KeyError(rid)
    artifacts = store.artifacts(rid)
    saved = next((a for a in reversed(artifacts) if a['name'] == 'verification-comparison.json'), None)
    if saved:
        result = {**store.content(saved['id']), 'comparison_artifact_id': saved['id'], 'run_status': run['status'], 'evidence_current': True}
        for capture in result['captures']:
            if not capture.get('artifact_id'):
                continue
            try:
                current = digest(store.content(capture['artifact_id'])) == capture['capture_hash']
            except KeyError:
                current = False
            if not current:
                result.update(evidence_current=False, recorded_outcome=result['outcome'], outcome='inconclusive')
                result['coverage_limits'] = result['coverage_limits'] + ['A capture changed or is unavailable. Inspect the original saved comparison before relying on it.']
                break
        return result
    captures = []
    for artifact in artifacts:
        if artifact['name'].startswith('http-'):
            data = store.content(artifact['id'])
            request = data.get('verification_request')
            if request in binding['requests']:
                captures.append(capture_summary(store, {'artifact_id': artifact['id']}, request, rid, binding['node_id']))
    return {**evaluate(binding, captures, interruption='Awaiting paired completion' if run['status'] in ('queued', 'running', 'paused') else run['status']),
            'run_id': rid, 'approval': run['config']['proposal_execution'], 'run_status': run['status'], 'comparison_artifact_id': None}


def attached_evidence(store, finding_id):
    with store.connect() as c:
        ids = [r['run_id'] for r in c.execute('SELECT run_id FROM verification_runs WHERE finding_id=? ORDER BY created DESC LIMIT 50', (finding_id,))]
    eligible = []
    for rid in ids:
        result = read_result(store, rid)
        if not result.get('evidence_current'):
            continue
        for capture in result['captures']:
            aid = capture.get('artifact_id')
            if aid and not capture.get('error'):
                meta = store.artifact_metadata(aid)
                if meta['run_id'] == rid and meta['name'].startswith('http-'):
                    eligible.append({'id': aid, 'name': meta['name'] + ' · ' + result['profile_id'] + ' · ' + capture['request']['role']})
    return eligible
