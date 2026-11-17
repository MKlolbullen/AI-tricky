"""Saved recon baselines, coverage receipts, and evidence-bound delta follow-ups."""

import json
import uuid

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .observations import canonical_asset, digest, encoded, PARSER_VERSION
from .scope import ScopeError, authorize, parse_target
from .store import now

MAX_RECORDS = 10000
TERMINAL = {'completed', 'failed', 'cancelled', 'interrupted'}
PRESENTATION = {'title', 'description', 'status', 'result', 'proposalId'}


def workflow_contract(config):
    graph = config.get('workflow') or {}
    return {
        'engine': config.get('engine'),
        'nodes': sorted([{'id': node['id'], 'data': {k: v for k, v in node['data'].items() if k not in PRESENTATION}}
                         for node in graph.get('nodes', [])], key=lambda n: n['id']),
        'edges': sorted([[edge.get(k) for k in ('source', 'sourceHandle', 'target', 'targetHandle')]
                         for edge in graph.get('edges', [])], key=encoded),
        'ports': sorted(config.get('ports', [])), 'cli_scope': config.get('cli_scope', 'standard'),
    }


def baseline_key(config):
    return digest({'scope': sorted(parse_target(t).url for t in config.get('targets', [])),
                   'workflow': workflow_contract(config)})


class BaselineInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    run_id: str = Field(min_length=1, max_length=64)
    expected_revision: int = Field(default=0, ge=0)


class DeltaPlanInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    baseline_id: str = Field(min_length=1, max_length=64)
    expected_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    fingerprints: list[Annotated[str, StringConstraints(pattern=r'^[a-f0-9]{64}$')]] = Field(min_length=1, max_length=8)


def coverage(store, run):
    config = run['config']
    nodes = {node['node_id']: node for node in store.nodes(run['id'])}
    artifacts = store.artifacts(run['id'])
    details, warnings = [], []
    if run['status'] != 'completed':
        warnings.append(f'Run is {run["status"]}.')
    if not config.get('allow_http'):
        warnings.append('Target execution was disabled.')
    for node in (config.get('workflow') or {}).get('nodes', []):
        actual = nodes.get(node['id'], {})
        result = actual.get('result') or {}
        state = actual.get('status', 'not_recorded')
        entry = {'node_id': node['id'], 'adapter': node['data'].get('toolId', node['data']['kind']),
                 'status': state, 'records': result.get('records'), 'errors': result.get('errors', 0),
                 'input_receipt_id': result.get('input_receipt_id'),
                 'input_receipt': store.content(result['input_receipt_id']) if result.get('input_receipt_id') else None, 'limits': {}}
        if state not in ('completed', 'reused'):
            warnings.append(f'{node["id"]} is {state}.')
        if entry['errors']:
            warnings.append(f'{node["id"]} recorded errors or blocked operations.')
        aid = result.get('artifact_id')
        if aid:
            content = store.content(aid)
            for row in content if isinstance(content, list) else []:
                if not isinstance(row, dict):
                    continue
                for key, value in (row.get('counts') or {}).items():
                    if value and (key.endswith('_limited') or key in ('errors', 'truncated', 'not_attempted')):
                        entry['limits'][key] = value
            if entry['limits']:
                warnings.append(f'{node["id"]} reached capture or execution limits.')
        details.append(entry)
    for artifact in artifacts:
        if artifact['name'].startswith('cli-'):
            content = store.content(artifact['id'])
            if isinstance(content, dict) and (content.get('error') or content.get('exit_code') != 0 or
                                             (content.get('cli_scope') or {}).get('denied')):
                warnings.append(f'{artifact["name"]} recorded scanner errors or gateway denials.')
    with store.connect() as c:
        parser_reports = [json.loads(row['report']) for row in c.execute('''SELECT i.report FROM evidence_index i
                          JOIN artifacts a ON a.id=i.artifact_id WHERE a.run_id=? AND i.parser_version=?''',
                          (run['id'], PARSER_VERSION))]
    if any(report.get('partial') or report.get('unparsed_lines') for report in parser_reports):
        warnings.append('Some captures are partial or contain unparsed records.')
    result = run.get('result') or {}
    for used, limit in (('request_count', 'max_requests'), ('cli_invocation_count', 'max_cli_invocations')):
        if config.get(limit) and result.get(used, 0) >= config[limit]:
            warnings.append(f'{limit} was reached. Inspect coverage before interpreting absence.')
    return {'nodes': details, 'warnings': sorted(set(warnings)),
            'budgets': {key: config.get(key) for key in ('max_hosts', 'max_requests', 'max_cli_invocations', 'max_seconds')},
            'input_snapshots': config.get('input_snapshots', {}),
            'binary_pins': config.get('cli_binaries', {}),
            'http_routing': config.get('http_routing_binding', config.get('http_routing')),
            'parser_coverage': {'partial': sum(bool(r.get('partial')) for r in parser_reports),
                                'unparsed_lines': sum(r.get('unparsed_lines', 0) for r in parser_reports)},
            'legacy_inputs': any(n['status'] in ('completed', 'reused') and not n['input_receipt_id'] for n in details)}


class DeltaRecon:
    def __init__(self, store, evidence, *, initialize=True):
        self.store, self.evidence = store, evidence
        if not initialize:
            return
        with store.connect() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS recon_baselines(
                id TEXT PRIMARY KEY,profile_key TEXT NOT NULL,revision INTEGER NOT NULL,
                run_id TEXT NOT NULL,created TEXT NOT NULL,snapshot_hash TEXT NOT NULL,snapshot TEXT NOT NULL,
                UNIQUE(profile_key,revision))''')

    def snapshot(self, rid, *, index=True):
        run = self.store.run(rid)
        if run['status'] not in TERMINAL:
            raise ScopeError('Finish or stop the run before comparing or saving a recon baseline.')
        if run['config'].get('engine') != 'workflow' or not run['config'].get('targets'):
            raise ScopeError('Delta recon requires a workflow run with entered targets.')
        if index:
            self.evidence.index_pending(rid)
        with self.store.connect() as c:
            rows = c.execute('''SELECT o.* FROM observations o JOIN observation_versions v ON v.observation_id=o.id
                                WHERE o.run_id=? AND v.parser_version=? ORDER BY o.id LIMIT ?''',
                             (rid, PARSER_VERSION, MAX_RECORDS + 1)).fetchall()
        if len(rows) > MAX_RECORDS:
            raise ScopeError('Delta recon is limited to 10,000 observations per run.')
        inventory = {}
        by_artifact = {}
        for row in rows:
            entry = inventory.setdefault(row['fingerprint'], {'fingerprint': row['fingerprint'], 'kind': row['kind'],
                                        'source': row['source'], 'asset': row['asset'], 'values': {}})
            value = entry['values'].setdefault(row['value_hash'], {'data': json.loads(row['data']),
                                              'evidence_ids': [], 'observation_ids': []})
            value['evidence_ids'].append(row['artifact_id'])
            value['observation_ids'].append(row['id'])
            by_artifact.setdefault(row['artifact_id'], []).append(row['id'])
        # Source files are already captured by the source collector. Their
        # bounded byte hash gives source changes their own searchable row.
        kinds = {node['id']: node['data']['kind'] for node in (run['config'].get('workflow') or {}).get('nodes', [])}
        for node in self.store.nodes(rid):
            aid = (node.get('result') or {}).get('artifact_id')
            if not aid or node['status'] not in ('completed', 'reused') or kinds.get(node['node_id']) not in ('native_web_assets', 'native_api_surface'):
                continue
            content = self.store.content(aid)
            for report in content if isinstance(content, list) else []:
                for source in report.get('manifest', []) if isinstance(report, dict) and kinds[node['node_id']] == 'native_web_assets' else []:
                    capture_id = source.get('artifact_id')
                    if not capture_id or source.get('kind') == 'page':
                        continue
                    meta = self.store.artifact_metadata(capture_id)
                    capture = self.store.content(capture_id)
                    asset = canonical_asset(source.get('url'))
                    if meta['run_id'] != rid or not asset or asset != canonical_asset(capture.get('url')):
                        continue
                    fingerprint = digest(['web-source', 'file', asset])
                    data = {key: capture.get(key) for key in ('status', 'body_sha256', 'truncated')}
                    data['file_type'] = source.get('kind')
                    entry = inventory.setdefault(fingerprint, {'fingerprint': fingerprint, 'kind': 'file',
                                                             'source': 'web-source', 'asset': asset, 'values': {}})
                    entry['values'][digest(data)] = {'data': data, 'evidence_ids': [capture_id, aid],
                                                    'observation_ids': by_artifact.get(capture_id, [])}
                for endpoint in report.get('endpoints', []) if isinstance(report, dict) and kinds[node['node_id']] == 'native_api_surface' else []:
                    asset = canonical_asset(endpoint.get('url'))
                    method = endpoint.get('method')
                    if not asset or not isinstance(method, str):
                        continue
                    source_ids = sorted({source['artifact_id'] for source in endpoint.get('sources', [])
                                         if source.get('artifact_id') in by_artifact})
                    fingerprint = digest(['api-surface', method, asset])
                    data = {'method': method, 'parameters': endpoint.get('parameters', []), 'inferred': True}
                    inventory[fingerprint] = {'fingerprint': fingerprint, 'kind': 'endpoint', 'source': 'api-surface',
                        'asset': asset, 'values': {digest(data): {'data': data, 'evidence_ids': [aid, *source_ids],
                            'observation_ids': sorted({oid for source in source_ids for oid in by_artifact[source]})}}}
        if len(inventory) > MAX_RECORDS:
            raise ScopeError('Delta recon is limited to 10,000 comparable records.')
        artifacts = self.store.artifacts(rid)
        if len(artifacts) > 2000:
            raise ScopeError('Delta recon supports up to 2,000 artifacts per run.')
        hashes = {artifact['id']: digest(self.store.content(artifact['id'])) for artifact in artifacts}
        return {'run_id': rid, 'profile_key': baseline_key(run['config']), 'parser_version': PARSER_VERSION,
                'scope': run['config']['targets'], 'inventory': inventory, 'coverage': coverage(self.store, run),
                'artifact_hashes': hashes}

    def save(self, rid, expected_revision):
        snapshot = self.snapshot(rid)
        run = self.store.run(rid)
        if run['status'] != 'completed' or not run['config'].get('allow_http'):
            raise ScopeError('Choose a completed execution run for the baseline.')
        if not snapshot['inventory']:
            raise ScopeError('The baseline needs captured, supported observations.')
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            revision = c.execute('SELECT COALESCE(MAX(revision),0) FROM recon_baselines WHERE profile_key=?',
                                 (snapshot['profile_key'],)).fetchone()[0]
            if revision != expected_revision:
                from .evidence import ReviewConflict
                raise ReviewConflict('The baseline changed. Reload it before saving a replacement.')
            identifier = str(uuid.uuid4())
            c.execute('INSERT INTO recon_baselines VALUES(?,?,?,?,?,?,?)',
                      (identifier, snapshot['profile_key'], revision + 1, rid, now(), digest(snapshot), encoded(snapshot)))
        return self.get(identifier)

    def get(self, identifier):
        with self.store.connect() as c:
            row = c.execute('SELECT * FROM recon_baselines WHERE id=?', (identifier,)).fetchone()
        if row is None:
            raise KeyError(identifier)
        return {**dict(row), 'snapshot': json.loads(row['snapshot'])}

    def baselines(self, rid):
        run = self.store.run(rid)
        key = baseline_key(run['config'])
        with self.store.connect() as c:
            return [dict(row) for row in c.execute('''SELECT id,revision,run_id,created,snapshot_hash FROM recon_baselines
                                                     WHERE profile_key=? ORDER BY revision DESC LIMIT 50''', (key,))]

    def compare(self, rid, baseline_id, *, index=True):
        baseline = self.get(baseline_id)
        before = baseline['snapshot']
        current = self.snapshot(rid, index=index)
        if rid == before['run_id']:
            raise ScopeError('Select a run different from the saved baseline.')
        if before['profile_key'] != current['profile_key']:
            raise ScopeError('This baseline belongs to a different entered scope or workflow.')
        evidence_current = digest(before) == baseline['snapshot_hash']
        for aid, expected in before['artifact_hashes'].items():
            try:
                evidence_current = evidence_current and digest(self.store.content(aid)) == expected
            except KeyError:
                evidence_current = False
        evidence_current = evidence_current and before['parser_version'] == PARSER_VERSION
        entries = []
        for key in sorted(before['inventory'].keys() | current['inventory'].keys()):
            old, new = before['inventory'].get(key), current['inventory'].get(key)
            state = ('new' if old is None else 'not_observed' if new is None else
                     'unchanged' if old['values'].keys() == new['values'].keys() else 'changed')
            entry = {k: (new or old)[k] for k in ('fingerprint', 'asset', 'source', 'kind')}
            ids = sorted({oid for value in new['values'].values() for oid in value['observation_ids']}) if new else []
            target = None
            get_only = all(value['data'].get('method', 'GET') == 'GET' for value in (new or old)['values'].values())
            if new and state in ('new', 'changed') and ids and get_only:
                asset = entry['asset']
                candidate = asset if asset.startswith(('http://', 'https://')) else 'https://' + (
                    '[' + asset + ']' if ':' in asset else asset) + '/'
                try:
                    target = authorize(candidate, [parse_target(t) for t in current['scope']]).url
                except ScopeError:
                    pass
            entries.append({**entry, 'state': state, 'before': list(old['values'].values()) if old else [],
                            'after': list(new['values'].values()) if new else [], 'observation_ids': ids,
                            'followup_url': target})
        warnings = list(current['coverage']['warnings'])
        warnings.extend('Baseline ' + warning for warning in before['coverage']['warnings'])
        if not evidence_current:
            warnings.append('Baseline evidence or parser generation changed. Save a fresh baseline before preparing follow-ups.')
        if before['coverage'].get('legacy_inputs') or current['coverage'].get('legacy_inputs'):
            warnings.append('Historical or reused nodes lack fresh input receipts. Their input coverage is unknown.')
        if before['coverage'] != current['coverage']:
            # Per-run artifact IDs differ normally. Compare the actual limits,
            # routing, registered inputs and executable pins separately.
            for field in ('budgets', 'input_snapshots', 'binary_pins', 'http_routing'):
                if before['coverage'][field] != current['coverage'][field]:
                    warnings.append(f'Coverage {field.replace("_", " ")} differs from the baseline.')
        result = {'baseline': {k: baseline[k] for k in ('id', 'revision', 'run_id', 'created', 'snapshot_hash')},
                  'run_id': rid, 'evidence_current': evidence_current, 'entries': entries,
                  'summary': {state: sum(e['state'] == state for e in entries)
                              for state in ('new', 'changed', 'unchanged', 'not_observed')},
                  'coverage': {'baseline': before['coverage'], 'current': current['coverage']},
                  'warnings': sorted(set(warnings)),
                  'absence_means': 'Not observed in the current run. Review collection coverage before interpreting absence.',
                  'current_hash': digest(current)}
        return {**result, 'comparison_hash': digest(result)}

    def check_binding(self, binding):
        from .proposals import StalePlan
        try:
            comparison = self.compare(binding['run_id'], binding['baseline_id'], index=False)
        except (ScopeError, KeyError) as exc:
            raise StalePlan('Delta baseline or source evidence is unavailable. Prepare a new comparison.') from exc
        if not comparison['evidence_current'] or comparison['comparison_hash'] != binding['comparison_hash']:
            raise StalePlan('Delta evidence or coverage changed. Prepare a fresh comparison and follow-up plan.')

    def plan(self, rid, body, planner):
        comparison = self.compare(rid, body.baseline_id)
        if comparison['comparison_hash'] != body.expected_hash or not comparison['evidence_current']:
            raise ScopeError('Delta comparison changed. Reload it before preparing follow-ups.')
        wanted = body.fingerprints
        if len(set(wanted)) != len(wanted):
            raise ScopeError('Select distinct change rows.')
        selected = [e for e in comparison['entries'] if e['fingerprint'] in wanted]
        if len(selected) != len(wanted) or any(not e['followup_url'] for e in selected):
            raise ScopeError('Select current new or changed records with an authorized follow-up URL.')
        ids = sorted({oid for entry in selected for oid in entry['observation_ids']})
        if len(ids) > 8:
            raise ScopeError('Select changes supported by at most eight observations per follow-up.')
        goal = 'Capture HTTP evidence for the selected recon changes.'
        context = planner.context(rid, ids, goal)
        targets = sorted({entry['followup_url'] for entry in selected})
        from .workflows import REGISTRY
        action = {'id': digest(targets)[:24], 'adapter_id': 'native_http', 'input_type': 'url',
                  'target': targets[0], 'targets': targets, 'params': {}, 'risk': 'low', 'title': 'Capture selected recon changes',
                  'signal': 'Current HTTP evidence for the selected new or changed assets.', 'observation_ids': ids,
                  'boundary': 'native scoped HTTP', 'cost': {'native_operations': len(targets), 'cli_invocations': 0,
                                                          'cli_internal_requests': None},
                  'contract_hash': digest(REGISTRY['native_http'])}
        context.update(actions=[action], delta={'baseline_id': body.baseline_id, 'run_id': rid,
                       'comparison_hash': comparison['comparison_hash'], 'fingerprints': wanted,
                       'baseline_revision': comparison['baseline']['revision']})
        context['coverage_limits'] += comparison['warnings'][:8]
        return planner.save(goal, context)
