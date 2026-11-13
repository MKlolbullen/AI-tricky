"""Reviewed branch recovery using immutable, provenance-bound node outputs.

Preparing a recovery performs local validation only. Dispatch consumes its
single-use review and creates a new run, checkpoint copies and audit receipt in
one transaction. Historical captures never masquerade as fresh observations.
"""
import hashlib
import hmac
import json
import secrets
import uuid
import inspect
from datetime import datetime, timedelta, timezone
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .catalog import CATALOG, TOOLS, registered_path
from .catalog_execution import preflight
from .cli_runner import input_fingerprint
from .observations import digest, encoded
from .proposal_execution import ExecutionError, REVIEW_SECONDS
from .scope import ScopeError, network_hosts, parse_target
from .store import now
from .workflows import REGISTRY, validate_workflow
from .http_routing import HTTPRouting, routing_binding

SCHEMA = 'ai-tricky.workflow-recovery/v1'
TERMINAL = {'completed', 'failed', 'cancelled', 'interrupted'}
MAX_CHECKPOINT_BYTES = 25_000_000
MAX_CHECKPOINT_ARTIFACTS = 1000
ID = Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9_-]{1,64}$')]


class RecoveryOptions(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    node_ids: list[ID] = Field(min_length=1, max_length=64)
    allow_cli: bool = False
    max_requests: int = Field(default=256, ge=1, le=2048)
    max_cli_invocations: int = Field(default=64, ge=1, le=256)
    max_hosts: int = Field(default=64, ge=1, le=256)
    max_seconds: int = Field(default=240, ge=1, le=3600)
    http_routing: HTTPRouting | None = None


def artifact_references(value):
    """Only structured provenance fields and file sockets carry artifact IDs."""
    refs = set()
    if isinstance(value, list):
        for item in value:
            refs.update(artifact_references(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            if key in ('artifact_id','handoff_artifact_id','report_artifact_id') and isinstance(item, str):
                refs.add(item)
            elif key in ('evidence_ids', 'invocation_artifact_ids') and isinstance(item, list):
                refs.update(v for v in item if isinstance(v, str))
            elif key == 'catalog_streams' and isinstance(item, dict):
                for typ in ('file', 'folder'):
                    values = item.get(typ, [])
                    if isinstance(values, list):
                        refs.update(v[9:] for v in values if isinstance(v, str) and v.startswith('artifact:'))
            else:
                refs.update(artifact_references(item))
    return refs


def remap_references(value, mapping):
    if isinstance(value, list):
        return [remap_references(v, mapping) for v in value]
    if not isinstance(value, dict):
        return value  # response bodies, headers and free text are not rewritten
    out = {}
    for key, item in value.items():
        if key in ('artifact_id','handoff_artifact_id','report_artifact_id') and isinstance(item, str):
            out[key] = mapping.get(item, item)
        elif key in ('evidence_ids', 'invocation_artifact_ids') and isinstance(item, list):
            out[key] = [mapping.get(v, v) if isinstance(v, str) else v for v in item]
        elif key == 'catalog_streams' and isinstance(item, dict):
            out[key] = {typ: [('artifact:' + mapping[v[9:]]) if typ in ('file', 'folder') and
                         isinstance(v, str) and v.startswith('artifact:') and v[9:] in mapping else v
                         for v in values] for typ, values in item.items()}
        else:
            out[key] = remap_references(item, mapping)
    return out


def checked_reused_content(store, aid):
    content = store.content(aid)
    with store.connect() as c:
        binding = c.execute('SELECT sha256 FROM artifact_reuse WHERE artifact_id=?', (aid,)).fetchone()
    if binding and digest(content) != binding['sha256']:
        raise ScopeError('A reused artifact changed after recovery approval.')
    return content


def load_checkpoints(store, rid, config):
    """Check the complete copied bundle before the runner admits any traffic."""
    checkpoints = store.checkpoints(rid)
    expected = set(config['workflow_recovery']['reused_ids'])
    if set(checkpoints) != expected:
        raise ScopeError('Recovery checkpoints no longer match the approved run.')
    with store.connect() as c:
        artifacts = c.execute('SELECT a.id FROM artifacts a JOIN artifact_reuse r ON r.artifact_id=a.id WHERE a.run_id=?', (rid,)).fetchall()
    for artifact in artifacts:
        checked_reused_content(store, artifact['id'])
    result = {}
    for nid, binding in checkpoints.items():
        content = checked_reused_content(store, binding['artifact_id'])
        if digest(content) != binding['sha256']:
            raise ScopeError('A node checkpoint changed after recovery approval.')
        result[nid] = {**binding, 'content': content}
    return result


class WorkflowRecoveries:
    def __init__(self, store, *, credential=lambda key: None, model_config=None, source_active=lambda rid: False):
        self.store, self.credential, self.model_config = store, credential, model_config
        self.source_active = source_active
        self.session, self.salt = str(uuid.uuid4()), secrets.token_bytes(32)
        with store.connect() as c:
            c.executescript('''
                CREATE TABLE IF NOT EXISTS workflow_recoveries(
                    id TEXT PRIMARY KEY,source_run_id TEXT NOT NULL,created TEXT NOT NULL,expires TEXT NOT NULL,
                    status TEXT NOT NULL,snapshot_hash TEXT NOT NULL,snapshot TEXT NOT NULL,run_id TEXT UNIQUE,reason TEXT);
                CREATE INDEX IF NOT EXISTS recoveries_by_source ON workflow_recoveries(source_run_id,created);
                CREATE TABLE IF NOT EXISTS workflow_recovery_events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,recovery_id TEXT NOT NULL,time TEXT NOT NULL,
                    kind TEXT NOT NULL,data TEXT NOT NULL);
            ''')
            for row in c.execute("SELECT id FROM workflow_recoveries WHERE status='pending'").fetchall():
                self._finish(c, row['id'], 'invalidated', 'The local runtime restarted. Prepare a new recovery review.')

    @staticmethod
    def _event(c, identifier, kind, data):
        c.execute('INSERT INTO workflow_recovery_events(recovery_id,time,kind,data) VALUES(?,?,?,?)',
                  (identifier, now(), kind, encoded(data)))

    def _finish(self, c, identifier, status, reason):
        changed = c.execute("UPDATE workflow_recoveries SET status=?,reason=? WHERE id=? AND status='pending'",
                            (status, reason, identifier))
        if changed.rowcount:
            self._event(c, identifier, status, {'reason': reason})

    def _source(self, rid):
        try:
            source = self.store.run(rid)
        except KeyError:
            raise ExecutionError('Source run not found.', 404) from None
        config = source['config']
        if self.source_active(rid):
            raise ExecutionError('The source run is still stopping. Wait for its workers to finish before recovery.')
        if source['status'] not in TERMINAL:
            raise ExecutionError('Wait for the source run to stop before recovering branches.')
        if config.get('engine') != 'workflow' or not config.get('allow_http'):
            raise ExecutionError('Recovery requires a recorded execution of a workflow, not a plan.')
        if config.get('verification'):
            raise ExecutionError('Paired verification requires a fresh proposal execution review; it cannot recover one side of a pair.')
        validate_workflow(config['workflow'], live=True)
        return source

    def _checkpoint(self, rid, node):
        aid = (node.get('result') or {}).get('artifact_id')
        if node['status'] not in ('completed', 'reused') or (node.get('result') or {}).get('errors') or not aid:
            return None
        try:
            meta = self.store.artifact_metadata(aid)
        except KeyError:
            return None
        return meta if meta['run_id'] == rid and meta['node_id'] == node['node_id'] else None

    def inspect(self, rid):
        source = self._source(rid)
        nodes = {n['node_id']: n for n in self.store.nodes(rid)}
        return {'source_run_id': rid, 'scope': source['config']['targets'], 'nodes': [
            {'id': n['id'], 'title': n['data'].get('title', n['id']), 'kind': n['data']['kind'],
             'status': nodes.get(n['id'], {}).get('status', 'interrupted'),
             'checkpoint_available': bool(self._checkpoint(rid, nodes[n['id']])) if n['id'] in nodes else False,
             'errors': (nodes.get(n['id'], {}).get('result') or {}).get('errors', 0)}
            for n in source['config']['workflow']['nodes']], 'history': self.history(rid)}

    def _secret_tag(self, values):
        return hmac.new(self.salt, encoded(values).encode(), hashlib.sha256).hexdigest()

    def _build(self, rid, options):
        source = self._source(rid)
        original = source['config']
        graph = original['workflow']
        order, incoming = validate_workflow(graph, live=True)
        selected = list(dict.fromkeys(options['node_ids']))
        if set(selected) - set(order):
            raise ExecutionError('Select only nodes from the recorded source workflow.', 422)
        states = {n['node_id']: n for n in self.store.nodes(rid)}
        healthy = {nid: self._checkpoint(rid, n) for nid, n in states.items()}
        outgoing = {nid: [] for nid in order}
        for edge in graph['edges']:
            outgoing[edge['source']].append(edge['target'])

        def closure(seeds, adjacency):
            reached, pending = set(seeds), list(seeds)
            while pending:
                for nid in adjacency[pending.pop()]:
                    if nid not in reached:
                        reached.add(nid); pending.append(nid)
            return reached

        rerun = closure(selected, outgoing)
        # A missing or unhealthy upstream checkpoint must run again; include its
        # descendants too, so no old downstream result survives a changed parent.
        while True:
            needed = closure(rerun, incoming)
            missing = {nid for nid in needed - rerun if not healthy.get(nid)}
            if not missing:
                break
            rerun = closure(rerun | missing, outgoing)
        reuse = needed - rerun
        subgraph = {**graph, 'nodes': [n for n in graph['nodes'] if n['id'] in needed],
                    'edges': [e for e in graph['edges'] if e['source'] in needed and e['target'] in needed]}
        validate_workflow(subgraph, live=True)
        scope = original['targets']
        known = {t['url']: t['id'] for t in self.store.targets()}
        if not scope or any(t not in known for t in scope):
            raise ExecutionError('Restore the original entered scope before preparing a recovery.')
        from .identity_graph import identity_workflow
        for target in map(parse_target, scope):
            if target.kind not in ('url', 'wildcard') and not identity_workflow(subgraph):
                network_hosts(target.url, [parse_target(t) for t in scope], options['max_hosts'])
        tools = [TOOLS[n['data']['toolId']] for n in subgraph['nodes']
                 if n['id'] in rerun and n['data']['kind'] == 'catalog_tool']
        keys = sorted({key for tool in tools for key in tool.get('secrets', [])
                       if key in original.get('cli_credential_keys', [])})
        credentials = {key: self.credential(key) for key in keys}
        config = {**{k: v for k, v in options.items() if k != 'node_ids'}, 'engine': 'workflow', 'workflow': subgraph,
                  'targets': scope, 'target_ids': [known[t] for t in scope], 'allow_http': True,
                  'goal': original.get('goal', 'Recover recorded workflow branches.'),
                  'ports': original.get('ports', [80, 443]), 'parallelism': original.get('parallelism', 4),
                  'cli_credential_keys': keys}
        if original.get('cli_scope') == 'enforced':
            config['cli_scope'] = 'enforced'
        config['http_routing']=options.get('http_routing') or original.get('http_routing') or HTTPRouting().model_dump()
        config['http_routing_binding']=routing_binding(config['http_routing'],self.store)
        ready = preflight(subgraph, config, self.store, credentials={k for k, v in credentials.items() if v}, node_ids=rerun)
        if not ready['ready']:
            raise ExecutionError('Recovery preflight failed: ' + ' '.join(dict.fromkeys(
                r for issue in ready['issues'] for r in issue['reasons'])), 422)
        if ready['cli_sandbox']:
            config['cli_sandbox'] = ready['cli_sandbox']
        pins = {}
        for node in subgraph['nodes']:
            data = node['data']
            refs = dict(data.get('inputRefs', {})) if node['id'] in rerun else {}
            if data['kind'] == 'catalog_source' and data.get('inputId'):
                refs[data['sourceType']] = data['inputId']
            for typ, identifier in refs.items():
                kind = 'folder' if typ in ('folder', 'templates') else 'file'
                path = registered_path(self.store, identifier, kind)
                pins[identifier] = {'kind': kind, 'sha256': input_fingerprint(path, kind)}
        config.update(cli_binaries=ready['cli_binaries'], input_snapshots=ready['input_snapshots'], recovery_input_pins=pins)

        artifacts, total, pending = {}, 0, {healthy[nid]['id'] for nid in reuse}
        while pending:
            aid = pending.pop()
            if aid in artifacts:
                continue
            try:
                meta = self.store.artifact_metadata(aid)
                with self.store.connect() as c:
                    size = c.execute('SELECT LENGTH(CAST(content AS BLOB)) FROM artifacts WHERE id=?', (aid,)).fetchone()[0]
                total += size
                if total > MAX_CHECKPOINT_BYTES or len(artifacts) >= MAX_CHECKPOINT_ARTIFACTS:
                    raise ExecutionError('Checkpoint bundle exceeds the 25 MB / 1000 artifact recovery limit.')
                if meta['run_id'] != rid or meta['node_id'] not in reuse:
                    raise ExecutionError('Checkpoint evidence must belong to the reused source nodes.')
                content = self.store.content(aid)
                if aid == healthy[meta['node_id']]['id'] and (not isinstance(content, list) or
                        any(not isinstance(row, dict) for row in content)):
                    raise ExecutionError('Node checkpoint is not a typed output record list.')
                if aid == healthy[meta['node_id']]['id']:
                    for row in content:
                        streams = row.get('catalog_streams')
                        if streams is not None and (not isinstance(streams, dict) or any(
                                not isinstance(values, list) or not all(isinstance(v, str) for v in values)
                                for values in streams.values())):
                            raise ExecutionError('Checkpoint contains an invalid typed stream.')
                artifacts[aid] = {**meta, 'sha256': digest(content), 'captured_at': meta['captured_at'] or source['created']}
                pending.update(artifact_references(content) - artifacts.keys())
            except KeyError:
                raise ExecutionError('Checkpoint evidence is unavailable. Include that node in the retry.') from None
        needs_model = any(n['id'] in rerun and n['data']['kind'] in ('native_cai', 'native_team') for n in subgraph['nodes'])
        for field in ('provider','model','team_routes','team_profile','team_task_level','roles','synthesize','adaptive'):
            if field in original:config[field]=original[field]
        model = (self.model_config(config) if inspect.signature(self.model_config).parameters else self.model_config()) if needs_model and self.model_config else None
        def bind_model(value):
            if not value:return None
            if 'routes' in value:
                return {'default':bind_model(value['default']),
                        'routes':{role:{part:bind_model(choice) for part,choice in route.items()} for role,route in value['routes'].items()}}
            return {'base_url':value.get('base_url'),'model':value.get('model'),
                    'credential_tag':self._secret_tag(value.get('api_key'))}
        model_binding = bind_model(model)
        return ({'source_run_id': rid, 'source_hash': digest({'config': original, 'status': source['status'], 'nodes': list(states.values())}),
                 'options': options, 'selected_ids': selected, 'rerun_ids': [nid for nid in order if nid in rerun],
                 'checkpoints': {nid: healthy[nid]['id'] for nid in order if nid in reuse},
                 'artifacts': {aid: artifacts[aid] for aid in sorted(artifacts)}, 'config': config,
                 'contract_hash': digest({'schema': SCHEMA, 'native': REGISTRY, 'catalog': CATALOG}),
                 'credential_tag': self._secret_tag(credentials), 'model_binding': model_binding}, credentials, model)

    def prepare(self, rid, options):
        plan, _, _ = self._build(rid, options)
        identifier, created = str(uuid.uuid4()), now()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=REVIEW_SECONDS)).isoformat()
        snapshot = {**plan, 'schema': SCHEMA, 'id': identifier, 'session': self.session, 'created': created, 'expires': expires}
        with self.store.connect() as c:
            c.execute('INSERT INTO workflow_recoveries VALUES(?,?,?,?,?,?,?,?,?)',
                      (identifier, rid, created, expires, 'pending', digest(snapshot), encoded(snapshot), None, None))
            self._event(c, identifier, 'prepared', {'snapshot_hash': digest(snapshot)})
        return self.get(identifier)

    @staticmethod
    def _read(c, identifier):
        row = c.execute('SELECT * FROM workflow_recoveries WHERE id=?', (identifier,)).fetchone()
        if row is None:
            raise ExecutionError('Recovery review not found.', 404)
        return {**dict(row), 'snapshot': json.loads(row['snapshot'])}

    def _verify(self, record):
        snapshot = record['snapshot']
        if snapshot['session'] != self.session or digest(snapshot) != record['snapshot_hash']:
            raise ExecutionError('Recovery bindings changed. Prepare a new review.')
        if datetime.fromisoformat(record['expires']) <= datetime.now(timezone.utc):
            raise ExecutionError('Recovery review expired. Prepare a new review.')
        plan, credentials, model = self._build(record['source_run_id'], snapshot['options'])
        if any(snapshot.get(key) != value for key, value in plan.items()):
            raise ExecutionError('Source, checkpoints, scope, inputs, credentials or executable bindings changed. Prepare a new review.')
        return credentials, model

    def _check_pending(self, c, record):
        if record['status'] != 'pending':
            return None, None
        try:
            return self._verify(record)
        except (ExecutionError, ScopeError, OSError) as exc:
            expired = datetime.fromisoformat(record['expires']) <= datetime.now(timezone.utc)
            reason = str(exc) if isinstance(exc, (ExecutionError, ScopeError)) else 'A reviewed input or executable is unavailable.'
            self._finish(c, record['id'], 'expired' if expired else 'invalidated', reason)
            return None, None

    def get(self, identifier):
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            record = self._read(c, identifier)
            self._check_pending(c, record)
            record = self._read(c, identifier)
            events = [{**dict(r), 'data': json.loads(r['data'])} for r in c.execute(
                'SELECT * FROM workflow_recovery_events WHERE recovery_id=? ORDER BY seq', (identifier,))]
        return {**record, 'events': events}

    def history(self, rid):
        with self.store.connect() as c:
            return [dict(r) for r in c.execute('SELECT id,created,expires,status,run_id,reason FROM workflow_recoveries WHERE source_run_id=? ORDER BY created DESC LIMIT 50', (rid,))]

    def revoke(self, identifier, expected_hash):
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            record = self._read(c, identifier)
            if record['snapshot_hash'] != expected_hash or record['status'] not in ('pending', 'revoked'):
                raise ExecutionError('This recovery review cannot be revoked with the supplied hash.')
            self._finish(c, identifier, 'revoked', 'Revoked by the local operator before dispatch.')
        return self.get(identifier)

    def dispatch(self, identifier, expected_hash):
        error = None
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            record = self._read(c, identifier)
            if record['snapshot_hash'] != expected_hash:
                raise ExecutionError('The recovery review hash does not match.')
            if record['status'] == 'dispatched':
                return self.store.run(record['run_id']), False, None, None
            credentials, model = self._check_pending(c, record)
            record = self._read(c, identifier)
            if record['status'] != 'pending':
                error = ExecutionError(record['reason'] or 'Recovery review is no longer pending.')
            else:
                snapshot = record['snapshot']
                provenance = {'id': identifier, 'source_run_id': snapshot['source_run_id'],
                              'snapshot_hash': record['snapshot_hash'], 'rerun_ids': snapshot['rerun_ids'],
                              'reused_ids': list(snapshot['checkpoints'])}
                run = self.store.new_run({**snapshot['config'], 'workflow_recovery': provenance}, connection=c)
                mapping = {aid: str(uuid.uuid4()) for aid in snapshot['artifacts']}
                for aid, binding in snapshot['artifacts'].items():
                    row = c.execute('SELECT content FROM artifacts WHERE id=?', (aid,)).fetchone()
                    content = json.loads(row['content'])
                    if digest(content) != binding['sha256']:
                        raise ExecutionError('Checkpoint content changed during dispatch.')
                    content = remap_references(content, mapping)
                    c.execute('INSERT INTO artifacts(id,run_id,name,content,node_id,captured_at) VALUES(?,?,?,?,?,?)',
                              (mapping[aid], run['id'], f'reused/{snapshot["source_run_id"]}/{binding["name"]}',
                               encoded(content), binding['node_id'], binding['captured_at']))
                    c.execute('INSERT INTO artifact_reuse VALUES(?,?,?,?,?,?)',
                              (mapping[aid], aid, snapshot['source_run_id'], identifier, binding['sha256'], digest(content)))
                for nid, aid in snapshot['checkpoints'].items():
                    content = json.loads(c.execute('SELECT content FROM artifacts WHERE id=?', (mapping[aid],)).fetchone()['content'])
                    c.execute('INSERT INTO workflow_checkpoints VALUES(?,?,?,?,?,?,?)',
                              (run['id'], nid, mapping[aid], digest(content), snapshot['source_run_id'], aid,
                               snapshot['artifacts'][aid]['captured_at']))
                c.execute("UPDATE workflow_recoveries SET status='dispatched',run_id=? WHERE id=?", (run['id'], identifier))
                self._event(c, identifier, 'approved', {'snapshot_hash': expected_hash, 'actor': 'local operator'})
                self._event(c, identifier, 'dispatched', {'run_id': run['id']})
                c.execute('INSERT INTO events(run_id,time,kind,data) VALUES(?,?,?,?)',
                          (run['id'], now(), 'recovery.approved', encoded(provenance)))
        if error:
            raise error
        return run, True, credentials, model
