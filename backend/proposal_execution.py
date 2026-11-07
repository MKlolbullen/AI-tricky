"""Operator-reviewed, single-use execution snapshots for saved proposals."""
import json
import uuid
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from typing import Annotated
from typing import Literal

from .catalog import registered_path
from .catalog_execution import preflight
from .cli_runner import input_fingerprint
from .observations import digest, encoded
from .proposals import StalePlan, action_graph
from .scope import ScopeError, network_hosts, parse_target
from .store import now
from .workflows import validate_workflow
from . import verification

SCHEMA = 'ai-tricky.proposal-execution/v1'
REVIEW_SECONDS = 900


class ExecutionOptions(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    allow_cli: bool = False
    max_requests: int = Field(default=1, ge=1, le=2048)
    max_cli_invocations: int = Field(default=1, ge=1, le=256)
    max_hosts: int = Field(default=64, ge=1, le=256)
    max_seconds: int = Field(default=120, ge=1, le=3600)
    input_refs: dict[str, Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9_-]{1,64}$')]] = Field(default_factory=dict, max_length=1)
    verification_profile: Literal['repeat_get', 'cors_origin'] | None = None
    finding_id: str | None = Field(default=None, min_length=1, max_length=64, pattern=r'^[A-Za-z0-9_-]+$')


class SnapshotAction(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    expected_hash: str = Field(pattern=r'^[0-9a-f]{64}$')


class DispatchAction(SnapshotAction):
    approve: bool


class ExecutionError(ValueError):
    def __init__(self, message, status=409):
        super().__init__(message)
        self.status = status


class ProposalExecutions:
    def __init__(self, store, planner):
        self.store, self.planner = store, planner
        self.session = str(uuid.uuid4())
        with store.connect() as c:
            c.executescript('''
                CREATE TABLE IF NOT EXISTS proposal_executions(
                    id TEXT PRIMARY KEY,plan_id TEXT NOT NULL,proposal_id TEXT NOT NULL,
                    created TEXT NOT NULL,expires TEXT NOT NULL,updated TEXT NOT NULL,
                    status TEXT NOT NULL,snapshot_hash TEXT NOT NULL,snapshot TEXT NOT NULL,
                    run_id TEXT UNIQUE,reason TEXT);
                CREATE INDEX IF NOT EXISTS executions_by_plan ON proposal_executions(plan_id,created);
                CREATE TABLE IF NOT EXISTS proposal_execution_events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,execution_id TEXT NOT NULL,
                    time TEXT NOT NULL,kind TEXT NOT NULL,data TEXT NOT NULL);
            ''')
            # Approval applies to one local runtime, never to an automatic restart.
            for row in c.execute("SELECT id FROM proposal_executions WHERE status='pending'").fetchall():
                self._finish(c, row['id'], 'invalidated', 'The local runtime restarted. Prepare a new execution review.')

    @staticmethod
    def _event(c, eid, kind, data):
        c.execute('INSERT INTO proposal_execution_events(execution_id,time,kind,data) VALUES(?,?,?,?)',
                  (eid, now(), kind, encoded(data)))

    def _finish(self, c, eid, state, reason):
        changed = c.execute("UPDATE proposal_executions SET status=?,reason=?,updated=? WHERE id=? AND status='pending'",
                            (state, reason, now(), eid))
        if changed.rowcount:
            self._event(c, eid, state, {'reason': reason})

    def _proposal(self, plan_id, proposal_id):
        try:
            plan = self.planner.plan(plan_id)
        except KeyError:
            raise ExecutionError('Evidence-guided plan not found.', 404) from None
        if not plan['current']:
            raise ExecutionError(plan['stale_reason'])
        proposal = next((p for p in plan['proposals'] if p['id'] == proposal_id), None)
        if proposal is None:
            raise ExecutionError('Proposal not found in this plan.', 404)
        return plan, proposal

    def _scope_ids(self, scope):
        known = {t['url']: t['id'] for t in self.store.targets()}
        if not scope or any(t not in known for t in scope):
            raise ExecutionError('Every recorded scope entry must still be an entered target. Restore the scope before preparing a new review.')
        return [known[t] for t in scope]

    def _bindings(self, config):
        ready = preflight(config['workflow'], config, self.store)
        if not ready['ready']:
            reasons = [reason for issue in ready['issues'] for reason in issue['reasons']]
            raise ExecutionError('Execution preflight failed: ' + ' '.join(dict.fromkeys(reasons)), 422)
        pins = {}
        for node in config['workflow']['nodes']:
            for typ, identifier in node['data'].get('inputRefs', {}).items():
                kind = 'folder' if typ in ('templates', 'folder') else 'file'
                path = registered_path(self.store, identifier, kind)
                pins[identifier] = {'kind': kind, 'sha256': input_fingerprint(path, kind)}
        return {'cli_binaries': ready['cli_binaries'], 'input_snapshots': ready['input_snapshots'],
                'proposal_input_pins': pins}

    def eligible_findings(self, plan_id, proposal_id):
        _, proposal = self._proposal(plan_id, proposal_id)
        ids = proposal['observation_ids']
        with self.store.connect() as c:
            rows = c.execute('''SELECT DISTINCT f.id,f.title,f.status FROM findings f
                                JOIN finding_occurrences o ON o.finding_id=f.id
                                WHERE o.observation_id IN (''' + ','.join('?' for _ in ids) + ')', ids).fetchall()
        return [dict(row) for row in rows]

    def _check_finding(self, plan_id, proposal_id, finding_id):
        if finding_id and finding_id not in {f['id'] for f in self.eligible_findings(plan_id, proposal_id)}:
            raise ExecutionError('Link only a finding supported by this proposal\'s cited observations.', 422)

    def prepare(self, plan_id, proposal_id, options):
        plan, proposal = self._proposal(plan_id, proposal_id)
        action = proposal['action']
        refs = options['input_refs']
        allowed_refs = {'templates'} if action['adapter_id'] == 'nuclei' else set()
        if set(refs) - allowed_refs:
            raise ExecutionError('Only the reviewed template binding declared by this proposal can be supplied.', 422)
        graph = action_graph(action, proposal_id)
        if refs:
            next(n for n in graph['nodes'] if n['id'] == 'followup-test')['data']['inputRefs'] = refs
        validate_workflow(graph, live=True)
        config = {k: v for k, v in options.items() if k not in ('input_refs', 'verification_profile', 'finding_id')}
        profile_id, finding_id = options.get('verification_profile'), options.get('finding_id')
        if profile_id:
            if action['adapter_id'] != 'native_http':
                raise ExecutionError('Controlled verification is available only for a bound native HTTP proposal.', 422)
            if config['max_requests'] < 2:
                raise ExecutionError('This verification profile requires a budget of at least two native operations.', 422)
            self._check_finding(plan_id, proposal_id, finding_id)
            config['verification'] = verification.contract(profile_id, action['target'], finding_id=finding_id)
        elif finding_id:
            raise ExecutionError('Select a controlled verification profile to link a finding.', 422)
        if not action['cost']['cli_invocations'] and config['allow_cli']:
            raise ExecutionError('This native proposal does not require CLI permission.', 422)
        config.update(target_ids=self._scope_ids(plan['scope']), targets=plan['scope'], goal=plan['goal'],
                      engine='workflow', workflow=graph, parallelism=1, ports=[80, 443], allow_http=True,
                      cli_credential_keys=[])
        scopes = [parse_target(t) for t in config['targets']]
        for target in scopes:
            if target.kind not in ('url', 'wildcard'):
                network_hosts(target.url, scopes, config['max_hosts'])
        if action['cost']['native_operations'] > config['max_requests'] or action['cost']['cli_invocations'] > config['max_cli_invocations']:
            raise ExecutionError('The selected budgets do not cover this proposal.', 422)
        config.update(self._bindings(config))
        # Recheck after filesystem preflight before persisting the review.
        self._proposal(plan_id, proposal_id)
        eid, created = str(uuid.uuid4()), now()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=REVIEW_SECONDS)).isoformat()
        snapshot = {'schema': SCHEMA, 'id': eid, 'created': created, 'expires': expires, 'session': self.session,
                    'plan_id': plan_id, 'proposal_id': proposal_id, 'source_run_id': plan['run_id'],
                    'context_hash': plan['context_hash'], 'action': action, 'config': config,
                    'observation_ids': proposal['observation_ids'], 'artifact_ids': proposal['artifact_ids']}
        fingerprint = digest(snapshot)
        with self.store.connect() as c:
            c.execute('INSERT INTO proposal_executions VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                      (eid, plan_id, proposal_id, created, expires, created, 'pending', fingerprint, encoded(snapshot), None, None))
            self._event(c, eid, 'prepared', {'snapshot_hash': fingerprint})
        return self.get(eid)

    def _read(self, c, eid):
        row = c.execute('SELECT * FROM proposal_executions WHERE id=?', (eid,)).fetchone()
        if row is None:
            raise ExecutionError('Execution review not found.', 404)
        return {**dict(row), 'snapshot': json.loads(row['snapshot'])}

    def _verify(self, record):
        snapshot = record['snapshot']
        if digest(snapshot) != record['snapshot_hash'] or snapshot['session'] != self.session:
            raise ExecutionError('Execution bindings changed. Prepare a new review.')
        if datetime.fromisoformat(record['expires']) <= datetime.now(timezone.utc):
            raise ExecutionError('This execution review expired. Prepare a new review.')
        plan, proposal = self._proposal(record['plan_id'], record['proposal_id'])
        if plan['context_hash'] != snapshot['context_hash'] or proposal['action'] != snapshot['action']:
            raise ExecutionError('Proposal bindings changed. Prepare a new review.')
        config = snapshot['config']
        if config.get('verification'):
            try:
                verification.check_contract(config['verification'])
            except ValueError as exc:
                raise ExecutionError(str(exc)) from None
            self._check_finding(record['plan_id'], record['proposal_id'], config['verification'].get('finding_id'))
        if self._scope_ids(plan['scope']) != config['target_ids'] or plan['scope'] != config['targets']:
            raise ExecutionError('The entered scope changed. Prepare a new review.')
        bindings = self._bindings(config)
        if any(bindings[key] != config[key] for key in bindings):
            raise ExecutionError('Executable or registered input contents changed. Prepare a new review.')

    def _check_pending(self, c, record):
        if record['status'] != 'pending':
            return
        try:
            self._verify(record)
        except (ExecutionError, ScopeError, StalePlan) as exc:
            expired = datetime.fromisoformat(record['expires']) <= datetime.now(timezone.utc)
            self._finish(c, record['id'], 'expired' if expired else 'invalidated', str(exc))
        except OSError:
            self._finish(c, record['id'], 'invalidated', 'An approved input or executable is unavailable. Prepare a new review.')

    def get(self, eid):
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            record = self._read(c, eid)
            self._check_pending(c, record)
            record = self._read(c, eid)
            events = [{**dict(r), 'data': json.loads(r['data'])} for r in c.execute(
                'SELECT * FROM proposal_execution_events WHERE execution_id=? ORDER BY seq', (eid,))]
        return {**record, 'events': events}

    def history(self, plan_id):
        with self.store.connect() as c:
            rows = c.execute('''SELECT id,proposal_id,created,expires,status,snapshot_hash,run_id,reason
                                FROM proposal_executions WHERE plan_id=? ORDER BY created DESC LIMIT 50''', (plan_id,))
            return [dict(r) for r in rows]

    def revoke(self, eid, expected_hash):
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            record = self._read(c, eid)
            if record['snapshot_hash'] != expected_hash:
                raise ExecutionError('The execution review hash does not match.')
            if record['status'] not in ('pending', 'revoked'):
                raise ExecutionError('This execution review can no longer be revoked.')
            self._finish(c, eid, 'revoked', 'Revoked by the local operator before dispatch.')
        return self.get(eid)

    def dispatch(self, eid, expected_hash):
        """Consume review and create its run in one SQLite transaction; retries return that run."""
        error = None
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            record = self._read(c, eid)
            if record['snapshot_hash'] != expected_hash:
                raise ExecutionError('The execution review hash does not match.')
            if record['status'] == 'dispatched':
                return self.store.run(record['run_id']), False
            self._check_pending(c, record)
            record = self._read(c, eid)
            if record['status'] != 'pending':
                error = ExecutionError(record['reason'] or 'This execution review is no longer pending.')
            else:
                snapshot = record['snapshot']
                provenance = {key: snapshot[key] for key in ('id', 'plan_id', 'proposal_id', 'source_run_id', 'context_hash')}
                provenance['snapshot_hash'] = record['snapshot_hash']
                config = {**snapshot['config'], 'proposal_execution': provenance}
                run = self.store.new_run(config, connection=c)
                if config.get('verification'):
                    binding = config['verification']
                    c.execute('INSERT INTO verification_runs VALUES(?,?,?,?,?)',
                              (run['id'], eid, binding.get('finding_id'), binding['profile_id'], now()))
                c.execute("UPDATE proposal_executions SET status='dispatched',run_id=?,updated=? WHERE id=?", (run['id'], now(), eid))
                self._event(c, eid, 'approved', {'snapshot_hash': expected_hash, 'actor': 'local operator'})
                self._event(c, eid, 'dispatched', {'run_id': run['id']})
                c.execute('INSERT INTO events(run_id,time,kind,data) VALUES(?,?,?,?)',
                          (run['id'], now(), 'proposal.approved', encoded(provenance)))
        if error:
            raise error
        return run, True
