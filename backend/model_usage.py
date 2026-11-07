"""Durable, metadata-only accounting for model call attempts and reported tokens.

Missing provider usage remains unknown. No prompts, responses, endpoint URLs,
credentials, exception messages or invented prices are stored here.
"""
import asyncio
import inspect
import json
import os
import uuid

from .observations import encoded
from .store import now

TOKEN_FIELDS = ('input_tokens', 'output_tokens', 'total_tokens', 'cached_input_tokens', 'reasoning_tokens')
PURPOSES = {'assessment', 'workflow_analysis', 'team_member', 'team_synthesis',
            'workflow_plan', 'canvas_assist', 'evidence_plan'}
MAX_TOKEN_VALUE = 1_000_000_000


def _field(value, key):
    return value.get(key) if isinstance(value, dict) else getattr(value, key, None)


def _token(value):
    return value if type(value) is int and 0 <= value <= MAX_TOKEN_VALUE else None


def provider_tokens(usage):
    return {'input_tokens': _token(_field(usage, 'prompt_tokens')),
            'output_tokens': _token(_field(usage, 'completion_tokens')),
            'total_tokens': _token(_field(usage, 'total_tokens')),
            'cached_input_tokens': _token(_field(_field(usage, 'prompt_tokens_details'), 'cached_tokens')),
            'reasoning_tokens': _token(_field(_field(usage, 'completion_tokens_details'), 'reasoning_tokens'))}


def validate_event(event):
    if not isinstance(event, dict) or event.get('phase') not in ('started', 'response', 'failed'):
        raise RuntimeError('Invalid model usage event.')
    sequence = event.get('sequence')
    expected = {'sequence', 'phase', 'tokens'} if event['phase'] == 'response' else {'sequence', 'phase'}
    if set(event) != expected or type(sequence) is not int or not 1 <= sequence <= 24:
        raise RuntimeError('Invalid model usage event fields.')
    if event['phase'] == 'response':
        tokens = event['tokens']
        if not isinstance(tokens, dict) or set(tokens) != set(TOKEN_FIELDS) or any(
                value is not None and _token(value) is None for value in tokens.values()):
            raise RuntimeError('Invalid reported model token counts.')
    return event


async def tracked_completion(client, callback, sequence, **request):
    """Persist admission before the provider call; retain usage before parsing its output."""
    if callback:
        await callback({'sequence': sequence, 'phase': 'started'})
    try:
        response = await client.chat.completions.create(**request)
    except BaseException:
        if callback:
            await callback({'sequence': sequence, 'phase': 'failed'})
        raise
    if callback:
        await callback({'sequence': sequence, 'phase': 'response', 'tokens': provider_tokens(_field(response, 'usage'))})
    return response


class ModelUsage:
    def __init__(self, store):
        self.store = store
        with store.connect() as c:
            c.executescript('''
                CREATE TABLE IF NOT EXISTS model_usage_runs(run_id TEXT PRIMARY KEY,created TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS model_invocations(
                    id TEXT PRIMARY KEY,run_id TEXT,related_run_id TEXT,node_id TEXT,role TEXT,
                    purpose TEXT NOT NULL,provider TEXT,model TEXT,execution_mode TEXT,
                    max_turns INTEGER NOT NULL,metered INTEGER NOT NULL,started TEXT NOT NULL,finished TEXT,status TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS model_invocations_by_run ON model_invocations(run_id,started);
                CREATE TABLE IF NOT EXISTS model_calls(
                    invocation_id TEXT NOT NULL,sequence INTEGER NOT NULL,started TEXT NOT NULL,finished TEXT,
                    status TEXT NOT NULL,input_tokens INTEGER,output_tokens INTEGER,total_tokens INTEGER,
                    cached_input_tokens INTEGER,reasoning_tokens INTEGER,PRIMARY KEY(invocation_id,sequence));
            ''')
            c.execute("UPDATE model_calls SET status='interrupted',finished=? WHERE status='pending'", (now(),))
            c.execute("UPDATE model_invocations SET status='interrupted',finished=? WHERE status='running'", (now(),))

    def start_run(self, rid):
        with self.store.connect() as c:
            c.execute('INSERT OR IGNORE INTO model_usage_runs VALUES(?,?)', (rid, now()))

    def begin(self, *, run_id=None, related_run_id=None, node_id=None, role=None, purpose='assessment',
              provider=None, model=None, execution_mode='in-process', max_turns=12, metered=True):
        if purpose not in PURPOSES or type(max_turns) is not int or not 1 <= max_turns <= 24:
            raise RuntimeError('Invalid model accounting context.')
        identifier = str(uuid.uuid4())
        # Identity comes from the caller's server-owned context, never a worker frame.
        with self.store.connect() as c:
            c.execute('INSERT INTO model_invocations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                      (identifier, run_id, related_run_id, node_id, role, purpose, str(provider or 'configured')[:40],
                       str(model or 'configured model')[:120], execution_mode, max_turns, int(metered), now(), None, 'running'))
        return identifier

    def record(self, identifier, event):
        event = validate_event(event)
        sequence, phase = event['sequence'], event['phase']
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            invocation = c.execute('SELECT * FROM model_invocations WHERE id=?', (identifier,)).fetchone()
            if invocation is None or invocation['status'] != 'running' or not invocation['metered'] or sequence > invocation['max_turns']:
                raise RuntimeError('Model usage event has no active accounting context.')
            existing = c.execute('SELECT * FROM model_calls WHERE invocation_id=? AND sequence=?', (identifier, sequence)).fetchone()
            if phase == 'started':
                if existing:
                    return  # idempotent persistence; the worker protocol rejects duplicate admissions
                rows = c.execute('SELECT sequence,status FROM model_calls WHERE invocation_id=?', (identifier,)).fetchall()
                if sequence != len(rows) + 1 or any(row['status'] == 'pending' for row in rows):
                    raise RuntimeError('Model usage admission is out of sequence.')
                c.execute('INSERT INTO model_calls(invocation_id,sequence,started,status) VALUES(?,?,?,?)',
                          (identifier, sequence, now(), 'pending'))
            else:
                if existing is None:
                    raise RuntimeError('Model usage response has no admitted attempt.')
                tokens = event.get('tokens') or {key: None for key in TOKEN_FIELDS}
                if existing['status'] != 'pending':
                    if existing['status'] == phase and all(existing[k] == tokens[k] for k in TOKEN_FIELDS):
                        return
                    raise RuntimeError('Model usage response conflicts with its recorded attempt.')
                c.execute('UPDATE model_calls SET status=?,finished=?,input_tokens=?,output_tokens=?,total_tokens=?,cached_input_tokens=?,reasoning_tokens=? WHERE invocation_id=? AND sequence=?',
                          (phase, now(), *(tokens[k] for k in TOKEN_FIELDS), identifier, sequence))
            if invocation['run_id']:
                c.execute('INSERT INTO events(run_id,time,kind,data) VALUES(?,?,?,?)',
                          (invocation['run_id'], now(), 'model.' + phase, encoded({'usage_id': identifier,
                           'sequence': sequence, 'node_id': invocation['node_id'], 'role': invocation['role'],
                           **({'tokens': event['tokens']} if phase == 'response' else {})})))

    def finish(self, identifier, status):
        if status not in ('completed', 'failed', 'cancelled'):
            raise RuntimeError('Invalid model accounting completion.')
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            c.execute("UPDATE model_calls SET status='interrupted',finished=? WHERE invocation_id=? AND status='pending'", (now(), identifier))
            c.execute("UPDATE model_invocations SET status=?,finished=? WHERE id=? AND status='running'", (status, now(), identifier))

    def summary(self, *, run_id=None, invocation_id=None):
        with self.store.connect() as c:
            c.execute('BEGIN')
            return self._summary(c, run_id=run_id, invocation_id=invocation_id)

    def _summary(self, c, *, run_id=None, invocation_id=None):
        where, args = [], []
        if run_id is not None: where.append('i.run_id=?'); args.append(run_id)
        if invocation_id is not None: where.append('i.id=?'); args.append(invocation_id)
        clause = ' WHERE ' + ' AND '.join(where) if where else ''
        available = run_id is None or bool(c.execute('SELECT 1 FROM model_usage_runs WHERE run_id=?', (run_id,)).fetchone())
        passes = c.execute('SELECT COUNT(*) AS n,SUM(CASE WHEN metered=0 THEN 1 ELSE 0 END) AS unmetered,SUM(CASE WHEN status=\'running\' THEN 1 ELSE 0 END) AS running FROM model_invocations i' + clause, args).fetchone()
        counters = ["COUNT(*) AS attempts", "SUM(CASE WHEN c.status='response' THEN 1 ELSE 0 END) AS responses",
                    "SUM(CASE WHEN c.status!='response' THEN 1 ELSE 0 END) AS unknown_attempts",
                    "SUM(CASE WHEN c.status='response' AND (input_tokens IS NULL OR output_tokens IS NULL OR total_tokens IS NULL) THEN 1 ELSE 0 END) AS missing_usage_responses"]
        counters += [f"SUM(CASE WHEN c.status='{status}' THEN 1 ELSE 0 END) AS {name}_attempts"
                     for status, name in [('pending', 'pending'), ('failed', 'failed'), ('interrupted', 'interrupted')]]
        counters += [f"SUM(CASE WHEN c.status='response' THEN {key} END) AS {key}" for key in TOKEN_FIELDS]
        calls = c.execute('SELECT ' + ','.join(counters) + ' FROM model_calls c JOIN model_invocations i ON i.id=c.invocation_id' + clause, args).fetchone()
        counts = {key: calls[key] or 0 for key in ('attempts', 'responses', 'unknown_attempts', 'missing_usage_responses',
                                                'pending_attempts', 'failed_attempts', 'interrupted_attempts')}
        totals = {key: calls[key] for key in TOKEN_FIELDS}
        coverage = ('unavailable' if not available else 'in_progress' if passes['running'] else
                    'partial' if counts['unknown_attempts'] or counts['missing_usage_responses'] or passes['unmetered'] else 'complete')
        return {'available': available, 'coverage': coverage, 'invocations': passes['n'],
                'unmetered_invocations': passes['unmetered'] or 0, 'active_invocations': passes['running'] or 0,
                **counts, **totals}

    def history(self, *, run_id=None, limit=50, offset=0):
        clause, args = (' WHERE run_id=?', [run_id]) if run_id is not None else ('', [])
        with self.store.connect() as c:
            c.execute('BEGIN')
            total = c.execute('SELECT COUNT(*) FROM model_invocations' + clause, args).fetchone()[0]
            rows = c.execute('SELECT * FROM model_invocations' + clause + ' ORDER BY started DESC,id LIMIT ? OFFSET ?',
                             [*args, max(1, min(limit, 100)), max(0, offset)]).fetchall()
            return {'schema': 'ai-tricky.model-usage/v1', 'run_id': run_id, 'captured_at': now(),
                    'summary': self._summary(c, run_id=run_id), 'items': [
                {**dict(row), 'usage': self._summary(c, invocation_id=row['id'])} for row in rows],
                'total': total, 'limit': max(1, min(limit, 100)), 'offset': max(0, offset)}

    async def assess(self, assessor, targets, goal, request_tool, *, run_id=None, related_run_id=None,
                     node_id=None, role=None, purpose='assessment', execution_mode=None, **kwargs):
        supported = 'usage_callback' in inspect.signature(assessor).parameters
        cfg = kwargs.get('model') or {}
        identifier = self.begin(run_id=run_id, related_run_id=related_run_id, node_id=node_id, role=role,
            purpose=purpose, provider=cfg.get('provider'), model=cfg.get('model') or os.environ.get('CAI_MODEL'),
            execution_mode=execution_mode or ('isolated-interpreter' if os.environ.get('CAI_PYTHON') else 'in-process'),
            max_turns=max(1, min(int(kwargs.get('max_turns', 12)), 24)), metered=supported)
        async def record(event):
            # Commit completes before acknowledging a worker or admitting its request.
            self.record(identifier, event)
        try:
            result = await assessor(targets, goal, request_tool, **kwargs,
                                    **({'usage_callback': record} if supported else {}))
        except BaseException as exc:
            self.finish(identifier, 'cancelled' if isinstance(exc, asyncio.CancelledError) else 'failed')
            raise
        self.finish(identifier, 'completed')
        return {**result, 'model_usage_id': identifier, 'model_usage': self.summary(invocation_id=identifier)}
