"""Durable evidence index, operator reviews, and conservative run comparisons."""
import json
import re
import uuid

from .observations import canonical_asset, digest, encoded, parse_artifact, PARSER_VERSION, SEVERITIES
from .store import now


class ReviewConflict(ValueError):
    pass


class EvidenceIndex:
    def __init__(self, store):
        self.store = store
        with store.connect() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS evidence_index(
                artifact_id TEXT NOT NULL, parser_version TEXT NOT NULL, report TEXT NOT NULL,
                PRIMARY KEY(artifact_id,parser_version));
            CREATE TABLE IF NOT EXISTS observations(
                id TEXT PRIMARY KEY, run_id TEXT NOT NULL, node_id TEXT, artifact_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL, value_hash TEXT NOT NULL, kind TEXT NOT NULL,
                asset TEXT NOT NULL, source TEXT NOT NULL, parser_version TEXT NOT NULL,
                data TEXT NOT NULL, observed_at TEXT NOT NULL,
                UNIQUE(artifact_id,fingerprint,value_hash));
            CREATE INDEX IF NOT EXISTS observations_by_run ON observations(run_id,fingerprint);
            CREATE INDEX IF NOT EXISTS observations_by_asset ON observations(asset,kind);
            CREATE TABLE IF NOT EXISTS findings(
                id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL, asset TEXT NOT NULL,
                source TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
                confidence TEXT NOT NULL, status TEXT NOT NULL, rationale TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, revision INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS finding_occurrences(
                finding_id TEXT NOT NULL, observation_id TEXT NOT NULL UNIQUE, run_id TEXT NOT NULL,
                evidence_ids TEXT NOT NULL, snapshot TEXT NOT NULL,
                PRIMARY KEY(finding_id,observation_id));
            CREATE INDEX IF NOT EXISTS occurrences_by_run ON finding_occurrences(run_id,finding_id);
            CREATE TABLE IF NOT EXISTS finding_reviews(
                id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, created TEXT NOT NULL,
                revision INTEGER NOT NULL, previous TEXT NOT NULL, decision TEXT NOT NULL,
                note TEXT NOT NULL, evidence_id TEXT, UNIQUE(finding_id,revision));
            ''')

    def _model_records(self, c, artifact, content):
        records = []
        if not artifact['name'].startswith('node-') or not isinstance(content, list):
            return records
        for row in content:
            analysis = row.get('analysis') if isinstance(row, dict) else None
            if not isinstance(analysis, dict):
                continue
            candidates = analysis.get('candidates', [])
            if not isinstance(candidates, list):
                continue
            for candidate in candidates[:30]:
                if not isinstance(candidate, dict):
                    continue
                ids = candidate.get('evidence_ids')
                title, severity = candidate.get('title'), candidate.get('severity')
                if not isinstance(ids, list) or not ids or len(ids) > 20 or not all(isinstance(i, str) for i in ids):
                    continue
                if not isinstance(title, str) or not title.strip() or not isinstance(severity, str) or severity not in SEVERITIES:
                    continue
                assets = []
                for aid in ids:
                    evidence = c.execute('SELECT name,content FROM artifacts WHERE id=? AND run_id=?', (aid, artifact['run_id'])).fetchone()
                    if evidence is None or not evidence['name'].startswith('http-'):
                        break
                    capture = json.loads(evidence['content'])
                    asset = canonical_asset(capture.get('url')) if isinstance(capture, dict) else None
                    if not asset or type(capture.get('status')) is not int:
                        break
                    assets.append(asset)
                else:
                    assets = sorted(set(assets))
                    rule = encoded([' '.join(title.lower().split()), assets])
                    rationale = str(candidate.get('rationale', ''))[:4000]
                    data = {'title': title[:200], 'severity': severity, 'rationale': rationale,
                            'next_test': str(candidate.get('next_test', ''))[:2000], 'assets': assets}
                    records.append({'kind': 'detection', 'asset': assets[0], 'source': 'cai-evidence',
                                    'fingerprint': digest(['cai-evidence', rule]), 'value_hash': digest(data),
                                    'data': data, 'parser_version': PARSER_VERSION,
                                    'finding': {'rule_id': rule, 'title': title[:200], 'severity': severity,
                                                'rationale': rationale, 'confidence': 'unknown'}, 'evidence_ids': ids})
        return records

    def index_pending(self, run_id=None):
        """Index append-only artifacts in transactions; historical runs need no rewrite."""
        with self.store.connect() as c:
            query = '''SELECT a.id,a.run_id,a.name,a.node_id,COALESCE(a.captured_at,r.created) AS observed_at
                       FROM artifacts a JOIN runs r ON r.id=a.run_id
                       LEFT JOIN evidence_index i ON i.artifact_id=a.id AND i.parser_version=?
                       WHERE i.artifact_id IS NULL'''
            args = [PARSER_VERSION]
            if run_id:
                query += ' AND a.run_id=?'
                args.append(run_id)
            pending = c.execute(query + ' ORDER BY r.created,a.rowid', args).fetchall()
        for artifact in pending:
            with self.store.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                if c.execute('SELECT 1 FROM evidence_index WHERE artifact_id=? AND parser_version=?',
                             (artifact['id'], PARSER_VERSION)).fetchone():
                    continue
                # Large generated binary/file artifacts have no parser contract. Do not
                # load their base64 payloads merely to populate the evidence index.
                eligible = artifact['name'] == 'tcp-inventory.json' or re.fullmatch(r'(?:http|cli|node)-[A-Za-z0-9_-]+\.json', artifact['name'])
                content = json.loads(c.execute('SELECT content FROM artifacts WHERE id=?', (artifact['id'],)).fetchone()['content']) if eligible else None
                records, report = parse_artifact(artifact['name'], content)
                model_records = self._model_records(c, artifact, content)
                records.extend(model_records)
                if model_records:
                    report = {'supported': True, 'parser_version': PARSER_VERSION, 'parsed_records': len(model_records)}
                for record in records:
                    oid = str(uuid.uuid4())
                    c.execute('''INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                              (oid, artifact['run_id'], artifact['node_id'], artifact['id'], record['fingerprint'],
                               record['value_hash'], record['kind'], record['asset'], record['source'],
                               PARSER_VERSION, encoded(record['data']), artifact['observed_at']))
                    if not c.execute('SELECT 1 FROM observations WHERE id=?', (oid,)).fetchone():
                        continue
                    finding = record.get('finding')
                    if finding:
                        fid = str(uuid.uuid4())
                        fingerprint = digest([record['source'], record['asset'], finding['rule_id']])
                        c.execute('''INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                                  (fid, fingerprint, record['asset'], record['source'], finding['title'], finding['severity'],
                                   'unknown', 'candidate', finding['rationale'], artifact['observed_at'], artifact['observed_at'], 1))
                        fid = c.execute('SELECT id FROM findings WHERE fingerprint=?', (fingerprint,)).fetchone()['id']
                        # New scanner output cannot overwrite a human review or severity decision.
                        c.execute('UPDATE findings SET first_seen=MIN(first_seen,?),last_seen=MAX(last_seen,?) WHERE id=?',
                                  (artifact['observed_at'], artifact['observed_at'], fid))
                        evidence_ids = list(dict.fromkeys([artifact['id'], *record.get('evidence_ids', [])]))
                        c.execute('INSERT INTO finding_occurrences VALUES(?,?,?,?,?)',
                                  (fid, oid, artifact['run_id'], encoded(evidence_ids), encoded(record['data'])))
                c.execute('INSERT INTO evidence_index VALUES(?,?,?)', (artifact['id'], PARSER_VERSION, encoded(report)))

    def observations(self, *, run_id=None, kind=None, q='', limit=100, offset=0):
        self.index_pending(run_id)
        where, args = ['1=1'], []
        for column, value in [('run_id', run_id), ('kind', kind)]:
            if value:
                where.append(column + '=?')
                args.append(value)
        if q:
            where.append('(instr(lower(asset),lower(?))>0 OR instr(lower(source),lower(?))>0)')
            args.extend([q, q])
        with self.store.connect() as c:
            total = c.execute('SELECT COUNT(*) FROM observations WHERE ' + ' AND '.join(where), args).fetchone()[0]
            rows = c.execute('''SELECT observations.*,
                             CASE WHEN (SELECT captured_at FROM artifacts WHERE id=observations.artifact_id) IS NULL
                             THEN 'run-start (legacy)' ELSE 'capture' END AS time_basis FROM observations WHERE ''' + ' AND '.join(where) +
                             ' ORDER BY observed_at DESC,id LIMIT ? OFFSET ?', [*args, limit, offset]).fetchall()
        return {'items': [{**dict(r), 'data': json.loads(r['data'])} for r in rows],
                'total': total, 'limit': limit, 'offset': offset}

    def findings(self, *, run_id=None, status=None, severity=None, q='', limit=100, offset=0):
        self.index_pending()  # A reviewable finding spans all of its observed runs.
        where, args = ['1=1'], []
        for column, value in [('status', status), ('severity', severity)]:
            if value:
                where.append('f.' + column + '=?')
                args.append(value)
        if run_id:
            where.append('EXISTS(SELECT 1 FROM finding_occurrences x WHERE x.finding_id=f.id AND x.run_id=?)')
            args.append(run_id)
        if q:
            where.append('(instr(lower(f.asset),lower(?))>0 OR instr(lower(f.title),lower(?))>0)')
            args.extend([q, q])
        with self.store.connect() as c:
            clause = ' FROM findings f WHERE ' + ' AND '.join(where)
            total = c.execute('SELECT COUNT(*)' + clause, args).fetchone()[0]
            rows = c.execute('SELECT f.*,(SELECT COUNT(DISTINCT run_id) FROM finding_occurrences x WHERE x.finding_id=f.id) AS run_count' +
                             clause + ' ORDER BY f.last_seen DESC,f.id LIMIT ? OFFSET ?', [*args, limit, offset]).fetchall()
        return {'items': [dict(r) for r in rows], 'total': total, 'limit': limit, 'offset': offset}

    def finding(self, fid):
        self.index_pending()
        with self.store.connect() as c:
            row = c.execute('SELECT * FROM findings WHERE id=?', (fid,)).fetchone()
            if row is None:
                raise KeyError(fid)
            occurrences = c.execute('''SELECT x.*,o.artifact_id,o.node_id,o.observed_at FROM finding_occurrences x
                                       JOIN observations o ON o.id=x.observation_id WHERE finding_id=?
                                       ORDER BY o.observed_at DESC,o.id''', (fid,)).fetchall()
            reviews = c.execute('SELECT * FROM finding_reviews WHERE finding_id=? ORDER BY revision', (fid,)).fetchall()
        return {**dict(row), 'observed_after_review': bool(reviews and row['last_seen'] > reviews[-1]['created']),
                'occurrences': [{**dict(r), 'evidence_ids': json.loads(r['evidence_ids']),
                                            'snapshot': json.loads(r['snapshot'])} for r in occurrences],
                'reviews': [{**dict(r), 'previous': json.loads(r['previous']), 'decision': json.loads(r['decision'])} for r in reviews]}

    def review(self, fid, *, expected_revision, status, severity, confidence, note, evidence_id=None):
        if status not in {'candidate', 'triaged', 'verified', 'rejected', 'resolved'} or severity not in SEVERITIES or confidence not in {'unknown', 'low', 'medium', 'high'}:
            raise ValueError('Unsupported finding review value.')
        if not note.strip():
            raise ValueError('A review note is required.')
        finding = self.finding(fid)
        allowed = {aid for o in finding['occurrences'] for aid in o['evidence_ids']}
        if evidence_id and evidence_id not in allowed:
            raise ValueError('Select evidence attached to this finding.')
        if status == 'verified':
            if not evidence_id:
                raise ValueError('Verification requires captured evidence and an explanatory review note.')
            name = self.store.artifact_metadata(evidence_id)['name']
            if not name.startswith(('http-', 'cli-')):
                raise ValueError('Select captured HTTP or CLI evidence, rather than model analysis.')
        decision = {'status': status, 'severity': severity, 'confidence': confidence}
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            current = c.execute('SELECT * FROM findings WHERE id=?', (fid,)).fetchone()
            if current['revision'] != expected_revision:
                raise ReviewConflict('This finding changed. Reload it before saving your review.')
            previous = {key: current[key] for key in decision}
            c.execute('UPDATE findings SET status=?,severity=?,confidence=?,revision=revision+1 WHERE id=?',
                      (status, severity, confidence, fid))
            c.execute('INSERT INTO finding_reviews VALUES(?,?,?,?,?,?,?,?)',
                      (str(uuid.uuid4()), fid, now(), expected_revision + 1, encoded(previous), encoded(decision), note.strip(), evidence_id))
        return self.finding(fid)

    def compare(self, baseline_id, current_id):
        if baseline_id == current_id:
            raise ValueError('Select two different runs.')
        baseline, current = self.store.run(baseline_id), self.store.run(current_id)
        self.index_pending(baseline_id)
        self.index_pending(current_id)
        def grouped(c, rid):
            rows = c.execute('SELECT * FROM observations WHERE run_id=? ORDER BY fingerprint,value_hash', (rid,)).fetchall()
            if len(rows) > 10000:
                raise ValueError('Comparison is limited to 10,000 normalized observations per run.')
            result = {}
            for row in rows:
                entry = result.setdefault(row['fingerprint'], {'kind': row['kind'], 'asset': row['asset'], 'source': row['source'], 'values': {}})
                entry['values'].setdefault(row['value_hash'], {'data': json.loads(row['data']), 'evidence_ids': []})['evidence_ids'].append(row['artifact_id'])
            return result
        with self.store.connect() as c:
            before, after = grouped(c, baseline_id), grouped(c, current_id)
            run_findings = {}
            for rid in (baseline_id, current_id):
                rows = c.execute('''SELECT f.id,f.title,f.asset,f.source,x.snapshot,x.evidence_ids
                                    FROM finding_occurrences x JOIN findings f ON f.id=x.finding_id WHERE x.run_id=?''', (rid,)).fetchall()
                values = {}
                for row in rows:
                    entry = values.setdefault(row['id'], {'id': row['id'], 'title': row['title'], 'asset': row['asset'], 'source': row['source'], 'snapshots': {}})
                    snapshot = entry['snapshots'].setdefault(row['snapshot'], {'data': json.loads(row['snapshot']), 'evidence_ids': []})
                    snapshot['evidence_ids'] = sorted(set(snapshot['evidence_ids']) | set(json.loads(row['evidence_ids'])))
                run_findings[rid] = values
        changes = []
        for key in sorted(before.keys() | after.keys()):
            old, new = before.get(key), after.get(key)
            state = 'new' if old is None else 'not_observed' if new is None else 'unchanged' if old['values'].keys() == new['values'].keys() else 'changed'
            changes.append({'fingerprint': key, 'state': state, **{k: (new or old)[k] for k in ('kind', 'asset', 'source')},
                            'before': list(old['values'].values()) if old else [], 'after': list(new['values'].values()) if new else []})
        finding_changes = []
        previous, latest = run_findings[baseline_id], run_findings[current_id]
        for fid in sorted(previous.keys() | latest.keys()):
            old, new = previous.get(fid), latest.get(fid)
            state = 'new' if old is None else 'not_observed' if new is None else 'recurring' if old['snapshots'].keys() == new['snapshots'].keys() else 'changed'
            finding_changes.append({**{k: (new or old)[k] for k in ('id', 'title', 'asset', 'source')}, 'state': state,
                                    'before': list(old['snapshots'].values()) if old else [], 'after': list(new['snapshots'].values()) if new else []})
        warnings = []
        scope = lambda run: sorted(canonical_asset(t) or t for t in run['config'].get('targets', []))
        if scope(baseline) != scope(current):
            warnings.append('The entered scope differs between these runs.')
        for label, run in [('Baseline', baseline), ('Current', current)]:
            if run['status'] != 'completed':
                warnings.append(f'{label} run is {run["status"]}; its evidence may be partial.')
            if not run['config'].get('allow_http'):
                warnings.append(f'{label} run had execution disabled.')
            if any(node.get('result') and node['result'].get('errors') for node in self.store.nodes(run['id'])):
                warnings.append(f'{label} run contains node errors or blocked operations; coverage is incomplete.')
        if any(baseline['config'].get(k) != current['config'].get(k) for k in
               ('engine', 'workflow', 'ports', 'max_hosts', 'max_requests', 'max_cli_invocations')):
            warnings.append('Workflow or execution limits differ; coverage may differ.')
        with self.store.connect() as c:
            reports = c.execute('''SELECT a.run_id,a.id,a.name,i.report FROM evidence_index i JOIN artifacts a ON a.id=i.artifact_id
                                   WHERE a.run_id IN (?,?) AND i.parser_version=?''', (baseline_id, current_id, PARSER_VERSION)).fetchall()
        coverage = [{**dict(r), 'report': json.loads(r['report'])} for r in reports]
        if any(r['report'].get('partial') for r in coverage):
            warnings.append('One or more captures are truncated, partial or failed.')
        return {'baseline_id': baseline_id, 'current_id': current_id, 'warnings': warnings,
                'absence_means': 'Not observed in the selected run; this does not establish resolution or equivalent coverage.',
                'summary': {s: sum(r['state'] == s for r in changes) for s in ('new', 'changed', 'unchanged', 'not_observed')},
                'observations': changes, 'findings': finding_changes, 'coverage': coverage}
