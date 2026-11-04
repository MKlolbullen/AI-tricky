import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Existing installations retain their database and evidence. New installations use the new brand.
        legacy = root / 'reconforge.sqlite3'
        self.db = legacy if legacy.exists() else root / 'offsecs-u-ai.sqlite3'
        with self.connect() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY, url TEXT UNIQUE NOT NULL, created TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, status TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, config TEXT NOT NULL, result TEXT);
            CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, time TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, run_id TEXT NOT NULL, name TEXT NOT NULL, content TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS workflows(id TEXT PRIMARY KEY, name TEXT NOT NULL, graph TEXT NOT NULL, revision INTEGER NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS run_nodes(run_id TEXT NOT NULL, node_id TEXT NOT NULL, status TEXT NOT NULL, updated TEXT NOT NULL, result TEXT, PRIMARY KEY(run_id,node_id));
            CREATE INDEX IF NOT EXISTS events_by_run ON events(run_id,seq);
            CREATE TABLE IF NOT EXISTS inputs(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,path TEXT NOT NULL,sha256 TEXT,created TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS verification_runs(run_id TEXT PRIMARY KEY,execution_id TEXT NOT NULL,finding_id TEXT,profile_id TEXT NOT NULL,created TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS verification_by_finding ON verification_runs(finding_id,created);
            ''')
            if 'node_id' not in {r['name'] for r in c.execute('PRAGMA table_info(artifacts)')}:
                c.execute('ALTER TABLE artifacts ADD COLUMN node_id TEXT')
            if 'captured_at' not in {r['name'] for r in c.execute('PRAGMA table_info(artifacts)')}:
                c.execute('ALTER TABLE artifacts ADD COLUMN captured_at TEXT')
            # A process restart cannot revive prior in-memory tasks.
            c.execute("UPDATE runs SET status='interrupted',updated=? WHERE status IN ('queued','running','paused')", (now(),))
            c.execute("UPDATE run_nodes SET status='interrupted',updated=? WHERE status IN ('queued','running')", (now(),))
        os.chmod(self.db, 0o600)
        (self.root/'jobs').mkdir(exist_ok=True,mode=0o700)
        (self.root/'inputs').mkdir(exist_ok=True,mode=0o700)

    def connect(self):
        c = sqlite3.connect(self.db, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def targets(self):
        with self.connect() as c:
            return [dict(r) for r in c.execute('SELECT * FROM targets ORDER BY created DESC')]

    def add_target(self, url):
        with self.connect() as c:
            c.execute('INSERT OR IGNORE INTO targets VALUES(?,?,?)', (str(uuid.uuid4()), url, now()))
        return next(t for t in self.targets() if t['url'] == url)

    def new_run(self, config, *, connection=None):
        rid = str(uuid.uuid4())
        created = now()
        values = (rid, 'queued', created, created, json.dumps(config), None)
        if connection is not None:
            connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?)', values)
        else:
            with self.connect() as c:
                c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?)', values)
        return {'id': rid, 'status': 'queued', 'created': created, 'updated': created, 'config': config, 'result': None}

    def run(self, rid):
        with self.connect() as c:
            row = c.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone()
        if row is None:
            raise KeyError(rid)
        r = dict(row)
        r['config'] = json.loads(r['config'])
        r['result'] = json.loads(r['result']) if r['result'] else None
        return r

    def runs(self):
        with self.connect() as c:
            ids = [r['id'] for r in c.execute('SELECT id FROM runs ORDER BY created DESC LIMIT 100')]
        return [self.run(rid) for rid in ids]

    def status(self, rid, status, result=None):
        with self.connect() as c:
            c.execute('UPDATE runs SET status=?, updated=?, result=COALESCE(?,result) WHERE id=?', (status, now(), json.dumps(result) if result is not None else None, rid))

    def event(self, rid, kind, data):
        with self.connect() as c:
            c.execute('INSERT INTO events(run_id,time,kind,data) VALUES(?,?,?,?)', (rid, now(), kind, json.dumps(data)))

    def events(self, rid, after=0, limit=500):
        with self.connect() as c:
            rows = c.execute('SELECT * FROM events WHERE run_id=? AND seq>? ORDER BY seq LIMIT ?', (rid, after, min(limit,10000)))
            return [{**dict(r), 'data': json.loads(r['data'])} for r in rows]

    def artifact(self, rid, name, content, node_id=None):
        aid = str(uuid.uuid4())
        with self.connect() as c:
            c.execute('INSERT INTO artifacts(id,run_id,name,content,node_id,captured_at) VALUES(?,?,?,?,?,?)', (aid, rid, name, json.dumps(content), node_id, now()))
        return aid

    def artifacts(self, rid):
        with self.connect() as c:
            return [dict(r) for r in c.execute('SELECT id,run_id,name,node_id FROM artifacts WHERE run_id=? ORDER BY rowid', (rid,))]

    def content(self, aid):
        with self.connect() as c:
            row = c.execute('SELECT content FROM artifacts WHERE id=?', (aid,)).fetchone()
        if row is None:
            raise KeyError(aid)
        return json.loads(row['content'])

    def node_status(self, rid, nid, status, result=None):
        with self.connect() as c:
            c.execute('INSERT INTO run_nodes VALUES(?,?,?,?,?) ON CONFLICT(run_id,node_id) DO UPDATE SET status=excluded.status,updated=excluded.updated,result=excluded.result',
                      (rid, nid, status, now(), json.dumps(result) if result is not None else None))

    def nodes(self, rid):
        with self.connect() as c:
            return [{**dict(r), 'result': json.loads(r['result']) if r['result'] else None} for r in c.execute('SELECT * FROM run_nodes WHERE run_id=? ORDER BY rowid', (rid,))]

    def workflows(self):
        with self.connect() as c:
            return [dict(r) for r in c.execute('SELECT id,name,revision,created,updated FROM workflows ORDER BY updated DESC')]

    def workflow(self, wid):
        with self.connect() as c:
            row = c.execute('SELECT * FROM workflows WHERE id=?', (wid,)).fetchone()
        if row is None:
            raise KeyError(wid)
        return {**dict(row), 'graph': json.loads(row['graph'])}

    def save_workflow(self, name, graph, wid=None, expected_revision=None):
        with self.connect() as c:
            if wid:
                updated = c.execute('UPDATE workflows SET name=?,graph=?,revision=revision+1,updated=? WHERE id=? AND revision=?',
                                    (name, json.dumps(graph), now(), wid, expected_revision))
                if updated.rowcount != 1:
                    raise ValueError('Workflow changed or was removed. Load the current version before saving.')
            else:
                wid = str(uuid.uuid4())
                c.execute('INSERT INTO workflows VALUES(?,?,?,?,?,?)', (wid, name, json.dumps(graph), 1, now(), now()))
        return self.workflow(wid)

    def add_input(self,name,kind,path,sha256=None):
        identifier=str(uuid.uuid4())
        with self.connect() as c:
            c.execute('INSERT INTO inputs VALUES(?,?,?,?,?,?)',(identifier,name,kind,str(path),sha256,now()))
        return self.input(identifier)

    def input(self,identifier):
        with self.connect() as c:
            row=c.execute('SELECT * FROM inputs WHERE id=?',(identifier,)).fetchone()
        if row is None:raise KeyError(identifier)
        return dict(row)

    def inputs(self):
        with self.connect() as c:
            return [dict(r) for r in c.execute('SELECT * FROM inputs ORDER BY created DESC')]

    def artifact_metadata(self,aid):
        with self.connect() as c:
            row=c.execute('SELECT id,run_id,name,node_id,captured_at FROM artifacts WHERE id=?',(aid,)).fetchone()
        if row is None:raise KeyError(aid)
        return dict(row)
