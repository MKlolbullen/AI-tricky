"""Deterministic asset / attack-surface graph built from captured artifacts.

Typed entities (hosts, IPs, services, technologies, files) and typed edges
(subdomain_of, resolves_to, exposes, runs, serves) are derived by extractors
from append-only capture artifacts, provenance-bound to the artifact(s) that
asserted them and versioned like observations. The graph records observed facts
only — never findings, never model assertions, and it initiates no target
traffic. An asset the graph stops observing is "not observed", never resolved.

v1 extracts from native captures (`http-*.json`, `tcp-inventory.json`). CLI and
passive-source extraction, and netblock/certificate/bucket entities, are later
layers (see docs/design/evidence-asset-graph.md).
"""
import json
import uuid
from urllib.parse import urlsplit

from .observations import canonical_asset, digest, encoded
from .store import now

GRAPH_VERSION = '1'
ENTITY_KINDS = frozenset({'host', 'ip', 'service', 'technology', 'file'})
EDGE_RELS = frozenset({'subdomain_of', 'resolves_to', 'exposes', 'runs', 'serves'})
_DEFAULT_PORT = {'http': 80, 'https': 443}


def _host(value):
    """Canonical hostname/IP for a bare host value, or None."""
    return canonical_asset(value) if isinstance(value, str) and '://' not in value else None


def _parent_host(host):
    """PSL-free parent: strip the leftmost label while at least two labels remain.
    Stops at a two-label apex, so api.example.com -> example.com -> (none)."""
    if ':' in host or host.replace('.', '').isdigit():  # IP, not a domain
        return None
    return host.split('.', 1)[1] if host.count('.') >= 2 else None


def _technologies(capture):
    """Deterministic technology strings from a capture's headers and fields."""
    out = []
    headers = capture.get('headers') if isinstance(capture.get('headers'), dict) else {}
    lower = {str(k).lower(): v for k, v in headers.items()}
    for key in ('server', 'x-powered-by'):
        value = lower.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip()[:120])
    for field in ('webserver',):
        value = capture.get(field)
        if isinstance(value, str) and value.strip():
            out.append(value.strip()[:120])
    tech = capture.get('tech')
    if isinstance(tech, str) and tech.strip():
        out.append(tech.strip()[:120])
    elif isinstance(tech, list):
        out.extend(str(t).strip()[:120] for t in tech if isinstance(t, str) and t.strip())
    # Case-insensitive de-duplication, preserving first spelling seen.
    seen, unique = set(), []
    for value in out:
        if value.lower() not in seen:
            seen.add(value.lower())
            unique.append(value)
    return unique


class AssetGraph:
    def __init__(self, store):
        self.store = store
        with store.connect() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS assets(
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, canonical TEXT NOT NULL,
                data TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                UNIQUE(kind, canonical));
            CREATE INDEX IF NOT EXISTS assets_by_kind ON assets(kind);
            CREATE TABLE IF NOT EXISTS asset_edges(
                id TEXT PRIMARY KEY, rel TEXT NOT NULL, src_id TEXT NOT NULL, dst_id TEXT NOT NULL,
                source TEXT NOT NULL, fingerprint TEXT UNIQUE NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS edges_by_src ON asset_edges(src_id);
            CREATE INDEX IF NOT EXISTS edges_by_dst ON asset_edges(dst_id);
            CREATE TABLE IF NOT EXISTS asset_provenance(
                ref_id TEXT NOT NULL, artifact_id TEXT NOT NULL, run_id TEXT NOT NULL,
                graph_version TEXT NOT NULL, observed_at TEXT NOT NULL,
                PRIMARY KEY(ref_id, artifact_id, graph_version));
            CREATE INDEX IF NOT EXISTS provenance_by_artifact ON asset_provenance(artifact_id, graph_version);
            CREATE INDEX IF NOT EXISTS provenance_by_run ON asset_provenance(run_id);
            CREATE TABLE IF NOT EXISTS graph_index(
                artifact_id TEXT NOT NULL, graph_version TEXT NOT NULL,
                PRIMARY KEY(artifact_id, graph_version));
            ''')

    # -- indexing -------------------------------------------------------------
    def index_pending(self, run_id=None):
        with self.store.connect() as c:
            query = '''SELECT a.id,a.run_id,a.name,COALESCE(a.captured_at,r.created) AS observed_at
                       FROM artifacts a JOIN runs r ON r.id=a.run_id
                       LEFT JOIN graph_index g ON g.artifact_id=a.id AND g.graph_version=?
                       WHERE g.artifact_id IS NULL'''
            args = [GRAPH_VERSION]
            if run_id:
                query += ' AND a.run_id=?'
                args.append(run_id)
            pending = c.execute(query + ' ORDER BY r.created,a.rowid', args).fetchall()
        for artifact in pending:
            with self.store.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                if c.execute('SELECT 1 FROM graph_index WHERE artifact_id=? AND graph_version=?',
                             (artifact['id'], GRAPH_VERSION)).fetchone():
                    continue
                name = artifact['name']
                eligible = name == 'tcp-inventory.json' or (name.startswith('http-') and name.endswith('.json'))
                content = json.loads(c.execute('SELECT content FROM artifacts WHERE id=?', (artifact['id'],)).fetchone()['content']) if eligible else None
                refs = set()
                ctx = {'c': c, 'run_id': artifact['run_id'], 'artifact_id': artifact['id'],
                       'observed_at': artifact['observed_at'], 'refs': refs}
                try:
                    if name == 'tcp-inventory.json' and isinstance(content, list):
                        self._extract_tcp(ctx, content)
                    elif eligible and isinstance(content, dict):
                        self._extract_http(ctx, content)
                finally:
                    for ref in refs:
                        c.execute('INSERT OR IGNORE INTO asset_provenance VALUES(?,?,?,?,?)',
                                  (ref, artifact['id'], artifact['run_id'], GRAPH_VERSION, artifact['observed_at']))
                    c.execute('INSERT INTO graph_index VALUES(?,?)', (artifact['id'], GRAPH_VERSION))

    def _entity(self, ctx, kind, canonical, data):
        c, at = ctx['c'], ctx['observed_at']
        c.execute('INSERT OR IGNORE INTO assets VALUES(?,?,?,?,?,?)', (str(uuid.uuid4()), kind, canonical, encoded(data), at, at))
        eid = c.execute('SELECT id FROM assets WHERE kind=? AND canonical=?', (kind, canonical)).fetchone()['id']
        c.execute('UPDATE assets SET first_seen=MIN(first_seen,?),last_seen=MAX(last_seen,?) WHERE id=?', (at, at, eid))
        ctx['refs'].add(eid)
        return eid

    def _edge(self, ctx, rel, src_id, dst_id, source):
        c, at = ctx['c'], ctx['observed_at']
        fp = digest([rel, src_id, dst_id, source])
        c.execute('INSERT OR IGNORE INTO asset_edges VALUES(?,?,?,?,?,?,?,?)', (str(uuid.uuid4()), rel, src_id, dst_id, source, fp, at, at))
        edge = c.execute('SELECT id FROM asset_edges WHERE fingerprint=?', (fp,)).fetchone()['id']
        c.execute('UPDATE asset_edges SET last_seen=MAX(last_seen,?) WHERE id=?', (at, edge))
        ctx['refs'].add(edge)
        return edge

    def _host_tree(self, ctx, host, source):
        """Create the host entity and its subdomain_of chain to the apex."""
        hid = self._entity(ctx, 'host', host, {'host': host})
        parent = _parent_host(host)
        if parent:
            pid = self._host_tree(ctx, parent, source)
            self._edge(ctx, 'subdomain_of', hid, pid, source)
        return hid

    def _extract_http(self, ctx, capture, source='scoped-http'):
        url = capture.get('url')
        if not isinstance(url, str) or '://' not in url:
            return
        parts = urlsplit(url)
        host = _host(parts.hostname) if parts.hostname else None
        if host is None:
            return
        hid = self._host_tree(ctx, host, source)
        port = parts.port or _DEFAULT_PORT.get(parts.scheme.lower())
        if port:
            sid = self._entity(ctx, 'service', f'{host}:{port}/tcp', {'host': host, 'port': port, 'transport': 'tcp', 'state': 'open'})
            self._edge(ctx, 'exposes', hid, sid, source)
        ip = capture.get('connected_ip')
        if isinstance(ip, str):
            cip = _host(ip)
            if cip and (':' in cip or cip.replace('.', '').isdigit()):
                iid = self._entity(ctx, 'ip', cip, {'ip': cip})
                self._edge(ctx, 'resolves_to', hid, iid, source)
        canonical_url = canonical_asset(url)
        if canonical_url:
            data = {'url': canonical_url, 'host': host, 'path': parts.path or '/'}
            if isinstance(capture.get('status'), int):
                data['status'] = capture['status']
            fid = self._entity(ctx, 'file', canonical_url, data)
            self._edge(ctx, 'serves', hid, fid, source)
        for tech in _technologies(capture):
            tid = self._entity(ctx, 'technology', tech.lower(), {'name': tech})
            self._edge(ctx, 'runs', hid, tid, source)

    def _extract_tcp(self, ctx, rows, source='native-tcp'):
        for row in rows:
            if not isinstance(row, dict) or row.get('state') != 'open':
                continue
            host = _host(row.get('host'))
            if host is None:
                continue
            hid = self._host_tree(ctx, host, source)
            port = row.get('port')
            if isinstance(port, int) and 1 <= port <= 65535:
                sid = self._entity(ctx, 'service', f'{host}:{port}/tcp', {'host': host, 'port': port, 'transport': 'tcp', 'state': 'open'})
                self._edge(ctx, 'exposes', hid, sid, source)
            ip = _host(row.get('ip'))
            if ip and (':' in ip or ip.replace('.', '').isdigit()):
                iid = self._entity(ctx, 'ip', ip, {'ip': ip})
                self._edge(ctx, 'resolves_to', hid, iid, source)

    # -- reads ----------------------------------------------------------------
    def graph(self, *, run_id=None, kind=None, q='', limit=500):
        self.index_pending(run_id)
        where, args = ['1=1'], []
        if run_id:
            where.append('a.id IN (SELECT ref_id FROM asset_provenance WHERE run_id=?)')
            args.append(run_id)
        if kind in ENTITY_KINDS:
            where.append('a.kind=?')
            args.append(kind)
        if q:
            where.append('instr(lower(a.canonical),lower(?))>0')
            args.append(q)
        with self.store.connect() as c:
            clause = ' FROM assets a WHERE ' + ' AND '.join(where)
            total = c.execute('SELECT COUNT(*)' + clause, args).fetchone()[0]
            rows = c.execute('SELECT a.*' + clause + ' ORDER BY a.kind,a.canonical LIMIT ?', [*args, limit]).fetchall()
            entities = [{'id': r['id'], 'kind': r['kind'], 'canonical': r['canonical'],
                         'data': json.loads(r['data']), 'first_seen': r['first_seen'], 'last_seen': r['last_seen']} for r in rows]
            ids = {e['id'] for e in entities}
            edges = []
            if ids:
                placeholders = ','.join('?' * len(ids))
                for e in c.execute(f'SELECT * FROM asset_edges WHERE src_id IN ({placeholders}) AND dst_id IN ({placeholders})', [*ids, *ids]):
                    edges.append({'id': e['id'], 'rel': e['rel'], 'src_id': e['src_id'], 'dst_id': e['dst_id'],
                                  'source': e['source'], 'last_seen': e['last_seen']})
        return {'entities': entities, 'edges': edges, 'total': total, 'limit': limit,
                'absence_means': 'Not observed in the selected scope; this does not establish resolution or coverage.'}

    def entity(self, asset_id):
        self.index_pending()
        with self.store.connect() as c:
            row = c.execute('SELECT * FROM assets WHERE id=?', (asset_id,)).fetchone()
            if row is None:
                raise KeyError(asset_id)
            neighbours = c.execute('''SELECT e.*, s.kind AS src_kind, s.canonical AS src_canonical,
                                      d.kind AS dst_kind, d.canonical AS dst_canonical
                                      FROM asset_edges e JOIN assets s ON s.id=e.src_id JOIN assets d ON d.id=e.dst_id
                                      WHERE e.src_id=? OR e.dst_id=?''', (asset_id, asset_id)).fetchall()
            provenance = c.execute('''SELECT artifact_id,run_id,observed_at FROM asset_provenance
                                      WHERE ref_id=? ORDER BY observed_at DESC''', (asset_id,)).fetchall()
        return {'id': row['id'], 'kind': row['kind'], 'canonical': row['canonical'], 'data': json.loads(row['data']),
                'first_seen': row['first_seen'], 'last_seen': row['last_seen'],
                'edges': [{'id': e['id'], 'rel': e['rel'], 'direction': 'out' if e['src_id'] == asset_id else 'in',
                           'source': e['source'], 'other_id': e['dst_id'] if e['src_id'] == asset_id else e['src_id'],
                           'other_kind': e['dst_kind'] if e['src_id'] == asset_id else e['src_kind'],
                           'other_canonical': e['dst_canonical'] if e['src_id'] == asset_id else e['src_canonical']} for e in neighbours],
                'provenance': [dict(p) for p in provenance]}
