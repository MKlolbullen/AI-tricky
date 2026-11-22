"""Prepare report inputs from stored observations and the latest operator reviews."""
import json
from urllib.parse import urlsplit

from .observations import PARSER_VERSION
from .scope import ScopeError, parse_target


def report_scope(value):
    try:
        target = parse_target(value)
    except ScopeError:
        return 'Unrecognized scope entry (withheld)'
    if target.kind != 'url':
        return target.url
    parts = urlsplit(target.url)
    return f'{parts.scheme}://{parts.netloc}' + ('/[path withheld]' if target.path != '/' else '/')


def report_inputs(evidence, run):
    rid = run['id']
    evidence.index_pending(rid)
    config = run['config']
    gaps = []
    if not config.get('allow_http'):
        gaps.append('Target execution was disabled.')
    result = run.get('result') or {}
    if result.get('coverage_limits'):
        gaps.append(f"The run recorded {len(result['coverage_limits'])} coverage limits. See the saved run for details.")
    for used, limit in [('request_count', 'max_requests'), ('cli_invocation_count', 'max_cli_invocations')]:
        if config.get(limit) and result.get(used, 0) >= config[limit]:
            gaps.append(f'The run reached {limit}.')
    with evidence.store.connect() as db:
        db.execute('BEGIN')  # Bind review IDs, decisions and citations to one SQLite snapshot.
        artifacts = {r['id'] for r in db.execute('SELECT id FROM artifacts WHERE run_id=?', (rid,))}
        nodes = {r['node_id']: r for r in db.execute('SELECT node_id,status,result FROM run_nodes WHERE run_id=?', (rid,))}
        planned = {n['id'] for n in (config.get('workflow') or {}).get('nodes', [])}
        incomplete = len(planned - nodes.keys()) + sum(
            r['status'] not in ('completed', 'reused') or bool((json.loads(r['result'] or '{}') or {}).get('errors'))
            for r in nodes.values())
        if incomplete:
            gaps.append(f'{incomplete} workflow node(s) had errors or lack a successful execution record.')
        parser_rows = db.execute(
            '''SELECT i.report FROM evidence_index i JOIN artifacts a ON a.id=i.artifact_id
               WHERE a.run_id=? AND i.parser_version=?''', (rid, PARSER_VERSION))
        parser_reports = (json.loads(row['report']) for row in parser_rows)
        partial = sum(bool(p.get('partial') or p.get('unparsed_lines')) for p in parser_reports)
        if partial:
            gaps.append(f'{partial} indexed capture(s) were partial or contained unparsed records.')
        rows = db.execute('''SELECT f.id,f.title,f.asset,f.status,f.severity,f.confidence,
                                    r.id AS review_id,r.revision,r.created,r.evidence_id,
                                    x.evidence_ids,o.observed_at
                             FROM finding_occurrences x JOIN findings f ON f.id=x.finding_id
                             JOIN observations o ON o.id=x.observation_id
                             JOIN observation_versions v ON v.observation_id=o.id AND v.parser_version=?
                             LEFT JOIN finding_reviews r ON r.finding_id=f.id AND r.revision=f.revision
                             WHERE x.run_id=? ORDER BY f.id,o.id''', (PARSER_VERSION, rid))
        findings, unreviewed = {}, set()
        for row in rows:
            fid = row['id']
            if not row['review_id']:
                unreviewed.add(fid)
                continue
            review_capture = row['evidence_id']
            if fid not in findings:
                findings[fid] = {
                    'id': fid, 'local_title': row['title'], 'local_asset': row['asset'],
                    'review': {'id': row['review_id'], 'revision': row['revision'], 'created': row['created'],
                               'status': row['status'], 'severity': row['severity'], 'confidence': row['confidence'],
                               'artifact_id': review_capture if review_capture in artifacts else None,
                               'support_outside_run': bool(review_capture and review_capture not in artifacts)},
                    'artifact_ids': set(), 'observed_after_review': False,
                }
            item = findings[fid]
            item['artifact_ids'].update(artifacts.intersection(json.loads(row['evidence_ids'])))
            item['observed_after_review'] |= row['observed_at'] > row['created']
        for item in findings.values():
            item['artifact_ids'] = sorted(item['artifact_ids'])
    return {'run_id': rid, 'completed_at': run['updated'], 'parser_version': PARSER_VERSION,
            'scope': [report_scope(t) for t in config.get('targets', [])],
            'coverage_gaps': gaps, 'unreviewed_count': len(unreviewed), 'findings': list(findings.values())}
