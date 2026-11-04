"""Disposable browser-test data. This server never dispatches target traffic."""
import json
from pathlib import Path
import sys
import tempfile

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from backend.app import create_app
from backend.store import Store, now
from backend.proposals import ProposalPlanner


def seed(store):
    config = {'targets': ['https://example.invalid/'], 'engine': 'inventory', 'allow_http': True,
              'goal': 'Automated browser QA fixtures; no target requests', 'max_requests': 256,
              'max_cli_invocations': 64, 'ports': [443], 'max_hosts': 1}
    for rid in ('qa-baseline', 'qa-current'):
        with store.connect() as c:
            c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?)', (rid, 'completed', now(), now(), json.dumps(config), None))
        detections = [{'template-id': f'qa-rule-{i:02}', 'matched-at': f'https://example.invalid/{i}',
                       'info': {'name': f'QA finding {i:02}', 'severity': 'high'}} for i in range(51)]
        store.artifact(rid, 'cli-1-nuclei.json', {'tool_id': 'nuclei', 'exit_code': 0,
                       'stdout': '\n'.join(json.dumps(d) for d in detections)}, node_id='scanner')
        store.artifact(rid, 'scanner/report.json', {'encoding': 'base64', 'bytes': 'Zml4dHVyZQ=='})
    aid = store.artifact('qa-current', 'http-1.json', {'url': 'https://example.invalid/api', 'status': 200,
                                                    'body': 'Browser QA evidence', 'headers': {}}, node_id='http')
    store.artifact('qa-current', 'node-analysis.json', [{'analysis': {'candidates': [
        {'title': 'Potential API issue', 'severity': 'medium', 'rationale': 'Browser QA candidate',
         'next_test': 'Inspect captured response', 'evidence_ids': [aid]}]}}], node_id='analysis')
    planner = ProposalPlanner(store)
    oid = planner.evidence.observations(run_id='qa-current', kind='http')['items'][0]['id']
    stale = planner.save('Stale fixture plan from an earlier catalog', planner.context('qa-current', [oid], 'Review captured HTTP'))
    with store.connect() as c:
        row = c.execute('SELECT context FROM agent_plans WHERE id=?', (stale['id'],)).fetchone()
        context = json.loads(row['context']); context['catalog_hash'] = 'previous-catalog-fixture'
        c.execute('UPDATE agent_plans SET context=? WHERE id=?', (json.dumps(context), stale['id']))


if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='ai-tricky-browser-') as directory:
        store = Store(Path(directory))
        seed(store)
        uvicorn.run(create_app(directory), host='127.0.0.1', port=8787, access_log=False)
