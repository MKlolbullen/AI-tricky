"""Disposable browser data; execution tests contact only the loopback fixture."""
import json
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading

import uvicorn
from fastapi.routing import APIRoute

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from backend.app import create_app
from backend.store import Store, now
from backend.proposals import ProposalPlanner
from backend.team import run_team
from backend.model_usage import ModelUsage, TOKEN_FIELDS


def seed(store, fixture_url):
    target = store.add_target(fixture_url + '/')
    surface_run = store.new_run({'engine': 'workflow', 'targets': [fixture_url + '/'], 'workflow': {'nodes': [
        {'id': 'qa-web-source', 'data': {'kind': 'native_web_assets'}},
    ]}})['id']
    bundle = fixture_url + '/app.js'
    capture = store.artifact(surface_run, 'http-1.json', {'url': bundle, 'body': "fetch('/api/users?sort=asc');"}, node_id='qa-web-source')
    source_output = store.artifact(surface_run, 'node-qa-web-source.json', [{'manifest': [
        {'url': bundle, 'kind': 'js', 'status': 200, 'artifact_id': capture},
    ]}], node_id='qa-web-source')
    store.node_status(surface_run, 'qa-web-source', 'completed', {'artifact_id': source_output, 'records': 1})
    store.status(surface_run, 'completed', {'report': 'Saved API Surface fixture.'})
    # Interrupted workflow fixture: only the selected recovery dispatch will
    # contact the loopback HTTP server. Seeding/previewing has no target access.
    from backend.workflows import REGISTRY
    kinds = ['native_scope', 'native_http', 'native_summary']
    titles = ['Saved scope', 'HTTP retry', 'Recovery summary']
    recovery_graph = {'schema': 'offsecs-u-ai.workflow/v1', 'nodes': [
        {'id': f'r{i}', 'type': 'tool', 'position': {'x': i * 230, 'y': 0},
         'data': {'kind': kind, 'title': titles[i], 'inputs': REGISTRY[kind]['inputs'],
                  'output': REGISTRY[kind]['output'], 'timeout': 30, 'retries': 0}}
        for i, kind in enumerate(kinds)], 'edges': [
            {'id': f're{i}', 'source': f'r{i}', 'target': f'r{i+1}'} for i in range(2)]}
    recovery_config = {'engine': 'workflow', 'allow_http': True, 'workflow': recovery_graph,
                       'targets': [fixture_url + '/'], 'target_ids': [target['id']], 'goal': 'Recovery browser fixture',
                       'max_requests': 1, 'max_cli_invocations': 1, 'max_hosts': 1, 'max_seconds': 30,
                       'parallelism': 1, 'ports': [80], 'allow_cli': False, 'cli_credential_keys': []}
    with store.connect() as c:
        c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?)', ('qa-recovery', 'failed', now(), now(), json.dumps(recovery_config), None))
    checkpoint = store.artifact('qa-recovery', 'node-r0.json', [{'target': fixture_url + '/', 'kind': 'url'}], node_id='r0')
    store.node_status('qa-recovery', 'r0', 'completed', {'artifact_id': checkpoint, 'records': 1, 'errors': 0})
    store.node_status('qa-recovery', 'r1', 'failed', {'error': 'Interrupted fixture capture'})
    store.node_status('qa-recovery', 'r2', 'skipped', {'reason': 'Upstream capture interrupted'})
    async def fixture_analyst(*args, **kwargs):
        return {'report': 'Browser fixture candidate review; no model or target access.'}
    # A staged-team result from the real coordinator, with captured synthetic
    # evidence and injected JSON reports. No provider or target call is made.
    specialist_config={'engine':'team','team_profile':'specialist','targets':[fixture_url+'/'],
                       'max_requests':1,'max_cli_invocations':0}
    with store.connect() as c:
        c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?)',('qa-specialists','completed',now(),now(),json.dumps(specialist_config),None))
    capture={'url':fixture_url+'/','status':200,'body':'Previously captured browser fixture','headers':{}}
    evidence_id=store.artifact('qa-specialists','http-1.json',capture)
    async def specialist_fixture(*args,**kwargs):
        from backend.team import ROLES
        role=next(k for k,v in ROLES.items() if v['focus']==kwargs['role_instructions'])
        body={'summary':'Fixture review','coverage_limits':[],**({'validations':[]} if role=='poc' else {'candidates':[]})}
        return {'report':json.dumps(body),'model':'fixture-model','model_attempts':[
            {'provider':'local','model':'fixture-model','max_turns':8,'status':'completed','fallback':False}]}
    specialist_result=asyncio.run(run_team([fixture_url+'/'],'Review recorded evidence',None,None,specialist_fixture,
        profile='specialist',evidence=[{**capture,'artifact_id':evidence_id}],
        on_handoff=lambda packet:store.artifact('qa-specialists','handoff-'+packet['recipient']+'.json',packet),
        on_member=lambda member:store.artifact('qa-specialists','member-'+member['role']+'.json',member)))
    store.status('qa-specialists','completed',specialist_result)
    # Real deterministic coordinator output, with injected evidence-only fixture
    # analysts. Seed before the existing runs so comparison defaults stay stable.
    budget_result = asyncio.run(run_team([], 'Fixture review', None, None, fixture_analyst, team_max_turns=2))
    budget_config = {'engine': 'team', 'targets': [fixture_url + '/'], 'max_requests': 1, 'team_max_turns': 2}
    with store.connect() as c:
        c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?)', ('qa-team-budget', 'completed', now(), now(),
                  json.dumps(budget_config), json.dumps(budget_result)))
    fixture_config = {'targets': [fixture_url + '/'], 'engine': 'inventory', 'allow_http': True,
                      'goal': 'Loopback proposal execution fixture', 'max_requests': 1,
                      'max_cli_invocations': 1, 'ports': [80], 'max_hosts': 1}
    with store.connect() as c:
        c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?)', ('qa-execution', 'completed', now(), now(), json.dumps(fixture_config), None))
    store.artifact('qa-execution', 'http-1.json', {'url': fixture_url + '/approved', 'status': 200,
                                               'body': 'Recorded loopback fixture', 'headers': {}})
    store.artifact('qa-execution', 'cli-1-nuclei.json', {'tool_id': 'nuclei', 'exit_code': 0,
        'stdout': json.dumps({'template-id': 'qa-verification-candidate', 'matched-at': fixture_url + '/approved',
                              'info': {'name': 'Verification fixture candidate', 'severity': 'medium'}})})
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
    # Metadata fixtures only: no provider request is made by this seed.
    usage = ModelUsage(store)
    usage.start_run('qa-current')
    identifier = usage.begin(run_id='qa-current', purpose='workflow_analysis', node_id='qa-analysis',
                             role='analyst', provider='local', model='local-usage-fixture', execution_mode='fixture')
    usage.record(identifier, {'phase': 'started', 'sequence': 1})
    usage.record(identifier, {'phase': 'response', 'sequence': 1,
                              'tokens': dict(zip(TOKEN_FIELDS, (100, 25, 125, 40, 5)))})
    usage.record(identifier, {'phase': 'started', 'sequence': 2})
    usage.record(identifier, {'phase': 'response', 'sequence': 2, 'tokens': {key: None for key in TOKEN_FIELDS}})
    usage.finish(identifier, 'completed')


if __name__ == '__main__':
    class FixtureHandler(BaseHTTPRequestHandler):
        calls = []
        def do_GET(self):
            self.calls.append({'path': self.path, 'origin': self.headers.get('Origin'),
                               'cookie': bool(self.headers.get('Cookie')), 'authorization': bool(self.headers.get('Authorization'))})
            token = self.headers.get('Authorization')
            if self.path in ('/approved', '/control') and token in ('Bearer qa-owner-token', 'Bearer qa-other-token'):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Set-Cookie', 'fixture=' + token)
                self.end_headers()
                self.wfile.write(json.dumps({'id': 'owner' if self.path == '/approved' else 'control'}).encode())
                return
            self.send_response(200); self.send_header('Content-Type', 'text/plain')
            if self.headers.get('Origin'):
                self.send_header('Access-Control-Allow-Origin', self.headers['Origin'])
                self.send_header('Access-Control-Allow-Credentials', 'true')
            self.end_headers()
            self.wfile.write(b'Approved loopback browser execution fixture')
        def log_message(self, *args):
            pass
    fixture = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='ai-tricky-browser-') as directory:
        store = Store(Path(directory))
        fixture_url = f'http://127.0.0.1:{fixture.server_port}'
        seed(store, fixture_url)
        app = create_app(directory)
        def reset_fixture():
            # Test-only route: every browser case gets fresh evidence, approvals and run IDs.
            with store.connect() as c:
                tables = [r['name'] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
                for table in tables:
                    c.execute('DELETE FROM "' + table + '"')
            seed(store, fixture_url)
            FixtureHandler.calls.clear()
            return {'reset': True}
        app.router.routes.insert(0, APIRoute('/api/_qa/reset', reset_fixture, methods=['POST']))
        app.router.routes.insert(0, APIRoute('/api/_qa/target-calls', lambda: FixtureHandler.calls, methods=['GET']))
        try:
            uvicorn.run(app, host='127.0.0.1', port=8787, access_log=False)
        finally:
            fixture.shutdown(); fixture.server_close()
