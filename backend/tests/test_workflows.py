import asyncio
import copy
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.intelligence import analysis_goal, plan_workflow, validate_analysis
from backend.scope import ScopeError
from backend.store import Store
from backend.workflows import REGISTRY, SCHEMA, validate_workflow
from backend.tests.test_local import target_server, wait_done


def graph(*kinds):
    nodes = [{'id': f'n{i}', 'type': 'tool', 'position': {'x': i*230, 'y': 0}, 'data': {'kind': k, 'title': REGISTRY[k]['name'], 'inputs': REGISTRY[k]['inputs'], 'output': REGISTRY[k]['output'], 'timeout': 120, 'retries': 0}} for i,k in enumerate(kinds)]
    return {'schema': SCHEMA, 'nodes': nodes, 'edges': [{'id': f'e{i}', 'source': nodes[i]['id'], 'target': nodes[i+1]['id']} for i in range(len(nodes)-1)]}


def launch(c, base, g, **kwargs):
    tid = c.post('/api/targets', json={'value': base}).json()['id']
    return c.post('/api/runs', json={'engine': 'workflow', 'workflow': g, 'target_ids': [tid], 'allow_http': True, **kwargs})


def test_native_dag_real_http_and_node_provenance(tmp_path, target_server):
    base, handler = target_server
    g = graph('native_scope','native_tcp','native_http','native_summary')
    with TestClient(create_app(tmp_path)) as c:
        response = launch(c,base+'/redirect',g)
        assert response.status_code == 201, response.text
        rid = response.json()['id']
        done = wait_done(c,rid)
        assert done['status'] == 'completed', done
        assert handler.calls == ['/redirect']
        assert done['result']['request_count'] == 1  # URL-only TCP node passes through, no port enumeration.
        nodes = c.get(f'/api/runs/{rid}/nodes').json()
        assert [n['status'] for n in nodes] == ['completed']*4
        evidence = [a for a in c.get(f'/api/runs/{rid}/artifacts').json() if a['name']=='http-1.json'][0]
        assert evidence['node_id'] == 'n2'
        assert c.get('/api/artifacts/'+evidence['id']).json()['status'] == 302
        observations = c.get('/api/artifacts/'+nodes[2]['result']['artifact_id']).json()
        assert observations[0]['artifact_id'] == evidence['id']
        events = c.get(f'/api/runs/{rid}/events').json()
        assert next(e for e in events if e['kind']=='http.admitted')['data']['node_id']=='n2'


def test_plan_does_not_call_network_or_model(tmp_path, target_server):
    base, handler = target_server
    async def unavailable(*args):
        raise AssertionError('Planning must not call the model')
    with TestClient(create_app(tmp_path,assessor=unavailable)) as c:
        r = launch(c,base,graph('native_scope','native_http','native_cai','native_summary'),allow_http=False)
        assert r.status_code==201,r.text
        rid=r.json()['id']
        done=wait_done(c,rid)
        assert done['result']['evidence_status']=='PLAN'
        assert done['result']['request_count']==0
        assert not handler.calls
        assert {n['status'] for n in c.get(f'/api/runs/{rid}/nodes').json()} == {'planned'}


def test_parallel_branches_share_budget_and_no_duplicate_operation_ids(tmp_path,target_server):
    base,handler=target_server
    g=graph('native_scope','native_http','native_summary')
    extra=copy.deepcopy(g['nodes'][1]);extra['id']='branch';g['nodes'].append(extra)
    g['edges'] += [{'id':'branch-in','source':'n0','target':'branch'},{'id':'branch-out','source':'branch','target':'n2'}]
    with TestClient(create_app(tmp_path)) as c:
        response=launch(c,base,g,max_requests=1,parallelism=4)
        rid=response.json()['id'];done=wait_done(c,rid)
        assert done['status']=='completed'
        assert done['result']['request_count']==1
        assert len(handler.calls)==1
        events=c.get(f'/api/runs/{rid}/events').json()
        assert [e['data']['request_number'] for e in events if e['kind']=='http.admitted']==[1]
        assert sum(n['result'].get('errors',0) for n in c.get(f'/api/runs/{rid}/nodes').json())>=1


def test_workflow_revision_conflict_and_run_snapshot(tmp_path,target_server):
    base,_=target_server
    g=graph('native_scope','native_http')
    with TestClient(create_app(tmp_path)) as c:
        saved=c.post('/api/workflows',json={'name':'Original','graph':g}).json()
        rid=launch(c,base,g).json()['id'];wait_done(c,rid)
        edited=copy.deepcopy(g);edited['nodes'][1]['data']['title']='Edited after launch'
        body={'id':saved['id'],'expected_revision':1,'name':'Edited','graph':edited}
        assert c.post('/api/workflows',json=body).json()['revision']==2
        assert c.post('/api/workflows',json=body).status_code==409
        assert c.get(f'/api/runs/{rid}').json()['config']['workflow']['nodes'][1]['data']['title']=='HTTP evidence'
    with TestClient(create_app(tmp_path)) as c:
        assert c.get('/api/workflows/'+saved['id']).json()['revision']==2
        assert c.get(f'/api/runs/{rid}/nodes').json()[1]['status']=='completed'


@pytest.mark.parametrize('change',[
    lambda g:g['nodes'][1]['data'].update(kind='shell'),
    lambda g:g['nodes'][1]['data'].update(output='findings'),
    lambda g:g['nodes'][1]['data'].update(inputs=['anything']),
    lambda g:g['nodes'][1]['data'].update(retries=1),
    lambda g:g['nodes'][1].update(id='../path'),
    lambda g:g['nodes'][1].update(position={'x':float('inf'),'y':0}),
    lambda g:g['edges'].append({'id':'bad','source':'unknown','target':'n1'}),
    lambda g:g['edges'].append({'id':'duplicate','source':'n0','target':'n1'}),
    lambda g:g.update(edges=[]),
    lambda g:g['edges'].append({'id':'cycle','source':'n1','target':'n0'}),
])
def test_live_validation_rejects_invalid_or_unimplemented_graphs(change):
    g=graph('native_scope','native_http');change(g)
    with pytest.raises(ScopeError): validate_workflow(g,live=True)


def test_all_existing_catalog_graphs_can_be_saved():
    from backend.workflows import ROOT
    for w in json.loads((ROOT/'src/templates.json').read_text())['workflows']:
        validate_workflow({'schema':SCHEMA,'nodes':w['nodes'],'edges':w['edges']})


def test_structured_analysis_cites_only_upstream_evidence(tmp_path,target_server):
    base,handler=target_server
    async def analyst(targets,goal,fetch):
        assert not targets
        assert (await fetch('https://outside.invalid'))['error'].startswith('Evidence-only')
        evidence=json.loads(goal[goal.rfind('\n')+1:])['evidence'][0]
        assert evidence['body']=='local test evidence'
        return {'report':json.dumps({'summary':'Review complete','candidates':[{'title':'Review response','severity':'info','rationale':'Captured response supports manual review','evidence_ids':[evidence['artifact_id']],'next_test':'Compare authorized responses under two test identities.'}],'coverage_limits':['Only one unauthenticated response.']})}
    with TestClient(create_app(tmp_path,assessor=analyst)) as c:
        rid=launch(c,base,graph('native_scope','native_http','native_cai','native_summary')).json()['id']
        done=wait_done(c,rid)
        assert done['status']=='completed',done
        nodes=c.get(f'/api/runs/{rid}/nodes').json()
        review=c.get('/api/artifacts/'+nodes[2]['result']['artifact_id']).json()[0]['analysis']
        assert review['confirmed'] is False
        assert review['candidates'][0]['severity']=='info'
        assert len(handler.calls)==1


def test_bad_model_output_fails_node_and_skips_dependents(tmp_path,target_server):
    base,_=target_server
    async def analyst(*args):
        return {'report':json.dumps({'summary':'Fake claim','candidates':[{'title':'Unbound finding','severity':'critical','rationale':'invented','evidence_ids':['made-up'],'next_test':'do something'}],'coverage_limits':[]})}
    with TestClient(create_app(tmp_path,assessor=analyst)) as c:
        rid=launch(c,base,graph('native_scope','native_http','native_cai','native_summary')).json()['id']
        done=wait_done(c,rid)
        assert done['status']=='failed'
        assert [n['status'] for n in c.get(f'/api/runs/{rid}/nodes').json()]==['completed','completed','failed','skipped']


def test_cancel_cleans_up_node_tasks(tmp_path,target_server):
    base,handler=target_server
    started=threading.Event()
    async def analyst(*args):
        started.set()
        await asyncio.sleep(10)
    with TestClient(create_app(tmp_path,assessor=analyst)) as c:
        rid=launch(c,base,graph('native_scope','native_http','native_cai','native_summary')).json()['id']
        assert started.wait(2)
        assert c.post(f'/api/runs/{rid}/cancel',json={}).status_code==200
        for _ in range(50):
            nodes=c.get(f'/api/runs/{rid}/nodes').json()
            if all(n['status'] not in ('queued','running') for n in nodes):break
            time.sleep(.01)
        assert [n['status'] for n in nodes]==['completed','completed','cancelled','cancelled']
        assert len(handler.calls)==1


def test_pause_after_dns_prevents_tcp_dispatch(tmp_path,monkeypatch):
    started,release=threading.Event(),threading.Event()
    calls=[]
    def resolve(host,port):
        started.set();release.wait(2);return '127.0.0.1'
    async def connect(host,port):
        calls.append((host,port));raise OSError()
    monkeypatch.setattr('backend.app.resolve_target',resolve)
    monkeypatch.setattr('backend.app.asyncio.open_connection',connect)
    with TestClient(create_app(tmp_path)) as c:
        rid=launch(c,'127.0.0.1',graph('native_scope','native_tcp'),ports=[12345]).json()['id']
        assert started.wait(2)
        c.post(f'/api/runs/{rid}/pause',json={});release.set();time.sleep(.05)
        assert not calls
        c.post(f'/api/runs/{rid}/cancel',json={});time.sleep(.05)
        assert not calls


def test_restart_interrupts_running_nodes(tmp_path):
    s=Store(tmp_path)
    rid=s.new_run({'targets':['example.com']})['id']
    s.node_status(rid,'n1','running')
    s=Store(tmp_path)
    assert s.run(rid)['status']=='interrupted'
    assert s.nodes(rid)[0]['status']=='interrupted'


def test_rule_planner_and_model_plans_are_validated():
    plan=plan_workflow('headers only',include_analysis=True)
    assert plan['planner']=='local-rules' and not plan['model_called']
    validate_workflow(plan['graph'],live=True)
    with pytest.raises(ScopeError):plan_workflow('x',model_plan='{"adapters":["native_scope","shell"]}')
    with pytest.raises(ScopeError):plan_workflow('x',model_plan='{"adapters":["native_scope","native_cai"]}')
    with pytest.raises(ScopeError):plan_workflow('x',model_plan='{"adapters":["native_scope","native_http","native_cai"]}')


def test_rule_planning_api_never_calls_model(tmp_path):
    async def not_called(*args):raise AssertionError()
    with TestClient(create_app(tmp_path,assessor=not_called)) as c:
        p=c.post('/api/agent/plan',json={'goal':'headers only'}).json()
        assert p['planner']=='local-rules'
        assert not c.get('/api/runs').json()


def test_model_planning_api_uses_no_target_tools(tmp_path):
    async def planner(targets,goal,fetch):
        assert not targets
        assert 'error' in await fetch('http://outside.invalid')
        return {'report':'{"adapters":["native_scope","native_http","native_summary"]}'}
    with TestClient(create_app(tmp_path,assessor=planner)) as c:
        p=c.post('/api/agent/plan',json={'goal':'Review HTTP responses','use_model':True}).json()
        assert p['planner']=='cai-model'
        validate_workflow(p['graph'],live=True)


def test_node_timeout_prevents_late_http_dispatch_after_dns(tmp_path,target_server,monkeypatch):
    base,handler=target_server
    started,release=threading.Event(),threading.Event()
    def resolve(host,port):
        started.set();release.wait(3);return '127.0.0.1'
    monkeypatch.setattr('backend.scope.resolve_target',resolve)
    g=graph('native_scope','native_http','native_summary')
    g['nodes'][1]['data']['timeout']=1
    with TestClient(create_app(tmp_path)) as c:
        rid=launch(c,base,g).json()['id']
        assert started.wait(2)
        done=wait_done(c,rid)
        assert done['status']=='failed'
        release.set();time.sleep(.05)
        assert not handler.calls
        nodes=c.get(f'/api/runs/{rid}/nodes').json()
        assert nodes[1]['result']['error']=='TimeoutError'
        assert nodes[2]['status']=='skipped'


def test_api_rejects_cli_nodes_before_starting_a_run(tmp_path,target_server):
    base,handler=target_server
    g=graph('native_scope','native_http')
    g['nodes'][1]['data']['kind']='httpx'
    with TestClient(create_app(tmp_path)) as c:
        response=launch(c,base,g)
        assert response.status_code==422
        assert not c.get('/api/runs').json()
        assert not handler.calls


def test_graph_data_cannot_replace_selected_scope(tmp_path,target_server):
    base,handler=target_server
    g=graph('native_scope','native_http')
    g['nodes'][0]['data']['targets']=['http://outside.invalid/']
    with TestClient(create_app(tmp_path)) as c:
        rid=launch(c,base+'/api',g).json()['id']
        assert wait_done(c,rid)['status']=='completed'
        assert handler.calls==['/api']
