import asyncio
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.model_errors import ProviderUnavailable, transient_provider_error
from backend.model_usage import TOKEN_FIELDS
from backend.team import ROLES, SPECIALIST_ROLES
from backend.team_contracts import handoff_packet, validate_specialist
from backend.team_routing import execute_route, RoutedFailure
from backend.tests.test_local import wait_done, target_server
from backend.tests.test_workflows import graph, launch
from backend.tests.test_recovery import prepare as prepare_recovery, dispatch as dispatch_recovery


def choice(provider='local', model='fixture'):
    return {'provider':provider,'model':model}


@pytest.mark.parametrize('cap', [1,2,3,8,24])
def test_explicit_availability_fallback_stays_within_the_role_ceiling(cap):
    calls=[]; events=[]
    async def call(model,limit):
        calls.append((model['model'],limit))
        if len(calls)==1:raise ProviderUnavailable()
        return {'report':'Fallback completed'}
    operation=execute_route(call,role='analyst',allowance=cap,
        route={'primary':choice(model='primary'),'fallback':choice(model='backup')},
        on_event=lambda k,v:events.append((k,v)))
    if cap==1:
        with pytest.raises(RoutedFailure):asyncio.run(operation)
    else:
        result=asyncio.run(operation)
        assert result['model_attempts'][1]['fallback'] is True
    assert sum(limit for _,limit in calls)<=cap
    assert calls[0][1]==(cap+1)//2
    assert len(events)==2*len(calls)


@pytest.mark.parametrize('error',[RuntimeError('secret provider body'),ValueError('malformed'),asyncio.CancelledError()])
def test_no_fallback_for_report_failures_refusals_or_cancellation(error):
    calls=[]
    async def call(*args):calls.append(args);raise error
    operation=execute_route(call,role='poc',allowance=8,route={'primary':choice(),'fallback':choice(model='backup')})
    with pytest.raises(asyncio.CancelledError if isinstance(error,asyncio.CancelledError) else RoutedFailure) as caught:
        asyncio.run(operation)
    assert len(calls)==1 and 'secret provider body' not in str(caught.value)
    async def refusal(*args):return {'report':'Insufficient evidence; no test proposed.'}
    assert len(asyncio.run(execute_route(refusal,role='poc',allowance=8,route={'primary':choice(),'fallback':choice(model='backup')}))['model_attempts'])==1


@pytest.mark.parametrize('status,expected',[(401,False),(403,False),(400,False),(429,True),(500,True),(503,True)])
def test_only_provider_transport_statuses_qualify(status,expected):
    error=type('APIStatusError',(Exception,),{'__module__':'openai','status_code':status})()
    assert transient_provider_error(error)==expected
    assert not transient_provider_error(RuntimeError('HTTP 503'))


@pytest.mark.parametrize('routes',[
    {'unknown':{'primary':choice()}}, {'surface':{'primary':{'provider':'unsupported','model':'x'}}},
    {'surface':{'primary':{'provider':'openai','model':''}}},
    {'surface':{'primary':{**choice(),'api_key':'must-not-be-accepted'}}},
    {'surface':{'primary':choice(model='https://arbitrary.invalid')}},
    {'surface':{'primary':choice(model=' bad id ')}},
    {'surface':{'primary':choice(),'fallback_on':['refusal']}},
])
def test_route_schema_rejects_unauthorized_fields_before_creating_a_run(tmp_path,routes):
    with TestClient(create_app(tmp_path,assessor=lambda:None)) as c:
        tid=c.post('/api/targets',json={'value':'https://example.test/'}).json()['id']
        result=c.post('/api/runs',json={'engine':'team','target_ids':[tid],'team_routes':routes})
        assert result.status_code==422
        assert c.get('/api/runs').json()==[]


def test_missing_fallback_credentials_and_remote_permission_fail_preflight(tmp_path,monkeypatch):
    monkeypatch.delenv('VENICE_API_KEY',raising=False);monkeypatch.delenv('CAI_ALLOW_REMOTE_MODEL',raising=False)
    with TestClient(create_app(tmp_path,assessor=lambda:None)) as c:
        tid=c.post('/api/targets',json={'value':'https://example.test/'}).json()['id']
        body={'engine':'team','target_ids':[tid],'team_routes':{'surface':{'primary':choice(),'fallback':choice('venice')}}}
        assert c.post('/api/runs/preflight',json=body).status_code==409
        monkeypatch.setenv('VENICE_API_KEY','fixture-venice-secret')
        assert c.post('/api/runs',json=body).status_code==409
        assert c.get('/api/runs').json()==[]


@pytest.mark.parametrize('level,expected',[('standard','routine'),('complex','stronger')])
def test_task_complexity_selects_only_the_explicit_tier(level,expected):
    called=[]
    async def call(model,limit):called.append(model['model']);return {'report':'Review'}
    result=asyncio.run(execute_route(call,role='surface',allowance=4,task_level=level,
        route={'primary':choice(model='routine'),'complex_task':choice(model='stronger')}))
    assert called==[expected] and result['model_attempts'][0]['task_level']==level


def specialist_fixture(calls,base,monkeypatch=None):
    async def assess(targets,goal,fetch,usage_callback=None,**kwargs):
        role=next(k for k,v in ROLES.items() if v['focus']==kwargs.get('role_instructions'))
        calls.append((role,kwargs.get('model')))
        if usage_callback:
            await usage_callback({'sequence':1,'phase':'started'})
            await usage_callback({'sequence':1,'phase':'response','tokens':dict.fromkeys(TOKEN_FIELDS,1)})
        if role=='surface':
            if targets:
                await fetch(base)
                if monkeypatch:monkeypatch.setenv('VENICE_API_KEY','new-secret-after-start')
            report=json.dumps({'summary':'Captured surface','candidates':[],'coverage_limits':[]})
        else:
            assert targets==[] and kwargs.get('network_tool') is None
            assert 'error' in await fetch(base+'/forbidden')
            packet=json.loads(goal.split('\n')[-1])['handoff']
            expected=SPECIALIST_ROLES[:SPECIALIST_ROLES.index(role)]
            assert [p['role'] for p in packet['upstream_reports']]==expected
            assert all(p['report_artifact_id'] for p in packet['upstream_reports'])
            ids=[e['artifact_id'] for e in packet['evidence']]
            report=json.dumps({'summary':'Evidence-based review','coverage_limits':[],
                **({'validations':[{'title':'Review captured control','evidence_ids':ids,'steps':['Compare the captured response against the documented expected control.'],
                    'expected_signal':'A reproducible difference','negative_signal':'No reproducible difference'}] if ids else []}
                   if role=='poc' else {'candidates':[]})})
        return {'report':report,'model':(kwargs.get('model') or {}).get('model','fixture')}
    return assess


def test_staged_roles_route_models_preserve_snapshot_and_handoff_provenance(tmp_path,target_server,monkeypatch):
    base,handler=target_server;calls=[]
    for key in ('GEMINI_API_KEY','OPENAI_API_KEY','VENICE_API_KEY'):monkeypatch.setenv(key,'initial-'+key)
    monkeypatch.setenv('CAI_ALLOW_REMOTE_MODEL','1')
    routes={r:{'primary':choice(p,r+'-model')} for r,p in [('surface','gemini'),('analyst','openai'),('vulnerability','venice'),('poc','venice')]}
    with TestClient(create_app(tmp_path,assessor=specialist_fixture(calls,base+'/',monkeypatch))) as c:
        tid=c.post('/api/targets',json={'value':base+'/'}).json()['id']
        response=c.post('/api/runs',json={'engine':'team','target_ids':[tid],'allow_http':True,'team_profile':'specialist','team_routes':routes})
        assert response.status_code==201,response.text
        done=wait_done(c,response.json()['id']);result=done['result']
        assert [r for r,_ in calls]==SPECIALIST_ROLES
        assert all(m['status']=='ok' for m in result['members']),result
        assert [m['model_attempts'][0]['provider'] for m in result['members']]==['gemini','openai','venice','venice']
        assert calls[-1][1]['api_key']=='initial-VENICE_API_KEY'
        assert result['members'][-1]['analysis']['execution']=='not_executed'
        assert handler.calls==['/'] and result['request_count']==1
        for member in result['members']:
            packet=c.get('/api/artifacts/'+member['handoff_artifact_id']).json()
            assert packet['recipient']==member['role']
        usage=c.get('/api/runs/'+done['id']+'/model-usage').json()
        assert usage['summary']['attempts']==4
        assert {i['role'] for i in usage['items']}==set(SPECIALIST_ROLES)
        for path in ('/api/runs/'+done['id'],'/api/runs/'+done['id']+'/events','/api/runs/'+done['id']+'/model-usage'):
            assert 'initial-VENICE_API_KEY' not in c.get(path).text


def test_workflow_specialists_have_no_live_tools_and_use_recorded_inputs(tmp_path,target_server):
    base,handler=target_server;calls=[]
    g=graph('native_scope','native_http','native_team');g['nodes'][-1]['data']['team_profile']='specialist'
    with TestClient(create_app(tmp_path,assessor=specialist_fixture(calls,base))) as c:
        done=wait_done(c,launch(c,base+'/',g).json()['id'])
        assert done['status']=='completed' and done['result']['failed_nodes']==0,done
        artifacts=c.get('/api/runs/'+done['id']+'/artifacts').json()
        team=c.get('/api/artifacts/'+next(a['id'] for a in artifacts if a['name']=='node-n2.json')).json()[0]
        assert all(m['status']=='ok' for m in team['members']),team
        assert team['members'][-1]['analysis']['review_required'] is True
        assert handler.calls==['/']


def test_poc_cannot_cite_unobserved_artifacts_or_claim_execution():
    packet=handoff_packet('poc',[],[{'status':200,'artifact_id':'captured','headers':[]}],[])
    report={'summary':'Candidate','validations':[{'title':'Test','evidence_ids':['invented'],'steps':['Compare'],
        'expected_signal':'Difference','negative_signal':'No difference'}],'coverage_limits':[]}
    with pytest.raises(RuntimeError):validate_specialist(json.dumps(report),'poc',packet)
    report['validations']=[];report['confirmed']=True
    with pytest.raises(RuntimeError):validate_specialist(json.dumps(report),'poc',packet)


def test_lead_has_its_own_model_and_no_target_tools(tmp_path,target_server):
    base,handler=target_server;seen=[]
    async def assess(targets,goal,fetch,**kwargs):
        model=kwargs.get('model') or {}
        seen.append(model.get('model'))
        if model.get('model')=='lead-model':
            assert targets==[] and kwargs['evidence_only'] is True
            assert 'no target access' in (await fetch(base))['error']
        return {'report':'Candidate review.'}
    with TestClient(create_app(tmp_path,assessor=assess)) as c:
        tid=c.post('/api/targets',json={'value':base}).json()['id']
        response=c.post('/api/runs',json={'engine':'team','target_ids':[tid],'allow_http':True,'roles':['surface'],
            'synthesize':True,'team_routes':{'lead':{'primary':choice(model='lead-model')}}})
        done=wait_done(c,response.json()['id'])
        assert seen==[None,'lead-model']
        assert done['result']['synthesis']['model_attempts'][0]['model']=='lead-model'
        assert handler.calls==[]


def test_recovery_binds_role_credentials_and_preserves_profile_and_selection(tmp_path,target_server,monkeypatch):
    base,handler=target_server
    monkeypatch.setenv('OPENAI_API_KEY','first-key-snapshot');monkeypatch.setenv('CAI_ALLOW_REMOTE_MODEL','1')
    async def assess(*args,**kwargs):return {'report':json.dumps({'summary':'Reviewed capture','candidates':[],'coverage_limits':[]})}
    with TestClient(create_app(tmp_path,assessor=assess)) as c:
        source=wait_done(c,launch(c,base+'/',graph('native_scope','native_http','native_team'),roles=['surface'],
            team_routes={'surface':{'primary':choice('openai','surface-model')}}).json()['id'])
        review=prepare_recovery(c,source,['n2'])
        monkeypatch.setenv('OPENAI_API_KEY','rotated-key')
        assert dispatch_recovery(c,review).status_code==409
        review=prepare_recovery(c,source,['n2'])
        result=dispatch_recovery(c,review)
        recovered=wait_done(c,result.json()['run']['id'])
        assert recovered['config']['roles']==['surface']
        assert recovered['config']['team_routes']==source['config']['team_routes']
        assert recovered['result']['request_count']==0 and handler.calls==['/']
        assert 'rotated-key' not in json.dumps(review)


def test_reused_specialist_checkpoints_copy_and_remap_handoff_provenance(tmp_path,target_server):
    base,handler=target_server;calls=[]
    with TestClient(create_app(tmp_path,assessor=specialist_fixture(calls,base))) as c:
        source=wait_done(c,launch(c,base+'/',graph('native_scope','native_http','native_team','native_summary'),
            team_profile='specialist').json()['id'])
        assert source['status']=='completed'
        review=prepare_recovery(c,source,['n3'])
        recovered=wait_done(c,dispatch_recovery(c,review).json()['run']['id'])
        assert recovered['status']=='completed',recovered
        assert recovered['result']['model_usage']['invocations']==0
        assert recovered['result']['request_count']==0 and handler.calls==['/']
        artifacts=c.get('/api/runs/'+recovered['id']+'/artifacts').json()
        team=c.get('/api/artifacts/'+next(a['id'] for a in artifacts if a['name'].startswith('reused/') and a['name'].endswith('/node-n2.json'))).json()[0]
        owned={a['id'] for a in artifacts}
        for member in team['members']:
            assert member['handoff_artifact_id'] in owned and member['report_artifact_id'] in owned
            packet=c.get('/api/artifacts/'+member['handoff_artifact_id']).json()
            assert all(e['artifact_id'] in owned for e in packet['evidence'])


def test_pause_stops_evidence_only_stage_dispatch_until_resume(tmp_path,target_server):
    base,_=target_server;calls=[];started=threading.Event();release=threading.Event()
    delegate=specialist_fixture(calls,base+'/')
    async def assess(*args,usage_callback=None,**kwargs):
        result=await delegate(*args,usage_callback=usage_callback,**kwargs)
        if kwargs.get('role_instructions')==ROLES['surface']['focus']:
            started.set();await asyncio.to_thread(release.wait,3)
        return result
    with TestClient(create_app(tmp_path,assessor=assess)) as c:
        tid=c.post('/api/targets',json={'value':base+'/'}).json()['id']
        rid=c.post('/api/runs',json={'engine':'team','target_ids':[tid],'allow_http':True,'team_profile':'specialist'}).json()['id']
        assert started.wait(2)
        assert c.post('/api/runs/'+rid+'/pause',json={}).status_code==200
        release.set()
        for _ in range(100):
            artifacts=c.get('/api/runs/'+rid+'/artifacts').json()
            if any(a['name']=='team-handoff-analyst.json' for a in artifacts):break
            time.sleep(.01)
        else:pytest.fail('Expected the next stage to reach its dispatch gate')
        assert [r for r,_ in calls]==['surface']
        assert c.post('/api/runs/'+rid+'/resume',json={}).status_code==200
        assert wait_done(c,rid)['status']=='completed'
        assert [r for r,_ in calls]==SPECIALIST_ROLES
