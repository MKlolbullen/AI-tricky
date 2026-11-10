import asyncio
import base64
import copy
import io
import json
import os
from pathlib import Path
import socket
import sys
import time
import zipfile

import pytest
from fastapi.testclient import TestClient
from backend.app import create_app, RunControl
from backend.identity_graph import analyze_exports, documents, SCHEMA, strict_json
from backend.identity_tools import graph_token, collect, PROFILES
from backend.scope import ScopeError
from backend.store import Store
from backend.workflows import REGISTRY
from backend.tests.test_local import wait_done

AD={'platform':'ad','domain':'corp.test','tenant_id':''}
TENANT='11111111-1111-1111-1111-111111111111'
ENTRA={'platform':'entra','domain':'corp.onmicrosoft.com','tenant_id':TENANT}


def normalized(scope=AD):
    return {'schema':SCHEMA,'scope':scope,'nodes':[{'id':'user','label':'Fixture user','kind':'user'},
        {'id':'group','label':'Privileged group','kind':'group'},{'id':'goal','label':'Fixture goal','kind':'group'}],
        'edges':[{'source':'user','target':'group','kind':'GenericAll'},{'source':'group','target':'goal','kind':'MemberOf'}]}


def analyze(doc,scope=AD,starts=('user',),goals=('goal',),depth=4):
    return analyze_exports([('fixture-evidence',json.dumps(doc).encode())],scope,starts,goals,depth)


def graph(scope=AD,*,input_id=None,profile=None,auth_id=None,agent=False):
    kinds=['native_scope']+(['native_identity_collect'] if profile else [])+['native_identity_paths']+(['native_team'] if agent else [])+['native_summary']
    nodes=[]
    for i,kind in enumerate(kinds):
        data={'kind':kind,**{k:v for k,v in REGISTRY[kind].items() if k in ('inputs','output')},'title':kind,'timeout':30,'retries':0}
        if kind.startswith('native_identity_'):data['identity_scope']=scope
        if kind=='native_identity_paths':data.update(inputRefs={'graph':input_id} if input_id else {},start_ids=[] if profile else ['user'],goal_ids=[] if profile else ['goal'])
        if kind=='native_identity_collect':data.update(profile_id=profile,identity_auth={'username':'analyst','dc_host':'dc.corp.test','dc_ip':'127.0.0.1'} if scope['platform']=='ad' else {},inputRefs={'kerberos_cache' if scope['platform']=='ad' else 'access_token':auth_id})
        if kind=='native_team':data.update(roles=['ad_identity' if scope['platform']=='ad' else 'entra_identity','poc'])
        nodes.append({'id':'i'+str(i),'type':'tool','position':{'x':i*240,'y':0},'data':data})
    return {'schema':'offsecs-u-ai.workflow/v1','nodes':nodes,'edges':[{'id':'e'+str(i),'source':nodes[i]['id'],'target':nodes[i+1]['id']} for i in range(len(nodes)-1)],'parallelism':2}


def run_body(c,workflow,scope=AD,**options):
    values=[scope['domain']]+(['dc.corp.test','127.0.0.1'] if any(n['data']['kind']=='native_identity_collect' for n in workflow['nodes']) and scope['platform']=='ad' else [])
    ids=[c.post('/api/targets',json={'value':v}).json()['id'] for v in values]
    return {'engine':'workflow','target_ids':ids,'workflow':workflow,'allow_http':True,'max_requests':1,'max_cli_invocations':2,'max_seconds':30,**options}


def input_file(c,tmp_path,name,raw):
    path=tmp_path/name;path.write_bytes(raw)
    result=c.post('/api/inputs',json={'name':name,'path':str(path)});assert result.status_code==201,result.text
    return result.json()['id'],path


def jwt(**overrides):
    claims={'tid':TENANT,'aud':'https://graph.microsoft.com','exp':int(time.time())+3600,**overrides}
    enc=lambda v:base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip('=')
    return enc({'alg':'RS256'})+'.'+enc(claims)+'.fixture_signature'


def test_paths_are_bounded_candidates_with_original_evidence_and_no_implicit_control():
    result=analyze(normalized())
    assert result['paths'][0]['nodes']==['USER','GROUP','GOAL']
    assert result['paths'][0]['evidence_ids']==['fixture-evidence']
    assert result['paths'][0]['executed'] is False and result['confirmed'] is False
    assert 'Assumes control' in result['paths'][0]['requires']
    assert analyze(normalized(),depth=1)['paths']==[]
    assert analyze(normalized(),starts=())['paths']==[]
    with pytest.raises(ScopeError):analyze(normalized(),starts=('missing',))


def test_cross_scope_objects_and_eligible_roles_are_not_traversable():
    doc=normalized(ENTRA)
    doc['nodes'][1]['scope']='22222222-2222-2222-2222-222222222222'
    doc['edges'].append({'source':'user','target':'goal','kind':'EligibleRole'})
    result=analyze(doc,ENTRA)
    assert result['paths']==[] and len(result['nodes'])==2
    assert any('excluded' in x for x in result['coverage_limits'])
    assert any('unsupported' in x for x in result['coverage_limits'])
    with pytest.raises(ScopeError):analyze(doc,AD)


def test_cycles_do_not_loop_or_imply_a_path():
    doc=normalized();doc['edges'].append({'source':'group','target':'user','kind':'GenericAll'})
    result=analyze(doc);assert len(result['paths'])==1 and result['search']['expanded']<=4


def test_bloodhound_zip_maps_membership_and_effective_replication_pair_only():
    users={'meta':{'type':'users','version':5},'data':[{'ObjectIdentifier':'U','Properties':{'domain':'CORP.TEST','name':'User@corp.test'},'PrimaryGroupSID':'G'}]}
    groups={'meta':{'type':'groups','version':5},'data':[{'ObjectIdentifier':'G','Properties':{'domain':'corp.test','name':'Group'},'Members':[]}]}
    domain={'meta':{'type':'domains','version':5},'data':[{'ObjectIdentifier':'D','Properties':{'domain':'corp.test','name':'corp.test'},'Aces':[{'PrincipalSID':'G','RightName':'GetChanges'},{'PrincipalSID':'G','RightName':'GetChangesAll'}]}]}
    def package():
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            for name,doc in [('users.json',users),('groups.json',groups),('domains.json',domain)]:z.writestr(name,json.dumps(doc))
        return out.getvalue()
    result=analyze_exports([('zip-source',package())],AD,['U'],['D'])
    assert [s['kind'] for s in result['paths'][0]['steps']]==['MemberOf','DCSync']
    domain['data'][0]['Aces'].pop()
    assert analyze_exports([('zip-source',package())],AD,['U'],['D'])['paths']==[]


def test_azurehound_v5_nested_members_and_tenant_wide_active_role_assignments():
    doc={'meta':{'type':'azure','version':5},'data':[
        {'kind':kind,'data':{'id':identifier,'displayName':identifier,'tenantId':TENANT}} for kind,identifier in [('AZUser','U'),('AZGroup','G'),('AZRole','R')]]}
    doc['data'] += [
        {'kind':'AZGroupMember','data':{'groupId':'G','members':[{'groupId':'G','member':{'id':'U'}}]}},
        {'kind':'AZRoleAssignment','data':{'tenantId':TENANT,'roleDefinitionId':'R','roleAssignments':[{'principalId':'G','roleDefinitionId':'R','directoryScopeId':'/'}]}},
        {'kind':'AZRoleEligibilityScheduleInstance','data':{'tenantId':TENANT,'principalId':'U','roleDefinitionId':'R'}}]
    result=analyze(doc,ENTRA,['U'],['R'])
    assert [s['kind'] for s in result['paths'][0]['steps']]==['MemberOf','HasRole']
    doc['data'][-2]['data']['roleAssignments'][0]['directoryScopeId']='/restricted-app'
    assert analyze(doc,ENTRA,['U'],['R'])['paths']==[]


@pytest.mark.parametrize('raw',[b'{"x":1,"x":2}',b'{"x":NaN}',b'not-json'])
def test_malformed_or_ambiguous_graph_json_rejected(raw):
    with pytest.raises(ScopeError):strict_json(raw)


@pytest.mark.parametrize('name',['../users.json','/users.json','users.txt'])
def test_zip_paths_and_non_json_members_rejected(name):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w') as z:z.writestr(name,'{}')
    with pytest.raises(ScopeError):documents(out.getvalue())


@pytest.mark.parametrize('claims',[{'tid':'other'},{'aud':'https://management.azure.com'},{'exp':1}])
def test_graph_token_requires_matching_tenant_audience_and_expiry(claims):
    with pytest.raises(ScopeError):graph_token(jwt(**claims).encode(),TENANT)


def test_offline_import_agent_handoff_and_artifacts_do_not_perform_network(tmp_path,monkeypatch):
    calls=[]
    def no_dns(*args,**kwargs):raise AssertionError('No DNS for offline identity analysis')
    monkeypatch.setattr(socket,'getaddrinfo',no_dns)
    async def analyst(targets,goal,fetch,**kwargs):
        calls.append((targets,goal,kwargs['role_instructions']))
        assert targets==[] and (await fetch('https://outside.test/'))['error']
        return {'report':json.dumps({'summary':'Identity fixture review','candidates':[],'coverage_limits':[]}) if 'validation plans' not in kwargs['role_instructions'] else json.dumps({'summary':'No automatic execution','validations':[],'coverage_limits':[]})}
    with TestClient(create_app(tmp_path/'state',assessor=analyst)) as c:
        iid,path=input_file(c,tmp_path,'graph.json',json.dumps(normalized()).encode())
        body=run_body(c,graph(input_id=iid,agent=True))
        before=path.read_bytes();result=c.post('/api/runs',json=body)
        assert result.status_code==201,result.text
        done=wait_done(c,result.json()['id']);assert done['result']['failed_nodes']==0,done
        artifacts=c.get('/api/runs/'+done['id']+'/artifacts').json()
        result=next(c.get('/api/artifacts/'+a['id']).json() for a in artifacts if a['name'].startswith('identity-analysis-'))
        assert len(result['paths'])==1 and result['confirmed'] is False
        assert path.read_bytes()==before and len(calls)==2
        assert all('identity_evidence' in goal or 'handoff' in goal for _,goal,_ in calls)
        assert c.get('/api/findings').json()['total']==0
        assert not any(e['kind'] in ('http.admitted','tcp.admitted','cli.admitted') for e in c.get('/api/runs/'+done['id']+'/events').json())
        assert {'ad_identity','entra_identity'} <= {r['key'] for r in c.get('/api/runtime').json()['team_roles']}


@pytest.fixture
def identity_binary(tmp_path,monkeypatch):
    path=tmp_path/'bin';path.mkdir()
    code=f'#!{sys.executable}\n'+'''import json,os,sys,stat
from pathlib import Path
args=sys.argv[1:]
if '--config' in args:
 auth=Path(args[args.index('--config')+1]);secret=json.loads(auth.read_text())['jwt']
 print('token='+secret,flush=True)
 output=Path(args[args.index('--output')+1]);output.write_text(json.dumps({'meta':{'type':'azure','version':5},'data':[]}))
else:
 auth=Path(os.environ['KRB5CCNAME'])
 print('AccountName  DelegationType',flush=True)
print(json.dumps({'args':args,'env_keys':sorted(os.environ),'private':stat.S_IMODE(auth.stat().st_mode),'bytes':auth.stat().st_size}),flush=True)
'''
    for profile in PROFILES.values():
        p=path/profile['binary'];p.write_text(code);p.chmod(0o755)
    monkeypatch.setenv('PATH',str(path)+os.pathsep+os.environ.get('PATH',''))
    for name in ('HTTP_PROXY','AZUREHOUND_JWT','KRB5_CONFIG','AZURE_CONFIG_DIR'):monkeypatch.setenv(name,'ambient-must-not-be-inherited')
    return path


@pytest.mark.parametrize('profile',['impacket-ad-users','impacket-spns','impacket-delegation','azurehound-entra'])
def test_fixed_collector_profiles_use_private_credentials_and_shared_cli_accounting(tmp_path,identity_binary,profile):
    scope=ENTRA if profile=='azurehound-entra' else AD;secret=jwt() if scope==ENTRA else 'fixture-cache-bytes'
    with TestClient(create_app(tmp_path/'state')) as c:
        iid,_=input_file(c,tmp_path,'credential',secret.encode())
        body=run_body(c,graph(scope,profile=profile,auth_id=iid),scope,allow_cli=True)
        preflight=c.post('/api/runs/preflight',json=body);assert preflight.status_code==200 and preflight.json()['ready'],preflight.text
        start=c.post('/api/runs',json=body);assert start.status_code==201,start.text
        done=wait_done(c,start.json()['id']);assert done['result']['failed_nodes']==0,done
        artifacts=c.get('/api/runs/'+done['id']+'/artifacts').json()
        records=[c.get('/api/artifacts/'+a['id']).json() for a in artifacts]
        record=next(row for row in records if isinstance(row,dict) and row.get('tool_id')==profile)
        assert secret not in json.dumps(records)
        captured=json.loads(record['stdout'].splitlines()[-1]);assert captured['private']==0o600
        assert not {'HTTP_PROXY','AZUREHOUND_JWT','KRB5_CONFIG','AZURE_CONFIG_DIR'} & set(captured['env_keys'])
        assert record['native_requests_counted'] is False and record['exit_code']==0
        args=captured['args']
        if scope==AD:
            assert '-k' in args and '-no-pass' in args and args[-1]=='corp.test/analyst'
            assert not {'-request','-hashes','-aesKey','-request-user','-target-domain'} & set(args)
        else:assert args[:2]==['list','az-ad'] and '--jwt' not in args
        events=c.get('/api/runs/'+done['id']+'/events').json()
        assert sum(e['kind']=='cli.admitted' for e in events)==1
        assert not any(e['kind'] in ('http.admitted','tcp.admitted') for e in events)
        assert not list((tmp_path/'state'/'jobs').glob('identity-*'))


def test_missing_explicit_dc_address_scope_is_rejected_before_a_run(tmp_path,identity_binary):
    with TestClient(create_app(tmp_path/'state')) as c:
        iid,_=input_file(c,tmp_path,'cache',b'fixture')
        body=run_body(c,graph(profile='impacket-ad-users',auth_id=iid),allow_cli=True)
        body['target_ids']=body['target_ids'][:2]
        result=c.post('/api/runs',json=body)
        assert result.status_code==422 and 'DC IP' in result.text
        assert c.get('/api/runs').json()==[]


def test_arbitrary_identity_flags_are_rejected_and_context_does_not_grant_tenant_access(tmp_path):
    with TestClient(create_app(tmp_path/'state')) as c:
        iid,_=input_file(c,tmp_path,'graph.json',json.dumps(normalized()).encode())
        workflow=graph(input_id=iid);workflow['nodes'][1]['data']['params']={'-request':True}
        assert c.post('/api/runs',json=run_body(c,workflow)).status_code==422
        workflow=graph(ENTRA,input_id=iid);body=run_body(c,workflow,ENTRA)
        body['target_ids']=[c.post('/api/targets',json={'value':'https://corp.onmicrosoft.com/'}).json()['id']]
        assert c.post('/api/runs',json=body).status_code==422


def test_identity_recovery_binds_import_bytes_and_requires_fresh_review(tmp_path,monkeypatch):
    def no_dns(*args,**kwargs):raise AssertionError('Identity recovery must not resolve the offline domain')
    monkeypatch.setattr(socket,'getaddrinfo',no_dns)
    with TestClient(create_app(tmp_path/'state')) as c:
        iid,path=input_file(c,tmp_path,'graph.json',json.dumps(normalized()).encode())
        run=c.post('/api/runs',json=run_body(c,graph(input_id=iid))).json();source=wait_done(c,run['id'])
        result=c.post('/api/runs/'+source['id']+'/recoveries',json={'node_ids':['i1'],'max_requests':1,'max_hosts':1,'max_seconds':30})
        assert result.status_code==201,result.text
        review=result.json();assert iid in review['snapshot']['config']['recovery_input_pins']
        path.write_bytes(path.read_bytes()+b'\n')
        response=c.post('/api/recoveries/'+review['id']+'/dispatch',json={'approve':True,'expected_hash':review['snapshot_hash']})
        assert response.status_code==409,response.text
        assert len(c.get('/api/runs').json())==1


def test_identity_binary_change_after_preflight_stops_before_cli_admission(tmp_path,identity_binary):
    from backend.catalog_execution import preflight
    from backend.cli_runner import digest
    store=Store(tmp_path/'state');cache=tmp_path/'cache';cache.write_bytes(b'fixture')
    iid=store.add_input('cache','file',cache.resolve(),digest(cache))['id']
    workflow=graph(profile='impacket-ad-users',auth_id=iid)
    config={'workflow':workflow,'targets':['corp.test','dc.corp.test','127.0.0.1'],'allow_cli':True,'max_cli_invocations':1,'max_seconds':30}
    config.update(preflight(workflow,config,store));rid=store.new_run(config)['id'];ctl=RunControl()
    binary=identity_binary/'impacket-GetADUsers';binary.write_text(binary.read_text()+'\n# changed\n')
    with pytest.raises(ScopeError):asyncio.run(collect(rid,'i1',workflow['nodes'][1]['data'],config,ctl,store))
    assert ctl.cli_invocations==0


def test_cancelled_identity_collection_keeps_partial_logs_and_removes_private_job(tmp_path,identity_binary):
    binary=identity_binary/'impacket-GetADUsers'
    binary.write_text(f'#!{sys.executable}\nimport time\nprint("partial fixture collection",flush=True)\ntime.sleep(20)\n')
    with TestClient(create_app(tmp_path/'state')) as c:
        iid,_=input_file(c,tmp_path,'cache',b'fixture')
        run=c.post('/api/runs',json=run_body(c,graph(profile='impacket-ad-users',auth_id=iid),allow_cli=True)).json()
        for _ in range(100):
            if list((tmp_path/'state'/'jobs').glob('identity-*')) and any(e['kind']=='cli.admitted' for e in c.get('/api/runs/'+run['id']+'/events').json()):break
            time.sleep(.01)
        time.sleep(.1)
        assert c.post('/api/runs/'+run['id']+'/cancel',json={}).status_code==200
        for _ in range(150):
            artifacts=c.get('/api/runs/'+run['id']+'/artifacts').json()
            logs=[c.get('/api/artifacts/'+a['id']).json() for a in artifacts if a['name'].startswith('cli-')]
            if logs and not list((tmp_path/'state'/'jobs').glob('identity-*')):break
            time.sleep(.01)
        else:pytest.fail('Collector did not finish cancellation cleanup')
        assert logs[0]['error']=='CancelledError' and 'partial fixture collection' in logs[0]['stdout']
        assert c.get('/api/runs/'+run['id']).json()['status']=='cancelled'


def test_credential_file_selected_as_a_graph_is_not_retained_as_evidence(tmp_path):
    secret=jwt()
    with TestClient(create_app(tmp_path/'state')) as c:
        iid,_=input_file(c,tmp_path,'token.json',json.dumps({'access_token':secret}).encode())
        start=c.post('/api/runs',json=run_body(c,graph(input_id=iid))).json();done=wait_done(c,start['id'])
        assert done['result']['failed_nodes']==1
        artifacts=c.get('/api/runs/'+done['id']+'/artifacts').json()
        assert not any(a['name'].startswith('identity-import-') for a in artifacts)
        assert all(secret not in json.dumps(c.get('/api/artifacts/'+a['id']).json()) for a in artifacts)


def test_identity_model_candidates_can_cite_only_the_supplied_analysis_artifact():
    from backend.intelligence import validate_analysis
    values=[{'kind':'identity_evidence','identity_scope':AD,'artifact_id':'identity-capture','body':'Imported candidate path'}]
    report={'summary':'Review identity prerequisites','candidates':[{'title':'Candidate identity path','severity':'medium','rationale':'Imported rights need effective-access validation','evidence_ids':['identity-capture'],'next_test':'Review the effective ACL and restrictions'}],'coverage_limits':[]}
    assert validate_analysis(json.dumps(report),values)['confirmed'] is False
    report['candidates'][0]['evidence_ids']=['unavailable']
    with pytest.raises(RuntimeError):validate_analysis(json.dumps(report),values)


def test_non_string_collection_profile_is_rejected_at_graph_validation():
    from backend.workflows import validate_workflow
    workflow=graph(profile='impacket-ad-users',auth_id='fixture-input')
    workflow['nodes'][1]['data']['profile_id']=['impacket-ad-users']
    with pytest.raises(ScopeError):validate_workflow(workflow,live=True)
