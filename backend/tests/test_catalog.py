import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import pytest
from fastapi.testclient import TestClient

from backend.app import RunControl, create_app
from backend.catalog import CATALOG, TOOLS, ROOT, contract, convert_mini, registered_path, scoped_lines
from backend.catalog_execution import incoming_streams, preflight
from backend.cli_runner import CLIError, build_command, digest, execute_cli, pin_binary, prepare_context
from backend.scope import ScopeError
from backend.store import Store
from backend.workflows import validate_workflow

CONFIG={'targets':['example.test','https://example.test/'],'max_hosts':64,'allow_http':True,'allow_cli':True,'max_cli_invocations':64,'max_seconds':5,'cli_credential_keys':[]}


def data_for(tool):
    return {'kind':'catalog_tool','toolId':tool['id'],'inputs':tool['inputs'],'outputs':tool['outputs'],'output':tool['outputs'][0],'params':{'exploit_type':'mysql'} if tool['id']=='gopherus' else {},'timeout':3,'retries':0}


@pytest.fixture
def fixture_binary(tmp_path):
    path=tmp_path/'fixture-tool'
    path.write_text(f'#!{sys.executable}\n'+'''import json,os,sys
from pathlib import Path
stdin=sys.stdin.read()
if Path(sys.argv[0]).name in ('gowitness','aquatone','wapiti','zap-baseline.py'):
 Path('generated.json').write_text('{"fixture":true}')
print(json.dumps({'url':'https://example.test/','args':sys.argv[1:],'stdin':stdin,'env_keys':sorted(os.environ),'secret':os.environ.get('SHODAN_API_KEY','')}))
''')
    path.chmod(0o755)
    return path


def streams_for(tool,store,tmp_path):
    file=tmp_path/'source.txt';file.write_text('local fixture data\n')
    folder=tmp_path/'project';folder.mkdir(exist_ok=True);(folder/'source.js').write_text('const fixture = true;')
    registered_file=store.add_input('file','file',file.resolve(),digest(file))
    registered_folder=store.add_input('folder','folder',folder.resolve())
    available={'domain':['example.test'],'targets':['https://example.test/'],'url':['https://example.test/'],'query':['domain:example.test'],'wordlist':['one','two'],'file':['input:'+registered_file['id']],'folder':['input:'+registered_folder['id']],'sbom':['{"bomFormat":"CycloneDX"}']}
    types=tool['inputs']
    if tool['adapter']['traffic']=='offline' and 'folder' in types:types=['folder']
    elif tool['adapter']['traffic']=='offline' and 'file' in types:types=['file']
    streams={typ:available[typ] for typ in types}
    streams['paths_file']=['/api']
    if any('{wordlist_file}' in s for s in tool['command']):streams.setdefault('wordlist',['one','two'])
    return streams


def test_complete_source_counts_and_all_graphs_are_typed():
    assert len(TOOLS)==151
    assert len(CATALOG['workflows'])==57
    assert len({w['id'] for w in CATALOG['workflows']})==57
    for w in CATALOG['workflows']:validate_workflow(w,live=True)
    assert sum(t['adapter']['mode']=='blocked' for t in TOOLS.values())==10


def test_raw_mini_tricky_templates_convert_without_socket_loss():
    import yaml
    raw=[]
    for filename in ('templates.yaml','templates.nextgen.yaml'):raw+=yaml.safe_load((ROOT/'third-party/mini-tricky'/filename).read_text())['templates']
    for original,migrated in zip(raw,CATALOG['workflows']):
        converted=convert_mini(original)
        assert converted['nodes']==migrated['nodes'] or all(a['id']==b['id'] and a['data']['outputs']==b['data']['outputs'] for a,b in zip(converted['nodes'],migrated['nodes']))
        assert converted['edges']==migrated['edges']
        validate_workflow(converted,live=True)


@pytest.mark.parametrize('tid',list(TOOLS))
def test_every_tool_compiles_or_reports_its_explicit_context_restriction(tid,tmp_path,fixture_binary):
    tool=TOOLS[tid];store=Store(tmp_path/'state');data=data_for(tool)
    contract(data)
    binary=fixture_binary.parent/tool['command'][0]
    binary.write_bytes(fixture_binary.read_bytes());binary.chmod(0o755)
    pin={'path':str(binary),'sha256':digest(binary)}
    rid=store.new_run(CONFIG)['id'];ctl=RunControl()
    streams=streams_for(tool,store,tmp_path)
    if tid in ('massdns','shuffledns'):
        resolver=tmp_path/'resolvers';resolver.write_text('127.0.0.1\n');entry=store.add_input('resolvers','file',resolver.resolve(),digest(resolver));data['inputRefs']={'resolvers':entry['id']}
    if tid in ('nuclei','nuclei-takeover','jaeles'):
        entry=store.add_input('templates','folder',(tmp_path/'project').resolve());data['inputRefs']={**data.get('inputRefs',{}),'templates':entry['id']}
    config={**CONFIG,'cli_binaries':{tid:pin}}
    if tool['adapter']['mode']=='blocked':
        with pytest.raises(ScopeError):asyncio.run(execute_cli(rid,'tool',data,streams,config,ctl,store))
        assert ctl.cli_invocations==0
    else:
        result=asyncio.run(execute_cli(rid,'tool',data,streams,config,ctl,store))
        assert set(result[0]['catalog_streams'])==set(tool['outputs'])
        assert ctl.cli_invocations==1
        record=store.content(result[0]['invocation_artifact_ids'][0])
        assert record['exit_code']==0
        captured=json.loads(record['stdout'])
        assert isinstance(captured['args'],list)
        assert 'CAI_MODEL_API_KEY' not in captured['env_keys']
        if tool['adapter']['stdin']:assert captured['stdin']


def test_typed_multi_output_edges_use_requested_socket():
    graph={'nodes':[{'id':'source','data':{'output':'targets'}},{'id':'sink','data':{'output':'report'}}],'edges':[{'source':'source','target':'sink','sourceHandle':'out:url','targetHandle':'in:url'}]}
    values={'source':[{'catalog_streams':{'targets':['wrong.example'],'url':['https://example.test/']}}]}
    assert incoming_streams(graph,'sink',values)=={'url':['https://example.test/']}


def test_numeric_one_is_a_value_and_not_a_boolean_flag(fixture_binary):
    tool=TOOLS['subfinder'];data=data_for(tool);data['params']={'-t':1,'-recursive':True}
    command=build_command(tool,data,{'domain':'example.test'},{'path':str(fixture_binary)})
    assert command[-3:]==['-t','1','-recursive']


@pytest.mark.parametrize('updates',[{'command':['sh','-c','touch bad']},{'environment':{'CAI_MODEL_API_KEY':'bad'}},{'params':{'--unknown':'x'}},{'params':{'-fr':True}}])
def test_commands_environment_and_unsafe_flags_cannot_be_injected(updates):
    data=data_for(TOOLS['httpx']);data.update(updates)
    with pytest.raises(ScopeError):contract(data)


def test_binary_change_after_preflight_is_rejected(tmp_path,fixture_binary):
    store=Store(tmp_path/'state');tool=TOOLS['subfinder'];pin={'path':str(fixture_binary),'sha256':digest(fixture_binary)}
    fixture_binary.write_text(fixture_binary.read_text()+'\n# changed\n')
    config={**CONFIG,'cli_binaries':{'subfinder':pin}}
    with pytest.raises(ScopeError):asyncio.run(execute_cli(store.new_run(config)['id'],'tool',data_for(tool),{'domain':['example.test']},config,RunControl(),store))


def test_discoveries_are_not_active_authorization():
    allowed,_=scoped_lines(['dev.example.test'],'targets',CONFIG,discovery=True)
    assert allowed==['dev.example.test']
    allowed,rejected=scoped_lines(allowed,'targets',CONFIG)
    assert allowed==[] and rejected==['dev.example.test']


def test_registered_file_change_is_detected(tmp_path):
    store=Store(tmp_path/'state');path=tmp_path/'input';path.write_text('before')
    saved=store.add_input('input','file',path.resolve(),digest(path));path.write_text('after')
    with pytest.raises(ScopeError):registered_path(store,saved['id'])


def test_preflight_reports_missing_binaries_inputs_and_restrictions(tmp_path,monkeypatch):
    monkeypatch.setenv('PATH',str(tmp_path/'missing'))
    graph=next(w for w in CATALOG['workflows'] if any(n['data'].get('toolId')=='prowler' for n in w['nodes']))
    report=preflight(graph,CONFIG,Store(tmp_path/'state'))
    assert not report['ready']
    assert any('account scope' in reason for issue in report['issues'] for reason in issue['reasons'])


def test_input_registration_import_and_preflight_api(tmp_path,monkeypatch):
    monkeypatch.setenv('PATH',str(tmp_path/'missing'))
    with TestClient(create_app(tmp_path/'state')) as c:
        uploaded=c.post('/api/inputs',json={'name':'words.txt','content':'one\ntwo\n'})
        assert uploaded.status_code==201
        assert c.get('/api/inputs').json()[0]['id']==uploaded.json()['id']
        import yaml
        raw=yaml.safe_load((ROOT/'third-party/mini-tricky/templates.yaml').read_text())['templates'][0]
        converted=c.post('/api/catalog/import',json={'workflow':raw})
        assert converted.status_code==200,converted.text
        tid=c.post('/api/targets',json={'value':'example.test'}).json()['id']
        config={'engine':'workflow','workflow':converted.json(),'target_ids':[tid],'allow_http':True,'allow_cli':True}
        ready=c.post('/api/runs/preflight',json=config)
        assert ready.status_code==200 and not ready.json()['ready']
        assert c.post('/api/runs',json=config).status_code==422
        assert not c.get('/api/runs').json()


def test_arbitrary_legacy_scripts_are_not_imported():
    raw={'nodes':[{'id':'script','kind':'script','label':'bad','script_body':'touch bad'}],'edges':[]}
    with pytest.raises(ScopeError):convert_mini(raw)


def test_real_graph_stream_routing_and_cli_accounting(tmp_path,fixture_binary,monkeypatch):
    for tid in ('subfinder','httpx','nuclei'):
        executable=tmp_path/TOOLS[tid]['command'][0];executable.write_bytes(fixture_binary.read_bytes());executable.chmod(0o755)
    monkeypatch.setenv('PATH',str(tmp_path)+os.pathsep+os.environ.get('PATH',''))
    graph=copy.deepcopy(next(w for w in CATALOG['workflows'] if w['id']=='tpl-full-recon'))
    # Use only the canonical subfinder -> HTTPX -> Nuclei branch to avoid requiring unrelated binaries.
    source=next(n for n in graph['nodes'] if n['data']['kind']=='catalog_source')
    tool_nodes=[next(n for n in graph['nodes'] if n['data'].get('toolId')==tid) for tid in ('subfinder','httpx','nuclei')]
    sink={'id':'collector','type':'tool','position':{'x':1000,'y':0},'data':{'kind':'catalog_output','title':'Collect','inputs':['any'],'outputs':['report'],'output':'report','timeout':120,'retries':0}}
    nodes=[source,*tool_nodes,sink];types=['domain','targets','url','findings']
    edges=[{'id':f'e{i}','source':nodes[i]['id'],'target':nodes[i+1]['id'],'sourceHandle':'out:'+typ,'targetHandle':'in:'+('any' if i==3 else typ)} for i,typ in enumerate(types)]
    g={'schema':'offsecs-u-ai.workflow/v1','nodes':nodes,'edges':edges}
    from backend.tests.test_local import wait_done
    with TestClient(create_app(tmp_path/'state')) as c:
        tid=c.post('/api/targets',json={'value':'example.test'}).json()['id']
        resources=tmp_path/'templates';resources.mkdir();(resources/'fixture.yaml').write_text('id: fixture')
        binding=c.post('/api/inputs',json={'name':'templates','path':str(resources)}).json()['id']
        next(n for n in g['nodes'] if n['data'].get('toolId')=='nuclei')['data']['inputRefs']={'templates':binding}
        config={'engine':'workflow','workflow':g,'target_ids':[tid],'allow_http':True,'allow_cli':True,'max_cli_invocations':3}
        assert c.post('/api/runs/preflight',json=config).json()['ready']
        response=c.post('/api/runs',json=config);assert response.status_code==201,response.text
        rid=response.json()['id'];done=wait_done(c,rid)
        assert done['status']=='completed',done
        assert done['result']['request_count']==0
        assert done['result']['cli_invocation_count']==3
        events=c.get(f'/api/runs/{rid}/events').json()
        assert len([e for e in events if e['kind']=='cli.admitted'])==3
        assert len(c.get(f'/api/runs/{rid}/nodes').json())==5


def test_cli_fanout_shares_process_budget_and_keeps_partial_logs(tmp_path,fixture_binary):
    store=Store(tmp_path/'state');tool=TOOLS['subfinder'];ctl=RunControl()
    config={**CONFIG,'targets':['one.example.test','two.example.test'],'max_cli_invocations':1,'cli_binaries':{'subfinder':{'path':str(fixture_binary),'sha256':digest(fixture_binary)}}}
    rid=store.new_run(config)['id']
    with pytest.raises(ScopeError,match='budget exhausted'):
        asyncio.run(execute_cli(rid,'tool',data_for(tool),{'domain':['one.example.test','two.example.test']},config,ctl,store))
    assert ctl.cli_invocations==1
    assert ctl.requests==0
    assert len(store.artifacts(rid))==1


def test_cancellation_kills_process_group_and_persists_partial_output(tmp_path):
    from backend.cli_runner import pause_processes
    marker=tmp_path/'orphan-marker';started=tmp_path/'started';binary=tmp_path/'subfinder'
    binary.write_text(f'#!{sys.executable}\n'+f'''import subprocess,sys,time
from pathlib import Path
subprocess.Popen([sys.executable,'-c',"import time;from pathlib import Path;time.sleep(.5);Path({str(marker)!r}).write_text('orphan')"])
Path({str(started)!r}).write_text('ready')
print('partial log',flush=True)
time.sleep(10)
''');binary.chmod(0o755)
    store=Store(tmp_path/'state');ctl=RunControl();config={**CONFIG,'cli_binaries':{'subfinder':{'path':str(binary),'sha256':digest(binary)}}};rid=store.new_run(config)['id']
    async def exercise():
        task=asyncio.create_task(execute_cli(rid,'tool',data_for(TOOLS['subfinder']),{'domain':['example.test']},config,ctl,store))
        for _ in range(100):
            if started.exists():break
            await asyncio.sleep(.01)
        assert started.exists()
        ctl.cancelled=True;task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        await asyncio.sleep(.6)
    asyncio.run(exercise())
    assert not marker.exists()
    assert not ctl.processes
    assert not list((store.root/'jobs').iterdir())
    artifact=store.content(store.artifacts(rid)[0]['id'])
    assert artifact['error']=='CancelledError'
    assert 'partial log' in artifact['stdout']


def test_timeout_kills_cli_and_records_failure(tmp_path):
    binary=tmp_path/'subfinder';binary.write_text(f'#!{sys.executable}\nimport time\nprint("before timeout",flush=True)\ntime.sleep(10)\n');binary.chmod(0o755)
    store=Store(tmp_path/'state');ctl=RunControl();config={**CONFIG,'cli_binaries':{'subfinder':{'path':str(binary),'sha256':digest(binary)}}};rid=store.new_run(config)['id'];data=data_for(TOOLS['subfinder']);data['timeout']=1
    with pytest.raises(TimeoutError):asyncio.run(execute_cli(rid,'tool',data,{'domain':['example.test']},config,ctl,store))
    assert not ctl.processes
    assert store.content(store.artifacts(rid)[0]['id'])['error']=='TimeoutError'


def test_stream_output_limit_terminates_process(tmp_path):
    binary=tmp_path/'subfinder';binary.write_text(f'#!{sys.executable}\nimport sys\nsys.stdout.write("x"*3000000)\nsys.stdout.flush()\n');binary.chmod(0o755)
    store=Store(tmp_path/'state');ctl=RunControl();config={**CONFIG,'cli_binaries':{'subfinder':{'path':str(binary),'sha256':digest(binary)}}};rid=store.new_run(config)['id']
    with pytest.raises(CLIError):asyncio.run(execute_cli(rid,'tool',data_for(TOOLS['subfinder']),{'domain':['example.test']},config,ctl,store))
    assert len(store.content(store.artifacts(rid)[0]['id'])['stdout'])<=2_000_000
    assert not ctl.processes


def test_only_selected_provider_credentials_are_inherited_and_redacted(tmp_path,fixture_binary,monkeypatch):
    # The selected provider credential is supplied through the per-run snapshot
    # on the control object. An ambient environment variable of the same name is
    # never read, and the model API key in the environment is never inherited.
    monkeypatch.setenv('CAI_MODEL_API_KEY','fixture-never-inherited')
    monkeypatch.setenv('SHODAN_API_KEY','env-value-must-be-ignored')
    store=Store(tmp_path/'state');tool=TOOLS['shodan-cli'];config={**CONFIG,'cli_credential_keys':['SHODAN_API_KEY'],'cli_binaries':{tool['id']:{'path':str(fixture_binary),'sha256':digest(fixture_binary)}}};rid=store.new_run(config)['id']
    ctl=RunControl();ctl.credentials={'SHODAN_API_KEY':'fixture-selected-secret'}
    result=asyncio.run(execute_cli(rid,'tool',data_for(tool),{'domain':['example.test']},config,ctl,store))
    record=store.content(result[0]['invocation_artifact_ids'][0]);raw=json.dumps(record)
    assert 'fixture-selected-secret' not in raw
    assert 'env-value-must-be-ignored' not in raw
    assert 'fixture-never-inherited' not in raw
    assert '[REDACTED]' in record['stdout']
    assert 'CAI_MODEL_API_KEY' not in json.loads(record['stdout'])['env_keys']


def test_cross_run_file_artifacts_cannot_be_bound_as_inputs(tmp_path):
    import base64
    store=Store(tmp_path/'state');rid=store.new_run(CONFIG)['id'];other=store.new_run(CONFIG)['id']
    aid=store.artifact(other,'secret.txt',{'encoding':'base64','bytes':base64.b64encode(b'not authorized').decode()})
    work=tmp_path/'work';work.mkdir()
    with pytest.raises(ScopeError,match='belong to this run'):
        prepare_context({'file':['artifact:'+aid]},data_for(TOOLS['jsluice']),work,store,CONFIG,TOOLS['jsluice'],run_id=rid)


def test_catalog_capability_planner_produces_valid_graphs():
    from backend.catalog_planner import plan_catalog
    for source,target in [('domain','findings'),('folder','sbom'),('sbom','findings'),('query','findings')]:
        plan=plan_catalog('Review evidence',source,target)
        validate_workflow(plan['graph'],live=True)
        assert plan['planner']=='catalog-capabilities' and not plan['model_called']


def test_host_port_outputs_keep_host_scope_and_special_ranges_blocked():
    assert scoped_lines(['example.test:443'],'targets',CONFIG)[0]==['example.test:443']
    assert scoped_lines(['other.test:443'],'targets',CONFIG)[0]==[]
    assert scoped_lines(['http://169.254.169.254/'],'url',{**CONFIG,'targets':['169.254.169.254']})[0]==[]


def test_real_uro_adapter_with_loopback_free_offline_input(tmp_path):
    binary=Path(sys.executable).parent/'uro'
    if not binary.exists():pytest.skip('Optional real uro binary not installed')
    store=Store(tmp_path/'state');tool=TOOLS['uro'];config={**CONFIG,'cli_binaries':{'uro':{'path':str(binary),'sha256':digest(binary)}}};rid=store.new_run(config)['id']
    result=asyncio.run(execute_cli(rid,'uro',data_for(tool),{'targets':['https://example.test/profile?id=1','https://example.test/profile?id=2']},config,RunControl(),store))
    assert result[0]['catalog_streams']['targets']
    assert all(v.startswith('https://example.test/') for v in result[0]['catalog_streams']['targets'])


@pytest.mark.skipif(os.name!='posix',reason='POSIX process-group pause test')
def test_pause_resume_signals_the_cli_process_group(tmp_path):
    from backend.cli_runner import pause_processes
    heartbeat=tmp_path/'heartbeat';binary=tmp_path/'subfinder'
    binary.write_text(f'#!{sys.executable}\n'+f'''import time
from pathlib import Path
while True:
 with Path({str(heartbeat)!r}).open('a') as f:f.write('x')
 time.sleep(.02)
''');binary.chmod(0o755)
    store=Store(tmp_path/'state');ctl=RunControl();config={**CONFIG,'cli_binaries':{'subfinder':{'path':str(binary),'sha256':digest(binary)}}};rid=store.new_run(config)['id']
    async def exercise():
        task=asyncio.create_task(execute_cli(rid,'tool',data_for(TOOLS['subfinder']),{'domain':['example.test']},config,ctl,store))
        for _ in range(100):
            if heartbeat.exists():break
            await asyncio.sleep(.01)
        ctl.gate.clear();pause_processes(ctl,True)
        await asyncio.sleep(.03);before=heartbeat.stat().st_size;await asyncio.sleep(.12)
        assert heartbeat.stat().st_size==before
        pause_processes(ctl,False);ctl.gate.set();await asyncio.sleep(.1)
        assert heartbeat.stat().st_size>before
        ctl.cancelled=True;task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
    asyncio.run(exercise())


def test_same_run_file_artifacts_materialize_as_bounded_folder_input(tmp_path):
    import base64
    store=Store(tmp_path/'state');rid=store.new_run(CONFIG)['id']
    aid=store.artifact(rid,'upstream/result.json',{'encoding':'base64','bytes':base64.b64encode(b'{"fixture":true}').decode()})
    work=tmp_path/'work';work.mkdir()
    context,_,_=prepare_context({'folder':['artifact:'+aid]},data_for(TOOLS['syft']),work,store,CONFIG,TOOLS['syft'],run_id=rid)
    assert list(Path(context['folder']).iterdir())[0].read_text()=='{"fixture":true}'


def test_boolean_catalog_flags_reject_numeric_lookalikes():
    data=data_for(TOOLS['subfinder']);data['params']={'-recursive':1}
    with pytest.raises(ScopeError):contract(data)


def test_untrusted_structured_tool_output_does_not_change_output_types():
    from backend.cli_runner import output_streams
    result=output_streams(TOOLS['httpx'],'{"url":{"unexpected":"object"}}\n{"url":"https://example.test/"}',[])
    assert result=={'targets':['https://example.test/'],'url':['https://example.test/']}
