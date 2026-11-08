import copy
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys
import zipfile

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app, RunControl
from backend.catalog import TOOLS, registered_path
from backend.catalog_execution import preflight
from backend.cli_runner import digest, execute_cli, prepare_context, build_command
from backend.scope import ScopeError
from backend.store import Store
from backend.support_data import SupportData, extract_archive
from backend.workflows import SCHEMA


def workflow(*tools):
    source={'id':'scope','type':'tool','position':{'x':0,'y':0},'data':{'kind':'catalog_source','sourceType':'targets','inputs':[],'outputs':['targets'],'output':'targets','value':''}}
    nodes=[source]; edges=[]
    for i,tid in enumerate(tools):
        spec=TOOLS[tid]
        nodes.append({'id':tid,'type':'tool','position':{'x':230,'y':i*200},'data':{'kind':'catalog_tool','toolId':tid,'inputs':spec['inputs'],'outputs':spec['outputs'],'output':spec['outputs'][0],'timeout':10,'retries':0}})
        edges.append({'id':'to-'+tid,'source':'scope','target':tid,'sourceHandle':'out:targets','targetHandle':'in:targets'})
    return {'schema':SCHEMA,'nodes':nodes,'edges':edges}


def test_bundled_inputs_are_offline_pinned_and_repeatable(tmp_path):
    store=Store(tmp_path); manager=SupportData(store,downloader=lambda *a:pytest.fail('Bundled setup must be offline'))
    assert not any(p['installed'] for p in manager.status()['bundled'])
    first=manager.install(); ids={p['id'] for p in store.inputs()}
    assert len(ids)==8 and all(p['installed'] for p in first['bundled'])
    assert manager.install()==first
    assert {p['id'] for p in store.inputs()}==ids
    assert store.runs()==[] and store.targets()==[]
    assert all(p['sha256'] for p in store.inputs())
    with store.connect() as c:c.execute('DELETE FROM inputs WHERE id=?',(next(iter(ids)),))
    manager.install()
    assert {p['id'] for p in store.inputs()}==ids  # interrupted registration recovers


def test_binding_fills_only_missing_context_and_passes_data_preflight(tmp_path):
    store=Store(tmp_path); manager=SupportData(store); manager.install()
    original=workflow('nuclei','massdns','ffuf','jaeles')
    result=manager.bind(original)
    assert len(result['bindings'])==3
    assert result['missing']==[{'node_id':'jaeles','slot':'templates','role':'jaeles-signatures'}]
    assert all('inputRefs' not in n['data'] for n in original['nodes'])
    assert manager.bind(result['graph'])['bindings']==[]
    smaller=copy.deepcopy(result['graph']); smaller['nodes']=[n for n in smaller['nodes'] if n['id']!='jaeles']; smaller['edges']=[e for e in smaller['edges'] if e['target']!='jaeles']
    assert preflight(smaller,{'targets':['example.test'],'max_hosts':5,'allow_cli':True},store,check_binaries=False)['ready']


def test_connected_wordlist_and_manual_refs_are_preserved(tmp_path):
    manager=SupportData(Store(tmp_path)); manager.install(); g=workflow('ffuf','nuclei')
    g['nodes'][2]['data']['inputRefs']={'templates':'operator-picked-id'}
    g['nodes'].append({'id':'words','type':'tool','position':{'x':0,'y':200},'data':{'kind':'catalog_source','sourceType':'wordlist','inputs':[],'outputs':['wordlist'],'output':'wordlist','inputId':'selected-wordlist'}})
    g['edges'].append({'id':'word-edge','source':'words','target':'ffuf'})
    result=manager.bind(g)
    assert result['bindings']==[]
    assert result['graph']==g


def test_puredns_receives_both_resolver_bindings_and_dns_wordlist(tmp_path):
    store=Store(tmp_path/'state'); manager=SupportData(store); manager.install()
    graph=workflow('puredns')
    graph['nodes'][0]['data'].update(sourceType='domain',outputs=['domain'],output='domain')
    graph['edges'][0].update(sourceHandle='out:domain',targetHandle='in:domain')
    before=preflight(graph,{'targets':['example.test'],'max_hosts':5,'allow_cli':True},store,check_binaries=False)
    reasons=' '.join(r for n in before['issues'] for r in n['reasons'])
    assert 'trusted resolvers' in reasons and not before['ready']
    bound=manager.bind(graph)
    assert len(bound['bindings'])==3 and not bound['missing']
    data=bound['graph']['nodes'][1]['data']; refs=data['inputRefs']
    assert store.input(refs['wordlist'])['name']=='Small DNS labels'
    work=tmp_path/'job'; work.mkdir()
    context,_,_=prepare_context({'domain':['example.test']},data,work,store,{'targets':['example.test'],'max_hosts':5},TOOLS['puredns'])
    argv=build_command(TOOLS['puredns'],data,context,{'path':'/fixture/puredns'})
    for flag,slot in [('-r','resolvers'),('--resolvers-trusted','resolvers_trusted')]:
        path=Path(argv[argv.index(flag)+1])
        assert path.parent==work
        assert path.read_bytes()==Path(store.input(refs[slot])['path']).read_bytes()
    assert Path(argv[2]).read_text().splitlines()[0]=='admin'
    assert preflight(bound['graph'],{'targets':['example.test'],'max_hosts':5,'allow_cli':True},store,check_binaries=False)['ready']


def test_rooted_http_paths_are_distinct_from_directory_fuzzer_words(tmp_path):
    store=Store(tmp_path); manager=SupportData(store); manager.install()
    result=manager.bind(workflow('meg','ffuf'))
    nodes={n['id']:n['data'] for n in result['graph']['nodes']}
    rooted=Path(store.input(nodes['meg']['inputRefs']['paths_file'])['path']).read_text().splitlines()
    words=Path(store.input(nodes['ffuf']['inputRefs']['wordlist'])['path']).read_text().splitlines()
    assert rooted[0]=='/' and all(p.startswith('/') for p in rooted)
    assert all(not p.startswith('/') for p in words)


def test_new_binding_roles_install_a_new_version_without_replacing_old_inputs(tmp_path):
    store=Store(tmp_path); manager=SupportData(store)
    trusted=next(e for e in manager.manifest['bundled'] if e['id']=='resolvers-trusted')
    trusted['roles']=['resolvers']
    original=manager.install()
    old=next(p for p in original['bundled'] if p['id']=='resolvers-trusted')['inputs'][0]
    updated=SupportData(store).install()
    new=next(p for p in updated['bundled'] if p['id']=='resolvers-trusted')['inputs'][0]
    assert new['input_id']!=old['input_id']
    assert 'resolvers-trusted' in new['roles']
    assert registered_path(store,old['input_id'],'file').is_file()


@pytest.mark.parametrize('pack,kind',[('wordlist-paths','file'),('nuclei-starter','folder')])
def test_changed_support_data_is_not_silently_overwritten_or_used(tmp_path,pack,kind):
    store=Store(tmp_path); manager=SupportData(store); status=manager.install()
    iid=next(p for p in status['bundled'] if p['id']==pack)['inputs'][0]['input_id']
    path=Path(store.input(iid)['path']); changed=path/'extra.yaml' if kind=='folder' else path
    changed.write_text('operator changed contents')
    with pytest.raises(ScopeError):registered_path(store,iid,kind)
    with pytest.raises(ScopeError):manager.install()
    assert changed.read_text()=='operator changed contents'


def test_bundled_checksum_mismatch_has_no_registration(tmp_path):
    store=Store(tmp_path/'state'); manager=SupportData(store)
    manager.manifest['bundled'][0]['sha256']['LICENSE.md']='0'*64
    with pytest.raises(ScopeError,match='checksum'):manager.install()
    assert not store.inputs()


def archive_fixture(tmp_path, *, nuclei=False):
    path=tmp_path/'fixture.zip'; prefix='fixture-revision'
    entries={'README.md':'Upstream MIT declaration','LICENSE.md':'MIT license'}
    if nuclei:
        entries.update({'http/exposures/a.yaml':'id: a\n','http/takeovers/t.yaml':'id: t\n','helpers/payload.txt':'helper bytes','.nuclei-ignore':'tags: []\n'})
    else:entries['common/a.yaml']='id: jaeles-fixture\n'
    with zipfile.ZipFile(path,'w') as z:
        for name,body in entries.items():z.writestr(prefix+'/'+name,body)
    ident='nuclei-templates' if nuclei else 'jaeles-signatures'
    entry={'id':ident,'name':ident,'repository':'fixture/data','revision':'revision','url':'https://example.invalid/pinned.zip','archive_prefix':prefix,'sha256':digest(path),'license_file':'LICENSE.md' if nuclei else 'README.md'}
    return path,{'bundled':[],'remote':[entry]}


@pytest.mark.parametrize('nuclei',[False,True])
def test_pinned_remote_archive_preserves_helpers_and_registers_views(tmp_path,nuclei):
    archive,manifest=archive_fixture(tmp_path,nuclei=nuclei); calls=[]
    def download(url,dest):calls.append(url);shutil.copyfile(archive,dest)
    store=Store(tmp_path/'state'); manager=SupportData(store,manifest=manifest,downloader=download)
    manager.install(manifest['remote'][0]['id']); manager.install(manifest['remote'][0]['id'])
    assert calls==['https://example.invalid/pinned.zip']
    inputs=store.inputs(); assert len(inputs)==(2 if nuclei else 1)
    if nuclei:
        for row in inputs:
            root=Path(row['path']); assert (root/'helpers/payload.txt').read_text()=='helper bytes'
            assert (root/'.nuclei-ignore').is_file() and (root/'LICENSE.md').is_file()
    assert all(registered_path(store,row['id'],'folder') for row in inputs)


def test_bad_archive_hash_is_rejected_before_extracting(tmp_path):
    archive,manifest=archive_fixture(tmp_path);manifest['remote'][0]['sha256']='0'*64
    store=Store(tmp_path/'state'); manager=SupportData(store,manifest=manifest,downloader=lambda u,d:shutil.copyfile(archive,d))
    with pytest.raises(ScopeError,match='checksum'):manager.install('jaeles-signatures')
    assert not store.inputs() and not list(manager.root.glob('.stage-*'))


@pytest.mark.parametrize('name,mode',[('fixture/../escape',0),('fixture/absolute\\escape',0),('/fixture/escape',0),('fixture/link',stat.S_IFLNK|0o777),('fixture/pipe',stat.S_IFIFO|0o600),('other/README.md',0)])
def test_archive_rejects_traversal_links_and_special_files(tmp_path,name,mode):
    archive=tmp_path/'unsafe.zip'
    with zipfile.ZipFile(archive,'w') as z:
        info=zipfile.ZipInfo(name);info.external_attr=mode<<16;z.writestr(info,'unsafe')
    out=tmp_path/'out';out.mkdir()
    with pytest.raises(ScopeError):extract_archive(archive,out,'fixture')
    assert not list(out.rglob('*'))


def test_archive_expansion_limit(tmp_path,monkeypatch):
    archive,_=archive_fixture(tmp_path);monkeypatch.setattr('backend.support_data.MAX_EXPANDED',1)
    with pytest.raises(ScopeError,match='limits'):extract_archive(archive,tmp_path/'out','fixture-revision')


def test_nuclei_sees_helpers_in_private_home_and_unchanged_template_bytes(tmp_path):
    import asyncio
    store=Store(tmp_path/'state'); manager=SupportData(store); manager.install()
    data=manager.bind(workflow('nuclei'))['graph']['nodes'][1]['data']
    binary=tmp_path/'nuclei-fixture'
    binary.write_text(f'#!{sys.executable}\n'+'''import os,sys,json
from pathlib import Path
templates=Path(sys.argv[sys.argv.index('-t')+1])
assert templates==Path(os.environ['HOME'])/'nuclei-templates'
assert (templates/'http/exposures/configs/git-config.yaml').is_file()
assert (templates/'.nuclei-ignore').is_file()
print(json.dumps({'private_home':True,'template_count':len(list(templates.rglob('*.yaml')))}))
''');binary.chmod(0o755)
    config={'targets':['https://example.test/'],'max_hosts':5,'max_seconds':5,'max_cli_invocations':1,'allow_cli':True,'cli_binaries':{'nuclei':{'path':str(binary),'sha256':digest(binary)}}}
    rid=store.new_run(config)['id'];ctl=RunControl()
    result=asyncio.run(execute_cli(rid,'nuclei',data,{'targets':['https://example.test/']},config,ctl,store))
    capture=store.content(result[0]['invocation_artifact_ids'][0])
    assert json.loads(capture['stdout'])=={'private_home':True,'template_count':7}
    assert all(flag in capture['command'] for flag in ('-ni','-dr','-duc'))
    assert ctl.requests==0 and ctl.cli_invocations==1


def test_support_api_installs_only_explicitly_and_never_dispatches(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        assert c.get('/api/inputs').json()==[]
        assert not any(p['installed'] for p in c.get('/api/support-data').json()['bundled'])
        assert c.post('/api/support-data/install/not-registered',json={}).status_code==422
        assert c.post('/api/support-data/install/bundled',json={}).status_code==200
        assert c.post('/api/support-data/bind',json={'graph':workflow('nuclei','ffuf')}).status_code==200
        assert len(c.get('/api/inputs').json())==8
        assert c.get('/api/runs').json()==[]
