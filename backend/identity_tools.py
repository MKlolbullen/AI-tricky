"""Fixed identity collection profiles: shell-free, explicit context, no general exploit runner."""
import asyncio
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import tempfile
import time

from .catalog import ROOT, registered_path
from .cli_runner import digest, stop_process, pause_processes, close_pipes
from .identity_graph import bound_input, check_scope, scope_value, strict_json
from .scope import ScopeError, parse_target, host_matches

CATALOG=json.loads((ROOT/'src/identity-tools.json').read_text())
PROFILES={p['id']:p for p in CATALOG['profiles']}
AUTH_KEYS={'username','dc_host','dc_ip'}


def validate_collection(data):
    if data.get('profile_id','impacket-ad-users') not in PROFILES:raise ScopeError('Unknown identity collection profile.')
    auth=data.get('identity_auth',{})
    if not isinstance(auth,dict) or set(auth)-AUTH_KEYS or any(not isinstance(v,str) or len(v)>253 or any(ord(c)<32 for c in v) for v in auth.values()):
        raise ScopeError('Identity authentication accepts only username, DC hostname and DC IP metadata; bind credentials as registered files.')


def pin_profile(profile):
    name=next((shutil.which(n) for n in [profile['binary'],*profile['aliases']] if shutil.which(n)),None)
    if not name:raise ScopeError('Missing identity executable: '+profile['binary']+'.')
    path=Path(name).resolve()
    if not path.is_file():raise ScopeError('Identity executable must be a regular file.')
    return {'path':str(path),'sha256':digest(path)}


def graph_token(raw,tenant):
    if len(raw)>100000:raise ScopeError('Graph token input exceeds 100 KB.')
    try:
        text=raw.decode('utf-8').strip()
        if text.startswith('{'):text=strict_json(text).get('access_token','')
        if not isinstance(text,str) or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',text):raise ValueError()
        claims=strict_json(base64.urlsafe_b64decode(text.split('.')[1]+'='*(-len(text.split('.')[1])%4)))
        if str(claims.get('tid','')).lower()!=tenant:raise ValueError()
        if claims.get('aud') not in ('https://graph.microsoft.com','https://graph.microsoft.com/','00000003-0000-0000-c000-000000000000'):raise ValueError()
        if type(claims.get('exp')) is not int or claims['exp']<=time.time()+30:raise ValueError()
    except (ValueError,UnicodeError,AttributeError,TypeError):raise ScopeError('Provide an unexpired Microsoft Graph access-token JWT for the explicit tenant. Claim checks are not signature verification; the service authenticates the token.') from None
    return text


def context(data,config,store):
    validate_collection(data);scope=check_scope(data,config);profile=PROFILES[data.get('profile_id','impacket-ad-users')]
    if profile['platform']!=scope['platform']:raise ScopeError('Identity collection profile differs from the selected platform.')
    refs=data.get('inputRefs',{});auth=data.get('identity_auth',{})
    required='kerberos_cache' if scope['platform']=='ad' else 'access_token'
    if set(refs)!={required}:raise ScopeError('Bind exactly one '+required+' registered input for this collection profile.')
    path=registered_path(store,refs[required],'file')
    if scope['platform']=='ad':
        if not re.fullmatch(r'[A-Za-z0-9_.$][A-Za-z0-9_.$@-]{0,63}',auth.get('username','')):raise ScopeError('Enter a bounded AD account name without a domain prefix.')
        dc=parse_target(auth.get('dc_host',''))
        if dc.kind!='domain' or not dc.host.endswith('.'+scope['domain']):raise ScopeError('DC hostname must be inside the explicit AD domain.')
        selected=list(map(parse_target,config['targets']))
        if not any(t.kind in ('domain','wildcard') and host_matches(dc.host,t) for t in selected):raise ScopeError('Enter the DC hostname as its own target or an explicit matching wildcard.')
        try:ip=ipaddress.ip_address(auth.get('dc_ip',''))
        except ValueError:raise ScopeError('Enter a literal DC IP address.') from None
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or (ip.is_reserved and not ip.is_loopback):raise ScopeError('Blocked DC special-use address.')
        if not any(t.kind=='ip' and t.host==str(ip) or t.kind=='cidr' and ip in ipaddress.ip_network(t.url) for t in selected):
            raise ScopeError('Select the DC IP or a containing CIDR explicitly; a DNS name does not grant its resolved IP.')
        if path.stat().st_size>1_000_000:raise ScopeError('Kerberos cache input exceeds 1 MB.')
        return profile,scope,{'username':auth['username'],'dc_host':dc.host,'dc_ip':str(ip)},required
    graph_token(path.read_bytes(),scope['tenant_id'])
    return profile,scope,{},required


def preflight_node(data,config,store,*,check_binaries=True):
    profile,scope,auth,required=context(data,config,store)
    if not config.get('allow_cli'):raise ScopeError('Enable catalog CLI execution for identity collection; launches use the shared CLI budget.')
    pin=pin_profile(profile) if check_binaries else None
    iid=data['inputRefs'][required]
    return profile,pin,{iid:store.input(iid)}


def catalog_status():
    rows=[]
    for profile in CATALOG['profiles']:
        try:pin_profile(profile);state='binary_found'
        except ScopeError:state='missing_binary'
        rows.append({**profile,'readiness':state,'context_required':True,'compatibility_verified':False})
    return {**CATALOG,'profiles':rows,'boundary':'Fixed collection profiles only. Graph reachability is candidate evidence; no automatic exploitation or credential extraction.'}


async def collect(rid,nid,data,config,ctl,store):
    profile,scope,auth,required=context(data,config,store)
    if not config.get('allow_cli'):raise ScopeError('Identity CLI execution is disabled.')
    pin=config.get('cli_binaries',{}).get(profile['id'])
    if not pin or not Path(pin['path']).is_file() or digest(pin['path'])!=pin['sha256']:raise ScopeError('Identity executable changed after preflight.')
    raw=bound_input(store,data['inputRefs'][required],config)
    with tempfile.TemporaryDirectory(prefix='identity-',dir=store.root/'jobs') as directory:
        work=Path(directory);home=work/'home';home.mkdir(mode=0o700)
        env={k:os.environ[k] for k in ('PATH','LANG','LC_ALL','SystemRoot','WINDIR','PATHEXT') if k in os.environ}
        env.update({'HOME':str(home),'USERPROFILE':str(home),'NO_COLOR':'1','DO_NOT_TRACK':'1'})
        secret=None;output=work/'collection.json'
        if scope['platform']=='ad':
            cache=work/'auth.ccache';cache.write_bytes(raw);cache.chmod(0o600);env['KRB5CCNAME']=str(cache)
            argv=[pin['path'],*(['-all'] if profile['id']=='impacket-ad-users' else []),'-k','-no-pass','-dc-ip',auth['dc_ip'],'-dc-host',auth['dc_host'],scope['domain']+'/'+auth['username']]
        else:
            secret=graph_token(raw,scope['tenant_id'])
            private=work/'auth.json';private.write_text(json.dumps({'jwt':secret}));private.chmod(0o600)
            argv=[pin['path'],'list','az-ad','--tenant',scope['tenant_id'],'--config',str(private),'--output',str(output)]
            routing=config.get('http_routing') or {}
            if routing.get('mode')=='proxy':argv+=['--proxy',routing['proxy_url']]
            if routing.get('ca_input_id'):
                from .http_routing import resolve_routing
                resolved=resolve_routing(routing,store)
                if resolved.ca_sha256!=config['http_routing_binding']['ca_sha256']:raise ScopeError('HTTP CA changed after preflight.')
                ca=work/'trust.pem';ca.write_text(''.join(ssl.DER_cert_to_PEM_cert(c) for c in resolved.context.get_ca_certs(binary_form=True)))
                env['SSL_CERT_FILE']=str(ca)
        def redact(value):return value.replace(secret,'[REDACTED]') if secret else value
        buffers={'stdout':bytearray(),'stderr':bytearray()};proc=None;number=None;error=None;exit_code=None
        async def read(name,stream):
            while chunk:=await stream.read(65536):
                buffers[name].extend(chunk)
                if len(buffers[name])>2_000_000:raise ScopeError('Identity collector output exceeded 2 MB per stream.')
        async def disk_limit():
            while True:
                total=0
                for p in work.rglob('*'):
                    with contextlib.suppress(FileNotFoundError):
                        if p.is_file() and not p.is_symlink():total+=p.stat().st_size
                if total>30_000_000:raise ScopeError('Identity collector workspace exceeded 30 MB.')
                await asyncio.sleep(.1)
        while True:
            await ctl.gate.wait()
            async with ctl.lock:
                if ctl.cancelled:raise asyncio.CancelledError()
                if not ctl.gate.is_set():continue
                if ctl.cli_invocations>=config['max_cli_invocations']:raise ScopeError('CLI invocation budget exhausted.')
                if digest(pin['path'])!=pin['sha256']:raise ScopeError('Identity executable changed before dispatch.')
                ctl.cli_invocations+=1;number=ctl.cli_invocations
                store.event(rid,'cli.admitted',{'node_id':nid,'tool_id':profile['id'],'invocation_number':number,'traffic':'identity_collection'})
                break
        tasks=[]
        try:
            proc=await asyncio.create_subprocess_exec(*argv,cwd=work,env=env,stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=os.name=='posix')
            ctl.processes[proc.pid]=proc
            if ctl.cancelled:raise asyncio.CancelledError()
            if not ctl.gate.is_set():pause_processes(ctl,True)
            readers=[asyncio.create_task(read('stdout',proc.stdout)),asyncio.create_task(read('stderr',proc.stderr))]
            done=asyncio.create_task(proc.wait());disk=asyncio.create_task(disk_limit());tasks=[*readers,done,disk]
            async with asyncio.timeout(min(data.get('timeout',120),config['max_seconds'])):
                pending=set(tasks)
                while not done.done():
                    finished,pending=await asyncio.wait(pending,return_when=asyncio.FIRST_COMPLETED)
                    for task in finished:
                        if task.cancelled():raise asyncio.CancelledError()
                        if task.exception():raise task.exception()
                exit_code=done.result()
                await stop_process(proc);await asyncio.gather(*readers)
        except BaseException as exc:error=type(exc).__name__;raise
        finally:
            if proc:
                await stop_process(proc)
                for task in tasks:
                    if not task.done():task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
                await close_pipes(proc);ctl.processes.pop(proc.pid,None)
            record={'tool_id':profile['id'],'command':argv,'exit_code':exit_code,'error':error,'scope':scope,
                'stdout':redact(bytes(buffers['stdout'][:2_000_000]).decode(errors='replace')),
                'stderr':redact(bytes(buffers['stderr'][:2_000_000]).decode(errors='replace')),
                'native_requests_counted':False,'http_capture':'external_proxy_history' if scope['platform']=='entra' and (config.get('http_routing') or {}).get('mode')=='proxy' else 'tool_output_only'}
            aid=store.artifact(rid,f'cli-{number}-{profile["id"]}.json',record,node_id=nid)
            store.event(rid,'cli.finished',{'node_id':nid,'tool_id':profile['id'],'artifact_id':aid,'exit_code':exit_code,'error':error})
        if exit_code!=0:raise ScopeError('Identity collector exited unsuccessfully; inspect its retained CLI artifact.')
        if scope['platform']=='entra':
            if not output.is_file() or output.is_symlink() or output.stat().st_size>10_000_000:raise ScopeError('AzureHound must produce a regular JSON export under 10 MB.')
            payload=redact(output.read_text()).encode()
            strict_json(payload)
        else:payload=json.dumps({'schema':'ai-tricky.identity-collection/v1','scope':scope,'profile_id':profile['id'],'stdout':record['stdout'],'invocation_artifact_id':aid}).encode()
        fid=store.artifact(rid,'identity-'+nid+'.json',{'encoding':'base64','bytes':base64.b64encode(payload).decode(),'size':len(payload),'identity_scope':scope,'source_artifact_id':aid},node_id=nid)
        return [{'catalog_streams':{'file':['artifact:'+fid]},'artifact_id':fid,'identity_scope':scope,'evidence_status':'OBSERVATION','collection_profile':profile['id']}]
