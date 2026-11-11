"""Shell-free catalog processes with bounded streams and process-tree cleanup.

Input scope checks do not make a third-party binary an OS network sandbox.
CLI launch accounting is deliberately separate from native request accounting.
"""
import asyncio
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import tempfile
from urllib.parse import urlsplit, urlunsplit

from .catalog import TOOLS, registered_path, scoped_lines
from .scope import ScopeError, authorize, parse_target

MAX_STREAM=2_000_000
MAX_INPUT=10_000_000
MAX_OUTPUT_FILES=32
MAX_OUTPUT_TOTAL=16_000_000


class CLIError(RuntimeError):
    pass


def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(65536),b''):h.update(chunk)
    return h.hexdigest()


def pin_binary(tool):
    path=shutil.which(tool['command'][0])
    if not path:raise ScopeError(f"Missing executable: {tool['command'][0]}.")
    path=Path(path).resolve()
    if not path.is_file():raise ScopeError('Executable must be a regular file.')
    # The Python package named httpx is not ProjectDiscovery's HTTPX binary.
    if tool['id']=='httpx':
        with path.open('rb') as f:head=f.read(4096)
        if b'from httpx' in head or b'httpx._main' in head:raise ScopeError('The installed httpx is the Python HTTP client, not ProjectDiscovery HTTPX.')
    return {'path':str(path),'sha256':digest(path)}


def snapshot_folder(source,destination=None):
    total=0;count=0
    for root,dirs,files in os.walk(source,followlinks=False):
        for name in dirs+files:
            path=Path(root)/name
            if path.is_symlink():raise ScopeError('Registered folder contains a symlink; choose an explicit symlink-free input tree.')
        for name in files:
            path=Path(root)/name
            if not path.is_file():raise ScopeError('Folder contains a non-regular file.')
            total+=path.stat().st_size;count+=1
            if total>20_000_000 or count>10000:raise ScopeError('Folder input exceeds 20 MB or 10,000 files.')
    if destination is not None:shutil.copytree(source,destination,symlinks=False)
    return destination or source


def input_fingerprint(source, kind):
    """Bound registered/copy input contents, including relative folder paths."""
    source = Path(source)
    if source.is_symlink():raise ScopeError('Approved inputs cannot contain symlinks.')
    if kind == 'folder' and not source.is_dir() or kind == 'file' and not source.is_file():
        raise ScopeError('Approved input type changed before execution.')
    paths = [source]
    if kind == 'folder':
        paths = []
        for path in source.rglob('*'):
            paths.append(path)
            if len(paths) > 20000:raise ScopeError('Approved folder exceeds 20,000 entries.')
        paths.sort()
    if kind == 'folder':snapshot_folder(source)
    total = 0; count = 0; manifest = []
    for path in paths:
        if path.is_symlink():raise ScopeError('Approved inputs cannot contain symlinks.')
        relative = path.relative_to(source).as_posix() if kind == 'folder' else '.'
        if path.is_dir():
            manifest.append([relative, 'directory']);continue
        if not path.is_file():raise ScopeError('Approved input is not a regular file.')
        count += 1; fingerprint = hashlib.sha256()
        if count > 10000:raise ScopeError('Approved input exceeds 10,000 files.')
        with path.open('rb') as handle:
            for chunk in iter(lambda:handle.read(65536), b''):
                total += len(chunk)
                if total > (20_000_000 if kind == 'folder' else 10_000_000):raise ScopeError('Approved input exceeds its content limit.')
                fingerprint.update(chunk)
        manifest.append([relative, 'file', fingerprint.hexdigest()])
    return hashlib.sha256(json.dumps(manifest, separators=(',', ':')).encode()).hexdigest()


def prepare_context(streams,data,work,store,config,tool,run_id=None):
    context={'artifact_dir':str(work),'artifact_file':str(work/'output.txt')}
    streams={k:list(dict.fromkeys(v)) for k,v in streams.items()}
    for typ,identifier in data.get('inputRefs',{}).items():streams[typ]=['input:'+identifier]
    for typ,values in list(streams.items()):
        if any(not isinstance(v,str) or len(v)>(MAX_INPUT if typ=='sbom' else 16000) or '\x00' in v for v in values):raise ScopeError('Invalid typed input value.')
        if typ in ('folder','file') and values and all(v.startswith('artifact:') for v in values):
            if typ=='file' and len(values)!=1:raise ScopeError('File port accepts one artifact.')
            destination=work/'imported';destination.mkdir(exist_ok=True)
            total=0;paths=[]
            for index,reference in enumerate(values):
                aid=reference.removeprefix('artifact:')
                from .recovery import checked_reused_content
                try:meta=store.artifact_metadata(aid);body=checked_reused_content(store,aid)
                except KeyError:raise ScopeError('Upstream file artifact is unavailable.') from None
                if meta['run_id']!=run_id or not isinstance(body,dict) or body.get('encoding')!='base64':raise ScopeError('File artifact must belong to this run.')
                try:raw=base64.b64decode(body['bytes'],validate=True)
                except (KeyError,ValueError):raise ScopeError('Invalid upstream file encoding.') from None
                total+=len(raw)
                if total>MAX_INPUT:raise ScopeError('Upstream file input exceeds 10 MB.')
                path=destination/f'{index}-{Path(meta["name"]).name}';path.write_bytes(raw);paths.append(path)
            context['folder' if typ=='folder' else 'file_file']=str(destination if typ=='folder' else paths[0])
            streams[typ]=[context['folder' if typ=='folder' else 'file_file']]
        elif typ in ('folder','file','sbom','paths_file','resolvers','resolvers_trusted','wordlist','templates') and values and values[0].startswith('input:'):
            if len(values)!=1:raise ScopeError('File and folder ports accept one registered input.')
            source=registered_path(store,values[0][6:],'folder' if typ in ('folder','templates') else 'file')
            if typ in ('folder','templates'):
                destination=work/'home'/'nuclei-templates' if typ=='templates' and tool['id'] in ('nuclei','nuclei-takeover') else work/('source' if typ=='folder' else 'templates')
                destination.parent.mkdir(parents=True,exist_ok=True)
                path=snapshot_folder(source,destination)
                expected=store.input(values[0][6:]).get('sha256')
                if expected and input_fingerprint(path,'folder')!=expected:raise ScopeError('Pinned support folder changed during copying.')
            else:
                path=work/(typ+'.input');shutil.copyfile(source,path)
            if config.get('proposal_execution') or config.get('workflow_recovery'):
                pins='recovery_input_pins' if config.get('workflow_recovery') else 'proposal_input_pins'
                pin=config.get(pins,{}).get(values[0][6:])
                kind='folder' if typ in ('folder','templates') else 'file'
                if not pin or pin['kind']!=kind or input_fingerprint(path,kind)!=pin['sha256']:
                    raise ScopeError('Approved input contents changed before execution. Prepare a new execution review.')
            context[typ if typ in ('folder','templates') else 'sbom_file' if typ=='sbom' else 'wordlist_file' if typ=='wordlist' else typ if typ.endswith('_file') else typ+'_file']=str(path)
            streams[typ]=[str(path)]
        elif typ in ('wordlist','sbom','targets','url','domain','query','paths_file','resolvers'):
            body='\n'.join(values)+'\n' if values else ''
            if len(body.encode())>MAX_INPUT:raise ScopeError('Typed input exceeds the 10 MB limit.')
            path=work/(typ+'.txt');path.write_text(body)
            context['sbom_file' if typ=='sbom' else 'wordlist_file' if typ=='wordlist' else typ if typ.endswith('_file') else typ+'_file']=str(path)
    target_values=streams.get('targets') or streams.get('url') or streams.get('domain') or streams.get('file') or streams.get('folder') or []
    if tool['adapter']['traffic']!='offline':
        typ='url' if streams.get('url') and not streams.get('targets') else 'targets'
        if streams.get('domain') and not streams.get('targets') and not streams.get('url'):typ='domain'
        target_values,rejected=scoped_lines(target_values,typ,config,discovery=tool['adapter']['traffic']=='passive')
        if rejected and not target_values:raise ScopeError('No upstream targets are authorized for this CLI invocation.')
        if rejected:context['rejected_count']=len(rejected)
    if target_values:
        if tool['id']=='ffuf':
            scoped=[parse_target(v) for v in config['targets']]
            fuzzed=[]
            for value in target_values:
                # Path-fuzzing convenience only. Custom FUZZ query/path inputs
                # remain explicit; wordlists still need a registered binding.
                if 'FUZZ' not in value:
                    parsed=urlsplit(value)
                    if parsed.scheme not in ('http','https'):raise ScopeError('ffuf requires HTTP(S) URL inputs.')
                    value=urlunsplit((parsed.scheme,parsed.netloc,parsed.path.rstrip('/')+'/FUZZ',parsed.query,''))
                fuzzed.append(authorize(value,scoped).url)
            target_values=fuzzed
        # Avoid option injection even when a CLI doesn't support an explicit -- delimiter.
        if any(v.startswith('-') or '\n' in v or '\r' in v for v in target_values):raise ScopeError('Invalid scalar target.')
        path=work/'targets.txt';path.write_text('\n'.join(target_values)+'\n')
        context['targets_file']=str(path)
        context['targets']=target_values[0]
    if streams.get('domain') and target_values:context['domain']=target_values[0]
    if tool['id']=='katana':
        from .web_recon import crawler_scope
        path=work/'crawl-scope.txt';path.write_text('\n'.join(crawler_scope(config))+'\n')
        context['crawl_scope_file']=str(path)
    if streams.get('query'):context['query']=streams['query'][0]
    # Upstream URL lists can feed tools whose original placeholder is named targets.
    context.update({k:v for k,v in data.get('params',{}).items() if k in ('pattern','exploit_type')})
    if tool['id']=='gf':context.setdefault('pattern','xss')
    return context,target_values,streams


def build_command(tool,data,context,binary):
    try:argv=[part.format_map(context) for part in tool['command']]
    except KeyError as exc:raise ScopeError(f'Missing typed input or named context: {exc.args[0]}.') from None
    argv[0]=binary['path']
    if tool['id'] == 'subfinder':
        argv.append('-duc')
    if tool['id'] in ('shuffledns','massdns'):
        if not context.get('resolvers_file'):raise ScopeError('Register a resolvers file for this DNS adapter.')
        argv=[context['resolvers_file'] if part in ('/usr/share/resolvers.txt','resolvers.txt') else part for part in argv]
    if tool['id']=='puredns':
        if not context.get('resolvers_file') or not context.get('resolvers_trusted_file'):raise ScopeError('Bind regular and trusted resolver files for PureDNS.')
        argv+=['-r',context['resolvers_file'],'--resolvers-trusted',context['resolvers_trusted_file']]
    for key,value in data.get('params',{}).items():
        if not key.startswith('-'):continue
        if value is False or value=='':continue
        argv.append(key)
        if value is not True and value!='__flag__':argv.append(str(value))
    # Correct source-catalog adapters where the tool consumes stdin or a local
    # artifact instead of the source catalog's generic placeholder assumptions.
    if tool['id']=='hakrawler':argv=[binary['path']]+[a for a in argv[1:] if a not in ('-plain',)]
    if tool['id']=='anew':argv=[binary['path'],context['artifact_file']]+argv[2:]
    if tool['id']=='gitleaks' and context.get('folder'):argv=[binary['path'],'detect','--source',context['folder'],'--no-banner']+argv[4:]
    if tool['id']=='trufflehog' and context.get('folder'):argv=[binary['path'],'filesystem',context['folder'],'--json']+argv[3:]
    if tool['id']=='retire' and (context.get('folder') or context.get('file_file')):argv+=['--path',context.get('folder') or context['file_file']]
    # Avoid known automatic redirect expansion in the source command itself.
    if tool['id']=='cmseek':argv=[a for a in argv if a!='--follow-redirect']
    if tool['id'] in ('nuclei','nuclei-takeover'):
        if not context.get('templates'):raise ScopeError('Bind a reviewed Nuclei templates folder.')
        argv+=['-dr','-ni','-duc','-t',context['templates']]
    if tool['id']=='jaeles':
        if not context.get('templates'):raise ScopeError('Bind a reviewed Jaeles signatures folder.')
        argv+=['-s',context['templates']]
    if tool['id']=='httpx':argv+=['-duc']
    if tool['id']=='katana':argv+=['-dr','-fs','fqdn','-duc','-cs',context['crawl_scope_file']]
    return argv


async def stop_process(proc):
    if proc.returncode is not None and os.name!='posix':return
    if os.name=='posix':
        with contextlib.suppress(ProcessLookupError):os.killpg(proc.pid,signal.SIGCONT)
        with contextlib.suppress(ProcessLookupError):os.killpg(proc.pid,signal.SIGTERM)
    else:
        # taskkill is a system utility, never a graph-selected program.
        killer=await asyncio.create_subprocess_exec(str(Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/taskkill.exe'),'/PID',str(proc.pid),'/T','/F',stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL)
        await killer.wait()
    try:await asyncio.wait_for(proc.wait(),1)
    except TimeoutError:
        if os.name=='posix':
            with contextlib.suppress(ProcessLookupError):os.killpg(proc.pid,signal.SIGKILL)
        else:proc.kill()
        await proc.wait()


async def close_pipes(proc):
    if proc.stdin:
        proc.stdin.close()
        with contextlib.suppress(BrokenPipeError,ConnectionResetError):
            await proc.stdin.wait_closed()
    async def discard(reader):
        while await reader.read(65536):pass
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(asyncio.gather(discard(proc.stdout),discard(proc.stderr)),1)
    await asyncio.sleep(0)


def pause_processes(ctl,paused):
    if os.name=='posix':
        for proc in list(ctl.processes.values()):
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):os.killpg(proc.pid,signal.SIGSTOP if paused else signal.SIGCONT)


def output_streams(tool,text,files):
    lines=[line.strip() for line in text.splitlines() if line.strip()]
    targets=[];urls=[]
    for line in lines:
        try:
            obj=json.loads(line)
            candidate=(obj.get('url') or obj.get('host') or obj.get('input') or '') if isinstance(obj,dict) else ''
        except ValueError:candidate=line.split()[0] if line.split() else ''
        if not isinstance(candidate,str):candidate=''
        if candidate.startswith(('http://','https://')):urls.append(candidate)
        if candidate:targets.append(candidate)
    streams={}
    for typ in tool['outputs']:
        if typ=='url':streams[typ]=list(dict.fromkeys(urls))
        elif typ=='targets':streams[typ]=list(dict.fromkeys(targets))
        elif typ=='sbom':streams[typ]=[text]
        elif typ in ('file','folder'):streams[typ]=['artifact:'+f['id'] for f in files]
        else:streams[typ]=lines
    return streams


async def execute_cli(rid,nid,data,streams,config,ctl,store):
    tool=TOOLS[data['toolId']]
    if tool['adapter']['mode']=='blocked':raise ScopeError(tool['adapter']['reason'])
    if not config.get('allow_cli'):raise ScopeError('CLI execution is disabled for this run.')
    pin=config.get('cli_binaries',{}).get(tool['id'])
    if not pin or not Path(pin['path']).is_file() or digest(pin['path'])!=pin['sha256']:raise ScopeError('Executable changed after preflight. Run preflight again.')
    # Credentials from the model/runtime environment are never inherited by tools.
    env={k:os.environ[k] for k in ('PATH','SystemRoot','WINDIR','PATHEXT','LANG','LC_ALL') if k in os.environ}
    env.update({'NO_COLOR':'1','DO_NOT_TRACK':'1','GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1'})
    # Per-run credential snapshot (taken at run start, server-side only) — never
    # the live process environment, so keys cannot bleed across runs or apps.
    run_credentials=getattr(ctl,'credentials',None) or {}
    secret_values=[]
    for key in config.get('cli_credential_keys',[]):
        if key in tool.get('secrets',[]) and run_credentials.get(key):env[key]=run_credentials[key];secret_values.append(run_credentials[key])
    def redact(value):
        for secret in secret_values:
            if len(secret)>=4:value=value.replace(secret,'[REDACTED]')
        return value
    total_streams={k:[] for k in tool['outputs']};invocation_artifacts=[]
    # Scalar adapters fan out instead of silently using only the first target.
    scalar=any('{targets}' in p or '{domain}' in p for p in tool['command'])
    streams=dict(streams)
    # Filter before scalar fan-out as well as immediately before dispatch: one
    # unapproved discovery must not prevent the remaining approved hosts running.
    if tool['adapter']['traffic']!='offline':
        key=next((k for k in ('targets','url','domain') if streams.get(k)),None)
        if key:
            allowed,rejected=scoped_lines(streams[key],key,config,discovery=tool['adapter']['traffic']=='passive')
            if rejected:store.event(rid,'cli.inputs_filtered',{'node_id':nid,'tool_id':tool['id'],'rejected_count':len(rejected)})
            if not allowed:raise ScopeError('No upstream targets are authorized for this CLI invocation.')
            streams[key]=allowed
    base=streams.get('targets') or streams.get('url') or streams.get('domain') or streams.get('file') or [None]
    batches=[[v] for v in base] if scalar else [base]
    if len(batches)>config['max_hosts']:raise ScopeError('Scalar CLI fan-out exceeds the run host cap.')
    for batch in batches:
        with tempfile.TemporaryDirectory(prefix='cli-',dir=store.root/'jobs') as directory:
            work=Path(directory).resolve();selected=dict(streams)
            if scalar:
                for typ in ('targets','url','domain','file'):
                    if selected.get(typ):selected[typ]=batch
            context,targets,prepared=prepare_context(selected,data,work,store,config,tool,run_id=rid)
            argv=build_command(tool,data,context,pin)
            from .http_routing import cli_routing, resolve_routing, CLI_PROXY_FLAGS
            argv+=cli_routing(tool,config)
            if tool['id'] in CLI_PROXY_FLAGS and (config.get('http_routing') or {}).get('ca_input_id'):
                resolved=resolve_routing(config['http_routing'],store)
                if config.get('http_routing_binding') and resolved.ca_sha256!=config['http_routing_binding']['ca_sha256']:
                    raise ScopeError('Proxy CA changed after execution review.')
                import ssl
                bundle=work/'trusted-http-ca.pem'
                bundle.write_text(''.join(ssl.DER_cert_to_PEM_cert(cert) for cert in resolved.context.get_ca_certs(binary_form=True)))
                for key in ('SSL_CERT_FILE','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE'):env[key]=str(bundle)
            if tool['id']=='hakrawler':argv=[pin['path']]+[a for a in argv[1:] if a not in ('-url',context.get('targets'))]
            stdin_lines=targets if tool['adapter']['stdin'] or tool['id']=='hakrawler' else []
            stdin_data=('\n'.join(stdin_lines)+'\n').encode() if stdin_lines else b''
            env['HOME']=str(work/'home');env['USERPROFILE']=env['HOME'];Path(env['HOME']).mkdir(exist_ok=True)
            if tool['id']=='gf':
                patterns=json.loads((Path(__file__).parent/'gf-patterns.json').read_text())
                pattern=context['pattern']
                if pattern not in patterns:raise ScopeError('Use a bundled named GF pattern: '+', '.join(patterns))
                destination=Path(env['HOME'])/'.gf';destination.mkdir()
                (destination/(pattern+'.json')).write_text(json.dumps(patterns[pattern]))
            input_paths={p for p in work.rglob('*') if p.is_file()}
            proc=None;buffers={'stdout':bytearray(),'stderr':bytearray()};failure=None;returncode=None
            async def read_stream(name,reader):
                while chunk:=await reader.read(65536):
                    buffers[name].extend(chunk)
                    if len(buffers[name])>MAX_STREAM:raise CLIError('CLI output exceeded the stream limit.')
            async def monitor_disk():
                while True:
                    size=0
                    for file in work.rglob('*'):
                        with contextlib.suppress(FileNotFoundError):
                            if file.is_file() and not file.is_symlink():size+=file.stat().st_size
                    if size>40_000_000:raise CLIError('CLI workspace exceeded the disk limit.')
                    await asyncio.sleep(.1)
            while True:
                await ctl.gate.wait()
                async with ctl.lock:
                    if ctl.cancelled:raise asyncio.CancelledError()
                    if not ctl.gate.is_set():continue
                    if ctl.cli_invocations>=config['max_cli_invocations']:raise ScopeError('CLI invocation budget exhausted.')
                    if digest(pin['path'])!=pin['sha256']:raise ScopeError('Executable changed after preflight.')
                    ctl.cli_invocations+=1;number=ctl.cli_invocations
                    store.event(rid,'cli.admitted',{'node_id':nid,'tool_id':tool['id'],'invocation_number':number,'traffic':tool['adapter']['traffic']})
                    break
            try:
                proc=await asyncio.create_subprocess_exec(*argv,cwd=work,env=env,stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=os.name=='posix')
                ctl.processes[proc.pid]=proc
                # A pause/cancel racing with process creation is handled before stdin is delivered.
                if ctl.cancelled:raise asyncio.CancelledError()
                if not ctl.gate.is_set():pause_processes(ctl,True)
                async def feed():
                    try:
                        proc.stdin.write(stdin_data);await proc.stdin.drain()
                    except (BrokenPipeError,ConnectionResetError):pass
                    finally:proc.stdin.close()
                disk=asyncio.create_task(monitor_disk())
                readers=[asyncio.create_task(read_stream('stdout',proc.stdout)),asyncio.create_task(read_stream('stderr',proc.stderr)),asyncio.create_task(feed())]
                try:
                    async with asyncio.timeout(min(data.get('timeout',120),config['max_seconds'])):
                        done=asyncio.create_task(proc.wait())
                        watched=[done,disk,*readers]
                        while not done.done():
                            finished,_=await asyncio.wait(watched,return_when=asyncio.FIRST_COMPLETED)
                            for task in finished:
                                if task.cancelled():raise asyncio.CancelledError()
                                error=task.exception()
                                if error:raise error
                            watched=[t for t in watched if not t.done()]
                        returncode=done.result()
                        await stop_process(proc)
                        await asyncio.gather(*readers)
                finally:
                    disk.cancel();await asyncio.gather(disk,return_exceptions=True)
                    await stop_process(proc)
                    for task in readers:
                        if not task.done():task.cancel()
                    await asyncio.gather(*readers,return_exceptions=True)
            except BaseException as exc:
                failure=type(exc).__name__
                if proc:await stop_process(proc)
                raise
            finally:
                if proc:
                    await close_pipes(proc)
                    ctl.processes.pop(proc.pid,None)
                record={'tool_id':tool['id'],'invocation_number':number,'command':argv,'exit_code':returncode,'error':failure,'stdout':redact(bytes(buffers['stdout'][:MAX_STREAM]).decode(errors='replace')),'stderr':redact(bytes(buffers['stderr'][:MAX_STREAM]).decode(errors='replace')),'native_requests_counted':False,'http_capture':('external_proxy_history' if (config.get('http_routing') or {}).get('mode')=='proxy' and tool['id'] in CLI_PROXY_FLAGS else 'tool_output_only')}
                aid=store.artifact(rid,f'cli-{number}-{tool["id"]}.json',record,node_id=nid);invocation_artifacts.append(aid)
                store.event(rid,'cli.finished',{'node_id':nid,'tool_id':tool['id'],'artifact_id':aid,'exit_code':returncode,'error':failure})
            if returncode!=0:raise CLIError(f'{tool["id"]} exited with status {returncode}; inspect its CLI artifact.')
            generated=[];size=0
            for file in sorted(work.rglob('*')):
                if file.is_symlink():continue
                if not file.is_file() or file in input_paths or 'home' in file.relative_to(work).parts:continue
                size+=file.stat().st_size
                if len(generated)>=MAX_OUTPUT_FILES or size>MAX_OUTPUT_TOTAL:raise CLIError('CLI output files exceeded the artifact limit.')
                raw=file.read_bytes()
                fid=store.artifact(rid,f'{nid}/{file.relative_to(work)}',{'encoding':'base64','bytes':base64.b64encode(raw).decode(),'size':len(raw)},node_id=nid)
                generated.append({'id':fid,'name':str(file.relative_to(work))})
            text=record['stdout']
            if tool['output_mode']=='file' and not generated:raise CLIError('Tool completed without its declared file output.')
            result=output_streams(tool,text,generated)
            for typ,values in result.items():total_streams[typ].extend(values)
    return [{'catalog_streams':{k:list(dict.fromkeys(v)) for k,v in total_streams.items()},'tool_id':tool['id'],'invocation_artifact_ids':invocation_artifacts,'evidence_status':'OBSERVATION'}]
