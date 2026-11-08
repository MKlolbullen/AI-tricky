"""Pinned tool contracts, legacy-graph conversion, and explicit input registration."""
import hashlib
import ipaddress
import json
import os
import re
import shutil
from pathlib import Path
from urllib.parse import urlsplit

from .scope import ScopeError, authorize, network_hosts, parse_target

ROOT=Path(__file__).resolve().parent.parent
CATALOG=json.loads((ROOT/'src/mini-tricky-catalog.json').read_text())
TOOLS={t['id']:t for t in CATALOG['tools']}
CATALOG_KINDS={'catalog_tool','catalog_source','catalog_merge','catalog_output','catalog_payload'}
SOURCE_TYPES={'domain','targets','url','file','folder','wordlist','query','sbom'}
# Imported flags retain their metadata, but cannot override filesystem, code,
# callbacks, transport policy or credential boundaries in this adapter.
# Ambiguous short flags are restricted only where they designate a path/proxy/etc.
# Normal bounded numeric flags stay usable.
DANGEROUS_NAMES={'--os-shell','--os-cmd','--dump','--malicious','--headless','-headless','--config','--kubeconfig','--report-dir','--provider-config','-provider-config','--callback','--blind','--follow-redirects','-fr','--script','-sC','-A','-H','--headers','--custom-payload','--proxy','-proxy','-token','-server','-o','-oJ','-rL','--include'}
SENSITIVE_WORDS=('file','path','directory','folder','proxy','cookie','header','payload','callback','config','script','wordlist','command','token','password','secret')


def blocked_flag(arg):
    flag=arg['flag']
    if flag in DANGEROUS_NAMES:return 'Requires a separate path, credential, callback or execution-policy binding.'
    text=(arg.get('label','')+' '+arg.get('description','')).lower()
    if arg['type']=='string' and any(w in text for w in SENSITIVE_WORDS):return 'Register file inputs or use a dedicated context binding instead.'
    if 'redirect' in text:return 'Redirect policy cannot be changed by a catalog flag.'
    return None


def validate_params(tool,data):
    params=data.get('params',{})
    if not isinstance(params,dict) or len(params)>80:raise ScopeError('Invalid catalog parameters.')
    known={a['flag']:a for a in tool.get('args',[])}
    for key,value in params.items():
        if key in ('pattern','exploit_type'):
            if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',value):raise ScopeError('Invalid named pattern or exploit type.')
            continue
        arg=known.get(key)
        if arg is None:raise ScopeError(f'Unknown parameter {key} for {tool["id"]}.')
        if blocked_flag(arg):raise ScopeError(f'Parameter {key} needs a dedicated context binding.')
        if arg['type']=='flag':
            if type(value) is not bool and value not in ('__flag__',''):raise ScopeError('Boolean flag values must be true/false.')
        elif arg['type'] in ('int','float'):
            if isinstance(value,bool):raise ScopeError('Numeric flags cannot use booleans.')
            try:number=float(value)
            except (ValueError,TypeError):raise ScopeError('Invalid numeric parameter.') from None
            if not 0<=number<=1_000_000 or (arg['type']=='int' and not number.is_integer()):raise ScopeError('Numeric parameter outside supported bounds.')
        elif not isinstance(value,str) or len(value)>2048 or any(ord(c)<32 for c in value) or value.startswith('-'):
            raise ScopeError('Invalid string parameter.')
    refs=data.get('inputRefs',{})
    if not isinstance(refs,dict) or any(k not in ('wordlist','file','folder','sbom','paths_file','resolvers','resolvers_trusted','templates') or not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',v) for k,v in refs.items()):
        raise ScopeError('Invalid registered input references.')


def contract(data):
    kind=data.get('kind')
    if any(k in data for k in ('command','executable','environment','env','shell','cwd')):raise ScopeError('Execution commands and environment are server-owned.')
    if kind=='catalog_tool':
        tid=data.get('toolId');tool=TOOLS.get(tid) if isinstance(tid,str) else None
        if not tool:raise ScopeError('Unknown catalog tool.')
        validate_params(tool,data)
        inputs,outputs=tool['inputs'],tool['outputs']
    elif kind=='catalog_source':
        typ=data.get('sourceType')
        if not isinstance(typ,str) or typ not in SOURCE_TYPES:raise ScopeError('Unknown source type.')
        if not isinstance(data.get('value',''),str) or len(data.get('value',''))>16000:raise ScopeError('Invalid source value.')
        if data.get('inputId') is not None and (not isinstance(data['inputId'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',data['inputId'])):raise ScopeError('Invalid input reference.')
        inputs,outputs=[],[typ]
    elif kind=='catalog_merge':
        output=data.get('output')
        if output not in ('targets','url'):raise ScopeError('Merge output must be targets or url.')
        inputs,outputs=['any'],[output]
    elif kind=='catalog_output':inputs,outputs=['any'],['report']
    elif kind=='catalog_payload':
        params=data.get('params',{})
        if not isinstance(params,dict) or set(params)-{'payload_types','encodings'}:raise ScopeError('Invalid payload source parameters.')
        for field,allowed in [('payload_types',{'LFI','XSS','SQLI','RCE','SSRF','SSTI'}),('encodings',{'raw','url','double_url','base64','html'})]:
            value=params.get(field,'raw' if field=='encodings' else '')
            if not isinstance(value,str) or not set(value.split(','))<=allowed:raise ScopeError('Unsupported payload category or encoding.')
        inputs,outputs=[],['wordlist']
    else:raise ScopeError('Unknown catalog node.')
    if data.get('inputs')!=inputs or data.get('outputs')!=outputs or data.get('output')!=(outputs[0] if outputs else 'report'):
        raise ScopeError('Modified catalog socket contract.')
    return inputs,outputs


def convert_mini(value):
    raw=value.get('graph',value) if isinstance(value,dict) else None
    if not isinstance(raw,dict) or not isinstance(raw.get('nodes'),list) or not isinstance(raw.get('edges'),list) or len(raw['nodes'])>500 or len(raw['edges'])>2000:
        raise ScopeError('Invalid mini-tricky graph.')
    nodes=[]
    for n in raw['nodes']:
        if not isinstance(n,dict):raise ScopeError('Invalid mini-tricky node.')
        kind=n.get('kind');params=n.get('params') or {}
        if kind=='tool':
            t=TOOLS.get(n.get('tool_id')) if isinstance(n.get('tool_id'),str) else None
            if not t:raise ScopeError('Unknown mini-tricky tool.')
            data={'kind':'catalog_tool','toolId':t['id'],'inputs':t['inputs'],'outputs':t['outputs'],'output':t['outputs'][0],'params':params}
        elif kind=='variable':
            typ=n.get('variable_type','targets');data={'kind':'catalog_source','sourceType':typ,'inputs':[],'outputs':[typ],'output':typ,'value':n.get('value') or ''}
        elif kind=='output':data={'kind':'catalog_output','inputs':['any'],'outputs':['report'],'output':'report'}
        elif kind=='merge':
            typ=params.get('output_type','targets');data={'kind':'catalog_merge','inputs':['any'],'outputs':[typ],'output':typ}
        elif kind=='payload':data={'kind':'catalog_payload','inputs':[],'outputs':['wordlist'],'output':'wordlist','params':params}
        else:raise ScopeError('Scripts, conditions, loops and modules require dedicated migration contracts.')
        data.update(title=n.get('label') or n.get('tool_id') or kind,description='mini-tricky import',timeout=120,retries=0,status='pending',result='Not run')
        nodes.append({'id':n.get('id'),'type':'tool','position':n.get('position') or {'x':len(nodes)*230,'y':130},'data':data})
    edges=[]
    for i,e in enumerate(raw['edges']):
        if not isinstance(e,dict):raise ScopeError('Invalid mini-tricky edge.')
        edges.append({'id':e.get('id') or f'edge-{i}','source':e.get('source'),'target':e.get('target'),'sourceHandle':e.get('source_handle'),'targetHandle':e.get('target_handle'),'type':'smoothstep','label':str(e.get('source_handle') or 'out:any').removeprefix('out:')})
    return {'schema':'offsecs-u-ai.workflow/v1','nodes':nodes,'edges':edges,'parallelism':4}


def tool_readiness(tool):
    binary=shutil.which(tool['command'][0])
    reason=tool['adapter']['reason']
    return {'id':tool['id'],'adapter':tool['adapter']['mode'],'binary_found':bool(binary),'state':'restricted' if reason else 'available' if binary else 'missing_binary','reason':reason,'binary':str(Path(binary).resolve()) if binary else None,'identity_verified':False}


def registered_path(store,identifier,expected=None):
    try:entry=store.input(identifier)
    except KeyError:raise ScopeError('Registered input not found.') from None
    path=Path(entry['path'])
    if path.is_symlink() or path.resolve()!=path or not path.exists():raise ScopeError('Registered input path changed or no longer exists.')
    if expected=='folder':
        if not path.is_dir():raise ScopeError('A registered folder is required.')
        if entry.get('sha256'):
            from .cli_runner import input_fingerprint
            if input_fingerprint(path,'folder')!=entry['sha256']:
                raise ScopeError('Pinned support folder changed; install a new version or register a separate reviewed input.')
    elif not path.is_file():raise ScopeError('A registered file is required.')
    # Files are bound to their registered content, not just a reusable pathname.
    if path.is_file() and (path.stat().st_size>10_000_000 or hashlib.sha256(path.read_bytes()).hexdigest()!=entry['sha256']):
        raise ScopeError('Registered file changed; register the current file again.')
    return path


def scoped_lines(lines,typ,config,*,discovery=False):
    scope=[parse_target(t) for t in config['targets']];result=[];rejected=[]
    for value in dict.fromkeys(lines):
        endpoint=False
        try:
            if typ=='url' or '://' in value:
                req=authorize(value,scope);host=req.host
            else:
                try:parsed=parse_target(value);host=parsed.host
                except ScopeError:
                    endpoint_url=urlsplit('http://'+value)
                    if not endpoint_url.hostname or endpoint_url.path or endpoint_url.query or endpoint_url.fragment or not endpoint_url.port or endpoint_url.username:raise
                    host=endpoint_url.hostname;network_hosts(host,scope,config['max_hosts']);endpoint=True
            if host:
                try:ip=ipaddress.ip_address(host)
                except ValueError:ip=None
                if ip and (ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved):raise ScopeError('Blocked special-use destination.')
            if typ=='url' or '://' in value:authorize(value,scope)
            elif not endpoint:network_hosts(value,scope,config['max_hosts'])
            result.append(value)
        except (ScopeError,ValueError):
            if discovery:
                # Passive enumeration may discover subdomains of an entered domain,
                # but never turns those discoveries into active authorization.
                try:
                    t=parse_target(value)
                    if t.kind=='domain' and any(s.kind in ('domain','wildcard') and (t.host==s.host or t.host.endswith('.'+s.host)) for s in scope):result.append(value);continue
                except (ScopeError,ValueError):pass
            rejected.append(value)
    return result,rejected
