"""Typed data routing and preflight for the migrated catalog."""
import base64
import html
import json
from pathlib import Path
import re
from urllib.parse import quote

from .catalog import CATALOG, CATALOG_KINDS, ROOT, TOOLS, registered_path, scoped_lines
from .cli_runner import execute_cli, pin_binary
from .scope import ScopeError, parse_target


def incoming_streams(graph,nid,outputs):
    streams={}
    for edge in graph['edges']:
        if edge['target']!=nid:continue
        source=next(n for n in graph['nodes'] if n['id']==edge['source'])
        typ=(edge.get('sourceHandle') or 'out:'+source['data']['output']).removeprefix('out:')
        target=(edge.get('targetHandle') or 'in:'+typ).removeprefix('in:')
        for row in outputs.get(edge['source'],[]):
            packet=row.get('catalog_streams')
            values=packet.get(typ,[]) if packet is not None else [r['target'] for r in outputs[edge['source']] if 'target' in r] if typ=='targets' else []
            key=typ if target=='any' else target
            streams.setdefault(key,[]).extend(values)
            if packet is None:break
    return {k:list(dict.fromkeys(v)) for k,v in streams.items()}


def source_values(data,config):
    typ=data['sourceType']
    if typ in ('file','folder','wordlist','sbom'):
        if not data.get('inputId'):raise ScopeError('Select a registered file or folder input.')
        return ['input:'+data['inputId']]
    value=data.get('value','').strip()
    if typ=='query':
        if not value:raise ScopeError('Enter an explicit search query.')
        return [value]
    values=value.splitlines() if value else [t for t in config['targets'] if typ=='targets' or (typ=='domain' and parse_target(t).kind=='domain') or (typ=='url' and parse_target(t).kind=='url')]
    if not values:raise ScopeError(f'No selected {typ} targets are available for this source.')
    allowed,rejected=scoped_lines(values,typ,config)
    if rejected:raise ScopeError('A source value is outside the selected run scope.')
    if typ=='domain' and any(parse_target(v).kind!='domain' for v in allowed):raise ScopeError('Domain source needs a plain domain scope.')
    if typ=='url' and any(not v.startswith(('http://','https://')) for v in allowed):raise ScopeError('URL source needs an explicit HTTP(S) URL scope.')
    return allowed


def preflight(graph,config,store,*,check_binaries=True,credentials=frozenset(),node_ids=None):
    issues=[];binaries={};snapshots={}
    for n in graph['nodes']:
        if node_ids is not None and n['id'] not in node_ids:continue
        data=n['data'];kind=data['kind'];reason=[]
        if kind=='catalog_source':
            try:
                source_values(data,config)
                if data.get('inputId'):
                    path=registered_path(store,data['inputId'],'folder' if data['sourceType']=='folder' else 'file')
                    snapshots[data['inputId']]=store.input(data['inputId'])
            except ScopeError as exc:reason.append(str(exc))
        if kind=='catalog_tool':
            tool=TOOLS[data['toolId']]
            if tool['adapter']['mode']=='blocked':reason.append(tool['adapter']['reason'])
            for key in tool.get('secrets',[]):
                if key not in config.get('cli_credential_keys',[]) or key not in credentials:reason.append(f'Configure and select the provider credential variable {key}.')
            if not config.get('allow_cli'):reason.append('Enable catalog CLI execution for this run.')
            for typ,identifier in data.get('inputRefs',{}).items():
                try:registered_path(store,identifier,'folder' if typ in ('folder','templates') else 'file');snapshots[identifier]=store.input(identifier)
                except ScopeError as exc:reason.append(str(exc))
            incoming={(e.get('targetHandle') or 'in:'+next(x for x in graph['nodes'] if x['id']==e['source'])['data']['output']).removeprefix('in:') for e in graph['edges'] if e['target']==n['id']}
            placeholders={m for token in tool['command'] for m in re.findall(r'\{([^}]+)\}',token)}
            for field,typ in [('wordlist_file','wordlist'),('paths_file','paths_file'),('folder','folder'),('sbom_file','sbom')]:
                if field in placeholders and typ not in incoming and typ not in data.get('inputRefs',{}):reason.append(f'Requires a connected or registered {typ} input.')
            if tool['id'] in ('nuclei','nuclei-takeover','jaeles') and not data.get('inputRefs',{}).get('templates'):reason.append('Register and bind a reviewed templates/signatures folder for this adapter.')
            if tool['id'] in ('massdns','shuffledns') and not data.get('inputRefs',{}).get('resolvers'):reason.append('Register and bind a resolvers file for this DNS adapter.')
            if 'exploit_type' in placeholders and not data.get('params',{}).get('exploit_type'):reason.append('Choose a named exploit_type context.')
            if check_binaries and tool['adapter']['mode']!='blocked':
                try:binaries[tool['id']]=pin_binary(tool)
                except ScopeError as exc:reason.append(str(exc))
        if reason:issues.append({'node_id':n['id'],'reasons':list(dict.fromkeys(reason))})
    return {'ready':not issues,'issues':issues,'cli_binaries':binaries,'input_snapshots':snapshots,'catalog_tools':len({n['data']['toolId'] for n in graph['nodes'] if n['data']['kind']=='catalog_tool' and (node_ids is None or n['id'] in node_ids)}),'accounting':'Native operations count HTTP/TCP admissions. CLI operations count process launches; tool-internal network requests are not measured or limited by the native request cap.'}


async def execute_catalog_node(rid,nid,data,streams,config,ctl,store):
    kind=data['kind']
    if kind=='catalog_source':
        values=source_values(data,config)
        if data.get('inputId'):registered_path(store,data['inputId'],'folder' if data['sourceType']=='folder' else 'file')
        return [{'catalog_streams':{data['sourceType']:values},'evidence_status':'INPUT'}]
    if kind=='catalog_payload':
        params=data.get('params',{});lines=[]
        for category in params.get('payload_types','').split(','):
            lines.extend((ROOT/'third-party/mini-tricky/payloads'/f'{category}.txt').read_text().splitlines())
        encoded=[]
        for value in lines:
            if not value.strip():continue
            for encoding in params.get('encodings','raw').split(','):
                encoded.append(value if encoding=='raw' else quote(value,safe='') if encoding=='url' else quote(quote(value,safe=''),safe='') if encoding=='double_url' else base64.b64encode(value.encode()).decode() if encoding=='base64' else html.escape(value,quote=True))
        return [{'catalog_streams':{'wordlist':list(dict.fromkeys(encoded))},'evidence_status':'INPUT'}]
    if kind=='catalog_merge':
        values=sorted(set(v for values in streams.values() for v in values))
        return [{'catalog_streams':{data['output']:values},'evidence_status':'OBSERVATION'}]
    if kind=='catalog_output':
        return [{'catalog_streams':streams,'report':f'Collected {sum(len(v) for v in streams.values())} records across {len(streams)} typed streams. See upstream CLI artifacts for provenance.','evidence_status':'OBSERVATION'}]
    return await execute_cli(rid,nid,data,streams,config,ctl,store)
