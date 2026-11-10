"""Bounded AD / Entra graph evidence and candidate paths. No network or execution."""
import base64
from collections import defaultdict, deque
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import zipfile

from pydantic import BaseModel, ConfigDict, Field
from typing import Literal
from .catalog import registered_path
from .scope import ScopeError, parse_target

SCHEMA='ai-tricky.identity-graph/v1'
MAX_BYTES=10_000_000
MAX_EXPANDED=25_000_000
MAX_NODES=10000
MAX_EDGES=30000


def identity_workflow(graph):
    nodes=graph.get('nodes',[])
    allowed={'native_scope','native_identity_collect','native_identity_paths','native_team','native_cai','native_summary'}
    return any(n['data']['kind'].startswith('native_identity_') for n in nodes) and all(n['data']['kind'] in allowed or n['data']['kind']=='catalog_source' and n['data'].get('sourceType')=='file' for n in nodes)

RULES={
 'MemberOf':('Membership may carry group rights.','Verify effective membership, nesting and scope.'),
 'GenericAll':('Control over the destination object is reported.','Verify effective ACLs, deny entries and protected-object behavior.'),
 'WriteDacl':('ACL modification rights are reported.','Changing the ACL requires a separately reviewed action.'),
 'WriteOwner':('Ownership modification rights are reported.','Verify owner rights and protected objects before any separately reviewed change.'),
 'AddMember':('Group membership modification rights are reported.','Verify the actual writable attribute and privileged-group restrictions.'),
 'ForceChangePassword':('Password reset rights are reported.','Account mutation requires a separate action review.'),
 'AllowedToAct':('Resource-based delegation configuration is reported.','Verify effective principals, SPNs and Kerberos prerequisites; no impersonation performed.'),
 'AllowedToDelegate':('Constrained delegation configuration is reported.','Verify service SPNs, protocol transition and authentication prerequisites.'),
 'AdminTo':('Administrative access is reported by the collector.','Verify current access without assuming credentials or sessions.'),
 'Owns':('Entra ownership is reported.','Verify object type, role restrictions and effective permissions; ownership alone is not a proven compromise.'),
 'HasRole':('An active directory role assignment is reported.','Verify active state, directory scope, role permissions, PIM and access policies.'),
 'DCSync':('Both directory replication rights are reported for the same principal.','Verify effective ACLs and domain scope. No replication or credential extraction is performed.'),
}

class IdentityScope(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    platform:Literal['ad','entra']='ad'
    domain:str=Field(default='',max_length=253)
    tenant_id:str=Field(default='',max_length=36)


def scope_value(data,*,complete=True):
    try:value=IdentityScope.model_validate(data.get('identity_scope') or {}).model_dump()
    except ValueError:raise ScopeError('Invalid identity scope fields.') from None
    if value['domain']:
        target=parse_target(value['domain'])
        if target.kind!='domain':raise ScopeError('Identity domain must be an exact DNS domain.')
        value['domain']=target.host
    if value['tenant_id']:
        if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',value['tenant_id']):
            raise ScopeError('Entra scope requires a tenant UUID.')
        value['tenant_id']=value['tenant_id'].lower()
    if complete and (not value['domain'] or value['platform']=='entra' and not value['tenant_id']):
        raise ScopeError('Enter an exact identity domain and, for Entra, an explicit tenant UUID.')
    if value['platform']=='ad' and value['tenant_id']:raise ScopeError('AD scope cannot contain an Entra tenant UUID.')
    return value


def check_scope(data,config):
    scope=scope_value(data)
    if not any(t.kind=='domain' and t.host==scope['domain'] for t in map(parse_target,config['targets'])):
        raise ScopeError('Select the exact identity domain as an entered run target; web URLs and wildcard selectors do not grant directory scope.')
    return scope


def validate_node(data):
    if any(key in data for key in ('command','argv','environment','env','shell','cwd')) or data.get('params'):
        raise ScopeError('Identity profiles do not accept arbitrary commands, flags or environment variables.')
    scope_value(data,complete=False)
    for key,maximum in [('start_ids',10),('goal_ids',20)]:
        values=data.get(key,[])
        if not isinstance(values,list) or len(values)>maximum or any(not isinstance(v,str) or not 1<=len(v)<=200 or any(ord(c)<32 for c in v) for v in values):
            raise ScopeError('Identity path endpoints must be bounded object ID lists.')
    depth=data.get('max_depth',4)
    if type(depth) is not int or not 1<=depth<=6:raise ScopeError('Identity path depth must be 1–6.')
    refs=data.get('inputRefs',{})
    allowed={'graph'} if data['kind']=='native_identity_paths' else {'kerberos_cache','access_token'}
    if not isinstance(refs,dict) or set(refs)-allowed or any(not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',v) for v in refs.values()):
        raise ScopeError('Invalid registered identity input bindings.')


def bound_input(store,identifier,config):
    path=registered_path(store,identifier,'file');raw=path.read_bytes()
    if len(raw)>MAX_BYTES:raise ScopeError('Identity input exceeds 10 MB.')
    digest=hashlib.sha256(raw).hexdigest()
    snapshot=config.get('input_snapshots',{}).get(identifier)
    pins=config.get('recovery_input_pins',{}) if config.get('workflow_recovery') else config.get('proposal_input_pins',{}) if config.get('proposal_execution') else {}
    if snapshot and snapshot['sha256']!=digest or identifier in pins and pins[identifier]['sha256']!=digest:
        raise ScopeError('Identity input changed after review.')
    return raw


def strict_json(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            if key in result:raise ValueError()
            result[key]=value
        return result
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
    except (ValueError,UnicodeError,RecursionError):raise ScopeError('Identity evidence must be valid JSON without duplicate keys or non-finite numbers.') from None


def documents(raw):
    if len(raw)>MAX_BYTES:raise ScopeError('Identity export exceeds 10 MB.')
    if not raw.startswith(b'PK'):return [('export.json',strict_json(raw))]
    result=[];total=0;names=set()
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if len(archive.infolist())>32:raise ScopeError('Import at most 32 JSON files per ZIP.')
            for item in archive.infolist():
                parts=item.filename.rstrip('/').split('/')
                if any(p in ('','..','.') for p in parts) or item.filename.startswith('/') or '\\' in item.filename or ':' in item.filename or (item.external_attr>>16)&0o170000==0o120000 or item.filename in names:
                    raise ScopeError('Unsafe or duplicate identity ZIP entry.')
                names.add(item.filename)
                if item.is_dir():continue
                if PurePosixPath(item.filename).suffix.lower()!='.json':raise ScopeError('Identity ZIPs may contain JSON exports only.')
                total+=item.file_size
                if total>MAX_EXPANDED or item.file_size>MAX_BYTES:raise ScopeError('Identity ZIP expansion exceeds limits.')
                with archive.open(item) as source:body=source.read(MAX_BYTES+1)
                if len(body)!=item.file_size:raise ScopeError('Identity ZIP entry exceeds its declared size.')
                result.append((item.filename,strict_json(body)))
    except (zipfile.BadZipFile,RuntimeError,NotImplementedError):raise ScopeError('Unsupported identity ZIP archive.') from None
    if not result:raise ScopeError('No JSON exports in identity ZIP.')
    return result


def object_id(value):
    if not isinstance(value,str) or not 1<=len(value)<=200 or any(ord(c)<32 for c in value):raise ScopeError('Invalid identity object ID.')
    return value.upper()


def analyze_exports(exports,scope,start_ids=(),goal_ids=(),max_depth=4):
    nodes={};edges={};gaps=[];pending=[];enumerations=[];excluded=0;unsupported=0
    scope_key=scope['tenant_id'] if scope['platform']=='entra' else scope['domain']
    def node(identifier,label,kind,environment,aid):
        nonlocal excluded
        if str(environment).lower()!=scope_key.lower():excluded+=1;return
        identifier=object_id(identifier)
        row={'id':identifier,'label':str(label or identifier)[:250],'kind':str(kind)[:40],'scope':scope_key,'evidence_ids':[aid]}
        if identifier in nodes:
            if nodes[identifier]['kind']!=row['kind']:raise ScopeError('Conflicting identity object kinds in imported exports.')
            nodes[identifier]['evidence_ids']=sorted(set(nodes[identifier]['evidence_ids']+[aid]));return
        if len(nodes)>=MAX_NODES:raise ScopeError('Identity export exceeds 10,000 objects.')
        nodes[identifier]=row
    def edge(source,target,kind,aid):
        nonlocal unsupported
        if kind not in RULES:unsupported+=1;return
        pending.append((object_id(source),object_id(target),kind,aid))
        if len(pending)>MAX_EDGES:raise ScopeError('Identity export exceeds 30,000 supported relationships.')
    for aid,raw in exports:
        for filename,doc in documents(raw):
            if not isinstance(doc,dict):raise ScopeError('Identity export must be a JSON object.')
            if doc.get('schema')==SCHEMA:
                if scope_value({'identity_scope':doc.get('scope')})!=scope:raise ScopeError('Normalized graph scope differs from the reviewed identity scope.')
                for row in doc.get('nodes',[]):
                    if not isinstance(row,dict):raise ScopeError('Invalid identity node.')
                    node(row.get('id'),row.get('label'),row.get('kind','principal'),row.get('scope',scope_key),aid)
                for row in doc.get('edges',[]):
                    if not isinstance(row,dict):raise ScopeError('Invalid identity relationship.')
                    edge(row.get('source'),row.get('target'),row.get('kind'),aid)
            elif isinstance(doc.get('data'),list) and doc.get('meta',{}).get('type')=='azure':
                if scope['platform']!='entra':raise ScopeError('AzureHound requires an Entra scope.')
                for row in doc['data']:
                    data=row.get('data',{});kind=row.get('kind')
                    if not isinstance(data,dict):raise ScopeError('Invalid AzureHound record.')
                    tenant=str(data.get('tenantId','')).lower()
                    object_kinds=('AZUser','AZGroup','AZRole','AZApp','AZServicePrincipal','AZDevice')
                    if (tenant and tenant!=scope['tenant_id']) or (kind in object_kinds and not tenant):excluded+=1;continue
                    if kind in object_kinds:
                        # AzureHound app ownership uses appId; preserve that key rather than linking an unrelated service principal.
                        identifier=data.get('appId') if kind=='AZApp' else data.get('id')
                        node(identifier,data.get('displayName'),kind,tenant,aid)
                    elif kind=='AZGroupMember':
                        for member in data.get('members',[data]):edge(member.get('member',{}).get('id'),member.get('groupId',data.get('groupId')),'MemberOf',aid)
                    elif kind in ('AZGroupOwner','AZAppOwner','AZServicePrincipalOwner'):
                        key={'AZGroupOwner':'groupId','AZAppOwner':'appId','AZServicePrincipalOwner':'servicePrincipalId'}[kind]
                        for owner in data.get('owners',[data]):edge(owner.get('owner',{}).get('id'),owner.get(key,data.get(key)),'Owns',aid)
                    elif kind=='AZRoleAssignment':
                        for assignment in data.get('roleAssignments',[]):
                            if assignment.get('directoryScopeId')!='/':unsupported+=1;continue
                            edge(assignment.get('principalId'),assignment.get('roleDefinitionId',data.get('roleDefinitionId')),'HasRole',aid)
                    else:unsupported+=1
                gaps.append('AzureHound subset: objects, membership, ownership and active tenant-wide role assignments. PIM eligibility, custom role semantics, ARM and app consent are not traversed.')
            elif isinstance(doc.get('data'),list) and doc.get('meta',{}).get('type') in ('users','groups','computers','domains','ous','gpos','containers'):
                if scope['platform']!='ad':raise ScopeError('BloodHound AD exports require an AD scope.')
                kind=doc['meta']['type']
                for row in doc['data']:
                    props=row.get('Properties',{});identifier=row.get('ObjectIdentifier')
                    if not isinstance(props,dict):raise ScopeError('Invalid BloodHound properties.')
                    if str(props.get('domain','')).lower()!=scope['domain']:excluded+=1;continue
                    node(identifier,props.get('name'),kind,props.get('domain'),aid)
                    if row.get('PrimaryGroupSID'):edge(identifier,row['PrimaryGroupSID'],'MemberOf',aid)
                    for member in row.get('Members',[]):edge(member.get('ObjectIdentifier'),identifier,'MemberOf',aid)
                    for principal in row.get('AllowedToAct',[]):edge(principal.get('ObjectIdentifier'),identifier,'AllowedToAct',aid)
                    for principal in row.get('AllowedToDelegate',[]):edge(identifier,principal.get('ObjectIdentifier'),'AllowedToDelegate',aid)
                    rights=defaultdict(set)
                    for ace in row.get('Aces',[]):
                        principal=ace.get('PrincipalSID');right=ace.get('RightName')
                        if right in ('GetChanges','GetChangesAll'):rights[principal].add(right)
                        elif right in RULES:edge(principal,identifier,right,aid)
                        else:unsupported+=1
                    if kind=='domains':
                        for principal,grants in rights.items():
                            if {'GetChanges','GetChangesAll'}<=grants:edge(principal,identifier,'DCSync',aid)
                gaps.append('BloodHound subset: membership, selected ACL rights and delegation. Sessions, trust traversal, AD CS and implicit rights are not inferred.')
            elif doc.get('schema')=='ai-tricky.identity-collection/v1':
                if doc.get('scope')!=scope:raise ScopeError('Collection scope differs from the reviewed identity scope.')
                enumerations.append({'profile_id':str(doc.get('profile_id',''))[:100],'evidence_id':aid,'text':str(doc.get('stdout',''))[:12000]})
                gaps.append('Impacket collection is enumeration evidence, not a relationship graph. Import BloodHound or normalized graph data to compute paths.')
            else:raise ScopeError('Unsupported identity export: use BloodHound JSON/ZIP, AzureHound JSON or ai-tricky.identity-graph/v1.')
    for source,target,kind,aid in pending:
        if source not in nodes or target not in nodes:excluded+=1;continue
        key=(source,target,kind)
        if key in edges:edges[key]['evidence_ids']=sorted(set(edges[key]['evidence_ids']+[aid]));continue
        edges[key]={'source':source,'target':target,'kind':kind,'evidence_ids':[aid],'prerequisite':RULES[kind][1]}
    starts=[object_id(v) for v in start_ids];goals={object_id(v) for v in goal_ids}
    if any(v not in nodes for v in [*starts,*goals]):raise ScopeError('Path endpoints must name imported objects in the selected identity scope.')
    paths=[];expanded=0;limited=False;adj=defaultdict(list)
    for row in edges.values():adj[row['source']].append(row)
    queue=deque((start,[start],[]) for start in starts)
    while queue:
        source,visited,steps=queue.popleft();expanded+=1
        if expanded>20000 or len(queue)>10000:limited=True;break
        if source in goals and steps:
            evidence_ids=sorted({aid for step in steps for aid in step['evidence_ids']}|{aid for key in visited for aid in nodes[key]['evidence_ids']})
            paths.append({'nodes':visited,'steps':steps,'evidence_ids':evidence_ids,'status':'CANDIDATE_PATH','requires':'Assumes control of the selected start principal and satisfaction of every listed prerequisite.','executed':False})
            if len(paths)>=30:limited=bool(queue);break
            continue
        if len(steps)>=max_depth:continue
        for step in sorted(adj[source],key=lambda e:(e['kind'],e['target'])):
            if step['target'] not in visited:queue.append((step['target'],visited+[step['target']],steps+[step]))
    if not starts or not goals:gaps.append('Choose explicit start and goal object IDs to compute candidate paths; object presence never implies ownership or compromise.')
    if excluded:gaps.append(f'{excluded} out-of-scope objects or unresolved relationships were excluded from path traversal.')
    if unsupported:gaps.append(f'{unsupported} unsupported or conditional relationships were not traversed.')
    if limited:gaps.append('Path search hit its bound; results are incomplete.')
    return {'schema':'ai-tricky.identity-analysis/v1','scope':scope,'nodes':list(nodes.values()),'edges':list(edges.values()),'paths':paths,'enumerations':enumerations,
            'coverage_limits':list(dict.fromkeys(gaps))+['Imported/collected relationships are assertions, not verified exploitation. No live checks or environment changes are performed by path analysis.'],
            'search':{'max_depth':max_depth,'max_paths':30,'expanded':min(expanded,20000),'limited':limited},'evidence_status':'CANDIDATE','confirmed':False}


def execute_paths(rid,nid,data,values,config,store):
    scope=check_scope(data,config);references=[];exports=[];imports=[]
    if data.get('inputRefs',{}).get('graph'):references.append('input:'+data['inputRefs']['graph'])
    for row in values:
        references.extend(row.get('catalog_streams',{}).get('file',[]))
    references=list(dict.fromkeys(references))
    if not references or len(references)>16:raise ScopeError('Bind 1–16 registered or same-run identity export files.')
    total=0
    for index,reference in enumerate(references):
        if reference.startswith('input:'):
            raw=bound_input(store,reference[6:],config)
            aid='pending-input-'+str(index)
            imports.append((aid,index,reference[6:],raw))
        elif reference.startswith('artifact:'):
            aid=reference[9:]
            try:
                meta=store.artifact_metadata(aid)
                from .recovery import checked_reused_content
                content=checked_reused_content(store,aid)
                if meta['run_id']!=rid or content.get('encoding')!='base64':raise ValueError()
                raw=base64.b64decode(content['bytes'],validate=True)
            except (KeyError,ValueError,AttributeError):raise ScopeError('Identity artifact must be a same-run captured file.') from None
        else:raise ScopeError('Identity evidence requires registered inputs or same-run artifacts.')
        total+=len(raw)
        if total>MAX_EXPANDED:raise ScopeError('Combined identity exports exceed 25 MB.')
        exports.append((aid,raw))
    result=analyze_exports(exports,scope,data.get('start_ids',[]),data.get('goal_ids',[]),data.get('max_depth',4))
    replacements={}
    # Validate the entire import before persisting raw files. A credential file
    # accidentally selected as a graph must not become an evidence artifact.
    for temporary,index,identifier,raw in imports:
        replacements[temporary]=store.artifact(rid,f'identity-import-{nid}-{index}.json',{'encoding':'base64','bytes':base64.b64encode(raw).decode(),'size':len(raw),'input_id':identifier,'sha256':hashlib.sha256(raw).hexdigest()},node_id=nid)
    for row in [*result['nodes'],*result['edges'],*result['paths']]:
        row['evidence_ids']=[replacements.get(value,value) for value in row['evidence_ids']]
    for row in result['enumerations']:row['evidence_id']=replacements.get(row['evidence_id'],row['evidence_id'])
    aid=store.artifact(rid,'identity-analysis-'+nid+'.json',result,node_id=nid)
    preview={'scope':scope,'objects':len(result['nodes']),'relationships':len(result['edges']),'paths':result['paths'][:5],
             'objects_preview':result['nodes'][:20],'enumerations':result['enumerations'][:1],'coverage_limits':result['coverage_limits'],
             'preview_limit':'Full graph, paths and provenance are retained in the linked analysis artifact; agent previews are bounded.'}
    return [{'kind':'identity_evidence','artifact_id':aid,'identity_scope':scope,'body':json.dumps(preview)[:16000],
             'report':f'Identity evidence: {len(result["nodes"])} objects, {len(result["edges"])} relationships, {len(result["paths"])} candidate paths. No paths were executed.',
             'evidence_status':'CANDIDATE','confirmed':False}]
