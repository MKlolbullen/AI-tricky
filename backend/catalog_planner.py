"""Bounded capability planning over migrated typed tool transitions."""
from collections import deque
import re

from .catalog import TOOLS
from .scope import ScopeError

RISK={'passive':0,'low':1,'medium':2,'high':3,'critical':4}


def plan_catalog(goal,source_type='domain',target_type='findings',max_risk='medium'):
    if source_type not in {'domain','targets','url','file','folder','query','sbom'} or target_type not in {'targets','url','findings','sbom'} or max_risk not in RISK:
        raise ScopeError('Unsupported capability planning types or risk level.')
    words=set(re.findall(r'[a-z0-9]+',goal.lower()))
    queue=deque([(source_type,[],set(),0)]);results=[];expanded=0
    while queue and expanded<1500:
        current,path,used,cost=queue.popleft();expanded+=1
        if len(path)>=4:continue
        for tool in TOOLS.values():
            if tool['id'] in used or tool['adapter']['mode']=='blocked' or current not in tool['inputs'] or RISK.get(tool['risk'],2)>RISK[max_risk]:continue
            for output in tool['outputs']:
                step={'tool_id':tool['id'],'input_type':current,'output_type':output}
                score=cost+10+RISK.get(tool['risk'],2)*10+(0 if tool['adapter']['traffic']=='offline' else 3)
                if tool['id'].lower() in words or tool['name'].lower() in words:score-=8
                steps=path+[step]
                if output==target_type:results.append((score,steps));continue
                if output in {'targets','url','sbom'} and len(queue)<5000:queue.append((output,steps,used|{tool['id']},score))
    if not results:raise ScopeError('No supported catalog path exists within the chosen risk and step limits.')
    _,steps=min(results,key=lambda r:(r[0],len(r[1]),[s['tool_id'] for s in r[1]]))
    def source(nid,typ,x,y=130):return {'id':nid,'type':'tool','position':{'x':x,'y':y},'data':{'kind':'catalog_source','title':typ+' input','sourceType':typ,'value':'','inputs':[],'outputs':[typ],'output':typ,'timeout':120,'retries':0,'status':'pending'}}
    nodes=[source('plan-source',source_type,0)];edges=[];previous=nodes[0]['id'];previous_type=source_type
    for i,step in enumerate(steps):
        tool=TOOLS[step['tool_id']];nid=f'plan-tool-{i+1}'
        nodes.append({'id':nid,'type':'tool','position':{'x':(i+1)*230,'y':130},'data':{'kind':'catalog_tool','toolId':tool['id'],'title':tool['name'],'inputs':tool['inputs'],'outputs':tool['outputs'],'output':tool['outputs'][0],'params':{},'timeout':min(tool.get('timeout_seconds',300),3600),'retries':0,'status':'pending'}})
        edges.append({'id':f'plan-edge-{i+1}','source':previous,'target':nid,'sourceHandle':'out:'+previous_type,'targetHandle':'in:'+step['input_type'],'label':previous_type,'type':'smoothstep'})
        if 'wordlist' in tool['inputs'] and any('{wordlist_file}' in s for s in tool['command']):
            sid=f'plan-words-{i+1}';nodes.append(source(sid,'wordlist',(i+1)*230,380));edges.append({'id':sid+'-edge','source':sid,'target':nid,'sourceHandle':'out:wordlist','targetHandle':'in:wordlist','label':'wordlist','type':'smoothstep'})
        previous,previous_type=nid,step['output_type']
    nodes.append({'id':'plan-output','type':'tool','position':{'x':(len(steps)+1)*230,'y':130},'data':{'kind':'catalog_output','title':'Assessment artifacts','inputs':['any'],'outputs':['report'],'output':'report','timeout':120,'retries':0,'status':'pending'}})
    edges.append({'id':'plan-output-edge','source':previous,'target':'plan-output','sourceHandle':'out:'+previous_type,'targetHandle':'in:any','label':previous_type,'type':'smoothstep'})
    graph={'schema':'offsecs-u-ai.workflow/v1','nodes':nodes,'edges':edges,'parallelism':4}
    from .workflows import validate_workflow
    validate_workflow(graph,live=True)
    return {'graph':graph,'goal':goal,'planner':'catalog-capabilities','model_called':False,'adapters':[TOOLS[s['tool_id']]['name'] for s in steps],'explanation':'Deterministic typed capability plan from the migrated catalog. Preflight still checks binaries, input bindings, credentials and execution settings.','steps':steps}
