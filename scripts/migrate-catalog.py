"""Reproducible conversion of the pinned MIT mini-tricky catalog (no network)."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
# Single source of truth for the terminal-sink accepted-type sets.
from backend.catalog import OUTPUT_INPUTS, MERGE_INPUTS
SOURCE=ROOT/'third-party/mini-tricky'
BLOCKED={
 'interlace':'Requires an arbitrary command string. Use typed graph fan-out instead.',
 'rush':'Requires an arbitrary command string. Use typed graph fan-out instead.',
 'notify':'Requires an explicit notification destination contract.',
 'interactsh':'Requires an explicit callback/OAST account contract.',
 'kube-bench':'Requires a Kubernetes cluster/account scope contract.',
 'kubeaudit':'Requires a Kubernetes cluster/account scope contract.',
 'popeye':'Requires a Kubernetes cluster/account scope contract.',
 'prowler':'Requires a cloud account scope contract.',
 'scoutsuite':'Requires a cloud account scope contract.',
 'cloudsploit':'Requires a cloud account scope contract.',
}
STDIN={'qsreplace','uro','unfurl','gf','notify','hakcheckurl','subjs','aquatone','gxss','kxss','httprobe','hakip2host','cariddi'}
PASSIVE={'subfinder','amass','assetfinder','findomain','chaos','waybackurls','theharvester','shodan-cli','censys','spiderfoot','gau','waymore','paramspider','cloudenum','asnmap','smap','urlfinder','github-subdomains','gitdorker','crtsh','github-endpoints','gitlab-subdomains','nrich','uncover','bbot'}
OFFLINE={'anew','qsreplace','uro','unfurl','jq-filter','gf','gopherus','alterx','dnsgen','gotator','mapcidr','jsluice','gitleaks','semgrep','syft','grype','retire','dsieve'}
FILES={'gowitness':[], 'aquatone':[], 'wapiti':['wapiti-report.json'], 'zaproxy':['zap-report.json']}


def convert_graph(raw,tools):
 nodes=[]
 for n in raw['nodes']:
  kind=n['kind'];params=n.get('params') or {}
  if kind=='tool':
   spec=tools[n['tool_id']];data={'kind':'catalog_tool','toolId':spec['id'],'inputs':spec['inputs'],'outputs':spec['outputs'],'output':spec['outputs'][0] if spec['outputs'] else 'report','params':params}
  elif kind=='variable':
   typ=n.get('variable_type','targets');data={'kind':'catalog_source','sourceType':typ,'inputs':[],'outputs':[typ],'output':typ,'value':n.get('value') or ''}
  elif kind=='output':data={'kind':'catalog_output','inputs':list(OUTPUT_INPUTS),'outputs':['report'],'output':'report'}
  elif kind=='merge':
   typ=params.get('output_type','targets')
   if typ not in MERGE_INPUTS:raise ValueError(f'Unsupported merge output type: {typ}')
   data={'kind':'catalog_merge','inputs':list(MERGE_INPUTS[typ]),'outputs':[typ],'output':typ}
  elif kind=='payload':data={'kind':'catalog_payload','inputs':[],'outputs':['wordlist'],'output':'wordlist','params':params}
  else:raise ValueError(f'Unsupported source node kind: {kind}')
  data.update(title=n['label'],description='mini-tricky catalog',timeout=120,retries=0,status='pending',result='Not run')
  nodes.append({'id':n['id'],'type':'tool','position':n.get('position') or {'x':len(nodes)*230,'y':130},'data':data})
 by_id={n['id']:n for n in nodes}
 edges=[]
 for i,e in enumerate(raw['edges']):
  src_type=(e.get('source_handle') or ('out:'+by_id[e['source']]['data']['output'])).removeprefix('out:')
  # Sink nodes now declare real accepted types instead of a blanket 'any', so a
  # pinned 'in:any' edge into a sink is normalised to the concrete source type
  # (the pinned templates.yaml is hash-checked and must not be edited).
  tgt_kind=by_id[e['target']]['data']['kind']
  raw_tgt=e.get('target_handle')
  tgt_type=src_type if tgt_kind in ('catalog_output','catalog_merge') and (raw_tgt in (None,'in:any')) else (raw_tgt or 'in:'+src_type).removeprefix('in:')
  edges.append({'id':e.get('id') or f'edge-{i}','source':e['source'],'target':e['target'],
                'sourceHandle':'out:'+src_type,'targetHandle':'in:'+tgt_type,'label':src_type,'type':'smoothstep'})
 return {'schema':'offsecs-u-ai.workflow/v1','nodes':nodes,'edges':edges,'parallelism':4}


def generate():
 tools=[];templates=[]
 for f in ('tools.yaml','tools.nextgen.yaml'):tools+=yaml.safe_load((SOURCE/f).read_text())['tools']
 for f in ('templates.yaml','templates.nextgen.yaml'):templates+=yaml.safe_load((SOURCE/f).read_text())['templates']
 policy=yaml.safe_load((SOURCE/'capabilities.yaml').read_text())
 extras=yaml.safe_load((SOURCE/'tools.nextgen.yaml').read_text()).get('capability_policy',{})
 for k in ('category_defaults','tools'):policy.setdefault(k,{}).update(extras.get(k,{}))
 for t in tools:
  tid=t['id'];meta={**policy.get('category_defaults',{}).get(t['category'],{}),**policy.get('tools',{}).get(tid,{})}
  t['risk']=meta.get('risk','medium');t['capabilities']=meta.get('capabilities',[]);t['secrets']=meta.get('secrets',[])
  t['adapter']={'mode':'blocked' if tid in BLOCKED else 'cli','reason':BLOCKED.get(tid),'stdin':tid in STDIN,'traffic':'offline' if tid in OFFLINE else 'passive' if tid in PASSIVE else 'target','file_outputs':FILES.get(tid,[])}
  t['provenance']='MKlolbullen/mini-tricky · MIT';t['repository']='https://github.com/MKlolbullen/mini-tricky';t['targets']=t['inputs'];t['sourceCatalog']='mini-tricky'
 by_id={t['id']:t for t in tools}
 workflows=[]
 for w in templates:
  graph=convert_graph(w['graph'],by_id)
  blocked=sorted({n['data']['toolId'] for n in graph['nodes'] if n['data']['kind']=='catalog_tool' and by_id[n['data']['toolId']]['adapter']['mode']=='blocked'})
  workflows.append({**{k:v for k,v in w.items() if k!='graph'},**graph,'sourceCatalog':'mini-tricky','targets':sorted({n['data']['sourceType'] for n in graph['nodes'] if n['data']['kind']=='catalog_source'}),'blocked_tools':blocked,'provenance':'MKlolbullen/mini-tricky · MIT','source':'https://github.com/MKlolbullen/mini-tricky','license':'MIT'})
 return {'source':json.loads((SOURCE/'SOURCE.json').read_text()),'source_hashes':{f:hashlib.sha256((SOURCE/f).read_bytes()).hexdigest() for f in ['tools.yaml','tools.nextgen.yaml','templates.yaml','templates.nextgen.yaml','capabilities.yaml']},'tools':tools,'workflows':workflows}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');args=p.parse_args()
 result=generate();body=json.dumps(result,ensure_ascii=False,indent=2)+'\n';path=ROOT/'src/mini-tricky-catalog.json'
 if args.check:
  if not path.exists() or path.read_text()!=body:raise SystemExit('Catalog drift: run scripts/migrate-catalog.py')
 else:path.write_text(body)
 print(f"{len(result['tools'])} tools, {len(result['workflows'])} workflows; {sum(t['adapter']['mode']=='blocked' for t in result['tools'])} tools have explicit context restrictions.")
