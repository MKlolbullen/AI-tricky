import React,{useEffect,useState} from 'react';
import {api} from './api.mjs';
import {nativeNode} from './native-workflow.mjs';
import IdentityNodeSettings from './IdentityNodeSettings';

export default function IdentityWorkspace({onLoad}){
 const [catalog,setCatalog]=useState(null),[error,setError]=useState(''),[collection,setCollection]=useState(false),[analysis,setAnalysis]=useState(false),[message,setMessage]=useState('');
 const [data,setData]=useState({kind:'native_identity_paths',identity_scope:{platform:'ad',domain:'',tenant_id:''},inputRefs:{},start_ids:[],goal_ids:[],max_depth:4});
 useEffect(()=>{api('/identity/catalog').then(setCatalog).catch(e=>setError(e.message))},[]);
 const load=()=>{const kinds=['native_scope',...(collection?['native_identity_collect']:[]),'native_identity_paths',...(analysis?['native_team']:[]),'native_summary'];
  const nodes=kinds.map((kind,i)=>nativeNode('identity-'+i,kind,{x:i*240,y:130}));
  for(const node of nodes){if(node.data.kind.startsWith('native_identity_')){
    const isCollector=node.data.kind==='native_identity_collect';node.data={...node.data,identity_scope:data.identity_scope,
     ...(isCollector?{profile_id:data.profile_id||(data.identity_scope.platform==='ad'?'impacket-ad-users':'azurehound-entra'),identity_auth:data.identity_auth||{},inputRefs:data.inputRefs}:
       {inputRefs:collection?{}:data.inputRefs,start_ids:data.start_ids||[],goal_ids:data.goal_ids||[],max_depth:data.max_depth??4})};
   }if(node.data.kind==='native_team')node.data.roles=[data.identity_scope.platform==='ad'?'ad_identity':'entra_identity','poc'];}
  const graph={schema:'offsecs-u-ai.workflow/v1',nodes,edges:nodes.slice(1).map((n,i)=>({id:'identity-edge-'+i,source:nodes[i].id,target:n.id,label:nodes[i].data.output,type:'smoothstep'})),parallelism:2};
  onLoad(graph);setMessage('Identity workflow loaded on the canvas. No collection or model call was started.');};
 return <section aria-label="Identity assessment workspace"><div className="section-intro"><div><h3>AD and Entra attack-path review</h3><p>Collect with fixed profiles or import graph evidence, inspect candidate paths and hand evidence to identity specialists.</p></div></div>
 <div className="local-setup-grid"><section><label className="http-toggle"><input type="checkbox" checked={collection} onChange={e=>{setCollection(e.target.checked);setData(d=>({...d,kind:e.target.checked?'native_identity_collect':'native_identity_paths',inputRefs:{}}))}}/><span>Collect directory evidence with a fixed tool profile</span></label>
 <IdentityNodeSettings data={data} onChange={patch=>setData(d=>({...d,...patch}))}/>
 <label className="http-toggle"><input type="checkbox" checked={analysis} onChange={e=>setAnalysis(e.target.checked)}/><span>Add identity specialist and PoC-plan agent review</span></label>
 <p>Agent review uses the selected model configuration and captured evidence only. Collection requires CLI execution, explicit scope and registered authentication inputs. Graph analysis sends no target requests.</p>
 <button className="primary" onClick={load}>Load identity workflow on canvas</button>{message&&<p role="status">{message}</p>}{error&&<p role="alert">{error}</p>}</section>
 <aside className="runtime-card"><h3>Agent tool coverage</h3>{catalog?.profiles.map(p=><article key={p.id}><strong>{p.name}</strong><p>{p.description}</p><small>{p.readiness.replaceAll('_',' ')} · fixed collection profile · context required</small><p><small>CLI contract tested with {p.cli_contract_tested_release}; live compatibility remains unverified.</small></p></article>)}<h4>External tools and import sources</h4>{catalog?.references.map(p=><article key={p.id}><a href={p.source} target="_blank" rel="noreferrer">{p.name}</a><p>{p.description}</p><small>External / operator-led; no execution adapter</small></article>)}</aside></div></section>;
}
