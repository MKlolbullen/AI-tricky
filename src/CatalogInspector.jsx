import React,{useEffect,useState} from 'react';
import {api} from './api.mjs';
import {catalogTools} from './catalog-contracts.mjs';
import ToolArguments from './ToolArguments';
export default function CatalogInspector({node,edges,onChange}){
 const data=node.data,tool=catalogTools.get(data.toolId);
 const [inputs,setInputs]=useState([]),[detail,setDetail]=useState(null),[error,setError]=useState('');
 useEffect(()=>{
  let current=true;
  const report=failure=>{if(current)setError(failure.message)};
  api('/inputs').then(values=>{if(current)setInputs(values)}).catch(report);
  if(tool)api('/catalog/tools/'+tool.id).then(value=>{if(current)setDetail(value)}).catch(report);
  return ()=>{current=false};
 },[node.id,tool?.id]);
 const connected=new Set(edges.filter(edge=>edge.target===node.id).map(edge=>edge.targetHandle?.slice(3)));
 const params=data.params||{};
 const change=(key,value)=>{const next={...params};if(value===undefined||value==='')delete next[key];else next[key]=value;onChange({params:next})};
 const reference=(typ,value)=>{const refs={...data.inputRefs};if(value)refs[typ]=value;else delete refs[typ];onChange({inputRefs:refs})};
 return <section className="catalog-inspector">{error&&<p role="alert">{error}</p>}{tool?<><p>{tool.description}</p><span className="tag">{tool.risk} · {detail?.readiness.state||'Checking executable'}</span>{tool.adapter.reason&&<div className="notice">{tool.adapter.reason}</div>}<p className="compact-help">{tool.adapter.traffic} adapter · executable: <code>{tool.command[0]}</code>. Binary presence does not establish version compatibility.</p>
 <ToolArguments tool={tool} detail={detail} params={params} change={change} inputs={inputs} bindings={data.inputRefs || {}}
  reference={reference} connected={connected} loading={!detail && !error}/>

 </>:data.kind==='catalog_source'?<><label>Source type<select value={data.sourceType} onChange={e=>onChange({sourceType:e.target.value,inputs:[],outputs:[e.target.value],output:e.target.value,inputId:undefined,value:''})}>{['domain','targets','url','file','folder','wordlist','query','sbom'].map(t=><option key={t}>{t}</option>)}</select></label>{['file','folder','wordlist','sbom'].includes(data.sourceType)?<label>Registered input<select value={data.inputId||''} onChange={e=>onChange({inputId:e.target.value||undefined})}><option value="">Choose an input</option>{inputs.filter(i=>data.sourceType==='folder'?i.kind==='folder':i.kind==='file').map(i=><option key={i.id} value={i.id}>{i.name}</option>)}</select><small>Add files and folders in Local workspace → Inputs.</small></label>:<label>{data.sourceType==='query'?'Search query':'Optional scope subset'}<textarea rows={4} value={data.value||''} onChange={e=>onChange({value:e.target.value})} placeholder={data.sourceType==='query'?'Explicit provider query':'Blank uses selected run targets of this type'}/><small>Entered values must remain inside the run scope. Discovery output does not authorize active tests.</small></label>}</>:data.kind==='catalog_merge'?<label>Merged output type<select value={data.output} onChange={e=>onChange({output:e.target.value,outputs:[e.target.value]})}><option>targets</option><option>url</option></select></label>:data.kind==='catalog_payload'?<><label>Payload categories<input value={params.payload_types||''} onChange={e=>change('payload_types',e.target.value)}/><small>LFI,XSS,SQLI,RCE,SSRF,SSTI</small></label><label>Encodings<input value={params.encodings||'raw'} onChange={e=>change('encodings',e.target.value)}/><small>raw,url,double_url,base64,html</small></label></>:<p>Collects typed upstream outputs and keeps their node-linked artifacts.</p>}<div className="port-info"><span>Inputs</span><code>{data.inputs.join(', ')||'Source'}</code></div><div className="port-info"><span>Outputs</span><code>{data.outputs.join(', ')}</code></div></section>;
}
