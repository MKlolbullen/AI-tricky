import React,{useState,useEffect} from 'react';
import {api,downloadJSON} from './api.mjs';
export function useLiveRun(id){
 const [state,setState]=useState(null);
 useEffect(()=>{setState(null);if(!id)return;let alive=true,timer;
  const read=async()=>{try{
   const run=await api('/runs/'+id);
   const [nodes,artifacts]=await Promise.all([api(`/runs/${id}/nodes`),api(`/runs/${id}/artifacts`)]);
   let events=[],page=[];
   do{page=await api(`/runs/${id}/events?after=${events.at(-1)?.seq||0}`);events.push(...page)}while(page.length===500);
   if(alive){setState({run,nodes,artifacts,events});if(['queued','running','paused'].includes(run.status))timer=setTimeout(read,1000)}
  }catch(e){if(alive){setState(s=>({...s,error:e.message}));timer=setTimeout(read,2000)}}};
  read();return()=>{alive=false;clearTimeout(timer)};
 },[id]);return state;
}
export default function LiveRunDock({state,id,onOpen,onExit}){
 const [tab,setTab]=useState('Events'),[artifact,setArtifact]=useState(null),[error,setError]=useState('');
 useEffect(()=>{setArtifact(null);setError('')},[id]);
 const content=async a=>{try{setArtifact({name:a.name,data:await api('/artifacts/'+a.id)})}catch(e){setError(e.message)}};
 const run=state?.run;
 return <section className="dock live-dock"><div className="run-strip"><strong>Local run · {id.slice(0,8)}</strong><span className="run-pill">{run?.status||'Loading…'}</span><span>{run?.result?.request_count??state?.events.filter(e=>['http.admitted','tcp.admitted'].includes(e.kind)).length??0} native operations · {run?.result?.cli_invocation_count??state?.events.filter(e=>e.kind==='cli.admitted').length??0} CLI launches</span><button className="secondary" onClick={onOpen}>Run details & controls</button><button onClick={onExit}>Return to design</button></div><div className="dock-tabs">{['Events','Artifacts'].map(t=><button key={t} className={tab===t?'active':''} onClick={()=>{setTab(t);setArtifact(null)}}>{t}{t==='Artifacts'?` (${state?.artifacts.length||0})`:''}</button>)}</div><div className="dock-content">{(error||state?.error)&&<p role="alert">{error||state.error}</p>}{artifact?<><button className="secondary" onClick={()=>setArtifact(null)}>Back to artifacts</button><button className="secondary" onClick={()=>downloadJSON(artifact.name,artifact.data)}>Download JSON</button><pre className="live-artifact">{JSON.stringify(artifact.data,null,2)}</pre></>:tab==='Events'?(state?.events||[]).map(e=><div className="log" key={e.seq}><time>{new Date(e.time).toLocaleTimeString()}</time><code>{e.data.node_id||'run'}</code><span>{e.kind} {e.data.url||e.data.error||''}</span></div>):(state?.artifacts||[]).map(a=><button className="output-row" key={a.id} onClick={()=>content(a)}><strong>{a.name}</strong><span>{a.node_id?`Node ${a.node_id}`:'Run report'}</span></button>)}</div></section>;
}
