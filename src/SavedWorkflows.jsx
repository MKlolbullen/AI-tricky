import React,{useEffect,useState} from 'react';
import {api} from './api.mjs';
export default function SavedWorkflows({workflow,onLoad,onStarter}){
 const [list,setList]=useState([]),[name,setName]=useState('My workflow'),[identity,setIdentity]=useState(null),[error,setError]=useState(''),[message,setMessage]=useState(''),[busy,setBusy]=useState(false);
 const refresh=()=>api('/workflows').then(setList).catch(e=>setError(e.message));
 useEffect(()=>{refresh()},[]);
 const save=async(copy=false)=>{setBusy(true);setError('');setMessage('');try{
  const saved=await api('/workflows',{name,graph:workflow,...(!copy&&identity?{id:identity.id,expected_revision:identity.revision}:{})});
  setIdentity(saved);setMessage(`Saved ${saved.name} · revision ${saved.revision}`);await refresh();
 }catch(e){setError(e.message)}finally{setBusy(false)}};
 const load=async id=>{setBusy(true);try{const saved=await api('/workflows/'+id);onLoad(saved.graph);setIdentity(saved);setName(saved.name);setMessage(`Loaded ${saved.name}`)}catch(e){setError(e.message)}finally{setBusy(false)}};
 return <section className="saved-workflows"><div className="section-intro"><div><h3>Saved workflows</h3><p>Keep editable graphs and reload them between sessions. Every run keeps its own immutable graph snapshot.</p></div><button className="secondary" onClick={onStarter}>Load native starter</button></div>
 {error&&<div className="local-error" role="alert">{error}</div>}{message&&<p role="status">{message}</p>}
 <form className="target-entry" onSubmit={e=>{e.preventDefault();save()}}><label htmlFor="workflow-name">Workflow name</label><div><input id="workflow-name" required maxLength={120} value={name} onChange={e=>setName(e.target.value)}/><button className="primary" disabled={busy||!workflow||!name.trim()}>Save current canvas</button>{identity&&<button type="button" className="secondary" disabled={busy} onClick={()=>save(true)}>Save as copy</button>}</div></form>
 <div className="saved-list">{list.map(w=><button className="history-row" disabled={busy} key={w.id} onClick={()=>load(w.id)}><span><strong>{w.name}</strong><small>Revision {w.revision} · {new Date(w.updated).toLocaleString()}</small></span><span>Load on canvas</span></button>)}{!list.length&&<p>No saved workflows. Load the native starter or save your current canvas.</p>}</div>
 </section>;
}
