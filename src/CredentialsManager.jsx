import React,{useEffect,useState,useCallback} from 'react';
import {Key,ArrowSquareOut,CheckCircle,Info,Trash,Eye,EyeSlash} from '@phosphor-icons/react';
import {api} from './api.mjs';

export default function CredentialsManager({onSaved}){
 const [providers,setProviders]=useState([]);
 const [draft,setDraft]=useState({});
 const [reveal,setReveal]=useState({});
 const [busy,setBusy]=useState('');
 const [error,setError]=useState('');
 const [message,setMessage]=useState('');

 const load=useCallback(()=>api('/credentials').then(d=>setProviders(d.providers)).catch(e=>setError(e.message)),[]);
 useEffect(()=>{load()},[load]);

 const apply=async(updates,label)=>{
  setBusy(label);setError('');setMessage('');
  try{
   const d=await api('/credentials',{updates});
   setProviders(d.providers);
   // Only clear a field whose current value still matches what we just sent, so
   // a value the user typed while the request was in flight is preserved.
   setDraft(p=>{const n={...p};for(const k of Object.keys(updates)){if((n[k]??'').trim()===(updates[k]??''))delete n[k]}return n});
   setMessage(`${label} updated · stored locally`);
   onSaved?.();
  }catch(e){setError(e.message)}finally{setBusy('')}
 };

 const saveProvider=p=>{
  const updates={};
  for(const v of p.variables){const val=draft[v.name];if(val!==undefined&&val.trim()!=='')updates[v.name]=val.trim()}
  if(!Object.keys(updates).length){setError('Enter a value before saving.');return}
  apply(updates,p.name);
 };

 return <section className="credentials">
  <div className="section-intro"><div><h3>Passive source API keys</h3><p>Keys for passive data providers used by catalog tools. Enter a key to store it for this machine.</p></div></div>
  <div className="notice"><Info size={20}/><span>Values are stored under your local data directory with owner-only permissions and are never shown again here. A key reaches a tool only when that tool declares it and a run selects its credential binding. Keys set in the environment are shown but managed outside the app.</span></div>
  {error&&<p role="alert" className="local-error">{error}</p>}
  {message&&<p role="status" className="credentials-saved"><CheckCircle size={16} weight="fill"/>{message}</p>}
  <div className="credentials-grid">
   {providers.map(p=><article className="credential-card" key={p.id}>
    <header><div className="credential-head"><Key size={20}/><strong>{p.name}</strong></div><a href={p.docs} target="_blank" rel="noreferrer" title={`Open ${p.name} API settings`}>Get key<ArrowSquareOut size={14}/></a></header>
    <p className="credential-desc">{p.description}</p>
    {p.variables.map(v=><div className="credential-field" key={v.name}>
     <label htmlFor={`cred-${v.name}`}>{v.label} <code>{v.name}</code></label>
     <div className="credential-input">
      <input id={`cred-${v.name}`} type={reveal[v.name]?'text':'password'} autoComplete="off" spellCheck={false}
             value={draft[v.name]??''} placeholder={v.configured?'Saved · enter a new value to replace':'Not set'}
             onChange={e=>setDraft(d=>({...d,[v.name]:e.target.value}))}/>
      <button type="button" className="icon-btn" aria-label={reveal[v.name]?'Hide value':'Show typed value'} onClick={()=>setReveal(r=>({...r,[v.name]:!r[v.name]}))}>{reveal[v.name]?<EyeSlash size={17}/>:<Eye size={17}/>}</button>
     </div>
     <div className="credential-meta">
      {v.configured
        ? <span className={`credential-status ${v.source}`}><CheckCircle size={14} weight="fill"/>Configured · {v.source==='stored'?'stored locally':'from environment'}</span>
        : <span className="credential-status none">Not set</span>}
      {v.source==='stored'&&<button type="button" className="credential-clear" disabled={!!busy} onClick={()=>apply({[v.name]:''},p.name)}><Trash size={13}/>Clear</button>}
     </div>
     <small className="credential-usage">{v.consumed_by.length?`Used by: ${v.consumed_by.join(', ')}`:'Stored for future use; no installed adapter declares this variable yet.'}</small>
    </div>)}
    <button className="primary wide" disabled={!!busy} onClick={()=>saveProvider(p)}>{busy===p.name?'Saving…':`Save ${p.name} key${p.variables.length>1?'s':''}`}</button>
   </article>)}
  </div>
 </section>;
}
