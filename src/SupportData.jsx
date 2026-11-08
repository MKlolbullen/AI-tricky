import React,{useEffect,useState} from 'react';
import {api} from './api.mjs';

export default function SupportData({workflow,onBound,onInstalled,compact=false}){
 const [status,setStatus]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState(''),[message,setMessage]=useState('');
 const refresh=()=>api('/support-data').then(setStatus).catch(e=>setError(e.message));
 useEffect(()=>{refresh()},[]);
 const install=async id=>{setBusy(true);setError('');setMessage('');try{setStatus(await api('/support-data/install/'+id,{}));setMessage('Support inputs installed and registered. Select their bindings before running.');onInstalled?.()}catch(e){setError(e.message)}finally{setBusy(false)}};
 const bind=async()=>{setBusy(true);setError('');setMessage('');try{const r=await api('/support-data/bind',{graph:workflow});onBound?.(r.graph);setMessage(`${r.bindings.length} missing bindings filled; ${r.missing.length} still need an input. Existing selections and connected inputs are preserved.`)}catch(e){setError(e.message)}finally{setBusy(false)}};
 return <section className="scope-summary" aria-label="Support data packages">
  <strong>Templates, resolvers and wordlists</strong>
  <p>Bundled: seven Nuclei HTTP exposure templates, Trickest trusted/public resolvers and small path/DNS wordlists. GF patterns and payload lists already ship with the application.</p>
  <button className="secondary" disabled={busy||!status} onClick={()=>install('bundled')}>Install bundled support files</button>{' '}
  {workflow&&<button className="secondary" disabled={busy||!status} onClick={bind}>Use installed support files</button>}
  {(busy||message)&&<p role="status">{busy?'Preparing and verifying support inputs…':message}</p>}{error&&<p role="alert">{error}</p>}
  {!compact&&status&&<><p>Optional pinned downloads keep the full upstream data and register bounded template categories. Installing adds data only; it does not run assessment tools.</p>
   {status.remote.map(p=><div className="runtime-row" key={p.id}><span><strong>{p.name}</strong><small>{p.revision.slice(0,12)} · {p.installed?`${p.inputs.length} registered inputs`:'Not installed'}</small></span><button className="secondary" disabled={busy||p.installed} onClick={()=>install(p.id)}>{p.installed?'Installed':'Install '+p.name}</button></div>)}
   <details><summary>Installed packs and adapter requirements</summary>{status.bundled.map(p=><p key={p.id}>{p.name} · {p.installed?'installed':'not installed'} · {p.revision.slice(0,12)}</p>)}<table><thead><tr><th>Tool</th><th>Required input</th><th>Available default</th></tr></thead><tbody>{status.requirements.flatMap(t=>t.bindings.map(b=><tr key={t.tool_id+b.slot}><td>{t.tool_id}</td><td>{b.slot}</td><td>{b.input_id?'Installed':b.role?'Install or register':'Supply a tool-specific input'}</td></tr>))}</tbody></table></details>
   <small>The installed catalog contains {status.catalog.tools} tools and {status.catalog.migrated_workflows} migrated workflows. Full Trickest catalog parity and arbitrary Trickest exports are not implemented.</small>
  </>}
 </section>;
}
