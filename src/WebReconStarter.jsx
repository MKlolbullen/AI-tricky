import React,{useState} from 'react';
import {api} from './api.mjs';

export default function WebReconStarter({disabled,onLoad}){
 const [busy,setBusy]=useState(false),[error,setError]=useState('');
 const load=async(fuzz=false)=>{setBusy(true);setError('');try{onLoad(await api('/workflow-starters/web-recon'+(fuzz?'?fuzz=true':'')))}catch(e){setError(e.message)}finally{setBusy(false)}};
 return <section className="scope-summary" aria-label="Web reconnaissance starter">
  <strong>Web reconnaissance starter</strong>
  <p>Selected enumeration domains → subfinder + assetfinder → unique hosts → httprobe → katana → scoped web source captures. Requires selected domain/wildcard scopes and installed CLI tools. Loading makes no target requests.</p>
  <button className="secondary" disabled={disabled||busy} onClick={()=>load()}>Load web recon workflow</button>{' '}
  <button className="secondary" disabled={disabled||busy} onClick={()=>load(true)}>Load web recon with path fuzzing</button>
  <small>The fuzzing branch requires a registered wordlist. Native source collection defaults to 10 pages, 40 assets and depth 2; adjust the collector node in the canvas.</small>
  {error&&<p role="alert">{error}</p>}
 </section>;
}
