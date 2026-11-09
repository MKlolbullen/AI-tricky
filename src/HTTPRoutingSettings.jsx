import React,{useEffect,useState} from 'react';
import {api} from './api.mjs';

export const defaultRouting={mode:'direct',proxy_url:'http://127.0.0.1:8080',ca_input_id:null};

export default function HTTPRoutingSettings({value=defaultRouting,onChange,disabled=false}){
 const [inputs,setInputs]=useState([]),[error,setError]=useState('');
 useEffect(()=>{api('/inputs').then(setInputs).catch(e=>setError(e.message))},[]);
 const change=(key,next)=>onChange({...defaultRouting,...value,[key]:next});
 return <section className="scope-summary" aria-label="Target HTTP routing"><strong>Target HTTP routing and recording</strong>
 <fieldset disabled={disabled}><label>HTTP routing<select value={value.mode} onChange={e=>change('mode',e.target.value)}><option value="direct">Direct · save native exchanges</option><option value="proxy">Burp / HTTP proxy · save native exchanges</option></select></label>
 {value.mode==='proxy'&&<label>HTTP proxy URL<input value={value.proxy_url} onChange={e=>change('proxy_url',e.target.value)} placeholder="http://127.0.0.1:8080" maxLength={256}/></label>}
 <label>Additional trusted CA<select value={value.ca_input_id||''} onChange={e=>change('ca_input_id',e.target.value||null)}><option value="">System trust only</option>{inputs.filter(i=>i.kind==='file').map(i=><option key={i.id} value={i.id}>{i.name}</option>)}</select></label></fieldset>
 <p>Native target HTTP requests and responses are always saved locally, including failed attempts. Inspect them in HTTP history and export HAR pages.</p>
 <small>For HTTPS interception, register Burp’s PEM/DER CA certificate in Inputs and select it here. TLS certificate and hostname verification stay enabled. Proxy settings apply to target traffic; model and passive-provider calls keep their own transports.</small>
 {value.mode==='proxy'&&<p>Supported CLI adapters receive an explicit proxy flag; other active HTTP adapters fail preflight. DNS/TCP checks stay direct. CLI exchange bodies are proxy-owned: import Burp saved-items XML to retain those captures here.</p>}
 {error&&<p role="alert">{error}</p>}</section>;
}
