import React,{useEffect,useState} from 'react';
import {api} from './api.mjs';

export default function IdentityNodeSettings({data,onChange}){
 const [inputs,setInputs]=useState([]),[catalog,setCatalog]=useState(null),[error,setError]=useState('');
 useEffect(()=>{Promise.all([api('/inputs'),api('/identity/catalog')]).then(([i,c])=>{setInputs(i);setCatalog(c)}).catch(e=>setError(e.message))},[]);
 const scope=data.identity_scope||{platform:'ad',domain:'',tenant_id:''},auth=data.identity_auth||{},refs=data.inputRefs||{};
 const setScope=(key,value)=>onChange({identity_scope:{...scope,[key]:value}});
 const setRef=(key,value)=>{const next={...refs};if(value)next[key]=value;else delete next[key];onChange({inputRefs:next})};
 const collection=data.kind==='native_identity_collect';
 const field=(key,label)=> <label key={key}>{label}<input value={auth[key]||''} maxLength={253} onChange={e=>onChange({identity_auth:{...auth,[key]:e.target.value}})}/></label>;
 return <section aria-label="Identity node settings"><label>Identity environment<select value={scope.platform} onChange={e=>onChange({identity_scope:{platform:e.target.value,domain:'',tenant_id:''},profile_id:e.target.value==='ad'?'impacket-ad-users':'azurehound-entra',identity_auth:{},inputRefs:{}})}><option value="ad">Active Directory</option><option value="entra">Microsoft Entra ID</option></select></label>
 <label>Identity domain<input value={scope.domain} maxLength={253} onChange={e=>setScope('domain',e.target.value)} placeholder={scope.platform==='ad'?'corp.example.com':'corp.onmicrosoft.com'}/><small>Select this exact domain as an entered run target. Wildcards and web URL scopes do not grant directory scope.</small></label>
 {scope.platform==='entra'&&<label>Entra tenant UUID<input value={scope.tenant_id} maxLength={36} onChange={e=>setScope('tenant_id',e.target.value)}/></label>}
 {collection?<><label>Identity collection profile<select value={data.profile_id||(scope.platform==='ad'?'impacket-ad-users':'azurehound-entra')} onChange={e=>onChange({profile_id:e.target.value})}>{catalog?.profiles.filter(p=>p.platform===scope.platform).map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
 {scope.platform==='ad'?<>{field('username','AD account name')}{field('dc_host','Domain controller hostname')}{field('dc_ip','Domain controller IP')}<small>Select the DC hostname and literal IP/CIDR as additional entered targets. Only an existing Kerberos cache is used.</small></>:<p>Uses an existing Graph access-token JWT for the tenant. Token claims are checked locally; Microsoft authenticates it. No password, refresh-token or login flow is launched.</p>}
 <label>{scope.platform==='ad'?'Kerberos cache input':'Graph access token input'}<select value={refs[scope.platform==='ad'?'kerberos_cache':'access_token']||''} onChange={e=>setRef(scope.platform==='ad'?'kerberos_cache':'access_token',e.target.value)}><option value="">Choose a registered credential file</option>{inputs.filter(i=>i.kind==='file').map(i=><option key={i.id} value={i.id}>{i.name}</option>)}</select></label><small>Register the credential file by absolute path in Inputs. Its bytes are pinned and copied into a private job directory; the credential file is not exported as evidence.</small></>:<>
 <label>Identity graph export<select value={refs.graph||''} onChange={e=>setRef('graph',e.target.value)}><option value="">Use connected collector / file source</option>{inputs.filter(i=>i.kind==='file').map(i=><option key={i.id} value={i.id}>{i.name}</option>)}</select></label>
 <small>BloodHound JSON/ZIP, AzureHound JSON, or ai-tricky.identity-graph/v1. ZIPs accept up to 32 JSON files; import and traversal are bounded.</small>
 {['start_ids','goal_ids'].map(key=><label key={key}>{key==='start_ids'?'Start object IDs':'Goal object IDs'}<textarea rows={3} value={(data[key]||[]).join('\n')} onChange={e=>onChange({[key]:e.target.value.split('\n').filter(Boolean)})}/></label>)}
 <label>Maximum identity path depth<input type="number" min={1} max={6} value={data.max_depth??4} onChange={e=>onChange({max_depth:Number(e.target.value)})}/></label><small>Explicit endpoints are required for path search. Empty endpoints produce an inventory only. Results assume control of the start principal and remain candidates.</small></>}
 {error&&<p role="alert">{error}</p>}</section>;
}
