import React from 'react';
import {ModelSelector} from './ModelSelector';

export default function RoleModelRoutes({runtime,roles,synthesize,routes,onChange,onPreset}){
 const providers=runtime?.model_providers||[{id:'local',name:'Local endpoint'}];
 const definitions=runtime?.team_roles||[];
 const selected=[...roles,...(synthesize?['lead']:[])];
 const local=()=>({provider:'local',model:runtime?.model||''});
 const update=(role,value)=>{const next={...routes};if(value)next[role]=value;else delete next[role];onChange(next)};
 const preset=()=>{onPreset();onChange(Object.fromEntries(Object.entries({surface:'gemini',analyst:'openai',vulnerability:'venice',poc:'venice',lead:'anthropic'}).map(([k,provider])=>[k,{primary:{provider,model:''}}])))};
 const choice=(role,part,name)=>{
  const route=routes[role],value=route[part],label=part==='complex_task'?'complex-task':part;
  return <div className="model-select"><label>{name} {label} provider<select aria-label={`${name} ${label} provider`} value={value.provider} onChange={e=>update(role,{...route,[part]:{provider:e.target.value,model:''}})}>{providers.map(p=><option key={p.id} value={p.id}>{p.name}{p.is_remote&&!p.configured?' · key missing':''}</option>)}</select></label><ModelSelector runtime={runtime} provider={value.provider} label={`${name} ${label} model`} value={value.model} onChange={model=>update(role,{...route,[part]:{...value,model}})}/></div>
 };
 return <section className="scope-summary role-model-routes" aria-label="Per-role model routing"><strong>Per-role model routing</strong><p>Choose exact model IDs. Roles without overrides inherit the default model. Missing credentials or remote-model permission fail preflight before dispatch.</p><button className="secondary" onClick={preset}>Use mixed-provider routing</button><small>Preset: Gemini recon, OpenAI analysis, Venice vulnerability/PoC, Anthropic lead. Choose models and configure provider keys; this does not make provider calls.</small>
 {selected.map(role=>{const name=definitions.find(r=>r.key===role)?.name||(role==='lead'?'Lead synthesis':role),route=routes[role];return <fieldset key={role}><legend>{name}</legend><label className="http-toggle"><input type="checkbox" checked={!!route} onChange={e=>update(role,e.target.checked?{primary:local()}:null)}/><span>{name} model override</span></label>{route&&<>{choice(role,'primary',name)}<label className="http-toggle"><input type="checkbox" checked={!!route.fallback} onChange={e=>{const next={...route};if(e.target.checked)next.fallback=local();else delete next.fallback;update(role,next)}}/><span>{name} availability fallback</span></label>{route.fallback&&choice(role,'fallback',name)}<label className="http-toggle"><input type="checkbox" checked={!!route.complex_task} onChange={e=>{const next={...route};if(e.target.checked)next.complex_task=local();else delete next.complex_task;update(role,next)}}/><span>{name} complex-task override</span></label>{route.complex_task&&choice(role,'complex_task',name)}</>}</fieldset>})}
 <small>Fallback reserves half of that role’s turns and runs only after provider connection failures, timeouts, rate limiting or server errors. Refusals and invalid reports never trigger a provider switch. One-turn roles have no fallback capacity. Specialist handoffs carry bounded evidence; PoC plans require a separate execution review.</small></section>;
}
