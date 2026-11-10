import React,{useEffect,useState} from 'react';

export function ModelSelector({runtime,provider,value,onChange,label='Model name',disabled=false}){
 const [custom,setCustom]=useState(false);
 useEffect(()=>setCustom(false),[provider]);
 const catalog=runtime?.model_catalog?.[provider];
 const options=new Map((catalog?.models||[]).map(m=>[m.id,m.name]));
 for(const id of runtime?.saved_models?.[provider]||[])if(!options.has(id))options.set(id,'Saved custom model');
 if(value&&!options.has(value))options.set(value,'Custom model');
 return <div className="model-picker"><label className="field-label">{label}<select aria-label={label} disabled={disabled} value={custom?'__custom__':value} onChange={e=>{if(e.target.value==='__custom__')setCustom(true);else{setCustom(false);onChange(e.target.value)}}}>
  <option value="">{provider==='local'?`Configured model · ${runtime?.model||'local endpoint'}`:'Choose a model…'}</option>
  {[...options].map(([id,name])=><option key={id} value={id}>{name} · {id}</option>)}
  <option value="__custom__">Custom model ID…</option>
 </select></label>{custom&&<label className="field-label">{label} custom ID<input aria-label={`${label} custom ID`} disabled={disabled} value={value} maxLength={120} spellCheck={false} placeholder="Exact provider model ID" onChange={e=>onChange(e.target.value)}/></label>}
 {catalog&&<small>Reviewed menu · {catalog.reviewed} · <a href={catalog.source} target="_blank" rel="noreferrer">Provider model docs</a>. Account access and SDK compatibility may vary.</small>}
 </div>;
}

export default function ProviderModelSelector({runtime,value,onChange,disabled=false}){
 const providers=runtime?.model_providers||[{id:'local',name:'Local endpoint'}];
 return <div className="model-select"><label className="field-label">Model provider<select aria-label="Model provider" value={value.provider} disabled={disabled} onChange={e=>onChange({provider:e.target.value,model:''})}>
 {providers.map(p=><option key={p.id} value={p.id}>{p.name}{p.is_remote&&(!p.configured?' · key missing':!runtime?.remote_model_enabled?' · remote use disabled':'')}</option>)}
 </select></label><ModelSelector runtime={runtime} provider={value.provider} value={value.model} onChange={model=>onChange({...value,model})} disabled={disabled}/>
 <small>Saving choices makes no provider calls. Remote inference still requires a configured key and remote model use enabled. Blank local selection uses the configured endpoint model.</small></div>;
}
