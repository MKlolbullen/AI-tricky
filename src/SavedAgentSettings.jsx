import React,{useState} from 'react';
import {api} from './api.mjs';

export default function SavedAgentSettings({index,onIndex,settings,onLoad,initialPreset,onPreset}){
 const [selected,setSelected]=useState(initialPreset?.id||''),[loaded,setLoaded]=useState(initialPreset||null);
 const [name,setName]=useState(initialPreset?.name||''),[isDefault,setDefault]=useState(initialPreset?.is_default||false);
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[status,setStatus]=useState('');
 const act=async operation=>{setBusy(true);setError('');setStatus('');try{await operation()}catch(e){setError(e.message)}finally{setBusy(false)}};
 const adopt=p=>{setSelected(p.id);setLoaded(p);setName(p.name);setDefault(p.is_default);onPreset(p)};
 const load=()=>act(async()=>{const p=await api('/agent-settings/'+selected);adopt(p);onLoad(p.settings);setStatus(`Loaded ${p.name}.`)});
 const save=copy=>act(async()=>{
  const p=await api('/agent-settings'+(!copy&&loaded?'/'+loaded.id:''),{name,settings,is_default:isDefault,...(!copy&&loaded?{revision:loaded.revision}:{})});
  adopt(p);onIndex(await api('/agent-settings'));setStatus(`Saved ${p.name}${p.is_default?' · restores on reopen':''}.`);
 });
 const remove=()=>act(async()=>{await api('/agent-settings/'+loaded.id+'/delete',{revision:loaded.revision});onIndex(await api('/agent-settings'));setSelected('');setLoaded(null);onPreset(null);setName('');setDefault(false);setStatus('Preset deleted. Current choices are still editable.')});
 return <section className="scope-summary agent-presets" aria-label="Saved agent settings"><h4>Saved agent settings</h4><p>Save team roles, routing, turn limits and the planning model. Make a preset the default to restore it when you reopen the workspace.</p>
 <fieldset disabled={busy}><label className="field-label">Saved preset<select aria-label="Saved preset" value={selected} onChange={e=>setSelected(e.target.value)}><option value="">Choose a saved preset…</option>{(index?.items||[]).map(p=><option key={p.id} value={p.id}>{p.name}{p.is_default?' · default':''}</option>)}</select></label><button className="secondary" disabled={!selected} onClick={load}>Load preset</button>
 <label className="field-label">Preset name<input aria-label="Preset name" maxLength={80} value={name} onChange={e=>setName(e.target.value)} placeholder="e.g. Web specialists"/></label>
 <label className="http-toggle"><input type="checkbox" checked={isDefault} onChange={e=>setDefault(e.target.checked)}/><span>Restore this preset by default</span></label>
 <div className="preset-actions"><button className="primary" disabled={!name.trim()||!!loaded&&selected!==loaded.id} onClick={()=>save(false)}>{loaded?'Save changes':'Save preset'}</button>{loaded&&<><button className="secondary" disabled={!name.trim()} onClick={()=>save(true)}>Save as new preset</button><button className="secondary" disabled={selected!==loaded.id} onClick={remove}>Delete preset</button></>}</div></fieldset>
 <small>Targets, traffic permissions, credentials and execution approvals are configured separately. Workflow node settings keep their own turn limits.</small>
 {error&&<p className="local-error" role="alert">{error}</p>}{status&&<p role="status">{status}</p>}</section>;
}
