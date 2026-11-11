import React,{useState,useEffect,useRef} from 'react';
import {X,MagnifyingGlass,Plus,Graph,ArrowSquareOut,DownloadSimple} from '@phosphor-icons/react';
import curated from './templates.json';
import {isExecutableTemplate, migrated, trickest} from './catalog-contracts.mjs';
import {api,downloadJSON} from './api.mjs';
const all = {
  tools: [...migrated.tools, ...trickest.tools, ...curated.tools],
  workflows: [...migrated.workflows, ...trickest.workflows, ...curated.workflows],
};
const sources = [
  ['mini-tricky', 'mini-tricky'],
  ['trickest-oss', 'Trickest open source'],
  ['Curated legacy', 'Curated legacy'],
  ['All sources', 'All sources'],
];
export default function TemplateLibrary({close,onTool,onWorkflow,onRun}){
 const dialogRef=useRef(null);
 const [tab,setTab]=useState('workflows'),[query,setQuery]=useState(''),[category,setCategory]=useState('All categories'),[target,setTarget]=useState('All targets'),[source,setSource]=useState('mini-tricky'),[availability,setAvailability]=useState('All availability'),[selected,setSelected]=useState(null),[readiness,setReadiness]=useState({});
 useEffect(()=>{api('/catalog').then(c=>setReadiness(Object.fromEntries(c.readiness.map(r=>[r.id,r])))).catch(()=>{})},[]);
 useEffect(()=>{const previous=document.activeElement,dialog=dialogRef.current;const trap=e=>{if(e.key!=='Tab')return;const items=[...dialog.querySelectorAll('button,input,select,a[href]')].filter(x=>!x.disabled);if(e.shiftKey&&document.activeElement===items[0]){e.preventDefault();items.at(-1)?.focus()}else if(!e.shiftKey&&document.activeElement===items.at(-1)){e.preventDefault();items[0]?.focus()}};dialog.addEventListener('keydown',trap);return()=>{dialog.removeEventListener('keydown',trap);previous?.focus()}},[]);
 const list=all[tab],categories=[...new Set(list.map(t=>t.category))].sort();
 const restricted=t=>!!t.adapter?.reason||!!t.blocked_tools?.length;
 const label = entry => {
   if (!isExecutableTemplate(entry)) return entry.engine ? 'Native preset' : 'Legacy design';
   if (restricted(entry)) return 'Context restricted';
   if (tab === 'workflows') return 'CLI workflow · preflight';
   const state = readiness[entry.id]?.state;
   if (state === 'missing_binary') return 'Binary missing';
   return state === 'available' ? 'Binary found · unverified' : 'CLI adapter';
 };
 const filtered = list.filter(entry => {
   const sourceMatches = source === 'All sources' || source === (entry.sourceCatalog || 'Curated legacy');
   const available = {
     'All availability': true,
     'CLI adapters': isExecutableTemplate(entry) && !restricted(entry),
     'Context restricted': restricted(entry),
     'Native presets': !!entry.engine,
     'Legacy designs': !entry.engine && !isExecutableTemplate(entry),
   }[availability];
   const steps = entry.steps || (entry.nodes || []).map(node => node.data.title);
   const terms = [entry.name, entry.category, entry.description, ...steps].join(' ').toLowerCase();
   return sourceMatches && available && (category === 'All categories' || entry.category === category)
     && (target === 'All targets' || entry.targets.includes(target)) && terms.includes(query.toLowerCase());
 });
 const current=filtered.find(t=>`${t.sourceCatalog||'curated'}:${t.id}`===selected)||filtered[0];
 return <div className="modal-shade" onMouseDown={e=>e.target===e.currentTarget&&close()}><section ref={dialogRef} className="template-library" role="dialog" aria-modal="true" aria-label="Template library"><header><div><span className="tag">AI-TRICKY / LOCAL CATALOG</span><h2>Build from a typed workflow</h2><p>mini-tricky: {migrated.workflows.length} workflows · {migrated.tools.length} tools · Trickest open source: {trickest.workflows.length} workflows · {trickest.tools.length} tools</p></div><button className="icon-btn" onClick={close} aria-label="Close template library"><X size={24}/></button></header><div className="template-toolbar"><div className="template-tabs">{['workflows','tools'].map(t=><button className={tab===t?'active':''} key={t} onClick={()=>{setTab(t);setCategory('All categories');setSelected(null)}}>{t==='tools'?'Tool catalog':'Workflow templates'}<small>{all[t].length}</small></button>)}</div><button className="secondary" onClick={()=>downloadJSON('ai-tricky-catalog.json',{migrated,curated,trickest})}><DownloadSimple size={16}/>Export catalog</button></div><div className="template-filters"><label className="search"><MagnifyingGlass/><input autoFocus aria-label="Search templates" placeholder="Search tools, categories, workflows…" value={query} onChange={e=>setQuery(e.target.value)}/></label><select aria-label="Catalog source" value={source} onChange={e=>setSource(e.target.value)}>{sources.map(([id,label])=><option key={id} value={id}>{label}</option>)}</select><select aria-label="Template category" value={category} onChange={e=>setCategory(e.target.value)}>{['All categories',...categories].map(c=><option key={c}>{c}</option>)}</select><select aria-label="Target type" value={target} onChange={e=>setTarget(e.target.value)}>{['All targets','domain','targets','url','file','folder','wordlist','query','sbom','ipv4','ipv6','cidr'].map(t=><option key={t}>{t}</option>)}</select><select aria-label="Template availability" value={availability} onChange={e=>setAvailability(e.target.value)}>{['All availability','CLI adapters','Context restricted','Native presets','Legacy designs'].map(t=><option key={t}>{t}</option>)}</select></div><div className="template-layout"><div className="template-results"><p className="template-count">{filtered.length} matching {tab}</p>{filtered.map(t=><button className={`template-card ${current===t?'selected':''}`} key={`${t.sourceCatalog||'curated'}:${t.id}`} onClick={()=>setSelected(`${t.sourceCatalog||'curated'}:${t.id}`)}><Graph size={22}/><span><strong>{t.name}</strong><small>{t.category} · {t.targets.join(' / ')||'Context required'}</small></span><em className={t.engine?'ready':''}>{label(t)}</em></button>)}{!filtered.length&&<p className="empty">No matching entries.</p>}</div><aside className="template-detail">{current?<><span className="tag">{current.category}</span><h3>{current.name}</h3><p>{current.description}</p><dl><dt>Execution</dt><dd>{isExecutableTemplate(current)?current.adapter?.reason||current.blocked_tools?.length?`Context required: ${current.adapter?.reason||current.blocked_tools.join(', ')}`:'Application-owned CLI adapter. Configure inputs and run preflight; binaries are not bundled.':current.engine?'Native assessment preset':'Legacy canvas design; no live adapter'}</dd>{current.inputs&&<><dt>Input → output</dt><dd><code>{current.inputs.join(', ')||'Context source'} → {current.outputs?.join(', ')||current.output}</code></dd></>}<dt>Provenance</dt><dd>{current.provenance}</dd><dt>License</dt><dd>{current.license||(isExecutableTemplate(current)?'MIT':'See source notices')}</dd></dl>{current.steps && <ol className="template-steps">{current.steps.map(step => <li key={step}>{step}</li>)}</ol>}{current.nodes?.length>0&&<div className="template-steps">{current.nodes.map((n,i)=><span key={n.id}><b>{String(i+1).padStart(2,'0')}</b>{n.data.title}<code>{n.data.outputs?.join(' / ')||n.data.output}</code></span>)}</div>}<a href={current.repository||current.source} target="_blank" rel="noreferrer">View source reference <ArrowSquareOut/></a><button className="primary wide" onClick={()=>current.engine?onRun(current.engine):tab==='tools'?onTool(current):onWorkflow(current)}>{current.engine?'Configure local preset':tab==='tools'?'Add tool to canvas':'Load workflow on canvas'}<Plus size={18}/></button>{tab==='workflows'&&<small className="template-caveat">Loading replaces the canvas. Save your current workflow first.</small>}</>:<p>Select an entry.</p>}</aside></div><footer className="template-footnote">Pinned MIT source catalog. CLI adapters use explicit argv and typed files/stdin. Preflight reports missing binaries, inputs and context restrictions.</footer></section></div>;
}
