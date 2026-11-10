import React from 'react';
import TeamTurnBudget from './TeamTurnBudget';
export function AnalysisPreview({data,onEvidence}){
 const analysis=Array.isArray(data)?data.find(row=>row.analysis)?.analysis:null;
 const team=Array.isArray(data)?data.find(row=>row.team):null;
 if(!analysis)return <TeamTurnBudget budget={team?.model_turn_budget} members={team?.members}/>;
 return <section className="analysis-preview"><h4>Agent evidence review <span className="tag">CANDIDATES</span></h4><p>{analysis.summary}</p>{analysis.candidates.map((c,i)=><article className="candidate-card" key={i}><h4>{c.title} <span className="tag">{c.severity}</span></h4><p>{c.rationale}</p><div className="scope-chips">{c.evidence_ids.map(id=><button className="secondary" key={id} onClick={()=>onEvidence({id,name:'HTTP evidence'})}>Evidence {id.slice(0,8)}</button>)}</div><strong>Suggested next test · not dispatched</strong><p>{c.next_test}</p></article>)}{!analysis.candidates.length&&<p>No candidate issues supported by this review.</p>}<h4>Coverage limits</h4><ul>{analysis.coverage_limits.map((c,i)=><li key={i}>{c}</li>)}</ul></section>;
}
