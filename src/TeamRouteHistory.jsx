import React from 'react';

export default function TeamRouteHistory({team,onArtifact}){
 if(!team?.members)return null;
 const members=[...team.members,...(team.synthesis?[{role:'lead',name:'Lead synthesis',...team.synthesis}]:[])];
 return <section className="scope-summary" aria-label="Team routes and handoffs"><strong>Team routes and handoffs</strong>{members.map(m=><div className="team-route-history" key={m.role}><h4>{m.name}</h4>{m.model_attempts?.map((a,i)=><p key={i}>{a.fallback?'Fallback':'Primary'} · {a.provider} / {a.model} · {a.status} · {a.max_turns} turn ceiling{a.error_code?' · '+a.error_code:''}</p>)}{m.handoff_artifact_id&&<button className="secondary" onClick={()=>onArtifact?.({id:m.handoff_artifact_id,name:'Handoff to '+m.name})}>Inspect {m.name} handoff</button>}{m.analysis?.review_required&&<p>Validation plan · not executed · separate execution review required</p>}</div>)}</section>;
}
