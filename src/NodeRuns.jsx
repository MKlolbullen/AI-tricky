import React from 'react';
export default function NodeRuns({nodes,graph,onArtifact}){
 if(!nodes.length)return null;
 return <section className="node-runs"><h4>Workflow nodes</h4><div className="node-run-row table-head"><span>Node</span><span>Status</span><span>Output</span></div>{nodes.map(n=><div className="node-run-row" key={n.node_id}><strong>{graph?.nodes.find(x=>x.id===n.node_id)?.data.title||n.node_id}</strong><span className={'run-status '+n.status}>{n.status}</span><span>{n.result?.artifact_id?<button className="secondary" onClick={()=>onArtifact({id:n.result.artifact_id,name:`node-${n.node_id}.json`})}>{n.result.records} records · {n.result.errors||0} errors</button>:n.result?.error||n.result?.reason||'—'}{n.status==='reused'&&<small className="checkpoint-origin">Source {n.result.source_run_id.slice(0,8)} · captured {new Date(n.result.captured_at).toLocaleString()}</small>}</span></div>)}</section>;
}
