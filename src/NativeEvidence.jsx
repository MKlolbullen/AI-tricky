import React,{useEffect,useState} from 'react';
import {api,downloadJSON} from './api.mjs';
import {AnalysisPreview} from './AnalysisPreview';
import {APISurfaceTable} from './APISurface';
export default function NativeEvidence({nodeId,live}){
 const [artifact,setArtifact]=useState(null),[error,setError]=useState('');
 const result=live?.nodes?.find(n=>n.node_id===nodeId);
 const surface=Array.isArray(artifact?.data)?artifact.data.find(row=>row.schema==='ai-tricky.api-surface/v1'):null;
 useEffect(()=>{setArtifact(null);setError('')},[nodeId,live?.run?.id]);
 const content=async a=>{try{setArtifact({name:a.name,data:await api('/artifacts/'+a.id)})}catch(e){setError(e.message)}};
 return <div className="native-evidence"><h3>Node evidence</h3>{result?<><p>Run {live.run.id.slice(0,8)} · {result.status}</p>{result.result?.artifact_id?<button className="primary wide" onClick={()=>content({id:result.result.artifact_id,name:`node-${nodeId}.json`})}>Inspect {result.result.records} output records</button>:<p>{result.result?.error||result.result?.reason||'This node has no output artifact yet.'}</p>}</>:<p>Select a native workflow run to inspect its captured output.</p>}{error&&<p role="alert">{error}</p>}{artifact&&<><h4>{artifact.name}</h4><AnalysisPreview data={artifact.data} onEvidence={content}/><button className="secondary" onClick={()=>downloadJSON(artifact.name,artifact.data)}>Download JSON</button>{surface?<APISurfaceTable surface={surface}/>:<pre className="live-artifact">{JSON.stringify(artifact.data,null,2)}</pre>}</>}</div>;
}
