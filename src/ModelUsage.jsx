import React, {useEffect, useState} from 'react';
import {api, downloadJSON} from './api.mjs';

const PURPOSES={assessment:'Assessment', workflow_analysis:'Workflow analysis', team_member:'Team analyst',
  team_synthesis:'Lead synthesis', workflow_plan:'Workflow plan', canvas_assist:'Canvas assistant', evidence_plan:'Evidence follow-ups'};
const count=value=>value===null || value===undefined ? 'Not reported' : value.toLocaleString();

export default function ModelUsage({runId, active=false, onRun}) {
  const [data,setData]=useState(null), [error,setError]=useState(''), [offset,setOffset]=useState(0);
  const [refresh,setRefresh]=useState(0), [busy,setBusy]=useState(false);
  useEffect(()=>{
    let alive=true, reading=false;
    const read=async()=>{
      if(reading)return;
      reading=true;
      if(alive) setBusy(true);
      try {
        const result=await api(`${runId?`/runs/${runId}/model-usage`:'/model-usage'}?limit=20&offset=${offset}`);
        if(alive){setData(result);setError('');}
      } catch(e){if(alive)setError(e.message);}
      finally {reading=false;if(alive)setBusy(false);}
    };
    read();
    const timer=active || !runId ? setInterval(read,runId?2000:5000) : null;
    return()=>{alive=false;if(timer)clearInterval(timer);};
  },[runId,offset,refresh,active]);
  const summary=data?.summary;
  const waiting=busy||!!data&&data.offset!==offset;
  return <section className="model-usage" aria-label={runId?'Run model usage':'Model usage ledger'}>
    <div className="section-intro"><div><h4>Model usage {summary&&<span className="tag">{summary.coverage.toUpperCase()}</span>}</h4>
      <p>Admitted model call attempts and provider-reported tokens. Missing reports remain unknown; counters do not estimate billing.</p></div>
      <div className="usage-actions"><button className="secondary" disabled={busy} onClick={()=>setRefresh(n=>n+1)}>Refresh usage</button>
        <button className="secondary" disabled={!data||waiting} onClick={()=>downloadJSON(`model-usage-${runId||'workspace'}.json`,data)}>Export displayed usage</button></div>
    </div>
    {error&&<p className="local-error" role="alert">{error}</p>}
    {!data&&!error&&<p>Loading model usage…</p>}
    {summary&&!summary.available&&<p className="comparison-notice">Usage was not recorded for this historical run. Its token counts are unavailable.</p>}
    {summary?.available&&<>
      <dl className="usage-totals" aria-label="Recorded model usage totals">
        <div><dt>Call attempts</dt><dd>{count(summary.attempts)}</dd></div>
        <div><dt>Responses received</dt><dd>{count(summary.responses)}</dd></div>
        <div><dt>Input tokens reported</dt><dd>{count(summary.input_tokens)}</dd></div>
        <div><dt>Output tokens reported</dt><dd>{count(summary.output_tokens)}</dd></div>
        <div><dt>Total tokens reported</dt><dd>{count(summary.total_tokens)}</dd></div>
      </dl>
      <p>Provider detail: cached input tokens {count(summary.cached_input_tokens)} · reasoning tokens {count(summary.reasoning_tokens)}.</p>
      {(summary.missing_usage_responses>0||summary.unknown_attempts>0||summary.unmetered_invocations>0)&&
        <p className="comparison-notice" role="status">Partial accounting: {summary.missing_usage_responses} response(s) lack complete token reports;
          {' '}{summary.unknown_attempts} attempt(s) have unknown usage; {summary.unmetered_invocations} pass(es) lack metering support.
          Reported token totals cover the known portion.</p>}
      <div className="usage-table-scroll"><table aria-label="Model usage passes">
        <thead><tr><th scope="col">Context</th><th scope="col">Provider / model</th><th scope="col">Attempts / responses</th>
          <th scope="col">Reported input / output / total tokens</th><th scope="col">Model pass state</th></tr></thead>
        <tbody>{data.items.map(row=><tr key={row.id}>
          <th scope="row">{PURPOSES[row.purpose]||row.purpose}<small>{[row.node_id,row.role].filter(Boolean).join(' · ')}</small>
            {(row.run_id||row.related_run_id)&&onRun&&<button className="secondary" onClick={async()=>{
              try{onRun(await api('/runs/'+(row.run_id||row.related_run_id)));}catch(e){setError(e.message);}
            }}>{row.run_id?'Open run':'Source run'}</button>}</th>
          <td>{row.provider}<small>{row.model}</small></td>
          <td>{count(row.usage.attempts)} / {count(row.usage.responses)}</td>
          <td>{count(row.usage.input_tokens)} / {count(row.usage.output_tokens)} / {count(row.usage.total_tokens)}</td>
          <td>{row.status}<small>{row.metered?row.usage.coverage:'unmetered'} · {row.execution_mode}</small></td>
        </tr>)}</tbody>
      </table></div>
      {!data.items.length&&<p>No model passes recorded for this view.</p>}
      <nav className="usage-pagination" aria-label="Model usage pages"><span>{data.total?data.offset+1:0}–{data.offset+data.items.length} of {data.total}</span>
        <button className="secondary" disabled={waiting||offset===0} onClick={()=>setOffset(n=>Math.max(0,n-20))}>Previous usage page</button>
        <button className="secondary" disabled={waiting||offset+data.items.length>=data.total} onClick={()=>setOffset(n=>n+20)}>Next usage page</button></nav>
    </>}
  </section>;
}
