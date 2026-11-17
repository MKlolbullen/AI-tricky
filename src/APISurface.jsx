import React, {useEffect, useState} from 'react';
import {api, downloadJSON} from './api.mjs';
import {RepeaterButton} from './BurpBridge';

const ProposalExecution = React.lazy(() => import('./ProposalExecution'));

export function APISurfaceTable({surface, runId, onRun}) {
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('');
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState('');
  const [matrixPlan, setMatrixPlan] = useState(null);
  const [planning, setPlanning] = useState(false);
  const filter = query.trim().toLowerCase();
  const rows = surface.endpoints.filter(row => (!status || row.status === status) &&
    `${row.method} ${row.url} ${row.parameters.join(' ')}`.toLowerCase().includes(filter));
  const detail = rows.find(row => row.id === selected);
  const labels = {observed: 'Observed', imported: 'Imported match', inferred: 'Inferred'};
  const inspect = async (kind, id) => {
    setError('');
    try {
      const record = await api((kind === 'source' ? '/artifacts/' : '/http-history/') + encodeURIComponent(id));
      downloadJSON(`${kind}-${id}.json`, record);
    } catch (failure) {
      setError(failure.message);
    }
  };

  const planMatrix = async (endpoint, exchange) => {
    setError('');
    setPlanning(true);
    try {
      const plan = await api(`/runs/${runId}/api-surface/${endpoint}/exchanges/${exchange}/verification-plan`, {});
      setMatrixPlan({endpoint, plan});
    } catch (failure) {
      setError(failure.message);
    } finally {
      setPlanning(false);
    }
  };

  return <section className="api-surface" aria-label="API endpoints">
    <div className="api-surface-controls">
      <label>Filter endpoints<input type="search" value={query} onChange={e => setQuery(e.target.value)} placeholder="Method, route, parameter"/></label>
      <label>Evidence<select value={status} onChange={e => setStatus(e.target.value)}><option value="">All evidence</option>{Object.entries(labels).map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label>
      <button className="secondary" onClick={() => downloadJSON('api-surface.json', surface)}>Export JSON</button>
    </div>
    <p role="status">{rows.length} of {surface.endpoints.length} endpoints · {surface.counts.documents} source files analyzed</p>
    {surface.limits_hit.length > 0 && <p className="notice">Partial coverage · {surface.limits_hit.join(', ')}</p>}
    <div className="api-surface-scroll"><table>
      <thead><tr><th>Endpoint</th><th>Parameters</th><th>Evidence</th></tr></thead>
      <tbody>{rows.map(row => <tr key={row.id}>
        <td><button className="surface-endpoint" aria-expanded={selected === row.id} onClick={() => {setSelected(selected === row.id ? null : row.id);setError('')}}><b>{row.method}</b> <code>{row.url}</code></button></td>
        <td>{row.parameters.join(', ') || '—'}</td><td>{labels[row.status]}</td>
      </tr>)}</tbody>
    </table></div>
    {!rows.length && <p>{surface.endpoints.length ? 'No endpoints match these filters.' : 'No supported request calls were found in these captures.'}</p>}
    {detail && <section className="surface-evidence" aria-label="Endpoint evidence">
      <h4>{detail.method} <code>{detail.url}</code></h4>
      <h5>Source locations</h5>
      <ul>{detail.sources.map((source, i) => <li key={i}><code>{source.embedded_source || source.source_url}:{source.line}:{source.column}</code>{source.embedded_source && <small>{source.source_url}</small>}<button className="secondary" onClick={() => inspect('source', source.artifact_id)}>Download capture</button></li>)}</ul>
      {detail.traffic.length > 0 && <><h5>Matching HTTP exchanges</h5><ul>{detail.traffic.map(row => <li key={row.exchange_id}>
        <span>{row.status} · {row.source === 'native' ? 'Native capture' : 'Imported capture'}</span>
        <button className="secondary" onClick={() => inspect('exchange', row.exchange_id)}>Download exchange</button>
        <RepeaterButton exchangeId={row.exchange_id}/>
        {onRun && detail.method === 'GET' && row.source === 'native' &&
          <button className="secondary" disabled={planning} onClick={() => planMatrix(detail.id, row.exchange_id)}>Set up access matrix</button>}
      </li>)}</ul></>}
      {matrixPlan?.endpoint === detail.id && <React.Suspense fallback={<p>Loading execution review…</p>}>
        <ProposalExecution key={matrixPlan.plan.id} plan={matrixPlan.plan} proposal={matrixPlan.plan.proposals[0]}
          initialProfile="access_matrix" onRun={onRun}/>
      </React.Suspense>}
    </section>}
    {error && <p role="alert">{error}</p>}
    <details><summary>Analysis coverage</summary><ul>{surface.coverage_limits.map(note => <li key={note}>{note}</li>)}</ul>
      <p>{surface.counts.truncated} truncated captures · {surface.counts.parse_errors} parse warnings · {surface.counts.out_of_scope} excluded routes · {surface.counts.missing} unavailable captures</p>
    </details>
  </section>;
}

export default function APISurface({runs, initialRun, onRun}) {
  const [runId, setRunId] = useState(initialRun || '');
  const [surface, setSurface] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const candidates = runs.filter(run => run.config.workflow?.nodes.some(node => node.data.kind === 'native_web_assets'));

  useEffect(() => {
    setSurface(null);
    setError('');
    if (!runId) {setBusy(false);return;}
    let current = true;
    setBusy(true);
    api('/runs/' + encodeURIComponent(runId) + '/api-surface').then(value => {
      if (current) setSurface(value);
    }).catch(failure => {
      if (current) setError(failure.message);
    }).finally(() => {if (current) setBusy(false)});
    return () => {current = false};
  }, [runId]);

  return <section aria-label="API Surface">
    <div className="section-intro"><div><h3>API Surface</h3><p>Find routes in saved JavaScript, TypeScript, and embedded source maps. Matching HTTP history is shown alongside source evidence.</p></div></div>
    <label className="field-label">Source collection run<select value={runId} onChange={e => setRunId(e.target.value)}>
      <option value="">Choose a run</option>
      {candidates.map(run => <option key={run.id} value={run.id}>{run.id.slice(0, 8)} · {run.config.targets.join(', ')} · {run.status}</option>)}
    </select></label>
    {!candidates.length && <p>Run a workflow with a Web source collector to populate this view.</p>}
    {busy && <p role="status">Analyzing saved sources…</p>}
    {error && <p role="alert">{error}</p>}
    {surface && <APISurfaceTable key={runId} surface={surface} runId={runId} onRun={onRun}/>}
  </section>;
}
