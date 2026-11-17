import React, {useEffect, useState} from 'react';
import {api, downloadJSON} from './api.mjs';
import {EvidenceViewer} from './EvidenceWorkbench';
const ProposalExecution = React.lazy(() => import('./ProposalExecution'));

export default function DeltaRecon({runs, onRun, onLoad}) {
  const candidates = runs.filter(run => run.config.engine === 'workflow' && ['completed', 'failed', 'cancelled', 'interrupted'].includes(run.status));
  const [runId, setRunId] = useState(candidates[0]?.id || '');
  const [baselines, setBaselines] = useState([]), [baselineId, setBaselineId] = useState('');
  const [report, setReport] = useState(null), [plan, setPlan] = useState(null), [capture, setCapture] = useState(null);
  const [selection, setSelection] = useState([]), [query, setQuery] = useState(''), [filter, setFilter] = useState('changes');
  const [busy, setBusy] = useState(false), [loading, setLoading] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    setReport(null); setPlan(null); setSelection([]); setCapture(null); setError(''); setNotice('');
    if (!runId) {setBaselines([]); setBaselineId(''); return;}
    let active = true;
    setLoading(true);
    api('/recon/baselines?run_id=' + encodeURIComponent(runId)).then(rows => {
      if (active) {setBaselines(rows); setBaselineId(rows.find(row => row.run_id !== runId)?.id || '');}
    }).catch(e => {if (active) setError(e.message);}).finally(() => {if (active) setLoading(false);});
    return () => {active = false;};
  }, [runId, refresh]);
  const save = async () => {
    setBusy(true); setError(''); setPlan(null);
    try {
      const baseline = await api('/recon/baselines', {run_id: runId, expected_revision: baselines[0]?.revision || 0});
      setBaselines(rows => [baseline, ...rows]);
      setReport(null); setSelection([]);
      setNotice('Baseline revision ' + baseline.revision + ' saved. Select a later run to inspect changes.');
    } catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const compare = async () => {
    setBusy(true); setError(''); setNotice(''); setReport(null); setPlan(null); setSelection([]); setCapture(null);
    try {setReport(await api(`/runs/${runId}/delta?baseline_id=${encodeURIComponent(baselineId)}`));}
    catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const prepare = async () => {
    setBusy(true); setError('');
    try {
      setPlan(await api(`/runs/${runId}/delta/proposals`, {baseline_id: baselineId,
        expected_hash: report.comparison_hash, fingerprints: selection}));
    } catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const toggle = fingerprint => {setSelection(previous => previous.includes(fingerprint) ? previous.filter(id => id !== fingerprint) : [...previous, fingerprint]); setPlan(null);};
  const rows = report?.entries.filter(row =>
    (filter === 'all' || (filter === 'changes' ? ['new', 'changed'].includes(row.state) : row.state === filter)) &&
    `${row.asset} ${row.kind} ${row.source}`.toLowerCase().includes(query.trim().toLowerCase())) || [];
  const source = candidates.find(run => run.id === runId);
  return <section className="evidence-workbench" aria-label="Delta recon">
    <div className="section-intro"><div><h3>Delta recon</h3><p>Compare a run with its saved scope and workflow baseline, then review a follow-up for selected changes.</p></div>
      <button className="secondary" disabled={busy || loading} onClick={() => setRefresh(value => value + 1)}>Refresh baselines</button></div>
    <div className="evidence-filters">
      <label className="field-label">Recon run<select value={runId} disabled={busy} onChange={e => setRunId(e.target.value)}>
        <option value="">Select a workflow run</option>{candidates.map(run => <option key={run.id} value={run.id}>{run.id.slice(0, 8)} · {run.status} · {run.config.targets.join(', ')}</option>)}</select></label>
      <label className="field-label">Saved baseline<select disabled={busy || loading} value={baselineId} onChange={e => {setBaselineId(e.target.value); setReport(null); setPlan(null); setSelection([]);}}>
        <option value="">Select a baseline for this scope and workflow</option>{baselines.filter(row => row.run_id !== runId).map(row =>
          <option key={row.id} value={row.id}>Revision {row.revision} · {row.run_id.slice(0, 8)} · {new Date(row.created).toLocaleString()}</option>)}</select></label>
    </div>
    <div className="evidence-actions"><button className="secondary" disabled={busy || loading || source?.status !== 'completed'} onClick={save}>Save this run as baseline</button>
      <button className="primary" disabled={busy || loading || !baselineId} onClick={compare}>Compare with baseline</button></div>
    {notice && <p role="status">{notice}</p>}{loading && <p role="status">Loading baselines…</p>}
    {error && <p className="local-error" role="alert">{error}</p>}
    {report && <>
      <div className="comparison-summary">{Object.entries(report.summary).map(([name, count]) => <div key={name}><strong>{count}</strong><span>{name.replaceAll('_', ' ')}</span></div>)}</div>
      <div className="comparison-notice"><p>{report.absence_means}</p>{report.warnings.map(note => <p key={note}>{note}</p>)}</div>
      <div className="evidence-filters"><label className="field-label">Change filter<select value={filter} onChange={e => setFilter(e.target.value)}>
        {['changes', 'new', 'changed', 'not_observed', 'unchanged', 'all'].map(state => <option key={state} value={state}>{state === 'changes' ? 'New and changed' : state.replaceAll('_', ' ')}</option>)}</select></label>
        <label className="field-label">Search changes<input type="search" value={query} onChange={e => setQuery(e.target.value)} placeholder="Host, endpoint, file, or source"/></label>
        <button className="secondary" onClick={() => downloadJSON(`delta-${report.run_id}.json`, report)}>Export delta</button></div>
      <p>{selection.length} selected · Maximum eight change rows per follow-up</p>
      {rows.map(row => <article className="comparison-row" key={row.fingerprint}>
        <label className="http-toggle"><input type="checkbox" aria-label={'Select change ' + row.asset + ' ' + row.source}
          checked={selection.includes(row.fingerprint)} disabled={!report.evidence_current || !row.followup_url || busy || (!selection.includes(row.fingerprint) && selection.length >= 8)}
          onChange={() => toggle(row.fingerprint)}/><span><strong>{row.asset}</strong><small>{row.kind} · {row.source} · {row.state.replaceAll('_', ' ')}</small></span></label>
        {!row.followup_url && <small>HTTP follow-up is unavailable for this record.</small>}
        <details><summary>Evidence and changed values</summary><div className="comparison-values">{['before', 'after'].map(side => <section key={side}>
          <h4>{side === 'before' ? 'Baseline' : 'Current'}</h4>{!row[side].length && <p>Not observed</p>}
          {row[side].map((entry, i) => <div key={i}><pre>{JSON.stringify(entry.data, null, 2)}</pre>{entry.evidence_ids.map(id =>
            <button key={id} className="secondary" onClick={() => setCapture({id})}>Capture {id.slice(0, 8)}</button>)}</div>)}</section>)}</div></details>
      </article>)}
      {!rows.length && <p>No records match this change filter.</p>}
      <button className="primary" disabled={busy || !report.evidence_current || !selection.length} onClick={prepare}>Prepare selected follow-up</button>
      {plan && <section aria-label="Delta follow-up"><p>{plan.proposals[0].action.cost.native_operations} GETs against the selected URLs. Review scope and limits before starting.</p>
        <button className="secondary" onClick={() => onLoad(plan.proposals[0].graph)}>Load selected workflow on canvas</button>
        <React.Suspense fallback={<p>Loading execution review…</p>}><ProposalExecution key={plan.id} plan={plan} proposal={plan.proposals[0]} initialOpen onRun={onRun}/></React.Suspense></section>}
      <details className="comparison-row"><summary>Node execution and input coverage</summary>{['baseline', 'current'].map(side => <section key={side}>
        <h4>{side === 'baseline' ? 'Baseline' : 'Current'}</h4><table className="delta-coverage"><thead><tr><th>Node</th><th>Execution</th><th>Inputs</th><th>Limits</th></tr></thead><tbody>
          {report.coverage[side].nodes.map(node => <tr key={node.node_id}><td>{node.node_id} · {node.adapter}</td><td>{node.status}{node.errors ? ' · errors ' + node.errors : ''}</td>
            <td>{node.input_receipt ? <><span>{node.input_receipt.input_records} records</span><br/><code>{node.input_receipt.input_hash.slice(0, 12)}</code>{' '}
              <button className="secondary" onClick={() => setCapture({id: node.input_receipt_id})}>Inspect input receipt</button></> : 'Not recorded'}</td>
            <td>{Object.entries(node.limits).map(([key, value]) => key.replaceAll('_', ' ') + ' ' + value).join(', ') || '—'}</td></tr>)}</tbody></table>
      </section>)}</details>
    </>}{capture && <EvidenceViewer artifact={capture} close={() => setCapture(null)}/>}
  </section>;
}
