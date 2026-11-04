import React, {useEffect, useState} from 'react';
import {api, downloadJSON} from './api.mjs';
import {EvidenceViewer} from './EvidenceWorkbench';
import ProposalExecution from './ProposalExecution';

export default function EvidencePlanner({runtime, runs, onPlan, onRun}) {
  const [runId, setRunId] = useState(''), [goal, setGoal] = useState('Identify the next useful evidence collection step and explain what it would establish.');
  const [page, setPage] = useState({items: [], total: 0}), [offset, setOffset] = useState(0), [q, setQ] = useState('');
  const [selected, setSelected] = useState({}), [useModel, setUseModel] = useState(false), [maxRisk, setMaxRisk] = useState('low');
  const [plan, setPlan] = useState(null), [history, setHistory] = useState([]), [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false), [loading, setLoading] = useState(false), [error, setError] = useState(''), [capture, setCapture] = useState(null);
  useEffect(() => {setRunId(value => value || runs[0]?.id || '');}, [runs]);
  useEffect(() => {
    let alive = true;
    if (!runId) {setPage({items: [], total: 0}); return;}
    setLoading(true); setError('');
    api('/observations?' + new URLSearchParams({run_id: runId, q, offset, limit: 50})).then(data => {
      if (alive) setPage(data);
    }).catch(e => {if (alive) setError(e.message);}).finally(() => {if (alive) setLoading(false);});
    return () => {alive = false;};
  }, [runId, q, offset]);
  useEffect(() => {
    let alive = true;
    if (!runId) {setHistory([]); return;}
    api('/agent/proposals?' + new URLSearchParams({run_id: runId})).then(data => {if (alive) setHistory(data);})
      .catch(e => {if (alive) setError(e.message);});
    return () => {alive = false;};
  }, [runId, refresh]);
  const sourceRun = value => {setRunId(value); setOffset(0); setSelected({}); setPlan(null); setCapture(null); setError('');};
  const choose = (record, checked) => setSelected(previous => {
    const next = {...previous};
    if (checked && Object.keys(next).length < 24) next[record.id] = record;
    else if (!checked) delete next[record.id];
    return next;
  });
  const generate = async event => {
    event.preventDefault(); setBusy(true); setError(''); setCapture(null);
    try {
      const result = await api('/agent/proposals', {run_id: runId, observation_ids: Object.keys(selected), goal, use_model: useModel, max_risk: maxRisk});
      setPlan(result); setRefresh(value => value + 1);
    } catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const restore = async id => {
    if (!id) return;
    setBusy(true); setError(''); setCapture(null);
    try {setPlan(await api('/agent/proposals/' + id));} catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const load = async proposal => {
    setBusy(true); setError('');
    try {onPlan(await api(`/agent/proposals/${plan.id}/${proposal.id}/workflow`));}
    catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const count = Object.keys(selected).length;
  return <section className="evidence-workbench evidence-planner">
    <div className="section-intro"><div><h3>Evidence-guided follow-ups</h3><p>Select captured observations, then review proposed tests with their evidence, expected signal and prerequisites.</p></div></div>
    <form onSubmit={generate}>
      <div className="evidence-filters"><label className="field-label">Source run<select disabled={busy} value={runId} onChange={e => sourceRun(e.target.value)}>
        <option value="">Select a recorded run</option>{runs.map(r => <option key={r.id} value={r.id}>{r.id.slice(0, 8)} · {r.status} · {new Date(r.created).toLocaleString()}</option>)}</select></label>
        <label className="field-label">Maximum proposed risk<select disabled={busy} value={maxRisk} onChange={e => setMaxRisk(e.target.value)}>{['passive', 'low', 'medium'].map(risk => <option key={risk}>{risk}</option>)}</select></label>
        <label className="field-label">Filter observations<input disabled={busy} value={q} maxLength={200} onChange={e => {setQ(e.target.value); setOffset(0);}} placeholder="Asset or source"/></label></div>
      <fieldset className="proposal-observations" disabled={busy}><legend>Supporting observations · {count} / 24 selected</legend>
        {loading ? <p role="status">Loading recorded observations…</p> : page.items.map(record => <label className="proposal-observation" key={record.id}>
          <input type="checkbox" aria-label={`Select observation ${record.id}`} checked={!!selected[record.id]} disabled={!selected[record.id] && count >= 24} onChange={e => choose(record, e.target.checked)}/>
          <span><strong>{record.asset}</strong><small>{record.kind} · {record.source} · {record.id.slice(0, 8)}</small></span></label>)}
        {!loading && !page.total && <p>No observations match this run and filter. Capture native HTTP/TCP or supported CLI evidence first.</p>}
      </fieldset>
      <nav className="evidence-pager" aria-label="Proposal observation pages"><span>{page.total} matching observations</span>
        <button type="button" className="secondary" disabled={busy || !offset} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous</button>
        <button type="button" className="secondary" disabled={busy || offset + 50 >= page.total} onClick={() => setOffset(offset + 50)}>Next</button>
        <button type="button" className="secondary" disabled={busy || !count} onClick={() => setSelected({})}>Clear selection</button></nav>
      <label className="field-label">Follow-up objective<textarea disabled={busy} required maxLength={4000} rows={3} value={goal} onChange={e => setGoal(e.target.value)}/></label>
      <label className="http-toggle"><input type="checkbox" checked={useModel} disabled={busy || !runtime?.sdk_ready} onChange={e => setUseModel(e.target.checked)}/>
        <span><strong>Use the configured CAI model for follow-ups</strong><small>{runtime?.remote_model_enabled ? 'Selected URLs and normalized metadata go to the configured remote provider.' : 'Uses the configured local model endpoint.'} Raw bodies and registered files are excluded. Off uses explicitly labelled rules.</small></span></label>
      <p className="proposal-boundary">Planning sends no target traffic. Load a proposal on the canvas, or review its exact execution snapshot and approve it once.</p>
      <button className="primary" disabled={busy || !runId || !count || !goal.trim() || useModel && !runtime?.sdk_ready}>{busy ? 'Preparing follow-ups…' : 'Propose follow-up tests'}</button>
    </form>
    <div className="evidence-filters"><label className="field-label">Recorded evidence-guided plans<select disabled={busy} value={plan?.id || ''} onChange={e => restore(e.target.value)}>
      <option value="">Choose a saved plan</option>{history.map(p => <option key={p.id} value={p.id}>{new Date(p.created).toLocaleString()} · {p.planner} · {p.goal.slice(0, 65)}</option>)}</select></label>
      {plan && <button className="secondary" disabled={busy} onClick={() => restore(plan.id)}>Refresh plan status</button>}</div>
    {error && <p className="local-error" role="alert">{error}</p>}
    {plan && <section className="proposal-plan" aria-label="Evidence-guided plan">
      <div className="section-intro"><div><span className="tag">{plan.model_called ? 'CAI MODEL PROPOSALS' : 'EVIDENCE RULES · NO MODEL CALLED'}</span><h3>Proposed follow-up tests</h3><p>{plan.summary}</p><small>Plan {plan.id.slice(0, 8)} · Source run {plan.run_id.slice(0, 8)}</small></div>
        <button className="secondary" onClick={() => downloadJSON(`followups-${plan.id}.json`, plan)}>Export proposals</button></div>
      {!plan.current && <div className="comparison-notice" role="status"><p>{plan.stale_reason}</p></div>}
      {!plan.proposals.length && <p>No supported follow-up test was proposed from this evidence.</p>}
      {plan.proposals.map(proposal => <article className="proposal-card" key={proposal.id}>
        <div className="section-intro"><h4>{proposal.action.title}</h4><span className="tag">{proposal.action.risk} · PROPOSED</span></div>
        <code>{proposal.action.adapter_id} → {proposal.action.target}</code>
        <dl><dt>Hypothesis</dt><dd>{proposal.hypothesis}</dd><dt>Why this test</dt><dd>{proposal.rationale}</dd>
          <dt>Expected signal</dt><dd>{proposal.expected_signal}</dd><dt>Negative / inconclusive</dt><dd>{proposal.negative_signal}</dd></dl>
        <p>{proposal.action.cost.native_operations} native operation(s) · {proposal.action.cost.cli_invocations} CLI launch(es){proposal.action.cost.cli_invocations ? ' · Internal CLI requests are uncounted' : ''}</p>
        <small>{proposal.validation}. This checks the proposal contract, not the truth of its hypothesis.</small>
        <div className="scope-chips">{proposal.observation_ids.map(id => <code key={id}>Observation {id.slice(0, 8)}</code>)}</div>
        <div className="evidence-actions">{proposal.artifact_ids.map(id => <button className="secondary" key={id} onClick={() => setCapture({id})}>Supporting capture {id.slice(0, 8)}</button>)}</div>
        {!!proposal.requirements.length && <div className="proposal-requirements"><strong>Before execution</strong><ul>{proposal.requirements.map(reason => <li key={reason}>{reason}</li>)}</ul></div>}
        <button className="primary" disabled={busy || !plan.current} onClick={() => load(proposal)}>Load proposed workflow</button>
        <ProposalExecution plan={plan} proposal={proposal} onRun={onRun}/>
      </article>)}
      <details className="comparison-row"><summary>Planning coverage and limits</summary><ul>{plan.coverage_limits.map((limit, i) => <li key={i}>{limit}</li>)}</ul></details>
    </section>}
    {capture && <EvidenceViewer artifact={capture} close={() => setCapture(null)}/>}
  </section>;
}
