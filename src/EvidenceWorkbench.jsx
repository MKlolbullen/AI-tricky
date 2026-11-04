import React, {useEffect, useState} from 'react';
import {api, downloadJSON} from './api.mjs';

const statuses = ['candidate', 'triaged', 'verified', 'rejected', 'resolved'];
const severities = ['info', 'low', 'medium', 'high', 'critical'];
const timestamp = value => new Date(value).toLocaleString();
const runLabel = run => `${run.id.slice(0, 8)} · ${run.status} · ${timestamp(run.created)}`;

function Pager({page, offset, setOffset}) {
  return <nav className="evidence-pager" aria-label="Results pages">
    <span>{page.items.length ? `${offset + 1}–${Math.min(offset + page.items.length, page.total)} of ${page.total}` : '0 results'}</span>
    <button className="secondary" disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous</button>
    <button className="secondary" disabled={offset + 50 >= page.total} onClick={() => setOffset(offset + 50)}>Next</button>
  </nav>;
}

function RunFilter({runs, value, onChange, label = 'Run', disabled = false, emptyLabel = 'All runs'}) {
  return <label className="field-label">{label}<select value={value} disabled={disabled} onChange={e => onChange(e.target.value)}>
    <option value="">{emptyLabel}</option>{runs.map(r => <option key={r.id} value={r.id}>{runLabel(r)}</option>)}
  </select></label>;
}

export function EvidenceViewer({artifact, close}) {
  const [data, setData] = useState(null), [error, setError] = useState('');
  useEffect(() => {
    let alive = true;
    setData(null); setError('');
    api('/artifacts/' + artifact.id).then(d => {if (alive) setData(d);}).catch(e => {if (alive) setError(e.message);});
    return () => {alive = false;};
  }, [artifact.id]);
  return <section className="report evidence-capture" aria-label="Captured evidence">
    <div className="section-intro"><div><h4>Original capture</h4><code>{artifact.id}</code></div>
      <div className="evidence-actions"><button className="secondary" disabled={data === null} onClick={() => downloadJSON(`evidence-${artifact.id}.json`, data)}>Download JSON</button>
        <button className="secondary" onClick={close}>Close capture</button></div></div>
    {error && <p className="local-error" role="alert">{error}</p>}
    {!error && <pre>{data === null ? 'Loading capture…' : JSON.stringify(data, null, 2)}</pre>}
  </section>;
}

export function ObservationBrowser({runs}) {
  const [runId, setRunId] = useState(''), [kind, setKind] = useState(''), [q, setQ] = useState('');
  const [offset, setOffset] = useState(0), [page, setPage] = useState({items: [], total: 0});
  const [selected, setSelected] = useState(null), [capture, setCapture] = useState(null);
  const [error, setError] = useState(''), [loading, setLoading] = useState(false), [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let alive = true; setLoading(true); setError('');
    const query = new URLSearchParams({run_id: runId, kind, q, offset, limit: 50});
    api('/observations?' + query).then(p => {
      if (!alive) return;
      if (offset && offset >= p.total) {setOffset(p.total ? Math.floor((p.total - 1) / 50) * 50 : 0); return;}
      setPage(p);
    }).catch(e => {if (alive) setError(e.message);}).finally(() => {if (alive) setLoading(false);});
    return () => {alive = false;};
  }, [runId, kind, q, offset, refresh]);
  const filter = setter => value => {setter(value); setOffset(0); setSelected(null); setCapture(null);};
  return <section className="evidence-workbench">
    <div className="section-intro"><div><h3>Structured observations</h3><p>Normalized captures with source, parser version and original evidence. An observation does not establish a vulnerability.</p></div>
      <button className="secondary" onClick={() => setRefresh(v => v + 1)}>Refresh observations</button></div>
    <div className="evidence-filters"><RunFilter runs={runs} value={runId} onChange={filter(setRunId)}/>
      <label className="field-label">Kind<select value={kind} onChange={e => filter(setKind)(e.target.value)}><option value="">All kinds</option>{['http', 'service', 'dns', 'endpoint', 'detection'].map(k => <option key={k}>{k}</option>)}</select></label>
      <label className="field-label">Search<input value={q} maxLength={200} onChange={e => filter(setQ)(e.target.value)} placeholder="Asset or source"/></label></div>
    {error && <p className="local-error" role="alert">{error}</p>}
    <div className="evidence-columns"><div aria-busy={loading}>
      {loading ? <p role="status">Loading observations…</p> : <div className="evidence-list">{page.items.map(o => <button className={'evidence-result ' + (selected?.id === o.id ? 'selected' : '')} key={o.id} onClick={() => {setSelected(o); setCapture(null);}}>
        <span className="tag">{o.kind}</span><strong>{o.asset}</strong><span>{o.source} · Run {o.run_id.slice(0, 8)}</span><small>{timestamp(o.observed_at)}</small></button>)}</div>}
      {!loading && !page.total && <div className="local-empty"><strong>No normalized observations</strong><p>Run a supported native or CLI workflow. Existing captures are indexed when this view opens.</p></div>}
      <Pager page={page} offset={offset} setOffset={setOffset}/></div>
      <aside className="evidence-detail">{selected ? <><span className="tag">OBSERVATION</span><h3>{selected.asset}</h3>
        <dl><dt>Source</dt><dd>{selected.source}</dd><dt>Parser</dt><dd>{selected.parser_version}</dd><dt>Run</dt><dd>{selected.run_id}</dd><dt>Node</dt><dd>{selected.node_id || 'Assessment'}</dd><dt>Time basis</dt><dd>{selected.time_basis}</dd></dl>
        <pre>{JSON.stringify(selected.data, null, 2)}</pre><button className="secondary" onClick={() => setCapture({id: selected.artifact_id})}>Inspect original capture</button></> : <p>Select an observation to inspect its normalized data and provenance.</p>}</aside>
    </div>{capture && <EvidenceViewer artifact={capture} close={() => setCapture(null)}/>}
  </section>;
}

function FindingReview({finding, onSaved}) {
  const [status, setStatus] = useState(finding.status), [severity, setSeverity] = useState(finding.severity);
  const [confidence, setConfidence] = useState(finding.confidence), [note, setNote] = useState(''), [evidenceId, setEvidenceId] = useState('');
  const [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const verificationEvidence = finding.verification_evidence || [];
  const save = async event => {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const result = await api(`/findings/${finding.id}/reviews`, {expected_revision: finding.revision, status, severity, confidence, note, evidence_id: evidenceId || null});
      onSaved(result);
    } catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  return <form className="finding-review" onSubmit={save}><h4>Record operator review</h4>
    <div className="evidence-filters"><label className="field-label">Review status<select value={status} onChange={e => setStatus(e.target.value)}>{statuses.map(s => <option key={s}>{s}</option>)}</select></label>
      <label className="field-label">Severity<select value={severity} onChange={e => setSeverity(e.target.value)}>{severities.map(s => <option key={s}>{s}</option>)}</select></label>
      <label className="field-label">Confidence<select value={confidence} onChange={e => setConfidence(e.target.value)}>{['unknown', 'low', 'medium', 'high'].map(s => <option key={s}>{s}</option>)}</select></label></div>
    <label className="field-label">Supporting capture{status === 'verified' ? ' (required)' : ''}<select required={status === 'verified'} value={evidenceId} onChange={e => setEvidenceId(e.target.value)}><option value="">Select captured evidence</option>{verificationEvidence.map(a => <option key={a.id} value={a.id}>{a.name} · {a.id.slice(0, 8)}</option>)}</select></label>
    <label className="field-label">Review note<textarea required maxLength={4000} rows={3} value={note} onChange={e => setNote(e.target.value)} placeholder="What supports this decision? Record reproduction details or the reason for rejection/resolution."/></label>
    <small>Verification records your evidence assessment. Saving a review sends no target requests.</small>
    {error && <p className="local-error" role="alert">{error}</p>}
    <button className="primary" disabled={busy || !note.trim()}>{busy ? 'Saving review…' : 'Save review'}</button>
  </form>;
}

export function FindingsWorkbench({runs}) {
  const [runId, setRunId] = useState(''), [status, setStatus] = useState(''), [severity, setSeverity] = useState(''), [q, setQ] = useState('');
  const [page, setPage] = useState({items: [], total: 0}), [offset, setOffset] = useState(0), [refresh, setRefresh] = useState(0);
  const [selectedId, setSelectedId] = useState(null), [finding, setFinding] = useState(null), [capture, setCapture] = useState(null);
  const [error, setError] = useState(''), [loading, setLoading] = useState(false);
  useEffect(() => {
    let alive = true; setLoading(true); setError('');
    const query = new URLSearchParams({run_id: runId, status, severity, q, limit: 50, offset});
    api('/findings?' + query).then(p => {
      if (!alive) return;
      if (offset && offset >= p.total) {setOffset(p.total ? Math.floor((p.total - 1) / 50) * 50 : 0); return;}
      setPage(p);
    }).catch(e => {if (alive) setError(e.message);}).finally(() => {if (alive) setLoading(false);});
    return () => {alive = false;};
  }, [runId, status, severity, q, offset, refresh]);
  useEffect(() => {
    let alive = true; setFinding(null); setCapture(null);
    if (selectedId) api('/findings/' + selectedId).then(f => {if (alive) setFinding(f);}).catch(e => {if (alive) setError(e.message);});
    return () => {alive = false;};
  }, [selectedId, refresh]);
  const filter = setter => value => {setter(value); setOffset(0); setSelectedId(null);};
  return <section className="evidence-workbench">
    <div className="section-intro"><div><h3>Findings workbench</h3><p>Persistent candidate IDs, evidence occurrences and operator review history. Severity, confidence and review status are independent.</p></div>
      <button className="secondary" onClick={() => setRefresh(v => v + 1)}>Refresh findings</button></div>
    <div className="evidence-filters"><RunFilter runs={runs} value={runId} onChange={filter(setRunId)}/>
      <label className="field-label">Status<select value={status} onChange={e => filter(setStatus)(e.target.value)}><option value="">All statuses</option>{statuses.map(s => <option key={s}>{s}</option>)}</select></label>
      <label className="field-label">Severity<select value={severity} onChange={e => filter(setSeverity)(e.target.value)}><option value="">All severities</option>{severities.map(s => <option key={s}>{s}</option>)}</select></label>
      <label className="field-label">Search<input value={q} maxLength={200} onChange={e => filter(setQ)(e.target.value)} placeholder="Title or asset"/></label></div>
    {error && <p className="local-error" role="alert">{error}</p>}
    <div className="evidence-columns"><div aria-busy={loading}>{loading ? <p role="status">Loading findings…</p> : <div className="evidence-list">{page.items.map(f => <button key={f.id} className={'evidence-result ' + (selectedId === f.id ? 'selected' : '')} onClick={() => setSelectedId(f.id)}>
      <span className={'tag severity-' + f.severity}>{f.severity} · {f.status}</span><strong>{f.title}</strong><code>{f.asset}</code><small>{f.id.slice(0, 8)} · {f.run_count} run(s) · confidence {f.confidence}</small></button>)}</div>}
      {!loading && !page.total && <div className="local-empty"><strong>No findings match these filters</strong><p>Nuclei matches and structured CAI evidence candidates enter this queue. Inventory observations remain in Observations.</p></div>}
      <Pager page={page} offset={offset} setOffset={setOffset}/></div>
      <aside className="evidence-detail">{finding ? <><span className="tag">{finding.status.toUpperCase()}</span><h3>{finding.title}</h3><code>{finding.asset}</code><p>{finding.rationale}</p>
        {finding.observed_after_review && <div className="comparison-notice"><p>Additional evidence was captured after the latest review. The recorded decision is preserved; review the new occurrence before relying on it.</p></div>}
        {!finding.occurrences.some(o => o.active) && <div className="comparison-notice"><p>This finding is retained from historical parser output. Its superseded occurrences are excluded from current run comparisons.</p></div>}
        <dl><dt>Finding ID</dt><dd>{finding.id}</dd><dt>Source</dt><dd>{finding.source}</dd><dt>First seen</dt><dd>{timestamp(finding.first_seen)}</dd><dt>Last seen</dt><dd>{timestamp(finding.last_seen)}</dd></dl>
        <FindingReview key={finding.id + ':' + finding.revision} finding={finding} onSaved={() => setRefresh(v => v + 1)}/>
        <h4>Evidence occurrences</h4>{finding.occurrences.map(o => <article className="evidence-occurrence" key={o.observation_id}><strong>Run {o.run_id.slice(0, 8)}</strong><small>{timestamp(o.observed_at)} · {o.node_id || 'Assessment'} · Parser {(o.parser_versions || []).join(', ')}{o.active ? '' : ' · superseded'}</small><p>Observed severity: {o.snapshot.severity}</p>
          {o.snapshot.next_test && <p>Suggested test: {o.snapshot.next_test}</p>}
          <div className="evidence-actions">{o.evidence_ids.map(id => <button key={id} className="secondary" onClick={() => setCapture({id})}>Capture {id.slice(0, 8)}</button>)}</div></article>)}
        <h4>Review history</h4>{!finding.reviews.length && <p>No operator reviews yet.</p>}{finding.reviews.map(r => <article className="evidence-occurrence" key={r.id}><strong>{r.previous.status} → {r.decision.status}</strong><small>{timestamp(r.created)} · Revision {r.revision}</small><p>Severity {r.previous.severity} → {r.decision.severity} · Confidence {r.previous.confidence} → {r.decision.confidence}</p><p>{r.note}</p>{r.evidence_id && <button className="secondary" onClick={() => setCapture({id: r.evidence_id})}>Review evidence</button>}</article>)}</> : <p>{selectedId ? 'Loading finding…' : 'Select a finding to review its evidence and history.'}</p>}</aside>
    </div>{capture && <EvidenceViewer artifact={capture} close={() => setCapture(null)}/>}
  </section>;
}

export function RunComparison({runs}) {
  const [baseline, setBaseline] = useState(runs[1]?.id || ''), [current, setCurrent] = useState(runs[0]?.id || '');
  const [comparison, setComparison] = useState(null), [error, setError] = useState(''), [busy, setBusy] = useState(false);
  const [state, setState] = useState('all'), [view, setView] = useState('observations'), [capture, setCapture] = useState(null);
  useEffect(() => {
    setCurrent(value => value || runs[0]?.id || '');
    setBaseline(value => value || runs.find(r => r.id !== (current || runs[0]?.id))?.id || '');
  }, [runs, current]);
  const compare = async event => {
    event.preventDefault(); setBusy(true); setError(''); setComparison(null); setCapture(null);
    try {setComparison(await api(`/runs/${current}/compare?baseline=${encodeURIComponent(baseline)}`));} catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const select = setter => value => {setter(value); setComparison(null); setCapture(null);};
  const rows = comparison ? comparison[view].filter(r => state === 'all' || r.state === state) : [];
  return <section className="evidence-workbench"><div className="section-intro"><div><h3>Compare recorded runs</h3><p>Compare normalized observations and finding occurrences. Missing evidence never automatically resolves a finding.</p></div></div>
    <form className="comparison-controls" onSubmit={compare}><RunFilter runs={runs} label="Baseline run" value={baseline} disabled={busy} emptyLabel="Select a run" onChange={select(setBaseline)}/><RunFilter runs={runs} label="Current run" value={current} disabled={busy} emptyLabel="Select a run" onChange={select(setCurrent)}/>
      <button className="primary" disabled={busy || !baseline || !current || baseline === current}>{busy ? 'Comparing…' : 'Compare runs'}</button></form>
    {runs.length < 2 && <p>Record at least two runs to compare results.</p>}{error && <p className="local-error" role="alert">{error}</p>}
    {comparison && <><div className="comparison-summary">{Object.entries(comparison.summary).map(([key, count]) => <div key={key}><strong>{count}</strong><span>{key.replaceAll('_', ' ')}</span></div>)}</div>
      <div className="comparison-notice"><p>{comparison.absence_means}</p>{comparison.warnings.map(w => <p key={w}>{w}</p>)}</div>
      <div className="evidence-filters"><label className="field-label">Compare<select value={view} onChange={e => {setView(e.target.value); setState('all');}}><option value="observations">Observations</option><option value="findings">Finding occurrences</option></select></label>
        <label className="field-label">Change<select value={state} onChange={e => setState(e.target.value)}>{['all', 'new', 'changed', view === 'findings' ? 'recurring' : 'unchanged', 'not_observed'].map(s => <option key={s} value={s}>{s.replaceAll('_', ' ')}</option>)}</select></label>
        <button className="secondary" onClick={() => downloadJSON(`comparison-${comparison.baseline_id.slice(0, 8)}-${comparison.current_id.slice(0, 8)}.json`, comparison)}>Export comparison</button></div>
      {!rows.length && <p>No results match this change filter.</p>}{rows.map(row => <details className="comparison-row" key={row.fingerprint || row.id}><summary><span className={'tag change-' + row.state}>{row.state.replaceAll('_', ' ')}</span><strong>{row.title || row.asset}</strong><span>{row.source}{row.kind ? ' · ' + row.kind : ''}</span></summary>
        <div className="comparison-values">{['before', 'after'].map(side => <section key={side}><h4>{side === 'before' ? 'Baseline evidence' : 'Current evidence'}</h4>{!row[side].length && <p>Not observed</p>}{row[side].map((value, i) => <div key={i}><pre>{JSON.stringify(value.data || value, null, 2)}</pre>{value.evidence_ids?.map(id => <button className="secondary" key={id} onClick={() => setCapture({id})}>Capture {id.slice(0, 8)}</button>)}</div>)}</section>)}</div></details>)}
      <details className="comparison-row"><summary>Parser coverage and capture limits</summary>{comparison.coverage.map(c => <p key={c.id}><code>{c.name}</code> · {c.report.supported ? 'supported parser' : 'raw evidence only'}{c.report.partial ? ' · partial capture' : ''}{c.report.unparsed_lines ? ` · ${c.report.unparsed_lines} unparsed lines` : ''}</p>)}</details>
    </>}{capture && <EvidenceViewer artifact={capture} close={() => setCapture(null)}/>}</section>;
}
