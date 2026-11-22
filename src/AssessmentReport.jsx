import React, {useEffect, useState} from 'react';
import {api, downloadJSON, downloadText} from './api.mjs';
import {EvidenceViewer} from './EvidenceWorkbench';
import {buildManifest, renderMarkdown} from './assessmentReport.mjs';

function ReportDraft({runId}) {
  const [snapshot, setSnapshot] = useState(null);
  const [selected, setSelected] = useState({});
  const [capture, setCapture] = useState(null);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    setError('');
    api('/runs/' + encodeURIComponent(runId) + '/assessment-report')
      .then(data => {if (active) setSnapshot(data);})
      .catch(e => {if (active) setError(e.message);});
    return () => {active = false;};
  }, [runId, attempt]);
  if (error) return <p role="alert">{error} <button className="secondary" onClick={() => setAttempt(attempt + 1)}>Retry</button></p>;
  if (!snapshot) return <p role="status">Loading saved reviews…</p>;
  function toggleFinding(f) {
    setSelected(previous => {
      const next = {...previous};
      if (next[f.id]) delete next[f.id];
      else next[f.id] = {summary: '', artifacts: [...f.artifact_ids]};
      return next;
    });
  }
  function update(id, change) {
    setSelected(previous => ({...previous, [id]: {...previous[id], ...change}}));
  }
  const manifest = buildManifest(snapshot, selected);
  const markdown = renderMarkdown(manifest);
  const missing = manifest.findings.some(f => !f.artifact_ids.length);
  const canExport = manifest.findings.length > 0 && !missing;
  return <>
    <h4>Reviewed findings</h4>
    <p>{snapshot.findings.length} reviewed · {snapshot.unreviewed_count} awaiting review</p>
    {!snapshot.findings.length && <p>Record an operator review in Findings to include a finding from this run.</p>}
    {snapshot.findings.map(f => <article className="comparison-row" key={f.id}>
      <label className="http-toggle"><input type="checkbox" checked={!!selected[f.id]} onChange={() => toggleFinding(f)}/>
        <span><strong>{f.local_title}</strong><small>{f.local_asset} · {f.review.status} · {f.review.severity}</small></span></label>
      {selected[f.id] && <>
        <label className="field-label">Publishable summary (optional)<textarea maxLength={2000} rows={2} value={selected[f.id].summary}
          onChange={e => update(f.id, {summary: e.target.value})}/></label>
        <fieldset><legend>Occurrence evidence</legend>{f.artifact_ids.map(id => <div className="evidence-actions" key={id}>
          <label><input type="checkbox" checked={selected[f.id].artifacts.includes(id)}
            onChange={e => update(f.id, {artifacts: e.target.checked ? [...selected[f.id].artifacts, id] : selected[f.id].artifacts.filter(a => a !== id)})}/> {id}</label>
          <button className="secondary" onClick={() => setCapture(id)}>Inspect capture</button>
        </div>)}</fieldset>
        {f.review.artifact_id && <button className="secondary" onClick={() => setCapture(f.review.artifact_id)}>Inspect review evidence</button>}
      </>}
    </article>)}
    <h4>Export preview</h4>
    <p>Both files include scope hosts, IPs, the latest operator decision for each finding, evidence IDs and any summary you enter. URL paths, original finding text, review notes and capture contents stay local.</p>
    <pre className="report" aria-label="Markdown preview">{markdown}</pre>
    <details><summary>JSON manifest preview</summary><pre>{JSON.stringify(manifest, null, 2)}</pre></details>
    {missing && <p role="status">Select at least one saved capture for each included finding.</p>}
    <div className="evidence-actions">
      <button className="primary" disabled={!canExport} onClick={() => downloadText('assessment-' + runId + '.md', markdown, 'text/markdown')}>Download Markdown</button>
      <button className="secondary" disabled={!canExport} onClick={() => downloadJSON('assessment-' + runId + '.json', manifest)}>Download manifest</button>
    </div>
    {capture && <EvidenceViewer readOnly artifact={{id: capture}} close={() => setCapture(null)}/>}
  </>;
}

export default function AssessmentReport({runs}) {
  const [runId, setRunId] = useState('');
  const completed = runs.filter(r => r.status === 'completed');
  return <section className="evidence-workbench" aria-label="Assessment report builder">
    <div className="section-intro"><div><h3>Assessment report</h3><p>Select a completed run and the reviewed findings to share.</p></div></div>
    <label className="field-label">Completed run<select value={runId} onChange={e => setRunId(e.target.value)}>
      <option value="">Select a run</option>{completed.map(r => <option key={r.id} value={r.id}>{r.id.slice(0, 8)} · {new Date(r.created).toLocaleString()} · {r.config.targets.join(', ')}</option>)}
    </select></label>
    {!completed.length && <p>No completed runs are available.</p>}
    {runId && <ReportDraft key={runId} runId={runId}/>}
  </section>;
}
