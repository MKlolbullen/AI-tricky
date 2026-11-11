import React, {useEffect, useState} from 'react';
import {api, downloadJSON} from './api.mjs';

function VerificationCard({report, onCapture}) {
  const access = report.profile_id === 'object_access';
  const roles = access ? ['owner', 'control', 'other'] : ['baseline', 'variant'];
  const labels = {owner: 'Owner object', control: 'Second identity control', other: 'Second identity on owner object'};
  return <article className="verification-card" aria-label="Paired verification result">
    <div className="section-intro"><h4>{report.title}</h4><span className="tag">{report.outcome.replaceAll('_', ' ').toUpperCase()}</span></div>
    <p>{report.summary}</p><small>Run {report.run_id.slice(0, 8)} · {report.run_status} · Profile version {report.profile_version}</small>
    <p className="proposal-boundary">This result concerns the selected check. Finding severity, confidence and review status remain separate.</p>
    {report.evidence_current === false && <p className="local-error" role="status">Captured evidence no longer matches the saved comparison. Recorded outcome: {report.recorded_outcome}.</p>}
    <table aria-label={access ? 'Object access evidence' : 'Baseline and variant evidence'}>
      <thead><tr><th>Role</th><th>HTTP</th>{access && <th>Resource ID matched</th>}
        <th>Bytes / connected IP</th><th>Capture</th></tr></thead>
      <tbody>{roles.map(role => {
        const capture = report.captures.find(c => c.request.role === role);
        const label = report.identities?.find(identity => identity.id === capture?.request.identity_id)?.label;
        return <tr key={role}>
          <td>{labels[role] || role}{label && <small> · {label}</small>}</td>
          <td>{capture?.status || 'Not captured'}{capture?.truncated ? ' · truncated' : ''}</td>
          {access && <td>{capture?.artifact_id ? (capture.resource_marker_matched ? 'Yes' : 'No') : '—'}</td>}
          <td>{capture?.body_bytes ?? '—'} · {capture?.connected_ip || '—'}</td>
          <td>{capture?.artifact_id ? <button className="secondary" onClick={() => onCapture(capture.artifact_id)}>Inspect {role}</button> : 'Unavailable'}</td>
        </tr>;
      })}</tbody>
    </table>
    {!!report.differences.length && <details open><summary>Captured differences ({report.differences.length})</summary><table><thead><tr><th>Field</th><th>Baseline</th><th>Variant</th></tr></thead><tbody>{report.differences.map(d => <tr key={d.field}><td>{d.field}</td><td><code>{d.baseline ?? 'Absent'}</code></td><td><code>{d.variant ?? 'Absent'}</code></td></tr>)}</tbody></table></details>}
    <details><summary>Request bindings, response headers and fingerprints</summary><pre>{JSON.stringify({facts: report.facts, captures: report.captures, approval: report.approval, profile_hash: report.contract_hash}, null, 2)}</pre></details>
    <details><summary>Coverage and interpretation</summary><ul>{report.coverage_limits.map((reason, i) => <li key={i}>{reason}</li>)}</ul></details>
    <div className="evidence-actions"><button className="secondary" onClick={() => downloadJSON(`verification-${report.run_id}.json`, report)}>Export verification result</button>{report.comparison_artifact_id && <button className="secondary" onClick={() => onCapture(report.comparison_artifact_id)}>Inspect saved comparison</button>}</div>
  </article>;
}

export function RunVerification({run, onCapture}) {
  const [report, setReport] = useState(null), [error, setError] = useState('');
  useEffect(() => {
    let alive = true; setReport(null); setError('');
    const read = () => api(`/runs/${run.id}/verification`).then(r => {if (alive) setReport(r);}).catch(e => {if (alive) setError(e.message);});
    read(); const timer = ['queued', 'running', 'paused'].includes(run.status) ? setInterval(read, 1500) : null;
    return () => {alive = false; if (timer) clearInterval(timer);};
  }, [run.id, run.status]);
  return <section className="verification-results" aria-label="Controlled verification"><h4>Controlled verification</h4>{error && <p className="local-error" role="alert">{error}</p>}{report ? <VerificationCard report={report} onCapture={onCapture}/> : !error && <p role="status">Loading paired evidence…</p>}</section>;
}

export function FindingVerifications({findingId, onCapture}) {
  const [reports, setReports] = useState([]), [error, setError] = useState(''), [refresh, setRefresh] = useState(0), [loading, setLoading] = useState(true);
  useEffect(() => {
    let alive = true; setReports([]); setError(''); setLoading(true);
    api(`/findings/${findingId}/verification`).then(r => {if (alive) setReports(r);}).catch(e => {if (alive) setError(e.message);}).finally(() => {if (alive) setLoading(false);});
    return () => {alive = false;};
  }, [findingId, refresh]);
  return <section className="verification-results" aria-label="Linked verification checks"><div className="section-intro"><h4>Linked verification checks</h4><button className="secondary" onClick={() => setRefresh(value => value + 1)}>Refresh checks</button></div>{error && <p className="local-error" role="alert">{error}</p>}{loading ? <p role="status">Loading linked checks…</p> : !reports.length && <p>No approved paired checks are linked to this finding.</p>}{reports.map(report => <VerificationCard key={report.run_id} report={report} onCapture={onCapture}/>)}</section>;
}
