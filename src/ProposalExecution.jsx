import React, {useEffect, useState} from 'react';
import {api, downloadJSON} from './api.mjs';
const HTTPRoutingSettings=React.lazy(()=>import('./HTTPRoutingSettings'));
const ObjectAccessOptions = React.lazy(() => import('./ObjectAccessOptions'));

export default function ProposalExecution({plan, proposal, onRun}) {
  const [open, setOpen] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [inputs, setInputs] = useState([]), [history, setHistory] = useState([]), [review, setReview] = useState(null);
  const [profiles, setProfiles] = useState([]), [findings, setFindings] = useState([]);
  const [approved, setApproved] = useState(false), [clock, setClock] = useState(Date.now());
  const [options, setOptions] = useState({allow_cli: false, max_requests: 1, max_cli_invocations: 1, max_hosts: 64, max_seconds: 120, http_routing:{mode:'direct',proxy_url:'http://127.0.0.1:8080',ca_input_id:null}, input_refs: {}, verification_profile: null, finding_id: null});
  const cli = !!proposal.action.cost.cli_invocations, templates = proposal.action.adapter_id === 'nuclei';
  const refreshHistory = async () => setHistory((await api(`/agent/proposals/${plan.id}/executions`)).filter(r => r.proposal_id === proposal.id));
  useEffect(() => {
    if (!open) return;
    let alive = true;
    Promise.all([api('/inputs'), api(`/agent/proposals/${plan.id}/executions`), api('/verification/profiles'),
      plan.current && proposal.action.adapter_id === 'native_http' ? api(`/agent/proposals/${plan.id}/${proposal.id}/verification-findings`).catch(() => []) : Promise.resolve([])]).then(([i, h, p, f]) => {
      if (alive) {setInputs(i); setHistory(h.filter(r => r.proposal_id === proposal.id)); setProfiles(p); setFindings(f);}
    }).catch(e => {if (alive) setError(e.message);});
    return () => {alive = false;};
  }, [open, plan.id, proposal.id]);
  useEffect(() => {setApproved(false);}, [review?.id, review?.status]);
  useEffect(() => {
    if (!review) return;
    const config = review.snapshot.config;
    setOptions({allow_cli: config.allow_cli, max_requests: config.max_requests,
      max_cli_invocations: config.max_cli_invocations, max_hosts: config.max_hosts, max_seconds: config.max_seconds,
      http_routing:config.http_routing||{mode:'direct',proxy_url:'http://127.0.0.1:8080',ca_input_id:null}, input_refs: config.workflow.nodes.find(n => n.id === 'followup-test')?.data.inputRefs || {},
      verification_profile: config.verification?.profile_id || null, finding_id: config.verification?.finding_id || null,
      object_access: config.verification?.access?.options || null});
  }, [review?.id]);
  useEffect(() => {
    if (review?.status !== 'pending') return;
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [review?.id, review?.status]);
  const binding = review?.snapshot.config.verification;
  const selectedProfile = profiles.find(profile => profile.id === options.verification_profile);
  const selectProfile = id => {
    const profile = profiles.find(entry => entry.id === id);
    setOptions(previous => ({...previous, verification_profile: id || null, finding_id: null,
      max_requests: Math.max(profile?.native_operations || 1, previous.max_requests),
      object_access: id === 'object_access' ? {json_pointer: '/id'} : null}));
  };
  const pending = review?.status === 'pending', expired = pending && clock >= Date.parse(review.expires);
  const update = (key, value) => setOptions(previous => ({...previous, [key]: value}));
  const prepare = async event => {
    event.preventDefault(); setBusy(true); setError('');
    try {setReview(await api(`/agent/proposals/${plan.id}/${proposal.id}/executions`, options)); setClock(Date.now()); await refreshHistory();}
    catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const restore = async id => {
    if (!id) return;
    setBusy(true); setError(''); setApproved(false);
    try {setReview(await api('/agent/executions/' + id)); setClock(Date.now());}
    catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const revoke = async edit => {
    setBusy(true); setError('');
    try {
      setReview(await api(`/agent/executions/${review.id}/revoke`, {expected_hash: review.snapshot_hash}));
      await refreshHistory(); if (edit) setReview(null);
    } catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const dispatch = async () => {
    setBusy(true); setError('');
    try {
      const receipt = await api(`/agent/executions/${review.id}/dispatch`, {expected_hash: review.snapshot_hash, approve: approved});
      onRun(receipt.run);
    } catch (e) {
      setError(e.message);
      try {setReview(await api('/agent/executions/' + review.id)); await refreshHistory();} catch { /* Retain the last receipt and original error. */ }
    } finally {setBusy(false);}
  };
  return <div className="proposal-execution">
    <button className="secondary" aria-expanded={open} onClick={() => setOpen(value => !value)}>{open ? 'Hide execution review' : 'Review execution'}</button>
    {open && <section aria-label="Proposal execution review">
      <h4>Review and approve one execution</h4>
      <p>Prepare a saved snapshot, inspect its exact scope and limits, then approve it once. Reviews expire after 15 minutes and a runtime restart requires a new review.</p>
      <form onSubmit={prepare}>
        <fieldset disabled={busy || pending || !plan.current} className="execution-options"><legend>Execution settings</legend><React.Suspense fallback={null}><HTTPRoutingSettings value={options.http_routing} onChange={v=>update('http_routing',v)}/></React.Suspense>
          {proposal.action.adapter_id === 'native_http' && <label className="field-label">HTTP check profile<select
            value={options.verification_profile || ''} onChange={e => selectProfile(e.target.value)}>
            <option value="">Single capture</option>{profiles.map(p => <option key={p.id} value={p.id}>{p.title} · {p.native_operations} GETs</option>)}
          </select></label>}
          {options.verification_profile === 'object_access' && <React.Suspense fallback={<p>Loading test identities…</p>}>
            <ObjectAccessOptions target={proposal.action.target} value={options.object_access || {json_pointer: '/id'}}
              onChange={value => update('object_access', value)}/>
          </React.Suspense>}
          <label className="field-label">Native operation limit<input type="number" min={selectedProfile?.native_operations || 1}
            max={2048} value={options.max_requests} onChange={e => update('max_requests', Number(e.target.value))}/></label>
          {options.verification_profile && <label className="field-label">Link supported finding<select value={options.finding_id || ''} onChange={e => update('finding_id', e.target.value || null)}><option value="">No finding link</option>{findings.map(f => <option key={f.id} value={f.id}>{f.title} · {f.status}</option>)}</select><small>Only findings supported by this proposal's cited observations are offered. Review status remains an operator decision.</small></label>}
          {cli && <><label className="field-label">CLI launch limit<input type="number" min={1} max={256} value={options.max_cli_invocations} onChange={e => update('max_cli_invocations', Number(e.target.value))}/></label>
            <label className="http-toggle"><input type="checkbox" checked={options.allow_cli} onChange={e => update('allow_cli', e.target.checked)}/><span>Enable this catalog CLI adapter</span></label></>}
          <label className="field-label">Host limit<input type="number" min={1} max={256} value={options.max_hosts} onChange={e => update('max_hosts', Number(e.target.value))}/></label>
          <label className="field-label">Execution deadline (seconds)<input type="number" min={1} max={3600} value={options.max_seconds} onChange={e => update('max_seconds', Number(e.target.value))}/></label>
          {templates && <label className="field-label">Reviewed templates folder<select required value={options.input_refs.templates || ''} onChange={e => update('input_refs', e.target.value ? {templates: e.target.value} : {})}>
            <option value="">Select a registered folder</option>{inputs.filter(i => i.kind === 'folder').map(i => <option key={i.id} value={i.id}>{i.name}</option>)}</select><small>Register a reviewed folder in Inputs first. Its contents are bound to this execution.</small></label>}
        </fieldset>
        <button className="secondary" disabled={busy || pending || !plan.current}>{busy ? 'Checking execution…' : 'Prepare execution review'}</button>
      </form>
      <label className="field-label">Saved execution reviews<select disabled={busy} value={review?.id || ''} onChange={e => restore(e.target.value)}>
        <option value="">Select a review or receipt</option>{history.map(r => <option key={r.id} value={r.id}>{new Date(r.created).toLocaleString()} · {r.status} · {r.id.slice(0, 8)}</option>)}</select></label>
      {error && <p className="local-error" role="alert">{error}</p>}
      {review && <div className="execution-snapshot" role="region" aria-label="Saved execution snapshot">
        <span className="tag">{expired ? 'EXPIRED · REFRESH STATUS' : review.status.toUpperCase()}</span>
        <h4>{review.snapshot.action.adapter_id} → {review.snapshot.action.target}</h4>
        <strong>Snapshot scope</strong><div className="scope-chips">{review.snapshot.config.targets.map(t => <code key={t}>{t}</code>)}</div>
        <p>{review.snapshot.config.max_requests} native operation(s) maximum · {review.snapshot.config.allow_cli ? review.snapshot.config.max_cli_invocations : 0} CLI launch(es) maximum · {review.snapshot.config.max_hosts} host(s) maximum · {review.snapshot.config.max_seconds}s deadline</p>
        {binding && <div className="verification-pair">
          <strong>{binding.title} · {binding.access ? 'up to 3 sequential GETs' : 'two sequential GETs'}</strong>
          <p>{binding.expected_signal}</p>
          <table aria-label={binding.access ? 'Approved object access requests' : 'Approved request pair'}>
            <thead><tr><th>Role</th><th>Method / URL</th><th>{binding.access ? 'Identity' : 'Additional headers'}</th></tr></thead>
            <tbody>{binding.requests.map(request => <tr key={request.role}><td>{request.role}</td>
              <td><code>{request.method} {request.url}</code></td>
              <td>{binding.access ? binding.access.identities.find(identity => identity.id === request.identity_id)?.label
                : <code>{Object.keys(request.headers).length ? JSON.stringify(request.headers) : 'None'}</code>}</td>
            </tr>)}</tbody>
          </table>
          {binding.access ? <small>Expected IDs at <code>{binding.access.options.json_pointer}</code>{' '}
            are <code>{binding.access.options.owner_object}</code> for the owner object and <code>{binding.access.options.control_object}</code> for the control.
            The comparison starts only after both controls succeed. Saved responses contain metadata and fingerprints.</small>
            : <small>Credentials omitted · Redirects not followed · Results do not change finding review status.</small>}
          {binding.access && <p>Confirm the owner object belongs to the first account and the second account should be denied.</p>}
        </div>}
        {cli && <p>CLI-internal network requests are uncounted. Input scope checks do not constrain traffic inside the external binary.</p>}
        <small>Review {review.id.slice(0, 8)} · Expires {new Date(review.expires).toLocaleString()}</small>
        <code className="execution-hash">{review.snapshot_hash}</code>
        <details><summary>Workflow and pinned bindings</summary><pre>{JSON.stringify({http_routing:review.snapshot.config.http_routing_binding, workflow: review.snapshot.config.workflow, verification: review.snapshot.config.verification, binaries: review.snapshot.config.cli_binaries, inputs: review.snapshot.config.input_snapshots, input_hashes: review.snapshot.config.proposal_input_pins, credential_keys: review.snapshot.config.cli_credential_keys}, null, 2)}</pre></details>
        {review.reason && <p role="status">{review.reason}</p>}
        {pending && <><label className="http-toggle"><input type="checkbox" disabled={busy || expired} checked={approved} onChange={e => setApproved(e.target.checked)}/><span>I approve this exact scope, workflow and limits.</span></label>
          <div className="evidence-actions"><button className="primary" disabled={busy || expired || !approved} onClick={dispatch}>Approve & start once</button>
            <button className="secondary" disabled={busy} onClick={() => revoke(false)}>Revoke review</button><button className="secondary" disabled={busy} onClick={() => revoke(true)}>Change settings</button></div></>}
        {review.run_id && <button className="primary" disabled={busy} onClick={async () => {setBusy(true); try {onRun(await api('/runs/' + review.run_id));} catch(e) {setError(e.message);} finally {setBusy(false);}}}>Open linked run</button>}
        <div className="evidence-actions"><button className="secondary" disabled={busy} onClick={() => restore(review.id)}>Refresh review status</button><button className="secondary" onClick={() => downloadJSON(`execution-${review.id}.json`, review)}>Export execution receipt</button></div>
        <details><summary>Approval audit</summary><ol>{review.events.map(e => <li key={e.seq}>{new Date(e.time).toLocaleString()} · {e.kind}{e.data.reason ? ' · ' + e.data.reason : ''}</li>)}</ol></details>
      </div>}
    </section>}
  </div>;
}
