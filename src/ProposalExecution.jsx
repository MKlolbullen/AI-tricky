import React, {useEffect, useState} from 'react';
import {api, downloadJSON} from './api.mjs';

export default function ProposalExecution({plan, proposal, onRun}) {
  const [open, setOpen] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [inputs, setInputs] = useState([]), [history, setHistory] = useState([]), [review, setReview] = useState(null);
  const [approved, setApproved] = useState(false), [clock, setClock] = useState(Date.now());
  const [options, setOptions] = useState({allow_cli: false, max_requests: 1, max_cli_invocations: 1, max_hosts: 64, max_seconds: 120, input_refs: {}});
  const cli = !!proposal.action.cost.cli_invocations, templates = proposal.action.adapter_id === 'nuclei';
  const refreshHistory = async () => setHistory((await api(`/agent/proposals/${plan.id}/executions`)).filter(r => r.proposal_id === proposal.id));
  useEffect(() => {
    if (!open) return;
    let alive = true;
    Promise.all([api('/inputs'), api(`/agent/proposals/${plan.id}/executions`)]).then(([i, h]) => {
      if (alive) {setInputs(i); setHistory(h.filter(r => r.proposal_id === proposal.id));}
    }).catch(e => {if (alive) setError(e.message);});
    return () => {alive = false;};
  }, [open, plan.id, proposal.id]);
  useEffect(() => {setApproved(false);}, [review?.id, review?.status]);
  useEffect(() => {
    if (!review) return;
    const config = review.snapshot.config;
    setOptions({allow_cli: config.allow_cli, max_requests: config.max_requests,
      max_cli_invocations: config.max_cli_invocations, max_hosts: config.max_hosts, max_seconds: config.max_seconds,
      input_refs: config.workflow.nodes.find(n => n.id === 'followup-test')?.data.inputRefs || {}});
  }, [review?.id]);
  useEffect(() => {
    if (review?.status !== 'pending') return;
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [review?.id, review?.status]);
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
        <fieldset disabled={busy || pending || !plan.current} className="execution-options"><legend>Execution settings</legend>
          <label className="field-label">Native operation limit<input type="number" min={1} max={2048} value={options.max_requests} onChange={e => update('max_requests', Number(e.target.value))}/></label>
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
        {cli && <p>CLI-internal network requests are uncounted. Input scope checks do not constrain traffic inside the external binary.</p>}
        <small>Review {review.id.slice(0, 8)} · Expires {new Date(review.expires).toLocaleString()}</small>
        <code className="execution-hash">{review.snapshot_hash}</code>
        <details><summary>Workflow and pinned bindings</summary><pre>{JSON.stringify({workflow: review.snapshot.config.workflow, binaries: review.snapshot.config.cli_binaries, inputs: review.snapshot.config.input_snapshots, input_hashes: review.snapshot.config.proposal_input_pins, credential_keys: review.snapshot.config.cli_credential_keys}, null, 2)}</pre></details>
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
