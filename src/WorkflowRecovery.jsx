import React, {useEffect, useState} from 'react';
import {api, downloadJSON} from './api.mjs';
const HTTPRoutingSettings=React.lazy(()=>import('./HTTPRoutingSettings'));

export default function WorkflowRecovery({run, onRun, onArtifact}) {
  const [open, setOpen] = useState(false), [info, setInfo] = useState(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const [selected, setSelected] = useState([]), [review, setReview] = useState(null);
  const [approved, setApproved] = useState(false), [clock, setClock] = useState(Date.now());
  const [options, setOptions] = useState({allow_cli: !!run.config.allow_cli,
    max_requests: run.config.max_requests || 256, max_cli_invocations: run.config.max_cli_invocations || 64,
    http_routing:run.config.http_routing||{mode:'direct',proxy_url:'http://127.0.0.1:8080',ca_input_id:null}, max_hosts: run.config.max_hosts || 64, max_seconds: run.config.max_seconds || 240});
  useEffect(() => {
    if (!open) return;
    let alive = true;
    api(`/runs/${run.id}/recovery`).then(value => {
      if (alive) {setInfo(value); if (!info) setSelected(value.nodes.filter(n => !n.checkpoint_available).map(n => n.id));}
    }).catch(e => {if (alive) setError(e.message);});
    return () => {alive = false;};
  }, [open, run.id]);
  useEffect(() => {setApproved(false);}, [review?.id, review?.status]);
  useEffect(() => {
    if (!review) return;
    const {node_ids, ...saved} = review.snapshot.options;
    setSelected(node_ids); setOptions(saved);
  }, [review?.id]);
  useEffect(() => {
    if (review?.status !== 'pending') return;
    const timer = setInterval(() => setClock(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [review?.id, review?.status]);
  if (run.config.engine !== 'workflow' || !run.config.allow_http || run.config.verification ||
      !['completed', 'failed', 'cancelled', 'interrupted'].includes(run.status)) return null;
  const pending = review?.status === 'pending', expired = pending && clock >= Date.parse(review.expires);
  const cli = run.config.workflow.nodes.some(n => n.data.kind === 'catalog_tool');
  const update = (key, value) => setOptions(previous => ({...previous, [key]: value}));
  const refresh = async () => setInfo(await api(`/runs/${run.id}/recovery`));
  const prepare = async event => {
    event.preventDefault(); setBusy(true); setError(''); setApproved(false);
    try {
      setReview(await api(`/runs/${run.id}/recoveries`, {...options, node_ids: selected}));
      setClock(Date.now()); await refresh();
    } catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const restore = async id => {
    if (!id) return;
    setBusy(true); setError(''); setApproved(false);
    try {setReview(await api(`/recoveries/${id}`)); setClock(Date.now());}
    catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const edit = async () => {
    setBusy(true); setError(''); setApproved(false);
    try {
      if (pending) await api(`/recoveries/${review.id}/revoke`, {expected_hash: review.snapshot_hash});
      setReview(null); await refresh();
    } catch (e) {setError(e.message);} finally {setBusy(false);}
  };
  const dispatch = async () => {
    setBusy(true); setError('');
    try {
      const receipt = await api(`/recoveries/${review.id}/dispatch`, {expected_hash: review.snapshot_hash, approve: approved});
      onRun(receipt.run);
    } catch (e) {
      setError(e.message);
      try {setReview(await api(`/recoveries/${review.id}`)); await refresh();} catch { /* Keep original error and receipt. */ }
    } finally {setBusy(false);}
  };
  return <section className="workflow-recovery proposal-execution" aria-label="Workflow recovery">
    <button className="secondary" aria-expanded={open} onClick={() => setOpen(v => !v)}>
      {open ? 'Hide workflow recovery' : 'Recover workflow branches'}
    </button>
    {open && <div>
      <h4>Recover selected workflow branches</h4>
      <p>Select retry roots. The review includes their descendants and any upstream steps without usable checkpoints.
        Other branches stay in the source run. Preparation makes no target requests or model calls.</p>
      <form onSubmit={prepare}>
        <fieldset disabled={busy || pending || !info} className="execution-options">
          <legend>Recovery settings</legend><React.Suspense fallback={null}><HTTPRoutingSettings value={options.http_routing||review?.snapshot.config.http_routing} onChange={v=>setOptions(s=>({...s,http_routing:v}))}/></React.Suspense>
          <div className="recovery-node-list" role="group" aria-label="Retry roots">
            {info?.nodes.map(n => <label key={n.id} className="http-toggle">
              <input type="checkbox" aria-label={`Retry ${n.title}`} checked={selected.includes(n.id)}
                onChange={e => setSelected(ids => e.target.checked ? [...ids, n.id] : ids.filter(id => id!==n.id))}/>
              <span><strong>{n.title}</strong><small>{n.id} · {n.status} · {n.checkpoint_available ? 'Checkpoint available' : 'Needs execution'}</small></span>
            </label>)}
          </div>
          <label className="field-label">Recovery native operation limit<input type="number" min="1" max="2048" value={options.max_requests} onChange={e => update('max_requests', Number(e.target.value))}/></label>
          {cli && <><label className="http-toggle"><input type="checkbox" checked={options.allow_cli} onChange={e => update('allow_cli', e.target.checked)}/><span>Enable reviewed recovery CLI steps</span></label>
            <label className="field-label">Recovery CLI launch limit<input type="number" min="1" max="256" value={options.max_cli_invocations} onChange={e => update('max_cli_invocations', Number(e.target.value))}/></label></>}
          <label className="field-label">Recovery host limit<input type="number" min="1" max="256" value={options.max_hosts} onChange={e => update('max_hosts', Number(e.target.value))}/></label>
          <label className="field-label">Recovery deadline (seconds)<input type="number" min="1" max="3600" value={options.max_seconds} onChange={e => update('max_seconds', Number(e.target.value))}/></label>
        </fieldset>
        <button className="secondary" disabled={busy || pending || !info || !selected.length}>
          {busy ? 'Checking recovery…' : 'Prepare recovery review'}
        </button>
      </form>
      <label className="field-label">Saved recovery reviews<select disabled={busy} value={review?.id || ''} onChange={e => restore(e.target.value)}>
        <option value="">Select a review or receipt</option>{info?.history.map(r => <option key={r.id} value={r.id}>
          {new Date(r.created).toLocaleString()} · {r.status} · {r.id.slice(0, 8)}</option>)}
      </select></label>
      {error && <p className="local-error" role="alert">{error}</p>}
      {review && <div className="execution-snapshot" role="region" aria-label="Recovery snapshot">
        <span className="tag">{expired ? 'EXPIRED · PREPARE NEW REVIEW' : review.status.toUpperCase()}</span>
        <h4>{review.snapshot.rerun_ids.length} step(s) to execute · {Object.keys(review.snapshot.checkpoints).length} checkpoint(s) to reuse</h4>
        <div className="scope-chips">{review.snapshot.config.targets.map(t => <code key={t}>{t}</code>)}</div>
        <table aria-label="Recovery execution steps"><thead><tr><th scope="col">Step</th><th scope="col">Action</th><th scope="col">Adapter</th></tr></thead>
          <tbody>{review.snapshot.config.workflow.nodes.map(n => <tr key={n.id}>
            <th scope="row">{n.data.title || n.id}</th>
            <td>{review.snapshot.rerun_ids.includes(n.id) ? 'Execute again' : <>
              Reuse checkpoint <button type="button" className="secondary" onClick={() => onArtifact({
                id: review.snapshot.checkpoints[n.id], name: `Original checkpoint · ${n.id}`})}>Inspect original</button>
              <small className="checkpoint-origin">Captured {new Date(review.snapshot.artifacts[review.snapshot.checkpoints[n.id]].captured_at).toLocaleString()}</small>
            </>}</td><td>{n.data.kind==='catalog_tool' ? n.data.toolId : n.data.kind}</td>
          </tr>)}</tbody></table>
        <p>{review.snapshot.config.max_requests} native operation(s) maximum · {review.snapshot.config.allow_cli ? review.snapshot.config.max_cli_invocations : 0} CLI launch(es) maximum · {review.snapshot.config.max_hosts} host(s) maximum · {review.snapshot.config.max_seconds}s deadline</p>
        <small>Ports: {review.snapshot.config.ports.join(', ')} · Workflow parallelism: {review.snapshot.config.parallelism}</small>
        <details><summary>Executable and input bindings</summary><pre className="live-artifact">{JSON.stringify({
          cli_binaries: review.snapshot.config.cli_binaries, registered_inputs: review.snapshot.config.recovery_input_pins,
          model: review.snapshot.model_binding ? {endpoint:review.snapshot.model_binding.base_url, model:review.snapshot.model_binding.model} : null,
        }, null, 2)}</pre></details>
        <p>Limits apply to the new run. Cached captures keep their original age and do not become fresh observations.
          CLI-internal requests are outside the native operation counter.</p>
        <small>Review expires {new Date(review.expires).toLocaleString()}. A runtime restart or changed bindings requires a new review.</small>
        <code className="execution-hash">{review.snapshot_hash}</code>
        <div className="recovery-actions"><button type="button" className="secondary" disabled={busy} onClick={edit}>Edit recovery settings</button>
          <button type="button" className="secondary" onClick={() => downloadJSON(`recovery-${review.id}.json`, review)}>Export recovery review</button></div>
        {pending && <><label className="http-toggle"><input type="checkbox" checked={approved} disabled={busy || expired} onChange={e => setApproved(e.target.checked)}/>
          <span>Approve this recovery snapshot and repeat the listed execution steps</span></label>
          <button type="button" className="primary" disabled={busy || expired || !approved} onClick={dispatch}>Start approved recovery</button></>}
        {review.reason && <p role="status">{review.reason}</p>}
        {review.run_id && <button type="button" className="secondary" onClick={async () => {
          try {onRun(await api(`/runs/${review.run_id}`));} catch (e) {setError(e.message);}
        }}>Open recovered run</button>}
      </div>}
    </div>}
  </section>;
}
