import React, {useState, useEffect} from 'react';
import {api} from './api.mjs';

const KINDS = ['host', 'ip', 'service', 'technology', 'file'];

export default function AssetGraphView({runs = []}) {
  const [runId, setRunId] = useState(''), [kind, setKind] = useState(''), [q, setQ] = useState('');
  const [graph, setGraph] = useState({entities: [], edges: [], total: 0});
  const [sel, setSel] = useState(null), [detail, setDetail] = useState(null);
  const [error, setError] = useState(''), [loading, setLoading] = useState(false);
  useEffect(() => {
    let alive = true;
    setLoading(true); setError('');
    const p = new URLSearchParams();
    if (runId) p.set('run_id', runId);
    if (kind) p.set('kind', kind);
    if (q) p.set('q', q);
    api('/assets/graph?' + p).then(d => {if (alive) setGraph(d);})
      .catch(e => {if (alive) setError(e.message);}).finally(() => {if (alive) setLoading(false);});
    return () => {alive = false;};
  }, [runId, kind, q]);
  const open = async entity => {
    setSel(entity.id); setDetail(null);
    try {setDetail(await api('/assets/' + entity.id));} catch (e) {setError(e.message);}
  };
  const byKind = KINDS.map(k => [k, graph.entities.filter(e => e.kind === k)]).filter(([, xs]) => xs.length);
  return <section className="evidence-workbench asset-graph">
    <div className="section-intro"><div><h3>Asset graph</h3><p>Hosts, IPs, services, technologies and files observed from captured evidence, with their relationships and the captures that asserted them. Observed facts only — never confirmed findings. Absence is “not observed”.</p></div></div>
    <div className="evidence-filters">
      <label className="field-label">Source run<select value={runId} onChange={e => {setRunId(e.target.value); setSel(null); setDetail(null);}}><option value="">All runs</option>{runs.map(r => <option key={r.id} value={r.id}>{r.id.slice(0, 8)} · {r.status}</option>)}</select></label>
      <label className="field-label">Entity kind<select value={kind} onChange={e => setKind(e.target.value)}><option value="">All kinds</option>{KINDS.map(k => <option key={k}>{k}</option>)}</select></label>
      <label className="field-label">Filter<input value={q} maxLength={200} onChange={e => setQ(e.target.value)} placeholder="host, ip, product…"/></label>
    </div>
    {error && <p className="local-error" role="alert">{error}</p>}
    <div className="asset-grid">
      <div className="asset-entities">
        {loading ? <p role="status">Loading asset graph…</p> : byKind.length ? byKind.map(([k, xs]) =>
          <div className="asset-kind" key={k}><h4>{k} <span className="tag">{xs.length}</span></h4>
            {xs.map(e => <button key={e.id} className={sel === e.id ? 'selected' : ''} onClick={() => open(e)}><code>{e.canonical}</code></button>)}</div>)
          : <div className="local-empty"><strong>No assets yet</strong><p>Run a native inventory or HTTP workflow, then the graph builds from captured evidence.</p></div>}
        {!loading && graph.entities.length > 0 && <small className="asset-count">{graph.entities.length} entities · {graph.edges.length} relationships{graph.total > graph.entities.length ? ` · showing ${graph.entities.length} of ${graph.total}` : ''}</small>}
      </div>
      <aside className="asset-detail">{detail ? <>
        <span className="tag">{detail.kind.toUpperCase()}</span><h3>{detail.canonical}</h3>
        <pre>{JSON.stringify(detail.data, null, 2)}</pre>
        <h4>Relationships</h4>{detail.edges.length ? <ul className="asset-edges">{detail.edges.map(ed => <li key={ed.id}><code>{ed.direction === 'out' ? '→' : '←'} {ed.rel}</code> <strong>{ed.other_canonical}</strong> <small>{ed.other_kind} · {ed.source}</small></li>)}</ul> : <p>No relationships recorded.</p>}
        <h4>Provenance</h4><ul className="asset-provenance">{detail.provenance.map((p, i) => <li key={i}><code>{p.artifact_id.slice(0, 8)}</code> · run {p.run_id.slice(0, 8)} · {new Date(p.observed_at).toLocaleString()}</li>)}</ul>
      </> : <p>Select an asset to inspect its data, relationships and the captures that asserted it.</p>}</aside>
    </div>
  </section>;
}
