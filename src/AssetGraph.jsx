import React, {useState, useEffect} from 'react';
import {api} from './api.mjs';

const KINDS = ['host', 'ip', 'service', 'technology', 'file', 'netblock', 'certificate', 'vulnerability', 'contact'];
const CLAIM_KINDS = new Set(['vulnerability', 'contact', 'netblock', 'certificate']);

export default function AssetGraphView({runs = [], runtime, targets = [], onEnriched}) {
  const [runId, setRunId] = useState(''), [kind, setKind] = useState(''), [q, setQ] = useState('');
  const [graph, setGraph] = useState({entities: [], edges: [], total: 0});
  const [sel, setSel] = useState(null), [detail, setDetail] = useState(null);
  const [error, setError] = useState(''), [loading, setLoading] = useState(false), [refresh, setRefresh] = useState(0);
  const [enrichTarget, setEnrichTarget] = useState(''), [enrichProviders, setEnrichProviders] = useState([]);
  const [enriching, setEnriching] = useState(false), [enrichSummary, setEnrichSummary] = useState(null);
  const [diffBase, setDiffBase] = useState(''), [diffCur, setDiffCur] = useState(''), [diffRes, setDiffRes] = useState(null), [diffBusy, setDiffBusy] = useState(false);
  const passive = runtime?.passive_providers;
  const scopeTargets = targets.filter(t => t.kind === 'domain' || t.kind === 'ip');
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
  }, [runId, kind, q, refresh]);
  const open = async entity => {
    setSel(entity.id); setDetail(null);
    try {setDetail(await api('/assets/' + entity.id));} catch (e) {setError(e.message);}
  };
  const toggleProvider = id => setEnrichProviders(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);
  const enrich = async e => {
    e.preventDefault(); setEnriching(true); setError(''); setEnrichSummary(null);
    try {
      const result = await api('/assets/enrich', {target: enrichTarget, providers: enrichProviders});
      setEnrichSummary(result.summary); setRunId(result.run_id); setRefresh(v => v + 1); onEnriched?.();
    } catch (e) {setError(e.message);} finally {setEnriching(false);}
  };
  const runDiff = async () => {
    setDiffBusy(true); setError(''); setDiffRes(null);
    try {setDiffRes(await api('/assets/diff?' + new URLSearchParams({baseline: diffBase, current: diffCur})));}
    catch (e) {setError(e.message);} finally {setDiffBusy(false);}
  };
  const byKind = KINDS.map(k => [k, graph.entities.filter(e => e.kind === k)]).filter(([, xs]) => xs.length);
  const diffChanges = diffRes ? [...diffRes.entities.filter(e => e.state !== 'unchanged').map(e => ({...e, label: `${e.kind} ${e.canonical}`})),
                                 ...diffRes.edges.filter(e => e.state !== 'unchanged').map(e => ({...e, label: `${e.rel} ${e.src_canonical} → ${e.dst_canonical} · ${e.source}`}))] : [];
  return <section className="evidence-workbench asset-graph">
    <div className="section-intro"><div><h3>Asset graph</h3><p>Hosts, IPs, services, technologies, files and — from passive sources — netblocks, certificates, vulnerabilities and contacts, with their relationships and provenance. Observed facts and third-party claims (each sourced), never confirmed findings. Absence is “not observed”.</p></div></div>
    <details className="enrich-panel"><summary>Enrich from passive sources</summary>
      <p className="enrich-note">Queries third-party provider APIs (not the target) for a domain or IP you have entered. Results are provenance-tagged third-party claims; vulnerabilities are claims, never confirmed findings. {passive?.enabled ? '' : 'Passive outbound is disabled — set AI_TRICKY_ALLOW_PASSIVE=1 to enable provider queries.'}</p>
      <form onSubmit={enrich}>
        <label className="field-label">Target<select value={enrichTarget} onChange={e => setEnrichTarget(e.target.value)}><option value="">Select an entered domain or IP</option>{scopeTargets.map(t => <option key={t.id} value={t.url}>{t.url}</option>)}</select></label>
        <fieldset className="enrich-providers"><legend>Providers</legend>{(passive?.providers || []).map(pr => <label className="http-toggle" key={pr.id}><input type="checkbox" disabled={!pr.configured} checked={enrichProviders.includes(pr.id)} onChange={() => toggleProvider(pr.id)}/><span>{pr.name}{pr.configured ? '' : ' · add key in Credentials'}</span></label>)}</fieldset>
        <button className="primary" disabled={enriching || !enrichTarget || !enrichProviders.length || !passive?.enabled}>{enriching ? 'Querying providers…' : 'Enrich asset graph'}</button>
      </form>
      {enrichSummary && <ul className="enrich-summary">{enrichSummary.map(s => <li key={s.provider}><strong>{s.name}</strong> · {s.status === 'ok' ? `${s.queries} query(ies)${s.source ? ' · ' + s.source : ''}` : `failed: ${s.reason}`}</li>)}</ul>}
    </details>
    <details className="enrich-panel"><summary>Compare two enrichment runs</summary>
      <p className="enrich-note">What the asset graph gained or stopped observing between two runs. Absence is “not observed”, never removal or resolution.</p>
      <div className="evidence-filters">
        <label className="field-label">Baseline run<select value={diffBase} onChange={e => setDiffBase(e.target.value)}><option value="">Select a run</option>{runs.map(r => <option key={r.id} value={r.id}>{r.id.slice(0, 8)} · {r.config?.engine || r.status}</option>)}</select></label>
        <label className="field-label">Current run<select value={diffCur} onChange={e => setDiffCur(e.target.value)}><option value="">Select a run</option>{runs.map(r => <option key={r.id} value={r.id}>{r.id.slice(0, 8)} · {r.config?.engine || r.status}</option>)}</select></label>
        <button className="primary" disabled={diffBusy || !diffBase || !diffCur || diffBase === diffCur} onClick={runDiff}>{diffBusy ? 'Comparing…' : 'Compare'}</button>
      </div>
      {diffRes && <div className="asset-diff"><div className="diff-summary"><span className="state-new">{diffRes.summary.new} new</span><span className="state-gone">{diffRes.summary.not_observed} not observed</span><span className="state-same">{diffRes.summary.unchanged} unchanged</span></div>
        {diffRes.warnings.map((w, i) => <p className="comparison-notice" key={i}>{w}</p>)}
        <ul className="diff-list">{diffChanges.length ? diffChanges.map((e, i) => <li key={i} className={e.state === 'new' ? 'state-new' : 'state-gone'}><code>{e.state === 'new' ? '+' : '−'}</code> {e.label}</li>) : <li>No differences between these runs.</li>}</ul></div>}
    </details>
    <div className="evidence-filters">
      <label className="field-label">Source run<select value={runId} onChange={e => {setRunId(e.target.value); setSel(null); setDetail(null);}}><option value="">All runs</option>{runs.map(r => <option key={r.id} value={r.id}>{r.id.slice(0, 8)} · {r.config?.engine || r.status}</option>)}</select></label>
      <label className="field-label">Entity kind<select value={kind} onChange={e => setKind(e.target.value)}><option value="">All kinds</option>{KINDS.map(k => <option key={k}>{k}</option>)}</select></label>
      <label className="field-label">Filter<input value={q} maxLength={200} onChange={e => setQ(e.target.value)} placeholder="host, ip, product, CVE…"/></label>
    </div>
    {error && <p className="local-error" role="alert">{error}</p>}
    <div className="asset-grid">
      <div className="asset-entities">
        {loading ? <p role="status">Loading asset graph…</p> : byKind.length ? byKind.map(([k, xs]) =>
          <div className="asset-kind" key={k}><h4>{k} <span className="tag">{xs.length}</span>{CLAIM_KINDS.has(k) && <span className="claim-tag">claim</span>}</h4>
            {xs.map(e => <button key={e.id} className={sel === e.id ? 'selected' : ''} onClick={() => open(e)}><code>{e.canonical}</code></button>)}</div>)
          : <div className="local-empty"><strong>No assets yet</strong><p>Run a native inventory or HTTP workflow, or enrich from passive sources above.</p></div>}
        {!loading && graph.entities.length > 0 && <small className="asset-count">{graph.entities.length} entities · {graph.edges.length} relationships{graph.total > graph.entities.length ? ` · showing ${graph.entities.length} of ${graph.total}` : ''}</small>}
      </div>
      <aside className="asset-detail">{detail ? <>
        <span className="tag">{detail.kind.toUpperCase()}</span>{CLAIM_KINDS.has(detail.kind) && <span className="claim-tag">third-party claim</span>}<h3>{detail.canonical}</h3>
        {detail.sources?.length > 0 && <div className="asset-sources">{detail.sources.map(s => <span className="source-badge" key={s}>{s}</span>)}</div>}
        <pre>{JSON.stringify(detail.data, null, 2)}</pre>
        <h4>Relationships</h4>{detail.edges.length ? <ul className="asset-edges">{detail.edges.map(ed => <li key={ed.id}><code>{ed.direction === 'out' ? '→' : '←'} {ed.rel}</code> <strong>{ed.other_canonical}</strong> <small>{ed.other_kind} · {ed.source}</small></li>)}</ul> : <p>No relationships recorded.</p>}
        <h4>Provenance</h4><ul className="asset-provenance">{detail.provenance.map((p, i) => <li key={i}><code>{p.artifact_id.slice(0, 8)}</code> · run {p.run_id.slice(0, 8)} · {new Date(p.observed_at).toLocaleString()}</li>)}</ul>
      </> : <p>Select an asset to inspect its data, relationships, sources and the captures or provider responses that asserted it.</p>}</aside>
    </div>
  </section>;
}
