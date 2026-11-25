import React, {useState} from 'react';
import {Books, X} from '@phosphor-icons/react';
import {directory, searchDirectory} from './tool-directory.mjs';

const coverages = [...new Set(directory.map(entry => entry.coverage))].sort();

export function ToolDirectory({query, selected, onSelect}) {
  const [coverage, setCoverage] = useState('');
  const entries = searchDirectory(query, coverage);
  return <section className="tool-directory" aria-label="Tool catalog">
    <h3>Tool catalog <span>{entries.length} / {directory.length}</span></h3>
    <select aria-label="Argument coverage" value={coverage} onChange={e => setCoverage(e.target.value)}>
      <option value="">All argument coverage</option>
      {coverages.map(value => <option key={value}>{value}</option>)}
    </select>
    <div className="directory-list">{entries.map(t => <button key={t.key} aria-pressed={selected?.key === t.key}
      onClick={() => onSelect(t)}><span>{t.name}</span><small>{t.group} · {t.category}</small></button>)}</div>
    {!entries.length && <p>No matching catalog records.</p>}
  </section>;
}

export function ToolReference({entry, close}) {
  return <aside className="inspector" aria-label="Tool catalog details">
    <div className="inspector-heading"><Books size={26}/><div><strong>{entry.name}</strong><small>{entry.group}</small></div>
      <button className="icon-btn" aria-label="Close catalog details" onClick={close}><X size={18}/></button></div>
    <div className="inspector-body"><p>{entry.description}</p>
      <dl className="directory-facts">
        <dt>Tool ID</dt><dd><code>{entry.id}</code></dd>
        <dt>Catalog status</dt><dd>{entry.kind}</dd>
        <dt>Argument coverage</dt><dd>{entry.coverage}{entry.version && ' · ' + entry.version}</dd>
        {entry.argumentCount != null && <><dt>Declared arguments</dt><dd>{entry.argumentCount}</dd></>}
        {entry.inputs ? <><dt>Input sockets</dt><dd>{entry.inputs.join(', ') || 'None'}</dd>
          <dt>Output sockets</dt><dd>{entry.outputs.join(', ') || 'None'}</dd></> :
          <><dt>Canvas sockets</dt><dd>No standalone socket contract</dd></>}
        <dt>Source</dt><dd>{entry.provenance}</dd>
      </dl>
    </div>
  </aside>;
}
