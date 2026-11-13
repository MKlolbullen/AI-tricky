import React, {useId, useState} from 'react';

const bindingLabels = {
  file: 'Input file', folder: 'Input folder', sbom: 'SBOM file', wordlist: 'Wordlist',
  paths_file: 'Path list', resolvers: 'DNS resolvers', resolvers_trusted: 'Trusted DNS resolvers',
  templates: 'Templates or signatures folder',
};
const enabled = (arg, params) => arg.type === 'flag'
  ? params[arg.flag] === true || params[arg.flag] === '__flag__'
  : params[arg.flag] !== undefined && params[arg.flag] !== '';

function ArgumentRow({arg, params, change}) {
  const id = useId();
  const active = enabled(arg, params);
  const restricted = Boolean(arg.blocked_reason);
  const isFlag = arg.type === 'flag';
  const numeric = arg.type === 'int' || arg.type === 'float';
  const value = params[arg.flag];
  const invalid = numeric && active && (Number(value) < 0 || Number(value) > 1000000 || !Number.isFinite(Number(value)) ||
    (arg.type === 'int' && !Number.isInteger(Number(value))));
  const description = arg.blocked_reason || (invalid ? 'Enter a number within 0–1,000,000' + (arg.type === 'int' ? ' with no decimal places.' : '.') : arg.description);
  const hasDefault = arg.default !== undefined && arg.default !== null && arg.default !== '';
  return <div className={`tool-arg-row${active ? ' is-set' : ''}${restricted ? ' is-restricted' : ''}`}>
    <div className="tool-arg-title">
      <label htmlFor={id}>{arg.label} <code>{arg.flag}</code></label>
      {isFlag && <input id={id} type="checkbox" aria-describedby={description ? `${id}-help` : undefined}
        disabled={restricted} checked={active} onChange={e => change(arg.flag, e.target.checked ? true : undefined)}/>}
      {!isFlag && active && !restricted && <button type="button" className="tool-arg-reset" aria-label={`Clear ${arg.flag}`} onClick={() => change(arg.flag)}>Reset</button>}
    </div>
    {!isFlag && <input id={id} disabled={restricted} type={numeric ? 'number' : 'text'}
      min={numeric ? 0 : undefined} max={numeric ? 1000000 : undefined} step={arg.type === 'int' ? 1 : numeric ? 'any' : undefined}
      maxLength={numeric ? undefined : 2048} value={params[arg.flag] ?? ''}
      aria-invalid={invalid || undefined} aria-describedby={description ? `${id}-help` : undefined} placeholder={hasDefault ? String(arg.default) : 'Tool default'}
      onChange={e => change(arg.flag, e.target.value)}/>}
    {description && <small id={`${id}-help`}>{description}</small>}
  </div>;
}

export default function ToolArguments({tool, detail, params, change, inputs, bindings, reference, connected, loading}) {
  const [query, setQuery] = useState('');
  const [configured, setConfigured] = useState(false);
  const args = detail?.args || [];
  const setCount = args.filter(arg => !arg.blocked_reason && enabled(arg, params)).length;
  const matches = arg => `${arg.flag} ${arg.label} ${arg.description || ''}`.toLowerCase().includes(query.trim().toLowerCase());
  const editable = args.filter(arg => !arg.blocked_reason && matches(arg) && (!configured || enabled(arg, params)));
  const restricted = args.filter(arg => arg.blocked_reason && matches(arg));
  const inputBindings = [...(detail?.bindings || [])];
  if (detail) for (const name of Object.keys(bindings)) {
    if (!inputBindings.some(binding => binding.name === name)) {
      inputBindings.push({name, kind: ['templates', 'folder'].includes(name) ? 'folder' : 'file', required: false});
    }
  }
  const overrides = args.filter(arg => !arg.blocked_reason && enabled(arg, params))
    .flatMap(arg => arg.type === 'flag' ? [arg.flag] : [arg.flag, String(params[arg.flag])]);

  return <>
    <section className="tool-arguments" aria-label="Tool arguments">
      <div className="tool-arg-heading"><h3>Arguments</h3><span>{setCount} configured</span></div>
      {loading && <p role="status">Loading argument controls…</p>}
      {detail && args.length > 0 && <div className="tool-arg-filters">
        <input aria-label="Filter arguments" type="search" placeholder="Find a flag or setting" value={query} onChange={e => setQuery(e.target.value)}/>
        <button type="button" className="secondary" aria-pressed={configured} onClick={() => setConfigured(!configured)}>Configured only</button>
      </div>}
      {editable.map(arg => <ArgumentRow key={arg.flag} arg={arg} params={params} change={change}/>)}
      {detail && !editable.length && <p className="compact-help">{args.length ? 'No editable arguments match.' : 'This adapter uses fixed arguments.'}</p>}
      {tool.command.some(token => token.includes('{pattern}')) && <label>Named GF pattern<input value={params.pattern ?? ''} placeholder="xss" onChange={e => change('pattern', e.target.value)}/></label>}
      {tool.command.some(token => token.includes('{exploit_type}')) && <label>Named exploit type<input value={params.exploit_type ?? ''} onChange={e => change('exploit_type', e.target.value)}/></label>}
      {restricted.length > 0 && !configured && <details className="tool-arg-details" open={query.trim() ? true : undefined}>
        <summary>Restricted arguments ({restricted.length})</summary>
        {restricted.map(arg => <ArgumentRow key={arg.flag} arg={arg} params={params} change={change}/>)}
      </details>}
      <details className="tool-arg-details">
        <summary>Command preview</summary>
        <small>Base command and selected flags. Preflight binds inputs and adds adapter options.</small>
        <pre>{JSON.stringify([...tool.command, ...overrides], null, 2)}</pre>
      </details>
    </section>
    {inputBindings.length > 0 && <section className="tool-input-bindings" aria-label="Tool input bindings">
      <h3>Input bindings</h3>
      {inputBindings.map(({name, kind, required}) => <label key={name}>
        <span>{bindingLabels[name]} <small>{required ? 'Required' : 'Optional'}</small></span>
        <select value={bindings[name] || ''} onChange={e => reference(name, e.target.value)}>
          <option value="">{connected.has(name) ? 'Use connected input' : 'Choose a registered ' + kind}</option>
          {inputs.filter(input => input.kind === kind).map(input => <option key={input.id} value={input.id}>{input.name}</option>)}
        </select>
        {bindings[name] && connected.has(name) && <small>The selected input overrides the connected input.</small>}
      </label>)}
      <small>Register files and folders in Local workspace → Inputs.</small>
    </section>}
  </>;
}
