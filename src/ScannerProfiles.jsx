import React, {useEffect, useState} from 'react';
import {api} from './api.mjs';
import {toolStatusLabel} from './ReconToolReadiness';

const capture = {
  scoped_gateway: 'HTTP History · native budget',
  external_proxy_history: 'External proxy history when configured',
  tool_output_only: 'Scanner output',
  offline: 'Offline output',
};

export default function ScannerProfiles() {
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [profileId, setProfileId] = useState('enforced-cli');
  const [check, setCheck] = useState(0);

  useEffect(() => {
    let current = true;
    setBusy(true);
    setError('');
    api('/scanner-profiles').then(data => {if (current) setReport(data);})
      .catch(failure => {if (current) setError(failure.message);})
      .finally(() => {if (current) setBusy(false);});
    return () => {current = false;};
  }, [check]);

  const profile = report?.profiles.find(p => p.id === profileId);
  return <section aria-label="Scanner profiles">
    <div className="section-intro"><div><h3>Scanner profiles</h3>
      <p>Check which binaries the app resolves, their pinned versions, input files and capture coverage.</p></div>
      <button className="secondary" disabled={busy} onClick={() => setCheck(value => value + 1)}>Check scanner setup</button>
    </div>
    {busy && <p role="status">Checking local setup…</p>}
    {error && <p role="alert">{error}</p>}
    {report && <><p>Detected {report.platform} / {report.architecture}. The clean-install beta is tested on Ubuntu 24.04 x86-64.</p>
      <label className="field-label">Profile<select value={profileId} onChange={e => setProfileId(e.target.value)}>
        {report.profiles.map(p => <option value={p.id} key={p.id}>{p.title}</option>)}
      </select></label>
      {profile && <section className="scope-summary">
        <p>Install from the beta folder or source checkout with <code>{profile.command}</code>.</p>
        <p>Tools on PATH take precedence. The app also checks the default profile directories.</p>
        <div className="http-history-scroll"><table aria-label="Scanner readiness">
          <thead><tr><th>Scanner</th><th>Version and binary</th><th>Capture coverage</th><th>Setup check</th></tr></thead>
          <tbody>{profile.tools.map(tool => <tr key={tool.tool_id}>
            <th scope="row">{tool.tool_id}</th>
            <td><strong>{toolStatusLabel(tool.status)}</strong>
              <p>{tool.installed_version || '—'} · Tested {tool.tested_version}{tool.build_target && ' · ' + tool.build_target}</p>
              {tool.path && <code>{tool.path}</code>}
              {tool.remediation && <p><code>{tool.remediation}</code></p>}</td>
            <td>{capture[tool.capture]}</td>
            <td>{tool.sandbox_verified ? 'Isolated launch verified' : tool.sandbox_error ||
                  (tool.capture === 'scoped_gateway' ? 'Install the pinned scanner to check isolation.' : 'Check workflow readiness for bound inputs.')}</td>
          </tr>)}</tbody>
        </table></div>
        <h4>Bundled inputs</h4>
        <ul>{profile.inputs.map(input => <li key={input.id}>{input.name} · {input.state === 'installed' ? 'Registered and verified' :
          input.state === 'invalid' ? 'Changed or unreadable' : 'Available to install'}</li>)}</ul>
        <p>Install bundled support files in <strong>Inputs</strong>, then bind them to the workflow.</p>
      </section>}
    </>}
  </section>;
}
