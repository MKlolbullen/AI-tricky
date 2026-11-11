import React from 'react';

const labels = {
  tested_version: 'Tested version',
  different_version: 'Different version',
  unverified: 'Version unavailable',
  wrong_binary: 'Wrong executable',
  missing: 'Missing executable',
};

export default function ReconToolReadiness({checks}) {
  if (!checks?.length) return null;
  return <section aria-label="Pinned tool checks">
    <h4>Pinned tools</h4>
    <ul>
      {checks.map(tool => <li key={tool.tool_id}>
        <strong>{tool.tool_id} · {labels[tool.status]}</strong>
        <p>{tool.path && <code>{tool.path}</code>}{tool.installed_version && <span> · {tool.installed_version}</span>}</p>
        {tool.remediation && <p>Tested with {tool.tested_version}. Install using <code>{tool.remediation}</code> and put its bin directory first on PATH.</p>}
      </li>)}
    </ul>
  </section>;
}
