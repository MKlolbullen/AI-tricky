// Export by allowlist. The picker also carries local titles and assets.
export function buildManifest(snapshot, selections) {
  const findings = snapshot.findings.filter(f => selections[f.id]).map(f => {
    const selected = selections[f.id];
    return {
      finding_id: f.id, summary: selected.summary.trim(), review: f.review,
      observed_after_review: f.observed_after_review,
      artifact_ids: f.artifact_ids.filter(id => selected.artifacts.includes(id)),
    };
  });
  return {
    schema: 'ai-tricky.assessment-report/v1', run_id: snapshot.run_id,
    completed_at: snapshot.completed_at, parser_version: snapshot.parser_version,
    scope: snapshot.scope, coverage_gaps: snapshot.coverage_gaps,
    reviewed_count: snapshot.findings.length, unreviewed_count: snapshot.unreviewed_count, findings,
  };
}

export function renderMarkdown(m) {
  const lines = ['# Assessment report', '', 'Run ID: ' + m.run_id,
    'Completed: ' + m.completed_at, 'Evidence parser: ' + m.parser_version, '',
    '## Entered scope', '', ...m.scope.map(value => '    ' + value), '',
    '## Coverage', '', ...m.coverage_gaps.map(gap => '- ' + gap),
    '', `Selected ${m.findings.length} of ${m.reviewed_count} reviewed findings. ${m.unreviewed_count} unreviewed findings excluded.`,
    'Coverage reflects saved records. Omitted findings and missing observations do not establish absence.'];
  for (const [index, f] of m.findings.entries()) {
    const r = f.review;
    lines.push('', '## Finding ' + (index + 1), '');
    if (f.summary) lines.push(...f.summary.split(/\r\n|[\r\n]/).map(line => '    ' + line), '');
    lines.push('Finding ID: ' + f.finding_id, '',
      `Operator decision: ${r.status} · Severity: ${r.severity} · Confidence: ${r.confidence}`, '',
      `Review ${r.id} · Revision ${r.revision} · ${r.created}`);
    if (r.artifact_id) lines.push('', 'Review evidence: ' + r.artifact_id);
    if (r.support_outside_run) lines.push('', 'The review cites evidence outside this run or unavailable in its saved artifacts.');
    if (f.observed_after_review) lines.push('', 'This run contains an occurrence captured after the cited review.');
    lines.push('', 'Selected occurrence evidence:', '', ...f.artifact_ids.map(id => '- ' + id));
  }
  return lines.join('\n') + '\n';
}
