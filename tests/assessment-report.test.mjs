import assert from 'node:assert/strict';
import test from 'node:test';
import {buildManifest, renderMarkdown} from '../src/assessmentReport.mjs';

test('both exports omit private finding fields and use only selected occurrence citations', () => {
  const review = {id: 'review-2', revision: 2, status: 'verified', severity: 'low', confidence: 'high',
    created: '2026-11-22', artifact_id: null, support_outside_run: true};
  const first = {id: 'finding-1', local_title: 'private-title', local_asset: 'private-url',
    observed_after_review: true, review, artifact_ids: ['capture-1', 'capture-2']};
  const snapshot = {run_id: 'run-1', completed_at: '2026-11-21', parser_version: 'v1',
    scope: ['*.example.com'], coverage_gaps: ['Partial capture'], unreviewed_count: 3,
    findings: [first, {...first, id: 'omitted-finding'}]};
  const manifest = buildManifest(snapshot, {'finding-1': {summary: 'Reviewed sample\n# literal', artifacts: ['capture-2']}});
  const markdown = renderMarkdown(manifest);
  for (const output of [markdown, JSON.stringify(manifest)]) {
    for (const privateField of ['private-title', 'private-url', 'capture-1', 'omitted-finding']) {
      assert.ok(!output.includes(privateField));
    }
    for (const citation of ['review-2', 'finding-1', 'capture-2', 'run-1']) assert.ok(output.includes(citation));
  }
  assert.match(markdown, /    # literal/);
  assert.match(markdown, /1 of 2 reviewed findings/);
  assert.match(markdown, /outside this run/);
  assert.match(markdown, /after the cited review/);
});
