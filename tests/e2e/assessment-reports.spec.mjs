import {readFile} from 'node:fs/promises';
import {test, expect} from './fixtures.mjs';

test('reviewer previews and exports the same selection and opens its saved evidence', async ({page, request}) => {
  const pageOfFindings = await (await request.get('/api/findings?run_id=qa-current&q=Potential%20API%20issue')).json();
  const f = pageOfFindings.items[0];
  const detail = await (await request.get('/api/findings/' + f.id)).json();
  const aid = detail.verification_evidence[0].id;
  const review = await request.post('/api/findings/' + f.id + '/reviews', {data: {
    expected_revision: f.revision, status: 'verified', severity: 'medium', confidence: 'high',
    evidence_id: aid, note: 'Private operator note',
  }});
  expect(review.ok()).toBe(true);
  await page.goto('/');
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  await page.getByRole('button', {name: 'Reports', exact: true}).click();
  const builder = page.getByRole('region', {name: 'Assessment report builder'});
  await builder.getByLabel('Completed run').selectOption('qa-current');
  await builder.getByRole('checkbox', {name: /Potential API issue/}).check();
  await builder.getByLabel('Publishable summary (optional)').fill('Access check reviewed.');
  await builder.getByRole('button', {name: 'Inspect review evidence'}).click();
  await expect(builder.getByLabel('Captured evidence')).toContainText('Browser QA evidence');
  const md = await builder.getByLabel('Markdown preview').textContent();
  expect(md).toContain('Access check reviewed.');
  for (const sensitive of ['Private operator note', 'Potential API issue', 'Browser QA evidence', 'example.invalid/api']) {
    expect(md).not.toContain(sensitive);
  }
  for (const [button, name] of [['Download Markdown', 'md'], ['Download manifest', 'json']]) {
    const pending = page.waitForEvent('download');
    await builder.getByRole('button', {name: button}).click();
    const download = await pending;
    expect(download.suggestedFilename()).toBe('assessment-qa-current.' + name);
    const contents = await readFile(await download.path(), 'utf8');
    if (name === 'md') expect(contents).toBe(md);
    else {
      const manifest = JSON.parse(contents);
      expect(manifest.findings).toHaveLength(1);
      expect(manifest.findings[0].review.artifact_id).toBe(aid);
      expect(manifest.findings[0].artifact_ids).toContain(aid);
      expect(contents).not.toContain('Potential API issue');
    }
  }
  await builder.getByLabel('Completed run').selectOption('qa-baseline');
  await expect(builder.getByRole('button', {name: 'Download Markdown'})).toBeDisabled();
  await expect(builder.getByLabel('Markdown preview')).not.toContainText(aid);
  expect(await (await request.get('/api/_qa/target-calls')).json()).toEqual([]);
});
