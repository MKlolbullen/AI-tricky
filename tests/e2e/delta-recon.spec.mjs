import {test, expect} from './fixtures.mjs';

test('saved baseline filters recon changes and approves only selected HTTP follow-ups', async ({page, request}) => {
  await request.post('/api/_qa/delta-fixture', {data: {}});
  await page.goto('/');
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  const workspace = page.getByRole('dialog', {name: 'Local assessment workspace'});
  await workspace.getByRole('button', {name: 'Delta recon', exact: true}).click();
  const delta = workspace.getByRole('region', {name: 'Delta recon', exact: true});
  await delta.getByLabel('Recon run').selectOption('qa-delta-baseline');
  const save = delta.getByRole('button', {name: 'Save this run as baseline'});
  await expect(save).toBeEnabled();
  await save.click();
  await expect(delta.getByRole('status')).toContainText('Baseline revision 1 saved');
  await delta.getByLabel('Recon run').selectOption('qa-delta-current');
  await expect(delta.getByLabel('Saved baseline')).not.toHaveValue('');
  await delta.getByRole('button', {name: 'Compare with baseline'}).click();
  await expect(delta.getByLabel('Change filter')).toHaveValue('changes');
  await expect(delta.getByRole('checkbox', {name: /stable\.js/})).toHaveCount(0);
  await delta.getByRole('checkbox', {name: /changed\.js web-source$/}).check();
  await delta.getByRole('checkbox', {name: /new\.js web-source$/}).check();
  await delta.getByRole('button', {name: 'Prepare selected follow-up'}).click();
  const followup = delta.getByRole('region', {name: 'Delta follow-up'});
  await expect(followup.getByLabel('Native operation limit')).toHaveValue('2');
  await followup.getByRole('button', {name: 'Prepare execution review'}).click();
  const saved = followup.getByRole('region', {name: 'Saved execution snapshot'});
  await expect(saved).toContainText('/delta/changed.js');
  await expect(saved).toContainText('/delta/new.js');
  await expect(saved).not.toContainText('/delta/stable.js');
  expect(await (await request.get('/api/_qa/target-calls')).json()).toEqual([]);
  await followup.getByLabel('I approve this exact scope, workflow and limits.').check();
  await followup.getByRole('button', {name: 'Approve & start once'}).click();
  await expect(workspace.locator('.local-tabs').getByRole('button', {name: 'Runs', exact: true})).toHaveClass(/active/);
  await expect.poll(async () => (await (await request.get('/api/_qa/target-calls')).json()).map(call => call.path)).toEqual([
    '/delta/changed.js', '/delta/new.js',
  ]);
});
