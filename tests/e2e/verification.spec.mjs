import {test, expect} from './fixtures.mjs';
import {readFile} from 'node:fs/promises';

async function openPlanner(page) {
  await page.goto('/');
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  const workspace = page.getByRole('dialog', {name: 'Local assessment workspace'});
  await workspace.locator('.local-tabs').getByRole('button', {name: 'Agent desk', exact: true}).click();
  await workspace.getByRole('button', {name: 'Evidence follow-ups', exact: true}).click();
  await workspace.getByRole('combobox', {name: /^Source run/}).selectOption('qa-execution');
  return workspace;
}

async function planAndReview(page, workspace, profile) {
  await workspace.locator('.proposal-observation').filter({hasText: 'nuclei'}).locator('input').check();
  const planned = page.waitForResponse(r => r.url().endsWith('/api/agent/proposals') && r.request().method() === 'POST');
  await workspace.getByRole('button', {name: 'Propose follow-up tests'}).click();
  const plan = await (await planned).json();
  await workspace.getByRole('button', {name: 'Review execution', exact: true}).click();
  await workspace.getByRole('combobox', {name: 'HTTP check profile'}).selectOption(profile);
  await expect(workspace.getByRole('spinbutton', {name: 'Native operation limit'})).toHaveValue(profile === 'object_access' ? '3' : '2');
  return plan;
}

async function prepare(page, workspace) {
  const prepared = page.waitForResponse(r => /\/proposals\/[^/]+\/[^/]+\/executions$/.test(r.url()) && r.request().method() === 'POST');
  await workspace.getByRole('button', {name: 'Prepare execution review', exact: true}).click();
  const response = await prepared;
  expect(response.status()).toBe(201);
  return response.json();
}

test('controlled CORS pair retains both captures and appears on the finding without changing review status', async ({page}) => {
  const workspace = await openPlanner(page);
  await planAndReview(page, workspace, 'cors_origin');
  const supported = workspace.getByRole('combobox', {name: 'Link supported finding'});
  await expect(supported.locator('option')).toHaveCount(2);
  const findingId = await supported.locator('option').last().getAttribute('value');
  await supported.selectOption(findingId);
  const before = await (await page.request.get(`/api/findings/${findingId}`)).json();
  const review = await prepare(page, workspace);
  await expect(workspace.getByRole('table', {name: 'Approved request pair'})).toContainText('https://ai-tricky.invalid');
  expect(await (await page.request.get('/api/_qa/target-calls')).json()).toEqual([]);
  await workspace.getByRole('checkbox', {name: 'I approve this exact scope, workflow and limits.'}).check();
  await workspace.getByRole('button', {name: 'Approve & start once', exact: true}).click();
  const controlled = workspace.getByRole('region', {name: 'Controlled verification'});
  await expect(controlled).toContainText('SIGNAL OBSERVED');
  const receipt = await (await page.request.get(`/api/agent/executions/${review.id}`)).json();
  const run = await (await page.request.get(`/api/runs/${receipt.run_id}`)).json();
  expect(run.result.request_count).toBe(2);
  const calls = await (await page.request.get('/api/_qa/target-calls')).json();
  expect(calls.map(c => c.origin)).toEqual([null, 'https://ai-tricky.invalid']);
  expect(calls.every(c => c.path === '/approved' && !c.cookie && !c.authorization)).toBe(true);
  const after = await (await page.request.get(`/api/findings/${findingId}`)).json();
  expect(after.status).toBe(before.status);
  expect(after.revision).toBe(before.revision);
  await workspace.locator('.local-tabs').getByRole('button', {name: 'Findings', exact: true}).click();
  await workspace.getByRole('textbox', {name: 'Search', exact: true}).fill('Verification fixture candidate');
  await workspace.locator('.evidence-result').click();
  const linked = workspace.getByRole('region', {name: 'Linked verification checks'});
  await expect(linked).toContainText('SIGNAL OBSERVED');
  await linked.getByRole('button', {name: 'Inspect variant', exact: true}).click();
  await expect(workspace.getByRole('region', {name: 'Captured evidence'})).toContainText('https://ai-tricky.invalid');
  await expect(workspace.getByRole('combobox', {name: /^Supporting capture/}).locator('option')).toHaveCount(4);
  const downloaded = page.waitForEvent('download');
  await linked.getByRole('button', {name: 'Export verification result', exact: true}).click();
  const file = await downloaded;
  const report = JSON.parse(await readFile(await file.path(), 'utf8'));
  expect(report.captures.map(c => c.request.role)).toEqual(['baseline', 'variant']);
  expect(report.approval.id).toBe(review.id);
});

test('paired verification profile restores its exact requests and requires fresh explicit approval', async ({page}) => {
  let workspace = await openPlanner(page);
  const plan = await planAndReview(page, workspace, 'repeat_get');
  const review = await prepare(page, workspace);
  workspace = await openPlanner(page);
  await workspace.getByRole('combobox', {name: 'Recorded evidence-guided plans'}).selectOption(plan.id);
  await workspace.getByRole('button', {name: 'Review execution', exact: true}).click();
  await workspace.getByRole('combobox', {name: 'Saved execution reviews'}).selectOption(review.id);
  await expect(workspace.getByRole('combobox', {name: 'HTTP check profile'})).toHaveValue('repeat_get');
  await expect(workspace.getByRole('combobox', {name: 'HTTP check profile'})).toBeDisabled();
  await expect(workspace.getByRole('table', {name: 'Approved request pair'})).toContainText('baseline');
  await expect(workspace.getByRole('spinbutton', {name: 'Native operation limit'})).toHaveValue('2');
  await expect(workspace.getByRole('button', {name: 'Approve & start once', exact: true})).toBeDisabled();
  expect(await (await page.request.get('/api/_qa/target-calls')).json()).toEqual([]);
});

test('operator registers two identities and reviews the authenticated object access captures', async ({page}) => {
  const workspace = await openPlanner(page);
  const plan = await planAndReview(page, workspace, 'object_access');
  const settings = workspace.getByRole('region', {name: 'Object access settings'});
  await settings.getByText('Manage test identities', {exact: true}).click();
  for (const [label, token] of [['Owner fixture', 'qa-owner-token'], ['Other fixture', 'qa-other-token']]) {
    await settings.getByLabel('Identity label').fill(label);
    await settings.getByLabel('Bearer token').fill(token);
    await settings.getByRole('button', {name: 'Register test identity'}).click();
    await expect(settings.getByLabel('Bearer token')).toHaveValue('');
  }
  await settings.getByLabel('Resource owner identity').selectOption({label: 'Owner fixture'});
  await settings.getByLabel('Second test identity').selectOption({label: 'Other fixture'});
  const origin = new URL(plan.proposals[0].action.target).origin;
  await settings.getByLabel("Second identity's control URL").fill(origin + '/control');
  await settings.getByLabel('Expected owner object ID').fill('owner');
  await settings.getByLabel('Expected control object ID').fill('control');
  const review = await prepare(page, workspace);
  const bindings = workspace.getByRole('table', {name: 'Approved object access requests'});
  await expect(bindings).toContainText('Owner fixture');
  await expect(bindings).toContainText(origin + '/control');
  expect(JSON.stringify(review)).not.toContain('qa-owner-token');
  expect(await (await page.request.get('/api/_qa/target-calls')).json()).toEqual([]);
  await workspace.getByRole('checkbox', {name: 'I approve this exact scope, workflow and limits.'}).check();
  await workspace.getByRole('button', {name: 'Approve & start once', exact: true}).click();
  const controlled = workspace.getByRole('region', {name: 'Controlled verification'});
  await expect(controlled).toContainText('SIGNAL OBSERVED');
  const captures = controlled.getByRole('table', {name: 'Object access evidence'});
  await expect(captures.getByRole('row')).toHaveCount(4);
  await expect(captures).toContainText('Second identity control');
  const calls = await (await page.request.get('/api/_qa/target-calls')).json();
  expect(calls.map(call => call.path)).toEqual(['/approved', '/control', '/approved']);
  expect(calls.every(call => call.authorization && !call.cookie)).toBe(true);
  for (const identity of review.snapshot.config.verification.access.identities) {
    await page.request.post('/api/verification/identities/' + identity.id + '/remove', {data: {}});
  }
});
