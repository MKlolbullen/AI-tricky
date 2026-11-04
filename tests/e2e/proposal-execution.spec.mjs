import {test, expect} from './fixtures.mjs';

async function openPlanner(page) {
  await page.goto('/');
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  const workspace = page.getByRole('dialog', {name: 'Local assessment workspace'});
  await workspace.locator('.local-tabs').getByRole('button', {name: 'Agent desk', exact: true}).click();
  await workspace.getByRole('button', {name: 'Evidence follow-ups', exact: true}).click();
  await workspace.getByRole('combobox', {name: /^Source run/}).selectOption('qa-execution');
  return workspace;
}

async function makePlan(page, workspace, goal) {
  await workspace.locator('.proposal-observation input').first().check();
  await workspace.getByRole('textbox', {name: 'Follow-up objective'}).fill(goal);
  const response = page.waitForResponse(r => r.url().endsWith('/api/agent/proposals') && r.request().method() === 'POST');
  await workspace.getByRole('button', {name: 'Propose follow-up tests'}).click();
  const plan = await (await response).json();
  await workspace.getByRole('button', {name: 'Review execution', exact: true}).click();
  return plan;
}

async function prepare(page, workspace) {
  const response = page.waitForResponse(r => /\/proposals\/[^/]+\/[^/]+\/executions$/.test(r.url()) && r.request().method() === 'POST');
  await workspace.getByRole('button', {name: 'Prepare execution review', exact: true}).click();
  const result = await response;
  expect(result.status()).toBe(201);
  return result.json();
}

test('execution review restores without approval and dispatches its exact snapshot once', async ({page}) => {
  let approvals = 0;
  page.on('request', r => {if (r.url().endsWith('/dispatch') && r.method() === 'POST') approvals++;});
  let workspace = await openPlanner(page);
  const plan = await makePlan(page, workspace, 'Browser approval persistence fixture');
  const review = await prepare(page, workspace);
  await expect(workspace.getByRole('button', {name: 'Approve & start once', exact: true})).toBeDisabled();
  expect(approvals).toBe(0);
  expect(review.status).toBe('pending');
  workspace = await openPlanner(page);
  await workspace.getByRole('combobox', {name: 'Recorded evidence-guided plans'}).selectOption(plan.id);
  await workspace.getByRole('button', {name: 'Review execution', exact: true}).click();
  await workspace.getByRole('combobox', {name: 'Saved execution reviews'}).selectOption(review.id);
  const snapshot = workspace.getByRole('region', {name: 'Saved execution snapshot'});
  await expect(snapshot).toContainText(review.snapshot_hash);
  await expect(snapshot.getByRole('checkbox', {name: 'I approve this exact scope, workflow and limits.'})).not.toBeChecked();
  await expect(snapshot.getByRole('button', {name: 'Approve & start once', exact: true})).toBeDisabled();
  await snapshot.getByRole('checkbox', {name: 'I approve this exact scope, workflow and limits.'}).check();
  const dispatched = page.waitForResponse(r => r.url().endsWith(`/executions/${review.id}/dispatch`));
  await snapshot.getByRole('button', {name: 'Approve & start once', exact: true}).click();
  const receipt = await (await dispatched).json();
  await expect(workspace.getByRole('region', {name: 'Proposal execution provenance'})).toContainText(review.snapshot_hash);
  await expect.poll(async () => (await (await page.request.get(`/api/runs/${receipt.run.id}`)).json()).status).toBe('completed');
  const run = await (await page.request.get(`/api/runs/${receipt.run.id}`)).json();
  expect(run.result.request_count).toBe(1);
  expect(run.config.targets).toEqual(review.snapshot.config.targets);
  const retry = await page.request.post(`/api/agent/executions/${review.id}/dispatch`, {data: {expected_hash: review.snapshot_hash, approve: true}});
  const repeated = await retry.json();
  expect(repeated.created).toBe(false);
  expect(repeated.run.id).toBe(receipt.run.id);
  expect(approvals).toBe(1);
});

test('changing execution settings revokes the old review and creates a new snapshot', async ({page}) => {
  const workspace = await openPlanner(page);
  await makePlan(page, workspace, 'Browser changed-budget fixture');
  const first = await prepare(page, workspace);
  await expect(workspace.getByRole('spinbutton', {name: 'Native operation limit'})).toBeDisabled();
  await workspace.getByRole('button', {name: 'Change settings', exact: true}).click();
  await workspace.getByRole('spinbutton', {name: 'Native operation limit'}).fill('2');
  const second = await prepare(page, workspace);
  expect(second.snapshot_hash).not.toBe(first.snapshot_hash);
  expect(second.snapshot.config.max_requests).toBe(2);
  const revoked = await (await page.request.get(`/api/agent/executions/${first.id}`)).json();
  expect(revoked.status).toBe('revoked');
  await expect(workspace.getByRole('button', {name: 'Approve & start once', exact: true})).toBeDisabled();
});
