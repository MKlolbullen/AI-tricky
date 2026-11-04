import {test, expect} from './fixtures.mjs';

async function openPlanner(page) {
  await page.goto('/');
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  const workspace = page.getByRole('dialog', {name: 'Local assessment workspace'});
  await workspace.locator('.local-tabs').getByRole('button', {name: 'Agent desk', exact: true}).click();
  await workspace.getByRole('button', {name: 'Evidence follow-ups', exact: true}).click();
  await expect(workspace.getByRole('combobox', {name: /^Source run/})).toHaveValue('qa-current');
  return workspace;
}

test('evidence follow-ups persist and reload, then load a workflow without dispatching a run', async ({page}) => {
  let runWrites = 0;
  page.on('request', request => {if (request.url().endsWith('/api/runs') && request.method() === 'POST') runWrites++;});
  let workspace = await openPlanner(page);
  await workspace.locator('.proposal-observation input').first().check();
  await workspace.getByRole('textbox', {name: 'Follow-up objective'}).fill('Browser QA follow-up plan');
  const created = page.waitForResponse(response => response.url().endsWith('/api/agent/proposals') && response.request().method() === 'POST');
  await workspace.getByRole('button', {name: 'Propose follow-up tests'}).click();
  const plan = await (await created).json();
  expect(plan.model_called).toBe(false);
  await expect(workspace.getByText('EVIDENCE RULES · NO MODEL CALLED', {exact: true})).toBeVisible();
  await expect(workspace.locator('.proposal-card')).toHaveCount(1);
  await expect(workspace.locator('.proposal-card')).toContainText('Expected signal');
  await expect(workspace.getByRole('button', {name: /^Supporting capture/})).toBeVisible();
  workspace = await openPlanner(page);
  const history = workspace.getByRole('combobox', {name: 'Recorded evidence-guided plans'});
  await expect(history.locator(`option[value="${plan.id}"]`)).toHaveCount(1);
  await history.selectOption(plan.id);
  await expect(workspace.getByRole('region', {name: 'Evidence-guided plan'})).toContainText(plan.id.slice(0, 8));
  await workspace.getByRole('button', {name: 'Load proposed workflow'}).click();
  await expect(workspace.getByRole('heading', {name: 'Assessment workflow', exact: true})).toBeVisible();
  expect(runWrites).toBe(0);
});

test('stale saved evidence plans remain inspectable and cannot load a workflow', async ({page}) => {
  const workspace = await openPlanner(page);
  const history = workspace.getByRole('combobox', {name: 'Recorded evidence-guided plans'});
  const option = history.locator('option').filter({hasText: 'Stale fixture plan'});
  await expect(option).toHaveCount(1);
  await history.selectOption(await option.getAttribute('value'));
  await expect(workspace.getByText('Parser or adapter contracts changed. Generate a new evidence-guided plan.', {exact: true})).toBeVisible();
  await expect(workspace.getByRole('button', {name: 'Load proposed workflow'})).toBeDisabled();
});

test('unsupported evidence and risk combinations return an honest empty proposal list', async ({page}) => {
  const workspace = await openPlanner(page);
  await workspace.locator('.proposal-observation input').first().check();
  await workspace.getByRole('combobox', {name: 'Maximum proposed risk'}).selectOption('passive');
  await workspace.getByRole('button', {name: 'Propose follow-up tests'}).click();
  await expect(workspace.getByText('No supported follow-up test was proposed from this evidence.', {exact: true})).toBeVisible();
  await expect(workspace.getByRole('button', {name: 'Load proposed workflow'})).toHaveCount(0);
});
