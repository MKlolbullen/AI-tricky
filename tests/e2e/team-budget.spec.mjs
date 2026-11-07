import {test, expect} from './fixtures.mjs';

async function openWorkspace(page, tab) {
  await page.goto('/');
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  const workspace = page.getByRole('dialog', {name: 'Local assessment workspace'});
  await workspace.locator('.local-tabs').getByRole('button', {name: tab, exact: true}).click();
  return workspace;
}

test('team setup sends a combined model turn ceiling and renders the recorded allocation', async ({page}) => {
  // UI contract test: no real model is called. The server seeded this result
  // through the real deterministic coordinator with injected fixture analysts.
  await page.route('**/api/runtime', async route => {
    const response = await route.fetch();
    await route.fulfill({json: {...await response.json(), sdk_ready: true}});
  });
  let sent;
  await page.route('**/api/runs', async route => {
    if (route.request().method()!=='POST') return route.continue();
    sent=route.request().postDataJSON();
    const result=await page.request.get('/api/runs/qa-team-budget');
    await route.fulfill({status:201, json:await result.json()});
  });
  const workspace=await openWorkspace(page, 'Run setup');
  await workspace.getByRole('combobox', {name:'Execution engine'}).selectOption('team');
  const total=workspace.getByRole('spinbutton', {name:'Total team model turns'});
  await expect(total).toHaveValue('48');
  await total.fill('2');
  await workspace.getByRole('spinbutton', {name:'Model turns per analyst'}).fill('8');
  await workspace.getByRole('button', {name:'Generate assessment plan', exact:true}).click();
  await expect.poll(()=>sent?.team_max_turns).toBe(2);
  expect(sent.member_max_turns).toBe(8);
  const budget=workspace.getByRole('region', {name:'Team model turn budget'});
  await expect(budget).toContainText('2 / 2 turns reserved');
  await expect(budget.getByRole('cell', {name:'Skipped: no budget', exact:true})).toHaveCount(3);
  await expect(workspace.locator('.team-member .run-status').filter({hasText:/^skipped$/})).toHaveCount(3);
  await expect(workspace.getByText(/Reserved upper bounds, not measured usage/)).toBeVisible();
});

test('native team inspector exposes its own persisted model turn ceilings', async ({page}) => {
  await page.goto('/');
  await page.locator('.library').getByRole('button', {name:'CAI team analyst', exact:true}).click();
  const node=page.locator('.react-flow__node').filter({hasText:'CAI team analyst'}).last();
  await node.click();
  const total=page.getByRole('spinbutton', {name:'Total team model turns'});
  await expect(total).toHaveValue('60');
  await total.fill('7');
  const member=page.getByRole('spinbutton', {name:'Model turns per analyst'});
  await member.fill('3');
  // Re-select the node to verify the controls read saved node data.
  await page.getByRole('button', {name:'Close inspector', exact:true}).click();
  await node.click();
  await expect(total).toHaveValue('7');
  await expect(member).toHaveValue('3');
});
