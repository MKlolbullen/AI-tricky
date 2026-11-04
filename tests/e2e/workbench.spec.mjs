import {test, expect} from './fixtures.mjs';
import {readFile} from 'node:fs/promises';

async function openWorkspace(page, tab) {
  await page.goto('/');
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  const workspace = page.getByRole('dialog', {name: 'Local assessment workspace'});
  await workspace.locator('.local-tabs').getByRole('button', {name: tab, exact: true}).click();
  return workspace;
}

test('late-loaded runs populate comparison defaults without replacing an explicit selection', async ({page}) => {
  let release;
  const gate = new Promise(resolve => {release = resolve;});
  await page.route('**/api/runs', async route => {await gate; await route.continue();});
  const workspace = await openWorkspace(page, 'Compare runs');
  const baseline = workspace.getByRole('combobox', {name: /^Baseline run/});
  const current = workspace.getByRole('combobox', {name: /^Current run/});
  await expect(current).toHaveValue('');
  release();
  await expect(current).toHaveValue('qa-current');
  await expect(baseline).toHaveValue('qa-baseline');
  await current.selectOption('qa-baseline');
  await workspace.getByRole('button', {name: 'Refresh local workspace'}).click();
  await expect(current).toHaveValue('qa-baseline');
});

test('comparison locks its run pair, exports matching IDs and shows unsupported artifact coverage', async ({page}) => {
  const workspace = await openWorkspace(page, 'Compare runs');
  const baseline = workspace.getByRole('combobox', {name: /^Baseline run/});
  const current = workspace.getByRole('combobox', {name: /^Current run/});
  await expect(current).toHaveValue('qa-current');
  let release;
  const gate = new Promise(resolve => {release = resolve;});
  await page.route('**/api/runs/qa-current/compare?baseline=qa-baseline', async route => {await gate; await route.continue();});
  await workspace.locator('form.comparison-controls').getByRole('button', {name: 'Compare runs'}).click();
  await expect(baseline).toBeDisabled();
  await expect(current).toBeDisabled();
  release();
  await expect(current).toBeEnabled();
  await workspace.getByText('Parser coverage and capture limits', {exact: true}).click();
  await expect(workspace.getByText('scanner/report.json', {exact: true})).toHaveCount(2);
  await expect(workspace.getByText(/raw evidence only/).first()).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await workspace.getByRole('button', {name: 'Export comparison'}).click();
  const download = await downloadPromise;
  const comparison = JSON.parse(await readFile(await download.path(), 'utf8'));
  expect(comparison.baseline_id).toBe('qa-baseline');
  expect(comparison.current_id).toBe('qa-current');
  expect(download.suggestedFilename()).toBe('comparison-qa-basel-qa-curre.json');
});

test('reviewing the last filtered finding returns pagination to a valid page', async ({page}) => {
  const workspace = await openWorkspace(page, 'Findings');
  await workspace.getByRole('textbox', {name: 'Search', exact: true}).fill('QA finding');
  await workspace.getByRole('combobox', {name: 'Status', exact: true}).selectOption('candidate');
  const pager = workspace.getByRole('navigation', {name: 'Results pages'});
  await expect(pager).toContainText('1–50 of 51');
  await pager.getByRole('button', {name: 'Next'}).click();
  await expect(pager).toContainText('51–51 of 51');
  await expect(workspace.locator('.evidence-result')).toHaveCount(1);
  await workspace.locator('.evidence-result').click();
  await workspace.getByRole('combobox', {name: /^Review status/}).selectOption('triaged');
  await workspace.getByRole('textbox', {name: 'Review note'}).fill('Browser regression: remove this candidate from the active filter.');
  await workspace.getByRole('button', {name: 'Save review'}).click();
  await expect(pager).toContainText('1–50 of 50');
  await expect(pager.getByRole('button', {name: 'Next'})).toBeDisabled();
});

test('verification offers captured HTTP evidence and excludes model analysis artifacts', async ({page}) => {
  const workspace = await openWorkspace(page, 'Findings');
  await workspace.getByRole('textbox', {name: 'Search', exact: true}).fill('Potential API issue');
  await expect(workspace.locator('.evidence-result')).toHaveCount(1);
  await workspace.locator('.evidence-result').click();
  const captures = workspace.getByRole('combobox', {name: /^Supporting capture/});
  await expect(captures.locator('option')).toHaveCount(2);
  await expect(captures.locator('option').last()).toContainText('http-1.json');
  await expect(captures).not.toContainText('node-analysis.json');
  const aid = await captures.locator('option').last().getAttribute('value');
  await workspace.getByRole('combobox', {name: /^Review status/}).selectOption('verified');
  await captures.selectOption(aid);
  await workspace.getByRole('textbox', {name: 'Review note'}).fill('Verified against the browser QA capture.');
  await workspace.getByRole('button', {name: 'Save review'}).click();
  await expect(workspace.getByText('candidate → verified', {exact: true})).toBeVisible();
});

test('failed capture requests show the error without a permanent loading message', async ({page}) => {
  const workspace = await openWorkspace(page, 'Observations');
  await workspace.getByRole('combobox', {name: 'Run', exact: true}).selectOption('qa-current');
  await workspace.getByRole('combobox', {name: 'Kind', exact: true}).selectOption('http');
  await expect(workspace.locator('.evidence-result')).toHaveCount(1);
  await workspace.locator('.evidence-result').click();
  await page.route('**/api/artifacts/*', route => route.fulfill({status: 500, json: {detail: 'Capture unavailable for QA'}}));
  await workspace.getByRole('button', {name: 'Inspect original capture'}).click();
  await expect(workspace.getByRole('alert')).toContainText('Capture unavailable for QA');
  await expect(workspace.getByText('Loading capture…', {exact: true})).toHaveCount(0);
});
