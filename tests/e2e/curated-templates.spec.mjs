import {test, expect} from './fixtures.mjs';

test('curated starters and legacy designs load from the template library without dispatch', async ({page, request}) => {
  const before = (await (await request.get('/api/runs')).json()).length;
  await page.goto('/');
  const open = page.getByRole('button', {name: /^Templates · \d+$/});
  const library = page.getByRole('dialog', {name: 'Template library'});
  await open.click();
  await library.getByLabel('Catalog source').selectOption('curated');
  await expect(library.getByText('1 matching workflows', {exact: true})).toBeVisible();
  await library.getByRole('button', {name: /Web Application Assessment/}).click();
  await expect(library.getByText('Typed starter · preflight')).toBeVisible();
  await library.getByRole('button', {name: 'Load workflow on canvas'}).click();
  const nodes = page.locator('.react-flow__node');
  await expect(nodes).toHaveCount(17);
  for (const title of ['API Surface', 'CAI team analyst', 'Nuclei — reviewed HTTP templates', 'Evidence summary']) {
    await expect(nodes.filter({hasText: title})).toBeVisible();
  }
  await open.click();
  await library.getByLabel('Catalog source').selectOption('Curated legacy');
  await expect(library.getByText('22 matching workflows', {exact: true})).toBeVisible();
  await library.getByRole('button', {name: /Passive subdomain discovery/}).click();
  await library.getByRole('button', {name: 'Load workflow on canvas'}).click();
  await expect(library).toBeHidden();
  await expect(nodes.first()).toBeVisible();
  expect((await (await request.get('/api/runs')).json()).length).toBe(before);
});
