import {test, expect} from './fixtures.mjs';

test('the Trickest catalog loads a local workflow and adds a typed tool', async ({page, request}) => {
  const before = (await (await request.get('/api/runs')).json()).length;
  const installed = await request.post('/api/support-data/install/bundled', {data: {}});
  expect(installed.ok()).toBe(true);
  await page.goto('/');
  const open = page.getByRole('button', {name: /^Templates · \d+$/});
  const library = page.getByRole('dialog', {name: 'Template library'});
  await open.click();
  await library.getByLabel('Catalog source').selectOption('trickest-oss');
  await expect(library.getByText('3 matching workflows', {exact: true})).toBeVisible();
  await library.getByRole('button', {name: /Trickest · Subdomain candidates/}).click();
  await library.getByRole('button', {name: 'Load workflow on canvas'}).click();
  await expect(page.locator('.react-flow__node').filter({hasText: 'mksub · Subdomain combinations'})).toBeVisible();
  await open.click();
  await library.getByLabel('Catalog source').selectOption('trickest-oss');
  await library.getByRole('button', {name: /Tool catalog/}).click();
  await expect(library.getByText('2 matching tools', {exact: true})).toBeVisible();
  await library.getByRole('button', {name: /mkpath · URL path combinations/}).click();
  await library.getByRole('button', {name: 'Add tool to canvas'}).click();
  await expect(page.locator('.react-flow__node').filter({hasText: 'mkpath · URL path combinations'})).toBeVisible();
  expect((await (await request.get('/api/runs')).json()).length).toBe(before);
});
