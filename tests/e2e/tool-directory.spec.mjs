import {test, expect} from './fixtures.mjs';

test('left catalog displays contract details without adding nodes and separates legacy records', async ({page, request}) => {
  await page.goto('/');
  const directory = page.getByRole('region', {name: 'Tool catalog'});
  const search = page.getByRole('textbox', {name: 'Search tools and nodes'});
  const nodes = page.locator('.react-flow__node');
  await expect(nodes.first()).toBeVisible();
  const count = await nodes.count();
  await search.fill('jq-filter');
  await directory.getByRole('button', {name: /JQ Filter/}).click();
  const details = page.getByRole('complementary', {name: 'Tool catalog details'});
  const contract = await (await request.get('/api/catalog/tools/jq-filter')).json();
  await expect(details.locator('dt').filter({hasText: 'Declared arguments'}).locator('+ dd')).toHaveText(String(contract.args.length));
  await expect(details.locator('dt').filter({hasText: 'Input sockets'}).locator('+ dd')).toHaveText(contract.inputs.join(', '));
  await expect(nodes).toHaveCount(count);
  await search.fill('httpx');
  await directory.getByRole('button', {name: /Legacy design/}).click();
  await expect(details).toContainText('Design preview');
  await directory.getByLabel('Argument coverage').selectOption('Pinned help checked');
  await expect(directory).toContainText('No matching catalog records');
  await search.fill('');
  await expect(directory.getByRole('button')).toHaveCount(5);
  await details.getByRole('button', {name: 'Close catalog details'}).click();
  await expect(details).toHaveCount(0);
  await expect(nodes).toHaveCount(count);
});
