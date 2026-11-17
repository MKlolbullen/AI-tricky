import {test, expect} from './fixtures.mjs';
import {catalogNode, migrated} from '../../src/catalog-contracts.mjs';
import {nativeNode} from '../../src/native-workflow.mjs';
import {WORKFLOW_SCHEMA} from '../../src/workflow-validation.mjs';

test('named catalog and native sockets connect, save, and restore', async ({page, request}) => {
  const graph = {
    schema: WORKFLOW_SCHEMA,
    nodes: [
      nativeNode('scope', 'native_scope', {x: 0, y: 100}),
      catalogNode('probe', migrated.tools.find(tool => tool.id === 'httpx'), {x: 260, y: 100}),
      nativeNode('capture', 'native_http', {x: 520, y: 100}),
    ],
    edges: [{id: 'scope-probe', source: 'scope', target: 'probe'}],
  };
  await page.goto('/');
  await page.locator('input[type=file][accept="application/json,.json"]').setInputFiles({
    name: 'socket-fixture.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(graph)),
  });
  const edges = page.locator('.react-flow__edge');
  await expect(edges).toHaveCount(1);
  const source = page.locator('[data-id="probe"] [data-handleid="out:url"]');
  const target = name => page.locator(`[data-id="capture"] [data-handleid="in:${name}"]`);
  await expect(source).toBeVisible();
  await expect(target('url')).toBeVisible();
  await source.dragTo(target('services'));
  await expect(edges).toHaveCount(1);
  await source.dragTo(target('url'));
  await expect(edges).toHaveCount(2);

  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  const workspace = page.getByRole('dialog', {name: 'Local assessment workspace'});
  await workspace.locator('.local-tabs').getByRole('button', {name: 'Workflows', exact: true}).click();
  await workspace.getByLabel('Workflow name').fill('Named socket fixture');
  await workspace.getByRole('button', {name: 'Save current canvas'}).click();
  await expect(workspace.getByRole('status')).toContainText('Saved Named socket fixture');
  const list = await (await request.get('/api/workflows')).json();
  const saved = await (await request.get('/api/workflows/' + list.find(row => row.name === 'Named socket fixture').id)).json();
  expect(saved.graph.edges).toMatchObject([
    {id: 'scope-probe', sourceHandle: 'out:targets', targetHandle: 'in:targets'},
    {id: 'edge-2', sourceHandle: 'out:url', targetHandle: 'in:url'},
  ]);
  await workspace.getByRole('button', {name: /Named socket fixture.*Load on canvas/}).click();
  await expect(workspace.getByRole('status')).toContainText('Loaded Named socket fixture');
  await expect(edges).toHaveCount(2);
});
