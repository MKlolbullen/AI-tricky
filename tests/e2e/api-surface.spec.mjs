import {test, expect} from './fixtures.mjs';

test('saved sources expose searchable API routes without sending traffic', async ({page, request}) => {
  const calls = await (await request.get('/api/_qa/target-calls')).json();
  await page.goto('/');
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  const workspace = page.getByRole('dialog', {name: 'Local assessment workspace'});
  await workspace.getByRole('button', {name: 'API Surface', exact: true}).click();
  const surface = workspace.getByRole('region', {name: 'API Surface', exact: true});
  await surface.getByLabel('Source collection run').selectOption({index: 1});
  const route = surface.getByRole('button', {name: /GET .*\/api\/users/});
  await expect(route).toBeVisible();
  await route.click();
  await expect(surface.getByRole('region', {name: 'Endpoint evidence'})).toContainText('/app.js:1:1');
  await surface.getByLabel('Filter endpoints').fill('sort');
  await expect(route).toBeVisible();
  await surface.getByLabel('Filter endpoints').fill('absent');
  await expect(route).toHaveCount(0);
  expect(await (await request.get('/api/_qa/target-calls')).json()).toEqual(calls);
});

test('tool inspector edits flags and values with separate required bindings', async ({page, request}) => {
  await request.post('/api/support-data/install/bundled', {data: {}});
  await page.goto('/');
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  const workspace = page.getByRole('dialog', {name: 'Local assessment workspace'});
  await workspace.getByLabel('Domain, wildcard, IP, CIDR or HTTP(S) URL').fill('*.example.test');
  await workspace.getByRole('button', {name: 'Add target', exact: true}).click();
  await workspace.getByRole('button', {name: 'Load web recon with path fuzzing', exact: true}).click();
  await workspace.getByRole('button', {name: 'Close local workspace'}).click();
  await page.locator('.react-flow__node').filter({hasText: 'Optional path fuzzing'}).click();
  const panel = page.getByRole('region', {name: 'Tool arguments'});
  const filter = panel.getByRole('searchbox', {name: 'Filter arguments'});
  await filter.fill('Stop on Flood');
  await panel.getByRole('checkbox', {name: /Stop on Flood/}).check();
  await filter.fill('Threads');
  await panel.getByRole('spinbutton', {name: /Threads/}).fill('7');
  await expect(panel).toContainText('2 configured');
  await panel.getByText('Command preview', {exact: true}).click();
  await expect(panel.locator('pre')).toContainText('"7"');
  await filter.fill('Follow Redirects');
  await expect(panel.getByRole('checkbox', {name: /Follow Redirects/})).toBeDisabled();
  const bindings = page.getByRole('region', {name: 'Tool input bindings'});
  await expect(bindings).toContainText('Required');
  await bindings.getByLabel(/Wordlist/).selectOption({label: 'Small directory paths'});
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  await workspace.locator('.local-tabs').getByRole('button', {name: 'Workflows', exact: true}).click();
  await workspace.getByLabel('Workflow name').fill('Configured ffuf');
  await workspace.getByRole('button', {name: 'Save current canvas'}).click();
  await expect(workspace.getByRole('status')).toContainText('Saved Configured ffuf');
  const list = await (await request.get('/api/workflows')).json();
  const saved = await (await request.get('/api/workflows/' + list.find(row => row.name === 'Configured ffuf').id)).json();
  const fuzz = saved.graph.nodes.find(node => node.data.toolId === 'ffuf').data;
  expect(fuzz.params).toMatchObject({'-sf': true, '-t': '7'});
  expect(fuzz.inputRefs.wordlist).toBeTruthy();
});

test('a saved native GET opens an approved multi-identity access matrix', async ({page, request}) => {
  await page.goto('/');
  await page.getByRole('button', {name: 'Local workspace', exact: true}).click();
  const workspace = page.getByRole('dialog', {name: 'Local assessment workspace'});
  await workspace.getByRole('button', {name: 'API Surface', exact: true}).click();
  const surface = workspace.getByRole('region', {name: 'API Surface', exact: true});
  await surface.getByLabel('Source collection run').selectOption({index: 1});
  await surface.getByRole('button', {name: /GET .*\/api\/users/}).click();
  await surface.getByRole('button', {name: 'Set up access matrix'}).click();
  const settings = surface.getByRole('region', {name: 'Access matrix settings'});
  await expect(surface.getByLabel('HTTP check profile')).toHaveValue('access_matrix');
  await expect(surface.getByLabel('Native operation limit')).toHaveValue('6');
  await settings.getByText('Manage test identities', {exact: true}).click();
  const identityIds = [];
  for (const [label, token] of [['Owner', 'qa-matrix-owner'], ['Peer', 'qa-matrix-peer'], ['Read-only', 'qa-matrix-expired']]) {
    await settings.getByLabel('Identity label').fill(label);
    await settings.getByLabel('Bearer token').fill(token);
    const added = page.waitForResponse(response => response.url().endsWith('/api/verification/identities') &&
      response.request().method() === 'POST');
    await settings.getByRole('button', {name: 'Register test identity'}).click();
    identityIds.push((await (await added).json()).id);
    await expect(settings.getByLabel('Bearer token')).toHaveValue('');
  }
  await settings.getByLabel('Object A owner', {exact: true}).selectOption({label: 'Owner'});
  await settings.getByLabel('Object B owner', {exact: true}).selectOption({label: 'Peer'});
  await settings.getByLabel('Third test identity', {exact: true}).selectOption({label: 'Read-only'});
  await settings.getByLabel('Expected object A ID').fill('first');
  const saved = await settings.locator('.verification-matrix-objects code').textContent();
  await settings.getByLabel('Object B URL').fill(new URL('/matrix-control', saved).href);
  await settings.getByLabel('Expected object B ID').fill('second');
  await settings.getByLabel('Object A owner on object B').selectOption('allow');
  await settings.getByLabel('Object B owner on object A').selectOption('deny');
  await settings.getByLabel('Third test identity on object A').selectOption('allow');
  await settings.getByLabel('Third test identity on object B').selectOption('deny');
  await surface.getByRole('button', {name: 'Prepare execution review'}).click();
  const preview = surface.getByRole('table', {name: 'Approved access matrix requests'});
  await expect(preview.getByRole('row')).toHaveCount(7);
  await expect(preview.getByRole('row').filter({hasText: 'identity-2-object-1'})).toContainText('deny');
  expect(await (await request.get('/api/_qa/target-calls')).json()).toEqual([]);
  await surface.getByRole('checkbox', {name: 'I approve this exact scope, workflow and limits.'}).check();
  await surface.getByRole('button', {name: 'Approve & start once'}).click();
  const results = workspace.getByRole('table', {name: 'Access matrix results'});
  await expect(results.getByRole('row').filter({hasText: 'Peer'})).toContainText('Unexpected access result');
  await expect(results.getByRole('row').filter({hasText: 'Read-only'})).toContainText('HTTP 401');
  await expect(results.getByRole('row').filter({hasText: 'Read-only'})).toContainText('Inconclusive');
  const calls = await (await request.get('/api/_qa/target-calls')).json();
  expect(calls.map(call => call.path)).toEqual(['/api/users', '/matrix-control', '/matrix-control', '/api/users', '/api/users', '/matrix-control']);
  expect(calls.every(call => call.authorization && !call.cookie)).toBe(true);
  for (const id of identityIds) {
    await request.post('/api/verification/identities/' + id + '/remove', {data: {}});
  }
});
