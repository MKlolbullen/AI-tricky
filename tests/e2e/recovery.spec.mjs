import {test, expect} from './fixtures.mjs';
import {readFile} from 'node:fs/promises';

async function openRecovery(page) {
  await page.goto('/');
  await page.getByRole('button', {name:'Local workspace', exact:true}).click();
  const workspace=page.getByRole('dialog', {name:'Local assessment workspace'});
  await workspace.locator('.local-tabs').getByRole('button', {name:'Runs', exact:true}).click();
  await workspace.locator('.local-runs').getByRole('button', {name:/^qa-recov/}).click();
  await workspace.getByRole('button', {name:'Recover workflow branches', exact:true}).click();
  const recovery=workspace.getByRole('region', {name:'Workflow recovery', exact:true});
  await expect(recovery.getByRole('checkbox', {name:'Retry HTTP retry', exact:true})).toBeChecked();
  return {workspace, recovery};
}

test('recovery restores without approval, reuses the checkpoint and dispatches exactly once', async ({page, request}) => {
  let {workspace, recovery}=await openRecovery(page);
  await recovery.getByRole('button', {name:'Prepare recovery review', exact:true}).click();
  let snapshot=recovery.getByRole('region', {name:'Recovery snapshot', exact:true});
  await expect(snapshot).toContainText('2 step(s) to execute · 1 checkpoint(s) to reuse');
  await expect(snapshot.getByRole('row', {name:/Saved scope Reuse checkpoint/})).toBeVisible();
  await expect(snapshot.getByRole('button', {name:'Start approved recovery'})).toBeDisabled();
  expect(await (await request.get('/api/_qa/target-calls')).json()).toEqual([]);
  const pendingDownload=page.waitForEvent('download');
  await snapshot.getByRole('button', {name:'Export recovery review'}).click();
  const review=JSON.parse(await readFile(await (await pendingDownload).path(), 'utf8'));
  expect(review.snapshot.source_run_id).toBe('qa-recovery');
  expect(review.snapshot.rerun_ids).toEqual(['r1','r2']);
  await page.reload();
  ({workspace, recovery}=await openRecovery(page));
  await recovery.getByRole('combobox', {name:'Saved recovery reviews'}).selectOption(review.id);
  snapshot=recovery.getByRole('region', {name:'Recovery snapshot', exact:true});
  const approve=snapshot.getByRole('checkbox', {name:'Approve this recovery snapshot and repeat the listed execution steps'});
  await expect(approve).not.toBeChecked();
  await expect(snapshot.getByRole('button', {name:'Start approved recovery'})).toBeDisabled();
  await expect(recovery.getByRole('spinbutton', {name:'Recovery native operation limit'})).toBeDisabled();
  await approve.check();
  await snapshot.getByRole('button', {name:'Start approved recovery'}).click();
  const provenance=workspace.getByRole('region', {name:'Workflow recovery provenance'});
  await expect(provenance).toContainText('Source run qa-recov');
  await expect(workspace.locator('.node-run-row .run-status.reused')).toHaveCount(1);
  await expect(workspace.locator('.checkpoint-origin')).toContainText('Source qa-recov');
  const recorded=await (await request.get(`/api/recoveries/${review.id}`)).json();
  await expect.poll(async () => (await (await request.get(`/api/runs/${recorded.run_id}`)).json()).status).toBe('completed');
  const calls=await (await request.get('/api/_qa/target-calls')).json();
  expect(calls).toHaveLength(1);
  const receipt=await (await request.post(`/api/recoveries/${review.id}/dispatch`, {data:{expected_hash:review.snapshot_hash, approve:true}})).json();
  expect(receipt.created).toBe(false);
  expect(receipt.run.result.request_count).toBe(1);
  expect(await (await request.get('/api/_qa/target-calls')).json()).toHaveLength(1);
  expect((await (await request.get('/api/runs/qa-recovery')).json()).status).toBe('failed');
});

test('editing recovery settings revokes the previous snapshot and requires fresh approval', async ({page, request}) => {
  const {recovery}=await openRecovery(page);
  await recovery.getByRole('button', {name:'Prepare recovery review', exact:true}).click();
  const snapshot=recovery.getByRole('region', {name:'Recovery snapshot', exact:true});
  await expect(snapshot).toBeVisible();
  const previousHash=await snapshot.locator('.execution-hash').textContent();
  await snapshot.getByRole('checkbox', {name:'Approve this recovery snapshot and repeat the listed execution steps'}).check();
  await snapshot.getByRole('button', {name:'Edit recovery settings'}).click();
  await recovery.getByRole('spinbutton', {name:'Recovery native operation limit'}).fill('2');
  await recovery.getByRole('button', {name:'Prepare recovery review', exact:true}).click();
  await expect(snapshot).toContainText('2 native operation(s) maximum');
  await expect(snapshot.locator('.execution-hash')).not.toHaveText(previousHash);
  await expect(snapshot.getByRole('checkbox', {name:'Approve this recovery snapshot and repeat the listed execution steps'})).not.toBeChecked();
  await expect(snapshot.getByRole('button', {name:'Start approved recovery'})).toBeDisabled();
  expect(await (await request.get('/api/_qa/target-calls')).json()).toEqual([]);
});
