import {test,expect} from './fixtures.mjs';
import {readFile} from 'node:fs/promises';

async function workspace(page,tab){
  await page.goto('/');
  await page.getByRole('button',{name:'Local workspace',exact:true}).click();
  const w=page.getByRole('dialog',{name:'Local assessment workspace'});
  await w.locator('.local-tabs').getByRole('button',{name:tab,exact:true}).click();
  return w;
}

test('workspace usage shows known partial token totals and exports the displayed ledger',async({page})=>{
  const w=await workspace(page,'Usage');
  const usage=w.getByRole('region',{name:'Model usage ledger',exact:true});
  await expect(usage).toContainText('PARTIAL');
  const totals=usage.getByRole('definition');
  await expect(totals).toHaveCount(5);
  await expect(totals.nth(0)).toHaveText('2');
  await expect(totals.nth(1)).toHaveText('2');
  await expect(totals.nth(4)).toHaveText('125');
  await expect(usage.getByRole('status')).toContainText('1 response(s) lack complete token reports');
  await expect(usage.getByRole('row',{name:/Workflow analysis qa-analysis/})).toContainText('100 / 25 / 125');
  const pending=page.waitForEvent('download');
  await usage.getByRole('button',{name:'Export displayed usage'}).click();
  const download=await pending;
  const exported=JSON.parse(await readFile(await download.path(),'utf8'));
  expect(exported.summary.attempts).toBe(2);
  expect(exported.summary.total_tokens).toBe(125);
  expect(exported.summary.missing_usage_responses).toBe(1);
  expect(exported.items[0].node_id).toBe('qa-analysis');
});

test('historical run usage stays unavailable and recorded run totals survive reload',async({page})=>{
  let w=await workspace(page,'Runs');
  await w.locator('.local-runs').getByRole('button',{name:/^qa-basel/}).click();
  let usage=w.getByRole('region',{name:'Run model usage',exact:true});
  await expect(usage).toContainText('Usage was not recorded for this historical run');
  await expect(usage.locator('.usage-totals')).toHaveCount(0);
  await w.locator('.local-runs').getByRole('button',{name:/^qa-curre/}).click();
  await expect(usage).toContainText('PARTIAL');
  await expect(usage.locator('.usage-totals dd').last()).toHaveText('125');
  w=await workspace(page,'Runs');
  await w.locator('.local-runs').getByRole('button',{name:/^qa-curre/}).click();
  usage=w.getByRole('region',{name:'Run model usage',exact:true});
  await expect(usage.locator('.usage-totals dd').last()).toHaveText('125');
});
