import {test,expect} from './fixtures.mjs';

test('mixed-provider profile sends explicit per-role models and fallback bindings',async({page})=>{
 await page.route('**/api/runtime',async route=>{
  const response=await route.fetch();const runtime=await response.json();
  await route.fulfill({json:{...runtime,sdk_ready:true,remote_model_enabled:true,
   model_providers:runtime.model_providers.map(p=>({...p,configured:true}))}});
 });
 let sent;
 await page.route('**/api/runs',async route=>{
  if(route.request().method()!=='POST')return route.continue();
  sent=route.request().postDataJSON();
  await route.fulfill({status:201,json:await (await page.request.get('/api/runs/qa-specialists')).json()});
 });
 await page.goto('/');await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 const w=page.getByRole('dialog',{name:'Local assessment workspace'});
 await w.locator('.local-tabs').getByRole('button',{name:'Run setup',exact:true}).click();
 await w.getByRole('combobox',{name:'Execution engine'}).selectOption('team');
 await w.getByRole('button',{name:'Use mixed-provider routing',exact:true}).click();
 await expect(w.getByRole('combobox',{name:'Team profile',exact:true})).toHaveValue('specialist');
 const names=['Surface & recon','Evidence analyst','Vulnerability specialist','PoC / validation specialist','Lead synthesis'];
 for(let i=0;i<names.length;i++)await w.getByRole('textbox',{name:names[i]+' primary model',exact:true}).fill('fixture-'+i);
 await w.getByRole('checkbox',{name:'Surface & recon availability fallback',exact:true}).check();
 await w.getByRole('combobox',{name:'Surface & recon fallback provider',exact:true}).selectOption('openai');
 await w.getByRole('textbox',{name:'Surface & recon fallback model',exact:true}).fill('backup-fixture');
 await w.getByRole('checkbox',{name:'Surface & recon complex-task override',exact:true}).check();
 await w.getByRole('combobox',{name:'Surface & recon complex-task provider',exact:true}).selectOption('openai');
 await w.getByRole('textbox',{name:'Surface & recon complex-task model',exact:true}).fill('complex-fixture');
 await w.getByRole('combobox',{name:'Task complexity',exact:true}).selectOption('complex');
 await w.getByRole('button',{name:'Generate assessment plan',exact:true}).click();
 await expect.poll(()=>sent?.team_profile).toBe('specialist');
 expect(sent.synthesize).toBe(true);
 expect(sent.team_task_level).toBe('complex');
 expect(sent.team_routes.surface.complex_task).toEqual({provider:'openai',model:'complex-fixture'});
 expect(sent.team_routes.surface.primary.provider).toBe('gemini');
 expect(sent.team_routes.surface.fallback).toEqual({provider:'openai',model:'backup-fixture'});
 expect(sent.team_routes.analyst.primary.provider).toBe('openai');
 expect(sent.team_routes.vulnerability.primary.provider).toBe('venice');
 expect(sent.team_routes.poc.primary.provider).toBe('venice');
 expect(sent.team_routes.lead.primary.provider).toBe('anthropic');
 expect(JSON.stringify(sent)).not.toContain('api_key');
});

test('recorded specialist routes and handoffs can be inspected without target dispatch',async({page,request})=>{
 const before=(await (await request.get('/api/runs')).json()).length;
 await page.goto('/');await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 const w=page.getByRole('dialog',{name:'Local assessment workspace'});
 await w.locator('.local-tabs').getByRole('button',{name:'Runs',exact:true}).click();
 await w.locator('.local-runs button').filter({hasText:'qa-speci'}).click();
 const history=w.getByRole('region',{name:'Team routes and handoffs',exact:true});
 await expect(history).toContainText('Primary · local / fixture-model · completed');
 await expect(history).toContainText('Validation plan · not executed');
 await history.getByRole('button',{name:'Inspect PoC / validation specialist handoff',exact:true}).click();
 await expect(w.locator('.report').filter({hasText:'Handoff to PoC / validation specialist'})).toContainText('ai-tricky.team-handoff/v1');
 expect((await (await request.get('/api/runs')).json()).length).toBe(before);
});
