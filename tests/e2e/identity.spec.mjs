import {test,expect} from './fixtures.mjs';

async function workspace(page){
 await page.goto('/');await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 return page.getByRole('dialog',{name:'Local assessment workspace'});
}
const fixture={schema:'ai-tricky.identity-graph/v1',scope:{platform:'ad',domain:'corp.test',tenant_id:''},
 nodes:[{id:'user',label:'Fixture user',kind:'user'},{id:'goal',label:'Fixture goal',kind:'group'}],edges:[{source:'user',target:'goal',kind:'GenericAll'}]};

test('identity import runs offline and retained path evidence stays a candidate',async({page,request})=>{
 const registered=await request.post('/api/inputs',{data:{name:'Browser identity graph',content:JSON.stringify(fixture)}});const input=await registered.json();
 const before=(await (await request.get('/api/runs')).json()).length;
 const w=await workspace(page);
 await w.getByLabel('Domain, wildcard, IP, CIDR or HTTP(S) URL').fill('corp.test');await w.getByRole('button',{name:'Add target',exact:true}).click();
 await w.locator('.local-tabs').getByRole('button',{name:'Identity',exact:true}).click();
 await w.getByRole('textbox',{name:'Identity domain',exact:true}).fill('corp.test');
 await w.getByRole('combobox',{name:'Identity graph export',exact:true}).selectOption(input.id);
 await w.getByRole('textbox',{name:'Start object IDs',exact:true}).fill('user');await w.getByRole('textbox',{name:'Goal object IDs',exact:true}).fill('goal');
 await w.getByRole('button',{name:'Load identity workflow on canvas',exact:true}).click();
 await w.getByRole('button',{name:'Check workflow readiness',exact:true}).click();await expect(w.getByRole('status')).toContainText('Preflight ready');
 expect((await (await request.get('/api/runs')).json()).length).toBe(before);
 await w.getByLabel('Enable workflow execution and target traffic').check();
 const launched=page.waitForResponse(r=>r.url().endsWith('/api/runs')&&r.request().method()==='POST');
 await w.getByRole('button',{name:'Start assessment workflow',exact:true}).click();const response=await launched;expect(response.status()).toBe(201);const run=await response.json();
 await expect.poll(async()=> (await (await request.get('/api/runs/'+run.id)).json()).status).toBe('completed');
 await expect(w.locator('.local-artifacts button').filter({hasText:'identity-analysis-'})).toHaveCount(1);
 await w.locator('.local-artifacts button').filter({hasText:'identity-analysis-'}).click();
 await expect(w.locator('.report').filter({hasText:'identity-analysis-'}).locator('pre')).toContainText('CANDIDATE_PATH');await expect(w.locator('.report').filter({hasText:'identity-analysis-'}).locator('pre')).toContainText('"executed": false');
 expect(await (await request.get('/api/_qa/target-calls')).json()).toHaveLength(0);
});

test('Entra collection stays a configured canvas operation with explicit tenant and credential reference',async({page,request})=>{
 const credential=await (await request.post('/api/inputs',{data:{name:'Fixture Graph credential',content:'never-dispatched-fixture-token'}})).json();
 const before=(await (await request.get('/api/runs')).json()).length;
 const w=await workspace(page);await w.locator('.local-tabs').getByRole('button',{name:'Identity',exact:true}).click();
 await w.getByRole('checkbox',{name:'Collect directory evidence with a fixed tool profile',exact:true}).check();
 await w.getByRole('combobox',{name:'Identity environment',exact:true}).selectOption('entra');
 await w.getByRole('textbox',{name:'Identity domain',exact:true}).fill('corp.onmicrosoft.com');
 await w.getByRole('textbox',{name:'Entra tenant UUID',exact:true}).fill('11111111-1111-1111-1111-111111111111');
 await w.getByRole('combobox',{name:'Graph access token input',exact:true}).selectOption(credential.id);
 await expect(w.getByRole('region',{name:'Identity assessment workspace'})).toContainText('External / operator-led; no execution adapter');
 await w.getByRole('button',{name:'Load identity workflow on canvas',exact:true}).click();
 await w.locator('.local-tabs').getByRole('button',{name:'Workflows',exact:true}).click();
 await w.getByLabel('Workflow name').fill('Entra identity fixture');await w.getByRole('button',{name:'Save current canvas',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('Saved Entra identity fixture');
 const workflows=await (await request.get('/api/workflows')).json();const saved=await (await request.get('/api/workflows/'+workflows.find(x=>x.name==='Entra identity fixture').id)).json();
 const collector=saved.graph.nodes.find(n=>n.data.kind==='native_identity_collect').data;
 expect(collector.profile_id).toBe('azurehound-entra');expect(collector.identity_scope.tenant_id).toBe('11111111-1111-1111-1111-111111111111');
 expect(collector.inputRefs).toEqual({access_token:credential.id});expect(JSON.stringify(saved.graph)).not.toContain('never-dispatched-fixture-token');
 expect((await (await request.get('/api/runs')).json()).length).toBe(before);
 expect(await (await request.get('/api/_qa/target-calls')).json()).toHaveLength(0);
});
