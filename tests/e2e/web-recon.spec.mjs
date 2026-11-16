import {test,expect} from './fixtures.mjs';

test('wildcard scope survives reload and web recon loads without dispatch',async({page,request})=>{
 await page.goto('/');
 await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 let w=page.getByRole('dialog',{name:'Local assessment workspace'});
 await w.getByLabel('Domain, wildcard, IP, CIDR or HTTP(S) URL').fill('*.Example.com');
 await w.getByRole('button',{name:'Add target',exact:true}).click();
 await expect(w.getByLabel('Select *.example.com',{exact:true})).toBeChecked();
 await expect(w).toContainText('excludes the apex');
 const before=(await (await request.get('/api/runs')).json()).length;
 await w.getByRole('button',{name:'Load web recon workflow',exact:true}).click();
 await expect(w.locator('.local-tabs').getByRole('button',{name:'Run setup',exact:true})).toHaveClass(/active/);
 expect((await (await request.get('/api/runs')).json()).length).toBe(before);
 await w.locator('.local-tabs').getByRole('button',{name:'Workflows',exact:true}).click();
 await w.getByLabel('Workflow name').fill('Scoped web recon fixture');
 await w.getByRole('button',{name:'Save current canvas',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('Saved Scoped web recon fixture');
 const workflows=await (await request.get('/api/workflows')).json();
 const saved=await (await request.get('/api/workflows/'+workflows.find(x=>x.name==='Scoped web recon fixture').id)).json();
 expect(saved.graph.nodes.map(x=>x.data.toolId).filter(Boolean)).toEqual(['subfinder','assetfinder','httprobe','katana']);
 expect(saved.graph.nodes.some(x=>x.data.kind==='native_web_assets')).toBe(true);
 await page.reload();
 await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 w=page.getByRole('dialog',{name:'Local assessment workspace'});
 await expect(w.getByLabel('Select *.example.com',{exact:true})).toBeVisible();
});

test('optional fuzzing starter exposes the required wordlist before execution',async({page,request})=>{
 await page.goto('/');
 await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 const w=page.getByRole('dialog',{name:'Local assessment workspace'});
 await w.getByLabel('Domain, wildcard, IP, CIDR or HTTP(S) URL').fill('*.example.com');
 await w.getByRole('button',{name:'Add target',exact:true}).click();
 const before=(await (await request.get('/api/runs')).json()).length;
 await w.getByRole('button',{name:'Load web recon with path fuzzing',exact:true}).click();
 await w.getByLabel('Enable catalog CLI execution').check();
 await w.getByRole('button',{name:'Check workflow readiness',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('registered wordlist');
 expect((await (await request.get('/api/runs')).json()).length).toBe(before);
});

test('scoped ffuf starter loads enforcement and prompts for a wordlist',async({page,request})=>{
 await page.goto('/');
 await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 const w=page.getByRole('dialog',{name:'Local assessment workspace'});
 await w.getByRole('button',{name:'Load scoped ffuf',exact:true}).click();
 await expect(w.getByLabel('CLI scope enforcement')).toHaveValue('enforced');
 await w.getByLabel('Enable catalog CLI execution').check();
 await w.getByRole('button',{name:'Check workflow readiness',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('registered wordlist');
 expect(await (await request.get('/api/_qa/target-calls')).json()).toEqual([]);
});

test('scanner profiles report pinned versions, capture coverage, and bundled inputs',async({page,request})=>{
 await page.goto('/');
 await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 const workspace=page.getByRole('dialog',{name:'Local assessment workspace'});
 await workspace.getByRole('button',{name:'Scanner profiles',exact:true}).click();
 const readiness=workspace.getByRole('region',{name:'Scanner profiles'});
 const table=readiness.getByRole('table',{name:'Scanner readiness'});
 await expect(table.getByRole('row').filter({hasText:'httprobe'})).toContainText('HTTP History');
 await expect(table.getByRole('row').filter({hasText:'ffuf'})).toContainText('v2.1.0');
 await request.post('/api/support-data/install/bundled',{data:{}});
 await readiness.getByRole('button',{name:'Check scanner setup'}).click();
 await expect(readiness).toContainText('Small directory paths · Registered and verified');
 await readiness.getByLabel('Profile',{exact:false}).selectOption('web-recon');
 await expect(table.getByRole('row').filter({hasText:'nuclei'})).toContainText('External proxy history');
 await expect(readiness).toContainText('Trickest trusted resolvers · Registered and verified');
 expect(await (await request.get('/api/_qa/target-calls')).json()).toEqual([]);
});
