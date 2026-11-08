import {test,expect} from './fixtures.mjs';

test('bundled support data installs as inputs without dispatching assessments',async({page,request})=>{
 await page.goto('/');
 await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 const w=page.getByRole('dialog',{name:'Local assessment workspace'});
 await w.locator('.local-tabs').getByRole('button',{name:'Inputs',exact:true}).click();
 const data=w.getByRole('region',{name:'Support data packages',exact:true});
 const before=(await (await request.get('/api/runs')).json()).length;
 await data.getByRole('button',{name:'Install bundled support files',exact:true}).click();
 await expect(data.getByRole('status')).toContainText('installed and registered');
 const inputs=await (await request.get('/api/inputs')).json();
 expect(inputs.filter(x=>x.name==='Small directory paths')).toHaveLength(1);
 expect(inputs.filter(x=>x.name==='Trickest trusted resolvers')).toHaveLength(1);
 expect(inputs.filter(x=>x.name==='Nuclei HTTP starter (7 exposure templates)')).toHaveLength(1);
 await data.getByRole('button',{name:'Install bundled support files',exact:true}).click();
 await expect(data.getByRole('status')).toContainText('installed and registered');
 expect((await (await request.get('/api/inputs')).json()).length).toBe(inputs.length);
 expect((await (await request.get('/api/runs')).json()).length).toBe(before);
});

test('installed files fill workflow bindings and persist on the canvas',async({page,request})=>{
 await page.goto('/');
 await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 const w=page.getByRole('dialog',{name:'Local assessment workspace'});
 await w.getByRole('button',{name:'Load web recon with path fuzzing',exact:true}).click();
 const data=w.getByRole('region',{name:'Support data packages',exact:true});
 await data.getByRole('button',{name:'Install bundled support files',exact:true}).click();
 await expect(data.getByRole('status')).toContainText('installed and registered');
 await data.getByRole('button',{name:'Use installed support files',exact:true}).click();
 await expect(data.getByRole('status')).toContainText('1 missing bindings filled; 0 still need an input');
 await w.locator('.local-tabs').getByRole('button',{name:'Workflows',exact:true}).click();
 await w.getByLabel('Workflow name').fill('Bound support files');
 await w.getByRole('button',{name:'Save current canvas',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('Saved Bound support files');
 const list=await (await request.get('/api/workflows')).json();
 const saved=await (await request.get('/api/workflows/'+list.find(x=>x.name==='Bound support files').id)).json();
 const fuzz=saved.graph.nodes.find(x=>x.data.toolId==='ffuf');
 const inputs=await (await request.get('/api/inputs')).json();
 expect(inputs.find(x=>x.id===fuzz.data.inputRefs.wordlist).name).toBe('Small directory paths');
});
