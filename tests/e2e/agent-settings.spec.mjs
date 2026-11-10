import {test,expect} from './fixtures.mjs';

async function open(page){
 await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 const w=page.getByRole('dialog',{name:'Local assessment workspace'});
 await w.locator('.local-tabs').getByRole('button',{name:'Agent settings',exact:true}).click();
 await expect(w.getByRole('region',{name:'Saved agent settings'})).toBeVisible();
 return w;
}

test('saved team and planning models restore on reopen without granting execution',async({page,request})=>{
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const before=(await (await request.get('/api/runs')).json()).length;
 await page.goto('/');let w=await open(page);
 // Model choices can be prepared even when provider keys/SDK are unavailable.
 await w.getByRole('combobox',{name:'Model provider',exact:true}).nth(0).selectOption('xai');
 await w.getByRole('combobox',{name:'Model name',exact:true}).nth(0).selectOption('grok-4.7');
 await w.getByRole('combobox',{name:'Model provider',exact:true}).nth(1).selectOption('openai');
 await w.getByRole('combobox',{name:'Model name',exact:true}).nth(1).selectOption('gpt-5.4-mini');
 await w.getByRole('combobox',{name:'Team profile',exact:true}).selectOption('specialist');
 await w.getByRole('combobox',{name:'Task complexity',exact:true}).selectOption('complex');
 await w.getByRole('spinbutton',{name:'Model turns per analyst'}).fill('9');
 await w.getByRole('spinbutton',{name:'Total team model turns'}).fill('63');
 await w.getByRole('spinbutton',{name:'Concurrent analyst workers'}).fill('2');
 await w.getByRole('checkbox',{name:'Adaptive role selection (deterministic)',exact:false}).check();
 await w.getByRole('checkbox',{name:'Add a lead synthesizer pass (model)',exact:false}).check();
 await w.getByRole('checkbox',{name:'Surface & recon model override',exact:true}).check();
 await w.getByRole('combobox',{name:'Surface & recon primary provider',exact:true}).selectOption('venice');
 await w.getByRole('combobox',{name:'Surface & recon primary model',exact:true}).selectOption('__custom__');
 await w.getByRole('textbox',{name:'Surface & recon primary model custom ID',exact:true}).fill('custom-recon-v1');
 await w.getByRole('textbox',{name:'Preset name',exact:true}).fill('Web team');
 await w.getByRole('checkbox',{name:'Restore this preset by default',exact:true}).check();
 await w.getByRole('button',{name:'Save preset',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('Saved Web team');
 const index=await (await request.get('/api/agent-settings')).json();
 expect(index.default.settings.team_routes.surface.primary).toEqual({provider:'venice',model:'custom-recon-v1'});
 expect(index.saved_models.venice).toContain('custom-recon-v1');
 await w.locator('.local-tabs').getByRole('button',{name:'Run setup',exact:true}).click();
 await w.getByRole('combobox',{name:'Execution engine'}).selectOption('workflow');
 await w.getByRole('checkbox',{name:'Enable workflow execution and target traffic',exact:false}).check();
 await w.getByRole('checkbox',{name:'Enable catalog CLI execution',exact:false}).check();
 await page.reload();w=await open(page);
 await expect(w.getByRole('textbox',{name:'Preset name',exact:true})).toHaveValue('Web team');
 await expect(w.getByRole('combobox',{name:'Team profile',exact:true})).toHaveValue('specialist');
 await expect(w.getByRole('combobox',{name:'Task complexity',exact:true})).toHaveValue('complex');
 await expect(w.getByRole('spinbutton',{name:'Model turns per analyst'})).toHaveValue('9');
 await expect(w.getByRole('spinbutton',{name:'Total team model turns'})).toHaveValue('63');
 await expect(w.getByRole('spinbutton',{name:'Concurrent analyst workers'})).toHaveValue('2');
 await expect(w.getByRole('combobox',{name:'Model name',exact:true}).nth(0)).toHaveValue('grok-4.7');
 await expect(w.getByRole('combobox',{name:'Model name',exact:true}).nth(1)).toHaveValue('gpt-5.4-mini');
 await expect(w.getByRole('combobox',{name:'Surface & recon primary model',exact:true})).toHaveValue('custom-recon-v1');
 // A saved custom model is also offered for another role using that provider.
 await w.getByRole('checkbox',{name:'Evidence analyst model override',exact:true}).check();
 await w.getByRole('combobox',{name:'Evidence analyst primary provider',exact:true}).selectOption('venice');
 await w.getByRole('combobox',{name:'Evidence analyst primary model',exact:true}).selectOption('custom-recon-v1');
 await w.locator('.local-tabs').getByRole('button',{name:'Agent desk',exact:true}).click();
 await expect(w.getByRole('checkbox',{name:'Use the configured CAI model to plan',exact:false})).not.toBeChecked();
 await w.locator('.local-tabs').getByRole('button',{name:'Run setup',exact:true}).click();
 await w.getByRole('combobox',{name:'Execution engine'}).selectOption('workflow');
 await expect(w.getByRole('checkbox',{name:'Enable workflow execution and target traffic',exact:false})).not.toBeChecked();
 await expect(w.getByRole('checkbox',{name:'Enable catalog CLI execution',exact:false})).not.toBeChecked();
 await expect(w.getByText('Scope snapshot · 0 targets',{exact:true})).toBeVisible();
 expect((await (await request.get('/api/runs')).json()).length).toBe(before);
 expect(errors).toEqual([]);
});

test('named presets support copy load update and delete',async({page,request})=>{
 await page.goto('/');let w=await open(page);
 await w.getByRole('textbox',{name:'Preset name',exact:true}).fill('First team');
 await w.getByRole('button',{name:'Save preset',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('Saved First team');
 await w.getByRole('spinbutton',{name:'Total team model turns'}).fill('31');
 await w.getByRole('textbox',{name:'Preset name',exact:true}).fill('Second team');
 await w.getByRole('button',{name:'Save as new preset',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('Saved Second team');
 let index=await (await request.get('/api/agent-settings')).json();
 const first=index.items.find(p=>p.name==='First team');
 await w.getByRole('combobox',{name:'Saved preset',exact:true}).selectOption(first.id);
 await w.getByRole('button',{name:'Load preset',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('Loaded First team');
 await expect(w.getByRole('spinbutton',{name:'Total team model turns'})).toHaveValue('48');
 await w.getByRole('spinbutton',{name:'Total team model turns'}).fill('52');
 await w.getByRole('button',{name:'Save changes',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('Saved First team');
 expect((await (await request.get('/api/agent-settings/'+first.id)).json()).settings.team_max_turns).toBe(52);
 await w.getByRole('button',{name:'Delete preset',exact:true}).click();
 await expect(w.getByRole('status')).toContainText('Preset deleted');
 index=await (await request.get('/api/agent-settings')).json();
 expect(index.items.map(p=>p.name)).toEqual(['Second team']);
 expect(index.default).toBeNull();
});
