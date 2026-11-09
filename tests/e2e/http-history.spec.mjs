import {test,expect} from './fixtures.mjs';
import {readFile} from 'node:fs/promises';

async function workspace(page,tab){
 await page.goto('/');await page.getByRole('button',{name:'Local workspace',exact:true}).click();
 const w=page.getByRole('dialog',{name:'Local assessment workspace'});
 await w.locator('.local-tabs').getByRole('button',{name:tab,exact:true}).click();return w;
}

test('run setup submits an explicit Burp-compatible route without dispatching target traffic',async({page,request})=>{
 let sent;
 await page.route('**/api/runs',async route=>{
  if(route.request().method()!=='POST')return route.continue();
  sent=route.request().postDataJSON();
  await route.fulfill({status:201,json:await (await request.get('/api/runs/qa-execution')).json()});
 });
 const w=await workspace(page,'Run setup');
 await expect(w.getByRole('combobox',{name:'HTTP routing',exact:true})).toHaveValue('direct');
 await w.getByRole('combobox',{name:'HTTP routing',exact:true}).selectOption('proxy');
 await expect(w.getByRole('textbox',{name:'HTTP proxy URL',exact:true})).toHaveValue('http://127.0.0.1:8080');
 await w.getByRole('textbox',{name:'HTTP proxy URL',exact:true}).fill('http://127.0.0.1:8081');
 await w.getByRole('button',{name:'Generate assessment plan',exact:true}).click();
 await expect.poll(()=>sent?.http_routing).toEqual({mode:'proxy',proxy_url:'http://127.0.0.1:8081',ca_input_id:null});
 expect(await (await request.get('/api/_qa/target-calls')).json()).toHaveLength(0);
});

test('direct native traffic survives reload with request response body and HAR inspection',async({page,request})=>{
 const targets=await (await request.get('/api/targets')).json();
 const start=await request.post('/api/runs',{data:{engine:'inventory',target_ids:[targets[0].id],allow_http:true,max_requests:1,ports:[80]}});
 expect(start.status()).toBe(201);const run=await start.json();
 await expect.poll(async()=> (await (await request.get('/api/runs/'+run.id)).json()).status).toBe('completed');
 const w=await workspace(page,'HTTP history');
 await w.getByRole('combobox',{name:'Traffic run',exact:true}).selectOption(run.id);
 await w.getByRole('button',{name:'GET '+targets[0].url,exact:true}).click();
 const saved=w.getByRole('region',{name:'Saved HTTP exchange',exact:true});
 await expect(saved.locator('pre')).toContainText('GET / HTTP/1.1');
 await saved.getByRole('button',{name:'Response',exact:true}).click();
 await expect(saved.locator('pre')).toContainText('Approved loopback browser execution fixture');
 let pending=page.waitForEvent('download');
 await saved.getByRole('button',{name:'Download response body bytes',exact:true}).click();
 expect(await readFile(await (await pending).path(),'utf8')).toBe('Approved loopback browser execution fixture');
 pending=page.waitForEvent('download');await w.getByRole('button',{name:'Export this page as HAR',exact:true}).click();
 const har=JSON.parse(await readFile(await (await pending).path(),'utf8'));
 expect(har.log.entries).toHaveLength(1);
 expect(har.log.entries[0]._ai_tricky.route.mode).toBe('direct');
 expect(har.log._capture_page.has_more).toBe(false);
 await workspace(page,'HTTP history');
 await expect(page.getByRole('button',{name:'GET '+targets[0].url,exact:true})).toBeVisible();
 expect(await (await request.get('/api/_qa/target-calls')).json()).toHaveLength(1);
});

test('Burp saved-items import persists binary evidence without replay or duplicate items',async({page,request})=>{
 const run=await (await request.get('/api/runs/qa-execution')).json(),url=run.config.targets[0]+'from-burp';
 const req=Buffer.from('POST /from-burp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nDATA').toString('base64');
 const res=Buffer.from('HTTP/1.1 200 OK\r\nX-Source: imported-proxy\r\n\r\n\u0000\u00ff','latin1').toString('base64');
 const xml=`<items><item><url>${url}</url><request base64="true">${req}</request><response base64="true">${res}</response></item></items>`;
 const w=await workspace(page,'HTTP history');
 await w.getByRole('combobox',{name:'Traffic run',exact:true}).selectOption(run.id);
 for(let i=0;i<2;i++){
  await w.getByLabel('Import Burp saved-items XML').setInputFiles({name:'burp.xml',mimeType:'application/xml',buffer:Buffer.from(xml)});
  await expect(w.getByRole('status')).toContainText('1 exported items stored or already present');
 }
 await expect(w.getByRole('button',{name:'POST '+url,exact:true})).toHaveCount(1);
 await w.getByRole('button',{name:'POST '+url,exact:true}).click();
 const saved=w.getByRole('region',{name:'Saved HTTP exchange',exact:true});
 await expect(saved).toContainText('burp_xml');
 await expect(saved.locator('pre')).toContainText('DATA');
 await saved.getByRole('button',{name:'Response',exact:true}).click();
 const pending=page.waitForEvent('download');await saved.getByRole('button',{name:'Download response body bytes',exact:true}).click();
 expect(await readFile(await (await pending).path())).toEqual(Buffer.from([0,255]));
 expect(await (await request.get('/api/_qa/target-calls')).json()).toHaveLength(0);
});
