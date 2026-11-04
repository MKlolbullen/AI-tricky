import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateWorkflow,WORKFLOW_SCHEMA} from '../src/workflow-validation.mjs';
const catalog=JSON.parse(readFileSync(new URL('../src/templates.json',import.meta.url)));
const graph=()=>structuredClone({schema:WORKFLOW_SCHEMA,...catalog.workflows.find(t=>t.id==='web-recon')});
test('every template graph has known tools, compatible ports, unique IDs and no cycles',()=>{
 assert.equal(new Set(catalog.tools.map(t=>t.id)).size,catalog.tools.length);
 assert.equal(new Set(catalog.workflows.map(t=>t.id)).size,catalog.workflows.length);
 for(const w of catalog.workflows)validateWorkflow({schema:WORKFLOW_SCHEMA,...w},['template'],catalog.tools);
 assert.deepEqual(catalog.workflows.filter(w=>w.engine).map(w=>w.engine).sort(),['cai','inventory']);
});
test('reject dangling edges, mismatched descriptors, duplicate IDs and cycles',()=>{
 let v=graph();v.edges[0].target='missing';assert.throws(()=>validateWorkflow(v,['template'],catalog.tools));
 v=graph();v.nodes[1].data.output='findings';assert.throws(()=>validateWorkflow(v,['template'],catalog.tools));
 v=graph();v.nodes[1].id=v.nodes[0].id;assert.throws(()=>validateWorkflow(v,['template'],catalog.tools));
 v=graph();v.edges.push({id:'cycle',source:v.nodes[2].id,target:v.nodes[1].id});assert.throws(()=>validateWorkflow(v,['template'],catalog.tools));
 v=graph();v.edges[0].target=v.nodes[3].id;assert.throws(()=>validateWorkflow(v,['template'],catalog.tools));
});
test('legacy exports are accepted and arbitrary binary nodes are rejected',()=>{
 const v={schema:'reconforge.prototype.workflow/v1',nodes:[{id:'01',type:'tool',position:{x:0,y:0},data:{kind:'domain'}}],edges:[]};
 assert.equal(validateWorkflow(v,['domain'],catalog.tools),v);
 v.nodes[0].data.kind='shell';assert.throws(()=>validateWorkflow(v,['domain'],catalog.tools));
});

import {nativeWorkflow,nativeNode,registry} from '../src/native-workflow.mjs';
test('native starter imports with canonical typed adapter contracts',()=>{
 const v=nativeWorkflow();
 validateWorkflow(v,[...Object.keys(registry),'template'],catalog.tools);
 assert.equal(v.nodes[0].data.kind,'native_scope');
 assert.equal(v.nodes.at(-1).data.kind,'native_summary');
 const modified=structuredClone(v);modified.nodes[1].data.inputs=['anything'];
 assert.throws(()=>validateWorkflow(modified,Object.keys(registry),catalog.tools),/contract/);
 const mismatch=structuredClone(v);mismatch.edges[1].source=mismatch.nodes[0].id;
 // HTTP supports targets directly, but summary does not.
 mismatch.edges[2].source=mismatch.nodes[0].id;
 assert.throws(()=>validateWorkflow(mismatch,Object.keys(registry),catalog.tools),/port/);
});
