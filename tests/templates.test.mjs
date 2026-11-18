import test from 'node:test';
import assert from 'node:assert/strict';
import {validateWorkflow,WORKFLOW_SCHEMA} from '../src/workflow-validation.mjs';
import {migrated,catalogKinds,isExecutableTemplate} from '../src/catalog-contracts.mjs';
import curated from '../src/templates.json' with {type:'json'};
const graph=()=>structuredClone({schema:WORKFLOW_SCHEMA,...migrated.workflows.find(t=>t.id==='tpl-full-recon')});
test('every template graph has known tools, compatible ports, unique IDs and no cycles',()=>{
 assert.equal(new Set(migrated.tools.map(t=>t.id)).size,migrated.tools.length);
 assert.equal(new Set(migrated.workflows.map(t=>t.id)).size,migrated.workflows.length);
 for(const w of migrated.workflows)validateWorkflow({schema:WORKFLOW_SCHEMA,...w},catalogKinds,[]);
});
test('reject dangling edges, mismatched descriptors, duplicate IDs and cycles',()=>{
 let v=graph();v.edges[0].target='missing';assert.throws(()=>validateWorkflow(v,catalogKinds,[]));
 v=graph();v.nodes[1].data.output='findings';assert.throws(()=>validateWorkflow(v,catalogKinds,[]));
 v=graph();v.nodes[1].id=v.nodes[0].id;assert.throws(()=>validateWorkflow(v,catalogKinds,[]));
 v=graph();v.edges.push({id:'cycle',source:v.nodes[3].id,target:v.nodes[2].id,sourceHandle:'out:targets',targetHandle:'in:targets'});assert.throws(()=>validateWorkflow(v,catalogKinds,[]));
 v=graph();v.edges[0].target=v.nodes[5].id;v.edges[0].targetHandle='in:findings';assert.throws(()=>validateWorkflow(v,catalogKinds,[]));
});
test('legacy exports are accepted and arbitrary binary nodes are rejected',()=>{
 const v={schema:'reconforge.prototype.workflow/v1',nodes:[{id:'01',type:'tool',position:{x:0,y:0},data:{kind:'domain'}}],edges:[]};
 assert.equal(validateWorkflow(v,['domain'],[]),v);
 v.nodes[0].data.kind='shell';assert.throws(()=>validateWorkflow(v,['domain'],[]));
});

import {nativeWorkflow,nativeNode,registry} from '../src/native-workflow.mjs';
test('native starter imports with canonical typed adapter contracts',()=>{
 const v=nativeWorkflow();
 validateWorkflow(v,Object.keys(registry),[]);
 assert.equal(v.nodes[0].data.kind,'native_scope');
 assert.equal(v.nodes.at(-1).data.kind,'native_summary');
 const modified=structuredClone(v);modified.nodes[1].data.inputs=['anything'];
 assert.throws(()=>validateWorkflow(modified,Object.keys(registry),[]),/contract/);
 const mismatch=structuredClone(v);mismatch.edges[1].source=mismatch.nodes[0].id;
 // HTTP supports targets directly, but summary does not.
 mismatch.edges[2].source=mismatch.nodes[0].id;
 assert.throws(()=>validateWorkflow(mismatch,Object.keys(registry),[]),/port/);
});

test('curated catalog keeps its legacy designs and marks server-built starters',()=>{
 assert.ok(curated.tools.length>=53);assert.ok(curated.workflows.length>=23);
 assert.equal(new Set(curated.tools.map(t=>t.id)).size,curated.tools.length);
 assert.equal(new Set(curated.workflows.map(t=>t.id)).size,curated.workflows.length);
 for(const w of curated.workflows){
  for(const key of ['id','name','category','description','provenance'])assert.equal(typeof w[key],'string');
  assert.ok(Array.isArray(w.targets));
  if(w.starter){assert.equal(w.nodes,undefined);assert.ok(w.steps.length);assert.ok(isExecutableTemplate(w))}
  else{assert.ok(w.nodes.length||['inventory','cai'].includes(w.id),w.id);validateWorkflow({schema:WORKFLOW_SCHEMA,nodes:w.nodes,edges:w.edges},['template'],curated.tools);assert.ok(!isExecutableTemplate(w))}
 }
 assert.deepEqual(curated.workflows.filter(w=>w.starter).map(w=>w.starter),['web-app-assessment']);
});
