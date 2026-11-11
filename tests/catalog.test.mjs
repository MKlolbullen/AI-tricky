import test from 'node:test';
import assert from 'node:assert/strict';
import {migrated,catalogKinds,catalogNode,catalogSource} from '../src/catalog-contracts.mjs';
import {validateWorkflow,WORKFLOW_SCHEMA} from '../src/workflow-validation.mjs';

test('all 151 migrated tool descriptors and 57 workflows have valid socket contracts',()=>{
 assert.equal(migrated.tools.length,151);assert.equal(migrated.workflows.length,57);
 assert.equal(new Set(migrated.tools.map(t=>t.id)).size,151);
 for(const w of migrated.workflows)validateWorkflow(w,catalogKinds,[]);
 for(const t of migrated.tools){const n=catalogNode('tool',t);validateWorkflow({schema:WORKFLOW_SCHEMA,nodes:[n],edges:[]},catalogKinds,[])}
});
test('multi-output connections bind the selected socket rather than the primary alias',()=>{
 const t=migrated.tools.find(t=>t.id==='httpx'),a=catalogNode('httpx',t),b=catalogSource('out','catalog_output');
 const workflow={schema:WORKFLOW_SCHEMA,nodes:[a,b],edges:[{id:'e1',source:a.id,target:b.id,sourceHandle:'out:url',targetHandle:'in:url'}]};
 validateWorkflow(workflow,catalogKinds,[]);
 workflow.edges[0].sourceHandle='out:invented';
 assert.throws(()=>validateWorkflow(workflow,catalogKinds,[]),/socket/);
});
test('modified migrated tool input/output contracts are rejected',()=>{
 const n=catalogNode('tool',migrated.tools[0]);n.data.outputs=['arbitrary'];
 assert.throws(()=>validateWorkflow({schema:WORKFLOW_SCHEMA,nodes:[n],edges:[]},catalogKinds,[]),/contract/);
});
test('payload and merge sources keep canonical output types',()=>{
 for(const kind of ['catalog_source','catalog_payload','catalog_merge','catalog_output'])validateWorkflow({schema:WORKFLOW_SCHEMA,nodes:[catalogSource('node',kind)],edges:[]},catalogKinds,[]);
});
