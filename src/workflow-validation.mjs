import {isCatalog,catalogContract,catalogKinds} from './catalog-contracts.mjs';
import nativeRegistry from './native-registry.json' with {type:'json'};
import {resolveConnection} from './workflow-sockets.mjs';
export const WORKFLOW_SCHEMA='offsecs-u-ai.workflow/v1';
export function validateWorkflow(v,knownKinds,templates){
 if(![WORKFLOW_SCHEMA,'reconforge.prototype.workflow/v1'].includes(v?.schema)||!Array.isArray(v.nodes)||!Array.isArray(v.edges)||v.nodes.length>500||v.edges.length>2000)throw Error('Invalid workflow format or size');
 const ids=new Set();
 for(const n of v.nodes){
  if(typeof n.id!=='string'||!n.id||ids.has(n.id)||!Number.isFinite(n.position?.x)||!Number.isFinite(n.position?.y)||n.type!=='tool'||!knownKinds.includes(n.data?.kind)&&!catalogKinds.includes(n.data?.kind))throw Error('Invalid or duplicate node');
  if(['title','description','output','result','status','backend','domain'].some(k=>n.data[k]!==undefined&&typeof n.data[k]!=='string'))throw Error('Invalid node data');
  if(n.data.kind==='template'&&!templates.some(t=>t.id===n.data.templateId&&t.output===n.data.output&&JSON.stringify(t.inputs)===JSON.stringify(n.data.inputs)))throw Error('Unknown or modified tool descriptor');
  if(nativeRegistry[n.data.kind]){const spec=nativeRegistry[n.data.kind];if(n.data.output!==spec.output||JSON.stringify(n.data.inputs)!==JSON.stringify(spec.inputs))throw Error('Modified native adapter contract');}
  if(isCatalog(n.data)){const c=catalogContract(n.data);if(JSON.stringify(n.data.inputs)!==JSON.stringify(c.inputs)||JSON.stringify(n.data.outputs)!==JSON.stringify(c.outputs)||n.data.output!==c.outputs[0])throw Error('Modified catalog socket contract');}
  ids.add(n.id);
 }
 const graph=new Map(v.nodes.map(n=>[n.id,[]])),edgeIds=new Set();
 const byId=new Map(v.nodes.map(n=>[n.id,n.data]));
 for(const e of v.edges){if(typeof e.id!=='string'||(e.label!==undefined&&typeof e.label!=='string'))throw Error('Invalid edge data');if(!ids.has(e.source)||!ids.has(e.target)||e.source===e.target||edgeIds.has(e.id))throw Error('Invalid edge');edgeIds.add(e.id);graph.get(e.source).push(e.target);
  resolveConnection(e,byId.get(e.source),byId.get(e.target));
 }
 const visited=new Set(),active=new Set();function visit(id){if(active.has(id))throw Error('Workflow contains a cycle');if(visited.has(id))return;active.add(id);graph.get(id).forEach(visit);active.delete(id);visited.add(id)}
 ids.forEach(visit);return v;
}
