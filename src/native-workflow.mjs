import registry from './native-registry.json' with {type:'json'};
import {WORKFLOW_SCHEMA} from './workflow-validation.mjs';
export {registry};
export function nativeNode(id,kind,position={x:0,y:0}){
 const spec=registry[kind];
 return {id,type:'tool',position,data:{kind,title:spec.name,description:spec.description,inputs:spec.inputs,output:spec.output,status:'pending',result:'Ready for local execution',timeout:120,retries:0}};
}
export function nativeWorkflow(){
 const kinds=['native_scope','native_tcp','native_http','native_summary'];
 const nodes=kinds.map((kind,i)=>nativeNode(`native-${i+1}`,kind,{x:i*230,y:130}));
 return {schema:WORKFLOW_SCHEMA,nodes,edges:nodes.slice(1).map((n,i)=>({id:`edge-${i+1}`,source:nodes[i].id,target:n.id,label:nodes[i].data.output,type:'smoothstep'})),parallelism:4};
}
