import migrated from './mini-tricky-catalog.json' with {type:'json'};
export {migrated};
export const catalogKinds=['catalog_tool','catalog_source','catalog_merge','catalog_output','catalog_payload'];
export const catalogTools=new Map(migrated.tools.map(t=>[t.id,t]));
export const isCatalog=data=>catalogKinds.includes(data?.kind);
export function catalogContract(data){
 if(data.kind==='catalog_tool'){const t=catalogTools.get(data.toolId);if(!t)throw Error('Unknown migrated tool');return {inputs:t.inputs,outputs:t.outputs}}
 if(data.kind==='catalog_source'){if(!['domain','targets','url','folder','file','wordlist','query','sbom'].includes(data.sourceType))throw Error('Unknown source type');return {inputs:[],outputs:[data.sourceType]}}
 if(data.kind==='catalog_merge')return {inputs:['any'],outputs:[data.output]};
 if(data.kind==='catalog_output')return {inputs:['any'],outputs:['report']};
 if(data.kind==='catalog_payload')return {inputs:[],outputs:['wordlist']};
 throw Error('Unknown catalog kind');
}
export function catalogNode(id,tool,position={x:0,y:0}){
 return {id,type:'tool',position,data:{kind:'catalog_tool',toolId:tool.id,title:tool.name,description:tool.category,inputs:tool.inputs,outputs:tool.outputs,output:tool.outputs[0],params:{},timeout:Math.min(tool.timeout_seconds||300,3600),retries:0,status:'pending',result:'Preflight required'}};
}
export function catalogSource(id,kind='catalog_source',position={x:0,y:0}){
 const data={kind,title:kind==='catalog_source'?'Scope / input source':kind==='catalog_merge'?'Merge & dedupe':kind==='catalog_payload'?'Payload set':'Collect artifacts',sourceType:'domain',value:'',output:kind==='catalog_source'?'domain':kind==='catalog_merge'?'targets':kind==='catalog_payload'?'wordlist':'report',params:kind==='catalog_payload'?{payload_types:'XSS',encodings:'raw'}:{},timeout:120,retries:0,status:'pending',result:'Not run'};
 const contract=catalogContract(data);return {id,type:'tool',position,data:{...data,...contract}};
}
