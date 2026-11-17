import {catalogContract, isCatalog} from './catalog-contracts.mjs';
import nativeRegistry from './native-registry.json' with {type:'json'};

const legacyInputs = {
  domain: [], file: [], subfinder: ['domain'], assetfinder: ['domain'],
  dnsx: ['domain_list'], httpx: ['domain_list'], merge: ['domain_list'],
  agent: ['url_list'], burp: ['findings'],
};

export function nodeSockets(data) {
  if (isCatalog(data)) return catalogContract(data);
  const native = nativeRegistry[data.kind];
  if (native) return {inputs: native.inputs, outputs: [native.output]};
  return {inputs: data.kind === 'template' ? data.inputs : legacyInputs[data.kind] || [], outputs: [data.output]};
}

export function resolveConnection(edge, source, target) {
  const {outputs} = nodeSockets(source);
  const {inputs} = nodeSockets(target);
  if (edge.sourceHandle != null && (typeof edge.sourceHandle !== 'string' || !edge.sourceHandle.startsWith('out:'))) {
    throw Error('Invalid source socket');
  }
  if (edge.targetHandle != null && (typeof edge.targetHandle !== 'string' || !edge.targetHandle.startsWith('in:'))) {
    throw Error('Invalid target socket');
  }
  const output = edge.sourceHandle?.slice(4) ?? outputs[0];
  let input = edge.targetHandle?.slice(3) ?? output;
  if (input === output && !inputs.includes(input) && inputs.includes('any')) input = 'any';
  if (!outputs.includes(output)) throw Error('Unknown source socket');
  if (!inputs.includes(input) || (input !== output && input !== 'any')) throw Error('Incompatible port types');
  return {sourceHandle: `out:${output}`, targetHandle: `in:${input}`};
}

export function namedEdges(nodes, edges) {
  const byId = new Map(nodes.map(node => [node.id, node.data]));
  const routes = new Set();
  const ids = new Set(edges.map(edge => edge.id));
  let number = 1;
  return edges.flatMap(edge => {
    const handles = resolveConnection(edge, byId.get(edge.source), byId.get(edge.target));
    const route = JSON.stringify([edge.source, edge.target, handles.sourceHandle, handles.targetHandle]);
    if (routes.has(route)) return [];
    routes.add(route);
    let id = edge.id;
    const oldId = `xy-edge__${edge.source}${edge.sourceHandle || ''}-${edge.target}${edge.targetHandle || ''}`;
    if (id === oldId) {
      while (ids.has(`edge-${number}`)) number++;
      id = `edge-${number++}`;
    }
    return [{...edge, ...handles, id}];
  });
}
