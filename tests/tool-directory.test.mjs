import test from 'node:test';
import assert from 'node:assert/strict';
import {directory, searchDirectory} from '../src/tool-directory.mjs';
import {catalogNode, catalogTools, catalogSource} from '../src/catalog-contracts.mjs';
import {namedEdges, nodeSockets, resolveConnection} from '../src/workflow-sockets.mjs';
import overlay from '../src/tool-argument-overlay.json' with {type: 'json'};
import curated from '../src/templates.json' with {type: 'json'};
import identity from '../src/identity-tools.json' with {type: 'json'};

test('directory includes each source record once, including overlapping legacy IDs', () => {
  assert.equal(directory.length, catalogTools.size + curated.tools.length + identity.profiles.length + identity.references.length);
  assert.equal(new Set(directory.map(t => t.key)).size, directory.length);
  assert.ok(searchDirectory('httpx').some(t => t.group === 'Legacy design'));
  assert.ok(searchDirectory('httpx').some(t => t.group === 'mini-tricky'));
  assert.equal(searchDirectory(' jq-filter  Utility ').length, 1);
  assert.deepEqual(searchDirectory('', 'Pinned help checked').map(t => t.id).sort(), Object.keys(overlay.tools).sort());
});

test('each catalog record accounts for typed arguments, corrections and actual canvas sockets', () => {
  const knownTypes = ['flag', 'int', 'float', 'string'];
  for (const t of catalogTools.values()) {
    const record = directory.find(row => row.key === t.sourceCatalog + '/' + t.id);
    const extra = overlay.tools[t.id];
    const args = [...t.args, ...(extra?.args || [])];
    assert.equal(record.argumentCount, args.length, t.id);
    assert.equal(new Set(args.map(arg => arg.flag)).size, args.length, t.id);
    const corrected = new Map((extra?.corrections || []).map(arg => [arg.flag, arg]));
    for (const base of args) {
      const arg = {...base, ...corrected.get(base.flag)};
      assert.ok(arg.flag.trim() && arg.label.trim() && arg.description.trim() && knownTypes.includes(arg.type), t.id);
    }
    const sockets = nodeSockets(catalogNode('tool', t).data);
    assert.deepEqual({inputs: record.inputs, outputs: record.outputs}, sockets);
    for (const ports of Object.values(sockets)) {
      assert.equal(new Set(ports).size, ports.length, t.id);
      assert.ok(ports.every(port => typeof port === 'string' && port.trim()), t.id);
    }
  }
});

test('artifact collector accepts its declared file socket and rejects a mismatched or missing endpoint', () => {
  const source = catalogSource('file');
  source.data.sourceType = 'file';
  const sink = catalogSource('sink', 'catalog_output');
  const edge = {id: 'edge', source: source.id, target: sink.id, sourceHandle: 'out:file', targetHandle: 'in:file'};
  assert.deepEqual(namedEdges([source, sink], [edge]), [edge]);
  assert.throws(() => resolveConnection({...edge, targetHandle: 'in:url'}, source.data, sink.data), /Incompatible/);
  assert.throws(() => namedEdges([source], [edge]), /missing node/);
});
