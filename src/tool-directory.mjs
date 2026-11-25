import {migrated, trickest} from './catalog-contracts.mjs';
import curated from './templates.json' with {type: 'json'};
import identity from './identity-tools.json' with {type: 'json'};
import overlay from './tool-argument-overlay.json' with {type: 'json'};

function catalogRecord(t) {
  const extra = overlay.tools[t.id];
  const count = t.args.length + (extra?.args.length || 0);
  return {
    id: t.id, name: t.name, group: t.sourceCatalog, category: t.category,
    description: t.description, provenance: t.provenance, inputs: t.inputs, outputs: t.outputs,
    kind: t.adapter.reason ? 'Context restricted' : 'CLI adapter',
    argumentCount: count, version: extra?.version,
    coverage: extra ? 'Pinned help checked' : count ? 'Imported arguments' : 'No declared overrides',
  };
}

function identityRecord(t) {
  return {
    id: t.id, name: t.name, group: 'Identity', category: t.platform.toUpperCase(),
    description: t.description, provenance: t.source, inputs: null, outputs: null,
    kind: t.mode === 'collection' ? 'Collection profile' : 'External reference', coverage: 'No CLI argument schema',
  };
}

export const directory = [
  ...[...migrated.tools, ...trickest.tools].map(catalogRecord),
  ...curated.tools.map(t => ({
    id: t.id, name: t.name, group: 'Legacy design', category: t.category,
    description: t.description, provenance: t.provenance, inputs: t.inputs, outputs: [t.output],
    kind: 'Design preview', coverage: 'No CLI argument schema',
  })),
  ...[...identity.profiles, ...identity.references].map(identityRecord),
].map(t => ({...t, key: t.group + '/' + t.id})).sort((a, b) => a.name.localeCompare(b.name) || a.key.localeCompare(b.key));

export function searchDirectory(query, coverage = '') {
  const terms = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  return directory.filter(t => {
    if (coverage && t.coverage !== coverage) return false;
    const text = [t.id, t.name, t.group, t.category, t.kind, ...(t.inputs || []), ...(t.outputs || [])].join(' ').toLowerCase();
    return terms.every(term => text.includes(term));
  });
}
