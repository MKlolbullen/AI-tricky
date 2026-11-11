"""Local, bounded workflows for the reviewed Trickest open-source adapters."""

from pathlib import Path
import re
from urllib.parse import urlsplit

from .scope import ScopeError, authorize, parse_target

GENERATORS = {'mksub', 'mkpath'}
MAX_WORDS = 32
MAX_WORD_BYTES = 4096
DNS_LABEL = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?')
PATH_SEGMENT = re.compile(r'[A-Za-z0-9._~-]{1,64}')


def validate_wordlist(tool, path):
    with Path(path).open('rb') as wordlist:
        raw = wordlist.read(MAX_WORD_BYTES + 1)
    if len(raw) > MAX_WORD_BYTES:
        raise ScopeError('Use a Trickest generator wordlist of at most 4 KiB.')
    try:
        words = [line.strip() for line in raw.decode('ascii').splitlines() if line.strip()]
    except UnicodeError:
        raise ScopeError('Use an ASCII wordlist for the Trickest generator.') from None
    words = list(dict.fromkeys(words))
    if not 1 <= len(words) <= MAX_WORDS:
        raise ScopeError('Use a Trickest generator wordlist with 1–32 distinct entries.')
    for word in words:
        if tool == 'mksub':
            valid = DNS_LABEL.fullmatch(word)
        else:
            parts = word.rstrip('/').split('/')
            valid = len(word) <= 96 and all(part not in ('.', '..') and PATH_SEGMENT.fullmatch(part)
                                             for part in parts)
        if not valid:
            raise ScopeError('Wordlist entries must be DNS labels for mksub or safe relative paths for mkpath.')
    return words


def prepare_generator(tool, context, values, config, work):
    if len(values) != 1 or not context.get('wordlist_file'):
        raise ScopeError('Bind one seed and a wordlist for each Trickest generator invocation.')
    words = validate_wordlist(tool, context['wordlist_file'])
    # Write the bounded wordlist into this run's work directory explicitly, never
    # beside the (already copied) input, so the registered-inputs area is never
    # written and concurrent runs cannot share or clobber the bounded file.
    path = Path(work) / 'bounded-trickest-wordlist.txt'
    path.write_text('\n'.join(words) + '\n', encoding='ascii')
    context['wordlist_file'] = str(path)
    scopes = [parse_target(value) for value in config['targets']]
    if tool == 'mksub':
        seed = parse_target(values[0])
        if seed.kind != 'domain' or not any(
            item.kind in ('domain', 'wildcard') and
            (seed.host == item.host or seed.host.endswith('.' + item.host)) for item in scopes
        ):
            raise ScopeError('mksub requires a domain seed from the selected domain or wildcard scope.')
        context['domain'] = seed.host
        return [seed.host]

    seed = authorize(values[0], scopes)
    if urlsplit(seed.url).query or len(seed.url) > 512:
        raise ScopeError('mkpath needs a base URL of at most 512 characters without a query string.')
    context['targets'] = seed.url.rstrip('/')
    return [context['targets']]


def candidate_output(tool, streams, seed, config):
    # Candidate generation only: for mksub these are subdomains of the entered
    # seed, which may fall outside an exact-host scope entry (they are in scope
    # only under a wildcard). They are never probed here — active tools
    # re-authorise every value before any traffic. See the candidate-boundary
    # test, which asserts exact-host scope rejects them and wildcard accepts them.
    output = 'targets' if tool == 'mksub' else 'url'
    candidates = []
    scopes = [parse_target(value) for value in config['targets']]
    base = urlsplit(seed)
    for value in streams[output]:
        try:
            if tool == 'mksub':
                target = parse_target(value)
                if target.kind == 'domain' and target.host.endswith('.' + seed):
                    candidates.append(target.host)
            else:
                target = authorize(value, scopes)
                parsed = urlsplit(target.url)
                if (parsed.scheme, parsed.netloc) == (base.scheme, base.netloc) and not parsed.query:
                    prefix = base.path.rstrip('/') + '/'
                    if parsed.path.startswith(prefix) and parsed.path != prefix:
                        candidates.append(target.url)
        except ScopeError:
            continue
    return {output: sorted(set(candidates))}


def workflow(identifier):
    from .catalog import TOOLS, TRICKEST_CATALOG, OUTPUT_INPUTS
    from .web_recon import recon_workflow
    from .workflows import SCHEMA, validate_workflow

    if identifier not in {item['id'] for item in TRICKEST_CATALOG['workflows']}:
        raise KeyError(identifier)
    if identifier == 'trickest-local-recon':
        return recon_workflow(scan=True)

    tool, source = ('mksub', 'domain') if identifier == 'trickest-subdomain-candidates' else ('mkpath', 'url')
    spec = TOOLS[tool]
    output = spec['outputs'][0]
    nodes = []
    for name, kind, title, inputs, outputs, fields in (
        ('seed', 'catalog_source', 'Selected ' + source, [], [source], {'sourceType': source, 'value': ''}),
        ('generate', 'catalog_tool', spec['name'], spec['inputs'], spec['outputs'], {'toolId': tool}),
        ('report', 'catalog_output', 'Generated candidates', list(OUTPUT_INPUTS), ['report'], {}),
    ):
        nodes.append({'id': name, 'type': 'tool', 'position': {'x': len(nodes) * 260, 'y': 100},
                      'data': {'kind': kind, 'title': title, 'inputs': inputs, 'outputs': outputs,
                               'output': outputs[0], 'timeout': 30, 'retries': 0, **fields}})
    edges = [
        {'id': f'{start}-{end}', 'source': start, 'target': end, 'type': 'smoothstep',
         'sourceHandle': 'out:' + typ, 'targetHandle': 'in:' + port, 'label': typ}
        for start, end, typ, port in (('seed', 'generate', source, source),
                                      ('generate', 'report', output, output))
    ]
    graph = {'schema': SCHEMA, 'nodes': nodes, 'edges': edges, 'parallelism': 2}
    validate_workflow(graph, live=True)
    return graph
