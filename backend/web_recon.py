"""Bounded, discovery-led source collection. No JS execution or guessed paths."""
import json
import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from .scope import ScopeError, authorize

ASSET_EXTENSIONS = {'.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.map', '.chunk', '.webchunk',
                    '.css', '.json', '.webmanifest', '.manifest', '.graphql', '.gql', '.txt', '.xml', '.yaml', '.yml'}
DEFAULT_LIMITS = {'max_pages': 10, 'max_assets': 40, 'max_depth': 2}
LIMIT_CEILINGS = {'max_pages': 50, 'max_assets': 200, 'max_depth': 5}
MAX_REFERENCES = 1000
MAX_TEXT = 131072
QUOTED_ASSET = re.compile(r'''["']([^\s"'<>`]{1,2048}\.(?:m?js|cjs|jsx|tsx?|map|chunk|webchunk|css|json|webmanifest|manifest|graphql|gql|txt|xml|ya?ml)(?:\?[^\s"'<>`]{0,1024})?)["']''', re.I)
SOURCE_MAP = re.compile(r'[#@]\s*sourceMappingURL\s*=\s*([^\s*]{1,4096})')


def limits(data):
    result = {}
    for key, default in DEFAULT_LIMITS.items():
        value = data.get(key, default)
        if type(value) is not int or not 0 <= value <= LIMIT_CEILINGS[key]:
            raise ScopeError(f'{key} must be a whole number from 0 to {LIMIT_CEILINGS[key]}.')
        result[key] = value
    return result


def asset_kind(url):
    path = urlsplit(url).path.lower()
    ext = '.' + path.rsplit('.', 1)[-1] if '.' in path.rsplit('/', 1)[-1] else ''
    return ext[1:] if ext in ASSET_EXTENSIONS else None


def crawler_scope(config):
    """Best-effort RE2 URL boundaries for Katana, in addition to native checks."""
    from .scope import parse_target, network_hosts
    scopes = [parse_target(t) for t in config['targets']]
    patterns = []
    for target in scopes:
        if target.kind == 'url':
            host = '[' + target.host + ']' if ':' in target.host else target.host
            port = f'(?::{target.port})?' if target.port == (443 if target.scheme == 'https' else 80) else f':{target.port}'
            patterns.append('^' + re.escape(target.scheme + '://' + host) + port +
                            re.escape(target.path.rstrip('/')) + r'(?:/|\?|$)')
        else:
            hosts = [target.host] if target.kind == 'wildcard' else network_hosts(target.url, scopes, config['max_hosts'])
            for host in hosts:
                host = '[' + host + ']' if ':' in host else host
                prefix = r'(?:[a-zA-Z0-9-]+\.)+' if target.kind == 'wildcard' else ''
                patterns.append(r'^https?://' + prefix + re.escape(host) + r'(?::[0-9]{1,5})?(?:/|\?|$)')
    return patterns


class References(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.refs = []
        self.base = None

    def handle_starttag(self, tag, attrs):
        if len(self.refs) >= MAX_REFERENCES:
            return
        attrs = dict(attrs)
        if tag == 'base' and self.base is None:
            self.base = attrs.get('href')
        if tag in ('script', 'iframe') and attrs.get('src'):
            self.refs.append((attrs['src'], 'script' if tag == 'script' else 'page'))
        if tag in ('a', 'link') and attrs.get('href'):
            role = 'asset' if tag == 'link' and (set(attrs.get('rel', '').lower().split()) &
                    {'stylesheet', 'modulepreload', 'manifest'} or attrs.get('as') in ('script', 'style')) else 'page'
            self.refs.append((attrs['href'], role))


def references(body, url, content_type=''):
    body = body[:MAX_TEXT]
    refs = []
    base = url
    is_html = 'text/html' in content_type.lower() or (not asset_kind(url) and body.lstrip().startswith('<'))
    parser = References()
    if is_html:
        parser.feed(body)
        refs.extend(parser.refs)
        if parser.base:
            base = urljoin(url, parser.base)
    # Static bundler chunk names, imports and source-map directives. This never
    # evaluates code. Bare package imports without a file extension are ignored.
    refs.extend((m.group(1), 'asset') for m in QUOTED_ASSET.finditer(body))
    refs.extend((m.group(1), 'source_map') for m in SOURCE_MAP.finditer(body))
    return [(urldefrag(urljoin(base, value))[0], role) for value, role in refs[:MAX_REFERENCES]]


async def collect_assets(values, config, data, fetch, store, node_id):
    from .scope import parse_target
    bounds = limits(data)
    scopes = [parse_target(t) for t in config['targets']]
    queue, seen, manifest, captures = deque(), set(), [], {}
    counts = {'pages': 0, 'assets': 0, 'out_of_scope': 0, 'unsupported': 0, 'depth_limited': 0,
              'page_limited': 0, 'asset_limited': 0, 'reference_limited': 0, 'truncated': 0, 'errors': 0}

    def enqueue(url, source=None, role='seed', depth=0):
        if not isinstance(url, str) or len(url) > 4096:
            counts['unsupported'] += 1
            return
        url = urldefrag(url)[0]
        try:
            url = authorize(url, scopes).url
        except ScopeError:
            counts['out_of_scope'] += 1
            return
        if url in seen:
            return
        if len(seen) >= MAX_REFERENCES:
            counts['reference_limited'] += 1
            return
        seen.add(url)
        queue.append((url, source, role, depth))

    for row in values:
        packet = row.get('catalog_streams', {})
        for url in packet.get('url', []) + packet.get('targets', []):
            enqueue(url)
        if row.get('url'):
            enqueue(row['url'])
            # Only parent-owned immutable capture IDs are re-read. Upstream
            # target data cannot supply a storage pathname.
            if row.get('artifact_id'):
                capture = store.content(row['artifact_id'])
                if isinstance(capture, dict) and capture.get('url') == row['url']:
                    captures[row['url']] = {**capture, 'artifact_id': row['artifact_id']}

    while queue:
        url, source, role, depth = queue.popleft()
        kind = asset_kind(url)
        is_asset = bool(kind or role in ('script', 'asset', 'source_map'))
        counter = 'assets' if is_asset else 'pages'
        if depth > bounds['max_depth']:
            counts['depth_limited'] += 1
            continue
        if counts[counter] >= bounds['max_' + counter]:
            counts['asset_limited' if is_asset else 'page_limited'] += 1
            continue
        counts[counter] += 1
        response = captures.get(url) or await fetch(url, node_id=node_id)
        # fetch() returns a model-sized body preview. Parse the full bounded
        # capture so references after 16 KB are not silently missed.
        if response.get('artifact_id'):
            capture = store.content(response['artifact_id'])
            if isinstance(capture, dict) and capture.get('url') == url:
                response = {**capture, 'artifact_id': response['artifact_id']}
        item = {'url': url, 'kind': kind or ('script' if is_asset else 'page'), 'discovered_from': source,
                'reference': role, 'depth': depth, 'artifact_id': response.get('artifact_id'),
                'status': response.get('status'), 'body_sha256': response.get('body_sha256'),
                'body_bytes': response.get('body_bytes'), 'truncated': bool(response.get('truncated'))}
        manifest.append(item)
        if response.get('error'):
            item['error'] = response['error']
            counts['errors'] += 1
            # Budgets are shared with upstream nodes and every queued GET.
            if response['error'] in ('Run request budget exhausted.', 'HTTP access disabled. Produce a plan only.'):
                counts['not_attempted'] = len(queue)
                break
            continue
        if response.get('truncated'):
            counts['truncated'] += 1
        if not 200 <= response.get('status', 0) < 300:
            continue  # never follow Location, even if its host is allowed
        body = response.get('body', '')[:MAX_TEXT]
        if kind == 'map':
            try:
                sourcemap = json.loads(body)
                if isinstance(sourcemap, dict) and isinstance(sourcemap.get('sources'), list):
                    item['map_sources'] = [s[:2048] for s in sourcemap['sources'][:200] if isinstance(s, str)]
                    item['map_sources_content'] = isinstance(sourcemap.get('sourcesContent'), list)
            except (ValueError, TypeError):
                item['map_parse_incomplete'] = True
            continue  # sources can be local/webpack paths; do not request them
        refs = references(body, url, response.get('headers', {}).get('content-type', ''))
        if len(refs) >= MAX_REFERENCES:
            counts['reference_limited'] += 1
        for child, child_role in refs:
            enqueue(child, url, child_role, depth + 1)

    coverage = ['Discovery-led collection only; dynamic imports, runtime-generated URLs and unlinked files may be absent.',
                'No JavaScript execution, redirects, authentication or guessed file paths. Captures are bounded to 128 KiB each.',
                'Native HTTP admissions share the run budget; upstream CLI internal traffic uses separate accounting.']
    return [{'report': f'Collected {len(manifest)} web source/page records; {counts["errors"]} request errors. See the manifest and linked HTTP captures.',
             'manifest': manifest, 'counts': counts, 'limits': bounds, 'coverage_limits': coverage,
             'evidence_status': 'OBSERVATION'}]


def recon_workflow(*, fuzz=False, scan=False, review=False, surface=False):
    """Independent curated starter; leaves the pinned migration catalog intact."""
    from .catalog import TOOLS
    from .workflows import REGISTRY, SCHEMA, validate_workflow
    nodes, edges = [], []

    def node(nid, kind, x, y, **data):
        if kind == 'catalog_tool':
            spec = TOOLS[data['toolId']]
            data = {'inputs': spec['inputs'], 'outputs': spec['outputs'], 'output': spec['outputs'][0],
                    'title': spec['id'], **data}
        elif kind in REGISTRY:
            spec = REGISTRY[kind]
            data = {'inputs': spec['inputs'], 'output': spec['output'], 'title': spec['name'], **data}
        nodes.append({'id': nid, 'type': 'tool', 'position': {'x': x, 'y': y},
                      'data': {'kind': kind, 'timeout': 120, 'retries': 0, **data}})

    def edge(src, dst, typ, incoming=None):
        edges.append({'id': f'{src}-{dst}', 'source': src, 'target': dst, 'type': 'smoothstep',
                      'sourceHandle': 'out:' + typ, 'targetHandle': 'in:' + (incoming or typ), 'label': typ})

    node('domains', 'catalog_source', 0, 100, sourceType='domain', inputs=[], outputs=['domain'], output='domain',
         title='Selected enumeration domains', value='')
    for nid, y in [('subfinder', 0), ('assetfinder', 200)]:
        node(nid, 'catalog_tool', 230, y, toolId=nid)
        edge('domains', nid, 'domain')
    node('hosts', 'catalog_merge', 460, 100, inputs=['any'], outputs=['targets'], output='targets', title='Unique discovered hosts')
    # Include an explicitly authorized apex even when --subs-only finds none.
    # A wildcard-only apex seed is filtered out before active probing.
    edge('domains', 'hosts', 'domain', 'any')
    edge('subfinder', 'hosts', 'targets', 'any'); edge('assetfinder', 'hosts', 'targets', 'any')
    node('probe', 'catalog_tool', 690, 100, toolId='httprobe'); edge('hosts', 'probe', 'targets')
    node('crawl', 'catalog_tool', 920, 0, toolId='katana', params={'-jc': True}); edge('probe', 'crawl', 'url')
    node('urls', 'catalog_merge', 1150, 100, inputs=['any'], outputs=['url'], output='url', title='Unique probe and crawl URLs')
    edge('probe', 'urls', 'url', 'any'); edge('crawl', 'urls', 'url', 'any')
    node('sources', 'native_web_assets', 1610 if review else 1380, 100)
    node('summary', 'native_summary', 1840 if review else 1610, 100)
    edge('sources', 'summary', 'report')
    if surface:
        node('api-surface', 'native_api_surface', 1840 if review else 1610, 310)
        edge('sources', 'api-surface', 'report')
    if review:
        node('capture', 'native_http', 1380, 100)
        edge('urls', 'capture', 'url')
        edge('capture', 'sources', 'observations')
        node('review', 'native_team', 1610, -120, team_profile='specialist')
        edge('capture', 'review', 'observations')
        edge('review', 'summary', 'report')
    else:
        edge('urls', 'sources', 'url')
    if scan:
        node('scan', 'catalog_tool', 920, 560, toolId='nuclei', title='Nuclei — reviewed HTTP templates')
        edge('probe', 'scan', 'url')
        node('scan-results', 'catalog_output', 1380, 560, inputs=['any'], outputs=['report'],
             output='report', title='Nuclei detections')
        edge('scan', 'scan-results', 'findings', 'any')
        edge('scan-results', 'summary', 'report')
    if fuzz:
        node('fuzz-urls', 'catalog_merge', 920, 320, inputs=['any'], outputs=['targets'], output='targets', title='Probed URLs for directory fuzzing')
        edge('probe', 'fuzz-urls', 'url', 'any')
        node('fuzz', 'catalog_tool', 1150, 320, toolId='ffuf', title='Optional path fuzzing — bind a wordlist')
        edge('fuzz-urls', 'fuzz', 'targets')
        node('fuzz-results', 'catalog_output', 1380, 320, inputs=['any'], outputs=['report'], output='report', title='Fuzzing observations')
        edge('fuzz', 'fuzz-results', 'findings', 'any'); edge('fuzz-results', 'summary', 'report')
    graph = {'schema': SCHEMA, 'nodes': nodes, 'edges': edges, 'parallelism': 3}
    validate_workflow(graph, live=True)
    return graph
