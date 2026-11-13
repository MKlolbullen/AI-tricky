"""Infer HTTP endpoints from saved source. Never execute code or send requests."""

import hashlib
import json
from pathlib import PurePosixPath
import re
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from tree_sitter import Language, Parser
import tree_sitter_javascript
import tree_sitter_typescript

from .scope import ScopeError, authorize, parse_target
from .web_recon import asset_kind

SCHEMA = 'ai-tricky.api-surface/v1'
SOURCE_TYPES = {'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'chunk', 'webchunk', 'script', 'map'}
METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'}
PARAM = re.compile(r'[A-Za-z0-9_$][A-Za-z0-9_.\[\]$-]{0,79}')
MAX_CAPTURES = 200
MAX_SOURCES = 200
MAX_BYTES = 2_000_000
MAX_ENDPOINTS = 500
MAX_LOCATIONS = 12
MAX_EXCHANGES = 5000
MAX_QUERY_BYTES = 2048
LANGUAGES = {
    'js': Language(tree_sitter_javascript.language()),
    'ts': Language(tree_sitter_typescript.language_typescript()),
    'tsx': Language(tree_sitter_typescript.language_tsx()),
}


def literal(node):
    if node is None or node.type not in ('string', 'template_string') or node.has_error:
        return None
    if any(child.type != 'string_fragment' for child in node.named_children):
        return None  # Escapes and interpolations require JS decoding/evaluation rules.
    return node.text[1:-1].decode('utf-8')


def object_fields(node):
    if node is None or node.type != 'object':
        return None
    fields = {}
    for child in node.named_children:
        if child.type == 'comment':
            continue
        if child.type == 'shorthand_property_identifier':
            fields[child.text.decode('utf-8')] = child
            continue
        if child.type != 'pair':
            return None  # Spreads or computed keys can override recognized options.
        key = child.child_by_field_name('key')
        name = literal(key) if key.type == 'string' else key.text.decode('utf-8') if key.type == 'property_identifier' else None
        if name is None:
            return None
        fields[name] = child.child_by_field_name('value')
    return fields


def request_call(node):
    callee = node.child_by_field_name('function')
    arguments = node.child_by_field_name('arguments')
    if callee is None or arguments is None or callee.type not in ('identifier', 'member_expression') or callee.end_byte - callee.start_byte > 30:
        return None
    name = re.sub(rb'\s+', b'', callee.text).decode('utf-8')
    args = [child for child in arguments.named_children if child.type != 'comment']
    if not args:
        return None
    method = 'GET'
    is_fetch = name in ('fetch', 'window.fetch', 'globalThis.fetch')
    is_axios = name in ('axios', 'axios.request') or name.startswith('axios.') and name[6:].upper() in METHODS
    if not (is_fetch or is_axios):
        return None
    url = args[0]
    if name == 'axios.request' or name == 'axios' and url.type == 'object':
        options = object_fields(url)
        url = options.get('url') if options is not None else None
    else:
        if is_axios and name != 'axios':
            method = name[6:].upper()
        option_index = 2 if is_axios and method in ('POST', 'PUT', 'PATCH') else 1
        options = object_fields(args[option_index]) if len(args) > option_index else {}
    value = literal(url)
    if not value or len(value) > 2048 or options is None:
        return None
    if 'method' in options and (is_fetch or name in ('axios', 'axios.request')):
        method = (literal(options['method']) or '').upper()
    if method not in METHODS:
        return None
    base = literal(options.get('baseURL')) if is_axios else None
    if is_axios and 'baseURL' in options and base is None:
        return None
    params = object_fields(options.get('params')) if is_axios else None
    return method, value, base, set(params or ()), 'fetch' if is_fetch else 'axios'


def call_sites(tree):
    cursor = tree.walk()
    while True:
        node = cursor.node
        if node.type == 'call_expression' and not node.has_error:
            call = request_call(node)
            if call is not None:
                yield node.start_point, call
        if cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return


def add_endpoint(endpoints, key, query, location, limits):
    if key not in endpoints and len(endpoints) >= MAX_ENDPOINTS:
        limits.add('endpoint limit')
        return
    method, url = key
    if key not in endpoints:
        endpoints[key] = {'id': hashlib.sha256(f'{method} {url}'.encode()).hexdigest(),
                          'method': method, 'url': url, 'parameters': set(), 'sources': [], 'traffic': []}
    endpoint = endpoints[key]
    names = endpoint['parameters'] | {name for name in query if PARAM.fullmatch(name)}
    endpoint['parameters'] = set(sorted(names)[:50])
    if len(names) > 50:
        limits.add('per-endpoint parameter limit')
    if location not in endpoint['sources']:
        if len(endpoint['sources']) < MAX_LOCATIONS:
            endpoint['sources'].append(location)
        else:
            limits.add('per-endpoint source limit')


def route_key(value, scopes):
    try:
        authorized = authorize(value, scopes)
        parsed = urlsplit(value)
    except (ScopeError, ValueError):
        return None
    query = {key for key, _ in parse_qsl(parsed.query[:MAX_QUERY_BYTES], keep_blank_values=True) if PARAM.fullmatch(key)}
    origin = urlsplit(authorized.url)
    return urlunsplit((origin.scheme, origin.netloc, parsed.path or '/', '', '')), query


def resolve_url(value, base_url, page_url, source_url):
    if re.match(r'^[a-z][a-z0-9+.-]*:', value, flags=re.I):
        return value  # The scope parser rejects unsupported schemes.
    if value.startswith('//'):
        return urljoin(page_url or source_url, value)
    # Fetch resolves relative to the document. The bundle directory is not a document base.
    if base_url:
        if not base_url.startswith(('https://', 'http://')) and not page_url:
            return None
        if '?' in base_url or '#' in base_url:
            return None
        return urljoin(page_url or source_url, base_url.rstrip('/') + '/' + value.lstrip('/'))
    if page_url or value.startswith('/'):
        return urljoin(page_url or source_url, value)
    return None


def source_documents(body, kind):
    if kind != 'map':
        yield None, kind, body
        return
    parsed = json.loads(body)
    if not isinstance(parsed, dict) or parsed.get('version') != 3:
        raise ValueError('Unsupported source map.')
    names, sources = parsed.get('sources'), parsed.get('sourcesContent')
    if not isinstance(names, list) or not isinstance(sources, list):
        return
    for name, source in zip(names[:MAX_SOURCES], sources):
        if isinstance(name, str) and isinstance(source, str) and source:
            ext = PurePosixPath(name.split('?', 1)[0]).suffix.lower().lstrip('.')
            if ext in SOURCE_TYPES - {'map', 'script'}:
                yield name.split('?', 1)[0][:240], ext, source


def analyze_surface(store, run_id, values, targets, exchanges):
    scopes = [parse_target(value) for value in targets]
    endpoints, parsers, seen = {}, {}, set()
    counts = dict.fromkeys(('captures', 'documents', 'bytes', 'missing', 'truncated', 'parse_errors', 'unresolved', 'out_of_scope'), 0)
    limits = set()

    for manifest in values:
        items = manifest.get('manifest', [])
        by_url = {item['url']: item for item in items}
        for item in items:
            artifact_id = item.get('artifact_id')
            url = item['url']
            kind = item.get('kind') or asset_kind(url)
            if kind not in SOURCE_TYPES or not 200 <= (item.get('status') or 0) < 300:
                continue
            if not artifact_id:
                counts['missing'] += 1
                continue
            # Use a captured document ancestor for relative paths when one is known.
            page_url = None
            parent = item.get('discovered_from')
            for _ in range(6):
                entry = by_url.get(parent)
                if not entry:
                    break
                if entry.get('kind') == 'page' and 200 <= (entry.get('status') or 0) < 300:
                    page_url = parent
                    break
                parent = entry.get('discovered_from')
            identity = artifact_id, page_url
            if identity in seen:
                continue
            if counts['captures'] >= MAX_CAPTURES:
                limits.add('capture limit')
                break
            seen.add(identity)
            counts['captures'] += 1
            try:
                authorize(url, scopes)
                meta = store.artifact_metadata(artifact_id)
                if meta['run_id'] != run_id or not re.fullmatch(r'http-[0-9]+\.json', meta['name'].rsplit('/', 1)[-1]):
                    raise KeyError(artifact_id)
                from .recovery import checked_reused_content
                capture = checked_reused_content(store, artifact_id)
                if capture.get('url') != url or not isinstance(capture.get('body'), str):
                    raise KeyError(artifact_id)
            except (KeyError, ScopeError):
                counts['missing'] += 1
                continue
            if capture.get('truncated') or item.get('truncated'):
                counts['truncated'] += 1
            try:
                for source_name, extension, document in source_documents(capture['body'], kind):
                    encoded = document.encode('utf-8', errors='replace')
                    if counts['documents'] >= MAX_SOURCES or counts['bytes'] + len(encoded) > MAX_BYTES:
                        limits.add('source parsing limit')
                        break
                    counts['documents'] += 1
                    counts['bytes'] += len(encoded)
                    language = extension if extension in ('ts', 'tsx') else 'js'
                    if language not in parsers:
                        parsers[language] = Parser(LANGUAGES[language])
                    tree = parsers[language].parse(encoded)
                    counts['parse_errors'] += int(tree.root_node.has_error)
                    source_url = urlunsplit((*urlsplit(url)[:3], '', ''))
                    for (line, column), (method, value, base, params, client) in call_sites(tree):
                        try:
                            resolved = resolve_url(value, base, page_url, url)
                        except ValueError:
                            resolved = None
                        if not resolved:
                            counts['unresolved'] += 1
                            continue
                        route = route_key(resolved, scopes)
                        if route is None:
                            counts['out_of_scope'] += 1
                            continue
                        normalized, query = route
                        location = {'artifact_id': artifact_id, 'source_url': source_url, 'embedded_source': source_name,
                                    'line': line + 1, 'column': column + 1, 'client': client}
                        add_endpoint(endpoints, (method, normalized), query | params, location, limits)
            except (ValueError, RecursionError):
                counts['parse_errors'] += 1

    traffic, traffic_limited = exchanges(run_id, MAX_EXCHANGES) if endpoints else ([], False)
    if traffic_limited:
        limits.add('HTTP history limit')
    for row in traffic:
        route = route_key(row['url'], scopes)
        endpoint = endpoints.get((row['method'], route[0])) if route else None
        if endpoint and len(endpoint['traffic']) < MAX_LOCATIONS:
            endpoint['traffic'].append({'exchange_id': row['id'], 'source': row['source'], 'status': row['status']})
        elif endpoint:
            limits.add('per-endpoint exchange limit')
    result = []
    for _, endpoint in sorted(endpoints.items()):
        endpoint['parameters'] = sorted(endpoint['parameters'])[:50]
        endpoint['status'] = 'observed' if any(row['source'] == 'native' for row in endpoint['traffic']) else 'imported' if endpoint['traffic'] else 'inferred'
        result.append(endpoint)
    return {'schema': SCHEMA, 'endpoints': result, 'counts': counts, 'limits_hit': sorted(limits),
            'coverage_limits': ['Literal fetch and Axios calls only. Dynamic URLs, client aliases and runtime configuration may be absent.',
                                'Relative paths use a known captured page. Root-relative paths without a page use the captured source origin.',
                                'Only matching method and path in completed native or imported HTTP exchanges corroborate a route.']}
