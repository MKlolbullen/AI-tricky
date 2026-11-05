"""Validated, application-owned DAG adapters. Never interpret graph data as commands."""
import asyncio
import json
import math
import re
from pathlib import Path

from .scope import ScopeError, network_hosts, parse_target, parse_url
from .catalog import CATALOG_KINDS, contract

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = json.loads((ROOT / 'src/native-registry.json').read_text())
CATALOG = {t['id']: t for t in json.loads((ROOT / 'src/templates.json').read_text())['tools']}
LEGACY = {
    'domain': ([], 'domain'), 'file': ([], 'domain_list'),
    'subfinder': (['domain'], 'domain_list'), 'assetfinder': (['domain'], 'domain_list'),
    'dnsx': (['domain_list'], 'domain_list'), 'httpx': (['domain_list'], 'url_list'),
    'merge': (['domain_list'], 'domain_list'), 'agent': (['url_list'], 'findings'),
    'burp': (['findings'], 'evidence'),
}
SCHEMA = 'offsecs-u-ai.workflow/v1'
ID = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


def validate_workflow(graph, *, live=False):
    if not isinstance(graph, dict) or len(json.dumps(graph)) > 1_000_000:
        raise ScopeError('Workflow must be an object smaller than 1 MB.')
    nodes, edges = graph.get('nodes'), graph.get('edges')
    if graph.get('schema') not in (SCHEMA, 'reconforge.prototype.workflow/v1'):
        raise ScopeError('Unsupported workflow schema.')
    if not isinstance(nodes, list) or not (1 if live else 0) <= len(nodes) <= (64 if live else 500) or not isinstance(edges, list) or len(edges) > 2000:
        raise ScopeError('Invalid workflow size (live limit: 64 nodes).')
    specs, by_id, incoming = {}, {}, {}
    for n in nodes:
        if not isinstance(n, dict) or not isinstance(n.get('id'), str) or not ID.fullmatch(n['id']) or n['id'] in by_id or n.get('type') != 'tool':
            raise ScopeError('Invalid or duplicate workflow node.')
        pos, data = n.get('position', {}), n.get('data', {})
        if not isinstance(pos, dict) or any(type(pos.get(k)) not in (int, float) or not math.isfinite(pos[k]) for k in ('x', 'y')) or not isinstance(data, dict):
            raise ScopeError('Invalid node position or data.')
        kind = data.get('kind')
        if not isinstance(kind, str):
            raise ScopeError('Invalid node adapter.')
        if kind in CATALOG_KINDS:
            inputs, outputs = contract(data)
            output = outputs[0]
        elif kind in REGISTRY:
            spec = REGISTRY[kind]
            inputs, output = spec['inputs'], spec['output']
            if data.get('inputs') != inputs:
                raise ScopeError('Modified native input contract.')
        elif live:
            raise ScopeError(f"Node {n['id']} has no live adapter. Use native nodes or keep this graph as a design.")
        elif kind == 'template':
            template_id = data.get('templateId')
            spec = CATALOG.get(template_id) if isinstance(template_id, str) else None
            if not spec or data.get('inputs') != spec['inputs']:
                raise ScopeError('Unknown or modified catalog descriptor.')
            inputs, output = spec['inputs'], spec['output']
        elif kind in LEGACY:
            inputs, output = LEGACY[kind]
        else:
            raise ScopeError('Unknown workflow adapter.')
        if data.get('output') != output:
            raise ScopeError('Modified output type is not supported.')
        for key in ('title', 'description', 'output', 'result', 'status', 'backend', 'domain'):
            if key in data and (not isinstance(data[key], str) or len(data[key]) > 4096):
                raise ScopeError('Invalid node text.')
        timeout = data.get('timeout', 120)
        if type(timeout) is not int or not 1 <= timeout <= (3600 if kind in CATALOG_KINDS or not live else 240):
            raise ScopeError('Node timeout must be 1–240 whole seconds.')
        if type(data.get('retries', 0)) is not int or (live and data.get('retries', 0) != 0):
            raise ScopeError('Native DAG retries must be zero; rerun explicitly to repeat traffic.')
        specs[n['id']] = (inputs, data['outputs'] if kind in CATALOG_KINDS else [output])
        by_id[n['id']], incoming[n['id']] = n, []
    edge_ids, pairs = set(), set()
    for e in edges:
        if not isinstance(e, dict) or not isinstance(e.get('id'), str) or not ID.fullmatch(e['id']) or e['id'] in edge_ids:
            raise ScopeError('Invalid or duplicate workflow edge.')
        if any(e.get(k) is not None and not isinstance(e[k],str) for k in ('sourceHandle','targetHandle')):
            raise ScopeError('Invalid typed socket handle.')
        source, target = e.get('source'), e.get('target')
        if not isinstance(source, str) or not isinstance(target, str) or source not in by_id or target not in by_id or source == target or (source, target, e.get('sourceHandle'), e.get('targetHandle')) in pairs:
            raise ScopeError('Dangling, duplicate or self-referencing edge.')
        source_type = e.get('sourceHandle')
        target_type = e.get('targetHandle')
        if source_type is not None and (not isinstance(source_type,str) or not source_type.startswith('out:')):
            raise ScopeError('Invalid source socket.')
        if target_type is not None and (not isinstance(target_type,str) or not target_type.startswith('in:')):
            raise ScopeError('Invalid target socket.')
        source_type = source_type[4:] if source_type else specs[source][1][0]
        target_type = target_type[3:] if target_type else source_type
        if source_type not in specs[source][1] or (target_type not in specs[target][0] and 'any' not in specs[target][0]) or (target_type!='any' and source_type!=target_type):
            raise ScopeError('Incompatible workflow port types.')
        incoming[target].append(source)
        edge_ids.add(e['id'])
        pairs.add((source,target,e.get('sourceHandle'),e.get('targetHandle')))
    remaining, order = set(by_id), []
    while remaining:
        ready = [n['id'] for n in nodes if n['id'] in remaining and all(x not in remaining for x in incoming[n['id']])]
        if not ready:
            raise ScopeError('Workflow contains a cycle.')
        order.extend(ready)
        remaining.difference_update(ready)
    if live:
        catalog_graph=any(n['data']['kind'] in CATALOG_KINDS for n in nodes)
        scopes=[n for n in nodes if n['data']['kind']=='native_scope']
        roots={'native_scope','catalog_source','catalog_payload'}
        if (not catalog_graph and len(scopes)!=1) or len(scopes)>1 or any(not incoming[n['id']] and n['data']['kind'] not in roots and not (n['data']['kind']=='catalog_tool' and not n['data']['inputs']) for n in nodes):
            raise ScopeError('Live workflows need connected inputs and explicit scope or registered source nodes.')
    return order, incoming


def web_url(host, port):
    host = f'[{host}]' if ':' in host else host
    return f"{'https' if port in (443, 8443) else 'http'}://{host}:{port}/"


async def execute_workflow(rid, config, ctl, store, fetch, probe, analyze, asset_graph=None):
    graph = config['workflow']
    order, incoming = validate_workflow(graph, live=True)
    by_id = {n['id']: n for n in graph['nodes']}
    outputs, states = {}, {nid: 'queued' for nid in order}
    slots = asyncio.Semaphore(config['parallelism'])
    tasks = {}

    async def dispatch(nid, values):
        kind = by_id[nid]['data']['kind']
        if kind in CATALOG_KINDS:
            from .catalog_execution import incoming_streams, execute_catalog_node
            streams=incoming_streams(graph,nid,outputs)
            return await execute_catalog_node(rid,nid,by_id[nid]['data'],streams,config,ctl,store)
        if kind == 'native_scope':
            return [{'target': t, 'kind': parse_target(t).kind} for t in config['targets']]
        if kind == 'native_tcp':
            rows = []
            for entry in values:
                if entry['kind'] == 'url':
                    rows.append({'url': entry['target'], 'state': 'url_scope', 'kind': 'url'})
                else:
                    result = await probe(entry['target'], config['ports'], node_id=nid)
                    if 'error' in result:
                        rows.append({'target': entry['target'], 'state': 'error', 'error': result['error']})
                    else:
                        rows.extend(store.content(result['artifact_id']))
            return rows
        if kind == 'native_http':
            urls = []
            expanded=[]
            for entry in values:
                if 'catalog_streams' in entry:
                    for typ in ('url','targets'):
                        for value in entry['catalog_streams'].get(typ,[]):
                            try:
                                target=parse_url(value) if '://' in value else parse_target(value)
                                expanded.append({'target':target.url,'kind':target.kind})
                            except ScopeError:pass
                else:expanded.append(entry)
            for entry in expanded:
                if 'target' in entry and 'kind' in entry:
                    target = parse_url(entry['target']) if '://' in entry['target'] else parse_target(entry['target'])
                    if target.kind == 'url':
                        urls.append(target.url)
                    else:
                        for host in network_hosts(target.url, [parse_target(t) for t in config['targets']], config['max_hosts']):
                            urls.extend(web_url(host, p) for p in config['ports'] if p in (80, 443, 8080, 8443))
                elif entry.get('url'):
                    urls.append(entry['url'])
                elif entry.get('state') == 'open' and entry['port'] in (80, 443, 8080, 8443):
                    urls.append(web_url(entry['host'], entry['port']))
            rows = []
            if config.get('verification') and nid == config['verification']['node_id']:
                from .verification import execute_pair
                return await execute_pair(rid, nid, config, urls, fetch, store)
            for url in dict.fromkeys(urls):
                rows.append({'url': url, **await fetch(url, node_id=nid)})
            return rows
        if kind == 'native_cai':
            # Evidence-only analysis: the existing configured CAI provider gets no live tools.
            result = await analyze(values)
            from .intelligence import validate_analysis
            analysis = validate_analysis(result['report'], values)
            return [{'report': analysis['summary'], 'analysis': analysis, 'evidence_status': 'CANDIDATE'}]
        if kind == 'native_asset_graph':
            # Read-only: the current asset graph scoped to the entered targets.
            # No target traffic and no scope expansion — observed data for review.
            sub = asset_graph.scope_subgraph(config['targets']) if asset_graph else {'entities': [], 'edges': []}
            counts = {}
            for e in sub['entities']:
                counts[e['kind']] = counts.get(e['kind'], 0) + 1
            breakdown = ', '.join(f'{v} {k}' for k, v in sorted(counts.items())) or 'no entities'
            summary = (f'Asset graph for the entered scope: {len(sub["entities"])} entities, {len(sub["edges"])} relationships '
                       f'({breakdown}). Observed data and third-party claims, not confirmed findings.')
            return [{'report': summary, 'asset_graph': sub, 'evidence_status': 'OBSERVATION'}]
        if kind == 'native_team':
            # Evidence-only multi-role review. Each role analyses the same captured
            # evidence with no target tools; results are aggregated per role and a
            # role failure becomes a coverage gap, not a node failure. Nothing is
            # auto-confirmed.
            from .intelligence import validate_analysis
            from . import team as team_leader
            async def member(key):
                spec = team_leader.ROLES[key]
                try:
                    out = await analyze(values, role_instructions=spec['focus'])
                    analysis = validate_analysis(out['report'], values)
                    return {'role': key, 'name': spec['name'], 'status': 'ok',
                            'summary': analysis['summary'], 'analysis': analysis}
                except (ScopeError, RuntimeError) as exc:
                    return {'role': key, 'name': spec['name'], 'status': 'failed', 'reason': str(exc)[:300]}
            members = list(await asyncio.gather(*(member(k) for k in team_leader.DEFAULT_ROLES)))
            completed = [m for m in members if m['status'] == 'ok']
            coverage = [f'{m["name"]} role did not complete: {m["reason"]}' for m in members if m['status'] != 'ok']
            summary = f'CAI team evidence review: {len(completed)}/{len(members)} roles completed. Candidates only; nothing auto-confirmed.'
            return [{'report': summary, 'team': True, 'members': members, 'coverage_limits': coverage, 'evidence_status': 'CANDIDATE'}]
        open_ports = sum(v.get('state') == 'open' for v in values)
        responses = sum('status' in v and 'url' in v for v in values)
        errors = sum('error' in v or v.get('state') in ('blocked', 'budget_exhausted') for v in values)
        return [{'report': f'{len(values)} upstream records; {open_ports} open TCP services; {responses} HTTP responses; {errors} errors or blocked operations. These are observations, not confirmed vulnerabilities. Only connected upstream nodes are covered.', 'evidence_status': 'OBSERVATION', 'records': len(values), 'errors': errors}]

    async def run_node(nid):
        for parent in incoming[nid]:
            await tasks[parent]
        if any(states[p] not in ('completed', 'planned') for p in incoming[nid]):
            states[nid] = 'skipped'
            store.node_status(rid, nid, 'skipped', {'reason': 'Upstream node failed.'})
            store.event(rid, 'node.skipped', {'node_id': nid, 'reason': 'Upstream node failed.'})
            return
        async with slots:
            await ctl.gate.wait()
            if ctl.cancelled:
                raise asyncio.CancelledError()
            if not config['allow_http']:
                states[nid] = 'planned'
                store.node_status(rid, nid, 'planned', {'reason': 'Planning only; no adapters or model called.'})
                store.event(rid, 'node.planned', {'node_id': nid})
                return
            states[nid] = 'running'
            ctl.active_nodes.add(nid)
            store.node_status(rid, nid, 'running')
            store.event(rid, 'node.started', {'node_id': nid, 'adapter': by_id[nid]['data']['kind']})
            try:
                values = []
                seen = set()
                for parent in incoming[nid]:
                    for row in outputs[parent]:
                        key = json.dumps(row, sort_keys=True)
                        if key not in seen:
                            values.append(row)
                            seen.add(key)
                async with asyncio.timeout(by_id[nid]['data'].get('timeout', 120)):
                    result = await dispatch(nid, values)
                outputs[nid] = result
                aid = store.artifact(rid, f'node-{nid}.json', result, node_id=nid)
                errors = sum('error' in row or row.get('state') in ('blocked', 'budget_exhausted') for row in result)
                states[nid] = 'completed'
                metadata = {'artifact_id': aid, 'records': sum(sum(len(v) for v in row['catalog_streams'].values()) if 'catalog_streams' in row else 1 for row in result), 'errors': errors}
                store.node_status(rid, nid, 'completed', metadata)
                store.event(rid, 'node.completed', {'node_id': nid, **metadata})
            except asyncio.CancelledError:
                states[nid] = 'cancelled'
                store.node_status(rid, nid, 'cancelled')
                store.event(rid, 'node.cancelled', {'node_id': nid})
                raise
            except Exception as exc:
                states[nid] = 'failed'
                # Do not persist provider exception messages or untrusted response bodies.
                error = str(exc)[:500] if isinstance(exc,(ScopeError,RuntimeError)) else type(exc).__name__
                store.node_status(rid, nid, 'failed', {'error': error})
                store.event(rid, 'node.failed', {'node_id': nid, 'error': error})
            finally:
                ctl.active_nodes.discard(nid)

    for nid in order:
        store.node_status(rid, nid, 'queued')
    try:
        async with asyncio.TaskGroup() as group:
            for nid in order:
                tasks[nid] = group.create_task(run_node(nid))
    finally:
        for nid in order:
            if states[nid] in ('queued', 'running'):
                store.node_status(rid, nid, 'cancelled')
                store.event(rid, 'node.cancelled', {'node_id': nid})
    if not config['allow_http']:
        return {'report': f'Validated plan for {len(order)} nodes. No target requests or model calls were made.', 'engine': 'native-dag', 'evidence_status': 'PLAN'}
    failed = sum(s == 'failed' for s in states.values())
    records = sum(len(v) for v in outputs.values())
    errors = sum('error' in row or row.get('state') in ('blocked', 'budget_exhausted') for rows in outputs.values() for row in rows)
    verification = next((row['verification'] for rows in outputs.values() for row in rows if 'verification' in row), None)
    return {'report': f'Workflow finished: {sum(s == "completed" for s in states.values())}/{len(order)} nodes completed, {failed} failed. {errors} output records contain errors or blocked operations; inspect node artifacts for coverage. No vulnerabilities are automatically confirmed.', 'engine': 'native-dag', 'evidence_status': 'OBSERVATION', 'failed_nodes': failed, 'records': records, 'node_states': states,
            **({'verification': verification} if verification else {})}
