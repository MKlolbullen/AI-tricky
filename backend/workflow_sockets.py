"""Resolve workflow edges and project node results onto their selected sockets."""

from .catalog import CATALOG_KINDS
from .scope import ScopeError, parse_target, parse_url


def resolve_sockets(edge, outputs, inputs):
    source = edge.get('sourceHandle')
    target = edge.get('targetHandle')
    if source is not None and (not isinstance(source, str) or not source.startswith('out:')):
        raise ScopeError('Invalid source socket.')
    if target is not None and (not isinstance(target, str) or not target.startswith('in:')):
        raise ScopeError('Invalid target socket.')

    output = source[4:] if source is not None else outputs[0]
    input_type = target[3:] if target is not None else output
    # Older graphs omit the handles or name the incoming type on an any socket.
    if input_type == output and input_type not in inputs and 'any' in inputs:
        input_type = 'any'
    if output not in outputs or input_type not in inputs or input_type not in (output, 'any'):
        raise ScopeError('Incompatible workflow port types.')
    return output, input_type


def incoming_routes(graph):
    nodes = {node['id']: node['data'] for node in graph['nodes']}
    routes = {node_id: [] for node_id in nodes}
    for edge in graph['edges']:
        parent, child = edge['source'], edge['target']
        source = nodes[parent]
        outputs = source['outputs'] if source['kind'] in CATALOG_KINDS else [source['output']]
        output, input_type = resolve_sockets(edge, outputs, nodes[child]['inputs'])
        routes[child].append((parent, output, input_type))
    return routes


def catalog_socket_values(row, output):
    # The collector retains its inputs in the artifact alongside its report.
    if output == 'report' and 'report' in row:
        return [row['report']]
    return row['catalog_streams'].get(output, [])


def routed_rows(routes, outputs):
    """Native adapters receive native rows or a packet with one selected stream."""
    for parent, output, _ in routes:
        for row in outputs[parent]:
            packet = row.get('catalog_streams')
            if packet is None:
                yield row
                continue
            selected = catalog_socket_values(row, output)
            if output in ('targets', 'url'):
                for value in selected:
                    try:
                        target = parse_url(value) if output == 'url' or '://' in value else parse_target(value)
                    except ScopeError:
                        continue
                    yield {'url': target.url} if output == 'url' else {'target': target.url, 'kind': target.kind}
            elif output == 'report' and 'report' in row:
                yield {key: value for key, value in row.items() if key != 'catalog_streams'}
            elif selected:
                yield {**row, 'catalog_streams': {output: selected}}
