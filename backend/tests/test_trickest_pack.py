import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.catalog import CATALOG, TOOLS, TRICKEST_CATALOG, scoped_lines
from backend.catalog_execution import preflight
from backend.recon_tools import PROFILES_BY_GROUP, tool_check
from backend.store import Store
from backend.tests.test_local import wait_done
from backend.tests.test_workflows import launch
from backend.trickest_pack import GENERATORS, candidate_output, validate_wordlist, workflow
from backend.scope import ScopeError
from backend.workflows import validate_workflow


def test_public_pack_catalog_loads_typed_workflows_without_dispatch(tmp_path):
    assert len(CATALOG['tools']) == 151 and len(CATALOG['workflows']) == 57
    assert set(TOOLS) - {tool['id'] for tool in CATALOG['tools']} == GENERATORS
    assert set(PROFILES_BY_GROUP['trickest-oss']) == GENERATORS
    for tool in TRICKEST_CATALOG['tools']:
        assert tool['version'] == PROFILES_BY_GROUP['trickest-oss'][tool['id']][1]
    with TestClient(create_app(tmp_path)) as client:
        catalog = client.get('/api/catalog').json()
        assert catalog['trickest'] == TRICKEST_CATALOG
        for entry in catalog['trickest']['workflows']:
            path = '/api/workflow-starters/trickest/' + entry['id']
            graph = client.get(path).json()
            validate_workflow(graph, live=True)
            assert all(not node['data'].get('inputRefs') for node in graph['nodes'])
        assert client.get('/api/workflow-starters/trickest/unknown').status_code == 404
        assert client.post('/api/support-data/install/bundled', json={}).status_code == 200
        for entry in catalog['trickest']['workflows']:
            graph = client.get('/api/workflow-starters/trickest/' + entry['id']).json()
            bindings = {slot for node in graph['nodes'] for slot in node['data'].get('inputRefs', {})}
            assert bindings == ({'templates'} if entry['id'] == 'trickest-local-recon' else {'wordlist'})
        assert client.get('/api/runs').json() == []


@pytest.mark.parametrize('tool,words', [
    ('mksub', '../dev\n'), ('mksub', 'api.example.test\n'), ('mksub', 'x\x00y\n'),
    ('mkpath', '/outside\n'), ('mkpath', 'api/../admin\n'), ('mkpath', 'admin?x=1\n'),
    ('mkpath', 'admin%2f..\n'), ('mkpath', 'foo\u00e4\n'),
    ('mksub', '\n'.join('word'+str(i) for i in range(33))),
])
def test_generator_wordlists_reject_unsafe_or_unbounded_inputs(tmp_path, tool, words):
    path = tmp_path / 'words.txt'
    path.write_text(words)
    with pytest.raises(ScopeError):
        validate_wordlist(tool, path)


def test_candidate_boundaries_are_checked_before_downstream_use():
    exact = {'targets': ['example.test'], 'max_hosts': 8}
    words = candidate_output('mksub', {'targets': ['app.example.test', 'example.test', 'elsewhere.test']},
                             'example.test', exact)
    assert words == {'targets': ['app.example.test']}
    assert scoped_lines(words['targets'], 'targets', exact)[0] == []
    wildcard = {**exact, 'targets': ['*.example.test']}
    assert scoped_lines(words['targets'], 'targets', wildcard)[0] == words['targets']
    scope = {'targets': ['https://example.test/app'], 'max_hosts': 8}
    paths = candidate_output('mkpath', {'url': [
        'https://example.test/app', 'https://example.test/app/login', 'https://example.test/other',
        'https://example.test/app/login?x=1', 'https://example.test:8443/app/login',
    ]}, 'https://example.test/app', scope)
    assert paths == {'url': ['https://example.test/app/login']}


def test_preflight_requires_a_bound_wordlist(tmp_path):
    store = Store(tmp_path)
    graph = workflow('trickest-subdomain-candidates')
    config = {'targets': ['example.test'], 'max_hosts': 8, 'allow_cli': True}
    result = preflight(graph, config, store, check_binaries=False)
    assert not result['ready']
    assert result['issues'] == [{'node_id': 'generate', 'reasons': ['Requires a connected or registered wordlist input.']}]


@pytest.mark.parametrize('identifier,tool,seed,socket,expected', [
    ('trickest-subdomain-candidates', 'mksub', 'example.test', 'targets', 'api.dev.example.test'),
    ('trickest-path-candidates', 'mkpath', 'https://example.test/app', 'url', 'https://example.test/app/api/dev'),
])
def test_pinned_trickest_binaries_run_through_local_dag(tmp_path, monkeypatch, identifier, tool, seed, socket, expected):
    directory = os.environ.get('AI_TRICKY_TRICKEST_BIN')
    if not directory:
        pytest.skip('Install the pinned Trickest open-source tools first')
    binary = Path(directory) / tool
    assert tool_check(tool, binary)['status'] == 'tested_version'
    monkeypatch.setenv('PATH', os.pathsep.join((directory, os.defpath)))
    with TestClient(create_app(tmp_path)) as client:
        graph = client.get('/api/workflow-starters/trickest/' + identifier).json()
        words = client.post('/api/inputs', json={'name': 'Small wordlist', 'content': 'api\ndev\n'})
        assert words.status_code == 201
        next(node for node in graph['nodes'] if node['id'] == 'generate')['data']['inputRefs'] = {
            'wordlist': words.json()['id'],
        }
        response = launch(client, seed, graph, allow_cli=True, max_requests=1)
        assert response.status_code == 201, response.text
        rid = response.json()['id']
        run = wait_done(client, rid)
        assert run['status'] == 'completed', run
        assert run['result']['request_count'] == 0 and run['result']['cli_invocation_count'] == 1
        nodes = client.get(f'/api/runs/{rid}/nodes').json()
        generator = next(node for node in nodes if node['node_id'] == 'generate')
        result = client.get('/api/artifacts/' + generator['result']['artifact_id']).json()[0]
        output = result['catalog_streams'][socket]
        assert expected in output and len(output) == 6
        assert seed not in output and output == sorted(set(output))
