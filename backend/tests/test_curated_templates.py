"""Guards for the curated template catalog and its server-built starters.

src/templates.json was once replaced by an empty catalog without any test
noticing; these checks pin the legacy designs, the tool descriptors and every
starter the catalog names.
"""
import json
import subprocess
import sys

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.web_recon import recon_workflow, web_app_assessment_workflow
from backend.workflows import CATALOG, ROOT, SCHEMA, validate_workflow

CURATED = json.loads((ROOT / 'src/templates.json').read_text())
LEGACY_DESIGNS = {
    'inventory', 'cai', 'subdomains', 'amass-recon', 'web-recon', 'archive', 'wayback', 'crawl', 'directory',
    'content', 'screenshots', 'ports', 'tls', 'ssh', 'templates', 'fingerprint', 'js-audit', 'secrets', 'code',
    'iac', 'cloud', 'trickest-recon-adaptation',
}
STARTERS = [entry for entry in CURATED['workflows'] if entry.get('starter')]


def test_curated_catalog_keeps_legacy_designs_and_tool_descriptors():
    tools, workflows = CURATED['tools'], CURATED['workflows']
    assert len(tools) >= 53 and len({tool['id'] for tool in tools}) == len(tools)
    assert len(CATALOG) == len(tools)
    identifiers = [entry['id'] for entry in workflows]
    assert len(set(identifiers)) == len(identifiers)
    assert LEGACY_DESIGNS <= set(identifiers)
    for entry in workflows:
        assert all(isinstance(entry.get(key), str) and entry[key] for key in ('name', 'category', 'description', 'provenance'))
        assert isinstance(entry['targets'], list)
        if entry.get('starter'):
            # The graph is server-owned; a stored copy could drift from the socket contracts.
            assert 'nodes' not in entry and 'edges' not in entry and entry['steps']
        else:
            # Only the two native presets open a run form instead of a canvas design.
            assert entry['nodes'] or entry['id'] in ('inventory', 'cai'), entry['id']
            validate_workflow({'schema': SCHEMA, 'nodes': entry['nodes'], 'edges': entry['edges']})


def test_every_curated_starter_is_served_as_a_live_valid_graph(tmp_path):
    assert {entry['id'] for entry in STARTERS} == {'tpl-web-app-assessment'}
    with TestClient(create_app(tmp_path)) as client:
        for entry in STARTERS:
            response = client.get('/api/workflow-starters/' + entry['starter'])
            assert response.status_code == 200, response.text
            validate_workflow(response.json(), live=True)
        assert client.get('/api/workflow-starters/web-app-assessment').json() == web_app_assessment_workflow()
        assert client.get('/api/runs').json() == []


def test_web_application_assessment_covers_each_documented_phase():
    graph = web_app_assessment_workflow()
    assert graph == recon_workflow(fuzz=True, scan=True, review=True, surface=True)
    data = [node['data'] for node in graph['nodes']]
    assert {'subfinder', 'assetfinder', 'httprobe', 'katana', 'nuclei', 'ffuf'} == {d['toolId'] for d in data if d['kind'] == 'catalog_tool'}
    assert {'native_http', 'native_web_assets', 'native_api_surface', 'native_team', 'native_summary'} == {
        d['kind'] for d in data if d['kind'].startswith('native_')}
    # The specialist review is evidence-only: it reads saved captures, never a tool stream.
    review = next(node['id'] for node in graph['nodes'] if node['data']['kind'] == 'native_team')
    assert [(edge['source'], edge['sourceHandle']) for edge in graph['edges'] if edge['target'] == review] == [
        ('capture', 'out:observations')]


def test_documented_starter_exports_match_their_builders():
    check = subprocess.run([sys.executable, str(ROOT / 'scripts/export-starter-templates.py'), '--check'],
                           capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    exported = sorted((ROOT / 'docs/templates').glob('*.json'))
    assert [path.name for path in exported] == sorted(entry['starter'] + '-workflow.json' for entry in STARTERS)
    for path in exported:
        validate_workflow(json.loads(path.read_text()), live=True)
