from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.agent_settings import AgentPresets, PresetInput
from backend.store import Store


def preferences():
    return {'schema_version': 1, 'default_model': {'provider': 'openai', 'model': 'custom-default'},
            'planner_model': {'provider': 'gemini', 'model': 'custom-planner'},
            'team_profile': 'specialist', 'team_task_level': 'complex',
            'roles': ['surface', 'analyst', 'vulnerability', 'poc', 'ad_identity'],
            'member_max_turns': 11, 'team_max_turns': 71, 'member_workers': 2,
            'adaptive': True, 'synthesize': True,
            'team_routes': {'surface': {'primary': {'provider': 'gemini', 'model': 'custom-recon'},
                           'fallback': {'provider': 'xai', 'model': 'custom-fallback'},
                           'complex_task': {'provider': 'anthropic', 'model': 'custom-complex'}},
                            'poc': {'primary': {'provider': 'venice', 'model': 'custom-poc'}}}}


def test_round_trip_restart_default_and_saved_model_menu(tmp_path, monkeypatch):
    monkeypatch.setenv('CAI_ALLOW_REMOTE_MODEL', '0')
    def unexpected(*args, **kwargs):
        pytest.fail('Saving or loading preferences must not call a provider')
    monkeypatch.setattr('backend.cai_adapter.assess', unexpected)
    settings = preferences()
    with TestClient(create_app(tmp_path)) as client:
        assert client.get('/api/agent-settings').json() == {'items': [], 'default': None, 'saved_models': {}}
        response = client.post('/api/agent-settings', json={'name': ' Web specialists ', 'settings': settings, 'is_default': True})
        assert response.status_code == 201
        saved = response.json()
        assert saved['name'] == 'Web specialists' and saved['revision'] == 1
        assert saved['settings'] == settings
        assert client.get('/api/runs').json() == []
    with TestClient(create_app(tmp_path)) as client:
        index = client.get('/api/agent-settings').json()
        assert index['default'] == saved
        assert client.get('/api/agent-settings/' + saved['id']).json() == saved
        assert 'settings' not in index['items'][0]
        assert index['saved_models'] == {'openai': ['custom-default'], 'gemini': ['custom-planner', 'custom-recon'],
                                         'xai': ['custom-fallback'], 'anthropic': ['custom-complex'], 'venice': ['custom-poc']}
        assert not client.get('/api/runtime').json()['remote_model_enabled']
        assert not (tmp_path/'credentials.json').exists()


def test_revision_conflicts_rename_default_switch_delete_and_rollback(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        def create(name, default=False):
            return client.post('/api/agent-settings', json={'name': name, 'settings': {}, 'is_default': default}).json()
        a = create('A', True)
        b = create('B', True)
        current_a = client.get('/api/agent-settings/' + a['id']).json()
        assert current_a['revision'] == 2 and not current_a['is_default']
        assert client.post('/api/agent-settings/' + a['id'], json={'name': 'Changed', 'settings': {}, 'revision': a['revision']}).status_code == 409
        # A duplicate name must roll back the attempted default transfer.
        assert client.post('/api/agent-settings/' + a['id'], json={'name': 'b', 'settings': {}, 'revision': 2, 'is_default': True}).status_code == 409
        assert client.get('/api/agent-settings').json()['default']['id'] == b['id']
        assert client.post('/api/agent-settings/' + a['id'] + '/delete', json={'revision': 1}).status_code == 409
        renamed = client.post('/api/agent-settings/' + a['id'], json={'name': 'Renamed', 'settings': {}, 'revision': 2}).json()
        assert renamed['revision'] == 3
        assert client.post('/api/agent-settings/' + a['id'] + '/delete', json={'revision': 3}).status_code == 200
        assert client.get('/api/agent-settings/' + a['id']).status_code == 404
        assert client.post('/api/agent-settings/' + b['id'] + '/delete', json={'revision': 1}).status_code == 200
        assert client.get('/api/agent-settings').json()['default'] is None


@pytest.mark.parametrize('field,value', [('api_key', 'never-echo-me'), ('target_ids', ['example.com']),
    ('allow_http', True), ('allow_cli', True), ('http_routing', {'mode': 'direct'}),
    ('schema_version', 2), ('team_profile', 'unknown'), ('roles', ['poc', 'poc']),
    ('roles', ['unsupported']), ('member_max_turns', 0), ('team_max_turns', 145),
    ('member_workers', 9), ('member_workers', '2'), ('synthesize', 'false'),
    ('team_routes', {'bogus': {'primary': {'provider': 'local', 'model': 'x'}}}),
    ('planner_model', {'provider': 'bogus', 'model': 'x'}),
    ('default_model', {'provider': 'openai', 'model': 'https://example.com'}),
    ('default_model', {'provider': 'openai', 'model': ' whitespace '})])
def test_strict_preferences_reject_execution_secrets_and_invalid_choices(tmp_path, field, value):
    with TestClient(create_app(tmp_path)) as client:
        settings = preferences(); settings[field] = value
        response = client.post('/api/agent-settings', json={'name': 'Invalid', 'settings': settings})
        assert response.status_code == 422
        assert 'never-echo-me' not in response.text
        assert client.get('/api/agent-settings').json()['items'] == []


def test_drafts_can_be_saved_but_do_not_become_executable_routes(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        settings = preferences(); settings['team_routes']['surface']['primary']['model'] = ''
        response = client.post('/api/agent-settings', json={'name': 'Draft', 'settings': settings})
        assert response.status_code == 201
        assert client.post('/api/runs/preflight', json={'engine': 'team', 'goal': 'Check draft',
                           'team_routes': settings['team_routes']}).status_code == 422
        assert client.get('/api/runs').json() == []


def test_limit_and_two_concurrent_default_writers(tmp_path):
    store = Store(tmp_path); presets = AgentPresets(store)
    def save(i):
        return presets.save(PresetInput(name=f'Team {i}', settings={}, is_default=True))
    with ThreadPoolExecutor(max_workers=2) as pool:
        saved = list(pool.map(save, range(2)))
    index = presets.index()
    assert sum(p['is_default'] for p in index['items']) == 1
    assert index['default']['id'] in {p['id'] for p in saved}
    for i in range(2, 50):
        save(i)
    with TestClient(create_app(tmp_path)) as client:
        assert client.post('/api/agent-settings', json={'name': 'Overflow', 'settings': {}}).status_code == 409


def test_catalog_is_offline_and_custom_choices_are_not_restricted_to_it(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        runtime = client.get('/api/runtime').json()
        assert set(runtime['model_catalog']) == {p['id'] for p in runtime['model_providers'] if p['id'] != 'local'}
        for catalog in runtime['model_catalog'].values():
            assert catalog['source'].startswith('https://')
            assert catalog['reviewed'] == '2026-11-10'
            assert len({m['id'] for m in catalog['models']}) == len(catalog['models']) >= 2
        response = client.post('/api/agent-settings', json={'name': 'Custom', 'settings': preferences()})
        assert response.status_code == 201
        assert client.post('/api/agent-settings', json={'name': 'Revision on create', 'settings': {}, 'revision': 1}).status_code == 422
        assert client.post('/api/agent-settings', json={'name': '   ', 'settings': {}}).status_code == 422
        assert client.post('/api/agent-settings', json={'name': 'Blocked', 'settings': {}}, headers={'Origin': 'https://example.com'}).status_code == 403
