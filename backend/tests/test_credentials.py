import json

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.credentials import CredentialVault, PROVIDERS, VARS


@pytest.fixture
def clean_env(monkeypatch):
    # Isolate every credential variable so vault env-sync starts from a known
    # baseline and nothing leaks between tests.
    for name in VARS:
        monkeypatch.delenv(name, raising=False)


def _var(providers, var_name):
    for provider in providers:
        for var in provider['variables']:
            if var['name'] == var_name:
                return var
    raise AssertionError(f'{var_name} not reported')


def test_registry_lists_providers_and_consumers(clean_env, tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        providers = c.get('/api/credentials').json()['providers']
    ids = [p['id'] for p in providers]
    assert {'shodan', 'censys', 'projectdiscovery', 'securitytrails', 'netlas',
            'urlscan', 'virustotal', 'binaryedge', 'github'} <= set(ids)
    # Catalog-declared variables report their consuming tools; others do not.
    assert _var(providers, 'SHODAN_API_KEY')['consumed_by'] == ['shodan-cli']
    assert _var(providers, 'PDCP_API_KEY')['consumed_by'] == ['chaos']
    assert _var(providers, 'VIRUSTOTAL_API_KEY')['consumed_by'] == []


def test_set_trims_persists_and_syncs_runtime(clean_env, tmp_path):
    import os
    with TestClient(create_app(tmp_path)) as c:
        body = c.post('/api/credentials', json={'updates': {'SHODAN_API_KEY': '  secret-123456  '}}).json()
        var = _var(body['providers'], 'SHODAN_API_KEY')
        assert var['configured'] and var['source'] == 'stored' and var['length'] == len('secret-123456')
        assert os.environ['SHODAN_API_KEY'] == 'secret-123456'
        runtime = c.get('/api/runtime').json()['cli_credential_variables']
        assert any(v['name'] == 'SHODAN_API_KEY' and v['configured'] for v in runtime)
    # Persisted file is owner-only and holds only the trimmed value.
    path = tmp_path / 'credentials.json'
    assert path.exists() and oct(path.stat().st_mode & 0o777) == '0o600'
    assert json.loads(path.read_text()) == {'SHODAN_API_KEY': 'secret-123456'}


def test_empty_value_clears(clean_env, tmp_path):
    import os
    with TestClient(create_app(tmp_path)) as c:
        c.post('/api/credentials', json={'updates': {'NETLAS_API_KEY': 'abc'}})
        body = c.post('/api/credentials', json={'updates': {'NETLAS_API_KEY': ''}}).json()
        assert _var(body['providers'], 'NETLAS_API_KEY')['configured'] is False
        assert 'NETLAS_API_KEY' not in os.environ
    assert json.loads((tmp_path / 'credentials.json').read_text()) == {}


def test_rejects_unknown_and_oversized(clean_env, tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        assert c.post('/api/credentials', json={'updates': {'NOT_A_VAR': 'x'}}).status_code == 422
        assert c.post('/api/credentials', json={'updates': {'SHODAN_API_KEY': 'x' * 5000}}).status_code == 422


def test_values_never_returned(clean_env, tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        c.post('/api/credentials', json={'updates': {'URLSCAN_API_KEY': 'topsecretvalue'}})
        assert 'topsecretvalue' not in json.dumps(c.get('/api/credentials').json())


def test_persists_across_restart(clean_env, tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        c.post('/api/credentials', json={'updates': {'BINARYEDGE_API_KEY': 'persisted'}})
    with TestClient(create_app(tmp_path)) as c2:
        assert _var(c2.get('/api/credentials').json()['providers'], 'BINARYEDGE_API_KEY')['configured'] is True


def test_environment_source_and_store_precedence(monkeypatch, tmp_path):
    import os
    for name in VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('GITHUB_TOKEN', 'env-token')
    vault = CredentialVault(tmp_path)
    assert _var(vault.status(), 'GITHUB_TOKEN')['source'] == 'environment'
    # Stored value overrides the environment, and clearing restores it.
    vault.set_many({'GITHUB_TOKEN': 'stored-token'})
    assert os.environ['GITHUB_TOKEN'] == 'stored-token'
    assert _var(vault.status(), 'GITHUB_TOKEN')['source'] == 'stored'
    vault.set_many({'GITHUB_TOKEN': ''})
    assert os.environ['GITHUB_TOKEN'] == 'env-token'
    assert _var(vault.status(), 'GITHUB_TOKEN')['source'] == 'environment'
