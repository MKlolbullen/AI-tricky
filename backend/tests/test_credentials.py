import json
import os

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.credentials import CredentialVault, VARS


@pytest.fixture
def clean_env(monkeypatch):
    # Isolate every credential variable so the ambient-environment fallback is
    # empty and nothing leaks between tests.
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
    assert _var(providers, 'SHODAN_API_KEY')['consumed_by'] == ['shodan-cli']
    assert _var(providers, 'PDCP_API_KEY')['consumed_by'] == ['chaos']
    assert _var(providers, 'VIRUSTOTAL_API_KEY')['consumed_by'] == []


def test_set_trims_persists_and_reports(clean_env, tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        post = c.post('/api/credentials', json={'updates': {'SHODAN_API_KEY': '  secret-123456  '}}).json()
        var = _var(post['providers'], 'SHODAN_API_KEY')
        assert var['configured'] and var['source'] == 'stored' and var['length'] == len('secret-123456')
        runtime = c.get('/api/runtime').json()['cli_credential_variables']
        assert any(v['name'] == 'SHODAN_API_KEY' and v['configured'] for v in runtime)
    # The vault does not touch the process environment.
    assert 'SHODAN_API_KEY' not in os.environ
    path = tmp_path / 'credentials.json'
    assert json.loads(path.read_text()) == {'SHODAN_API_KEY': 'secret-123456'}


def test_stored_file_is_owner_only(clean_env, tmp_path):
    if os.name == 'nt':
        pytest.skip('POSIX permission bits do not apply on Windows')
    with TestClient(create_app(tmp_path)) as c:
        c.post('/api/credentials', json={'updates': {'NETLAS_API_KEY': 'abc'}})
    assert oct((tmp_path / 'credentials.json').stat().st_mode & 0o777) == '0o600'


def test_empty_value_clears(clean_env, tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        c.post('/api/credentials', json={'updates': {'NETLAS_API_KEY': 'abc'}})
        body = c.post('/api/credentials', json={'updates': {'NETLAS_API_KEY': ''}}).json()
        assert _var(body['providers'], 'NETLAS_API_KEY')['configured'] is False
    assert json.loads((tmp_path / 'credentials.json').read_text()) == {}


def test_rejects_unknown_nul_and_oversized(clean_env, tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        assert c.post('/api/credentials', json={'updates': {'NOT_A_VAR': 'x'}}).status_code == 422
        assert c.post('/api/credentials', json={'updates': {'SHODAN_API_KEY': 'x' * 5000}}).status_code == 422
        assert c.post('/api/credentials', json={'updates': {'SHODAN_API_KEY': 'a\x00b'}}).status_code == 422


def test_batch_is_atomic_on_rejection(clean_env, tmp_path):
    # A valid update batched with an invalid one must not be applied or persisted.
    with TestClient(create_app(tmp_path)) as c:
        r = c.post('/api/credentials', json={'updates': {'NETLAS_API_KEY': 'good', 'SHODAN_API_KEY': 'x' * 5000}})
        assert r.status_code == 422
        providers = c.get('/api/credentials').json()['providers']
        assert _var(providers, 'NETLAS_API_KEY')['configured'] is False
    assert not (tmp_path / 'credentials.json').exists()


def test_corrupt_file_is_not_overwritten(clean_env, tmp_path):
    (tmp_path / 'credentials.json').write_text('{ not valid json')
    with TestClient(create_app(tmp_path)) as c:
        assert c.post('/api/credentials', json={'updates': {'SHODAN_API_KEY': 'x'}}).status_code == 422
    # The unreadable file is preserved, not clobbered with a fresh store.
    assert (tmp_path / 'credentials.json').read_text() == '{ not valid json'


def test_validation_error_does_not_echo_value(clean_env, tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        # A stray top-level key (extra='forbid') carrying a secret must not be
        # reflected back in the 422 body.
        r = c.post('/api/credentials', json={'SHODAN_API_KEY': 'supersecretvalue', 'updates': {}})
        assert r.status_code == 422
        assert 'supersecretvalue' not in r.text


def test_values_never_returned(clean_env, tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        post = c.post('/api/credentials', json={'updates': {'URLSCAN_API_KEY': 'topsecretvalue'}})
        assert 'topsecretvalue' not in json.dumps(post.json())
        assert 'topsecretvalue' not in json.dumps(c.get('/api/credentials').json())


def test_persists_across_restart(clean_env, tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        c.post('/api/credentials', json={'updates': {'BINARYEDGE_API_KEY': 'persisted'}})
    # With no environment mutation there is no fallback; a fresh vault must read
    # the value from disk and report it as stored.
    assert 'BINARYEDGE_API_KEY' not in os.environ
    with TestClient(create_app(tmp_path)) as c2:
        var = _var(c2.get('/api/credentials').json()['providers'], 'BINARYEDGE_API_KEY')
        assert var['configured'] is True and var['source'] == 'stored'


def test_environment_fallback_and_store_precedence(monkeypatch, tmp_path):
    for name in VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('GITHUB_TOKEN', 'env-token')
    vault = CredentialVault(tmp_path)
    assert _var(vault.status(), 'GITHUB_TOKEN')['source'] == 'environment'
    assert vault.effective('GITHUB_TOKEN') == 'env-token'
    # A stored value wins over the ambient environment without changing it.
    vault.set_many({'GITHUB_TOKEN': 'stored-token'})
    assert vault.effective('GITHUB_TOKEN') == 'stored-token'
    assert _var(vault.status(), 'GITHUB_TOKEN')['source'] == 'stored'
    assert os.environ['GITHUB_TOKEN'] == 'env-token'
    # Clearing the stored value falls back to the untouched environment.
    vault.set_many({'GITHUB_TOKEN': ''})
    assert vault.effective('GITHUB_TOKEN') == 'env-token'
    assert _var(vault.status(), 'GITHUB_TOKEN')['source'] == 'environment'
