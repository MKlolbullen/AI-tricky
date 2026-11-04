"""Passive-source API credentials: a curated provider registry and a local,
server-owned vault.

Credential values are entered through the settings UI, stored under the data
directory with owner-only permissions, and synchronised into ``os.environ`` so
the existing, already-gated injection path (a secret reaches a tool only when
the tool declares it and the run selects it) picks them up unchanged. A stored
value takes precedence over an ambient environment variable of the same name.

Values are never returned to the client; only presence, source and length are
reported.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# Curated passive data sources. `variables` are the environment-variable names
# the catalog's tools read. `consumed` is computed at runtime from the tool
# catalog, so a variable no installed adapter declares is still storable here.
PROVIDERS: list[dict] = [
    {
        'id': 'shodan', 'name': 'Shodan',
        'docs': 'https://account.shodan.io/',
        'description': 'Host, service and exposure intelligence.',
        'variables': [{'name': 'SHODAN_API_KEY', 'label': 'API key'}],
    },
    {
        'id': 'censys', 'name': 'Censys',
        'docs': 'https://search.censys.io/account/api',
        'description': 'Internet host and certificate search.',
        'variables': [
            {'name': 'CENSYS_API_ID', 'label': 'API ID'},
            {'name': 'CENSYS_API_SECRET', 'label': 'API secret'},
        ],
    },
    {
        'id': 'projectdiscovery', 'name': 'ProjectDiscovery Cloud',
        'docs': 'https://cloud.projectdiscovery.io/',
        'description': 'Chaos subdomain dataset and PDCP services.',
        'variables': [{'name': 'PDCP_API_KEY', 'label': 'API key'}],
    },
    {
        'id': 'securitytrails', 'name': 'SecurityTrails',
        'docs': 'https://securitytrails.com/app/account/credentials',
        'description': 'Passive DNS and historical records.',
        'variables': [{'name': 'SECURITYTRAILS_API_KEY', 'label': 'API key'}],
    },
    {
        'id': 'netlas', 'name': 'Netlas',
        'docs': 'https://app.netlas.io/profile/',
        'description': 'Attack-surface and certificate search.',
        'variables': [{'name': 'NETLAS_API_KEY', 'label': 'API key'}],
    },
    {
        'id': 'urlscan', 'name': 'urlscan.io',
        'docs': 'https://urlscan.io/user/profile/',
        'description': 'URL and page-scan intelligence.',
        'variables': [{'name': 'URLSCAN_API_KEY', 'label': 'API key'}],
    },
    {
        'id': 'virustotal', 'name': 'VirusTotal',
        'docs': 'https://www.virustotal.com/gui/my-apikey',
        'description': 'Domain, IP and file reputation.',
        'variables': [{'name': 'VIRUSTOTAL_API_KEY', 'label': 'API key'}],
    },
    {
        'id': 'binaryedge', 'name': 'BinaryEdge',
        'docs': 'https://app.binaryedge.io/account/api',
        'description': 'Internet scan data and exposure.',
        'variables': [{'name': 'BINARYEDGE_API_KEY', 'label': 'API key'}],
    },
    {
        'id': 'github', 'name': 'GitHub',
        'docs': 'https://github.com/settings/tokens',
        'description': 'Token for GitHub code/subdomain reconnaissance (read-only scope recommended).',
        'variables': [{'name': 'GITHUB_TOKEN', 'label': 'Personal access token'}],
    },
]

VARS: list[str] = [v['name'] for p in PROVIDERS for v in p['variables']]
VAR_SET: set[str] = set(VARS)
MAX_VALUE_LEN = 4096


class CredentialVault:
    """Loads, persists and env-syncs passive-source credentials."""

    def __init__(self, root: Path):
        self.path = Path(root) / 'credentials.json'
        # Original environment values, captured before any override, so that
        # clearing a stored value restores (or removes) the ambient one.
        self._env_baseline: dict[str, str | None] = {}
        self._store: dict[str, str] = self._load()
        self.sync_env()

    # -- persistence ----------------------------------------------------------
    def _load(self) -> dict[str, str]:
        try:
            data = json.loads(self.path.read_text())
        except (FileNotFoundError, ValueError, OSError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {k: v for k, v in data.items()
                if k in VAR_SET and isinstance(v, str) and v}

    def _save(self) -> None:
        tmp = self.path.with_name(self.path.name + '.tmp')
        tmp.write_text(json.dumps(self._store, indent=2, sort_keys=True))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- environment ----------------------------------------------------------
    def sync_env(self) -> None:
        """Project the stored values onto os.environ. Stored values win over
        the ambient environment; cleared values fall back to the original."""
        for name in VAR_SET:
            if name not in self._env_baseline:
                self._env_baseline[name] = os.environ.get(name)
            if name in self._store:
                os.environ[name] = self._store[name]
            elif self._env_baseline[name] is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = self._env_baseline[name]

    def effective(self, name: str) -> str | None:
        return self._store.get(name) or os.environ.get(name)

    # -- mutation -------------------------------------------------------------
    def set_many(self, updates: dict) -> bool:
        """Apply {name: value}. An empty/None value clears the stored key.
        Unknown names and oversized values are rejected."""
        if not isinstance(updates, dict):
            raise ValueError('Credential updates must be an object.')
        for name in updates:
            if name not in VAR_SET:
                raise ValueError(f'Unknown credential variable: {name}')
        changed = False
        for name, value in updates.items():
            if value is None or str(value).strip() == '':
                if name in self._store:
                    del self._store[name]
                    changed = True
            else:
                value = str(value).strip()
                if len(value) > MAX_VALUE_LEN:
                    raise ValueError(f'{name} exceeds the maximum length.')
                if self._store.get(name) != value:
                    self._store[name] = value
                    changed = True
        if changed:
            self._save()
            self.sync_env()
        return changed

    # -- reporting ------------------------------------------------------------
    def status(self, consumed: dict[str, list[str]] | None = None) -> list[dict]:
        """Provider list with per-variable presence/source/length and the
        catalog tools that consume each variable. Never includes values."""
        consumed = consumed or {}
        providers = []
        for provider in PROVIDERS:
            variables = []
            for var in provider['variables']:
                name = var['name']
                stored = name in self._store
                env_only = (not stored) and bool(self._env_baseline.get(name))
                value = self.effective(name)
                variables.append({
                    'name': name,
                    'label': var['label'],
                    'configured': bool(value),
                    'source': 'stored' if stored else ('environment' if env_only else None),
                    'length': len(value) if value else 0,
                    'consumed_by': consumed.get(name, []),
                })
            providers.append({
                'id': provider['id'],
                'name': provider['name'],
                'docs': provider['docs'],
                'description': provider['description'],
                'variables': variables,
            })
        return providers
