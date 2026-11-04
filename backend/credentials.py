"""Passive-source API credentials: a curated provider registry and a local,
server-owned vault.

Credential values are entered through the settings UI and stored under the data
directory with owner-only permissions. The vault is the source of truth; it
never mutates the process environment, so credentials cannot leak between
different data directories sharing one process. A stored value takes precedence
over an ambient environment variable of the same name, which is read only as a
fallback. The run pipeline snapshots the selected credentials once per run (see
app.start_run) so a mid-run change cannot mix identities.

Values are never returned to the client; only presence, source and length are
reported.
"""
from __future__ import annotations

import json
import os
import stat
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


def _valid_value(value: str) -> str:
    # NUL cannot survive an environment assignment or a clean JSON round-trip,
    # so reject it before it can be stored and break a later startup.
    if '\x00' in value:
        raise ValueError('Credential values cannot contain a NUL character.')
    if len(value) > MAX_VALUE_LEN:
        raise ValueError('Credential value exceeds the maximum length.')
    return value


class CredentialVault:
    """Loads, validates and persists passive-source credentials locally."""

    def __init__(self, root: Path):
        self.path = Path(root) / 'credentials.json'
        self._store: dict[str, str] = self._load()

    # -- persistence ----------------------------------------------------------
    def _load(self) -> dict[str, str]:
        try:
            data = json.loads(self.path.read_text())
        except (FileNotFoundError, ValueError, OSError):
            return {}
        if not isinstance(data, dict):
            return {}
        out: dict[str, str] = {}
        for k, v in data.items():
            if (k in VAR_SET and isinstance(v, str) and v
                    and '\x00' not in v and len(v) <= MAX_VALUE_LEN):
                out[k] = v
        return out

    @staticmethod
    def _enforce_owner_only(path: Path) -> None:
        # POSIX mode bits don't apply on Windows; there the user profile ACL
        # governs access and os.chmod can't tighten it, so skip the check.
        if os.name == 'nt':
            return
        os.chmod(path, 0o600)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            raise OSError(f'Refusing to store credentials: {path} is group/world accessible (mode {oct(mode)}).')

    def _write(self, store: dict[str, str]) -> None:
        payload = json.dumps(store, indent=2, sort_keys=True)
        tmp = self.path.with_name(self.path.name + '.tmp')
        try:
            # Create owner-only from the outset so there is no readable window.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as handle:
                handle.write(payload)
            self._enforce_owner_only(tmp)
            os.replace(tmp, self.path)
            self._enforce_owner_only(self.path)
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass

    # -- lookup ---------------------------------------------------------------
    def effective(self, name: str) -> str | None:
        return self._store.get(name) or os.environ.get(name)

    # -- mutation -------------------------------------------------------------
    def set_many(self, updates: dict) -> bool:
        """Apply {name: value}. An empty/None value clears the stored key.
        The whole batch is validated and staged before anything is written, and
        the in-memory store is updated only after a successful persist, so a
        rejected or failed update leaves the vault unchanged."""
        if not isinstance(updates, dict):
            raise ValueError('Credential updates must be an object.')
        for name in updates:
            if name not in VAR_SET:
                raise ValueError(f'Unknown credential variable: {name}')
        staged = dict(self._store)
        changed = False
        for name, value in updates.items():
            if value is None or str(value).strip() == '':
                if staged.pop(name, None) is not None:
                    changed = True
            else:
                value = _valid_value(str(value).strip())
                if staged.get(name) != value:
                    staged[name] = value
                    changed = True
        if changed:
            self._write(staged)
            self._store = staged
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
                env_only = (not stored) and bool(os.environ.get(name))
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
