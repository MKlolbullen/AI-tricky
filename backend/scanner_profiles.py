"""Local readiness checks for the pinned scanner profiles."""

import platform

from . import cli_scope
from .http_routing import CLI_PROXY_FLAGS
from .recon_tools import PROFILES_BY_GROUP, tool_check
from .scope import ScopeError

TITLES = {'web-recon': 'Web reconnaissance', 'trickest-oss': 'Trickest generators',
          'enforced-cli': 'Enforced Linux scanners'}
BUNDLED = {
    'web-recon': ('nuclei-starter', 'resolvers-trusted'),
    'trickest-oss': ('wordlist-subdomains', 'wordlist-paths'),
    'enforced-cli': ('wordlist-paths', 'nuclei-starter'),
}


def status(support):
    profiles = []
    entries = {entry['id']: entry for entry in support.manifest['bundled']}
    for group, specs in PROFILES_BY_GROUP.items():
        checks = []
        for tool in specs:
            check = tool_check(tool, group=group)
            check['capture'] = ('scoped_gateway' if group == 'enforced-cli' else 'offline' if group == 'trickest-oss'
                                else 'external_proxy_history' if tool in CLI_PROXY_FLAGS else 'tool_output_only')
            if group == 'enforced-cli' and check['status'] == 'tested_version':
                try:
                    cli_scope.preflight_sandbox({'path': check['path']}, tool)
                except ScopeError as exc:
                    check['sandbox_error'] = str(exc)
                else:
                    check['sandbox_verified'] = True
            checks.append(check)
        inputs = []
        for identifier in BUNDLED[group]:
            entry = entries[identifier]
            try:
                registered = support._checked_inputs(entry, validate=True)
                state = 'installed' if registered else 'missing'
            except (ScopeError, OSError, ValueError):
                state = 'invalid'
            inputs.append({'id': identifier, 'name': entry['name'], 'state': state})
        profiles.append({'id': group, 'title': TITLES[group], 'tools': checks, 'inputs': inputs,
                         'command': f'./scripts/install-tools.sh --{group}'})
    return {'platform': platform.system(), 'architecture': platform.machine(), 'profiles': profiles}
