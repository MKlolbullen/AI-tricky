"""The argument overlay: extra flags for version-pinned tools, checked against real help output.

Structural tests always run. The help checks need the pinned binaries: CI names
the tools it installs in AI_TRICKY_ARG_HELP_REQUIRED so a missing binary fails
there instead of silently skipping.
"""
import copy
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.catalog import (ADAPTER_FLAGS, ARGUMENT_OVERLAY, CATALOG, OVERLAY_ORIGIN, ROOT, TOOLS, blocked_flag,
                             contract, merge_argument_overlay, validate_params)
from backend.cli_runner import build_command
from backend.cli_scope import validate_node
from backend.scope import ScopeError

OVERLAY = ARGUMENT_OVERLAY['tools']
PINNED = {tool['id']: tool for tool in CATALOG['tools']}
SAMPLES = {'flag': True, 'int': 3, 'float': 0.5, 'string': 'value'}


def toolchain_pins():
    pins = {}
    for path in sorted((ROOT / 'toolchains').glob('*.tsv')):
        for line in path.read_text().splitlines():
            if line and not line.startswith('#'):
                tool, package, version = line.split('\t')
                pins.setdefault(tool, set()).add((package, version))
    return pins


def node(tool_id, params):
    tool = TOOLS[tool_id]
    return {'kind': 'catalog_tool', 'toolId': tool_id, 'inputs': tool['inputs'], 'outputs': tool['outputs'],
            'output': tool['outputs'][0], 'params': params}


def test_overlay_leaves_the_pinned_catalog_untouched_and_marks_its_additions():
    assert CATALOG == json.loads((ROOT / 'src/mini-tricky-catalog.json').read_text())
    assert not any('origin' in arg for tool in CATALOG['tools'] for arg in tool.get('args', []))
    assert set(OVERLAY) == {'subfinder', 'httprobe', 'ffuf', 'katana', 'nuclei'}
    for tool_id, entry in OVERLAY.items():
        before, after = PINNED[tool_id].get('args', []), TOOLS[tool_id]['args']
        assert [arg['flag'] for arg in after[:len(before)]] == [arg['flag'] for arg in before]
        added = after[len(before):]
        assert [arg['flag'] for arg in added] == [arg['flag'] for arg in entry['args']] and added
        assert all(arg['origin'] == OVERLAY_ORIGIN and arg['verified_version'] == entry['version'] for arg in added)
        corrected = {fix['flag'] for fix in entry.get('corrections', [])}
        assert {arg['flag'] for arg in after[:len(before)] if arg.get('origin')} == corrected
    untouched = set(TOOLS) - set(OVERLAY)
    assert all(TOOLS[tool_id] is PINNED[tool_id] for tool_id in untouched if tool_id in PINNED)


def test_overlay_entries_are_bound_to_the_pinned_toolchain_versions():
    pins = toolchain_pins()
    for tool_id, entry in OVERLAY.items():
        assert (entry['package'], entry['version']) in pins[tool_id], tool_id


def test_every_overlay_argument_is_usable_and_reaches_argv_shell_free():
    for tool_id, entry in OVERLAY.items():
        offered = [*entry['args'], *(arg for arg in TOOLS[tool_id]['args'] if arg['flag'] in
                                     {fix['flag'] for fix in entry.get('corrections', [])})]
        for arg in offered:
            assert blocked_flag(arg) is None, (tool_id, arg['flag'])
            assert arg['flag'] not in TOOLS[tool_id]['command'] and arg['flag'] not in ADAPTER_FLAGS.get(tool_id, set())
            data = node(tool_id, {arg['flag']: SAMPLES[arg['type']]})
            contract(data)
    data = node('subfinder', {'-s': 'crtsh,github', '-rl': 5, '-ei': True, '-es': ''})
    argv = build_command(TOOLS['subfinder'], data, {'domain': 'example.test'}, {'path': '/pinned/subfinder'})
    assert argv == ['/pinned/subfinder', '-silent', '-d', 'example.test', '-duc', '-s', 'crtsh,github', '-rl', '5', '-ei']


@pytest.mark.parametrize('params', [
    {'-s': '-dL'}, {'-s': 'crtsh\nx'}, {'-rl': 'fast'}, {'-rl': 1_000_001}, {'-ei': 'yes'}, {'-dL': 'hosts.txt'},
    {'-o': 'out.txt'}, {'-proxy': 'http://127.0.0.1:8080'},
])
def test_overlay_arguments_keep_server_side_value_validation(params):
    with pytest.raises(ScopeError):
        validate_params(TOOLS['subfinder'], node('subfinder', params))


def test_corrected_katana_arguments_take_values_instead_of_bare_switches():
    assert {arg['flag']: arg['type'] for arg in PINNED['katana']['args'] if arg['flag'] in ('-kf', '-ef')} == {
        '-kf': 'flag', '-ef': 'flag'}
    validate_params(TOOLS['katana'], node('katana', {'-kf': 'robotstxt', '-ef': 'png,css'}))
    for flag in ('-kf', '-ef'):
        with pytest.raises(ScopeError):
            validate_params(TOOLS['katana'], node('katana', {flag: True}))


def test_enforced_scanner_profiles_still_reject_overlay_arguments():
    config = {'targets': ['https://example.test/'], 'http_routing': {'mode': 'direct'}}
    validate_node({**node('ffuf', {'-mc': '200'}), 'require_cli_scope': True}, config)
    for tool_id, params in (('ffuf', {'-fl': '10'}), ('ffuf', {'-e': '.php'}), ('httprobe', {'-c': 5})):
        with pytest.raises(ScopeError):
            validate_node({**node(tool_id, params), 'require_cli_scope': True}, config)


@pytest.mark.parametrize('change,message', [
    (lambda o: o['tools'].update(missing={'package': 'p', 'version': 'v', 'args': []}), 'unknown catalog tool'),
    (lambda o: o['tools']['subfinder']['args'].append(dict(o['tools']['subfinder']['args'][0])), 'already defined'),
    (lambda o: o['tools']['subfinder']['args'].append({'flag': '-t', 'label': 'T', 'description': 'd', 'type': 'int'}), 'already defined'),
    (lambda o: o['tools']['subfinder']['args'].append({'flag': '-duc', 'label': 'U', 'description': 'd', 'type': 'flag'}), 'adapter-owned'),
    (lambda o: o['tools']['subfinder']['args'].append({'flag': '-silent', 'label': 'S', 'description': 'd', 'type': 'flag'}), 'already defined'),
    (lambda o: o['tools']['subfinder']['args'].append({'flag': '-o', 'label': 'Out', 'description': 'd', 'type': 'string'}), 'context binding'),
    (lambda o: o['tools']['subfinder']['args'].append({'flag': '-dL', 'label': 'List', 'description': 'Read names from a file', 'type': 'string'}), 'context binding'),
    (lambda o: o['tools']['subfinder']['args'].append({'flag': '-x; id', 'label': 'X', 'description': 'd', 'type': 'flag'}), 'Invalid overlay flag'),
    (lambda o: o['tools']['subfinder']['args'].append({'flag': '-x', 'label': 'X', 'description': 'd', 'type': 'flag', 'command': ['id']}), 'Invalid overlay argument'),
    (lambda o: o['tools']['subfinder'].pop('version'), 'pinned package and version'),
    (lambda o: o['tools']['katana']['corrections'].append({'flag': '-unknown', 'type': 'string'}), 'Invalid overlay correction'),
])
def test_unsafe_or_malformed_overlays_fail_closed_at_load(change, message):
    overlay = copy.deepcopy(ARGUMENT_OVERLAY)
    change(overlay)
    base = {**PINNED, **{k: v for k, v in TOOLS.items() if k not in PINNED}}
    with pytest.raises(RuntimeError, match=message):
        merge_argument_overlay(base, overlay)


def test_tool_detail_serves_merged_arguments_while_the_catalog_export_stays_pinned(tmp_path):
    with TestClient(create_app(tmp_path)) as client:
        detail = client.get('/api/catalog/tools/nuclei').json()
        added = [arg for arg in detail['args'] if arg.get('origin') == OVERLAY_ORIGIN]
        assert len(added) == len(OVERLAY['nuclei']['args']) and all(arg['blocked_reason'] is None for arg in added)
        assert all(arg['verified_version'] == 'v3.11.1' for arg in added)
        exported = {tool['id']: tool for tool in client.get('/api/catalog').json()['tools']}
        assert exported['nuclei']['args'] == PINNED['nuclei']['args']


# ---- checks against the real pinned binaries --------------------------------------------------

HELP_LINE = re.compile(r'^\s+(-{1,2}[A-Za-z][\w-]*(?:, -{1,2}[A-Za-z][\w-]*)*)(.*)$')
VALUE_TYPES = {'int': 'int', 'uint': 'int', 'int64': 'int', 'float': 'float', 'float64': 'float'}


def parse_help(text):
    """Map every flag spelling to its alias group and value type (None for a switch)."""
    flags = {}
    for line in text.splitlines():
        match = HELP_LINE.match(line)
        if not match:
            continue
        aliases = match.group(1).split(', ')
        typed = re.match(r'^ (\S+)(\s{2,}|\t|$)', match.group(2))
        info = {'aliases': frozenset(aliases), 'type': typed.group(1) if typed else None}
        for alias in aliases:
            flags.setdefault(alias, info)
    return flags


def binary_for(tool_id):
    for variable in ('AI_TRICKY_ARG_HELP_BIN', 'AI_TRICKY_RECON_BIN', 'AI_TRICKY_SCOPE_BIN'):
        directory = os.environ.get(variable)
        if directory and (Path(directory) / TOOLS[tool_id]['command'][0]).is_file():
            return Path(directory) / TOOLS[tool_id]['command'][0]
    return None


@pytest.mark.parametrize('tool_id', sorted(OVERLAY))
def test_arguments_match_the_pinned_binary_help(tool_id, tmp_path):
    binary = binary_for(tool_id)
    if binary is None:
        if tool_id in os.environ.get('AI_TRICKY_ARG_HELP_REQUIRED', '').split(','):
            pytest.fail(f'The pinned {tool_id} binary is required for argument verification but was not found.')
        pytest.skip(f'Install the pinned {tool_id} binary to verify its arguments')
    env = {'PATH': os.defpath, 'HOME': str(tmp_path), 'XDG_CONFIG_HOME': str(tmp_path / 'config'), 'NO_COLOR': '1'}
    done = subprocess.run([str(binary), '-h'], capture_output=True, text=True, timeout=60, env=env, cwd=tmp_path)
    flags = parse_help(done.stdout + done.stderr)
    assert len(flags) >= 5, 'help output was not recognised'
    typed_help = any(info['type'] for info in flags.values())
    tool = TOOLS[tool_id]
    owners = {}
    reserved = [token for token in tool['command'][1:] if token.startswith('-')] + sorted(ADAPTER_FLAGS.get(tool_id, set()))
    for flag in [*reserved, *(arg['flag'] for arg in tool['args'])]:
        assert flag in flags, f'{tool_id} {flag} is not a flag of the pinned binary'
        group = flags[flag]['aliases']
        assert owners.setdefault(group, flag) == flag, f'{tool_id} {flag} is an alias of {owners[group]}'
    if typed_help:
        for arg in tool['args']:
            kind = flags[arg['flag']]['type']
            if arg['type'] == 'flag' or kind is None:
                assert (arg['type'] == 'flag') == (kind is None), f'{tool_id} {arg["flag"]} is {arg["type"]} but help shows {kind!r}'
            elif arg.get('origin') == OVERLAY_ORIGIN:
                assert VALUE_TYPES.get(kind.rstrip('[]'), 'string') == arg['type'], f'{tool_id} {arg["flag"]} is {arg["type"]} but help shows {kind!r}'
