"""Inspect pinned tools' Go build metadata without running their executables."""

import mmap
import os
from pathlib import Path
import platform
import shutil
import sys

LOCK_DIR = Path(__file__).resolve().parents[1] / 'toolchains'


def read_profiles(group):
    return {
        tool: (package, version)
        for tool, package, version in (
            line.split('\t') for line in (LOCK_DIR / f'{group}.tsv').read_text().splitlines()
            if line and not line.startswith('#')
        )
    }


PROFILES_BY_GROUP = {group: read_profiles(group) for group in ('web-recon', 'trickest-oss', 'enforced-cli')}
PROFILES = PROFILES_BY_GROUP['web-recon']
TOOL_GROUPS = {}
for group, profiles in PROFILES_BY_GROUP.items():
    for tool in profiles:
        TOOL_GROUPS.setdefault(tool, group)


def installed_bin(group):
    return Path.home() / '.local' / 'share' / 'ai-tricky' / group / 'bin'


def resolve_tool(name, *, group=None):
    on_path = shutil.which(name)
    if on_path:
        return on_path
    candidates = [group] if group else [key for key, specs in PROFILES_BY_GROUP.items() if name in specs]
    return next((str(path) for key in candidates if (path := installed_bin(key) / name).is_file()
                 and os.access(path, os.X_OK)), None)

# Go's debug/buildinfo format uses a 32-byte header followed by two
# length-prefixed strings for builds using the inline format (Go 1.18+).
MAGIC = b'\xff Go buildinf:'
MAX_STRING = 256 * 1024


def _read_string(data, offset):
    size = 0
    for shift in range(0, 64, 7):
        byte = data[offset]
        offset += 1
        size |= (byte & 127) << shift
        if byte < 128:
            end = offset + size
            if size > MAX_STRING or end > len(data):
                raise ValueError('Invalid build metadata length.')
            return data[offset:end], end
    raise ValueError('Invalid build metadata length.')


def build_metadata(path):
    try:
        with open(path, 'rb') as binary:
            if os.fstat(binary.fileno()).st_size < 32:
                return None
            with mmap.mmap(binary.fileno(), 0, access=mmap.ACCESS_READ) as data:
                offset = data.find(MAGIC)
                while offset != -1:
                    if offset % 16 == 0 and data[offset + 15] & 2:
                        _, start = _read_string(data, offset + 32)
                        modules, _ = _read_string(data, start)
                        if len(modules) >= 33 and modules[-17] == 10:
                            return [line.split('\t') for line in modules[16:-16].decode().splitlines()]
                    offset = data.find(MAGIC, offset + len(MAGIC))
    except (OSError, ValueError, IndexError, OverflowError):
        return None
    return None


def tool_check(tool, path=None, *, group=None):
    found = path or resolve_tool(tool, group=group)
    group = group or TOOL_GROUPS[tool]
    package, tested_version = PROFILES_BY_GROUP[group][tool]
    path = str(Path(found).resolve()) if found else None
    command = f'./scripts/install-tools.sh --{group} --tools={tool}'
    result = {'tool_id': tool, 'path': path, 'default_bin': str(installed_bin(group)), 'tested_version': tested_version,
              'installed_version': None, 'status': 'missing', 'remediation': command}
    if not path or not Path(path).is_file() or not os.access(path, os.X_OK):
        return result
    result['status'] = 'unverified'
    metadata = build_metadata(path)
    if metadata is None:
        return result
    main = next((fields[1] for fields in metadata if len(fields) == 2 and fields[0] == 'path'), None)
    if main and main != package:
        result['status'] = 'wrong_binary'
        return result
    module = package.split('/cmd/')[0]
    version = next((fields[2] for fields in metadata
                    if len(fields) >= 3 and fields[:2] == ['mod', module]), None)
    if main != package or version in (None, '(devel)'):
        return result
    result['installed_version'] = version
    settings = dict(fields[1].split('=', 1) for fields in metadata
                    if len(fields) == 2 and fields[0] == 'build' and '=' in fields[1])
    goos, goarch = settings.get('GOOS'), settings.get('GOARCH')
    host_os = 'windows' if sys.platform == 'win32' else sys.platform
    host_arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'i386': '386', 'i686': '386'}.get(
        platform.machine().lower(), platform.machine().lower())
    if goos and goarch:
        result['build_target'] = f'{goos}/{goarch}'
        if (goos, goarch) != (host_os, host_arch):
            result['status'] = 'incompatible_platform'
            return result
    if group == 'enforced-cli' and settings.get('CGO_ENABLED') != '0':
        result['status'] = 'unverified'
        return result
    result['status'] = 'tested_version' if version == tested_version else 'different_version'
    if result['status'] == 'tested_version':
        result['remediation'] = None
    return result
