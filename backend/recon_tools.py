"""Inspect pinned tools' Go build metadata without running their executables."""

import mmap
import os
from pathlib import Path
import shutil

LOCK_DIR = Path(__file__).resolve().parents[1] / 'toolchains'


def read_profiles(group):
    return {
        tool: (package, version)
        for tool, package, version in (
            line.split('\t') for line in (LOCK_DIR / f'{group}.tsv').read_text().splitlines()
            if line and not line.startswith('#')
        )
    }


PROFILES_BY_GROUP = {group: read_profiles(group) for group in ('web-recon', 'trickest-oss')}
PROFILES = PROFILES_BY_GROUP['web-recon']
TOOL_GROUPS = {tool: group for group, profiles in PROFILES_BY_GROUP.items() for tool in profiles}

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


def tool_check(tool, path=None):
    group = TOOL_GROUPS[tool]
    package, tested_version = PROFILES_BY_GROUP[group][tool]
    found = path or shutil.which(tool)
    path = str(Path(found).resolve()) if found else None
    command = f'./scripts/install-tools.sh --{group} --tools={tool}'
    result = {'tool_id': tool, 'path': path, 'tested_version': tested_version,
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
    result['status'] = 'tested_version' if version == tested_version else 'different_version'
    if result['status'] == 'tested_version':
        result['remediation'] = None
    return result
