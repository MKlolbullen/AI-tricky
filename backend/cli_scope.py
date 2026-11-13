"""Linux network isolation and a path-only scoped HTTP relay for pinned ffuf."""

import asyncio
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit, urlunsplit

from .recon_tools import tool_check
from .scope import ScopeError, authorize, parse_target

MODE = 'enforced'
PROXY = 'http://127.0.0.1:28080'
RELAY_TARGET = 'http://127.0.0.1:28080/FUZZ'
EXIT_HEADERS = {'content-length', 'transfer-encoding', 'connection', 'keep-alive', 'proxy-connection', 'upgrade', 'trailer', 'te'}
FILTER_FLAGS = {'-mc', '-fc', '-fs'}
SAFE_WORD = re.compile(r'[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*')
MAX_WORDS = 2048
MAX_HEADER = 8192
MAX_DENIAL_EVENTS = 32


def enforced(config):
    return config.get('cli_scope') == MODE


def validate_node(data, config):
    if data.get('toolId') != 'ffuf':
        raise ScopeError('Enforced CLI scope currently supports only ffuf path discovery.')
    if (config.get('http_routing') or {}).get('mode') == 'proxy':
        raise ScopeError('Enforced CLI scope uses AI-tricky’s direct scoped transport. Select Direct HTTP routing.')
    if data.get('inputRefs', {}).keys() - {'wordlist'}:
        raise ScopeError('Enforced ffuf accepts only a registered or connected path wordlist.')
    if not config.get('targets'):
        raise ScopeError('Select entered targets for the scoped CLI gateway.')
    if any(name not in FILTER_FLAGS for name, value in data.get('params', {}).items() if value is not False and value != ''):
        raise ScopeError('Enforced ffuf supports match codes, filter codes and filter size. Remove other argument overrides.')


def executable_pin(path):
    if not path:
        raise ScopeError('Install bubblewrap and run scripts/install-tools.sh --enforced-cli, then add the profile bin directory to PATH.')
    executable = Path(path).resolve()
    try:
        info = executable.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & (stat.S_ISUID | stat.S_ISGID) or not os.access(executable, os.X_OK):
            raise OSError()
        with executable.open('rb') as handle:
            return {'path': str(executable), 'sha256': hashlib.file_digest(handle, 'sha256').hexdigest()}
    except OSError:
        raise ScopeError('Isolation helpers must be executable regular files without setuid or setgid.') from None


def sandbox_prefix(pins):
    # --new-session blocks TIOCSTI input injection into a controlling terminal.
    return [pins['bwrap']['path'], '--unshare-user', '--unshare-net', '--unshare-pid', '--unshare-ipc',
            '--unshare-uts', '--disable-userns', '--die-with-parent', '--new-session',
            '--cap-drop', 'ALL', '--clearenv', '--setenv', 'HOME', '/tmp',
            '--setenv', 'XDG_CONFIG_HOME', '/tmp', '--setenv', 'LANG', 'C',
            '--dev', '/dev', '--tmpfs', '/tmp', '--chdir', '/tmp',
            '--ro-bind', pins['relay']['path'], '/relay']


def probe_sandbox(pins, scanner):
    try:
        result = subprocess.run([*sandbox_prefix(pins), '--ro-bind', scanner, '/scanner',
                                 '--', '/relay', '/scanner', '-V'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                env={}, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ScopeError('The Linux CLI sandbox could not start. Check bubblewrap and user namespace support.') from None
    if result.returncode:
        raise ScopeError('The isolated scanner could not start. Check Bubblewrap user/network namespace permissions and install the static ffuf profile.')


def preflight_sandbox(ffuf_pin):
    if sys.platform != 'linux':
        raise ScopeError('Enforced CLI scope requires Linux and bubblewrap.')
    if tool_check('ffuf', ffuf_pin['path'])['status'] != 'tested_version':
        raise ScopeError('Enforced CLI scope requires pinned ffuf v2.1.0. Run scripts/install-tools.sh --enforced-cli.')
    pins = {'bwrap': executable_pin(shutil.which('bwrap')), 'relay': executable_pin(shutil.which('ai-tricky-cli-relay'))}
    probe_sandbox(pins, ffuf_pin['path'])
    return pins


def verify_pins(pins):
    if sys.platform != 'linux' or not pins or any(executable_pin(pins[key]['path']) != pins[key] for key in ('bwrap', 'relay')):
        raise ScopeError('The CLI sandbox helpers changed or are unavailable. Run workflow preflight again.')


def path_words(wordlist):
    try:
        with Path(wordlist).open('rb') as handle:
            raw = handle.read(131073)
    except OSError as exc:
        raise ScopeError('The enforced ffuf wordlist is unavailable.') from exc
    if len(raw) > 131072:
        raise ScopeError('Enforced ffuf wordlists are limited to 128 KiB.')
    try:
        words = list(dict.fromkeys(line.strip() for line in raw.decode('ascii').splitlines() if line.strip()))
    except UnicodeError:
        raise ScopeError('Enforced ffuf requires an ASCII path wordlist.') from None
    if not 1 <= len(words) <= MAX_WORDS:
        raise ScopeError('Enforced ffuf requires 1–2,048 distinct path entries.')
    for word in words:
        if len(word) > 240 or not SAFE_WORD.fullmatch(word) or any(part in ('.', '..') for part in word.split('/')):
            raise ScopeError('Use literal relative paths in the enforced ffuf wordlist.')
    return words


def target_urls(seed, wordlist, config):
    scope = [parse_target(value) for value in config['targets']]
    parsed = urlsplit(seed)
    if parsed.query or parsed.fragment or not parsed.path.endswith('/FUZZ') or seed.count('FUZZ') != 1:
        raise ScopeError('Enforced ffuf requires a query-free URL with FUZZ as its final path segment.')
    result = {}
    for word in path_words(wordlist):
        path = parsed.path.removesuffix('FUZZ') + word
        resolved = urlunsplit((parsed.scheme, parsed.netloc, path, '', ''))
        result['/' + word] = authorize(resolved, scope).url
    return result


class ScopedGateway:
    def __init__(self, rid, nid, config, ctl, store, fetch, allowed_urls):
        self.rid, self.nid, self.config, self.ctl = rid, nid, config, ctl
        self.store, self.fetch, self.allowed_urls = store, fetch, allowed_urls
        self.tasks = set()
        self.denied = 0
        self.requests = 0
        self.admitted = set()
        self.exchanges = {}
        self.exchange_ids = set()

    def denied_request(self, reason):
        self.denied += 1
        if self.denied <= MAX_DENIAL_EVENTS:
            self.store.event(self.rid, 'cli.scope_denied', {'node_id': self.nid, 'tool_id': 'ffuf', 'reason': reason})

    def accept(self, reader, writer):
        if len(self.tasks) >= 16:
            writer.close()
            return
        task = asyncio.create_task(self.handle(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def handle(self, reader, writer):
        try:
            status, headers, body = await self.response(reader)
            writer.write(f'HTTP/1.1 {status} Gateway\r\nContent-Length: {len(body)}\r\nConnection: close\r\n'.encode('ascii'))
            for name, value in headers:
                if name.lower() not in EXIT_HEADERS and not any(c in name + value for c in '\r\n'):
                    writer.write(f'{name}: {value}\r\n'.encode('latin-1', errors='replace'))
            writer.write(b'\r\n' + body)
            await asyncio.wait_for(writer.drain(), 3)
        except (OSError, TimeoutError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def response(self, reader):
        try:
            header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 4)
            if len(header) > MAX_HEADER:
                raise ValueError()
            start, *lines = header[:-4].decode('ascii').split('\r\n')
            method, path, version = start.split(' ')
            if method != 'GET' or version not in ('HTTP/1.0', 'HTTP/1.1'):
                raise ValueError()
            if path.startswith(PROXY + '/'):
                path = path.removeprefix(PROXY)
            # Scanner-supplied headers are never forwarded to targets.
            for line in lines:
                name, separator, _ = line.partition(':')
                if not separator or name.strip().lower() in ('transfer-encoding', 'content-length', 'upgrade'):
                    raise ValueError()
        except (ValueError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            self.denied_request('Unsupported relay request.')
            return 403, [], b''
        url = self.allowed_urls.get(path)
        if url is None:
            self.denied_request('Route was not in the bound wordlist.')
            return 403, [], b''
        if self.ctl.cancelled:
            return 503, [], b''
        # One destination request per bound route keeps traffic at most one
        # GET per wordlist entry and each ffuf row tied to one exchange.
        if path in self.admitted:
            self.denied_request('Route was already requested in this invocation.')
            return 403, [], b''
        self.admitted.add(path)
        self.requests += 1
        result = await self.fetch(url, node_id=self.nid)
        if exchange_id := result.get('http_exchange_id'):
            self.exchange_ids.add(exchange_id)
        if result.get('error'):
            self.denied_request('The scoped HTTP transport declined or failed the request.')
            return 503, [], b''
        self.exchanges[path] = result['http_exchange_id']
        # Use the journal capture for real status, duplicate headers and response bytes.
        capture = self.store.content(result['artifact_id'])['http_exchange']['response']
        return capture['status'], capture['headers'], base64.b64decode(capture['body_base64'])

    def remap_stdout(self, text):
        # ffuf emits JSONL. Keep only rows tied to a journaled gateway response.
        kept = []
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            url = row.get('url') if isinstance(row, dict) else None
            if not isinstance(url, str) or not url.startswith(PROXY + '/'):
                continue
            path = url.removeprefix(PROXY)
            if path not in self.exchanges:
                continue
            row.update(url=self.allowed_urls[path], http_exchange_id=self.exchanges[path])
            kept.append(json.dumps(row, separators=(',', ':')))
        return '\n'.join(kept)


@contextlib.asynccontextmanager
async def sandbox(rid, nid, data, config, ctl, store, fetch, work, argv, targets, context):
    if not enforced(config):
        yield argv, None
        return
    validate_node(data, config)
    if fetch is None or len(targets) != 1:
        raise ScopeError('Enforced ffuf requires one scoped URL and the application HTTP gateway.')
    pins = config.get('cli_sandbox')
    verify_pins(pins)
    allowed = target_urls(targets[0], context['wordlist_file'], config)
    bounded = work / 'scoped-paths.txt'
    bounded.write_text(''.join(path[1:] + '\n' for path in allowed), encoding='ascii')
    gateway = ScopedGateway(rid, nid, config, ctl, store, fetch, allowed)
    with tempfile.TemporaryDirectory(prefix='aits-') as directory:
        socket_path = str(Path(directory) / 'relay.sock')
        try:
            server = await asyncio.start_unix_server(gateway.accept, path=socket_path, limit=MAX_HEADER)
        except OSError:
            raise ScopeError('Unable to create the private CLI gateway socket. No scanner was started.') from None
        try:
            # Mount only the static scanner, relay, immutable wordlist and the
            # gateway socket. No host filesystem, host network or host /proc.
            command = [*sandbox_prefix(pins), '--ro-bind', argv[0], '/scanner',
                       '--ro-bind', str(bounded), '/words', '--ro-bind', socket_path, '/gateway',
                       '--', '/relay', '/scanner', '-w', '/words', '-u', RELAY_TARGET,
                       '-x', PROXY, '-noninteractive', '-s', '-json', '-t', '4', '-timeout', '12']
            for name in sorted(FILTER_FLAGS):
                if value := data.get('params', {}).get(name):
                    command.extend([name, value])
            yield command, gateway
        finally:
            server.close()
            await server.wait_closed()
            pending = tuple(gateway.tasks)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
