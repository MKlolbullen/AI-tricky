"""Linux network isolation and a scoped HTTP relay for pinned scanners."""

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

from .recon_tools import resolve_tool, tool_check
from .scope import ScopeError, authorize, parse_target

MODE = 'enforced'
SCANNERS = {'ffuf': '-V', 'httprobe': '-h', 'katana': '-version', 'nuclei': '-version'}
# ffuf and httprobe get exact routes bound before launch. A crawler or template
# scanner chooses its own request URLs, so each of its requests is authorized
# against the entered scope when it reaches the gateway.
DYNAMIC = frozenset({'katana', 'nuclei'})
PROBE_STDIN = b'127.0.0.1\n'
PROXY = 'http://127.0.0.1:28080'
RELAY_TARGET = 'http://127.0.0.1:28080/FUZZ'
EXIT_HEADERS = {'content-length', 'transfer-encoding', 'connection', 'keep-alive', 'proxy-connection', 'upgrade', 'trailer', 'te'}
FILTER_FLAGS = {'-mc', '-fc', '-fs'}
OVERRIDES = {'ffuf': FILTER_FLAGS, 'httprobe': frozenset(), 'katana': frozenset({'-d', '-jc'}),
             'nuclei': frozenset({'-severity', '-tags', '-etags'})}
INPUT_REFS = {'ffuf': {'wordlist'}, 'httprobe': set(), 'katana': set(), 'nuclei': {'templates'}}
REFUSALS = {
    'ffuf': ('Enforced ffuf accepts only a registered or connected path wordlist.',
             'Enforced ffuf accepts only match/filter overrides.'),
    'httprobe': ('Enforced httprobe uses typed target inputs.',
                 'Enforced httprobe uses fixed GET settings. Remove argument overrides.'),
    'katana': ('Enforced katana uses typed URL inputs.',
               'Enforced katana accepts only crawl depth (1–5) and JavaScript crawling overrides.'),
    'nuclei': ('Enforced nuclei accepts only a registered templates folder.',
               'Enforced nuclei accepts only severity and tag overrides.'),
}
# Katana checks its proxy with this fixed request; it is refused without noise.
PROXY_PROBES = frozenset({'http://burpsuite/'})
MAX_URL = 4096
MAX_SEEDS = 64
SAFE_WORD = re.compile(r'[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*')
MAX_WORDS = 2048
MAX_HEADER = 8192
MAX_DENIAL_EVENTS = 32


def enforced(config):
    return config.get('cli_scope') == MODE


def validate_node(data, config):
    tool_id = data.get('toolId')
    if tool_id not in SCANNERS:
        raise ScopeError('Enforced CLI scope supports only ffuf, httprobe, katana and nuclei.')
    if (config.get('http_routing') or {}).get('mode') == 'proxy':
        raise ScopeError('Enforced CLI scope uses AI-tricky’s direct scoped transport. Select Direct HTTP routing.')
    if not config.get('targets'):
        raise ScopeError('Select entered targets for the scoped CLI gateway.')
    bindings, overrides = REFUSALS[tool_id]
    if data.get('inputRefs', {}).keys() - INPUT_REFS[tool_id]:
        raise ScopeError(bindings)
    params = {name: value for name, value in data.get('params', {}).items() if value is not False and value != ''}
    if params.keys() - OVERRIDES[tool_id]:
        raise ScopeError(overrides)
    if tool_id == 'katana' and '-d' in params:
        try:
            depth = int(params['-d'])
        except (TypeError, ValueError):
            raise ScopeError(overrides) from None
        if isinstance(params['-d'], bool) or not 1 <= depth <= 5 or str(params['-d']).strip() != str(depth):
            raise ScopeError(overrides)


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


def probe_sandbox(pins, scanner, check_flag):
    try:
        result = subprocess.run([*sandbox_prefix(pins), '--ro-bind', scanner, '/scanner',
                                 '--', '/relay', '/scanner', check_flag],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                env={}, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ScopeError('The Linux CLI sandbox could not start. Check bubblewrap and user namespace support.') from None
    if result.returncode:
        raise ScopeError('The isolated scanner could not start. Check Bubblewrap user/network namespace permissions and the pinned static scanner.')


def preflight_sandbox(scanner_pin, tool_id='ffuf'):
    if sys.platform != 'linux':
        raise ScopeError('Enforced CLI scope requires Linux and bubblewrap.')
    check = tool_check(tool_id, scanner_pin['path'], group='enforced-cli')
    if check['status'] != 'tested_version':
        raise ScopeError(f'Enforced CLI scope requires static {tool_id} {check["tested_version"]}. {check["remediation"]}')
    bwrap = shutil.which('bwrap')
    relay = resolve_tool('ai-tricky-cli-relay', group='enforced-cli')
    if not bwrap:
        raise ScopeError('Bubblewrap is missing. Install your distribution’s bubblewrap package.')
    if not relay:
        raise ScopeError('The CLI relay is missing. Run scripts/install-tools.sh --enforced-cli.')
    pins = {'bwrap': executable_pin(bwrap), 'relay': executable_pin(relay)}
    probe_sandbox(pins, scanner_pin['path'], SCANNERS[tool_id])
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


def probe_urls(values, config, tool_id='httprobe'):
    scope = [parse_target(value) for value in config['targets']]
    urls = {}
    for value in values:
        if '://' in value:
            urls[authorize(value, scope).url] = None
            continue
        host = parse_target(value)
        if host.kind not in ('ip', 'domain'):
            raise ScopeError(f'Enforced {tool_id} accepts concrete hosts or explicit HTTP(S) URLs.')
        authority = f'[{host.host}]' if ':' in host.host else host.host
        for scheme in ('https', 'http'):
            urls[authorize(f'{scheme}://{authority}/', scope).url] = None
    return list(urls)


class ScopedGateway:
    def __init__(self, rid, nid, config, ctl, store, fetch, allowed_urls, *, tool_id='ffuf', scope=None):
        self.rid, self.nid, self.config, self.ctl = rid, nid, config, ctl
        self.store, self.fetch, self.allowed_urls = store, fetch, allowed_urls
        self.tool_id = tool_id
        # Parsed entered targets: set only for scanners that choose their own URLs.
        self.scope = scope
        self.captures = {}
        self.pending = {}
        self.tasks = set()
        self.denied = 0
        self.requests = 0
        self.admitted = set()
        self.exchanges = {}
        self.exchange_ids = set()

    def denied_request(self, reason):
        self.denied += 1
        if self.denied <= MAX_DENIAL_EVENTS:
            self.store.event(self.rid, 'cli.scope_denied', {'node_id': self.nid, 'tool_id': self.tool_id, 'reason': reason})

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
            if self.scope is None and path.startswith(PROXY + '/'):
                path = path.removeprefix(PROXY)
            # Scanner-supplied headers are never forwarded to targets.
            for line in lines:
                name, separator, _ = line.partition(':')
                if not separator or name.strip().lower() in ('transfer-encoding', 'content-length', 'upgrade'):
                    raise ValueError()
        except (ValueError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            self.denied_request('Unsupported relay request.')
            return 403, [], b''
        if self.scope is not None:
            return await self.scoped_request(path)
        url = self.allowed_urls.get(path)
        if url is None:
            self.denied_request('Route was outside the approved invocation.')
            return 403, [], b''
        if self.ctl.cancelled:
            return 503, [], b''
        # Each bound route may dispatch once per invocation.
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

    def saved(self, url):
        capture = self.store.content(self.captures[url])['http_exchange']['response']
        return capture['status'], capture['headers'], base64.b64decode(capture['body_base64'])

    async def scoped_request(self, target):
        """Authorize one scanner-chosen URL against the entered scope, then fetch it once."""
        if target in PROXY_PROBES:
            return 403, [], b''
        if len(target) > MAX_URL or '#' in target or not target.startswith(('http://', 'https://')):
            self.denied_request('Unsupported relay request.')
            return 403, [], b''
        try:
            url = authorize(target, self.scope).url
        except ScopeError:
            self.denied_request('Request was outside the entered scope.')
            return 403, [], b''
        if self.ctl.cancelled:
            return 503, [], b''
        # A repeated URL is answered from its saved exchange: no second target request.
        while url in self.pending:
            await self.pending[url]
        if url in self.captures:
            return self.saved(url)
        done = self.pending[url] = asyncio.get_running_loop().create_future()
        try:
            self.requests += 1
            result = await self.fetch(url, node_id=self.nid)
            if exchange_id := result.get('http_exchange_id'):
                self.exchange_ids.add(exchange_id)
            if result.get('error'):
                self.denied_request('The scoped HTTP transport declined or failed the request.')
                return 503, [], b''
            self.exchanges[url] = result['http_exchange_id']
            self.captures[url] = result['artifact_id']
        finally:
            del self.pending[url]
            done.set_result(None)
        return self.saved(url)

    def in_scope(self, value):
        try:
            return authorize(value, self.scope).url if isinstance(value, str) and value.startswith(('http://', 'https://')) else None
        except ScopeError:
            return None

    def remap_stdout(self, text):
        if self.tool_id == 'katana':
            # Discovered URLs are reported only when they are inside the entered scope.
            return '\n'.join(dict.fromkeys(url for line in text.splitlines() if (url := self.in_scope(line.strip()))))
        if self.tool_id == 'nuclei':
            # A refused or failed request reaches the scanner as a local 403/503. Keep
            # a detection only when its URL has a saved target response in this invocation.
            kept = []
            for line in text.splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict) and row.get('type') == 'http' and self.in_scope(row.get('matched-at')) in self.captures:
                    kept.append(json.dumps(row, separators=(',', ':')))
            return '\n'.join(kept)
        # httprobe prints the private listener when it receives an HTTP response.
        # A local 503 can look reachable to httprobe, so require a saved response.
        if self.tool_id == 'httprobe':
            if '/' in self.exchanges and PROXY in text.splitlines():
                return json.dumps({'url': self.allowed_urls['/'], 'http_exchange_id': self.exchanges['/']})
            return ''
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
    tool_id = data['toolId']
    dynamic = tool_id in DYNAMIC
    if fetch is None or (not dynamic and len(targets) != 1):
        raise ScopeError('Enforced scanners require one scoped URL per invocation.')
    pins = config.get('cli_sandbox')
    verify_pins(pins)
    mounts = []
    params = data.get('params', {})
    scope = [parse_target(value) for value in config['targets']]
    if dynamic:
        seeds = probe_urls(targets, config, tool_id)
        if not 1 <= len(seeds) <= MAX_SEEDS:
            raise ScopeError(f'Enforced {tool_id} accepts 1–{MAX_SEEDS} authorized seed URLs per invocation.')
        listing = work / 'scoped-targets.txt'
        listing.write_text(''.join(url + '\n' for url in seeds), encoding='ascii')
        mounts = ['--ro-bind', str(listing), '/targets']
        allowed = None
    if tool_id == 'katana':
        mounts += ['--ro-bind', context['crawl_scope_file'], '/scope']
        args = ['-silent', '-list', '/targets', '-duc', '-dr', '-fs', 'fqdn', '-cs', '/scope', '-proxy', PROXY,
                '-c', '4', '-p', '2', '-rl', '20', '-timeout', '12', '-retry', '0', '-d', str(int(params.get('-d') or 2))]
        if params.get('-jc') in (True, '__flag__'):
            args.append('-jc')
    elif tool_id == 'nuclei':
        if not context.get('templates'):
            raise ScopeError('Bind a reviewed Nuclei templates folder.')
        mounts += ['--ro-bind', context['templates'], '/templates']
        # HTTP templates only: nothing else can leave the namespace, and the gateway
        # forwards GET requests without scanner-supplied headers or bodies.
        args = ['-silent', '-l', '/targets', '-jsonl', '-dr', '-ni', '-duc', '-t', '/templates', '-proxy', PROXY,
                '-pt', 'http', '-nh', '-c', '4', '-bs', '4', '-rl', '20', '-timeout', '12', '-retries', '0']
        for name in ('-severity', '-tags', '-etags'):
            if value := params.get(name):
                args.extend([name, value])
    elif tool_id == 'ffuf':
        allowed = target_urls(targets[0], context['wordlist_file'], config)
        bounded = work / 'scoped-paths.txt'
        bounded.write_text(''.join(path[1:] + '\n' for path in allowed), encoding='ascii')
        mounts = ['--ro-bind', str(bounded), '/words']
        args = ['-w', '/words', '-u', RELAY_TARGET, '-x', PROXY,
                '-noninteractive', '-s', '-json', '-t', '4', '-timeout', '12']
        for name in sorted(FILTER_FLAGS):
            if value := data.get('params', {}).get(name):
                args.extend([name, value])
    else:
        allowed = {'/': authorize(targets[0], scope).url}
        args = ['-s', '-p', 'http:' + str(urlsplit(PROXY).port), '-c', '2', '-t', '12000']
    gateway = ScopedGateway(rid, nid, config, ctl, store, fetch, allowed, tool_id=tool_id,
                            scope=scope if dynamic else None)
    with tempfile.TemporaryDirectory(prefix='aits-') as directory:
        socket_path = str(Path(directory) / 'relay.sock')
        try:
            server = await asyncio.start_unix_server(gateway.accept, path=socket_path, limit=MAX_HEADER)
        except OSError:
            raise ScopeError('Unable to create the private CLI gateway socket. No scanner was started.') from None
        try:
            # Mount only the static scanner, relay, immutable invocation inputs and
            # the gateway socket. No host filesystem, host network or host /proc.
            command = [*sandbox_prefix(pins), '--ro-bind', argv[0], '/scanner', *mounts,
                       '--ro-bind', socket_path, '/gateway', '--', '/relay', '/scanner', *args]
            yield command, gateway
        finally:
            server.close()
            await server.wait_closed()
            pending = tuple(gateway.tasks)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
