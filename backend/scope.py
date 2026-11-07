"""Entered domains/IPs/CIDRs/URLs and pinned-address target transports."""
import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit, unquote

class ScopeError(ValueError):
    pass

@dataclass(frozen=True)
class Target:
    url: str
    host: str = ''
    port: int = 0
    scheme: str = ''
    path: str = '/'
    kind: str = 'url'


def safe_path(path: str) -> str:
    decoded = path
    for _ in range(8):
        next_path = unquote(decoded)
        if next_path == decoded:
            break
        decoded = next_path
    if '%' in decoded or any(ord(c) < 32 for c in decoded) or '\\' in decoded or any(x in ('.', '..') for x in decoded.split('/')):
        raise ScopeError('Ambiguous path or traversal segment is outside supported scope.')
    return decoded


def domain_name(value: str) -> str:
    try:
        host = value.encode('idna').decode('ascii').lower().rstrip('.')
    except UnicodeError as exc:
        raise ScopeError('Invalid domain name.') from exc
    if not host or len(host) > 253 or any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') or
                                         not all(c.isascii() and (c.isalnum() or c == '-') for c in label)
                                         for label in host.split('.')):
        raise ScopeError('Invalid domain name.')
    return host


def host_matches(host: str, target: Target) -> bool:
    """Host membership only; URL scheme/port/path checks belong to authorize()."""
    if target.kind == 'wildcard':
        return host != target.host and host.endswith('.' + target.host)
    if target.kind == 'cidr':
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(target.url)
        except ValueError:
            return False
    return host == target.host


def parse_url(value: str, *, scope_entry=False) -> Target:
    if not value or len(value) > 4096 or any(ord(c) < 33 for c in value) or '\\' in value:
        raise ScopeError('Invalid HTTP(S) URL.')
    try:
        p = urlsplit(value)
        host = (p.hostname or '').encode('idna').decode('ascii').lower().rstrip('.')
        port = p.port or (443 if p.scheme == 'https' else 80)
    except (ValueError, UnicodeError) as exc:
        raise ScopeError('Invalid target URL.') from exc
    if p.scheme not in ('http', 'https') or not host or p.username is not None or p.password is not None:
        raise ScopeError('Only HTTP(S) targets without embedded credentials are supported.')
    if p.fragment or '*' in host or '%' in host or not 1 <= port <= 65535 or (scope_entry and p.query):
        raise ScopeError('URLs must use concrete hosts without fragments; enter *.example.com as a separate host scope.')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        host = domain_name(host)
    path = safe_path(p.path or '/')
    netloc = f'[{host}]' if ':' in host else host
    if port != (443 if p.scheme == 'https' else 80):
        netloc += f':{port}'
    return Target(urlunsplit((p.scheme, netloc, path, p.query, '')), host, port, p.scheme, path)


def parse_target(value: str) -> Target:
    value = value.strip()
    if not value or len(value) > 2048 or any(ord(c) < 33 for c in value) or '\\' in value:
        raise ScopeError('Enter a domain, IP, CIDR or HTTP(S) URL.')
    if '://' in value:
        return parse_url(value, scope_entry=True)
    if value.startswith('*.'):
        host = domain_name(value[2:])
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return Target('*.' + host, host, kind='wildcard')
        raise ScopeError('Wildcard scope requires a domain, not an IP address.')
    try:
        if '/' in value:
            net = ipaddress.ip_network(value, strict=False)
            return Target(str(net), kind='cidr')
        ip = ipaddress.ip_address(value.strip('[]'))
        return Target(str(ip), str(ip), kind='ip')
    except ValueError:
        pass
    if any(c in value for c in '/:@?#*'):
        raise ScopeError('Use a plain domain, IP, CIDR or explicit HTTP(S) URL.')
    host = domain_name(value)
    return Target(host, host, kind='domain')


def authorize(url: str, targets: list[Target]) -> Target:
    req = parse_url(url)
    for t in targets:
        if t.kind == 'cidr':
            try:
                if ipaddress.ip_address(req.host) in ipaddress.ip_network(t.url):
                    return req
            except ValueError:
                continue
        elif t.kind in ('domain', 'ip', 'wildcard'):
            if host_matches(req.host, t):
                return req
        else:
            base = t.path.rstrip('/')
            if (req.scheme,req.host,req.port)==(t.scheme,t.host,t.port) and (not base or req.path==base or req.path.startswith(base+'/')):
                return req
    raise ScopeError('URL is outside the entered domains, IPs, CIDRs or URL path scopes.')


def network_hosts(value: str, targets: list[Target], max_hosts: int) -> list[str]:
    requested = parse_target(value)
    if requested.kind == 'wildcard':
        raise ScopeError('A wildcard is a scope selector. Discover concrete subdomains before probing.')
    if requested.kind == 'url':
        raise ScopeError('Port probing requires an entered domain, IP or CIDR; URL-only scope does not authorize port enumeration.')
    if requested.kind == 'cidr':
        net = ipaddress.ip_network(requested.url)
        allowed = any(t.kind=='cidr' and net.version==ipaddress.ip_network(t.url).version and net.subnet_of(ipaddress.ip_network(t.url)) for t in targets)
        count = net.num_addresses if net.prefixlen >= net.max_prefixlen-1 else net.num_addresses-2
        if not allowed:
            raise ScopeError('CIDR is outside the entered scope.')
        if count > max_hosts:
            raise ScopeError(f'CIDR exceeds this run\'s {max_hosts}-host limit. Choose a smaller subnet or increase the bounded host limit.')
        return [str(ip) for ip in net.hosts()]
    if requested.kind == 'domain' and any(t.kind in ('domain', 'wildcard') and host_matches(requested.host,t) for t in targets):
        return [requested.host]
    if requested.kind == 'ip':
        ip = ipaddress.ip_address(requested.host)
        if any((t.kind=='ip' and t.host==str(ip)) or (t.kind=='cidr' and ip in ipaddress.ip_network(t.url)) for t in targets):
            return [str(ip)]
    raise ScopeError('Network target is outside entered scope.')


def model_base_url(value: str, allow_remote: bool = False) -> str:
    try:
        p = urlsplit(value)
        port = p.port
    except ValueError as exc:
        raise ScopeError('Invalid model endpoint.') from exc
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise ScopeError('Use an HTTP(S) model endpoint without embedded credentials.')
    try:
        loopback = ipaddress.ip_address(p.hostname).is_loopback
    except ValueError:
        loopback = p.hostname == 'localhost'
    if not loopback and (not allow_remote or p.scheme != 'https'):
        raise ScopeError('Remote model endpoints need HTTPS and CAI_ALLOW_REMOTE_MODEL=1. Platform hosting remains local.')
    return value.rstrip('/')


def resolve_target(host: str, port: int) -> str:
    addresses = sorted({x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    if not addresses:
        raise ScopeError('Target has no resolved address.')
    for value in addresses:
        ip = ipaddress.ip_address(value)
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise ScopeError('Target resolved to a blocked special-use address.')
    return addresses[0]


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str):
        super().__init__(host, port, timeout=10, context=ssl.create_default_context())
        self.address = address
    def connect(self):
        sock = socket.create_connection((self.address,self.port),self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock,server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def fetch_scoped(url: str, targets: list[Target], max_bytes: int = 131072, allowed=None, *, controlled_headers=None) -> dict:
    from .verification import TEST_ORIGIN, COMPARE_HEADERS
    import hashlib
    # Deliberately narrow: model/client input cannot become an arbitrary header surface.
    if controlled_headers is not None and controlled_headers not in ({}, {'Origin': TEST_ORIGIN}):
        raise ScopeError('Unsupported controlled HTTP headers.')
    target = authorize(url,targets)
    address = resolve_target(target.host,target.port)
    if allowed is not None and not allowed():
        raise ScopeError('Run paused or cancelled before HTTP dispatch.')
    p = urlsplit(url)
    path = urlunsplit(('','',p.path or '/',p.query,''))
    conn = PinnedHTTPS(target.host,target.port,address) if target.scheme=='https' else http.client.HTTPConnection(address,target.port,timeout=10)
    host = f'[{target.host}]' if ':' in target.host else target.host
    if target.port != (443 if target.scheme=='https' else 80):
        host += f':{target.port}'
    try:
        conn.request('GET',path,headers={'Host':host,'User-Agent':'AI-tricky/0.8.0','Accept-Encoding':'identity', **(controlled_headers or {})})
        response = conn.getresponse()
        body = response.read(max_bytes+1)
        selected = [(k.lower(), v.strip(' \t')) for k,v in response.getheaders() if k.lower() in (*COMPARE_HEADERS, 'location')]
        headers = {k:v[:2000] for k,v in selected}
        return {'url':url,'status':response.status,'headers':headers,'body':body[:max_bytes].decode('utf-8',errors='replace'),
                'body_sha256':hashlib.sha256(body[:max_bytes]).hexdigest(),'body_bytes':len(body[:max_bytes]),
                'ambiguous_headers':sorted({k for k,v in selected if sum(name==k for name,value in selected)>1}),
                'truncated_headers':sorted({k for k,v in selected if len(v)>2000}),
                'truncated':len(body)>max_bytes,'connected_ip':address}
    finally:
        conn.close()
