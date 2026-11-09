"""Run-owned target HTTP routing; never use ambient proxy settings."""
from dataclasses import dataclass
import hashlib
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit, urlunsplit
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .scope import ScopeError

DEFAULT_PROXY = 'http://127.0.0.1:8080'
CLI_PROXY_FLAGS = {'httpx':'-http-proxy','katana':'-proxy','nuclei':'-proxy','nuclei-takeover':'-proxy','ffuf':'-x'}
DIRECT_NETWORK_TOOLS={'dnsx','puredns','shuffledns','massdns','naabu','nmap','rustscan','tlsx'}


def proxy_endpoint(value):
    try:
        p=urlsplit(value);port=p.port if p.port is not None else 8080
        host=p.hostname
        if host=='localhost':host='127.0.0.1'
        ip=ipaddress.ip_address(host or '')
        if (p.scheme!='http' or not ip.is_loopback or p.username is not None or p.password is not None or
                p.query or p.fragment or p.path not in ('','/') or not 1<=port<=65535):raise ValueError()
    except (ValueError,TypeError):raise ScopeError('Use a local HTTP proxy, for example http://127.0.0.1:8080, without credentials or a path.') from None
    return f'http://[{ip}]:{port}' if ip.version==6 else f'http://{ip}:{port}'


class HTTPRouting(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    mode: Literal['direct','proxy'] = 'direct'
    proxy_url: str = Field(default=DEFAULT_PROXY,max_length=256)
    ca_input_id: str | None = Field(default=None,pattern=r'^[A-Za-z0-9_-]{1,64}$')

    @field_validator('proxy_url')
    @classmethod
    def check_proxy(cls,value):return proxy_endpoint(value)


@dataclass
class ResolvedHTTPRouting:
    config: dict
    context: ssl.SSLContext
    ca_sha256: str | None = None


def resolve_routing(value, store):
    from .catalog import registered_path
    config=HTTPRouting.model_validate(value or {}).model_dump()
    context=ssl.create_default_context();fingerprint=None
    if config['ca_input_id']:
        path=registered_path(store,config['ca_input_id'],'file')
        raw=path.read_bytes()
        if not raw or len(raw)>1_000_000:raise ScopeError('Choose a registered CA certificate smaller than 1 MB.')
        try:context.load_verify_locations(cadata=raw.decode('ascii') if b'-----BEGIN CERTIFICATE-----' in raw else raw)
        except (ValueError,UnicodeError,ssl.SSLError):raise ScopeError('Registered CA input is not a valid PEM or DER certificate.') from None
        fingerprint=hashlib.sha256(raw).hexdigest()
        if fingerprint!=store.input(config['ca_input_id'])['sha256']:
            raise ScopeError('Registered CA contents changed while preparing HTTP routing.')
    return ResolvedHTTPRouting(config,context,fingerprint)


def routing_binding(value,store):
    resolved=resolve_routing(value,store)
    return {**resolved.config,'ca_sha256':resolved.ca_sha256}


def host_port(host,port):return f'[{host}]:{port}' if ':' in host else f'{host}:{port}'


class ProxyTargetConnection(http.client.HTTPConnection):
    """HTTPS CONNECT names the locally checked IP; SNI/Host keep the target name.

    A proxy can rewrite/redirect its own upstream traffic. The requested origin
    IP is recorded separately and never presented as an observed peer address.
    """
    def __init__(self,target,address,routing):
        super().__init__(target.host,target.port,timeout=10)
        self.target,self.address,self.routing=target,address,routing
        proxy=urlsplit(routing.config['proxy_url'])
        self.proxy_host,self.proxy_port=proxy.hostname,proxy.port
        if target.scheme=='https':self.set_tunnel(address,target.port)

    def connect(self):
        self.sock=socket.create_connection((self.proxy_host,self.proxy_port),self.timeout)
        try:
            if self.target.scheme=='https':
                self._tunnel()
                self.sock=self.routing.context.wrap_socket(self.sock,server_hostname=self.target.host)
        except BaseException:
            self.close();raise


def proxy_request_target(target,address):
    p=urlsplit(target.url)
    return urlunsplit(('http',host_port(address,target.port),p.path or '/',p.query,''))


def cli_routing(tool,config):
    routing=HTTPRouting.model_validate(config.get('http_routing') or {}).model_dump()
    active=tool['adapter']['traffic'] not in ('offline','passive')
    if routing['mode']!='proxy' or not active or tool['id'] in DIRECT_NETWORK_TOOLS:return []
    flag=CLI_PROXY_FLAGS.get(tool['id'])
    if not flag:raise ScopeError('This active CLI adapter has no reviewed proxy binding. Use a supported adapter or direct routing explicitly.')
    return [flag,routing['proxy_url']]
