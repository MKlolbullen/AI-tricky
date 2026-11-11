"""Session-only bearer identities and bounded JSON object checks."""

from dataclasses import dataclass, field
import hmac
import ipaddress
import json
import re
import threading
import uuid

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from .scope import ScopeError, authorize, parse_url

PROFILE_ID = 'object_access'
MAX_IDENTITIES = 32


def origin(target):
    host = f'[{target.host}]' if ':' in target.host else target.host
    return f'{target.scheme}://{host}:{target.port}'


def valid_transport(target):
    if target.scheme == 'https' or target.host == 'localhost':
        return
    try:
        if ipaddress.ip_address(target.host).is_loopback:
            return
    except ValueError:
        pass
    raise ScopeError('Test identities require HTTPS or direct loopback HTTP.')


class IdentityInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    label: str = Field(min_length=1, max_length=80)
    origin: str = Field(min_length=1, max_length=256)
    token: SecretStr

    @field_validator('label')
    @classmethod
    def clean_label(cls, value):
        value = value.strip()
        if not value or not value.isprintable():
            raise ValueError('Enter a printable identity label.')
        return value

    @field_validator('token')
    @classmethod
    def valid_token(cls, value):
        token = value.get_secret_value()
        if not 1 <= len(token) <= 4096 or not re.fullmatch(r'[A-Za-z0-9._~+/-]+=*', token):
            raise ValueError('Enter the bearer token without a header name or Bearer prefix.')
        return value


class ObjectAccessInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    owner_identity_id: str = Field(pattern=r'^[0-9a-f-]{36}$')
    other_identity_id: str = Field(pattern=r'^[0-9a-f-]{36}$')
    control_url: str = Field(min_length=1, max_length=2048)
    json_pointer: str = Field(default='/id', min_length=1, max_length=256)
    owner_object: str = Field(min_length=1, max_length=128)
    control_object: str = Field(min_length=1, max_length=128)

    @field_validator('json_pointer')
    @classmethod
    def valid_pointer(cls, value):
        if not value.startswith('/') or re.search(r'~(?![01])', value) or not value.isprintable():
            raise ValueError('Use a JSON Pointer such as /id or /data/id.')
        return value

    @field_validator('owner_object', 'control_object')
    @classmethod
    def valid_object(cls, value):
        if not value.isprintable() or not value.strip():
            raise ValueError('Enter the expected resource ID.')
        return value


@dataclass(frozen=True)
class TestIdentity:
    id: str
    label: str
    origin: str
    token: str = field(repr=False)

    def public(self):
        return {'id': self.id, 'label': self.label, 'origin': self.origin}


class TestIdentities:
    """Immutable identities. Removal invalidates reviews that reference them."""

    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()

    def list(self):
        with self._lock:
            return [identity.public() for identity in self._items.values()]

    def add(self, body):
        target = parse_url(body.origin)
        valid_transport(target)
        if target.path != '/' or '?' in body.origin or '#' in body.origin:
            raise ScopeError('Enter the exact origin without a resource path or query.')
        token = body.token.get_secret_value()
        if body.label == token:
            raise ScopeError('Use a label separate from the bearer token.')
        identity = TestIdentity(str(uuid.uuid4()), body.label, origin(target), token)
        with self._lock:
            if len(self._items) >= MAX_IDENTITIES:
                raise ScopeError('Remove an unused test identity before adding another.')
            self._items[identity.id] = identity
        return identity.public()

    def remove(self, identifier):
        with self._lock:
            if self._items.pop(identifier, None) is None:
                raise KeyError(identifier)

    def prepare(self, options, resource_url, scopes):
        owner_id, other_id = options['owner_identity_id'], options['other_identity_id']
        resource = authorize(resource_url, scopes)
        control = authorize(options['control_url'], scopes)
        valid_transport(resource)
        if origin(resource) != origin(control) or resource.url == control.url:
            raise ScopeError('Choose a separate control object on the same authorized origin.')
        if options['owner_object'] == options['control_object']:
            raise ScopeError('Choose distinct expected IDs for the owner and control objects.')
        with self._lock:
            owner, other = self._items.get(owner_id), self._items.get(other_id)
        if not owner or not other:
            raise ScopeError('Register both test identities before preparing the review.')
        if hmac.compare_digest(owner.token, other.token):
            raise ScopeError('Use distinct bearer tokens for the two test identities.')
        if owner.origin != origin(resource) or other.origin != origin(resource):
            raise ScopeError('Both test identities must be bound to the resource origin.')
        return {'options': {**options, 'control_url': control.url},
                'identities': [owner.public(), other.public()]}

    def snapshot(self, access):
        with self._lock:
            identities = [self._items.get(entry['id']) for entry in access['identities']]
        if any(identity is None or identity.public() != entry
               for identity, entry in zip(identities, access['identities'])):
            raise ScopeError('A test identity was removed or is unavailable. Prepare a new review.')
        return {identity.id: identity for identity in identities}


@dataclass(frozen=True)
class AuthenticatedRequest:
    identity: TestIdentity
    pointer: str
    expected_object: str
    fingerprint_key: bytes = field(repr=False)

    def authorize_peer(self, target, address, proxy):
        valid_transport(target)
        if proxy or self.identity.origin != origin(target):
            raise ScopeError('Authenticated verification requires the approved direct origin.')
        if target.scheme == 'http' and not ipaddress.ip_address(address).is_loopback:
            raise ScopeError('Plaintext test identity requests require a loopback peer.')

    def matches(self, headers, body, truncated):
        content_types = [v.split(';', 1)[0].strip().lower() for k, v in headers
                         if k.lower() == 'content-type']
        if truncated or len(content_types) != 1:
            return False
        media = content_types[0]
        if media != 'application/json' and not media.endswith('+json'):
            return False

        def unique_keys(pairs):
            result = dict(pairs)
            if len(result) != len(pairs):
                raise ValueError('Duplicate JSON key.')
            return result

        try:
            value = json.loads(body, object_pairs_hook=unique_keys)
            for escaped in self.pointer[1:].split('/'):
                key = escaped.replace('~1', '/').replace('~0', '~')
                if isinstance(value, list):
                    if not re.fullmatch(r'0|[1-9][0-9]{0,8}', key):
                        return False
                    value = value[int(key)]
                else:
                    value = value[key]
        except (ValueError, TypeError, KeyError, IndexError, RecursionError):
            return False
        return type(value) in (str, int) and str(value) == self.expected_object
