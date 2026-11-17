"""Run-bound transfer of saved exchanges between the local UI and Burp Repeater."""

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .http_journal import MAX_BODY, MAX_HEADERS, parse_saved_message
from .scope import ScopeError, authorize, parse_target, parse_url
from .store import now

MAX_BATCH = 25
MAX_MESSAGE = 4 * ((MAX_HEADERS + MAX_BODY + 2) // 3)
MAX_BATCH_BYTES = 8_000_000
MAX_QUEUE = 16
SESSION_SECONDS = 3600
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}')


class BridgeItem(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    url: str = Field(min_length=1, max_length=4096)
    request: str = Field(min_length=1, max_length=MAX_MESSAGE)
    response: str | None = Field(default=None, max_length=MAX_MESSAGE)


class ImportBatch(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    items: list[BridgeItem] = Field(min_length=1, max_length=MAX_BATCH)


def web_only(request):
    # The Burp bearer is for the extension routes only. Pairing and queuing are
    # deliberate UI writes governed by the local API's Host and Origin checks.
    if request.headers.get('sec-fetch-site') not in ('same-origin', 'same-site') or not request.headers.get('origin'):
        raise HTTPException(403, 'Use the local AI-tricky workspace for this action.')


async def read_batch(request: Request):
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BATCH_BYTES:
            raise HTTPException(413, 'Burp import exceeds the 8 MB transfer limit.')
        body.extend(chunk)
    try:
        return ImportBatch.model_validate_json(body)
    except ValidationError:
        raise ScopeError('Invalid Burp exchange batch. Supply up to 25 bounded base64 request/response pairs.') from None


def strict_bytes(value):
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ScopeError('Invalid base64 in Burp exchange.') from None


def authority(target):
    return target.scheme, target.host, target.port


def check_request(message, url):
    request_target = message['request_target']
    if any(name.lower() in (':scheme', ':path', ':method') for name, _ in message['headers']):
        raise ScopeError('Requests with conflicting HTTP pseudo-header fields are unsupported.')
    if message['method'].upper() == 'CONNECT' or request_target.startswith('//'):
        raise ScopeError('Only origin-form and matching absolute HTTP request targets are supported.')
    parsed = parse_url(url)
    origin = urlsplit(parsed.url)
    if request_target.startswith('/'):
        path = parse_url(f'{origin.scheme}://{origin.netloc}{request_target}')
    else:
        path = parse_url(request_target)
    raw_target = urlsplit(request_target)
    saved = urlsplit(url)
    if path.url != parsed.url or (raw_target.path or '/', raw_target.query) != (saved.path or '/', saved.query):
        raise ScopeError('Saved HTTP request target disagrees with the exchange URL.')
    hosts = [value for name, value in message['headers'] if name.lower() in ('host', ':authority')]
    if len(hosts) != 1 or any(char in hosts[0] for char in '/?#,@\\'):
        raise ScopeError('Saved HTTP request needs one unambiguous Host or authority header.')
    if authority(parse_url(parsed.scheme + '://' + hosts[0] + '/')) != authority(parsed):
        raise ScopeError('Saved HTTP request authority disagrees with the exchange URL.')


@dataclass
class Pairing:
    digest: bytes
    deadline: float
    expires_at: str
    queue: deque = field(default_factory=deque)


class BurpBridge:
    def __init__(self, store, journal):
        self.store = store
        self.journal = journal
        self.sessions = {}
        self.lock = threading.Lock()

    def _session(self, run_id):
        session = self.sessions.get(run_id)
        if session and session.deadline <= time.monotonic():
            del self.sessions[run_id]
            return None
        return session

    def status(self, run_id):
        with self.lock:
            session = self._session(run_id)
            return {'paired': session is not None, 'expires_at': session.expires_at if session else None,
                    'queued': len(session.queue) if session else 0}

    def pair(self, run):
        if not run['config'].get('targets'):
            raise HTTPException(409, 'Choose a run with an entered scope.')
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=SESSION_SECONDS)).isoformat()
        with self.lock:
            for run_id in list(self.sessions):
                self._session(run_id)
            if run['id'] not in self.sessions and len(self.sessions) >= 16:
                raise HTTPException(409, 'Disconnect an existing Burp pairing first.')
            self.sessions[run['id']] = Pairing(hashlib.sha256(token.encode()).digest(), time.monotonic() + SESSION_SECONDS, expires_at)
        return {'run_id': run['id'], 'token': token, 'expires_at': expires_at}

    def disconnect(self, run_id):
        with self.lock:
            self.sessions.pop(run_id, None)
        return {'paired': False, 'expires_at': None, 'queued': 0}

    def _authenticate(self, run_id, authorization):
        token = authorization.removeprefix('Bearer ')
        session = self._session(run_id)
        if not session or authorization == token or not TOKEN.fullmatch(token) or not hmac.compare_digest(session.digest, hashlib.sha256(token.encode()).digest()):
            raise HTTPException(401, 'Burp pairing is invalid or has expired.')
        return session

    def authenticate(self, run_id, authorization):
        with self.lock:
            self._authenticate(run_id, authorization)

    def import_items(self, run_id, authorization, batch):
        self.authenticate(run_id, authorization)
        scopes = [parse_target(value) for value in self.store.run(run_id)['config']['targets']]
        records = []
        for index, item in enumerate(batch.items, 1):
            try:
                target = authorize(item.url, scopes)
                raw_request = strict_bytes(item.request)
                raw_response = strict_bytes(item.response) if item.response is not None else None
                req = parse_saved_message(raw_request, url=item.url, bridge=True)
                check_request(req, item.url)
                res = parse_saved_message(raw_response, bridge=True) if raw_response is not None else None
            except ScopeError as exc:
                raise ScopeError(f'Burp item {index}: {exc}') from None
            # Hash encoded byte digests separately, preserving message framing.
            identity = json.dumps([run_id, target.url, hashlib.sha256(raw_request).hexdigest(),
                                   hashlib.sha256(raw_response).hexdigest() if raw_response is not None else None])
            identifier = str(uuid.uuid5(uuid.NAMESPACE_URL, 'ai-tricky-burp:' + identity))
            records.append((identifier, item.url, req, res))
        count = 0
        with self.lock:
            self._authenticate(run_id, authorization)
            with self.store.connect() as db:
                for identifier, url, req, res in records:
                    stamp = now()
                    route = {'mode': 'external', 'origin_peer_observed': False, 'provenance': 'operator-selected Burp exchange'}
                    count += db.execute('''INSERT OR IGNORE INTO http_exchanges
                        (id,run_id,number,started,finished,state,url,route,request,response,error,source)
                        VALUES(?,?,0,?,?,'imported',?,?,?,?,?,'burp_bridge')''',
                        (identifier, run_id, stamp, stamp, url, json.dumps(route), json.dumps(req),
                         json.dumps(res) if res is not None else None, None if res else 'Imported item has no response')).rowcount
        return {'items': len(records), 'stored': count, 'duplicates': len(records) - count, 'exchange_ids': [row[0] for row in records]}

    def queue(self, exchange_id):
        try:
            row = self.journal.get(exchange_id)
        except KeyError:
            raise HTTPException(404, 'Saved HTTP exchange not found.') from None
        run_id, req = row['run_id'], row['request']
        if row['state'] not in ('completed', 'imported') or row['cancel_requested'] or req.get('representation') == 'authenticated_metadata_only' or req.get('headers_truncated') or req.get('body_truncated'):
            raise HTTPException(409, 'Repeater requires a complete saved request with its original headers and body.')
        target = authorize(row['url'], [parse_target(value) for value in self.store.run(run_id)['config']['targets']])
        raw = strict_bytes(req['raw_headers_base64']) + strict_bytes(req['body_base64'])
        adapted = False
        if row['source'] == 'native' and row['route'].get('mode') == 'proxy' and target.scheme == 'http':
            # Native plain HTTP routes through the checked IP in absolute form.
            # Repeater receives the original hostname as its explicit HTTP service.
            line, _, rest = raw.partition(b'\r\n')
            parts = line.split(b' ')
            if len(parts) != 3:
                raise ScopeError('Saved request target could not be reconstructed.')
            parsed = urlsplit(row['url'])
            origin_form = (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
            raw = b' '.join((parts[0], origin_form.encode('ascii'), parts[2])) + b'\r\n' + rest
            adapted = True
        check_request(parse_saved_message(raw, url=row['url'], bridge=True), row['url'])
        with self.lock:
            session = self._session(run_id)
            if session is None:
                raise HTTPException(409, 'Pair Burp with this exchange’s run before opening Repeater.')
            if any(request['exchange_id'] == exchange_id for request in session.queue):
                return {'queued': True, 'exchange_id': exchange_id, 'already_queued': True, 'adapted': adapted}
            if len(session.queue) >= MAX_QUEUE:
                raise HTTPException(409, 'Repeater queue is full. Open the Burp extension to receive requests.')
            session.queue.append({'id': str(uuid.uuid4()), 'exchange_id': exchange_id, 'host': target.host, 'port': target.port,
                                  'tls': target.scheme == 'https', 'request': base64.b64encode(raw).decode('ascii')})
        return {'queued': True, 'exchange_id': exchange_id, 'already_queued': False, 'adapted': adapted}

    def pending(self, run_id, authorization):
        with self.lock:
            queue = self._authenticate(run_id, authorization).queue
            return {'item': queue[0] if queue else None}

    def acknowledge(self, run_id, authorization, exchange_id):
        with self.lock:
            queue = self._authenticate(run_id, authorization).queue
            if queue and queue[0]['id'] == exchange_id:
                queue.popleft()
        return {'acknowledged': True}
