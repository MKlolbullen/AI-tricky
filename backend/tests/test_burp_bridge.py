import base64

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.http_journal import HTTPJournal, request_message
from backend.store import Store

ORIGIN = {'Origin': 'http://127.0.0.1:8787', 'Sec-Fetch-Site': 'same-origin'}
URL = 'https://app.example.test/app/item?sort=desc'
REQUEST = b'POST /app/item?sort=desc HTTP/1.1\r\nHost: app.example.test\r\nX-Sample: A\r\nX-Sample: B\r\nContent-Length: 2\r\n\r\n\x00\xff'
RESPONSE = b'HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n\x01\xfe'


def terminal_run(store, targets=None):
    run = store.new_run({'engine': 'inventory', 'targets': targets or ['https://app.example.test/app']})
    store.status(run['id'], 'completed', {'request_count': 0})
    return run['id']


def exchange(url=URL, request=REQUEST, response=RESPONSE):
    return {'url': url, 'request': base64.b64encode(request).decode(),
            'response': base64.b64encode(response).decode() if response is not None else None}


def pair(client, base):
    result = client.post(base + '/pair', json={}, headers=ORIGIN)
    assert result.status_code == 200, result.text
    return {'Authorization': 'Bearer ' + result.json()['token']}


def test_bridge_import_is_run_bound_atomic_and_byte_preserving(tmp_path):
    app = create_app(tmp_path)
    store = app.state.store
    run_id, other_id = terminal_run(store), terminal_run(store)
    base = f'/api/runs/{run_id}/burp-bridge'
    with TestClient(app) as client:
        assert client.post(base + '/pair', json={}).status_code == 403
        headers = pair(client, base)
        assert client.get(base + '/repeater').status_code == 401
        assert client.get(f'/api/runs/{other_id}/burp-bridge/repeater', headers=headers).status_code == 401
        for rejected in (
            exchange(url='https://app.example.test/other'),
            exchange(request=REQUEST.replace(b'Host: app.example.test', b'Host: other.example.test')),
            exchange(request=REQUEST.replace(b'POST /app/item?sort=desc', b'POST //other.example.test/app/item')),
            exchange(request=REQUEST.replace(b'POST /app/item?sort=desc', b'POST /app/other?sort=desc')),
        ):
            invalid = client.post(base + '/exchanges', json={'items': [exchange(), rejected]}, headers=headers)
            assert invalid.status_code == 422
            assert client.get('/api/http-history', params={'run_id': run_id}).json()['total'] == 0
        data = {'items': [exchange(), exchange(response=None)]}
        imported = client.post(base + '/exchanges', json=data, headers=headers).json()
        assert imported['stored'] == 2 and imported['duplicates'] == 0
        again = client.post(base + '/exchanges', json={'items': data['items'][::-1]}, headers=headers).json()
        assert again['stored'] == 0 and again['exchange_ids'] == imported['exchange_ids'][::-1]
        original_id = imported['exchange_ids'][0]
        detail = client.get('/api/http-history/' + original_id).json()
        for name, raw in [('request', REQUEST), ('response', RESPONSE)]:
            msg = detail[name]
            assert base64.b64decode(msg['raw_headers_base64']) + base64.b64decode(msg['body_base64']) == raw
        assert detail['source'] == 'burp_bridge' and detail['state'] == 'imported'
        assert 'token' not in client.get(base).json()
        assert store.run(run_id)['result']['request_count'] == 0
        assert not store.events(run_id)

        queue = f'/api/http-history/{original_id}/repeater'
        assert client.post(queue, json={}, headers=headers).status_code == 403
        assert client.post(queue, json={}, headers=ORIGIN).json()['already_queued'] is False
        assert client.post(queue, json={}, headers=ORIGIN).json()['already_queued'] is True
        item = client.get(base + '/repeater', headers=headers).json()['item']
        assert item['exchange_id'] == original_id and base64.b64decode(item['request']) == REQUEST
        assert (item['host'], item['port'], item['tls']) == ('app.example.test', 443, True)
        assert client.get(base + '/repeater', headers=headers).json()['item'] == item
        ack = f"{base}/repeater/{item['id']}/ack"
        assert client.post(ack, json={}, headers=headers).status_code == 200
        assert client.get(base + '/repeater', headers=headers).json()['item'] is None
        client.post(queue, json={}, headers=ORIGIN)
        client.post(ack, json={}, headers=headers)  # An old retry cannot acknowledge a new delivery.
        assert client.get(base + '/repeater', headers=headers).json()['item']['id'] != item['id']
        assert client.post(base + '/disconnect', json={}, headers=ORIGIN).json()['queued'] == 0
        assert client.get(base + '/repeater', headers=headers).status_code == 401


def test_repeater_rechecks_privacy_and_adapts_native_proxy_target(tmp_path):
    app = create_app(tmp_path)
    store = app.state.store
    rid = terminal_run(store, ['http://app.example.test/app'])
    journal = HTTPJournal(store)
    url = 'http://app.example.test/app/z?q=1'
    artifact = store.artifact(rid, 'http-1.json', {'url': url})
    request = request_message(url, request_target='http://192.0.2.1/app/z?q=1')
    routed = journal.begin(rid, 'http', 1, url, {'mode': 'proxy'}, request)
    journal.finish(routed, response={'status': 200}, artifact_id=artifact)
    with TestClient(app) as client:
        base = f'/api/runs/{rid}/burp-bridge'
        headers = pair(client, base)
        assert client.post(f'/api/http-history/{routed}/repeater', json={}, headers=ORIGIN).json()['adapted'] is True
        item = client.get(base + '/repeater', headers=headers).json()['item']
        assert base64.b64decode(item['request']).startswith(b'GET /app/z?q=1 HTTP/1.1\r\n')
        for privacy in ({'representation': 'authenticated_metadata_only'}, {'body_truncated': True}, {'headers_truncated': True}):
            private = journal.begin(rid, 'http', 2, url, {'mode': 'direct'}, {**request, **privacy})
            journal.finish(private, response={'status': 200})
            assert client.post(f'/api/http-history/{private}/repeater', json={}, headers=ORIGIN).status_code == 409
        assert client.post(base + '/pair', json={}, headers=ORIGIN).status_code == 200
        assert client.get(base + '/repeater', headers=headers).status_code == 401
        assert client.get(base).json()['queued'] == 0
