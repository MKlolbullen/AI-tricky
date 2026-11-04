import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.scope import ScopeError, authorize, parse_target, model_base_url, fetch_scoped, network_hosts


def test_scope_exact_origin_and_path():
    t = parse_target('https://example.com/api')
    assert authorize('https://example.com/api/users?x=1', [t]).path == '/api/users'
    for u in ['https://evil.example.com/api', 'http://example.com/api', 'https://example.com:444/api', 'https://example.com/apix', 'https://example.com/api/%252e%252e/admin', 'https://example.com@evil.com/api', 'https://example.com/api#fragment']:
        with pytest.raises(ScopeError):
            authorize(u, [t])


def test_loopback_models_only():
    assert model_base_url('http://127.0.0.1:11434/v1')
    for u in ['https://api.example.com/v1', 'http://169.254.169.254/v1', 'http://127.0.0.1.evil.com/v1', 'http://user:password@127.0.0.1/v1']:
        with pytest.raises(ScopeError):
            model_base_url(u)


@pytest.fixture
def target_server():
    class Handler(BaseHTTPRequestHandler):
        calls = []
        def do_GET(self):
            self.calls.append(self.path)
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', 'http://outside.invalid/')
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Set-Cookie', 'secret=value')
                self.end_headers()
                self.wfile.write(b'local test evidence')
        def log_message(self, *args):
            pass
    s = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=s.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{s.server_port}', Handler
    s.shutdown()
    s.server_close()


def test_transport_does_not_follow_redirects_or_send_cookie(target_server):
    base, handler = target_server
    response = fetch_scoped(base + '/redirect', [parse_target(base)])
    assert response['status'] == 302
    assert handler.calls == ['/redirect']
    response = fetch_scoped(base + '/', [parse_target(base)], max_bytes=5)
    assert response['body'] == 'local'
    assert response['truncated']
    assert 'set-cookie' not in response['headers']


def wait_done(client, rid):
    for _ in range(100):
        r = client.get('/api/runs/' + rid).json()
        if r['status'] in ('failed','completed','cancelled'):
            return r
        time.sleep(.02)
    raise AssertionError('run did not finish')


def test_scope_budget_evidence_and_persistence(tmp_path, target_server):
    base, handler = target_server
    async def fake_cai(targets, goal, fetch):
        denied = await fetch('https://outside.invalid/')
        assert 'error' in denied
        result = await fetch(targets[0])
        assert result['status'] == 200
        exhausted = await fetch(targets[0])
        assert exhausted['error'] == 'Run request budget exhausted.'
        return {'report':'Candidate based on local evidence','evidence_status':'CANDIDATE'}
    with TestClient(create_app(tmp_path, assessor=fake_cai)) as client:
        tid = client.post('/api/targets', json={'value':base}).json()['id']
        rid = client.post('/api/runs', json={'target_ids':[tid], 'allow_http':True, 'max_requests':1}).json()['id']
        r = wait_done(client, rid)
        assert r['status'] == 'completed'
        assert r['result']['request_count'] == 1
        assert len(handler.calls) == 1
        assert len(client.get('/api/runs/'+rid+'/artifacts').json()) == 2
        assert client.get('/api/assets').json()[0]['status'] == 200
        assert any(e['kind']=='http.denied' for e in client.get('/api/runs/'+rid+'/events').json())
    with TestClient(create_app(tmp_path, assessor=fake_cai)) as client:
        assert client.get('/api/runs/'+rid).json()['status'] == 'completed'
        assert len(client.get('/api/targets').json()) == 1


def test_plan_only_cannot_send(tmp_path, target_server):
    base, handler = target_server
    async def fake_cai(targets, goal, fetch):
        assert (await fetch(targets[0]))['error'].startswith('HTTP access disabled')
        return {'report':'Plan only'}
    with TestClient(create_app(tmp_path, assessor=fake_cai)) as c:
        tid = c.post('/api/targets', json={'value':base}).json()['id']
        rid = c.post('/api/runs', json={'target_ids':[tid]}).json()['id']
        assert wait_done(c,rid)['status']=='completed'
        assert not handler.calls


def test_local_boundary_and_invalid_targets(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        assert c.post('/api/targets',json={'value':'https://example.com'},headers={'Origin':'https://evil.example'}).status_code == 403
        assert c.get('/api/targets',headers={'Host':'evil.example'}).status_code == 403
        assert c.post('/api/targets',content='value=x',headers={'Content-Type':'application/x-www-form-urlencoded'}).status_code == 415
        assert c.post('/api/targets',json={'value':'https://example.com/*'}).status_code == 201
        assert c.post('/api/targets',json={'value':'https://*.example.com'}).status_code == 422
        assert c.post('/api/runs',json={'target_ids':['unknown']}).status_code == 422


def test_pause_cancel_prevents_next_dispatch(tmp_path,target_server):
    base,handler=target_server
    async def fake_cai(targets,goal,fetch):
        await asyncio.sleep(.1)
        await fetch(targets[0])
        await asyncio.sleep(.5)
        await fetch(targets[0])
        return {'report':'done'}
    with TestClient(create_app(tmp_path,assessor=fake_cai)) as c:
        tid=c.post('/api/targets',json={'value':base}).json()['id']
        rid=c.post('/api/runs',json={'target_ids':[tid],'allow_http':True}).json()['id']
        assert c.post('/api/runs/'+rid+'/pause',json={}).status_code==200
        time.sleep(.2)
        assert not handler.calls
        assert c.post('/api/runs/'+rid+'/resume',json={}).status_code==200
        for _ in range(40):
            if handler.calls: break
            time.sleep(.01)
        assert len(handler.calls)==1
        assert c.post('/api/runs/'+rid+'/cancel',json={}).status_code==200
        time.sleep(.6)
        assert len(handler.calls)==1
        assert c.get('/api/runs/'+rid).json()['status']=='cancelled'


def test_domains_ips_cidrs_and_url_scope_differ():
    domain=parse_target('example.com')
    assert domain.kind=='domain'
    assert authorize('http://example.com:8080/a',[domain])
    with pytest.raises(ScopeError): authorize('https://sub.example.com/',[domain])
    ip=parse_target('192.168.1.10')
    assert ip.kind=='ip'
    assert authorize('https://192.168.1.10:8443/a',[ip])
    net=parse_target('10.10.0.5/24')
    assert net.kind=='cidr' and net.url=='10.10.0.0/24'
    assert authorize('http://10.10.0.99:8080/',[net])
    with pytest.raises(ScopeError): authorize('http://10.10.1.1/',[net])
    with pytest.raises(ScopeError): authorize('http://outside.invalid/',[net])
    assert network_hosts('10.10.0.0/30',[net],64)==['10.10.0.1','10.10.0.2']
    with pytest.raises(ScopeError): network_hosts(net.url,[net],64)
    with pytest.raises(ScopeError): network_hosts('10.10.1.0/30',[net],64)
    with pytest.raises(ScopeError): network_hosts('example.com',[parse_target('https://example.com/api')],64)
    assert parse_target('2001:db8::1').kind=='ip'
    assert parse_target('2001:db8::/64').kind=='cidr'
    assert model_base_url('https://provider.example/v1',allow_remote=True)
    with pytest.raises(ScopeError): model_base_url('http://provider.example/v1',allow_remote=True)


def test_native_cidr_workflow_without_model(tmp_path,target_server):
    base,handler=target_server
    port=int(base.rsplit(':',1)[1])
    with TestClient(create_app(tmp_path)) as c:
        tid=c.post('/api/targets',json={'value':'127.0.0.1/32'}).json()['id']
        response=c.post('/api/runs',json={'engine':'inventory','target_ids':[tid],'allow_http':True,'ports':[port],'max_requests':2})
        assert response.status_code==201,response.text
        rid=response.json()['id']
        r=wait_done(c,rid)
        assert r['status']=='completed',r
        assert r['result']['request_count']==1
        rows=c.get('/api/assets').json()
        assert any(x.get('status')=='open' for x in rows)
        assert not handler.calls  # Only TCP connect; no HTTP on this non-web test port.


def test_cancelled_resolution_cannot_dispatch(target_server):
    base,handler=target_server
    with pytest.raises(ScopeError):
        fetch_scoped(base+'/',[parse_target(base)],allowed=lambda:False)
    assert not handler.calls


def test_native_large_cidr_rejected_before_run_creation(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        tid=c.post('/api/targets',json={'value':'10.0.0.0/16'}).json()['id']
        response=c.post('/api/runs',json={'engine':'inventory','target_ids':[tid],'allow_http':True,'max_hosts':64})
        assert response.status_code==422
        assert 'host limit' in response.json()['detail']
        assert not c.get('/api/runs').json()
