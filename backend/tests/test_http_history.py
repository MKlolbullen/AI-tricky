import base64
import asyncio
import json
import select
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import http.client

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.http_journal import HTTPJournal, request_message
from backend.http_routing import HTTPRouting, resolve_routing, cli_routing
from backend.scope import fetch_scoped, parse_target, ScopeError
from backend.store import Store
from backend.tests.test_local import wait_done
from backend.tests.test_proposal_execution import plan_for, prepare, dispatch
from backend.catalog import TOOLS
from backend.app import RunControl
from backend.cli_runner import digest, execute_cli
from backend.tests.test_catalog import CONFIG, data_for, streams_for, fixture_binary


BODY=b'\x00\xffsaved entity bytes\x01'


@pytest.fixture
def traffic_target():
    class Handler(BaseHTTPRequestHandler):
        calls=[]
        def do_GET(self):
            self.calls.append((self.path,self.headers.get('Host')))
            self.send_response(302 if self.path=='/redirect' else 200)
            self.send_header('Content-Type','application/octet-stream')
            self.send_header('X-Trace','first');self.send_header('X-Trace','second')
            if self.path=='/redirect':self.send_header('Location','http://outside.invalid/')
            self.send_header('Content-Length',str(len(BODY)));self.end_headers();self.wfile.write(BODY)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    yield f'http://127.0.0.1:{server.server_port}',Handler
    server.shutdown();server.server_close()


@pytest.fixture
def proxy_server():
    class Proxy(BaseHTTPRequestHandler):
        calls=[]
        def do_GET(self):
            p=urlsplit(self.path);self.calls.append(('GET',self.path,self.headers.get('Host')))
            upstream=http.client.HTTPConnection(p.hostname,p.port,timeout=3)
            try:
                upstream.request('GET',(p.path or '/')+('?' + p.query if p.query else ''),headers=dict(self.headers))
                response=upstream.getresponse();body=response.read()
                self.send_response(response.status,response.reason)
                for k,v in response.getheaders():
                    if k.lower() not in ('connection','transfer-encoding'):self.send_header(k,v)
                self.end_headers();self.wfile.write(body)
            finally:upstream.close()
        def do_CONNECT(self):
            host,port=self.path.rsplit(':',1);host=host.strip('[]')
            self.calls.append(('CONNECT',self.path,self.headers.get('Host')))
            upstream=socket.create_connection((host,int(port)),timeout=3)
            self.send_response(200,'Connection established');self.end_headers();self.wfile.flush()
            try:
                while True:
                    ready,_,_=select.select([self.connection,upstream],[],[],3)
                    if not ready:break
                    for source in ready:
                        data=source.recv(65536)
                        if not data:return
                        (upstream if source is self.connection else self.connection).sendall(data)
            except (OSError,ConnectionError):pass
            finally:upstream.close();self.close_connection=True
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Proxy)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    yield f'http://127.0.0.1:{server.server_port}',Proxy
    server.shutdown();server.server_close()


@pytest.fixture
def tls_target(tmp_path):
    cert=tmp_path/'root.pem';key=tmp_path/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
        '-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(key),'-out',str(cert)],
        check=True,capture_output=True)
    class Handler(BaseHTTPRequestHandler):
        calls=[]
        def do_GET(self):
            self.calls.append(self.path);self.send_response(200);self.end_headers();self.wfile.write(b'trusted fixture')
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
    names=[];context.set_servername_callback(lambda sock,name,ctx:names.append(name))
    server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    yield f'https://localhost:{server.server_port}',cert,Handler,names
    server.shutdown();server.server_close()


def inventory(c,url,routing):
    tid=c.post('/api/targets',json={'value':url}).json()['id']
    result=c.post('/api/runs',json={'engine':'inventory','target_ids':[tid],'allow_http':True,'http_routing':routing})
    assert result.status_code==201,result.text
    return wait_done(c,result.json()['id'])


@pytest.mark.parametrize('mode',['direct','proxy'])
def test_requests_responses_binary_bytes_and_duplicates_saved_in_both_routes(tmp_path,traffic_target,proxy_server,mode):
    base,target=traffic_target;proxy,handler=proxy_server
    with TestClient(create_app(tmp_path)) as c:
        run=inventory(c,base+'/bytes',{'mode':mode,'proxy_url':proxy})
        history=c.get('/api/http-history',params={'run_id':run['id']}).json()
        assert history['total']==1 and history['items'][0]['status']==200
        detail=c.get('/api/http-history/'+history['items'][0]['id']).json()
        assert detail['request']['method']=='GET' and detail['request']['url']==base+'/bytes'
        assert base64.b64decode(detail['response']['body_base64'])==BODY
        assert [v for k,v in detail['response']['headers'] if k.lower()=='x-trace']==['first','second']
        assert detail['route']['origin_peer_observed']==(mode=='direct')
        artifact=c.get('/api/artifacts/'+detail['artifact_id']).json()
        assert artifact['connected_ip']==('127.0.0.1' if mode=='direct' else None)
        assert len(handler.calls)==(1 if mode=='proxy' else 0)
        assert target.calls[0][1]==urlsplit(base).netloc
        har=c.get('/api/http-history/har',params={'run_id':run['id']}).json()['log']
        assert base64.b64decode(har['entries'][0]['response']['content']['text'])==BODY
        assert har['_capture_page']['total']==1


def test_response_capture_boundaries_and_no_redirect_following(traffic_target):
    base,target=traffic_target
    response=fetch_scoped(base+'/redirect',[parse_target(base)],max_bytes=5)
    assert response['status']==302 and len(target.calls)==1
    saved=response['http_exchange']['response']
    assert saved['body_truncated'] and base64.b64decode(saved['body_base64'])==BODY[:5]


@pytest.mark.parametrize('trust',[False,True])
def test_https_proxy_connect_pins_requested_ip_preserves_sni_and_checks_ca(tmp_path,tls_target,proxy_server,trust):
    url,cert,target,names=tls_target;proxy,handler=proxy_server
    with TestClient(create_app(tmp_path/'state')) as c:
        routing={'mode':'proxy','proxy_url':proxy}
        if trust:routing['ca_input_id']=c.post('/api/inputs',json={'name':'Fixture CA','path':str(cert)}).json()['id']
        run=inventory(c,url+'/',routing)
        row=c.get('/api/http-history',params={'run_id':run['id']}).json()['items'][0]
        assert row['state']==('completed' if trust else 'failed')
        assert handler.calls[0][0]=='CONNECT' and handler.calls[0][1].startswith('127.0.0.1:')
        assert names==['localhost']
        assert target.calls==(['/'] if trust else [])
        detail=c.get('/api/http-history/'+row['id']).json()
        if trust:assert detail['route']['ca_sha256'] and detail['route']['origin_peer_observed'] is False
        else:assert detail['error']=='SSLCertVerificationError'


def test_failed_proxy_connection_is_saved_without_direct_fallback(tmp_path,traffic_target):
    base,target=traffic_target
    sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
    with TestClient(create_app(tmp_path)) as c:
        run=inventory(c,base+'/',{'mode':'proxy','proxy_url':f'http://127.0.0.1:{port}'})
        row=c.get('/api/http-history',params={'run_id':run['id']}).json()['items'][0]
        assert row['state']=='failed' and row['error']=='ConnectionRefusedError'
        assert target.calls==[]


@pytest.mark.parametrize('value',[
    {'mode':'proxy','proxy_url':'http://remote.invalid:8080'},
    {'mode':'proxy','proxy_url':'http://u:p@127.0.0.1:8080'},
    {'mode':'proxy','proxy_url':'http://127.0.0.1:8080/path'},
    {'mode':'proxy','proxy_url':'socks5://127.0.0.1:8080'},
    {'mode':'proxy','proxy_url':'http://127.0.0.1:0'},
    {'mode':'proxy','verify':False},
])
def test_unreviewed_proxy_destinations_and_tls_bypass_options_rejected(tmp_path,value):
    with TestClient(create_app(tmp_path)) as c:
        tid=c.post('/api/targets',json={'value':'https://example.test/'}).json()['id']
        assert c.post('/api/runs/preflight',json={'engine':'inventory','target_ids':[tid],'http_routing':value}).status_code==422
        assert c.get('/api/runs').json()==[]


def test_pending_exchange_survives_restart_as_interrupted(tmp_path):
    store=Store(tmp_path);journal=HTTPJournal(store)
    eid=journal.begin('fixture',None,1,'https://example.test/',{'mode':'direct'},request_message('https://example.test/'))
    restored=HTTPJournal(store).get(eid)
    assert restored['state']=='interrupted' and restored['request']['method']=='GET' and restored['response'] is None


def exported_xml(url):
    request=base64.b64encode(b'POST /saved HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nDATA').decode()
    response=base64.b64encode(b'HTTP/1.1 200 OK\r\nX-Duplicate: one\r\nX-Duplicate: two\r\n\r\n\x00\xff').decode()
    return f'<items><item><url>{url}</url><request base64="true">{request}</request><response base64="true">{response}</response></item></items>'


def test_burp_import_is_deduplicated_scoped_and_never_sent_or_verified(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        tid=c.post('/api/targets',json={'value':'https://example.test/'}).json()['id']
        rid=c.post('/api/runs',json={'engine':'inventory','target_ids':[tid]}).json()['id']
        before=wait_done(c,rid)
        for _ in range(2):
            result=c.post('/api/runs/'+rid+'/http-history/import',json={'xml':exported_xml('https://example.test/saved')})
            assert result.status_code==200,result.text
        page=c.get('/api/http-history',params={'run_id':rid}).json()
        assert page['total']==1 and page['items'][0]['source']=='burp_xml'
        record=c.get('/api/http-history/'+page['items'][0]['id']).json()
        assert base64.b64decode(record['request']['body_base64'])==b'DATA'
        assert base64.b64decode(record['response']['body_base64'])==b'\x00\xff'
        assert c.get('/api/runs/'+rid).json()==before
        har=c.get('/api/http-history/har',params={'run_id':rid}).json()['log']['entries'][0]
        assert har['request']['postData']['text']=='DATA'
        assert c.get('/api/findings').json()['total']==0
        for xml in [exported_xml('https://outside.test/'), '<!DOCTYPE x [<!ENTITY e "boom">]><items/>']:
            assert c.post('/api/runs/'+rid+'/http-history/import',json={'xml':xml}).status_code==422
        assert c.get('/api/http-history',params={'run_id':rid}).json()['total']==1


def test_proxy_settings_and_ca_are_bound_into_execution_review(tmp_path,tls_target,proxy_server):
    url,cert,_,_=tls_target;proxy,_=proxy_server
    with TestClient(create_app(tmp_path/'state')) as c:
        ca=c.post('/api/inputs',json={'name':'Review CA','path':str(cert)}).json()['id']
        app=c.app
        plan,proposal,_=plan_for(app,c,scope=url+'/')
        review=prepare(c,plan,proposal,http_routing={'mode':'proxy','proxy_url':proxy,'ca_input_id':ca}).json()
        assert review['snapshot']['config']['http_routing_binding']['ca_sha256']
        cert.write_bytes(cert.read_bytes()+b'\n')
        assert dispatch(c,review).status_code==409


def test_model_tools_get_bounded_selected_capture_without_the_raw_journal(tmp_path,traffic_target):
    base,_=traffic_target;responses=[]
    async def analyst(targets,goal,fetch):
        response=await fetch(base+'/');responses.append(response)
        assert 'http_exchange' not in response and 'http_exchange_id' in response
        return {'report':'Candidate evidence'}
    with TestClient(create_app(tmp_path,assessor=analyst)) as c:
        tid=c.post('/api/targets',json={'value':base}).json()['id']
        result=c.post('/api/runs',json={'target_ids':[tid],'allow_http':True})
        done=wait_done(c,result.json()['id'])
        assert done['status']=='completed' and responses
        assert c.get('/api/http-history').json()['total']==1


def test_inflight_response_is_retained_even_after_run_cancellation(tmp_path,traffic_target,monkeypatch):
    import backend.app as app_module
    base,_=traffic_target;started=threading.Event();release=threading.Event()
    original=app_module.fetch_scoped
    def delayed(*args,**kwargs):
        response=original(*args,**kwargs)
        started.set();release.wait(3);return response
    monkeypatch.setattr(app_module,'fetch_scoped',delayed)
    with TestClient(create_app(tmp_path)) as c:
        tid=c.post('/api/targets',json={'value':base+'/'}).json()['id']
        rid=c.post('/api/runs',json={'engine':'inventory','target_ids':[tid],'allow_http':True}).json()['id']
        assert started.wait(2)
        assert c.post('/api/runs/'+rid+'/cancel',json={}).status_code==200
        release.set()
        for _ in range(100):
            rows=c.get('/api/http-history',params={'run_id':rid}).json()['items']
            if rows and rows[0]['state']=='completed':break
            time.sleep(.01)
        else:pytest.fail('Expected the in-flight capture to be retained')
        assert rows[0]['cancel_requested']==1
        assert c.get('/api/runs/'+rid).json()['status']=='cancelled'


@pytest.mark.parametrize('tool,flag',[('httpx','-http-proxy'),('katana','-proxy'),('nuclei','-proxy'),('ffuf','-x')])
def test_cli_proxy_flags_are_server_owned_and_do_not_use_ambient_environment(tmp_path,fixture_binary,monkeypatch,tool,flag):
    store=Store(tmp_path/'state');descriptor=TOOLS[tool];data=data_for(descriptor)
    streams=streams_for(descriptor,store,tmp_path)
    if tool=='nuclei':data['inputRefs']={'templates':store.add_input('templates','folder',(tmp_path/'project').resolve())['id']}
    pin={'path':str(fixture_binary),'sha256':digest(fixture_binary)}
    config={**CONFIG,'cli_binaries':{tool:pin},'http_routing':{'mode':'proxy'}}
    for name in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY'):monkeypatch.setenv(name,'http://outside.invalid:9090')
    rid=store.new_run(config)['id']
    result=asyncio.run(execute_cli(rid,'fixture-tool',data,streams,config,RunControl(),store))
    artifact=store.content(result[0]['invocation_artifact_ids'][0]);captured=json.loads(artifact['stdout'])
    assert captured['args'][-2:]==[flag,'http://127.0.0.1:8080']
    assert not {'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY'} & set(captured['env_keys'])
    assert artifact['http_capture']=='external_proxy_history' and artifact['native_requests_counted'] is False
    assert cli_routing(TOOLS[tool],{'http_routing':{'mode':'direct'}})==[]
    assert cli_routing(TOOLS['dnsx'],{'http_routing':{'mode':'proxy'}})==[]
    with pytest.raises(ScopeError):cli_routing(TOOLS['httprobe'],{'http_routing':{'mode':'proxy'}})
