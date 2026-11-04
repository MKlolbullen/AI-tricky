"""Real CAI Runner -> loopback model fixture -> scoped tool -> local report."""
import asyncio
import json
import threading
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
from backend.cai_adapter import assess, installed_version


def select_runtime(monkeypatch, isolated):
    if isolated:
        monkeypatch.setenv('CAI_PYTHON', os.environ.get('CAI_TEST_PYTHON', sys.executable))
    else:
        monkeypatch.delenv('CAI_PYTHON', raising=False)
    if installed_version() != '0.5.10':
        pytest.skip('Optional CAI SDK not installed in the selected runtime')


@pytest.mark.parametrize('isolated', [False, True])
@pytest.mark.parametrize('tool_name',['fetch_target','probe_ports'])
def test_real_cai_sdk_uses_loopback_model_and_tool(monkeypatch,tool_name,isolated):
    select_runtime(monkeypatch, isolated)
    class ModelHandler(BaseHTTPRequestHandler):
        calls=[]
        def do_POST(self):
            payload=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            self.calls.append(payload)
            assert self.path == '/v1/chat/completions'
            if len(self.calls)==1:
                message={'role':'assistant','content':None,'tool_calls':[{'id':'call_local_test','type':'function','function':{'name':tool_name,'arguments':json.dumps({'url':'http://127.0.0.1:7777/'} if tool_name=='fetch_target' else {'target':'127.0.0.1/32','ports':[8080]})}}]}
                finish='tool_calls'
            else:
                assert any(m['role']=='tool' for m in payload['messages'])
                message={'role':'assistant','content':'Observed local fixture evidence. Candidate only.'}
                finish='stop'
            result={'id':'test','object':'chat.completion','created':1,'model':'local-fixture','choices':[{'index':0,'message':message,'finish_reason':finish}],'usage':{'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}}
            body=json.dumps(result).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),ModelHandler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    monkeypatch.setenv('CAI_MODEL_BASE_URL',f'http://127.0.0.1:{server.server_port}/v1')
    # A provider-looking model name must still route only to loopback.
    monkeypatch.setenv('CAI_MODEL','openai/provider-looking-local-model')
    calls=[]
    async def scoped_tool(url):
        calls.append(url)
        return {'status':200,'body':'local fixture evidence'}
    async def network_tool(target,ports):
        calls.append((target,ports))
        return {'results':[{'host':'127.0.0.1','port':8080,'state':'open'}]}
    try:
        result=asyncio.run(assess(['http://127.0.0.1:7777/'],'Read the target once.',scoped_tool,network_tool=network_tool if tool_name=='probe_ports' else None,timeout=30))
        assert result['report']=='Observed local fixture evidence. Candidate only.'
        assert calls==(['http://127.0.0.1:7777/'] if tool_name=='fetch_target' else [('127.0.0.1/32',[8080])])
        assert len(ModelHandler.calls)==2
        assert ModelHandler.calls[0]['model']=='openai/provider-looking-local-model'
        if isolated:
            assert result['sdk_execution'] == 'isolated-interpreter'
    finally:
        server.shutdown();server.server_close()


@pytest.mark.parametrize('isolated', [False, True])
def test_real_cai_evidence_only_attaches_no_tools(monkeypatch, isolated):
    select_runtime(monkeypatch, isolated)
    class Handler(BaseHTTPRequestHandler):
        calls=[]
        def do_POST(self):
            payload=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            self.calls.append(payload)
            assert not payload.get('tools')
            message={'role':'assistant','content':'{"summary":"Fixture evidence only","candidates":[],"coverage_limits":["One response"]}'}
            result={'id':'fixture','object':'chat.completion','created':1,'model':'local-fixture','choices':[{'index':0,'message':message,'finish_reason':'stop'}]}
            body=json.dumps(result).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    monkeypatch.setenv('CAI_MODEL_BASE_URL',f'http://127.0.0.1:{server.server_port}/v1')
    async def forbidden(url):raise AssertionError('No target tools should be attached')
    try:
        result=asyncio.run(assess([], 'Review captured evidence.', forbidden, evidence_only=True))
        assert json.loads(result['report'])['candidates']==[]
        assert len(Handler.calls)==1
    finally:
        server.shutdown();server.server_close()


@pytest.mark.parametrize('isolated', [False, True])
def test_real_sdk_generates_validated_evidence_proposals(monkeypatch, tmp_path, isolated):
    from fastapi.testclient import TestClient
    from backend.app import create_app
    from backend.tests.test_proposals import setup, model_payload
    select_runtime(monkeypatch, isolated)
    _, _, rid, oid, _, _ = setup(tmp_path)
    class Handler(BaseHTTPRequestHandler):
        calls = []
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            self.calls.append(payload)
            assert not payload.get('tools')
            goal = json.loads(payload['messages'][-1]['content'])['goal']
            context = model_payload(goal)
            action = next(a for a in context['available_actions'] if a['adapter_id'] == 'native_http')
            plan = {'summary': 'Fixture evidence-guided plan', 'coverage_limits': [], 'proposals': [
                {'action_id': action['id'], 'observation_ids': [oid], 'hypothesis': 'The response may have changed.',
                 'rationale': 'The captured URL supplies a concrete follow-up location.',
                 'expected_signal': 'Status and headers', 'negative_signal': 'A failed check remains inconclusive.'}]}
            result = {'id': 'fixture', 'object': 'chat.completion', 'created': 1, 'model': 'local-fixture',
                      'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': json.dumps(plan)}, 'finish_reason': 'stop'}]}
            body = json.dumps(result).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv('CAI_MODEL_BASE_URL', f'http://127.0.0.1:{server.server_port}/v1')
    try:
        with TestClient(create_app(tmp_path)) as client:
            response = client.post('/api/agent/proposals', json={'run_id': rid, 'observation_ids': [oid], 'goal': 'Review captured evidence', 'use_model': True})
            assert response.status_code == 201, response.text
            assert response.json()['planner'] == 'cai-model' and response.json()['model_called']
            assert response.json()['proposals'][0]['observation_ids'] == [oid]
            assert len(Handler.calls) == 1
    finally:
        server.shutdown(); server.server_close()
