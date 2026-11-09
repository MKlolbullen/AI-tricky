"""Actual SDK/client fallback and accounting, using only loopback model servers."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from backend.cai_adapter import assess
from backend.model_usage import ModelUsage
from backend.store import Store
from backend.team_routing import execute_route
from backend.tests.test_cai_sdk import select_runtime


@pytest.mark.parametrize('isolated',[False,True])
def test_real_sdk_availability_fallback_keeps_both_usage_records(tmp_path,monkeypatch,isolated):
    select_runtime(monkeypatch,isolated)
    class Handler(BaseHTTPRequestHandler):
        calls=[]
        def do_POST(self):
            payload=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            self.calls.append(payload)
            assert 'temperature' not in payload
            assert payload['max_completion_tokens']==2048
            assert not payload.get('tools')
            if payload['model']=='primary':
                self.send_response(503)
                raw=json.dumps({'error':{'message':'provider-sensitive-detail'}}).encode()
            else:
                self.send_response(200)
                raw=json.dumps({'id':'fixture','object':'chat.completion','created':1,'model':'backup',
                    'choices':[{'index':0,'message':{'role':'assistant','content':'Candidate review.'},'finish_reason':'stop'}],
                    'usage':{'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}}).encode()
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
            self.end_headers();self.wfile.write(raw)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    monkeypatch.setenv('CAI_MODEL_BASE_URL',f'http://127.0.0.1:{server.server_port}/v1')
    ledger=ModelUsage(Store(tmp_path))
    base={'provider':'openai','base_url':f'http://127.0.0.1:{server.server_port}/v1','api_key':'loopback-fixture'}
    async def call(model,limit):
        return await ledger.assess(assess,[],'Review fixture evidence.',None,model=model,evidence_only=True,
            role='poc',purpose='team_member',max_turns=limit,timeout=60)
    try:
        result=asyncio.run(execute_route(call,role='poc',allowance=4,
            route={'primary':{**base,'model':'primary'},'fallback':{**base,'model':'backup'}}))
        assert [p['model'] for p in Handler.calls]==['primary','backup']
        assert [p['status'] for p in result['model_attempts']]==['failed','completed']
        assert all(p['model_usage_id'] for p in result['model_attempts'])
        assert ledger.summary()['attempts']==2 and ledger.summary()['failed_attempts']==1
        assert ledger.summary()['total_tokens']==15
        assert 'provider-sensitive-detail' not in json.dumps(ledger.history())
    finally:server.shutdown();server.server_close()
