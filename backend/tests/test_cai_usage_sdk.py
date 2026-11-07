"""Real CAI Runner and provider client, over loopback only, in both execution modes."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from backend.cai_adapter import assess
from backend.model_usage import ModelUsage
from backend.store import Store
from backend.tests.test_cai_sdk import select_runtime


@pytest.mark.parametrize('isolated', [False, True])
@pytest.mark.parametrize('scenario', ['success', 'missing_usage', 'turn_cap', 'provider_error'])
def test_real_sdk_usage_survives_tool_turns_missing_metadata_and_failures(monkeypatch, tmp_path, isolated, scenario):
    select_runtime(monkeypatch, isolated)
    class Handler(BaseHTTPRequestHandler):
        calls = []
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            self.calls.append(payload)
            # Admission must already be durable when the fixture receives a request.
            assert ledger.summary()['attempts'] == len(self.calls)
            if scenario == 'provider_error':
                body = json.dumps({'error': {'message': 'provider-secret-must-not-be-persisted'}}).encode()
                self.send_response(500)
            else:
                if len(self.calls) == 1:
                    message = {'role': 'assistant', 'content': None, 'tool_calls': [{'id': 'fixture-call', 'type': 'function',
                               'function': {'name': 'fetch_target', 'arguments': '{"url":"http://fixture.invalid/"}'}}]}
                else:
                    message = {'role': 'assistant', 'content': 'Observed fixture response; candidate only.'}
                response = {'id': 'fixture', 'object': 'chat.completion', 'created': 1, 'model': 'fixture',
                            'choices': [{'index': 0, 'message': message, 'finish_reason': 'tool_calls' if len(self.calls)==1 else 'stop'}]}
                if scenario != 'missing_usage':
                    response['usage'] = {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15,
                                         'prompt_tokens_details': {'cached_tokens': 2}, 'completion_tokens_details': {'reasoning_tokens': 1}}
                body = json.dumps(response).encode(); self.send_response(200)
            self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def log_message(self, *_): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv('CAI_MODEL_BASE_URL', f'http://127.0.0.1:{server.server_port}/v1')
    monkeypatch.setenv('CAI_MODEL', 'local-usage-fixture')
    ledger = ModelUsage(Store(tmp_path))
    async def tool(url): return {'status': 200, 'body': 'Loopback tool fixture'}
    try:
        operation = ledger.assess(assess, ['http://fixture.invalid/'], 'Read the fixture.', tool,
                                  max_turns=1 if scenario=='turn_cap' else 4, timeout=60)
        if scenario in ('turn_cap', 'provider_error'):
            with pytest.raises(Exception): asyncio.run(operation)
        else:
            result = asyncio.run(operation)
            assert 'candidate only' in result['report']
        summary = ledger.summary()
        expected = 1 if scenario in ('turn_cap', 'provider_error') else 2
        assert len(Handler.calls) == summary['attempts'] == expected
        if scenario == 'provider_error':
            assert summary['failed_attempts'] == 1 and summary['responses'] == 0
            assert summary['total_tokens'] is None and summary['coverage'] == 'partial'
        elif scenario == 'missing_usage':
            assert summary['responses'] == 2 and summary['missing_usage_responses'] == 2
            assert summary['total_tokens'] is None and summary['coverage'] == 'partial'
        else:
            assert summary['total_tokens'] == expected * 15
            assert summary['cached_input_tokens'] == expected * 2
            assert summary['reasoning_tokens'] == expected
        assert 'provider-secret' not in json.dumps(ledger.history())
    finally:
        server.shutdown(); server.server_close()
