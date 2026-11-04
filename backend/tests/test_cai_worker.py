import asyncio
import json
import os
import sys

import pytest

from backend import cai_worker_client
from backend.cai_adapter import installed_version


def worker(monkeypatch, tmp_path, source):
    script = tmp_path / 'fake_worker.py'
    script.write_text('import sys,json,os\nrequest=json.loads(sys.stdin.readline())\n' + source)
    monkeypatch.setattr(cai_worker_client, 'WORKER_PATH', script)
    monkeypatch.setenv('CAI_PYTHON', sys.executable)
    monkeypatch.setenv('CAI_MODEL_BASE_URL', 'http://127.0.0.1:11434/v1')


@pytest.mark.parametrize('frame,evidence_only,network_enabled', [
    ({'type': 'tool', 'name': 'shell', 'arguments': {'command': 'anything'}}, False, False),
    ({'type': 'tool', 'name': 'fetch_target', 'arguments': {'url': 'http://example.invalid/'}}, True, False),
    ({'type': 'tool', 'name': 'fetch_target', 'arguments': {'url': 'http://example.invalid/', 'headers': {}}}, False, False),
    ({'type': 'tool', 'name': 'probe_ports', 'arguments': {'target': 'example.invalid', 'ports': [443]}}, False, False),
    ({'type': 'tool', 'name': 'probe_ports', 'arguments': {'target': 'example.invalid', 'ports': [True]}}, False, True),
])
def test_worker_cannot_expand_parent_tool_capabilities(monkeypatch, tmp_path, frame, evidence_only, network_enabled):
    worker(monkeypatch, tmp_path, f'print({json.dumps(json.dumps(frame))},flush=True)\nsys.stdin.readline()\n')
    calls = []
    async def forbidden(*arguments):
        calls.append(arguments)
        raise AssertionError('No operation should be admitted')
    with pytest.raises(RuntimeError, match='unavailable operation'):
        asyncio.run(cai_worker_client.assess_worker([], 'Review', forbidden, evidence_only=evidence_only,
                    network_tool=forbidden if network_enabled else None, timeout=5))
    assert calls == []


def test_worker_protocol_failure_is_sanitized_and_does_not_persist_provider_output(monkeypatch, tmp_path):
    worker(monkeypatch, tmp_path, 'print("provider-secret-do-not-persist",flush=True)\n')
    async def forbidden(*_):
        raise AssertionError()
    with pytest.raises(RuntimeError) as error:
        asyncio.run(cai_worker_client.assess_worker([], 'Review', forbidden, timeout=5))
    assert 'provider-secret' not in str(error.value)


def test_sdk_error_frame_reports_runtime_failure_without_provider_details(monkeypatch, tmp_path):
    worker(monkeypatch, tmp_path, 'print(json.dumps({"type":"error","detail":"provider-secret"}),flush=True)\n')
    async def forbidden(*_):
        raise AssertionError()
    with pytest.raises(RuntimeError, match='SDK worker failed') as error:
        asyncio.run(cai_worker_client.assess_worker([], 'Review', forbidden, timeout=5))
    assert 'provider-secret' not in str(error.value)


def test_worker_does_not_inherit_unrelated_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv('UNRELATED_TEST_SECRET', 'must-not-be-inherited')
    worker(monkeypatch, tmp_path, '''print(json.dumps({'type':'result','result':{'report':str('UNRELATED_TEST_SECRET' in os.environ),'evidence_status':'CANDIDATE'}}),flush=True)
''')
    async def forbidden(*_):
        raise AssertionError()
    result = asyncio.run(cai_worker_client.assess_worker([], 'Review', forbidden, timeout=5))
    assert result['report'] == 'False'


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process cleanup check')
def test_worker_timeout_terminates_child_process(monkeypatch, tmp_path):
    pidfile = tmp_path / 'worker.pid'
    worker(monkeypatch, tmp_path, f"open({str(pidfile)!r},'w').write(str(os.getpid()))\nimport time\ntime.sleep(60)\n")
    async def forbidden(*_):
        raise AssertionError()
    with pytest.raises(RuntimeError):
        asyncio.run(cai_worker_client.assess_worker([], 'Review', forbidden, timeout=.5))
    pid = int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_missing_sdk_interpreter_is_not_silently_replaced(monkeypatch, tmp_path):
    monkeypatch.setenv('CAI_PYTHON', str(tmp_path / 'missing-python'))
    assert installed_version() is None
