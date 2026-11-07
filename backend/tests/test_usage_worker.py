import asyncio
import json

import pytest

from backend.cai_worker_client import assess_worker
from backend.model_usage import ModelUsage
from backend.store import Store
from backend.tests.test_cai_worker import worker
from backend.tests.test_model_usage import TOKENS


def protocol(events, *, tail=''):
    frames = [{'type': 'model_usage', 'event': event} for event in events]
    return ('assert request["metering"] is True\n' +
            f'frames=json.loads({json.dumps(json.dumps(frames))})\n' +
            'for frame in frames:\n print(json.dumps(frame),flush=True)\n assert json.loads(sys.stdin.readline())["result"]=={"ok":True}\n' +
            tail + '\nprint(json.dumps({"type":"result","result":{"report":"Fixture","evidence_status":"CANDIDATE","model_usage":{"attempts":999}}}),flush=True)\n')


def test_worker_usage_frames_are_acknowledged_and_parent_context_owns_totals(monkeypatch, tmp_path):
    worker(monkeypatch, tmp_path, protocol([{'phase': 'started', 'sequence': 1},
        {'phase': 'response', 'sequence': 1, 'tokens': TOKENS}]))
    usage = ModelUsage(Store(tmp_path / 'state'))
    result = asyncio.run(usage.assess(assess_worker, [], 'Fixture', None, purpose='workflow_analysis',
                                     node_id='approved-node', role='transport', evidence_only=True))
    assert result['model_usage']['attempts'] == 1 and result['model_usage']['total_tokens'] == 15
    row = usage.history()['items'][0]
    assert row['node_id'] == 'approved-node' and row['role'] == 'transport'
    assert row['execution_mode'] == 'isolated-interpreter'


@pytest.mark.parametrize('events', [
    [{'phase': 'started', 'sequence': 1, 'run_id': 'spoof'}],
    [{'phase': 'response', 'sequence': 1, 'tokens': TOKENS}],
    [{'phase': 'started', 'sequence': 2}],
    [{'phase': 'started', 'sequence': 1}, {'phase': 'started', 'sequence': 1}],
    [{'phase': 'started', 'sequence': 1}, {'phase': 'response', 'sequence': 2, 'tokens': TOKENS}],
    [{'phase': 'started', 'sequence': 1}, {'phase': 'response', 'sequence': 1, 'tokens': {**TOKENS, 'total_tokens': 'provider-secret'}}],
])
def test_worker_cannot_spoof_reorder_or_duplicate_meter_events(monkeypatch, tmp_path, events):
    worker(monkeypatch, tmp_path, protocol(events))
    usage = ModelUsage(Store(tmp_path / 'state'))
    with pytest.raises(RuntimeError) as error:
        asyncio.run(usage.assess(assess_worker, [], 'Fixture', None, evidence_only=True))
    assert 'provider-secret' not in str(error.value)
    assert usage.summary()['attempts'] <= 1
    assert 'provider-secret' not in json.dumps(usage.history())


def test_worker_cannot_dispatch_before_the_parent_records_admission(monkeypatch, tmp_path):
    marker = tmp_path / 'model-dispatched'
    worker(monkeypatch, tmp_path, protocol([{'phase': 'started', 'sequence': 1}],
        tail=f'open({str(marker)!r},"w").write("dispatched")'))
    async def unavailable(event): raise RuntimeError('Usage recorder unavailable')
    with pytest.raises(RuntimeError):
        asyncio.run(assess_worker([], 'Fixture', None, usage_callback=unavailable, timeout=5))
    assert not marker.exists()


def test_worker_crash_after_admission_preserves_an_unknown_attempt(monkeypatch, tmp_path):
    worker(monkeypatch, tmp_path, protocol([{'phase': 'started', 'sequence': 1}], tail='os._exit(1)'))
    usage = ModelUsage(Store(tmp_path / 'state'))
    with pytest.raises(RuntimeError): asyncio.run(usage.assess(assess_worker, [], 'Fixture', None))
    summary = usage.summary()
    assert summary['attempts'] == summary['interrupted_attempts'] == 1
    assert summary['coverage'] == 'partial' and summary['total_tokens'] is None


def test_worker_24_turns_fit_the_protocol_without_increasing_tool_capabilities(monkeypatch, tmp_path):
    events = [event for sequence in range(1, 25) for event in (
        {'phase': 'started', 'sequence': sequence}, {'phase': 'response', 'sequence': sequence, 'tokens': TOKENS})]
    worker(monkeypatch, tmp_path, protocol(events))
    usage = ModelUsage(Store(tmp_path / 'state'))
    asyncio.run(usage.assess(assess_worker, [], 'Fixture', None, max_turns=24, evidence_only=True))
    assert usage.summary()['attempts'] == 24 and usage.summary()['total_tokens'] == 360


def test_meter_frames_require_explicit_parent_enablement(monkeypatch, tmp_path):
    worker(monkeypatch, tmp_path, 'print(json.dumps({"type":"model_usage","event":{"sequence":1,"phase":"started"}}),flush=True)\nsys.stdin.readline()\n')
    with pytest.raises(RuntimeError, match='unavailable accounting'):
        asyncio.run(assess_worker([], 'Fixture', None))
