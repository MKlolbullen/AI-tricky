"""Private stdin/stdout protocol; no HTTP listener or proxy service."""
import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.cai_adapter import assess_local

MAX_FRAME = 2_000_000


def emit(value):
    raw = json.dumps(value) + '\n'
    if len(raw.encode()) > MAX_FRAME:
        raise RuntimeError('Worker result exceeded its size limit.')
    sys.__stdout__.write(raw)
    sys.__stdout__.flush()


async def main():
    request = json.loads(sys.stdin.readline(MAX_FRAME + 1))
    lock = asyncio.Lock()
    async def rpc(name, arguments):
        # Serialize replies even when the SDK schedules multiple tool calls.
        async with lock:
            emit({'type': 'tool', 'name': name, 'arguments': arguments})
            raw = await asyncio.to_thread(sys.stdin.readline, MAX_FRAME + 1)
            if not raw or len(raw.encode()) > MAX_FRAME:
                raise RuntimeError('Invalid parent response.')
            return json.loads(raw)['result']
    async def fetch(url):
        return await rpc('fetch_target', {'url': url})
    async def probe(target, ports):
        return await rpc('probe_ports', {'target': target, 'ports': ports})
    result = await assess_local(request['targets'], request['goal'], fetch,
                               network_tool=probe if request['network_enabled'] else None,
                               timeout=request['timeout'], evidence_only=request['evidence_only'],
                               role_instructions=request.get('role_instructions'), max_turns=request.get('max_turns', 12))
    emit({'type': 'result', 'result': result})


if __name__ == '__main__':
    # SDK progress messages never enter the protocol or persisted evidence.
    sys.stdout = sys.stderr
    try:
        asyncio.run(main())
    except Exception:
        emit({'type': 'error'})
        raise SystemExit(1)
