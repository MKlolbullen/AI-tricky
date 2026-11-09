"""SDK dependency isolation. Target tools remain in the parent application."""
import asyncio
import json
import os
from pathlib import Path

from .scope import model_base_url
from .model_usage import validate_event
from .model_errors import ProviderUnavailable

MAX_FRAME = 2_000_000
WORKER_PATH = Path(__file__).with_name('cai_worker.py')


async def send_frame(writer, value):
    raw = json.dumps(value).encode() + b'\n'
    if len(raw) > MAX_FRAME:
        raise RuntimeError('CAI worker message exceeded its size limit.')
    writer.write(raw)
    await writer.drain()


async def assess_worker(targets, goal, request_tool, *, network_tool=None, timeout=180, evidence_only=False, model=None,
                        role_instructions=None, max_turns=12, usage_callback=None):
    from .cli_runner import stop_process
    cfg = model or {}
    base = model_base_url(cfg.get('base_url') or os.environ.get('CAI_MODEL_BASE_URL', 'http://127.0.0.1:11434/v1'),
                          os.environ.get('CAI_ALLOW_REMOTE_MODEL') == '1')
    # Preserve the venv executable path; resolving its symlink would select the
    # base interpreter and silently lose the SDK environment.
    interpreter = str(Path(os.environ['CAI_PYTHON']).expanduser().absolute())
    allowed = ('PATH', 'SystemRoot', 'WINDIR', 'LANG', 'LC_ALL', 'CAI_MODEL', 'CAI_MODEL_API_KEY',
               'CAI_LOCAL_API_KEY', 'CAI_ALLOW_REMOTE_MODEL')
    env = {k: os.environ[k] for k in allowed if k in os.environ}
    # A selected provider's config is passed to the worker through its own env
    # dict only — never the parent process environment.
    if cfg.get('api_key'):
        env['CAI_MODEL_API_KEY'] = cfg['api_key']
    if cfg.get('model'):
        env['CAI_MODEL'] = cfg['model']
    env['CAI_MODEL_BASE_URL'] = base
    env['CAI_MODEL_PROVIDER'] = cfg.get('provider','local')
    env['PYTHONUNBUFFERED'] = '1'
    proc = None
    try:
        async with asyncio.timeout(timeout):
            proc = await asyncio.create_subprocess_exec(interpreter, str(WORKER_PATH),
                       stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                       stderr=asyncio.subprocess.DEVNULL, env=env, limit=MAX_FRAME,
                       start_new_session=os.name == 'posix')
            await send_frame(proc.stdin, {'targets': targets, 'goal': goal, 'timeout': timeout,
                                         'evidence_only': evidence_only, 'network_enabled': network_tool is not None,
                                         'role_instructions': role_instructions, 'max_turns': max_turns,
                                         'metering': usage_callback is not None})
            sequence, pending, tool_count = 0, None, 0
            for _ in range(128):  # 24 start/response pairs + at most 64 target tool frames
                raw = await proc.stdout.readline()
                if not raw or len(raw) > MAX_FRAME:
                    raise RuntimeError('CAI worker stopped without a valid response.')
                frame = json.loads(raw)
                if not isinstance(frame, dict):
                    raise RuntimeError('CAI worker returned an invalid message.')
                if frame.get('type') == 'error':
                    if set(frame)=={'type','code'} and frame['code']=='provider_unavailable':
                        raise ProviderUnavailable()
                    raise RuntimeError('CAI SDK worker failed; check the selected runtime and model endpoint.')
                if frame.get('type') == 'result':
                    if usage_callback is not None and (not sequence or pending is not None):
                        raise RuntimeError('CAI worker returned incomplete model usage accounting.')
                    result = frame.get('result')
                    if not isinstance(result, dict) or not isinstance(result.get('report'), str) or result.get('evidence_status') != 'CANDIDATE':
                        raise RuntimeError('CAI worker returned an invalid assessment.')
                    return {**result, 'sdk_execution': 'isolated-interpreter'}
                if frame.get('type') == 'model_usage':
                    if usage_callback is None or set(frame) != {'type', 'event'}:
                        raise RuntimeError('CAI worker attempted an unavailable accounting operation.')
                    event = validate_event(frame['event'])
                    if event['phase'] == 'started':
                        if pending is not None or event['sequence'] != sequence + 1 or event['sequence'] > max(1, min(int(max_turns), 24)):
                            raise RuntimeError('CAI worker model usage is out of sequence.')
                        sequence = pending = event['sequence']
                    elif pending != event['sequence']:
                        raise RuntimeError('CAI worker model usage has no admitted attempt.')
                    else:
                        pending = None
                    await usage_callback(event)
                    await send_frame(proc.stdin, {'result': {'ok': True}})
                    continue
                if frame.get('type') != 'tool' or evidence_only:
                    raise RuntimeError('CAI worker attempted an unavailable operation.')
                tool_count += 1
                if tool_count > 64:
                    raise RuntimeError('CAI worker exceeded its target-tool message budget.')
                arguments = frame.get('arguments')
                if not isinstance(arguments, dict):
                    raise RuntimeError('CAI worker supplied invalid tool arguments.')
                if frame.get('name') == 'fetch_target' and set(arguments) == {'url'} and isinstance(arguments['url'], str) and len(arguments['url']) <= 4096:
                    operation = request_tool(arguments['url'])
                elif frame.get('name') == 'probe_ports' and network_tool is not None and set(arguments) == {'target', 'ports'} and isinstance(arguments['target'], str) and len(arguments['target']) <= 4096 and isinstance(arguments['ports'], list) and 1 <= len(arguments['ports']) <= 16 and all(type(p) is int and 1 <= p <= 65535 for p in arguments['ports']):
                    operation = network_tool(arguments['target'], arguments['ports'])
                else:
                    raise RuntimeError('CAI worker attempted an unavailable operation.')
                try:
                    result = await operation
                except asyncio.CancelledError:
                    raise
                except Exception:
                    result = {'error': 'The parent application rejected or could not complete the target operation.'}
                await send_frame(proc.stdin, {'result': result})
            raise RuntimeError('CAI worker exceeded its message budget.')
    except (OSError, ValueError, asyncio.IncompleteReadError):
        raise RuntimeError('CAI worker failed; check the selected SDK environment and model endpoint.') from None
    finally:
        if proc:
            await stop_process(proc)
