"""Explicit, credential-free help probes. This does not test authentication or scope enforcement."""
import asyncio
import os
from pathlib import Path
import re
import tempfile

from .cli_runner import digest, stop_process, close_pipes
from .identity_contracts import collection_command, TESTED_RELEASES


async def check_cli_contract(profile,binary):
    expected=TESTED_RELEASES['impacket' if profile['platform']=='ad' else 'azurehound']
    report={'schema':'ai-tricky.identity-cli-check/v1','profile_id':profile['id'],'tested_release':expected,
            'authentication_tested':False,'collection_tested':False,'network_scope_tested':False,
            'probe':'help_only_no_real_credentials_or_targets'}
    proc=None;readers=[];buffers=[bytearray(),bytearray()]
    with tempfile.TemporaryDirectory(prefix='identity-cli-check-') as directory:
        work=Path(directory);env={k:os.environ[k] for k in ('PATH','SystemRoot','WINDIR','PATHEXT','LANG','LC_ALL') if k in os.environ}
        env.update({'HOME':str(work),'USERPROFILE':str(work),'NO_COLOR':'1'})
        cache=work/'unused.ccache';cache.write_bytes(b'')
        config=work/'unused.json';config.write_text('{}')
        scope={'platform':profile['platform'],'domain':'identity-contract.invalid','tenant_id':'11111111-1111-1111-1111-111111111111'}
        argv=collection_command(profile,binary,scope,{'username':'unused','dc_host':'dc.identity-contract.invalid','dc_ip':'127.0.0.1'},cache if profile['platform']=='ad' else config,work/'unused-output.json')+['--help']
        async def read(index,stream):
            while chunk:=await stream.read(8192):
                buffers[index].extend(chunk)
                if len(buffers[index])>100000:raise ValueError('output_limit')
        try:
            before=digest(binary)
            proc=await asyncio.create_subprocess_exec(*argv,cwd=work,env=env,stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=os.name=='posix')
            readers=[asyncio.create_task(read(0,proc.stdout)),asyncio.create_task(read(1,proc.stderr))]
            async with asyncio.timeout(8):await asyncio.gather(proc.wait(),*readers)
            if before!=digest(binary):raise ValueError('binary_changed')
            output=b'\n'.join(map(bytes,buffers)).decode(errors='replace')
            flags=[value for value in argv[1:] if value.startswith('-')]
            missing=[flag for flag in flags if not re.search(r'(?<![\w-])'+re.escape(flag)+r'(?![\w-])',output)]
            match=re.search(r'(?i)(?:impacket\s+v|azurehound(?:\s+version)?\s+v?)([0-9]+\.[0-9]+\.[0-9]+[\w.-]*)',output)
            version=match[1] if match else None
            report.update(status='passed' if proc.returncode==0 and not missing and 'usage' in output.lower() else 'failed',
                binary_sha256=before,exit_code=proc.returncode,missing_flags=missing,observed_version=version,tested_release_match=version==expected)
        except TimeoutError:report['status']='timeout'
        except ValueError as exc:report['status']=str(exc) if str(exc) in ('output_limit','binary_changed') else 'failed'
        except OSError:report['status']='unavailable'
        finally:
            if proc:await stop_process(proc)
            for task in readers:
                if not task.done():task.cancel()
            await asyncio.gather(*readers,return_exceptions=True)
            if proc:await close_pipes(proc)
    return report
