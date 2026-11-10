"""Opt-in real tool CLI contracts and guarded Impacket failure behavior. No live directory."""
import asyncio
import os
from pathlib import Path
import subprocess

import pytest
from backend.identity_cli_check import check_cli_contract
from backend.identity_contracts import collection_command, collection_health
from backend.identity_tools import PROFILES


def real_binary(profile):
    if profile['platform']=='ad':
        directory=os.environ.get('AI_TRICKY_IMPACKET_BIN')
        if not directory:pytest.skip('Optional real Impacket CLI environment is not selected.')
        path=Path(directory)/profile['aliases'][0]
    else:
        value=os.environ.get('AI_TRICKY_AZUREHOUND_BIN')
        if not value:pytest.skip('Optional real AzureHound binary is not selected.')
        path=Path(value)
    assert path.is_file(),str(path)
    return path


@pytest.mark.parametrize('profile',PROFILES.values(),ids=PROFILES)
def test_owned_command_is_accepted_by_the_pinned_real_cli_help_contract(profile,monkeypatch):
    binary=real_binary(profile)
    monkeypatch.setenv('AZUREHOUND_JWT','must-not-be-read')
    monkeypatch.setenv('KRB5CCNAME','must-not-be-read')
    report=asyncio.run(check_cli_contract(profile,binary))
    assert report['status']=='passed',report
    assert report['missing_flags']==[] and report['tested_release_match'],report
    assert not report['authentication_tested'] and not report['collection_tested']


@pytest.mark.parametrize('key',['impacket-ad-users','impacket-spns','impacket-delegation'])
def test_real_impacket_reports_failure_even_though_its_exit_code_is_zero(tmp_path,key):
    profile=PROFILES[key];binary=real_binary(profile)
    # A Python startup guard prevents the real examples from reaching DNS,
    # UDP or TCP while they handle a deliberately invalid credential cache.
    guard=tmp_path/'sitecustomize.py'
    guard.write_text('''import socket\ndef denied(*a,**k):raise OSError("OFFLINE_TEST_NETWORK_BLOCKED")\nsocket.socket.connect=denied\nsocket.socket.connect_ex=denied\nsocket.socket.sendto=denied\nsocket.getaddrinfo=denied\nsocket.gethostbyname=denied\n''')
    cache=tmp_path/'invalid.ccache';cache.write_bytes(b'invalid-cache')
    scope={'domain':'identity-contract.invalid','tenant_id':''}
    auth={'dc_ip':'127.0.0.1','dc_host':'dc.identity-contract.invalid','username':'unused'}
    argv=collection_command(profile,binary,scope,auth,cache,tmp_path/'unused.json')
    env={k:os.environ[k] for k in ('PATH','LANG','SystemRoot','WINDIR') if k in os.environ}
    env.update({'HOME':str(tmp_path),'KRB5CCNAME':str(cache),'PYTHONPATH':str(tmp_path)})
    result=subprocess.run(argv,cwd=tmp_path,env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=12)
    assert result.returncode==0
    health=collection_health(profile,result.stdout,result.stderr,result.returncode)
    assert health['status']=='failed' and health['error_count']>=1,health
