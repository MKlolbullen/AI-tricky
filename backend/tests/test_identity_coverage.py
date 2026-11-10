import json

import pytest
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.identity_contracts import collection_health
from backend.identity_tools import PROFILES, graph_token
from backend.scope import ScopeError
from backend.tests.test_identity import identity_binary, input_file, run_body, graph, jwt, TENANT
from backend.tests.test_local import wait_done


@pytest.mark.parametrize('key',['impacket-ad-users','impacket-spns','impacket-delegation'])
def test_impacket_error_diagnostics_fail_even_with_zero_exit_status(key):
    health=collection_health(PROFILES[key],'Impacket v0.13.1\n[-] authentication failed\n','',0)
    assert health['status']=='failed' and health['error_count']==1 and not health['coverage_verified']


def test_partial_tables_preserve_data_but_do_not_claim_complete_coverage():
    health=collection_health(PROFILES['impacket-ad-users'],'Name  Email\n----  -----\nalice  fixture\n[-] one page was unavailable\n','',0)
    assert health['status']=='partial' and health['table_rows_observed']
    assert collection_health(PROFILES['impacket-ad-users'],'Name Email\n---- -----\nalice fixture','',0)['status']=='unverified'


def test_azurehound_json_errors_and_unknown_diagnostics_are_coverage_gaps():
    health=collection_health(PROFILES['azurehound-entra'],'','{"level":"error","message":"missing permission"}\n{"level":"warn","message":"partial"}\n',0)
    assert health['status']=='partial' and health['error_count']==1 and health['warning_count']==1
    assert collection_health(PROFILES['azurehound-entra'],'','unrecognized output',0)['status']=='partial'


def test_valid_graph_guid_audience_is_rejected_as_unsupported_by_this_profile():
    with pytest.raises(ScopeError,match='unsupported by the AzureHound profile'):
        graph_token(jwt(aud='00000003-0000-0000-c000-000000000000').encode(),TENANT)
    assert graph_token(jwt(aud='https://graph.microsoft.com/').encode(),TENANT)


def test_zero_exit_error_stops_the_branch_and_retains_invocation_logs(tmp_path,identity_binary):
    binary=identity_binary/'impacket-GetADUsers';binary.write_text(binary.read_text().split('args=sys.argv')[0]+'print("[-] fixture authentication failed")\n')
    with TestClient(create_app(tmp_path/'state')) as c:
        iid,_=input_file(c,tmp_path,'cache',b'fixture')
        start=c.post('/api/runs',json=run_body(c,graph(profile='impacket-ad-users',auth_id=iid),allow_cli=True)).json()
        done=wait_done(c,start['id']);assert done['result']['failed_nodes']==1
        artifacts=c.get('/api/runs/'+done['id']+'/artifacts').json()
        log=next(c.get('/api/artifacts/'+a['id']).json() for a in artifacts if a['name'].startswith('cli-'))
        assert log['exit_code']==0 and log['error']=='CollectorReportedFailure'
        assert log['collection_health']['status']=='failed'
        assert not any(a['name'].startswith('identity-analysis-') for a in artifacts)


def test_partial_collection_diagnostics_reach_path_analysis_and_agent_evidence(tmp_path,identity_binary):
    binary=identity_binary/'impacket-GetADUsers'
    binary.write_text(binary.read_text().split('args=sys.argv')[0]+'''print("Name  Email\\n----  -----\\nalice  fixture\\n[-] fixture page was unavailable")\n''')
    with TestClient(create_app(tmp_path/'state')) as c:
        iid,_=input_file(c,tmp_path,'cache',b'fixture')
        start=c.post('/api/runs',json=run_body(c,graph(profile='impacket-ad-users',auth_id=iid),allow_cli=True)).json()
        done=wait_done(c,start['id']);assert done['result']['failed_nodes']==0
        artifacts=c.get('/api/runs/'+done['id']+'/artifacts').json()
        report=next(c.get('/api/artifacts/'+a['id']).json() for a in artifacts if a['name'].startswith('identity-analysis-'))
        assert report['collection_coverage'][0]['status']=='partial'
        assert report['collection_coverage'][0]['artifact_id']
        assert any('reported error(s)' in gap for gap in report['coverage_limits'])
        node=c.get('/api/artifacts/'+next(a['id'] for a in artifacts if a['name']=='node-i2.json')).json()[0]
        assert 'collector health partial' in node['body'] and 'error_count' in node['body']
        assert c.get('/api/findings').json()['total']==0


def test_historical_collector_artifacts_remain_readable_without_inventing_health(tmp_path):
    import base64
    from backend.store import Store
    from backend.identity_graph import execute_paths
    from backend.tests.test_identity import AD,normalized
    store=Store(tmp_path/'state');config={'targets':['corp.test']};rid=store.new_run(config)['id']
    old=store.artifact(rid,'cli-1-impacket-ad-users.json',{'tool_id':'impacket-ad-users','scope':AD,'stdout':'legacy output','stderr':'','exit_code':0})
    raw=json.dumps(normalized()).encode()
    exported=store.artifact(rid,'identity-collector.json',{'encoding':'base64','bytes':base64.b64encode(raw).decode(),'source_artifact_id':old})
    rows=execute_paths(rid,'paths',{'identity_scope':AD,'start_ids':['user'],'goal_ids':['goal']},[{'catalog_streams':{'file':['artifact:'+exported]}}],config,store)
    result=store.content(rows[0]['artifact_id']);health=result['collection_coverage'][0]
    assert len(result['paths'])==1 and health['status']=='unavailable'
    assert health['error_count'] is None and health['warning_count'] is None
    assert store.content(old)['stdout']=='legacy output'
