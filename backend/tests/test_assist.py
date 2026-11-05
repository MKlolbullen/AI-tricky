from fastapi.testclient import TestClient

from backend.app import create_app


def test_assist_deterministic_returns_server_built_graph_and_diff(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        r = c.post('/api/agent/assist', json={'goal': 'add tcp inventory', 'current': ['native_scope', 'native_http'], 'use_model': False})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body['graph']['nodes'][0]['data']['kind'] == 'native_scope'
        assert body['planner'] == 'local-rules' and body['model_called'] is False
        assert body['current'] == ['native_scope', 'native_http']
        assert set(body) >= {'added', 'removed', 'result_kinds'}


def test_assist_model_picks_ids_and_server_builds_the_graph(tmp_path):
    async def planner(targets, goal, fetch, **kw):
        # The model may only return adapter IDs; the server builds/validates.
        return {'report': '{"adapters":["native_scope","native_tcp","native_http","native_summary"]}'}
    with TestClient(create_app(tmp_path, assessor=planner)) as c:
        r = c.post('/api/agent/assist', json={'goal': 'insert a tcp stage before http',
                                              'current': ['native_scope', 'native_http'], 'use_model': True})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body['result_kinds'] == ['native_scope', 'native_tcp', 'native_http', 'native_summary']
        assert 'native_tcp' in body['added'] and 'native_summary' in body['added']
        assert body['model_called'] is True


def test_assist_model_rejects_an_unsupported_plan(tmp_path):
    async def planner(targets, goal, fetch, **kw):
        return {'report': '{"adapters":["native_http"]}'}  # must start with native_scope
    with TestClient(create_app(tmp_path, assessor=planner)) as c:
        r = c.post('/api/agent/assist', json={'goal': 'x', 'current': [], 'use_model': True})
        assert r.status_code == 422


def test_assist_team_node_requires_analysis_flag(tmp_path):
    async def planner(targets, goal, fetch, **kw):
        return {'report': '{"adapters":["native_scope","native_http","native_team"]}'}
    with TestClient(create_app(tmp_path, assessor=planner)) as c:
        # include_analysis defaults False -> a team/cai node is rejected by the planner.
        assert c.post('/api/agent/assist', json={'goal': 'add the team', 'current': ['native_scope'], 'use_model': True}).status_code == 422
        ok = c.post('/api/agent/assist', json={'goal': 'add the team', 'current': ['native_scope'], 'use_model': True, 'include_analysis': True})
        assert ok.status_code == 200 and 'native_team' in ok.json()['result_kinds']
