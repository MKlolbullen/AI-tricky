import asyncio
import contextlib
import ipaddress
import json
import os
import hashlib
import secrets
import uuid
import threading
import http.client
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from . import cai_adapter
from .scope import ScopeError, parse_target, authorize, fetch_scoped, model_base_url, network_hosts, resolve_target, host_matches
from .store import Store
from .agent_settings import AgentPresets, PresetInput, PresetRevision, SettingsConflict
from .model_catalog import model_catalog
from .workflows import REGISTRY, validate_workflow, execute_workflow
from .intelligence import analysis_goal, plan_workflow
from .catalog import CATALOG as MINI_CATALOG, CATALOG_KINDS, TOOLS, TRICKEST_CATALOG, convert_mini, tool_readiness, blocked_flag
from .catalog_execution import preflight as catalog_preflight
from .cli_runner import pause_processes, snapshot_folder
from .support_data import SupportData
from .team_routing import ModelRoute, validate_routes, execute_route
from .http_routing import HTTPRouting, resolve_routing, routing_binding
from .http_journal import HTTPJournal, request_message
from .catalog_planner import plan_catalog
from .evidence import EvidenceIndex, ReviewConflict
from .proposals import ProposalPlanner, ProposalError, StalePlan
from .proposal_execution import ProposalExecutions, ExecutionOptions, SnapshotAction, DispatchAction, ExecutionError
from .recovery import WorkflowRecoveries, RecoveryOptions
from .model_usage import ModelUsage
from .credentials import CredentialVault, MODEL_PROVIDERS, MODEL_VARS
from .asset_graph import AssetGraph, ENTITY_KINDS
from .observations import canonical_asset
from .passive_sources import ADAPTERS as PASSIVE_ADAPTERS
from .passive_ingest import PassiveIngestor, default_passive_http, passive_enabled
from . import team as team_leader
from . import verification
from .access_verification import AuthenticatedRequest, IdentityInput, TestIdentities


class TargetInput(BaseModel):
    value: str = Field(min_length=1, max_length=2048)


class CredentialUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    updates: dict[str, str | None] = Field(default_factory=dict, max_length=30)


class RunInput(BaseModel):
    target_ids: list[str] = Field(default_factory=list, max_length=20)
    goal: str = Field(default='Assess the supplied web targets and report evidence-backed security candidates.', min_length=1, max_length=4000)
    allow_http: bool = False
    max_requests: int = Field(default=256, ge=1, le=2048)
    engine: Literal['cai','inventory','workflow','team'] = 'cai'
    workflow: dict | None = None
    parallelism: int = Field(default=4, ge=1, le=16)
    max_hosts: int = Field(default=64, ge=1, le=256)
    ports: list[int] = Field(default_factory=lambda:[22,80,443,8080,8443], min_length=1, max_length=16)
    allow_cli: bool = False
    max_cli_invocations: int = Field(default=64, ge=1, le=256)
    max_seconds: int = Field(default=240, ge=1, le=3600)
    cli_credential_keys: list[str] = Field(default_factory=list,max_length=30)
    roles: list[Annotated[str, StringConstraints(min_length=1, max_length=40)]] = Field(default_factory=list, max_length=12)
    member_max_turns: int = Field(default=8, ge=1, le=24)
    team_max_turns: int = Field(default=team_leader.DEFAULT_TEAM_TURNS, ge=1, le=team_leader.MAX_TEAM_TURNS, strict=True)
    member_workers: int = Field(default=3, ge=1, le=8)
    synthesize: bool = False
    adaptive: bool = False
    provider: str | None = Field(default=None, max_length=40)
    model: str | None = Field(default=None, max_length=120)
    team_profile: Literal['classic','specialist'] = 'classic'
    team_task_level: Literal['standard','complex'] = 'standard'
    team_routes: dict[str, ModelRoute] = Field(default_factory=dict, max_length=len(team_leader.ROLES)+1)
    http_routing: HTTPRouting = Field(default_factory=HTTPRouting)


class InputRegistration(BaseModel):
    name: str = Field(min_length=1,max_length=120)
    path: str | None = Field(default=None,max_length=4096)
    content: str | None = Field(default=None,max_length=10_000_000)


class BurpImport(BaseModel):
    model_config = ConfigDict(extra='forbid')
    xml: str = Field(min_length=1,max_length=10_000_000)


class CatalogImport(BaseModel):
    workflow: dict


class WorkflowInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    graph: dict
    id: str | None = None
    expected_revision: int | None = Field(default=None, ge=1)


class SupportBinding(BaseModel):
    model_config = ConfigDict(extra='forbid')
    graph: dict


class PlanInput(BaseModel):
    goal: str = Field(min_length=1, max_length=4000)
    include_analysis: bool = False
    use_model: bool = False
    provider: str | None = Field(default=None, max_length=40)
    model: str | None = Field(default=None, max_length=120)


class AssistInput(BaseModel):
    goal: str = Field(min_length=1, max_length=4000)
    current: list[Annotated[str, StringConstraints(min_length=1, max_length=40)]] = Field(default_factory=list, max_length=24)
    include_analysis: bool = False
    use_model: bool = False
    provider: str | None = Field(default=None, max_length=40)
    model: str | None = Field(default=None, max_length=120)


class EnrichInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str = Field(min_length=1, max_length=253)
    providers: list[Annotated[str, StringConstraints(min_length=1, max_length=40)]] = Field(min_length=1, max_length=12)


class CatalogPlanInput(BaseModel):
    goal: str = Field(min_length=1,max_length=4000)
    source_type: str = 'domain'
    target_type: str = 'findings'
    max_risk: str = 'medium'


class FindingReviewInput(BaseModel):
    expected_revision: int = Field(ge=1)
    status: Literal['candidate', 'triaged', 'verified', 'rejected', 'resolved']
    severity: Literal['info', 'low', 'medium', 'high', 'critical']
    confidence: Literal['unknown', 'low', 'medium', 'high']
    note: str = Field(min_length=1, max_length=4000)
    evidence_id: str | None = Field(default=None, max_length=100)


class EvidencePlanInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    run_id: str = Field(min_length=1, max_length=64)
    observation_ids: list[Annotated[str, StringConstraints(min_length=1, max_length=64)]] = Field(min_length=1, max_length=24)
    goal: str = Field(min_length=1, max_length=4000)
    use_model: bool = False
    max_risk: Literal['passive', 'low', 'medium'] = 'low'
    provider: str | None = Field(default=None, max_length=40)
    model: str | None = Field(default=None, max_length=120)


class RunControl:
    def __init__(self):
        self.gate = asyncio.Event()
        self.gate.set()
        self.cancelled = False
        self.requests = 0
        self.lock = asyncio.Lock()
        self.network_slots = asyncio.Semaphore(16)
        self.active_nodes = set()
        self.processes = {}
        self.cli_invocations = 0
        self.credentials = {}
        # Resolved model config (base_url, api_key, model) for a team run. Lives
        # only on the control object, never in the persisted run.
        self.model = None
        self.team_routes = {}
        self.team_task_level = 'standard'
        self.http_routing = None
        self.verification_identities = {}
        self.verification_fingerprint_key = None
        self.task = None


def create_app(data_dir=None, assessor=None, passive_http=None):
    store = Store(Path(data_dir or os.environ.get('AI_TRICKY_DATA_DIR') or os.environ.get('OFFSECS_U_AI_DATA_DIR') or os.environ.get('RECONFORGE_DATA_DIR', './local-data')))
    support_data = SupportData(store)
    http_journal = HTTPJournal(store)
    agent_presets = AgentPresets(store)
    evidence = EvidenceIndex(store)
    asset_graph = AssetGraph(store)
    passive_ingestor = PassiveIngestor(store, asset_graph)
    vault = CredentialVault(store.root)
    credential_consumers = {}
    for _tid, _tool in TOOLS.items():
        for _key in _tool.get('secrets', []):
            credential_consumers.setdefault(_key, []).append(_tid)
    catalog_secret_names = frozenset(credential_consumers)

    def configured_secret_keys():
        # Catalog credential variables that currently resolve to a value.
        return frozenset(key for key in catalog_secret_names if vault.effective(key))

    def resolve_model(provider_id=None, model_name=None, credential_snapshot=None):
        # Resolve the model config for a selected provider. 'local' (or none) uses
        # the configured local endpoint. A remote provider resolves only when its
        # key is stored AND remote model use is enabled — the gate that keeps
        # inference opt-in and platform hosting local.
        allow_remote = os.environ.get('CAI_ALLOW_REMOTE_MODEL') == '1'
        if not provider_id or provider_id == 'local':
            base = model_base_url(os.environ.get('CAI_MODEL_BASE_URL', 'http://127.0.0.1:11434/v1'), allow_remote)
            return {'provider': 'local', 'base_url': base, 'is_remote': False,
                    'api_key': os.environ.get('CAI_MODEL_API_KEY') or os.environ.get('CAI_LOCAL_API_KEY', 'local-only'),
                    'model': model_name or os.environ.get('CAI_MODEL', 'local-model')}
        mp = MODEL_PROVIDERS.get(provider_id)
        if not mp:
            raise HTTPException(422, 'Unknown model provider.')
        key = credential_snapshot.get(mp['key']) if credential_snapshot is not None else vault.effective(mp['key'])
        if not key:
            raise HTTPException(409, f"Store the {mp['name']} API key in Credentials before selecting it for planning.")
        try:
            base = model_base_url(mp['endpoint'], allow_remote)
        except ScopeError:
            raise HTTPException(409, f"Enable remote model use (set CAI_ALLOW_REMOTE_MODEL=1) to use {mp['name']} for planning. Platform hosting stays local.")
        if not model_name:
            raise HTTPException(422, f"Enter the {mp['name']} model name to use for planning.")
        return {'provider': provider_id, 'base_url': base, 'api_key': key, 'is_remote': True, 'model': model_name}

    def model_provider_status():
        providers = [{'id': 'local', 'name': 'Local endpoint', 'is_remote': False, 'configured': True}]
        for pid, mp in MODEL_PROVIDERS.items():
            providers.append({'id': pid, 'name': mp['name'], 'is_remote': True,
                              'configured': bool(vault.effective(mp['key']))})
        return providers

    def resolve_team_models(config):
        snapshot=vault.snapshot(MODEL_VARS)
        inherited=resolve_model(config.get('provider'),config.get('model'),snapshot) if assessor is None or config.get('provider') not in (None,'local') else None
        routes={role:{part:resolve_model(choice['provider'],choice['model'],snapshot) for part,choice in route.items() if choice is not None}
                for role,route in config.get('team_routes',{}).items()}
        return {'default':inherited,'routes':routes} if routes else inherited
    proposal_planner = ProposalPlanner(store, evidence)
    test_identities = TestIdentities()
    proposal_executions = ProposalExecutions(store, proposal_planner, test_identities)
    controls = {}
    def recovery_model_config(config=None):
        if assessor is not None and not (config or {}).get('team_routes'):
            return None  # injected test analyst, no SDK or provider request
        if assessor is None and cai_adapter.installed_version() != cai_adapter.SUPPORTED_CAI:
            raise ExecutionError('Install the supported CAI SDK before recovering an analyst node.')
        try:
            return resolve_team_models(config or {})
        except HTTPException as exc:
            raise ExecutionError(str(exc.detail), exc.status_code) from None
    recoveries = WorkflowRecoveries(store, credential=vault.effective, model_config=recovery_model_config,
        source_active=lambda rid: bool(controls.get(rid) and controls[rid].task and not controls[rid].task.done()))
    dispatch_lock = asyncio.Lock()
    dispatch_tasks = set()
    usage = ModelUsage(store)
    raw_assess = assessor or cai_adapter.assess
    async def assess(targets, goal, request_tool, *, usage_run_id=None, usage_related_run_id=None,
                     usage_node_id=None, usage_role=None, usage_purpose='assessment', **kwargs):
        return await usage.assess(raw_assess, targets, goal, request_tool,
            run_id=usage_run_id, related_run_id=usage_related_run_id, node_id=usage_node_id,
            role=usage_role, purpose=usage_purpose,
            execution_mode='injected' if assessor is not None else None, **kwargs)

    async def role_assess(ctl, rid, role, *args, **kwargs):
        await ctl.gate.wait()
        if ctl.cancelled:raise asyncio.CancelledError()
        if role not in ctl.team_routes:
            if ctl.model is not None:kwargs.setdefault('model',ctl.model)
            return await assess(*args,**kwargs)
        inherited=kwargs.pop('model',None) or ctl.model
        allowance=kwargs.pop('max_turns',12)
        async def call(model,limit):
            await ctl.gate.wait()
            if ctl.cancelled:raise asyncio.CancelledError()
            return await assess(*args,**kwargs,model=model,max_turns=limit)
        return await execute_route(call,role=role,allowance=allowance,inherited=inherited,
            route=ctl.team_routes.get(role),task_level=ctl.team_task_level,
            on_event=lambda kind,data:store.event(rid,kind,data))
    preview = (os.environ.get('AI_TRICKY_PREVIEW') or os.environ.get('OFFSECS_U_AI_PREVIEW') or os.environ.get('RECONFORGE_PREVIEW')) == '1'

    @asynccontextmanager
    async def lifespan(app):
        yield
        # Finish already approved consume/start operations even if their client disconnected.
        await asyncio.gather(*dispatch_tasks, return_exceptions=True)
        for ctl in controls.values():
            ctl.cancelled = True
            ctl.gate.set()
            if ctl.task and not ctl.task.done():
                ctl.task.cancel()
        await asyncio.gather(*(c.task for c in controls.values() if c.task), return_exceptions=True)

    app = FastAPI(title='AI-tricky Local', lifespan=lifespan)
    app.state.store = store

    @app.middleware('http')
    async def local_boundary(request: Request, call_next):
        # Loopback listener plus host/origin checks prevent accidental LAN exposure
        # and browser DNS-rebinding/CSRF against the local control API.
        host = request.url.hostname
        if host not in ('127.0.0.1', 'localhost', '::1', 'testserver'):
            return JSONResponse({'detail': 'Local host header required.'}, 403)
        peer = request.client.host if request.client else ''
        if peer not in ('testclient', 'testserver'):
            try:
                if not ipaddress.ip_address(peer).is_loopback:
                    return JSONResponse({'detail': 'Loopback clients only.'}, 403)
            except ValueError:
                return JSONResponse({'detail': 'Loopback clients only.'}, 403)
        origin = request.headers.get('origin')
        allowed = {'http://127.0.0.1:8787', 'http://localhost:8787', 'http://127.0.0.1:5173', 'http://localhost:5173'}
        # Honour a configured non-default loopback port (AI_TRICKY_PORT) so the UI
        # served there is same-origin with the API; the bind stays loopback-only.
        configured_port = os.environ.get('AI_TRICKY_PORT', '')
        if configured_port.isdigit() and 1 <= int(configured_port) <= 65535:
            # Normalize (e.g. "09000" -> 9000) so the origin matches the bound port.
            bound = int(configured_port)
            allowed |= {f'http://127.0.0.1:{bound}', f'http://localhost:{bound}'}
        if preview:
            allowed.add('http://terminal.local:4173')
        if origin and origin not in allowed:
            return JSONResponse({'detail': 'Cross-origin API access denied.'}, 403)
        if request.method in ('POST', 'PATCH', 'DELETE'):
            if request.headers.get('sec-fetch-site') == 'cross-site':
                return JSONResponse({'detail': 'Cross-site API writes denied.'}, 403)
            if request.headers.get('content-type', '').split(';')[0] != 'application/json':
                return JSONResponse({'detail': 'JSON content type required.'}, 415)
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Never echo submitted values back in 422 bodies; a credential update
        # body carries secrets, and the default handler returns `input`.
        safe = [{k: v for k, v in err.items() if k not in ('input', 'ctx')} for err in exc.errors()]
        return JSONResponse({'detail': safe}, status_code=422)

    @app.exception_handler(ScopeError)
    async def bad_scope(request, exc):
        return JSONResponse({'detail': str(exc)}, 422)

    @app.exception_handler(ExecutionError)
    async def bad_execution(request, exc):
        return JSONResponse({'detail': str(exc)}, exc.status)

    def get_run(rid):
        try:
            return store.run(rid)
        except KeyError:
            raise HTTPException(404, 'Run not found.')

    @app.get('/api/runtime')
    async def runtime():
        version = cai_adapter.installed_version()
        try:
            base = model_base_url(os.environ.get('CAI_MODEL_BASE_URL', 'http://127.0.0.1:11434/v1'), os.environ.get('CAI_ALLOW_REMOTE_MODEL') == '1')
            config_error = None
        except ValueError as exc:
            base, config_error = None, str(exc)
        return {'locally_hosted': True, 'cai_version': version, 'supported_version': cai_adapter.SUPPORTED_CAI,
                'sdk_execution': 'isolated-interpreter' if os.environ.get('CAI_PYTHON') else 'in-process',
                'sdk_ready': version == cai_adapter.SUPPORTED_CAI and config_error is None,
                'model_base_url': base, 'model': os.environ.get('CAI_MODEL', 'local-model'),
                'model_connection': 'not tested', 'remote_model_enabled': os.environ.get('CAI_ALLOW_REMOTE_MODEL') == '1', 'config_error': config_error,
                'capabilities': ['scoped_http_get', 'scoped_tcp_connect', 'domain_ip_cidr_inventory', 'cai_model', 'sqlite_history', 'native_dag', 'saved_workflows', 'workflow_recovery', 'model_usage'],
                'workflow_adapters': REGISTRY,
                'workflow_execution': 'Native DAG, CAI evidence review and 151 migrated catalog contracts; CLI execution requires explicit run enablement and preflight',
                'catalog_tools':len(TOOLS),'catalog_workflows':len(MINI_CATALOG['workflows']) + len(TRICKEST_CATALOG['workflows']),
                'cli_credential_variables':[{'name':key,'configured':bool(vault.effective(key))} for key in sorted({key for t in TOOLS.values() for key in t.get('secrets',[])}) if key not in MODEL_VARS],
                'model_providers':model_provider_status(),
                'model_catalog':model_catalog(),
                'team_roles':[{'key':k,'name':v['name'],'evidence_only':v.get('evidence_only',False)} for k,v in team_leader.ROLES.items()],
                'team_profiles':{'classic':team_leader.DEFAULT_ROLES,'specialist':team_leader.SPECIALIST_ROLES},
                'passive_providers':passive_provider_status()}

    @app.get('/api/credentials')
    async def credentials_status():
        return {'providers': vault.status(credential_consumers)}

    @app.post('/api/credentials')
    async def credentials_update(body: CredentialUpdate):
        try:
            vault.set_many(body.updates)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return {'providers': vault.status(credential_consumers)}
    # Clearing a key is a POST with an empty value, so the JSON-write guard and
    # the shared client helper (GET/POST only) both apply uniformly.

    @app.get('/api/workflows')
    async def workflows():
        return store.workflows()

    @app.get('/api/agent-settings')
    async def agent_settings_index():
        return agent_presets.index()

    @app.get('/api/agent-settings/{identifier}')
    async def agent_settings_get(identifier: str):
        try:
            return agent_presets.get(identifier)
        except KeyError:
            raise HTTPException(404, 'Agent preset not found.')

    @app.post('/api/agent-settings', status_code=201)
    async def agent_settings_create(body: PresetInput):
        try:
            return agent_presets.save(body)
        except SettingsConflict as exc:
            raise HTTPException(409, str(exc))
        except ValueError as exc:
            raise HTTPException(422, str(exc))

    @app.post('/api/agent-settings/{identifier}')
    async def agent_settings_save(identifier: str, body: PresetInput):
        try:
            return agent_presets.save(body, identifier)
        except SettingsConflict as exc:
            raise HTTPException(409, str(exc))

    @app.post('/api/agent-settings/{identifier}/delete')
    async def agent_settings_delete(identifier: str, body: PresetRevision):
        try:
            agent_presets.delete(identifier, body.revision)
        except SettingsConflict as exc:
            raise HTTPException(409, str(exc))
        return {'deleted': True}

    @app.get('/api/workflow-starters/web-recon')
    async def web_recon_starter(fuzz: bool = False, scan: bool = False, review: bool = False):
        from .web_recon import recon_workflow
        graph = recon_workflow(fuzz=fuzz, scan=scan, review=review)
        return support_data.bind(graph, bundled_only=True)['graph'] if scan else graph

    @app.get('/api/workflow-starters/trickest/{identifier}')
    def trickest_starter(identifier: str):
        from .trickest_pack import workflow
        try:
            graph = workflow(identifier)
        except KeyError:
            raise HTTPException(404, 'Trickest workflow template not found.') from None
        return support_data.bind(graph, bundled_only=True)['graph']

    @app.get('/api/catalog')
    async def catalog():
        return {**MINI_CATALOG, 'trickest': TRICKEST_CATALOG, 'readiness': [tool_readiness(t) for t in TOOLS.values()]}

    @app.post('/api/catalog/plan')
    async def catalog_plan(body: CatalogPlanInput):
        return plan_catalog(body.goal,body.source_type,body.target_type,body.max_risk)

    @app.post('/api/catalog/import')
    async def import_catalog(body: CatalogImport):
        graph=convert_mini(body.workflow)
        validate_workflow(graph)
        return graph

    @app.get('/api/catalog/tools/{tid}')
    async def catalog_tool(tid: str):
        tool=TOOLS.get(tid)
        if not tool:raise HTTPException(404,'Catalog tool not found.')
        return {**tool,'args':[{**a,'blocked_reason':blocked_flag(a)} for a in tool.get('args',[])],'readiness':tool_readiness(tool)}

    @app.get('/api/inputs')
    async def inputs():
        return store.inputs()

    @app.get('/api/support-data')
    async def support_status():
        return await asyncio.to_thread(support_data.status)

    @app.post('/api/support-data/install/{package}')
    async def install_support_data(package: str):
        try:
            return await asyncio.to_thread(support_data.install,package)
        except ScopeError:
            raise
        except Exception as exc:
            raise HTTPException(409,f'Support data installation did not complete ({type(exc).__name__}). Retry to resume registration; existing versions are preserved.') from None

    @app.post('/api/support-data/bind')
    async def bind_support_data(body: SupportBinding):
        return await asyncio.to_thread(support_data.bind,body.graph)

    @app.post('/api/inputs',status_code=201)
    async def register_input(body: InputRegistration):
        if (body.path is None)==(body.content is None):
            raise HTTPException(422,'Supply exactly one local path or uploaded text content.')
        if body.path is not None:
            original=Path(body.path).expanduser()
            if not original.is_absolute() or original.is_symlink():raise HTTPException(422,'Use an absolute path to a regular file or folder, without symlinks.')
            path=original.resolve()
            if path.is_dir():
                snapshot_folder(path)
                return store.add_input(body.name,'folder',path)
            if not path.is_file() or path.stat().st_size>10_000_000:raise HTTPException(422,'File input must be a regular file at most 10 MB.')
        else:
            path=store.root.resolve()/'inputs'/str(uuid.uuid4())
            content=body.content.encode()
            if len(content)>10_000_000:raise HTTPException(422,'Text input exceeds 10 MB.')
            path.write_bytes(content);os.chmod(path,0o600)
        return store.add_input(body.name,'file',path,hashlib.sha256(path.read_bytes()).hexdigest())

    @app.get('/api/workflows/{wid}')
    async def workflow(wid: str):
        try:
            return store.workflow(wid)
        except KeyError:
            raise HTTPException(404, 'Workflow not found.')

    @app.post('/api/workflows')
    async def save_workflow(body: WorkflowInput):
        validate_workflow(body.graph)
        if not body.name.strip():
            raise HTTPException(422, 'Workflow name is required.')
        if body.id and body.expected_revision is None:
            raise HTTPException(422, 'An expected revision is required when updating a saved workflow.')
        try:
            return store.save_workflow(body.name.strip(), body.graph, body.id, body.expected_revision)
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.get('/api/targets')
    async def targets():
        return [{**t,'kind':parse_target(t['url']).kind} for t in store.targets()]

    @app.get('/api/identity/catalog')
    def identity_catalog():
        from .identity_tools import catalog_status
        return catalog_status()

    @app.post('/api/agent/plan')
    async def agent_plan(body: PlanInput):
        if not body.use_model:
            return plan_workflow(body.goal, include_analysis=body.include_analysis)
        resolved_model = resolve_model(body.provider, body.model)
        if assessor is None and cai_adapter.installed_version() != cai_adapter.SUPPORTED_CAI:
            raise HTTPException(409, 'Configure the supported CAI SDK to use model planning, or use the local rules planner.')
        async def disabled(url):
            return {'error': 'Planning has no target access.'}
        goal = ('Choose a typed sequence of adapters for this goal. Return ONLY JSON {"adapters":[adapter IDs]}. '
                'Start with native_scope. Use 2–5 unique adapters with matching input/output types. '
                f'CAI analysis allowed: {body.include_analysis}. No commands or new adapters. Catalog: ' + json.dumps(REGISTRY) + '\nGoal: ' + body.goal)
        try:
            result = await assess([], goal, disabled, usage_purpose='workflow_plan', **({'evidence_only': True, 'model': resolved_model} if assessor is None else {}))
            return {**plan_workflow(body.goal, include_analysis=body.include_analysis, model_plan=result['report']),
                    'model_usage_id': result['model_usage_id']}
        except ScopeError:
            raise
        except Exception:
            raise HTTPException(502, 'Model planning failed. Check local provider readiness or use the local rules planner.') from None

    @app.post('/api/agent/assist')
    async def agent_assist(body: AssistInput):
        # Iterative canvas assistant. Only native adapter kinds already on the
        # canvas inform the suggestion; the server — never the model — builds and
        # type-validates the resulting graph. The model may only pick adapter IDs.
        current = [k for k in body.current if k in REGISTRY]
        def finish(built):
            new_kinds = [n['data']['kind'] for n in built['graph']['nodes']]
            return {**built, 'current': current,
                    'added': [k for k in new_kinds if k not in current],
                    'removed': [k for k in current if k not in new_kinds],
                    'result_kinds': new_kinds}
        if not body.use_model:
            return finish(plan_workflow(body.goal, include_analysis=body.include_analysis))
        resolved_model = resolve_model(body.provider, body.model)
        if assessor is None and cai_adapter.installed_version() != cai_adapter.SUPPORTED_CAI:
            raise HTTPException(409, 'Configure the supported CAI SDK to use the model assistant, or use the deterministic assistant.')
        async def disabled(url):
            return {'error': 'Assistance has no target access.'}
        goal = ('You are editing an existing typed security workflow on a canvas. Current adapters in order: ' + json.dumps(current) +
                '. Apply the requested change and return ONLY JSON {"adapters":[adapter IDs]} for the full desired ordered sequence. '
                'Start with native_scope. Use 2–5 unique adapters with matching input/output types. '
                f'CAI analysis allowed: {body.include_analysis}. No commands or new adapters. Catalog: ' + json.dumps(REGISTRY) + '\nChange: ' + body.goal)
        try:
            result = await assess([], goal, disabled, usage_purpose='canvas_assist', **({'evidence_only': True, 'model': resolved_model} if assessor is None else {}))
            return {**finish(plan_workflow(body.goal, include_analysis=body.include_analysis, model_plan=result['report'])),
                    'model_usage_id': result['model_usage_id']}
        except ScopeError:
            raise
        except Exception:
            raise HTTPException(502, 'Model assistance failed. Check provider readiness or use the deterministic assistant.') from None

    @app.post('/api/agent/proposals', status_code=201)
    async def propose_followups(body: EvidencePlanInput):
        get_run(body.run_id)
        if not body.goal.strip():
            raise HTTPException(422, 'Enter a follow-up objective.')
        context = await asyncio.to_thread(proposal_planner.context, body.run_id, body.observation_ids, body.goal, body.max_risk)
        if not body.use_model:
            try:
                return await asyncio.to_thread(proposal_planner.save, body.goal, context)
            except StalePlan as exc:
                raise HTTPException(409, str(exc))
        resolved_model = resolve_model(body.provider, body.model)
        if assessor is None and await asyncio.to_thread(cai_adapter.installed_version) != cai_adapter.SUPPORTED_CAI:
            raise HTTPException(409, 'Configure the supported CAI SDK to use model proposals, or select the rules planner.')
        async def disabled(url):
            return {'error': 'Evidence-guided planning has no target access.'}
        try:
            result = await assess([], proposal_planner.prompt(body.goal, context), disabled,
                                  usage_related_run_id=body.run_id, usage_purpose='evidence_plan',
                                  **({'evidence_only': True, 'model': resolved_model} if assessor is None else {}))
            return await asyncio.to_thread(proposal_planner.save, body.goal, context, result['report'], result)
        except StalePlan as exc:
            raise HTTPException(409, str(exc))
        except ProposalError as exc:
            raise HTTPException(502, str(exc))
        except ScopeError:
            raise
        except Exception:
            raise HTTPException(502, 'Evidence-guided model planning failed. Check provider readiness; no proposals were saved.') from None

    @app.get('/api/agent/proposals')
    def proposal_history(run_id: str):
        get_run(run_id)
        return proposal_planner.plans(run_id)

    @app.get('/api/agent/proposals/{plan_id}')
    def proposal_plan(plan_id: str):
        try:
            return proposal_planner.plan(plan_id)
        except KeyError:
            raise HTTPException(404, 'Evidence-guided plan not found.')

    @app.get('/api/agent/proposals/{plan_id}/{proposal_id}/workflow')
    def proposal_workflow(plan_id: str, proposal_id: str):
        result = proposal_plan(plan_id)
        if not result['current']:
            raise HTTPException(409, result['stale_reason'])
        selected = next((p for p in result['proposals'] if p['id'] == proposal_id), None)
        if selected is None:
            raise HTTPException(404, 'Proposal not found in this plan.')
        from .proposals import action_graph
        return {'graph': action_graph(selected['action'], selected['id']), 'goal': result['goal'],
                'scope': result['scope'], 'proposal_id': proposal_id, 'plan_id': plan_id,
                'dispatch_allowed': False}

    @app.get('/api/verification/profiles')
    def verification_profiles():
        return verification.profiles()

    @app.get('/api/verification/identities')
    def verification_identities():
        return test_identities.list()

    @app.post('/api/verification/identities', status_code=201)
    def add_verification_identity(body: IdentityInput):
        return test_identities.add(body)

    @app.post('/api/verification/identities/{identifier}/remove')
    def remove_verification_identity(identifier: str):
        try:
            test_identities.remove(identifier)
        except KeyError:
            raise HTTPException(404, 'Test identity not found.') from None
        return {'removed': True}

    @app.get('/api/agent/proposals/{plan_id}/{proposal_id}/verification-findings')
    def verification_findings(plan_id: str, proposal_id: str):
        return proposal_executions.eligible_findings(plan_id, proposal_id)

    @app.post('/api/targets', status_code=201)
    async def add_target(body: TargetInput):
        target=parse_target(body.value)
        return {**store.add_target(target.url),'kind':target.kind}

    @app.get('/api/assets')
    async def assets():
        records = {t['url']: {'url': t['url'], 'source': 'entered target', 'status': None} for t in store.targets()}
        for r in reversed(store.runs()):
            for e in store.events(r['id'],limit=10000):
                if e['kind'] == 'http.response':
                    d = e['data']
                    records[d['url']] = {**d, 'source': 'scoped HTTP', 'run_id': r['id']}
                elif e['kind']=='tcp.result' and e['data']['state']=='open':
                    d=e['data']; key=f"tcp://{d['host']}:{d['port']}"
                    records[key]={'url':key,'status':'open','source':'native TCP inventory','run_id':r['id']}
        return list(records.values())

    def passive_provider_status():
        providers = []
        for pid, adapter in PASSIVE_ADAPTERS.items():
            providers.append({'id': pid, 'name': adapter['name'],
                              'configured': all(vault.effective(v) for v in adapter['vars'])})
        return {'enabled': passive_enabled(), 'providers': providers}

    @app.post('/api/assets/enrich', status_code=201)
    async def enrich_assets(body: EnrichInput):
        target = canonical_asset(body.target.strip())
        parsed = None
        try:
            parsed = parse_target(body.target.strip())
        except ScopeError:
            parsed = None
        if target is None or parsed is None or parsed.kind not in ('domain', 'ip'):
            raise HTTPException(422, 'Passive enrichment takes an entered domain or IP.')
        entered = set()
        for row in store.targets():
            host = canonical_asset(parse_target(row['url']).host if parse_target(row['url']).kind in ('domain','ip','wildcard') else urlsplit(row['url']).hostname or '')
            if host:
                entered.add(host)
        if target not in entered:
            raise HTTPException(422, 'Enrich a target you have entered (domain or IP).')
        providers = list(dict.fromkeys(body.providers))
        for pid in providers:
            if pid not in PASSIVE_ADAPTERS:
                raise HTTPException(422, f'Unknown passive provider: {pid}')
        http = passive_http or default_passive_http
        if passive_http is None and not passive_enabled():
            raise HTTPException(409, 'Enable passive outbound (set AI_TRICKY_ALLOW_PASSIVE=1) to query provider APIs. Platform hosting stays local.')
        # Snapshot the selected provider credentials once, server-side.
        snapshot = {}
        for pid in providers:
            for var in PASSIVE_ADAPTERS[pid]['vars']:
                value = vault.effective(var)
                if not value:
                    raise HTTPException(409, f"Store the {PASSIVE_ADAPTERS[pid]['name']} credential ({var}) in Credentials before enriching.")
                snapshot[var] = value
        return await passive_ingestor.enrich(target, parsed.kind, providers, snapshot, http)

    @app.get('/api/assets/graph')
    def assets_graph(run_id: str | None = None, kind: str | None = None, q: str = '', limit: int = 500):
        if run_id:
            get_run(run_id)
        if kind is not None and kind not in ENTITY_KINDS:
            raise HTTPException(422, 'Unknown asset kind.')
        return asset_graph.graph(run_id=run_id, kind=kind, q=q[:200], limit=max(1, min(limit, 2000)))

    @app.get('/api/assets/diff')
    def assets_diff(baseline: str, current: str):
        if baseline == current:
            raise HTTPException(422, 'Select two different runs to compare.')
        get_run(baseline)
        get_run(current)
        return asset_graph.diff(baseline, current)

    @app.get('/api/assets/{asset_id}')
    def asset_entity(asset_id: str):
        try:
            return asset_graph.entity(asset_id)
        except KeyError:
            raise HTTPException(404, 'Asset not found.')

    @app.get('/api/runs')
    async def list_runs():
        return store.runs()

    @app.get('/api/observations')
    def observations(run_id: str | None = None, kind: str | None = None, q: str = '', limit: int = 100, offset: int = 0):
        if run_id:
            get_run(run_id)
        return evidence.observations(run_id=run_id, kind=kind, q=q[:200], limit=max(1, min(limit, 200)), offset=max(0, offset))

    @app.get('/api/findings')
    def findings(run_id: str | None = None, status: str | None = None, severity: str | None = None,
                 q: str = '', limit: int = 100, offset: int = 0):
        if run_id:
            get_run(run_id)
        return evidence.findings(run_id=run_id, status=status, severity=severity, q=q[:200],
                                 limit=max(1, min(limit, 200)), offset=max(0, offset))

    @app.get('/api/findings/{fid}')
    def finding(fid: str):
        try:
            return evidence.finding(fid)
        except KeyError:
            raise HTTPException(404, 'Finding not found.')

    @app.post('/api/findings/{fid}/reviews')
    def review_finding(fid: str, body: FindingReviewInput):
        try:
            return evidence.review(fid, **body.model_dump())
        except KeyError:
            raise HTTPException(404, 'Finding not found.')
        except ReviewConflict as exc:
            raise HTTPException(409, str(exc))
        except ValueError as exc:
            raise HTTPException(422, str(exc))

    @app.get('/api/runs/{rid}/compare')
    def compare_runs(rid: str, baseline: str):
        get_run(rid)
        get_run(baseline)
        try:
            return evidence.compare(baseline, rid)
        except ValueError as exc:
            raise HTTPException(422, str(exc))

    @app.get('/api/runs/{rid}')
    async def run(rid: str):
        return get_run(rid)

    @app.get('/api/runs/{rid}/events')
    async def events(rid: str, after: int = 0):
        get_run(rid)
        return store.events(rid, max(0, after))

    @app.get('/api/runs/{rid}/artifacts')
    async def artifacts(rid: str):
        get_run(rid)
        return store.artifacts(rid)

    @app.get('/api/runs/{rid}/nodes')
    async def run_nodes(rid: str):
        get_run(rid)
        return store.nodes(rid)

    @app.get('/api/model-usage')
    def model_usage(limit: int = 50, offset: int = 0):
        return usage.history(limit=limit, offset=offset)

    @app.get('/api/runs/{rid}/model-usage')
    def run_model_usage(rid: str, limit: int = 50, offset: int = 0):
        get_run(rid)
        return usage.history(run_id=rid, limit=limit, offset=offset)

    @app.get('/api/runs/{rid}/verification')
    def run_verification(rid: str):
        get_run(rid)
        try:
            return verification.read_result(store, rid)
        except KeyError:
            raise HTTPException(404, 'This run has no controlled verification profile.')

    @app.get('/api/findings/{fid}/verification')
    def finding_verification(fid: str):
        finding(fid)
        with store.connect() as c:
            ids = [r['run_id'] for r in c.execute('SELECT run_id FROM verification_runs WHERE finding_id=? ORDER BY created DESC LIMIT 50', (fid,))]
        return [verification.read_result(store, rid) for rid in ids]

    @app.get('/api/artifacts/{aid}')
    async def artifact(aid: str):
        try:
            return store.content(aid)
        except KeyError:
            raise HTTPException(404, 'Artifact not found.')

    @app.get('/api/http-history')
    def http_history(run_id: str | None=None,q: str='',limit: int=50,offset: int=0):
        if run_id:get_run(run_id)
        if not 1<=limit<=100 or offset<0 or len(q)>500:raise HTTPException(422,'Invalid HTTP history page.')
        return http_journal.history(run_id=run_id,q=q,limit=limit,offset=offset)

    @app.get('/api/http-history/har')
    def export_http_har(run_id: str | None=None,q: str='',limit: int=100,offset: int=0):
        if run_id:get_run(run_id)
        if not 1<=limit<=100 or offset<0 or len(q)>500:raise HTTPException(422,'Invalid HAR page.')
        return http_journal.har(run_id=run_id,q=q,limit=limit,offset=offset)

    @app.get('/api/http-history/{exchange_id}')
    def http_exchange(exchange_id: str):
        try:return http_journal.get(exchange_id)
        except KeyError:raise HTTPException(404,'HTTP exchange not found.') from None

    @app.post('/api/runs/{rid}/http-history/import')
    async def import_burp_history(rid: str,body: BurpImport):
        get_run(rid)
        return await asyncio.to_thread(http_journal.import_burp_xml,rid,body.xml)

    async def execute(rid, config, ctl):
        target_scope = [parse_target(t) for t in config['targets']]
        store.status(rid, 'running' if ctl.gate.is_set() else 'paused')
        store.event(rid, 'run.started', {'engine': config['engine'], 'scope': config['targets']})

        async def fetch(url, *, node_id=None, verification_step=None):
            request = None
            authentication = None
            if verification_step is not None:
                request = verification.request_spec(config, node_id, verification_step, url)
                if 'identity_id' in request:
                    options = config['verification']['access']['options']
                    identity = ctl.verification_identities.get(request['identity_id'])
                    if identity is None or ctl.verification_fingerprint_key is None:
                        return {'error': 'The approved test identity is unavailable.'}
                    expected = options['control_object'] if request['role'] == 'control' else options['owner_object']
                    authentication = AuthenticatedRequest(identity, options['json_pointer'], expected,
                                                          ctl.verification_fingerprint_key)
            while True:
                await ctl.gate.wait()
                async with ctl.lock:
                    if ctl.cancelled:
                        raise asyncio.CancelledError()
                    if not ctl.gate.is_set():
                        continue
                    if not config['allow_http']:
                        return {'error': 'HTTP access disabled. Produce a plan only.'}
                    try:
                        authorize(url, target_scope)
                    except ScopeError as exc:
                        store.event(rid, 'http.denied', {'url': url[:4096], 'reason': str(exc), 'node_id': node_id})
                        return {'error': str(exc)}
                    if ctl.requests >= config['max_requests']:
                        return {'error': 'Run request budget exhausted.'}
                    ctl.requests += 1
                    number = ctl.requests
                    store.event(rid, 'http.admitted', {'url': url, 'request_number': number, 'node_id': node_id,
                                                    **({'verification_role': request['role']} if request else {})})
                    break
            routing=config.get('http_routing',{'mode':'direct'})
            admitted_request = request_message(url)
            if authentication is not None:
                admitted_request['representation'] = 'authenticated_metadata_only'
            exchange_id=http_journal.begin(rid,node_id,number,url,routing,admitted_request)
            capture_started=threading.Event()
            capture_cancelled=threading.Event()
            capture_lock=threading.Lock()
            def capture():
                try:
                    with capture_lock:
                        if capture_cancelled.is_set():raise ScopeError('Cancelled before HTTP dispatch.')
                        capture_started.set()
                    response=fetch_scoped(url,target_scope,
                        allowed=lambda:not ctl.cancelled and ctl.gate.is_set() and (node_id is None or node_id in ctl.active_nodes),
                        routing=ctl.http_routing,on_request=lambda message:http_journal.prepared(exchange_id,message),
                        **({'authentication': authentication} if authentication is not None else {}),
                        **({'controlled_headers':request['headers']} if request else {}))
                    if request:response['verification_request']=request
                    response['http_exchange_id']=exchange_id
                    aid=store.artifact(rid,f'http-{number}.json',response,node_id=node_id)
                    http_journal.finish(exchange_id,response=response['http_exchange']['response'],artifact_id=aid,route=response['http_exchange']['route'])
                    store.event(rid,'http.response',{'url':url,'status':response['status'],'artifact_id':aid,
                        'connected_ip':response['connected_ip'],'node_id':node_id,'exchange_id':exchange_id})
                    return {**{k:v for k,v in response.items() if k!='http_exchange'},'body':response['body'][:16000],'artifact_id':aid}
                except BaseException as exc:
                    http_journal.finish(exchange_id,error=type(exc).__name__)
                    raise
            try:
                async with ctl.network_slots:
                    return await asyncio.to_thread(capture)
            except asyncio.CancelledError:
                http_journal.cancelled(exchange_id)
                with capture_lock:
                    capture_cancelled.set()
                    if not capture_started.is_set():http_journal.finish(exchange_id,error='CancelledBeforeDispatch')
                raise
            except (OSError, ValueError, TimeoutError, http.client.HTTPException) as exc:
                store.event(rid, 'http.error', {'url': url, 'reason': type(exc).__name__, 'node_id': node_id})
                return {'error': type(exc).__name__,'http_exchange_id':exchange_id}

        async def probe(value, ports, *, node_id=None):
            if not config['allow_http']:
                return {'error':'Network access disabled. Produce a plan only.'}
            if not ports or len(ports)>16 or any(type(p) is not int or not 1<=p<=65535 for p in ports):
                return {'error':'Supply 1–16 integer TCP ports in range 1–65535.'}
            try:
                hosts = network_hosts(value, target_scope, config['max_hosts'])
            except ScopeError as exc:
                store.event(rid,'network.denied',{'target':value[:2048],'reason':str(exc)})
                return {'error':str(exc)}
            async def check(host,port):
                async with ctl.network_slots:
                    while True:
                        await ctl.gate.wait()
                        async with ctl.lock:
                            if ctl.cancelled:
                                raise asyncio.CancelledError()
                            if not ctl.gate.is_set():
                                continue
                            if ctl.requests>=config['max_requests']:
                                return {'host':host,'port':port,'state':'budget_exhausted'}
                            ctl.requests+=1
                            number=ctl.requests
                            break
                    store.event(rid,'tcp.admitted',{'host':host,'port':port,'operation_number':number,'node_id':node_id})
                    try:
                        address=await asyncio.wait_for(asyncio.to_thread(resolve_target,host,port),timeout=5)
                        await ctl.gate.wait()
                        if ctl.cancelled:
                            raise asyncio.CancelledError()
                        reader,writer=await asyncio.wait_for(asyncio.open_connection(address,port),timeout=1)
                        writer.close()
                        with contextlib.suppress(OSError):
                            await writer.wait_closed()
                        row={'host':host,'ip':address,'port':port,'state':'open'}
                    except ScopeError as exc:
                        row={'host':host,'port':port,'state':'blocked','reason':str(exc)}
                    except (OSError, ValueError, TimeoutError):
                        row={'host':host,'port':port,'state':'closed_or_filtered'}
                    store.event(rid,'tcp.result',{**row,'node_id':node_id})
                    return row
            rows=await asyncio.gather(*(check(host,port) for host in hosts for port in sorted(set(ports))))
            aid=store.artifact(rid,'tcp-inventory.json',rows,node_id=node_id)
            open_rows=[r for r in rows if r['state']=='open']
            return {'results':open_rows[:256],'artifact_id':aid,'hosts':len(hosts),'operations':len(rows),'open_ports':len(open_rows),'blocked':sum(r['state']=='blocked' for r in rows),'truncated':len(open_rows)>256,'budget_exhausted':sum(r['state']=='budget_exhausted' for r in rows)}

        async def inventory():
            if not config['allow_http']:
                return {'report':'Inventory plan: validate entered scope, resolve domains, perform bounded TCP connect checks, inspect HTTP responses. Network access is disabled.', 'engine':'native-inventory','evidence_status':'OBSERVATION'}
            observations=[]
            for t in target_scope:
                if t.kind=='url':
                    observations.append(await fetch(t.url))
                else:
                    scanned=await probe(t.url,config['ports'])
                    observations.append(scanned)
                    for row in scanned.get('results',[]):
                        if row['state']!='open' or row['port'] not in (80,443,8080,8443):
                            continue
                        scheme='https' if row['port'] in (443,8443) else 'http'
                        host=f"[{row['host']}]" if ':' in row['host'] else row['host']
                        url=f"{scheme}://{host}:{row['port']}/"
                        observations.append(await fetch(url))
            aid=store.artifact(rid,'inventory-observations.json',observations)
            return {'report':f'Native inventory completed for {len(target_scope)} scope entries. See inventory and HTTP artifacts for observations. Open ports are observations, not vulnerability findings.', 'artifact_id':aid,'engine':'native-inventory','evidence_status':'OBSERVATION'}

        try:
            async with asyncio.timeout(config.get('max_seconds',240)):
                if config['engine']=='workflow':
                    async def analyze(values, role_instructions=None, max_turns=None, node_id=None, goal_override=None, role_override=None):
                        async def disabled(url):
                            return {'error': 'Evidence-only analysis has no target access.'}
                        # Bounded evidence is untrusted input. No target or network tools attached.
                        goal = goal_override or analysis_goal(config['goal'], values)
                        extra = {} if role_instructions is None else {'role_instructions': role_instructions}
                        if max_turns is not None:
                            extra['max_turns'] = max_turns
                        if ctl.model is not None:
                            extra['model'] = ctl.model
                        extra.update(usage_run_id=rid, usage_node_id=node_id, usage_purpose='team_synthesis' if role_override=='lead' else 'workflow_analysis',
                                     usage_role=role_override or next((key for key, role in team_leader.ROLES.items() if role['focus']==role_instructions), 'analyst'))
                        if assessor is None:extra['evidence_only']=True
                        return await role_assess(ctl,rid,extra['usage_role'],[],goal,disabled,**extra)
                    result=await execute_workflow(rid,config,ctl,store,fetch,probe,analyze,asset_graph=asset_graph)
                elif config['engine']=='inventory':
                    result=await inventory()
                elif config['engine']=='team':
                    # Members share this run's fetch/probe, so they draw on one
                    # budget ledger, scope and credential snapshot. The resolved
                    # model lives on the control object only, never persisted.
                    async def synthesize(prompt, *, max_turns):
                        # The optional lead synthesizer reviews role reports only;
                        # it gets no target access and never confirms a finding.
                        async def disabled(url):
                            return {'error': 'Team synthesis has no target access.'}
                        return await role_assess(ctl,rid,'lead',[],prompt,disabled,evidence_only=True,
                            max_turns=max_turns,usage_run_id=rid,usage_role='lead',usage_purpose='team_synthesis')
                    async def team_assess(*args, **kwargs):
                        role = next((key for key, spec in team_leader.ROLES.items() if spec['focus']==kwargs.get('role_instructions')), 'analyst')
                        return await role_assess(ctl,rid,role,*args,usage_run_id=rid,usage_role=role,usage_purpose='team_member',**kwargs)
                    # Adaptive selection (opt-in, no explicit roles): gather the
                    # entered scope's existing observations and asset-graph entities
                    # so the deterministic leader can narrow the roles. No evidence
                    # (e.g. a first run) falls back to the full set.
                    team_adaptive = bool(config.get('adaptive') and not config.get('roles'))
                    team_evidence, team_assets = None, None
                    if team_adaptive:
                        team_evidence = await asyncio.to_thread(gather_team_evidence, config['targets'])
                        team_assets = (await asyncio.to_thread(asset_graph.scope_subgraph, config['targets']))['entities']
                    result=await team_leader.run_team(config['targets'],config['goal'],fetch,probe,team_assess,
                                                       roles=config.get('roles'),model=ctl.model,
                                                       member_max_turns=config.get('member_max_turns',8),
                                                       timeout=min(config.get('max_seconds',240),180),
                                                       concurrency=config.get('parallelism',4),
                                                       synthesize=synthesize if config.get('synthesize') else None,
                                                       adaptive=team_adaptive, evidence=team_evidence,
                                                       asset_entities=team_assets, max_workers=config.get('member_workers'),
                                                       team_max_turns=config.get('team_max_turns',team_leader.DEFAULT_TEAM_TURNS),
                                                       on_budget=lambda budget: store.event(rid, 'team.turn_budget', budget),
                                                       profile=config.get('team_profile','classic'),
                                                       on_handoff=lambda packet:store.artifact(rid,'team-handoff-'+packet['recipient']+'.json',packet),
                                                       on_member=lambda result:store.artifact(rid,'team-member-'+result['role']+'.json',result))
                elif assessor is None:
                    result=await assess(config['targets'],config['goal'],fetch,network_tool=probe, usage_run_id=rid)
                else:
                    result=await assess(config['targets'],config['goal'],fetch, usage_run_id=rid)
            await ctl.gate.wait()
            if ctl.cancelled:
                raise asyncio.CancelledError()
            result['request_count'] = ctl.requests
            result['cli_invocation_count'] = ctl.cli_invocations
            result['model_usage'] = usage.summary(run_id=rid)
            aid = store.artifact(rid, 'assessment-report.json', result)
            status = 'failed' if result.get('failed_nodes') else 'completed'
            store.status(rid, status, result)
            store.event(rid, f'run.{status}', {'artifact_id': aid, 'request_count': ctl.requests,'cli_invocation_count':ctl.cli_invocations})
        except asyncio.CancelledError:
            store.status(rid, 'cancelled', {'request_count':ctl.requests,'cli_invocation_count':ctl.cli_invocations,
                                            'model_usage': usage.summary(run_id=rid)})
            store.event(rid, 'run.cancelled', {'request_count': ctl.requests,'cli_invocation_count':ctl.cli_invocations})
        except Exception as exc:
            ctl.cancelled = True  # A timed-out HTTP worker must not dispatch after DNS returns.
            ctl.gate.set()
            # Do not persist SDK exception bodies that may contain secrets or prompts.
            message = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
            store.status(rid, 'failed', {'error': message[:500], 'request_count': ctl.requests,'cli_invocation_count':ctl.cli_invocations,
                                       'model_usage': usage.summary(run_id=rid)})
            store.event(rid, 'run.failed', {'error': message[:500]})
        finally:
            ctl.verification_identities.clear()
            ctl.verification_fingerprint_key = None

    def gather_team_evidence(targets, limit=200):
        """Existing in-scope observations for adaptive team role selection. Read
        only; never initiates traffic. Returns observation records for assets in
        the explicit entered host/URL scope."""
        scopes = [parse_target(value) for value in targets]
        def in_scope(asset):
            try:
                value = canonical_asset(asset) or str(asset)
                if value.startswith('tcp://'):
                    host = urlsplit(value).hostname
                    return bool(host) and any(t.kind != 'url' and host_matches(host, t) for t in scopes)
                if '://' in value:
                    authorize(value, scopes)
                    return True
                host = parse_target(value).host
                return bool(host) and any(t.kind != 'url' and host_matches(host, t) for t in scopes)
            except ScopeError:
                return False
        return [item for item in evidence.observations(limit=limit)['items'] if in_scope(item.get('asset'))]

    def prepare_config(body):
        known = {t['id']: t for t in store.targets()}
        if any(tid not in known for tid in body.target_ids):
            raise HTTPException(422, 'Select only existing entered targets.')
        if any(not 1 <= p <= 65535 for p in body.ports):
            raise HTTPException(422, 'TCP ports must be integers from 1 to 65535.')
        if not body.target_ids and body.engine!='workflow':raise HTTPException(422,'Select at least one entered target.')
        if body.engine == 'workflow':
            validate_workflow(body.workflow, live=True)
        if body.engine in ('team','workflow'):
            try:
                team_leader.resolve_roles(body.roles)
            except ValueError as exc:
                raise HTTPException(422, str(exc))
        try:
            validate_routes({k:v.model_dump(exclude_none=True) for k,v in body.team_routes.items()},[*team_leader.ROLES,'lead'])
        except ValueError as exc:
            raise HTTPException(422,str(exc)) from None
        if body.team_routes and body.engine not in ('team','workflow'):
            raise HTTPException(422,'Per-role model routes require a team or analyst workflow.')
        needs_model = body.engine in ('cai','team') or (body.engine == 'workflow' and body.allow_http and any(n['data']['kind'] in ('native_cai','native_team') for n in body.workflow['nodes']))
        if assessor is None and needs_model:
            if cai_adapter.installed_version() != cai_adapter.SUPPORTED_CAI:
                raise HTTPException(409, 'CAI SDK is not installed at the supported version. See local setup instructions.')
            model_base_url(os.environ.get('CAI_MODEL_BASE_URL', 'http://127.0.0.1:11434/v1'), os.environ.get('CAI_ALLOW_REMOTE_MODEL') == '1')
        config = {**body.model_dump(), 'targets': list(dict.fromkeys(known[tid]['url'] for tid in body.target_ids))}
        config['http_routing_binding']=routing_binding(config['http_routing'],store)
        allowed_keys={key for tool in TOOLS.values() for key in tool.get('secrets',[]) if key not in MODEL_VARS}
        if any(key not in allowed_keys for key in body.cli_credential_keys):raise HTTPException(422,'Select only catalog-declared credential variable names.')
        from .identity_graph import identity_workflow
        identity_only=body.engine=='workflow' and identity_workflow(body.workflow)
        if body.engine in ('inventory','workflow','team') and body.allow_http and not identity_only:
            entered=[parse_target(t) for t in config['targets']]
            for target in entered:
                if target.kind not in ('url','wildcard'):
                    network_hosts(target.url,entered,body.max_hosts)
        return config

    @app.post('/api/runs/preflight')
    async def preflight_run(body: RunInput):
        config=prepare_config(body)
        if body.engine in ('team','workflow') and (body.engine=='team' or body.team_routes or body.provider or body.model):
            resolve_team_models(config)
        if body.engine!='workflow':return {'ready':True,'issues':[]}
        result=catalog_preflight(body.workflow,config,store,check_binaries=body.allow_http,credentials=configured_secret_keys())
        return {k:v for k,v in result.items() if k not in ('cli_binaries','input_snapshots')}

    @app.post('/api/runs', status_code=201)
    async def create_run(body: RunInput):
        async with dispatch_lock:
            check_run_capacity()
            config=await asyncio.to_thread(prepare_config,body)
            if body.engine=='workflow' and body.allow_http:
                ready=await asyncio.to_thread(catalog_preflight,body.workflow,config,store,credentials=configured_secret_keys())
                if not ready['ready']:raise HTTPException(422,{'message':'Catalog preflight failed.','issues':ready['issues']})
                config.update(cli_binaries=ready['cli_binaries'],input_snapshots=ready['input_snapshots'])
            # Resolve the selected model for a team run in the request path so the
            # provider gate (409/422) applies before the run is created. The
            # resolved config (with its key) is passed to the control object only.
            resolved_model = resolve_team_models(config) if body.engine=='team' or (body.engine=='workflow' and (body.team_routes or body.provider or body.model)) else None
            run = store.new_run(config)
            start_run(run, model=resolved_model)
        return run

    def check_run_capacity():
        if sum(not c.task.done() for c in controls.values() if c.task) >= 2:
            raise HTTPException(409, 'Two local runs are already active.')

    def start_run(run, model=None, credentials=None):
        usage.start_run(run['id'])
        ctl = RunControl()
        try:
            ctl.http_routing=resolve_routing(run['config'].get('http_routing'),store)
            expected=run['config'].get('http_routing_binding')
            if expected and {**ctl.http_routing.config,'ca_sha256':ctl.http_routing.ca_sha256}!=expected:
                raise ScopeError('HTTP routing or CA trust changed after preparation.')
        except (ValueError,ScopeError):
            store.status(run['id'],'failed',{'error':'HTTP routing or CA trust changed before dispatch.'})
            return
        if access := (run['config'].get('verification') or {}).get('access'):
            try:
                ctl.verification_identities = test_identities.snapshot(access)
            except ScopeError as exc:
                store.status(run['id'], 'failed', {'error': str(exc)})
                return
            ctl.verification_fingerprint_key = secrets.token_bytes(32)
        ctl.model = model.get('default') if model and 'routes' in model else model
        ctl.team_routes = model.get('routes',{}) if model else {}
        ctl.team_task_level = run['config'].get('team_task_level','standard')
        # Snapshot the selected credentials once, server-side, for the whole run
        # so a concurrent settings change cannot alter an in-flight run. The
        # snapshot lives only on the control object, never in the persisted run.
        ctl.credentials = credentials if credentials is not None else {
            key: vault.effective(key) for key in run['config'].get('cli_credential_keys', []) if vault.effective(key)}
        controls[run['id']] = ctl
        ctl.task = asyncio.create_task(execute(run['id'], run['config'], ctl))

    @app.post('/api/agent/proposals/{plan_id}/{proposal_id}/executions', status_code=201)
    async def prepare_proposal_execution(plan_id: str, proposal_id: str, body: ExecutionOptions):
        return await asyncio.to_thread(proposal_executions.prepare, plan_id, proposal_id, body.model_dump())

    @app.get('/api/agent/proposals/{plan_id}/executions')
    def proposal_execution_history(plan_id: str):
        # Historic execution receipts remain readable even when a plan becomes stale.
        proposal_plan(plan_id)
        return proposal_executions.history(plan_id)

    @app.get('/api/agent/executions/{execution_id}')
    def proposal_execution_review(execution_id: str):
        return proposal_executions.get(execution_id)

    @app.post('/api/agent/executions/{execution_id}/revoke')
    async def revoke_proposal_execution(execution_id: str, body: SnapshotAction):
        return await asyncio.to_thread(proposal_executions.revoke, execution_id, body.expected_hash)

    @app.post('/api/agent/executions/{execution_id}/dispatch')
    async def dispatch_proposal_execution(execution_id: str, body: DispatchAction):
        if body.approve is not True:
            raise HTTPException(422, 'Explicit operator approval is required to start this execution.')
        async def consume_and_start():
            async with dispatch_lock:
                receipt = await asyncio.to_thread(proposal_executions.get, execution_id)
                if receipt['status'] == 'pending':
                    check_run_capacity()
                run, created = await asyncio.to_thread(proposal_executions.dispatch, execution_id, body.expected_hash)
                if created:
                    start_run(run)
                return {'run': run, 'created': created, 'execution_id': execution_id}
        task = asyncio.create_task(consume_and_start())
        dispatch_tasks.add(task)
        def finished(job):
            dispatch_tasks.discard(job)
            if not job.cancelled():
                job.exception()  # Retrieve failures even if the requesting client disconnected.
        task.add_done_callback(finished)
        return await asyncio.shield(task)

    @app.get('/api/runs/{rid}/recovery')
    def inspect_recovery(rid: str):
        return recoveries.inspect(rid)

    @app.post('/api/runs/{rid}/recoveries', status_code=201)
    async def prepare_recovery(rid: str, body: RecoveryOptions):
        return await asyncio.to_thread(recoveries.prepare, rid, body.model_dump())

    @app.get('/api/recoveries/{recovery_id}')
    def recovery_review(recovery_id: str):
        return recoveries.get(recovery_id)

    @app.post('/api/recoveries/{recovery_id}/revoke')
    async def revoke_recovery(recovery_id: str, body: SnapshotAction):
        return await asyncio.to_thread(recoveries.revoke, recovery_id, body.expected_hash)

    @app.post('/api/recoveries/{recovery_id}/dispatch')
    async def dispatch_recovery(recovery_id: str, body: DispatchAction):
        if body.approve is not True:
            raise HTTPException(422, 'Explicit operator approval is required to recover this workflow.')
        async def consume_and_start():
            async with dispatch_lock:
                receipt = await asyncio.to_thread(recoveries.get, recovery_id)
                if receipt['status'] == 'pending':
                    check_run_capacity()
                run, created, credentials, model = await asyncio.to_thread(recoveries.dispatch, recovery_id, body.expected_hash)
                if created:
                    start_run(run, credentials=credentials, model=model)
                return {'run': run, 'created': created, 'recovery_id': recovery_id}
        task = asyncio.create_task(consume_and_start())
        dispatch_tasks.add(task)
        def finished(job):
            dispatch_tasks.discard(job)
            if not job.cancelled():
                job.exception()
        task.add_done_callback(finished)
        return await asyncio.shield(task)

    @app.post('/api/runs/{rid}/{action}')
    async def control(rid: str, action: str):
        run = get_run(rid)
        ctl = controls.get(rid)
        if action not in ('pause', 'resume', 'cancel'):
            raise HTTPException(404, 'Unknown run action.')
        if not ctl or ctl.task.done() or run['status'] not in ('queued', 'running', 'paused'):
            raise HTTPException(409, 'Run is no longer active.')
        if action == 'pause':
            ctl.gate.clear()
            pause_processes(ctl,True)
            store.status(rid, 'paused')
        elif action == 'resume':
            pause_processes(ctl,False)
            ctl.gate.set()
            store.status(rid, 'running')
        else:
            ctl.cancelled = True
            pause_processes(ctl,False)
            ctl.gate.set()
            ctl.task.cancel()
            store.status(rid, 'cancelled')
        store.event(rid, f'run.{action}', {'request_count': ctl.requests})
        return get_run(rid)

    ui = Path(__file__).resolve().parent.parent / 'dist' / 'client'
    if ui.exists():
        app.mount('/', StaticFiles(directory=ui, html=True), name='local-ui')
    return app
