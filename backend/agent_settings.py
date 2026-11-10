"""Local, revisioned agent preferences. No credential resolution or model calls."""
import json
import sqlite3
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .store import now
from .team import ROLES
from .team_routing import ModelChoice


class SettingsChoice(ModelChoice):
    # Draft routes may be saved before a model is chosen. Run validation still
    # requires a complete ModelChoice, independently of saved preferences.
    model: str = Field(default='', max_length=120)


class SettingsRoute(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    primary: SettingsChoice
    fallback: SettingsChoice | None = None
    complex_task: SettingsChoice | None = None


class AgentSettings(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    schema_version: Literal[1] = 1
    default_model: SettingsChoice = Field(default_factory=lambda: SettingsChoice(provider='local'))
    planner_model: SettingsChoice = Field(default_factory=lambda: SettingsChoice(provider='local'))
    team_profile: Literal['classic', 'specialist'] = 'classic'
    team_task_level: Literal['standard', 'complex'] = 'standard'
    roles: list[str] = Field(default_factory=list, max_length=len(ROLES))
    member_max_turns: int = Field(default=8, ge=1, le=24)
    team_max_turns: int = Field(default=48, ge=1, le=144)
    member_workers: int = Field(default=3, ge=1, le=8)
    synthesize: bool = False
    adaptive: bool = False
    team_routes: dict[str, SettingsRoute] = Field(default_factory=dict, max_length=len(ROLES)+1)

    @field_validator('roles')
    @classmethod
    def known_roles(cls, value):
        if len(set(value)) != len(value) or any(role not in ROLES for role in value):
            raise ValueError('Select unique registered analyst roles.')
        return value

    @field_validator('team_routes')
    @classmethod
    def known_routes(cls, value):
        if any(role not in {*ROLES, 'lead'} for role in value):
            raise ValueError('Unknown agent route role.')
        return value


class PresetInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    name: str = Field(min_length=1, max_length=80)
    settings: AgentSettings
    is_default: bool = False
    revision: int | None = Field(default=None, ge=1)

    @field_validator('name')
    @classmethod
    def clean_name(cls, value):
        value = value.strip()
        if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Enter a printable preset name.')
        return value


class PresetRevision(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    revision: int = Field(ge=1)


class SettingsConflict(ValueError):
    pass


class AgentPresets:
    def __init__(self, store):
        self.store = store
        with store.connect() as c:
            c.executescript('''
                CREATE TABLE IF NOT EXISTS agent_settings(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    settings TEXT NOT NULL, revision INTEGER NOT NULL,
                    is_default INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL, updated TEXT NOT NULL);
                CREATE UNIQUE INDEX IF NOT EXISTS one_default_agent_settings
                    ON agent_settings(is_default) WHERE is_default=1;
            ''')

    @staticmethod
    def decode(row):
        return {**dict(row), 'settings': json.loads(row['settings']), 'is_default': bool(row['is_default'])}

    def get(self, identifier):
        with self.store.connect() as c:
            row = c.execute('SELECT * FROM agent_settings WHERE id=?', (identifier,)).fetchone()
        if row is None:
            raise KeyError(identifier)
        return self.decode(row)

    def index(self):
        with self.store.connect() as c:
            presets = [self.decode(r) for r in c.execute('SELECT * FROM agent_settings ORDER BY name COLLATE NOCASE')]
        models = {}
        for preset in presets:
            s = preset['settings']
            choices = [s['default_model'], s['planner_model']]
            choices += [v for route in s['team_routes'].values() for v in route.values() if v]
            for choice in choices:
                if choice['model']:
                    models.setdefault(choice['provider'], set()).add(choice['model'])
        return {'items': [{k:v for k,v in p.items() if k != 'settings'} for p in presets],
                'default': next((p for p in presets if p['is_default']), None),
                'saved_models': {k:sorted(v) for k,v in models.items()}}

    def save(self, body: PresetInput, identifier=None):
        updating = identifier is not None
        with self.store.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            if identifier:
                old = c.execute('SELECT revision FROM agent_settings WHERE id=?', (identifier,)).fetchone()
                if old is None or old['revision'] != body.revision:
                    raise SettingsConflict('Preset changed or was removed. Reload it before saving.')
            elif body.revision is not None:
                raise ValueError('A new preset cannot have a revision.')
            elif c.execute('SELECT count(*) FROM agent_settings').fetchone()[0] >= 50:
                raise SettingsConflict('Keep at most 50 presets. Remove an unused preset first.')
            identifier = identifier or str(uuid.uuid4())
            if body.is_default:
                c.execute('UPDATE agent_settings SET is_default=0,revision=revision+1,updated=? WHERE is_default=1 AND id<>?', (now(), identifier))
            try:
                if updating:
                    c.execute('UPDATE agent_settings SET name=?,settings=?,revision=revision+1,is_default=?,updated=? WHERE id=?',
                              (body.name, body.settings.model_dump_json(exclude_none=True), int(body.is_default), now(), identifier))
                else:
                    c.execute('INSERT INTO agent_settings VALUES(?,?,?,?,?,?,?)',
                              (identifier, body.name, body.settings.model_dump_json(exclude_none=True), 1, int(body.is_default), now(), now()))
            except sqlite3.IntegrityError:
                raise SettingsConflict('That preset name is already in use.') from None
            # Read inside the write transaction so the caller gets its own revision.
            result = self.decode(c.execute('SELECT * FROM agent_settings WHERE id=?', (identifier,)).fetchone())
        return result

    def delete(self, identifier, revision):
        with self.store.connect() as c:
            changed = c.execute('DELETE FROM agent_settings WHERE id=? AND revision=?', (identifier, revision))
            if changed.rowcount != 1:
                raise SettingsConflict('Preset changed or was removed. Reload it before deleting.')

