"""Explicit per-role routing. Resolved credentials remain on run controls only."""
import asyncio
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .model_errors import ProviderUnavailable


class ModelChoice(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    provider: Literal['local', 'openai', 'anthropic', 'gemini', 'venice', 'xai']
    model: str = Field(min_length=1, max_length=120)

    @field_validator('model')
    @classmethod
    def clean_model(cls, value):
        if value != value.strip() or any(ord(c) < 33 for c in value) or '://' in value:
            raise ValueError('Use an explicit model ID without whitespace or endpoint URLs.')
        return value


class ModelRoute(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    primary: ModelChoice
    fallback: ModelChoice | None = None
    complex_task: ModelChoice | None = None


def validate_routes(value, allowed_roles):
    if not isinstance(value, dict) or set(value) - set(allowed_roles):
        raise ValueError('Model routes must name supported team roles or lead.')
    return {role: ModelRoute.model_validate(route).model_dump(exclude_none=True) for role, route in value.items()}


class RoutedFailure(RuntimeError):
    def __init__(self, attempts):
        super().__init__('Model pass did not complete; inspect its recorded route attempts.')
        self.attempts = attempts


async def execute_route(call, *, role, allowance, inherited=None, route=None, on_event=None, task_level='standard'):
    """Reserve fallback capacity *inside* the role cap, even without usage data.

    Primary gets ceil(cap/2) and fallback gets floor(cap/2). Without a fallback
    the primary gets the whole cap. Never switch providers after a refusal,
    malformed report, target error or cancellation. No second-provider default.
    """
    choices = [route.get('complex_task',route['primary']) if task_level=='complex' else route['primary']] if route else [inherited]
    if route and route.get('fallback'):
        choices.append(route['fallback'])
    limits = [(allowance + 1)//2, allowance//2] if len(choices)==2 else [allowance]
    attempts=[]
    for index, (choice, limit) in enumerate(zip(choices, limits)):
        if not limit:
            break
        attempt={'provider': (choice or {}).get('provider', 'configured'),
                 'model': (choice or {}).get('model', 'configured model'),
                 'max_turns':limit, 'fallback':bool(index), 'status':'running'}
        attempt['task_level']=task_level
        attempts.append(attempt)
        if on_event: on_event('team.model_started', {'role':role, **attempt})
        try:
            out=await call(choice,limit)
        except asyncio.CancelledError:
            attempt['status']='cancelled'
            if on_event: on_event('team.model_finished', {'role':role, **attempt})
            raise
        except Exception as exc:
            attempt.update(status='failed', error_code='provider_unavailable' if isinstance(exc,ProviderUnavailable) else 'assessment_failed')
            if getattr(exc,'model_usage_id',None):attempt['model_usage_id']=exc.model_usage_id
            if on_event: on_event('team.model_finished', {'role':role, **attempt})
            if not isinstance(exc,ProviderUnavailable):
                raise RoutedFailure(attempts) from None
        else:
            attempt.update(status='completed', model_usage_id=out.get('model_usage_id'))
            if on_event: on_event('team.model_finished', {'role':role, **attempt})
            return {**out,'model_attempts':attempts}
    raise RoutedFailure(attempts)
