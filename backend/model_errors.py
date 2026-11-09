"""Sanitized provider transport failures eligible for explicitly configured fallback."""


class ProviderUnavailable(RuntimeError):
    def __init__(self):
        super().__init__('Model provider temporarily unavailable.')
        self.model_usage_id = None


def transient_provider_error(exc):
    # Only failures from the actual provider client qualify. Parsing, auth,
    # scope, target-tool and SDK errors must not select a different provider.
    return type(exc).__module__.startswith('openai') and (
        getattr(exc, 'status_code', None) == 429 or
        isinstance(getattr(exc, 'status_code', None), int) and 500 <= exc.status_code <= 599 or
        type(exc).__name__ in ('APIConnectionError', 'APITimeoutError'))
