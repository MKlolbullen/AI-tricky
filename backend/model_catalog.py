"""Small reviewed menu, not account discovery or a compatibility guarantee.

Only model identifiers/labels are included. Credentials, pricing and rankings
do not belong here. Custom IDs remain valid settings independently of this menu.
"""

REVIEWED = '2026-11-10'
PROVIDERS = {
    'openai': ('https://developers.openai.com/api/docs/models', [
        ('gpt-5.4', 'GPT-5.4'), ('gpt-5.4-mini', 'GPT-5.4 Mini')]),
    'anthropic': ('https://platform.claude.com/docs/en/models/overview', [
        ('claude-opus-5-5', 'Claude Opus 5.5'), ('claude-sonnet-5-5', 'Claude Sonnet 5.5'),
        ('claude-haiku-5-5', 'Claude Haiku 5.5')]),
    'gemini': ('https://ai.google.dev/gemini-api/docs/models', [
        ('gemini-3.8-flash', 'Gemini 3.8 Flash'), ('gemini-3.5-flash-lite', 'Gemini 3.5 Flash-Lite'),
        ('gemini-3.1-pro-preview', 'Gemini 3.1 Pro Preview')]),
    'venice': ('https://docs.venice.ai/models/text', [
        ('zai-org-glm-5-2', 'GLM 5.2'), ('zai-org-glm-5', 'GLM 5')]),
    'xai': ('https://docs.x.ai/developers/models', [
        ('grok-4.7', 'Grok 4.7'), ('grok-4.3', 'Grok 4.3')]),
}


def model_catalog():
    return {provider: {'reviewed': REVIEWED, 'source': source,
                       'models': [{'id': identifier, 'name': name} for identifier, name in choices]}
            for provider, (source, choices) in PROVIDERS.items()}
