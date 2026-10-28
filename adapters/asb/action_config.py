"""Reuse AgentDojo's pi models/auth files without exporting their credentials."""
import json
import os
from pathlib import Path
import re

PROJECT = Path(__file__).resolve().parents[2]


class ActionConfigurationError(ValueError):
    """Finite diagnostics only: never include config contents or credentials."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def default_pi_directory():
    local = PROJECT / '.local-qwen'
    return local if (local / 'models.json').is_file() else Path.home() / '.pi/agent'


def resolve_value(value):
    if value is None:
        return ''
    if not isinstance(value, str):
        raise ActionConfigurationError('invalid_pi_string_value')
    if value.startswith('!'):
        raise ActionConfigurationError('pi_shell_config_values_require_explicit_export')
    missing = False
    def substitute(match):
        nonlocal missing
        name = match.group(1) or match.group(2)
        found = os.environ.get(name, '')
        if not found:
            missing = True
        return found
    result = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)', substitute, value)
    return '' if missing else result


def read_config(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        raise ActionConfigurationError('cannot_read_pi_configuration') from None
    if not isinstance(value, dict):
        raise ActionConfigurationError('invalid_pi_configuration')
    return value


def resolve_action_config(args):
    source = getattr(args, 'action_config', 'agentdojo')
    explicit_budget = args.max_tokens
    common = {'tool_schema': args.tool_schema, 'max_requests': args.max_requests}
    if source == 'env':
        return {**common, 'source': 'environment', 'provider': None,
            'model': args.model or os.environ.get('ASB_ACTION_MODEL', ''),
            'base_url': os.environ.get('ASB_ACTION_BASE_URL', os.environ.get('OPENAI_BASE_URL', 'https://api.openai.com/v1')),
            'api_key': os.environ.get('ASB_ACTION_API_KEY', os.environ.get('OPENAI_API_KEY', '')),
            'max_tokens': explicit_budget or 256, 'max_tokens_field': 'max_tokens', 'headers': {}}
    directory = (args.pi_agent_dir or default_pi_directory()).resolve()
    document = read_config(directory / 'models.json')
    providers = document.get('providers')
    if not isinstance(providers, dict):
        raise ActionConfigurationError('pi_providers_missing')
    candidates = []
    for name, provider in providers.items():
        if args.provider and name != args.provider:
            continue
        if not isinstance(provider, dict):
            raise ActionConfigurationError('invalid_pi_provider')
        for model in provider.get('models', []):
            if not isinstance(model, dict) or not isinstance(model.get('id'), str):
                raise ActionConfigurationError('invalid_pi_model')
            if args.model and model['id'] != args.model:
                continue
            candidates.append((name, provider, model))
    if len(candidates) != 1:
        raise ActionConfigurationError('select_one_pi_provider_and_model' if candidates else 'pi_model_not_found')
    name, provider, model = candidates[0]
    if model.get('api', provider.get('api')) != 'openai-completions':
        raise ActionConfigurationError('pi_api_must_be_openai_completions')
    endpoint = resolve_value(model.get('baseUrl', provider.get('baseUrl')))
    if not endpoint:
        raise ActionConfigurationError('pi_base_url_missing')
    # Match the stored API-key credential when present; otherwise use the
    # custom provider's key or environment reference, as in the pi setup.
    credential = None
    auth_path = directory / 'auth.json'
    if auth_path.is_file():
        auth = read_config(auth_path).get(name)
        if auth is not None:
            if not isinstance(auth, dict) or auth.get('type') != 'api_key':
                raise ActionConfigurationError('pi_oauth_not_supported_by_asb_transport')
            credential = auth.get('key')
    if credential is None:
        credential = provider.get('apiKey')
    headers = {}
    for settings in (provider, model):
        declared = settings.get('headers', {})
        if not isinstance(declared, dict):
            raise ActionConfigurationError('invalid_pi_headers')
        for header, value in declared.items():
            resolved = resolve_value(value)
            if not resolved:
                raise ActionConfigurationError('pi_header_environment_missing')
            headers[header] = resolved
    compatibility = {**provider.get('compat', {}), **model.get('compat', {})}
    token_field = compatibility.get('maxTokensField', 'max_tokens')
    if token_field not in {'max_tokens', 'max_completion_tokens'}:
        raise ActionConfigurationError('unsupported_pi_max_tokens_field')
    budget = explicit_budget if explicit_budget is not None else model.get('maxTokens', 256)
    if type(budget) is not int or budget < 1:
        raise ActionConfigurationError('invalid_pi_output_budget')
    return {**common, 'source': 'agentdojo_pi', 'pi_agent_dir': str(directory), 'provider': name,
            'model': model['id'], 'base_url': endpoint, 'api_key': resolve_value(credential),
            'max_tokens': budget, 'max_tokens_field': token_field, 'headers': headers}
