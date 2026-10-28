"""Run-local reviewer settings; never change the action model configuration."""
from contextlib import contextmanager
import os


THINKING_KEYS = (
    'ICB_REVIEW_THINKING_MODE', 'ICB_REVIEW_RETRY_THINKING_MODE',
    'ICB_REVIEW_ENABLE_THINKING', 'ICB_REVIEW_RETRY_ENABLE_THINKING',
    'ICB_REVIEW_REASONING_EFFORT', 'ICB_REVIEW_RETRY_REASONING_EFFORT',
    'ICB_INTENT_LLM_ENABLE_THINKING',
)
SETTINGS_KEYS = THINKING_KEYS + (
    'ICB_REVIEW_MAX_TOKENS', 'ICB_REVIEW_RETRY_MAX_TOKENS',
    'ICB_INTENT_LLM_MAX_TOKENS', 'ICB_REVIEW_CALL_TIMEOUT_SECONDS',
    'ICB_REVIEW_ACTION_RESERVE_SECONDS', 'ICB_INTENT_LLM_TIMEOUT_SECONDS',
    'ICB_REVIEW_AUTHORIZATION_PROFILE',
)


def settings_snapshot():
    return {key: os.environ.get(key) for key in SETTINGS_KEYS}


@contextmanager
def reviewer_environment(args):
    original = settings_snapshot()
    try:
        mode = args.review_thinking_mode
        # Do not infer provider capabilities from an endpoint URL. Preserve any
        # operator thinking controls in auto mode, including vLLM controls.
        if mode == 'auto':
            model = os.environ.get('ICB_INTENT_LLM_MODEL', '').lower()
            mode = ('disabled' if model.startswith('deepseek-') and
                    not any(os.environ.get(k) is not None for k in THINKING_KEYS)
                    else 'inherit')
        if mode != 'inherit':
            for key in THINKING_KEYS:
                os.environ.pop(key, None)
            os.environ['ICB_REVIEW_THINKING_MODE'] = mode
            os.environ['ICB_REVIEW_RETRY_THINKING_MODE'] = mode
        if args.review_max_tokens is not None:
            os.environ['ICB_REVIEW_MAX_TOKENS'] = str(args.review_max_tokens)
            os.environ['ICB_REVIEW_RETRY_MAX_TOKENS'] = str(args.review_max_tokens)
        elif not any(os.environ.get(k) is not None for k in
                     ('ICB_REVIEW_MAX_TOKENS', 'ICB_INTENT_LLM_MAX_TOKENS')):
            os.environ['ICB_REVIEW_MAX_TOKENS'] = '4096'
        os.environ['ICB_REVIEW_AUTHORIZATION_PROFILE'] = args.authorization_profile
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
