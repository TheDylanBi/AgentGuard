"""BrowserGym adapter (P5).

BrowserGym agents receive an ``obs`` dict (screenshot + accessibility text)
and call an ``action`` function with a string like ``"click [1234]"``. This
adapter guards that action call: it extracts the action type, builds the
visual state from obs, authorizes against the gateway, and only then runs
the underlying action.
"""
from .sdk import AuthorizationBlocked, AuthorizationNeedsConfirm, ICBGuardClient

_ACTION_TYPES = {"click", "type", "scroll", "hover", "dblclick", "fill",
                 "select_option", "upload_file", "go_back", "go_forward"}


def _parse_action(action_str: str):
    parts = action_str.strip().split(maxsplit=1)
    action_type = parts[0] if parts else "click"
    if action_type not in _ACTION_TYPES:
        action_type = "click"  # BrowserGym id-based actions map to click
    target = parts[1] if len(parts) > 1 else action_str.strip()
    return action_type, target


class GuardBrowserGymAction:
    def __init__(
        self,
        client: ICBGuardClient,
        tool_id: str,
        capabilities=None,
        intent_provider=None,
        action_fn=None,
        screenshot_key: str = "screenshot",
    ):
        self.client = client
        self.tool_id = tool_id
        self.capabilities = capabilities
        self.intent_provider = intent_provider
        self.action_fn = action_fn
        self.screenshot_key = screenshot_key
        self._cert_id = None

    def __call__(self, action_str: str, obs: dict):
        action_type, target = _parse_action(action_str)

        if self.capabilities is not None and self._cert_id is None:
            self._cert_id = self.client.register_tool(self.tool_id, self.capabilities)

        intent = self.intent_provider() if self.intent_provider else ""
        screenshot = obs.get(self.screenshot_key)
        a11y = obs.get("a11y_snapshot")  # optional pre-built node list

        result = self.client.authorize(
            self.tool_id, action_type, target, intent,
            capability_cert_id=self._cert_id,
            screenshot=screenshot,
            a11y_snapshot=a11y,
        )
        if result.blocked:
            raise AuthorizationBlocked(result.reason, result)
        if result.needs_confirm:
            raise AuthorizationNeedsConfirm(result.confirm_token, result)

        if self.action_fn is not None:
            return self.action_fn(action_str)
        return result
