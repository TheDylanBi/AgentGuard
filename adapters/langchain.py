"""LangChain adapter (P5).

Two integration styles:

1. ``GuardedTool`` — a standalone guarded wrapper (works without langchain).
2. ``GuardedBaseTool`` — a LangChain ``BaseTool`` subclass, created lazily so
   this module imports cleanly even when langchain is not installed.
"""
from .sdk import AuthorizationBlocked, AuthorizationNeedsConfirm, ICBGuardClient


class GuardedTool:
    """Framework-agnostic guarded tool with LangChain-style run/invoke/arun."""

    def __init__(
        self,
        client: ICBGuardClient,
        tool_id: str,
        action_type: str,
        fn,
        capabilities=None,
        intent: str = "",
        intent_provider=None,
        screenshot=None,
        screenshot_path=None,
        a11y_snapshot=None,
        target_from=None,
    ):
        self.client = client
        self.tool_id = tool_id
        self.action_type = action_type
        self.fn = fn
        self.capabilities = capabilities
        self.intent = intent
        self.intent_provider = intent_provider
        self.screenshot = screenshot
        self.screenshot_path = screenshot_path
        self.a11y_snapshot = a11y_snapshot
        self.target_from = target_from
        self._cert_id = None

    def _authorize(self, target: str):
        if self.capabilities is not None and self._cert_id is None:
            self._cert_id = self.client.register_tool(self.tool_id, self.capabilities)
        it = self.intent_provider() if self.intent_provider else self.intent
        return self.client.authorize(
            self.tool_id, self.action_type, target, it,
            capability_cert_id=self._cert_id,
            screenshot=self.screenshot, screenshot_path=self.screenshot_path,
            a11y_snapshot=self.a11y_snapshot,
        )

    def run(self, target: str, **kwargs):
        result = self._authorize(target)
        if result.blocked:
            raise AuthorizationBlocked(result.reason, result)
        if result.needs_confirm:
            raise AuthorizationNeedsConfirm(result.confirm_token, result)
        return self.fn(target, **kwargs)

    def invoke(self, inputs):
        target = inputs.get("target") or inputs.get("input") or ""
        return self.run(target)

    async def arun(self, target: str, **kwargs):
        return self.run(target, **kwargs)


def make_guarded_base_tool(
    client: ICBGuardClient,
    tool_id: str,
    action_type: str,
    name: str,
    description: str,
    fn,
    capabilities=None,
    intent: str = "",
    intent_provider=None,
    screenshot=None,
    screenshot_path=None,
    a11y_snapshot=None,
    target_from=None,
):
    """Return a LangChain BaseTool subclass instance (requires langchain_core)."""
    from langchain_core.tools import BaseTool

    guarder = GuardedTool(
        client, tool_id, action_type, fn,
        capabilities=capabilities, intent=intent, intent_provider=intent_provider,
        screenshot=screenshot, screenshot_path=screenshot_path,
        a11y_snapshot=a11y_snapshot, target_from=target_from,
    )

    class _Guarded(BaseTool):
        name: str = name
        description: str = description

        def _run(self, tool_input: str, **kwargs):
            return guarder.run(tool_input, **kwargs)

        async def _arun(self, tool_input: str, **kwargs):
            return guarder.run(tool_input, **kwargs)

    return _Guarded()
