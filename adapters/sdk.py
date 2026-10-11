"""ICB-Guard generic SDK (P5).

A minimal, framework-agnostic client. Any agent can import this, register a
capability certificate, and call ``authorize`` at its tool-call boundary.
"""
import base64
import hashlib
import io
import json
import os
import uuid
import copy
import inspect
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


class AuthorizationBlocked(Exception):
    def __init__(self, reason: str, result: "AuthorizeResult" = None):
        super().__init__(reason)
        self.result = result


class AuthorizationNeedsConfirm(Exception):
    def __init__(self, token: str, result: "AuthorizeResult" = None):
        super().__init__("authorization needs human confirmation")
        self.token = token
        self.result = result


@dataclass
class AuthorizeResult:
    verdict: str
    reason: str
    certificates: List[dict] = field(default_factory=list)
    decision_rule: Optional[str] = None
    confirm_token: Optional[str] = None
    # Progent-style least-privilege: present when the action was OUTSIDE the
    # current symbolic policy (an expansion requiring approval).
    policy_update: Optional[dict] = None
    # P4 TOCTOU binding: hash over the exact authorized action.
    decision_id: Optional[str] = None
    execution_ticket: Optional[str] = None
    request: Optional[dict] = None

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    @property
    def needs_confirm(self) -> bool:
        return self.verdict == "CONFIRM"

    @property
    def blocked(self) -> bool:
        return self.verdict == "BLOCK"


def _img_to_b64(img) -> Optional[str]:
    """Normalize Path / bytes / PIL Image / base64-str into base64 str."""
    if img is None:
        return None
    if isinstance(img, (str, os.PathLike)):
        p = Path(img)
        if p.exists():
            return base64.b64encode(p.read_bytes()).decode("ascii")
        if isinstance(img, str):
            return img  # assume already base64
        raise TypeError(f"no such file: {img!r}")
    if isinstance(img, (bytes, bytearray)):
        return base64.b64encode(bytes(img)).decode("ascii")
    if hasattr(img, "save"):  # PIL Image
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")
    raise TypeError(f"unsupported image type: {type(img)!r}")


class ICBGuardClient:
    def __init__(self, gateway_url: str = "http://127.0.0.1:8099", timeout: int = 120,
                 token: str = ""):
        self.gateway_url = gateway_url.rstrip("/")
        self.timeout = timeout
        self._cert_cache: Dict[str, str] = {}
        # P0-2: shared-secret token for the mutating endpoints.
        self._token = token or os.environ.get("ICB_EXECUTOR_TOKEN", "")
        self.session_id = uuid.uuid4().hex

    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def use_capability(self, tool_id: str, certificate_id: str):
        """Attach an administrator-provisioned grant to this executor client."""
        self._cert_cache[tool_id] = certificate_id

    # ---- registration ----
    def register_tool(
        self,
        tool_id: str,
        capabilities: Dict[str, Any],
        label: str = "",
        implementation_version: str = "0.0.0",
        implementation_hash: Optional[str] = None,
        force: bool = False,
    ) -> str:
        if not force and tool_id in self._cert_cache:
            return self._cert_cache[tool_id]
        req = {
            "tool_id": tool_id,
            "label": label or tool_id,
            "declared_capabilities": capabilities,
            "implementation_version": implementation_version,
            "implementation_hash": implementation_hash,
        }
        r = requests.post(f"{self.gateway_url}/register_tool", json=req, timeout=self.timeout,
                         headers=self._auth_headers())
        r.raise_for_status()
        cert = r.json()
        self._cert_cache[tool_id] = cert["capability_cert_id"]
        return cert["capability_cert_id"]

    # ---- authorization ----
    def authorize(
        self,
        tool_id: str,
        action_type: str,
        target: str,
        intent: str,
        capability_cert_id: Optional[str] = None,
        screenshot=None,
        screenshot_path=None,
        a11y_snapshot: Optional[List[dict]] = None,
        previous_screenshot=None,
        previous_screenshot_path=None,
        previous_a11y_snapshot: Optional[List[dict]] = None,
        session_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        intent_profile: Optional[dict] = None,
        approval_ticket: Optional[str] = None,
    ) -> AuthorizeResult:
        cert_id = capability_cert_id or self._cert_cache.get(tool_id)

        vs: Dict[str, Any] = {"mode": "screenshot"}
        b64 = _img_to_b64(screenshot) or (_img_to_b64(screenshot_path) if screenshot_path else None)
        if b64:
            vs["screenshot_b64"] = b64
        if a11y_snapshot is not None:
            vs["a11y_snapshot"] = a11y_snapshot
        prev_b64 = _img_to_b64(previous_screenshot) or (
            _img_to_b64(previous_screenshot_path) if previous_screenshot_path else None
        )
        if prev_b64:
            vs["previous_screenshot_b64"] = prev_b64
        if previous_a11y_snapshot is not None:
            vs["previous_a11y_snapshot"] = previous_a11y_snapshot

        req = {
            "session_id": session_id or self.session_id,
            "intent_anchor": {"text": intent, "signer": "session-bound"},
            "tool": {"tool_id": tool_id, "capability_cert_id": cert_id},
            "action": {"type": action_type, "target": target, "payload": payload or {}},
            "visual_state": vs,
        }
        if intent_profile:
            req["intent_profile"] = intent_profile
        if approval_ticket:
            req["approval_ticket"] = approval_ticket
        r = requests.post(f"{self.gateway_url}/authorize", json=req, timeout=self.timeout,
                         headers=self._auth_headers())
        r.raise_for_status()
        d = r.json()
        return AuthorizeResult(
            verdict=d["verdict"],
            reason=d["reason"],
            certificates=d.get("certificates", []),
            decision_rule=d.get("decision_rule"),
            confirm_token=d.get("confirm_token"),
            policy_update=d.get("policy_update"),
            decision_id=d.get("decision_id"),
            execution_ticket=d.get("execution_ticket"),
            request=req,
        )

    # ---- confirmation ----
    def confirm(self, token: str, approve: bool = True) -> dict:
        r = requests.post(
            f"{self.gateway_url}/confirm",
            json={"token": token, "approve": approve},
            timeout=self.timeout,
            headers=self._auth_headers(),
        )
        r.raise_for_status()
        return r.json()

    # ---- intent anchoring (方案C) ----
    def anchor_intent(self, prompt: str, session_id: Optional[str] = None) -> dict:
        r = requests.post(
            f"{self.gateway_url}/anchor_intent",
            json={"session_id": session_id or self.session_id, "prompt": prompt},
            timeout=self.timeout,
            headers=self._auth_headers(),
        )
        r.raise_for_status()
        return r.json()["profile"]

    # ---- attached-mode authorization (gateway pulls a11y via CDP) ----
    def authorize_attached(
        self,
        tool_id: str,
        action_type: str,
        target: str,
        intent: str,
        cdp_endpoint: str = "http://localhost:9222",
        intent_profile: Optional[dict] = None,
        capability_cert_id: Optional[str] = None,
    ) -> AuthorizeResult:
        cert_id = capability_cert_id or self._cert_cache.get(tool_id)
        req = {
            "session_id": self.session_id,
            "intent_anchor": {"text": intent, "signer": "session-bound"},
            "tool": {"tool_id": tool_id, "capability_cert_id": cert_id},
            "action": {"type": action_type, "target": target, "payload": {}},
            "visual_state": {"mode": "attached", "cdp_endpoint": cdp_endpoint},
        }
        if intent_profile:
            req["intent_profile"] = intent_profile
        r = requests.post(f"{self.gateway_url}/authorize", json=req, timeout=self.timeout,
                         headers=self._auth_headers())
        r.raise_for_status()
        d = r.json()
        return AuthorizeResult(
            verdict=d["verdict"],
            reason=d["reason"],
            certificates=d.get("certificates", []),
            decision_rule=d.get("decision_rule"),
            confirm_token=d.get("confirm_token"),
            policy_update=d.get("policy_update"),
            decision_id=d.get("decision_id"),
            execution_ticket=d.get("execution_ticket"),
            request=req,
        )

    def consume(self, result: AuthorizeResult) -> dict:
        if not result.allowed or not result.execution_ticket or not result.request:
            raise AuthorizationBlocked("Missing execution authorization", result)
        req = result.request
        response = requests.post(f"{self.gateway_url}/consume", json={
            "ticket": result.execution_ticket, "session_id": req["session_id"],
            "tool": req["tool"], "action": req["action"],
        }, headers=self._auth_headers(), timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "consumed":
            raise AuthorizationBlocked("Execution ticket rejected", result)
        return data

    def health(self) -> dict:
        return requests.get(f"{self.gateway_url}/health", timeout=10).json()


def guard(
    client: ICBGuardClient,
    tool_id: str,
    action_type: str,
    capabilities: Optional[Dict[str, Any]] = None,
    intent: str = "",
    intent_provider=None,
    screenshot=None,
    screenshot_path=None,
    a11y_snapshot=None,
    target_from=None,
):
    """Wrap a callable: authorize at the tool-call boundary before executing.

    The action target is taken from the first positional arg unless
    ``target_from(args, kwargs)`` is provided.
    """
    cert_id = None

    def decorator(fn):
        def wrapper(*args, **kwargs):
            nonlocal cert_id
            if capabilities is not None and cert_id is None:
                cert_id = client.register_tool(tool_id, capabilities)
            # Freeze the values that will actually be executed. Non-JSON inputs
            # require a dedicated typed adapter; never hash their str()/repr().
            signature = inspect.signature(fn)
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            bound.arguments = copy.deepcopy(bound.arguments)
            frozen_args, frozen_kwargs = bound.args, bound.kwargs
            arguments = dict(bound.arguments)
            for name, parameter in signature.parameters.items():
                if parameter.kind == inspect.Parameter.VAR_KEYWORD:
                    extras = arguments.pop(name, {})
                    if set(extras) & set(arguments):
                        raise AuthorizationBlocked("Ambiguous tool argument names")
                    arguments.update(extras)
            json.dumps(arguments, allow_nan=False)
            target = target_from(frozen_args, frozen_kwargs) if target_from else (
                frozen_args[0] if frozen_args else frozen_kwargs.get("target", "")
            )
            it = intent_provider() if intent_provider else intent
            result = client.authorize(
                tool_id, action_type, str(target), it, payload=arguments,
                capability_cert_id=cert_id,
                screenshot=screenshot, screenshot_path=screenshot_path,
                a11y_snapshot=a11y_snapshot,
            )
            if result.needs_confirm:
                raise AuthorizationNeedsConfirm(result.confirm_token, result)
            if not result.allowed:
                raise AuthorizationBlocked(result.reason, result)
            client.consume(result)
            return fn(*frozen_args, **frozen_kwargs)

        return wrapper

    return decorator
