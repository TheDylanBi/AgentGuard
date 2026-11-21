"""Connect the existing ICB-Guard review pipeline to Inspect tool approval.

This module does not implement or wrap AgentHarm. The official Inspect task,
agent, tools, scorers, sample scheduling, and logs remain in control. Inspect
calls this approver immediately before executing each official tool call.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import sys
import threading
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable

from inspect_ai.approval import Approval, Approver, approver
from inspect_ai.model import ChatMessage, ChatMessageTool
from inspect_ai.solver._task_state import sample_state
from inspect_ai.tool import ToolCall, ToolCallView

# This is a project-local editable extension. Make the existing ICB-Guard
# packages importable even when Inspect is launched outside the repository.
PROJECT = Path(__file__).resolve().parents[3]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from attestation.hashing import object_hash
from gateway.api_schema import Action
from policy.authorize import check_hard_boundaries
from policy.call_review import CallReviewer, SYSTEM, review_call
from policy.engine import PolicyEngine
from policy.intent_anchor import intent_llm_configured

from .operator_policy import AGENTHARM_OPERATOR_POLICY


def _agentharm_review_call(packet: Any, **kwargs: Any) -> dict[str, Any]:
    """Use the existing review transport/schema with an operator harm boundary."""
    return review_call(
        packet,
        system_policy=SYSTEM + AGENTHARM_OPERATOR_POLICY,
        **kwargs,
    )


# CallReviewer uses these markers for safe diagnostics and short evidence handles.
_agentharm_review_call.uses_packet_short_handles = True
_agentharm_review_call.provides_intent_diagnostic = True


def _message_text(message: ChatMessage) -> str:
    content = message.content
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for item in content:
        text = getattr(item, "text", None)
        if isinstance(text, str):
            parts.append(text)
        elif getattr(item, "type", None) == "text":
            value = getattr(item, "content", None)
            if isinstance(value, str):
                parts.append(value)
    return "\n".join(parts)


def _error_value(error: Any) -> Any:
    if error is None:
        return None
    if is_dataclass(error):
        return asdict(error)
    if hasattr(error, "model_dump"):
        return error.model_dump(mode="json")
    return {"type": type(error).__name__}


def _tool_name(tool: Any) -> str | None:
    info = getattr(tool, "__registry_info__", None)
    name = getattr(info, "name", None)
    if isinstance(name, str):
        return name.rsplit("/", 1)[-1]
    return None


def _tool_declaration(state: Any, function: str) -> dict[str, Any]:
    """Read only the live official tool definition, never task/grader labels."""
    for tool in state.tools:
        if _tool_name(tool) != function:
            continue
        signature = inspect.signature(tool)
        return {
            "description": inspect.cleandoc(tool.__doc__ or ""),
            "signature": str(signature),
            "parameters": [
                {
                    "name": name,
                    "required": parameter.default is inspect.Parameter.empty,
                    "annotation": str(parameter.annotation),
                }
                for name, parameter in signature.parameters.items()
            ],
        }
    raise RuntimeError("proposed AgentHarm tool is not in the live official tool set")


def _capability(function: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Minimal honest envelope; semantic effects remain explicit and unknown."""
    return {
        "actions": [function],
        "network_egress": "denied",
        "external_share": "denied",
        "credential_access": "denied",
        "process": "denied",
        "persistence": "denied",
        "network": "denied",
        "credential": "denied",
        "filesystem_read": [],
        "filesystem_write": [],
        "sources": [],
        "sensitive_params": sorted(arguments),
        "effect_type": None,
        "target_type": None,
        "parameter_constraints": {},
    }


class ReviewSession:
    """One independent reviewer and observation ledger per official sample."""

    def __init__(
        self,
        user_request: str,
        *,
        business_policy: Path | None = None,
        reviewer_factory: Callable[[str], CallReviewer] | None = None,
    ) -> None:
        self.user_request = str(user_request)
        self.reviewer = (
            reviewer_factory(self.user_request)
            if reviewer_factory is not None
            else CallReviewer(self.user_request, caller=_agentharm_review_call)
        )
        self.engine = PolicyEngine(PROJECT / "policy" / "policies", business_policy)
        self.pending: dict[str, dict[str, Any]] = {}
        self.observed_tool_messages: set[str] = set()
        self.call_index = 0
        self.lock = asyncio.Lock()

    def _sync_observations(self, history: list[ChatMessage]) -> None:
        for message in history:
            if not isinstance(message, ChatMessageTool) or not message.tool_call_id:
                continue
            if message.tool_call_id in self.observed_tool_messages:
                continue
            self.observed_tool_messages.add(message.tool_call_id)
            pending = self.pending.pop(message.tool_call_id, None)
            if pending is None:
                # Rejected or non-ICB calls are not executed evidence.
                continue
            self.reviewer.observe(
                pending["call_id"],
                pending["tool"],
                pending["arguments"],
                _message_text(message),
                _error_value(message.error),
                semantic_action=pending["semantic"],
            )

    def _hard_check(self, function: str, arguments: dict[str, Any]) -> dict[str, Any]:
        action = Action(type=function, target=function, payload=copy.deepcopy(arguments))
        return check_hard_boundaries(
            action,
            capability=_capability(function, arguments),
            engine=self.engine,
            taint_state={"dirty": False, "objects": []},
        )

    async def decide(
        self,
        call: ToolCall,
        history: list[ChatMessage],
        declaration: dict[str, Any],
    ) -> Approval:
        async with self.lock:
            self._sync_observations(history)
            self.call_index += 1
            call_id = f"call-{self.call_index}"
            arguments = copy.deepcopy(call.arguments)
            hard = self._hard_check(call.function, arguments)
            if hard["verdict"] != "PASS":
                verdict = hard["verdict"]
                return Approval(
                    decision="reject",
                    explanation=f"ICB-{verdict}: {hard['rule']}",
                    metadata={
                        "icb_verdict": verdict,
                        "icb_rule": hard["rule"],
                        "icb_stage": "hard_boundary",
                        "icb_call_id": call_id,
                    },
                )

            semantic = {
                "version": 1,
                "operation": "invoke_agentharm_simulated_tool",
                "resource_type": "agentharm_official_simulation",
                "tool_name": call.function,
                "tool_description": declaration["description"],
                "tool_signature": declaration["signature"],
                "parameters": arguments,
                "parameter_roles": {name: "candidate" for name in arguments},
                "effect_upper_bound": ["simulated_effect_not_narrowed_by_bridge"],
                "execution_model": (
                    "Official AgentHarm synthetic tool. The description and exact arguments "
                    "are operator-provided call semantics, not task permission."
                ),
                "tool_assurance": {
                    "source": "live_official_inspect_tool",
                    "task_authorized": False,
                    "description_hash": object_hash(declaration),
                },
            }
            state_hash = object_hash(
                {
                    "user_request": self.user_request,
                    "observations": self.reviewer.observations,
                    "business_policy": self.engine.business_policy.fingerprint,
                    "call_index": self.call_index,
                }
            )
            reviewed = await asyncio.to_thread(
                self.reviewer.check,
                call_id,
                call.function,
                arguments,
                semantic,
                state_hash,
            )
            verdict = {
                "allow": "ALLOW",
                "deny": "BLOCK",
                "needs_evidence": "CONFIRM",
            }[reviewed["decision"]]

            # Bind approval to the exact reviewed call, then re-run mandatory
            # boundaries immediately before execution, as in AgentDojo review.
            if verdict == "ALLOW":
                final_hard = self._hard_check(call.function, arguments)
                if final_hard["verdict"] != "PASS":
                    verdict = final_hard["verdict"]
                    reviewed = {
                        **reviewed,
                        "decision": "deny" if verdict == "BLOCK" else "needs_evidence",
                        "code": (
                            "forbidden_effect"
                            if verdict == "BLOCK"
                            else "insufficient_evidence"
                        ),
                    }

            record = copy.deepcopy(self.reviewer.records[-1])
            record.pop("decision_payload", None)
            metadata = {
                "icb_verdict": verdict,
                "icb_rule": "review." + reviewed["code"],
                "icb_stage": "review",
                "icb_call_id": call_id,
                "icb_review": record,
            }
            if verdict == "ALLOW":
                self.pending[call.id] = {
                    "call_id": call_id,
                    "tool": call.function,
                    "arguments": arguments,
                    "semantic": semantic,
                }
                return Approval(
                    decision="approve",
                    explanation="ICB-ALLOW: review.authorized",
                    metadata=metadata,
                )
            return Approval(
                decision="reject",
                explanation=f"ICB-{verdict}: review.{reviewed['code']}",
                metadata=metadata,
            )


class AgentHarmReviewApprover:
    """Concurrency-safe sample registry for the official Inspect boundary."""

    def __init__(
        self,
        *,
        business_policy: Path | None = None,
        reviewer_factory: Callable[[str], CallReviewer] | None = None,
    ) -> None:
        self.business_policy = business_policy
        self.reviewer_factory = reviewer_factory
        self._sessions: dict[str, ReviewSession] = {}
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._sessions.clear()

    def _session(self, state: Any, history: list[ChatMessage]) -> ReviewSession:
        key = state.uuid
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                user_request = next(
                    (
                        _message_text(message)
                        for message in history
                        if message.role == "user"
                    ),
                    state.input_text,
                )
                session = ReviewSession(
                    user_request,
                    business_policy=self.business_policy,
                    reviewer_factory=self.reviewer_factory,
                )
                self._sessions[key] = session
            return session

    async def __call__(
        self,
        message: str,
        call: ToolCall,
        view: ToolCallView,
        history: list[ChatMessage],
    ) -> Approval:
        del message, view
        state = sample_state()
        if state is None:
            raise RuntimeError("ICB AgentHarm approval requires an active Inspect sample")
        session = self._session(state, history)
        declaration = _tool_declaration(state, call.function)
        return await session.decide(call, history, declaration)


@approver(name="agentharm_review")
def agentharm_review_approver(
    business_policy: str | Path | None = None,
) -> Approver:
    """Create the review approver used by official AgentHarm eval commands."""
    if not intent_llm_configured():
        raise RuntimeError(
            "Configure independent ICB_INTENT_LLM_BASE_URL/API_KEY/MODEL "
            "before guarded AgentHarm evaluation"
        )
    path = Path(business_policy).resolve() if business_policy else None
    if path is not None and not path.is_file():
        raise FileNotFoundError(f"ICB business policy not found: {path}")
    return AgentHarmReviewApprover(business_policy=path)
