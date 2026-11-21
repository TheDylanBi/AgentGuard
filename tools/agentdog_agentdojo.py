"""Run the upstream AgentDoG PRE_REPLY guardrail inside AgentDojo's official CLI."""

import json
import os
from pathlib import Path
import re
import time

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.logging import Logger, TraceLogger
from agentdojo.types import text_content_block_from_string
from guardrail.trajectory import extract_tool_list, extract_trajectory_text
from openai import APIError, OpenAI


JUDGMENT = re.compile(r"\s*<Analysis>\s*.+?</Analysis>\s*<Judgment>\s*(safe|unsafe)\s*</Judgment>\s*", re.DOTALL)


def session_events(messages):
    """Convert native AgentDojo messages to the upstream evaluator's JSONL input."""
    events = []
    for message in messages:
        role = message["role"]
        if role == "system":
            continue
        content = []
        for block in message.get("content") or ():
            if block["type"] == "text":
                content.append({"type": "text", "text": block["content"]})
            elif block["type"] == "thinking":
                content.append({"type": "thinking", "thinking": block["content"]})
        record = {"role": role, "content": content}
        if role == "assistant":
            for call in message["tool_calls"] or ():
                content.append({"type": "toolCall", "name": call.function,
                                "arguments": call.model_dump(mode="json")["args"]})
        elif role == "tool":
            record.update(role="toolResult", toolName=message["tool_call"].function,
                          isError=bool(message["error"]))
        events.append(json.dumps({"type": "message", "timestamp": len(events) + 1, "message": record},
                                 ensure_ascii=False))
    return "\n".join(events)


class AgentDoGPreReply(BasePipelineElement):
    def __init__(self):
        self.model = os.environ["AGENTDOG_JUDGE_MODEL"]
        self.client = OpenAI(base_url=os.environ["AGENTDOG_JUDGE_BASE_URL"], api_key="local",
                             timeout=120, max_retries=0)
        self.template = Path(os.environ["AGENTDOG_PROMPT"]).read_text(encoding="utf-8")

    def review(self, messages):
        events = session_events(messages)
        prompt = self.template.format(formatted_trajectory=extract_trajectory_text(events),
                                      tool_list_text=", ".join(extract_tool_list(events)) or "(none)")
        try:
            response = self.client.chat.completions.create(
                model=self.model, messages=[{"role": "user", "content": prompt}],
                temperature=0, max_tokens=1024,
            )
        except APIError as error:
            return "judge_error", type(error).__name__
        if not response.choices:
            return "judge_error", "missing_choice"
        choice = response.choices[0]
        if choice.finish_reason != "stop":
            return "judge_error", f"finish_{choice.finish_reason}"
        judgment = JUDGMENT.fullmatch(choice.message.content or "")
        if not judgment:
            return "judge_error", "invalid_judgment"
        return ("blocked" if judgment[1] == "unsafe" else "allowed"), None

    def query(self, query, runtime, env, messages=(), extra_args=None):
        logger = Logger.get()
        if not isinstance(logger, TraceLogger):
            raise RuntimeError("AgentDoG requires AgentDojo's task trace")

        draft = messages[-1] if messages else None
        has_reply = (draft and draft["role"] == "assistant" and not draft["tool_calls"]
                     and any(block["type"] == "text" and block["content"].strip()
                             for block in draft["content"] or ()))
        if has_reply:
            started = time.monotonic()
            status, error = self.review(messages)
            elapsed = time.monotonic() - started
        else:
            status, error, elapsed = "no_final_reply", None, 0.0

        logger.set_contextarg("agentdog_guard", {"stage": "pre_reply", "decision": status,
                                                 "judge_model": self.model, "error": error,
                                                 "seconds": round(elapsed, 4)})
        if status == "blocked":
            # Match the upstream intervention boundary. Native tool effects remain in env.
            replacement = {**draft, "content": [text_content_block_from_string(
                "[AgentDoG] The safety guardrail blocked this reply.")]}
            messages = [*messages[:-1], replacement]
        return query, runtime, env, messages, extra_args or {}


_original_from_config = AgentPipeline.from_config.__func__


def _with_agentdog(cls, config):
    if config.llm != "openai-compatible" or not config.model_id or config.defense is not None:
        raise ValueError("Use --model OPENAI_COMPATIBLE --model-id MODEL and omit --defense")
    pipeline = _original_from_config(cls, config)
    elements = list(pipeline.elements)
    if not elements or not isinstance(elements[-1], ToolsExecutionLoop):
        raise RuntimeError("AgentDoG must follow AgentDojo's native tool execution loop")
    judge = AgentDoGPreReply()
    pipeline.elements = [*elements, judge]
    pipeline.name = f"openai-compatible-agentdog-prereply-{config.model_id}-{judge.model.rsplit('/', 1)[-1]}"
    return pipeline


AgentPipeline.from_config = classmethod(_with_agentdog)
