"""Load the author's IPIGuard pipeline into AgentDojo's benchmark CLI."""

import builtins
import hashlib
import json
import os
import re
from functools import lru_cache
from pathlib import Path
from types import ModuleType, SimpleNamespace
from urllib.parse import urlsplit

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import text_content_block_from_string
from google.genai.errors import ServerError
from openai import BadRequestError, OpenAI


AUTHOR_REVISION = "4e686ed2f62c135cb12564a4466daa95f3ace878"
# Load these exact upstream modules, accepting either LF or CRLF checkouts.
AUTHOR_FILES = {
    "default_suites.v1.tools.tool_white_list": "3d7a5005870db5aff2b081f3b6f678d7ee737a881a8c5aec59d18266f8d87af6",
    "agent_pipeline.llms.openai_llm": "bd0f58f4270e217b3630de968a79d9b6e9fada619775e706aa8e11425990eccb",
    "agent_pipeline.llms.ipiguard_llm": "6746200c74454aaeae52378068bbd6d74bfde1b1d2faa2a3e7860eba49673ea0",
    "agent_pipeline.tool_execution": "329eecab4252e733b4ad42aa0f6205ad95c30ee2a16a2ef2d557689debc6c83d",
}
BENCHMARK_VERSION = "v1.2.2"
EXPECTED_COUNTS = {
    "workspace": (40, 14),
    "travel": (20, 7),
    "banking": (16, 9),
    "slack": (21, 5),
}


@lru_cache(maxsize=1)
def load_author_pipeline(checkout: Path):
    source_root = checkout / "agentdojo" / "src" / "agentdojo"
    sources = {}
    for name, expected in AUTHOR_FILES.items():
        path = source_root.joinpath(*name.split(".")).with_suffix(".py")
        source = path.read_text(encoding="utf-8")
        if hashlib.sha256(source.encode("utf-8")).hexdigest() != expected:
            raise ValueError(f"Unexpected IPIGuard source at {path}. Use commit {AUTHOR_REVISION}.")
        sources[name] = (path, source)

    author_modules = {}

    def author_import(name, globals=None, locals=None, fromlist=(), level=0):
        # Only cross-references between the pinned files use legacy modules.
        # AgentDojo's installed runtime, logging and suites stay in use.
        if level == 0 and fromlist and name in author_modules:
            return author_modules[name]
        return builtins.__import__(name, globals, locals, fromlist, level)

    for name, (path, source) in sources.items():
        module = ModuleType(f"_ipiguard_author_{path.stem}")
        module.__file__ = str(path)
        module.__dict__["__builtins__"] = {**vars(builtins), "__import__": author_import}
        exec(compile(source, str(path), "exec"), module.__dict__)
        author_modules[f"agentdojo.{name}"] = module

    llms = author_modules["agentdojo.agent_pipeline.llms.ipiguard_llm"]
    tools = author_modules["agentdojo.agent_pipeline.tool_execution"]
    return llms.OpenAIConstructLLM, llms.OpenAITraverseLLM, tools.DagToolsExecutor, tools.DagToolsExecutionLoop


def author_checkout() -> Path:
    root = os.getenv("IPIGUARD_ROOT")
    if not root:
        raise ValueError("Set IPIGUARD_ROOT to the author's ipiguard checkout.")
    return Path(root).expanduser().resolve()


def suite_counts():
    suites = get_suites(BENCHMARK_VERSION)
    counts = {
        name: (len(suite.user_tasks), len(suite.injection_tasks))
        for name, suite in suites.items()
    }
    if counts != EXPECTED_COUNTS:
        raise ValueError(f"Expected AgentDojo {BENCHMARK_VERSION} with {EXPECTED_COUNTS}, got {counts}.")
    return counts


def thinking_mode(model_id):
    default = "disabled" if "qwen3" in model_id.lower() else "inherit"
    mode = os.getenv("IPIGUARD_QWEN3_THINKING", default)
    if mode not in ("disabled", "inherit"):
        raise ValueError("IPIGUARD_QWEN3_THINKING must be disabled or inherit.")
    return mode


class IPIGuardOutputError(RuntimeError):
    """The model response cannot be used by the author's pipeline."""


class IPIGuardChatClient:
    """Apply endpoint settings and check the final content before the author code reads it."""

    def __init__(self, client, thinking, *, token_completions=False):
        self.create_completion = (
            VLLMTokenCompletions(client) if token_completions else client.chat.completions.create
        )
        self.thinking = thinking
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **request):
        if self.thinking == "disabled":
            extra_body = dict(request.get("extra_body") or {})
            template_kwargs = dict(extra_body.get("chat_template_kwargs") or {})
            template_kwargs["enable_thinking"] = False
            extra_body["chat_template_kwargs"] = template_kwargs
            request["extra_body"] = extra_body

        response = self.create_completion(**request)
        choice = response.choices[0] if response.choices else None
        message = getattr(choice, "message", None)
        content = getattr(message, "content", None)
        finish_reason = getattr(choice, "finish_reason", None)
        structured = request.get("response_format") is not None
        if (isinstance(content, str) and content.strip()
                and not (structured and finish_reason == "length")):
            if not structured:
                return response
            try:
                if isinstance(json.loads(content), dict):
                    return response
            except json.JSONDecodeError:
                pass

        reasoning_present = bool(
            getattr(message, "reasoning_content", None) or getattr(message, "reasoning", None)
        )
        completion_tokens = getattr(getattr(response, "usage", None), "completion_tokens", None)
        expected = "complete JSON" if structured else "final answer text"
        raise IPIGuardOutputError(
            f"IPIGuard model response is missing {expected} in message.content "
            f"(finish_reason={finish_reason}, completion_tokens={completion_tokens}, "
            f"reasoning_present={reasoning_present}, thinking={self.thinking})."
        )


class VLLMTokenCompletions:
    """Keep vLLM's chat template while reading the raw completion text.

    The local chat endpoint can place the whole non-thinking answer in
    reasoning_content. The completions endpoint returns it directly as text.
    """

    def __init__(self, client):
        base = urlsplit(str(client.base_url))
        if (base.scheme != "http" or base.hostname not in {"127.0.0.1", "localhost", "::1"}
                or base.path.rstrip("/") != "/v1" or base.username or base.query or base.fragment):
            raise ValueError("Token completions require a loopback vLLM /v1 endpoint.")
        self.client = client
        self.tokenize_url = f"{base.scheme}://{base.netloc}/tokenize"

    def __call__(self, *, model, messages, temperature, response_format=None, extra_body=None):
        template = (extra_body or {}).get("chat_template_kwargs")
        if template != {"enable_thinking": False}:
            raise ValueError("Token completions require disabled Qwen3 thinking.")
        encoded = self.client.post(
            self.tokenize_url, cast_to=object, body={
                "model": model, "messages": messages, "add_generation_prompt": True,
                "chat_template_kwargs": template,
            },
        )
        tokens, context = encoded["tokens"], encoded["max_model_len"]
        if not isinstance(tokens, list) or not tokens or not isinstance(context, int) or context <= 0:
            raise RuntimeError("Unexpected vLLM tokenization response.")
        body = {"add_special_tokens": False}
        if response_format is not None:
            body["response_format"] = response_format
        try:
            completion = self.client.completions.create(
                model=model, prompt=tokens, temperature=temperature,
                max_tokens=max(1, context - len(tokens)), extra_body=body,
            )
        except BadRequestError as error:
            if len(tokens) >= context:
                # vLLM's text error has no code. The tokenizer has confirmed
                # this exact request cannot fit, so AgentDojo can record it.
                error.code = "context_length_exceeded"
            raise
        return SimpleNamespace(
            usage=completion.usage,
            choices=[SimpleNamespace(
                message=SimpleNamespace(content=choice.text, tool_calls=None),
                finish_reason=choice.finish_reason,
            ) for choice in completion.choices],
        )


class IPIGuardElement(BasePipelineElement):
    def __init__(self, client, model_id, system_message, author):
        construct, traverse, executor, loop = author
        self.construct = construct(client, model_id)
        self.loop = loop(executor(traverse(client, model_id)))
        self.system_message = system_message

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
        if messages:
            raise ValueError("IPIGuard starts from a fresh AgentDojo task.")
        # The author pipeline mutates the user message and expects string content.
        history = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": query},
        ]
        try:
            state = self.construct.query(query, runtime, env, history, dict(extra_args or {}))
            query, runtime, env, history, extra_args = self.loop.query(*state)
        except IPIGuardOutputError as error:
            # Let AgentDojo record this model-stage failure in the task trace.
            raise ServerError(500, {"error": {"code": 500, "message": str(error)}}) from error
        # Retain the author's tool calls and results for AgentDojo's scorers.
        native_messages = [
            {**message, "content": [text_content_block_from_string(message["content"])]}
            if isinstance(message["content"], str) else message
            for message in history
        ]
        return query, runtime, env, native_messages, extra_args


def with_ipiguard(cls, config):
    if config.llm not in ("local", "openai-compatible") or not config.model_id or config.defense is not None:
        raise ValueError("Use AgentDojo's local model option with --model-id MODEL and omit --defense.")
    suite_counts()
    author = load_author_pipeline(author_checkout())
    api_key = os.getenv("OPENAI_COMPATIBLE_API_KEY")
    if not api_key:
        raise ValueError("Set OPENAI_COMPATIBLE_API_KEY (use a placeholder for an unauthenticated server).")
    thinking = thinking_mode(config.model_id)
    transport = os.getenv("IPIGUARD_VLLM_TOKEN_COMPLETIONS", "0")
    if transport not in {"0", "1"}:
        raise ValueError("IPIGUARD_VLLM_TOKEN_COMPLETIONS must be 0 or 1.")
    if transport == "1" and thinking != "disabled":
        raise ValueError("The token completions transport requires IPIGUARD_QWEN3_THINKING=disabled.")
    client = OpenAI(
        base_url=os.getenv("OPENAI_COMPATIBLE_BASE_URL", "http://127.0.0.1:8000/v1"),
        api_key=api_key,
    )
    chat_client = IPIGuardChatClient(client, thinking, token_completions=transport == "1")
    element = IPIGuardElement(chat_client, config.model_id, config.system_message, author)
    pipeline = cls([element])
    model_slug = re.sub(r"[^A-Za-z0-9_.-]", "_", config.model_id)
    pipeline.name = f"openai-compatible-ipiguard-{AUTHOR_REVISION[:7]}-{model_slug}"
    if thinking == "disabled":
        pipeline.name += "-thinking-off"
    if transport == "1":
        pipeline.name += "-token-completions"
    # Stock 0.1.35 needs the same generic model name as our compatible checkout.
    MODEL_NAMES.setdefault("openai-compatible", "AI assistant")
    return pipeline


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True, help="Validate locally without model requests")
    parser.parse_args()
    counts = suite_counts()
    load_author_pipeline(author_checkout())
    print(json.dumps({
        "benchmark_version": BENCHMARK_VERSION,
        "ipiguard_revision": AUTHOR_REVISION,
        "suites": {name: {"clean_tasks": users, "injection_goals": goals, "pairs": users * goals}
                   for name, (users, goals) in counts.items()},
        "clean_tasks": sum(users for users, _ in counts.values()),
        "targeted_pairs_per_attack": sum(users * goals for users, goals in counts.values()),
    }, indent=2))
else:
    # AgentDojo's --module-to-load imports custom pipeline modules before evaluation.
    AgentPipeline.from_config = classmethod(with_ipiguard)
