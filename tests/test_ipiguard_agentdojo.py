"""Exercise the AgentDojo entry point without a live model server."""

import importlib
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.scripts.benchmark import main
from click.testing import CliRunner
from openai import BadRequestError


class IPIGuardAgentDojoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Restore the extension hook after import for unrelated tests.
        with patch.object(AgentPipeline, "from_config", AgentPipeline.__dict__["from_config"]):
            cls.bridge = importlib.import_module("tools.ipiguard_agentdojo")

    def test_targeted_pair_count(self):
        self.assertEqual(sum(a * b for a, b in self.bridge.suite_counts().values()), 949)

    def test_empty_and_truncated_json_responses_fail_with_diagnostics(self):
        for content, finish_reason in ((None, "stop"), ('{"tool_calls":', "length")):
            with self.subTest(finish_reason=finish_reason):
                client = Mock()
                client.chat.completions.create.return_value = SimpleNamespace(
                    choices=[SimpleNamespace(
                        message=SimpleNamespace(content=content, reasoning_content="private text"),
                        finish_reason=finish_reason,
                    )],
                    usage=SimpleNamespace(completion_tokens=128),
                )
                bridge_client = self.bridge.IPIGuardChatClient(client, "inherit")
                with self.assertRaisesRegex(
                    RuntimeError, f"finish_reason={finish_reason}, completion_tokens=128, reasoning_present=True"
                ) as error:
                    bridge_client.chat.completions.create(response_format={"type": "json_object"})
                self.assertNotIn("private text", str(error.exception))
                client.chat.completions.create.assert_called_once_with(response_format={"type": "json_object"})

    def test_local_token_transport_exposes_structured_completion_as_final_content(self):
        client = Mock()
        client.base_url = "http://127.0.0.1:8000/v1/"
        client.post.return_value = {"tokens": [4, 8, 12], "max_model_len": 64}
        client.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(text='{"tool_calls":[]}', finish_reason="stop")],
            usage=SimpleNamespace(prompt_tokens=3, completion_tokens=4),
        )
        adapter = self.bridge.IPIGuardChatClient(client, "disabled", token_completions=True)
        response = adapter.chat.completions.create(
            model="qwen3-32b-awq", messages=[{"role": "user", "content": "Test"}],
            temperature=0, response_format={"type": "json_object"},
        )
        self.assertEqual(json.loads(response.choices[0].message.content), {"tool_calls": []})
        self.assertIsNone(response.choices[0].message.tool_calls)
        self.assertEqual(client.post.call_args.args[0], "http://127.0.0.1:8000/tokenize")
        self.assertEqual(client.completions.create.call_args.kwargs["max_tokens"], 61)
        self.assertEqual(client.completions.create.call_args.kwargs["extra_body"]["response_format"],
                         {"type": "json_object"})
        client.chat.completions.create.assert_not_called()

    def test_local_token_transport_classifies_only_confirmed_context_overflows(self):
        for token_count, expected in ((8, "context_length_exceeded"), (7, None)):
            with self.subTest(token_count=token_count):
                client = Mock()
                client.base_url = "http://127.0.0.1:8000/v1/"
                client.post.return_value = {"tokens": [1] * token_count, "max_model_len": 8}
                client.completions.create.side_effect = BadRequestError("vLLM rejected the request",
                    response=Mock(), body={})
                transport = self.bridge.VLLMTokenCompletions(client)
                with self.assertRaises(BadRequestError) as error:
                    transport(model="qwen3-32b-awq", messages=[], temperature=0,
                              extra_body={"chat_template_kwargs": {"enable_thinking": False}})
                self.assertEqual(error.exception.code, expected)

    @unittest.skipUnless(os.getenv("IPIGUARD_ROOT"), "requires the pinned IPIGuard source")
    def test_native_cli_runs_author_pipeline_and_scores_its_tool_trace(self):
        def complete(**request):
            self.assertEqual(request["model"], "Qwen/Qwen3-32B")
            self.assertEqual(request["extra_body"], {"chat_template_kwargs": {"enable_thinking": False}})
            messages = request["messages"]
            if "response_format" not in request:
                observation = next(row["content"] for row in messages if row["role"] == "tool")
                answer = " ".join(re.findall(r"[\w.+-]+@[\w.-]+", observation))
                self.assertTrue(answer)
            elif len(client.chat.completions.create.call_args_list) == 2:
                answer = json.dumps({"tool_calls": [{
                    "id": "1",
                    "function_name": "search_calendar_events",
                    "args": {"query": "Networking event", "date": "2024-05-26"},
                    "depends_on": [],
                }]})
            else:
                answer = "{}"
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=answer))],
                usage=SimpleNamespace(prompt_tokens=20, completion_tokens=10),
            )

        client = Mock()
        client.chat.completions.create.side_effect = complete
        with tempfile.TemporaryDirectory(dir=os.getenv("IPIGUARD_TEST_TMPDIR")) as logs, patch.object(
            AgentPipeline, "from_config", classmethod(self.bridge.with_ipiguard)
        ), patch.object(self.bridge, "OpenAI", return_value=client) as make_client, patch.dict(
            os.environ, {
                "OPENAI_COMPATIBLE_API_KEY": "test",
                "OPENAI_COMPATIBLE_BASE_URL": "http://127.0.0.1:8000/v1",
                "IPIGUARD_QWEN3_THINKING": "disabled",
            }
        ):
            result = CliRunner().invoke(main, [
                "--benchmark-version", "v1.2.2", "--model", "LOCAL", "--model-id", "Qwen/Qwen3-32B",
                "--module-to-load", self.bridge.__name__, "--suite", "workspace", "--user-task", "user_task_0",
                "--max-workers", "1", "--logdir", logs,
            ], catch_exceptions=False)
            self.assertEqual(result.exit_code, 0, result.output)
            paths = list(Path(logs).glob("*/workspace/user_task_0/none/none.json"))
            self.assertEqual(len(paths), 1, result.output)
            self.assertTrue(paths[0].relative_to(logs).parts[0].endswith("-thinking-off"))
            trace = json.loads(paths[0].read_text(encoding="utf-8"))
            self.assertIs(trace["utility"], True)

        make_client.assert_called_once_with(base_url="http://127.0.0.1:8000/v1", api_key="test")
        self.assertGreaterEqual(client.chat.completions.create.call_count, 4)
