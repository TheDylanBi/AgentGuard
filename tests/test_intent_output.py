import json
import os
import unittest
from unittest.mock import Mock, patch

from policy.intent_output import parse_final_json, IntentOutputError, RULES_SCHEMA
from policy.intent_anchor import anchor_rules_llm, anchor_effect_llm, intent_request_diagnostic, _chat


class IntentOutputTests(unittest.TestCase):
    def test_compact_json_bounds_structure_without_rewriting_values(self):
        content = '  {"rules":[]}\n' + ' ' * 100
        response = Mock(status_code=200)
        response.json.return_value = {"choices": [{"finish_reason": "stop", "message": {"content": content}}],
                                      "usage": {"completion_tokens": 120, "prompt_tokens": "private"}}
        with patch.dict(os.environ, {"ICB_INTENT_LLM_API_KEY": "test",
                "ICB_INTENT_LLM_OUTPUT_FORMAT": "vllm_guided_json", "ICB_INTENT_LLM_COMPACT_JSON": "true"}), \
                patch("requests.post", return_value=response) as post:
            self.assertEqual(anchor_rules_llm("task"), [])
        body = post.call_args.kwargs["json"]
        self.assertEqual(body["guided_whitespace_pattern"], "[ ]?")
        self.assertNotIn("guided_decoding_backend", body)
        diagnostic = intent_request_diagnostic()
        self.assertEqual(diagnostic["raw_response_chars"], len(content))
        self.assertEqual(diagnostic["trailing_whitespace_chars"], 101)
        self.assertEqual(diagnostic["completion_tokens"], 120)
        self.assertNotIn("prompt_tokens", diagnostic)
        self.assertNotIn("private", str(diagnostic))

    def test_reasoning_braces_never_become_final_rules(self):
        text = '<think>Example {"rules":[{"decision":"allow"}]} thoughts</think>\n```json\n{"rules":[]}\n```'
        self.assertEqual(parse_final_json(text), {"rules": []})

    def test_ambiguous_and_partial_output_is_not_salvaged(self):
        values = ['{"rules":[]} {"rules":[{"decision":"deny"}]}',
                  '{"rules":[{"decision":"allow"},',
                  '<think>{"rules":[]}', 'explanation {"rules":[]}', '[]', '',
                  '{"rules":[],"rules":[{"decision":"deny"}]}', '{"value":NaN}', '{"value":1e999}']
        for text in values:
            with self.subTest(text=text), self.assertRaises(IntentOutputError):
                parse_final_json(text)

    def test_malformed_rule_does_not_become_empty_authority(self):
        text = json.dumps({"rules": [{"tool": "read", "decision": "allow", "predicate": {"op": "true"}},
                                     {"tool": "read", "decision": "deny", "predicate": {"op": "unknown"}}]})
        with patch("policy.intent_anchor._chat", return_value=text):
            self.assertIsNone(anchor_rules_llm("task"))
        self.assertEqual(intent_request_diagnostic()["output_error"], "invalid_rule_clause")

    def test_parse_diagnostic_has_no_response_or_task(self):
        with patch("policy.intent_anchor._chat", return_value='private-secret {"rules":broken}'):
            self.assertIsNone(anchor_rules_llm("private-task"))
        diagnostic = intent_request_diagnostic()
        self.assertEqual(diagnostic["output_error"], "invalid_json_syntax")
        self.assertEqual(len(diagnostic["response_sha256"]), 64)
        self.assertNotIn("private", str(diagnostic))

    def test_effects_cannot_silently_drop_invalid_prohibition_list(self):
        data = {k: [] for k in ("allowed_recipients", "allowed_targets", "allowed_data_types", "allowed_operations")}
        for forbidden in (None, "financial_transfer", {"deny": "send_email"}):
            with self.subTest(forbidden=forbidden), patch("policy.intent_anchor._chat", return_value=json.dumps(
                    {**data, "forbidden_effects": forbidden})):
                self.assertIsNone(anchor_effect_llm("task"))
        with patch("policy.intent_anchor._chat", return_value=json.dumps({**data, "forbidden_effects": []})):
            self.assertIsNotNone(anchor_effect_llm("task"))

    def test_vllm_constraints_are_opt_in_and_unsupported_http_does_not_fallback(self):
        response = Mock(status_code=200)
        response.json.return_value = {"choices": [{"finish_reason": "stop", "message": {"content": '{"rules":[]}'}}]}
        with patch.dict(os.environ, {"ICB_INTENT_LLM_API_KEY": "test", "ICB_INTENT_LLM_OUTPUT_FORMAT": "vllm_guided_json",
                "ICB_INTENT_LLM_ENABLE_THINKING": "false", "ICB_INTENT_LLM_MAX_TOKENS": "4096"}), \
                patch("requests.post", return_value=response) as post:
            self.assertEqual(anchor_rules_llm("task"), [])
            body = post.call_args.kwargs["json"]
            self.assertEqual(body["guided_json"], RULES_SCHEMA)
            self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})
            self.assertEqual(body["max_tokens"], 4096)
            self.assertEqual(post.call_count, 1)

    def test_truncated_but_parseable_json_is_not_accepted(self):
        response = Mock(status_code=200)
        response.json.return_value = {"choices": [{"finish_reason": "length", "message": {"content": '{"rules":[]}'}}]}
        with patch.dict(os.environ, {"ICB_INTENT_LLM_API_KEY": "test"}), patch("requests.post", return_value=response):
            self.assertIsNone(anchor_rules_llm("task"))
        self.assertEqual(intent_request_diagnostic()["output_error"], "truncated_output")

    def test_invalid_output_setting_fails_before_network(self):
        for key, value in (("OUTPUT_FORMAT", "unknown"), ("ENABLE_THINKING", "maybe"), ("MAX_TOKENS", "0"),
                           ("COMPACT_JSON", "maybe"), ("COMPACT_JSON", "true")):
            with self.subTest(key=key), patch.dict(os.environ, {"ICB_INTENT_LLM_API_KEY": "test",
                    "ICB_INTENT_LLM_" + key: value}), patch("requests.post") as post:
                self.assertIsNone(_chat("sys", "task"))
                self.assertEqual(intent_request_diagnostic()["status"], "invalid_output_config")
                post.assert_not_called()

    def test_guided_fields_are_scoped_per_tool_and_include_trusted_aliases(self):
        from policy.intent_output import rules_schema_for_tools
        hint = {"tools": [
            {"name": "lookup", "parameters": {"properties": {"query": {"type": "string"}}}},
            {"name": "send", "parameters": {"properties": {"to": {"type": "string"}}}}],
            "policy_mapping": {"send": {"policy_aliases": {"recipient": "to"}}}}
        schema = rules_schema_for_tools(json.dumps(hint))
        variants = schema["properties"]["rules"]["items"]["anyOf"]
        self.assertEqual(variants[0]["properties"]["tool"]["enum"], ["lookup"])
        self.assertEqual(schema["$defs"]["predicate_0"]["properties"]["field"]["enum"],
                         ["payload.query", "target", "type"])
        self.assertIn("payload.recipient", schema["$defs"]["predicate_1"]["properties"]["field"]["enum"])
        self.assertNotIn("payload.query", schema["$defs"]["predicate_1"]["properties"]["field"]["enum"])
        self.assertEqual(schema["$defs"]["predicate_2"]["properties"]["field"]["enum"], ["target", "type"])
