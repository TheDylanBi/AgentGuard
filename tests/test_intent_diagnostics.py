import unittest
import os
from unittest.mock import Mock, patch
import requests
from policy.intent_anchor import _chat, intent_request_diagnostic


class IntentDiagnosticsTests(unittest.TestCase):
    def call(self, response=None, error=None):
        with patch("policy.intent_anchor._llm_config", return_value={
                "base_url": "https://fixture.invalid/v1", "api_key": "secret-value", "model": "fixture"}), \
                patch("requests.post", return_value=response, side_effect=error):
            return _chat("private prompt", "private task")

    def test_timeout_is_distinct_and_does_not_leak_exception(self):
        self.assertIsNone(self.call(error=requests.exceptions.Timeout("secret-value")))
        info = intent_request_diagnostic()
        self.assertEqual(info["status"], "timeout")
        self.assertNotIn("secret-value", str(info))

    def test_http_error_records_only_status(self):
        response = Mock(status_code=401)
        response.raise_for_status.side_effect = requests.exceptions.HTTPError("secret-value")
        self.assertIsNone(self.call(response))
        self.assertEqual(intent_request_diagnostic()["http_status"], 401)
        self.assertEqual(intent_request_diagnostic()["status"], "http_error")

    def test_success_retains_original_output_and_records_truncation(self):
        response = Mock(status_code=200)
        response.json.return_value = {"choices": [{"finish_reason": "length", "message": {"content": " private response "}}]}
        self.assertEqual(self.call(response), "private response")
        info = intent_request_diagnostic()
        self.assertEqual(info["finish_reason"], "length")
        self.assertNotIn("private response", str(info))

    def test_invalid_response_structure(self):
        response = Mock(status_code=200)
        response.json.return_value = {"choices": []}
        self.assertIsNone(self.call(response))
        self.assertEqual(intent_request_diagnostic()["status"], "invalid_response_structure")

    def test_wrapped_read_timeout_is_not_generic_network_error(self):
        from urllib3.exceptions import ReadTimeoutError
        error = requests.exceptions.ConnectionError(ReadTimeoutError(None, "/private-url", "secret-value"))
        self.assertIsNone(self.call(error=error))
        info = intent_request_diagnostic()
        self.assertEqual(info["status"], "timeout")
        self.assertEqual(info["network_error_type"], "ConnectionError")
        self.assertNotIn("private-url", str(info))
        self.assertNotIn("secret-value", str(info))

    def test_connection_failure_is_not_assumed_to_be_timeout(self):
        self.assertIsNone(self.call(error=requests.exceptions.ConnectionError("secret-value")))
        self.assertEqual(intent_request_diagnostic()["status"], "network_error")

    def test_configured_timeout_is_passed_without_changing_request_body(self):
        with patch.dict(os.environ, {"ICB_INTENT_LLM_API_KEY": "fixture", "ICB_INTENT_LLM_TIMEOUT_SECONDS": "120"}), \
                patch("requests.post", side_effect=requests.exceptions.Timeout()) as post:
            self.assertIsNone(_chat("system", "task"))
            self.assertEqual(post.call_args.kwargs["timeout"], (30, 120))
            self.assertEqual(post.call_args.kwargs["json"]["messages"][1]["content"], "task")
            self.assertEqual(intent_request_diagnostic()["timeout_seconds"], 120)

    def test_invalid_timeout_fails_before_network_request(self):
        for value in ("bad", "nan", "inf", "0", "-1", "601"):
            with self.subTest(value=value), patch.dict(os.environ, {
                    "ICB_INTENT_LLM_API_KEY": "fixture", "ICB_INTENT_LLM_TIMEOUT_SECONDS": value}), \
                    patch("requests.post") as post:
                self.assertIsNone(_chat("system", "task"))
                self.assertEqual(intent_request_diagnostic()["status"], "invalid_timeout_config")
                post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
