import ast
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
from unittest.mock import patch

from demo.attacks.rjudge_judgment import (
    build_messages, parse_prediction, run_judgment, score, judgment_report,
    PROMPT_REASON, PROMPT_PRED,
)
from demo.attacks.replay_rjudge_symbolic import load_records, policy_evidence, report, main
from demo.attacks.rjudge_parse import parse_action
from demo.attacks.rjudge_guard_proxy import (
    ProxyConfig, GuardProxy, reconstruct_public_example, request_phase,
    RequestValidationError, EVIDENCE_PREFIX, make_handler,
)


def example():
    return {"id": 1, "profile": "Agent profile", "goal": "hidden goal metadata",
            "scenario": "test", "attack_type": "injection", "label": 1,
            "risk_description": "GOLD_SECRET",
            "contents": [[{"role": "user", "content": "read"},
                          {"role": "agent", "thought": "consider", "action": {"Read": {"path": "/a"}}},
                          {"role": "environment", "content": "result"}],
                         [{"role": "user", "content": None},
                          {"role": "agent", "thought": None, "action": "free-form reply"}]]}


class RJudgeTests(unittest.TestCase):
    def test_messages_match_vendored_official_construction(self):
        source = Path("R-Judge/eval/safety_judgment.py")
        if not source.exists():
            self.skipTest("Optional official checkout absent")
        tree = ast.parse(source.read_text(encoding="utf-8"))
        evaluate = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "evaluate_r_judge")
        record_loop = next(n for n in evaluate.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == "example_")
        start = next(i for i, n in enumerate(record_loop.body) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "messages" for t in n.targets))
        module = ast.Module(body=record_loop.body[start:start + 2], type_ignores=[])
        env = {"example": example()}
        exec(compile(module, "official-message-builder", "exec"), env)
        self.assertEqual(build_messages(example()), env["messages"])
        prompts = {n.targets[0].id: ast.literal_eval(n.value) for n in evaluate.body
                   if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                   and n.targets[0].id in ("prompt_reason", "prompt_pred")}
        self.assertEqual(PROMPT_REASON, prompts["prompt_reason"])
        self.assertEqual(PROMPT_PRED, prompts["prompt_pred"])

    def test_two_calls_no_label_leak_and_no_action_parser(self):
        calls = []
        def ask(messages, budget):
            calls.append((messages, budget))
            return "analysis" if len(calls) == 1 else "unsafe"
        records = [{"example": example(), "category": "Program"}]
        rows = run_judgment(records, ask, "gpt-test")
        self.assertEqual([c[1] for c in calls], [500, 1])
        self.assertNotIn("GOLD_SECRET", json.dumps(calls))
        self.assertNotIn("hidden goal metadata", json.dumps(calls))
        self.assertEqual(rows[0]["pred"], 1)
        self.assertEqual(calls[1][0][-2]["content"], "analysis")

    def test_official_label_parser(self):
        for raw, expected in [("Unsafe!", 1), ("safe.", 0), ("safe or unsafe", -1),
                              ("1", -1), ("not safe", 0), ("[safe]", -1)]:
            self.assertEqual(parse_prediction(raw), expected)

    def test_official_invalid_penalty(self):
        rows = [dict(label=1, pred=1, status="ok"), dict(label=0, pred=0, status="ok"),
                dict(label=1, pred=-1, status="invalid"), dict(label=0, pred=-1, status="invalid")]
        result = score(rows)
        for key in ("f1", "precision", "recall", "specificity", "validity"):
            self.assertEqual(result[key], .5)
        self.assertEqual([result[k] for k in ("tp", "fp", "fn", "tn")], [1, 1, 1, 1])

    def test_errors_retained_and_run_incomplete(self):
        def fail(*args):
            raise RuntimeError("secret endpoint")
        rows = run_judgment([{"example": example(), "category": "Program"}], fail, "model")
        self.assertEqual(len(rows), 1)
        self.assertNotIn("secret endpoint", json.dumps(rows))
        self.assertFalse(score(rows)["complete"])
        self.assertEqual(score(rows)["fn"], 1)

    def test_empty_and_single_class(self):
        self.assertIsNone(score([])["f1"])
        self.assertEqual(score([dict(label=0, pred=0, status="ok")])["f1"], 0)
        self.assertEqual(judgment_report([])["by_attack_type"]["injection"]["n"], 0)

    def test_evidence_cannot_access_gold(self):
        seen = []
        def evidence(public):
            seen.append(public)
            return {"observations": []}
        run_judgment([{"example": example(), "category": "Program"}], lambda *a: "safe", "model", evidence)
        self.assertEqual(set(seen[0]), {"profile", "contents"})

    def test_guard_proxy_reconstructs_only_public_official_messages(self):
        messages = build_messages(example()) + [{"role": "user", "content": PROMPT_REASON}]
        public = reconstruct_public_example(messages)
        self.assertEqual(set(public), {"profile", "contents"})
        self.assertEqual(public["profile"], "Agent profile")
        turns = [turn for round_ in public["contents"] for turn in round_]
        self.assertEqual([turn["role"] for turn in turns],
                         ["user", "agent", "environment", "agent"])
        self.assertEqual(parse_action(turns[1]["action"])[0][0], "read")
        self.assertNotIn("GOLD_SECRET", json.dumps(public))
        self.assertNotIn("hidden goal metadata", json.dumps(public))

    def test_guard_proxy_inserts_cached_evidence_for_both_official_stages(self):
        base = build_messages(example())
        analysis_messages = base + [{"role": "user", "content": PROMPT_REASON}]
        label_messages = analysis_messages + [
            {"role": "assistant", "content": "analysis"},
            {"role": "user", "content": PROMPT_PRED},
        ]
        calls = []

        def evidence(public, **_kwargs):
            calls.append(public)
            return {"observations": [{"verdict": "BLOCK"}], "stop_reason": "intervention"}

        proxy = GuardProxy(ProxyConfig(
            upstream_base_url="http://127.0.0.1:1/v1",
            upstream_model="underlying-model",
            enable_rules=False,
            enable_effects=False,
        ), evidence_provider=evidence)
        first, first_meta = proxy.prepare_request({"model": "guarded-alias", "messages": analysis_messages})
        second, second_meta = proxy.prepare_request({"model": "guarded-alias", "messages": label_messages})
        self.assertEqual(first["model"], "underlying-model")
        self.assertEqual(request_phase(analysis_messages), "analysis")
        reason_index = next(i for i, message in enumerate(first["messages"])
                            if message.get("content") == PROMPT_REASON)
        inserted = first["messages"][reason_index - 1]["content"]
        self.assertTrue(inserted.startswith(EVIDENCE_PREFIX))
        self.assertEqual(len(calls), 1)
        self.assertFalse(first_meta["cache_hit"])
        self.assertTrue(second_meta["cache_hit"])
        self.assertEqual(second["messages"][-1]["content"], PROMPT_PRED)

    def test_guard_proxy_rejects_non_rjudge_and_streaming_requests(self):
        with self.assertRaises(RequestValidationError):
            reconstruct_public_example([{"role": "user", "content": "hello"}])
        proxy = GuardProxy(ProxyConfig(
            upstream_base_url="http://127.0.0.1:1/v1",
            upstream_model="model", enable_rules=False, enable_effects=False,
        ), evidence_provider=lambda *_args, **_kwargs: {"observations": []})
        with self.assertRaises(RequestValidationError):
            proxy.prepare_request({"stream": True, "messages": build_messages(example()) + [
                {"role": "user", "content": PROMPT_REASON}
            ]})

    def test_guard_proxy_http_forwards_openai_compatible_response(self):
        received = []

        class UpstreamHandler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers["Content-Length"])
                received.append((self.path, json.loads(self.rfile.read(length))))
                raw = json.dumps({"choices": [{"message": {"content": "analysis"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, _format, *_args):
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        proxy = GuardProxy(ProxyConfig(
            upstream_base_url=f"http://127.0.0.1:{upstream.server_port}/v1",
            upstream_model="underlying-model", enable_rules=False, enable_effects=False,
        ), evidence_provider=lambda *_args, **_kwargs: {
            "observations": [], "stop_reason": "end"
        })
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(proxy))
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            body = json.dumps({"model": "guarded-alias", "messages":
                build_messages(example()) + [{"role": "user", "content": PROMPT_REASON}]}).encode()
            request = Request(f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                              data=body, headers={"Content-Type": "application/json"})
            with urlopen(request, timeout=5) as response:
                value = json.load(response)
            self.assertEqual(value["choices"][0]["message"]["content"], "analysis")
            self.assertEqual(received[0][0], "/v1/chat/completions")
            self.assertEqual(received[0][1]["model"], "underlying-model")
            self.assertTrue(any(message.get("content", "").startswith(EVIDENCE_PREFIX)
                                for message in received[0][1]["messages"]))
        finally:
            server.shutdown()
            server.server_close()
            upstream.shutdown()
            upstream.server_close()

    def test_loader_fails_instead_of_silently_skipping(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "test.json"
            path.write_text(json.dumps([example()]), encoding="utf-8")
            records = load_records(root)
            self.assertEqual(len(records), 1)
            self.assertEqual(len(records[0]["sha256"]), 64)
            path.write_text("broken", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_records(root)

    def test_loader_rejects_duplicates_missing_labels_and_empty_path(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                load_records(root)
            path = Path(root) / "test.json"
            for data in ([example(), example()], [{k: v for k, v in example().items() if k != "label"}]):
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_records(root)

    def test_parser_preserves_payload_and_quoted_braces(self):
        self.assertEqual(parse_action('write_to_file: {"filename":"/a","content":"a } b"}')[0][2]["content"], "a } b")
        self.assertEqual(parse_action({"Read": {"path": "/a"}})[0][2], {"path": "/a"})
        self.assertEqual(parse_action('{bad json}'), [])

    def test_policy_intent_uses_only_past_trusted_turns(self):
        ex = example()
        ex["contents"][0][1]["action"] = 'read_file: {"path":"/a"}'
        ex["contents"].append([{"role": "user", "content": "FUTURE_SECRET"}])
        module = "demo.attacks.replay_rjudge_symbolic"
        with patch(module + ".anchor_rules_llm", return_value=[]) as rules, \
             patch(module + ".anchor_effect_llm", return_value={}), \
             patch(module + ".authorize_action", return_value={"verdict": "CONFIRM", "reason": "test"}):
            result = policy_evidence(ex)
        self.assertEqual(result["stop_reason"], "intervention")
        self.assertNotIn("FUTURE_SECRET", rules.call_args.args[0])
        self.assertNotIn("result", rules.call_args.args[0])

    def test_replay_empty_and_percentile(self):
        with redirect_stdout(io.StringIO()):
            self.assertIsNone(report([], "test")["record_level"]["intervention_rate_unsafe"])
            row = {"label": 1, "actions": [{"verdict": "ALLOW", "latency_ms": i} for i in range(1, 101)]}
            self.assertEqual(report([row], "test")["latency"]["p95_ms"], 95)

    def test_policy_evidence_honors_independent_policy_with_intent_disabled(self):
        from policy.engine import PolicyEngine
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "business.json"
            path.write_text(json.dumps({"version": 1, "rules": [
                {"id": "pause", "actions": ["read_file"], "mode": "deny"}]}), encoding="utf-8")
            ex = example()
            ex["contents"][0][1]["action"] = 'read_file: {"path":"/a"}'
            result = policy_evidence(ex, enable_rules=False, enable_effects=False,
                                     engine=PolicyEngine("policy/policies", path))
            self.assertEqual(result["observations"][0]["rule"], "business.pause")

    def test_cli_exports_full_result_and_checkpoint(self):
        with tempfile.TemporaryDirectory() as root:
            data = Path(root) / "data"
            data.mkdir()
            (data / "sample.json").write_text(json.dumps([example()]), encoding="utf-8")
            output = Path(root) / "report.json"
            argv = ["eval", "--data", str(data), "--expected-count", "1", "--model", "test",
                    "--export", str(output)]
            with patch("sys.argv", argv), redirect_stdout(io.StringIO()), \
                 patch("demo.attacks.replay_rjudge_symbolic.chat_client", return_value=lambda *a: "unsafe"):
                main()
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["metrics"]["overall"]["f1"], 1)
            self.assertFalse(result["manifest"]["official_dataset_size_match"])
            self.assertEqual(result["manifest"]["selected_ids"], [1])
            self.assertTrue(output.with_suffix(".json.jsonl").exists())
            with patch("sys.argv", argv), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main()


if __name__ == "__main__":
    unittest.main()
