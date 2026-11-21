"""Official-evaluator proxy with direct review as the CLI default.

Only public transcripts cross the predictor boundary. Direct review uses
CallReviewer and hard checks, then maps action decisions to record labels.
The optional policy-assisted protocol retains the older upstream judge path.
No dataset actions are executed. See RJUDGE_EVALUATION.md for scope and mapping.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from demo.attacks.rjudge_judgment import PROMPT_PRED, PROMPT_REASON
from demo.attacks.replay_rjudge_symbolic import policy_evidence
from policy.engine import PolicyEngine
from policy.intent_anchor import intent_llm_configured


EVIDENCE_PREFIX = (
    "Auxiliary policy observations (not ground truth; an authorization denial "
    "or confirmation is not itself proof of unsafe behavior):\n"
)


class RequestValidationError(ValueError):
    """The client request is not an official R-Judge judgment request."""


@dataclass(frozen=True)
class ProxyConfig:
    upstream_base_url: str
    upstream_model: str
    upstream_api_key: str = ""
    client_token: str = ""
    enable_rules: bool = True
    enable_effects: bool = True
    business_policy: Optional[str] = None
    cache_size: int = 1024
    upstream_timeout: float = 120.0
    max_body_bytes: int = 8 * 1024 * 1024
    protocol: str = 'policy-assisted'
    trace_dir: Optional[str] = None


class EvidenceCache:
    """Small process-local LRU; avoids recomputing evidence for label stage."""

    def __init__(self, max_size: int):
        if max_size <= 0:
            raise ValueError("cache_size must be positive")
        self.max_size = max_size
        self._items: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            value = self._items.get(key)
            if value is None:
                return None
            self._items.move_to_end(key)
            return copy.deepcopy(value)

    def put(self, key: str, value: Dict[str, Any]) -> None:
        with self._lock:
            self._items[key] = copy.deepcopy(value)
            self._items.move_to_end(key)
            while len(self._items) > self.max_size:
                self._items.popitem(last=False)


def _extract_agent_action(content: str) -> Optional[str]:
    """Recover the official ``[Action]:`` field from one assistant message."""
    if not isinstance(content, str):
        return None
    lines = content.splitlines()
    collecting = False
    collected: List[str] = []
    for line in lines:
        if line.startswith("[Action]:"):
            collecting = True
            collected.append(line[len("[Action]:"):].lstrip())
            continue
        if collecting and line.startswith("[") and "]:" in line:
            break
        if collecting:
            collected.append(line)
    value = "\n".join(collected).strip()
    return None if value in ('', 'None', 'null') else value


def request_phase(messages: List[Dict[str, Any]]) -> str:
    if not messages or not isinstance(messages[-1], dict):
        raise RequestValidationError("messages must be a non-empty array")
    last = messages[-1]
    if last.get("role") != "user":
        raise RequestValidationError("last message must be an official R-Judge prompt")
    if last.get("content") == PROMPT_REASON:
        return "analysis"
    if last.get("content") == PROMPT_PRED:
        return "label"
    raise RequestValidationError("request does not end with an official R-Judge prompt")


def _reason_prompt_index(messages: List[Dict[str, Any]]) -> int:
    matches = [i for i, message in enumerate(messages)
               if message.get("role") == "user" and message.get("content") == PROMPT_REASON]
    if len(matches) != 1:
        raise RequestValidationError("expected exactly one official reasoning prompt")
    return matches[0]


def reconstruct_public_example(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Reconstruct only profile/contents from official evaluator messages.

    R-Judge flattens rounds before sending them. Singleton rounds retain the
    exact causal order needed by ``policy_evidence`` without inventing missing
    grouping information.
    """
    phase = request_phase(messages)
    reason_index = _reason_prompt_index(messages)
    if phase == "label":
        if reason_index + 2 >= len(messages):
            raise RequestValidationError("label request is missing prior analysis")
        if messages[reason_index + 1].get("role") != "assistant":
            raise RequestValidationError("label request is missing assistant analysis")

    transcript = messages[:reason_index]
    if not transcript or transcript[0].get("role") != "system":
        raise RequestValidationError("official R-Judge profile is missing")
    profile = transcript[0].get("content")
    if not isinstance(profile, str):
        raise RequestValidationError("profile must be text")

    contents: List[List[Dict[str, Any]]] = []
    for message in transcript[1:]:
        role = message.get("role")
        content = message.get("content")
        if not isinstance(content, str):
            raise RequestValidationError("transcript content must be text")
        if role == "user" and content.startswith("[ENVIRONMENT]:"):
            turn = {"role": "environment", "content": content[len("[ENVIRONMENT]:"):].lstrip()}
        elif role == "user":
            turn = {"role": "user", "content": content}
        elif role == "assistant":
            turn = {"role": "agent", "action": _extract_agent_action(content)}
        else:
            raise RequestValidationError("unexpected role in official transcript")
        contents.append([turn])
    return {"profile": profile, "contents": contents}


def augment_messages(messages: List[Dict[str, Any]], evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Insert evidence before the official reasoning prompt for both stages."""
    index = _reason_prompt_index(messages)
    augmented = copy.deepcopy(messages)
    augmented.insert(index, {
        "role": "user",
        "content": EVIDENCE_PREFIX + json.dumps(evidence, ensure_ascii=False, separators=(",", ":")),
    })
    return augmented


class GuardProxy:
    def __init__(
        self,
        config: ProxyConfig,
        *,
        evidence_provider: Callable[..., Dict[str, Any]] = policy_evidence,
        engine: Optional[PolicyEngine] = None,
    ):
        self.config = config
        self.evidence_provider = evidence_provider
        self.engine = engine if engine is not None else PolicyEngine(
            str(ROOT / "policy" / "policies"), config.business_policy
        )
        self.cache = EvidenceCache(config.cache_size)
        self.review_lock = threading.Lock()

    def _evidence_key(self, public: Dict[str, Any]) -> str:
        policy_fingerprint = getattr(getattr(self.engine, "business_policy", None), "fingerprint", None)
        material = {
            "public": public,
            "enable_rules": self.config.enable_rules,
            "enable_effects": self.config.enable_effects,
            "business_policy": policy_fingerprint,
        }
        raw = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def prepare_request(self, body: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        if not isinstance(body, dict):
            raise RequestValidationError("request body must be an object")
        messages = body.get("messages")
        if not isinstance(messages, list):
            raise RequestValidationError("messages must be an array")
        if body.get("stream"):
            raise RequestValidationError("streaming is not supported")

        phase = request_phase(messages)
        public = reconstruct_public_example(messages)
        key = self._evidence_key(public)
        evidence = self.cache.get(key)
        cache_hit = evidence is not None
        started = time.perf_counter()
        if evidence is None:
            evidence = self.evidence_provider(
                public,
                enable_rules=self.config.enable_rules,
                enable_effects=self.config.enable_effects,
                engine=self.engine,
            )
            if not isinstance(evidence, dict):
                raise RuntimeError("policy evidence provider returned a non-object")
            self.cache.put(key, evidence)

        forwarded = copy.deepcopy(body)
        forwarded["model"] = self.config.upstream_model
        forwarded["messages"] = augment_messages(messages, evidence)
        metadata = {
            "phase": phase,
            "transcript_sha256": key,
            "cache_hit": cache_hit,
            "evidence_ms": round((time.perf_counter() - started) * 1000, 2),
            "stop_reason": evidence.get("stop_reason"),
            "observations": len(evidence.get("observations", [])),
        }
        return forwarded, metadata

    def forward(self, body: Dict[str, Any]) -> Tuple[int, bytes, str, Dict[str, Any]]:
        if self.config.protocol == 'review':
            return self.forward_review(body)
        forwarded, metadata = self.prepare_request(body)
        raw = json.dumps(forwarded, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.config.upstream_api_key:
            headers["Authorization"] = "Bearer " + self.config.upstream_api_key
        request = urllib.request.Request(
            self.config.upstream_base_url.rstrip("/") + "/chat/completions",
            data=raw,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.upstream_timeout) as response:
                return response.status, response.read(), response.headers.get_content_type(), metadata
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(65536), exc.headers.get_content_type(), metadata

    def forward_review(self, body):
        from demo.attacks.rjudge_review import review_record
        if not isinstance(body, dict) or body.get('stream'):
            raise RequestValidationError('Only non-streaming judgment requests are supported')
        messages = body.get('messages')
        if not isinstance(messages, list):
            raise RequestValidationError('messages must be an array')
        phase = request_phase(messages)
        public = reconstruct_public_example(messages)
        key = self._evidence_key(public)
        with self.review_lock:
            result = self.cache.get(key)
            cache_hit = result is not None
            if result is None:
                result = review_record(public, engine=self.engine)
                self.cache.put(key, result)
                if self.config.trace_dir:
                    folder = Path(self.config.trace_dir)
                    folder.mkdir(parents=True, exist_ok=True)
                    temporary = folder / (key+'.tmp')
                    temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
                    temporary.replace(folder / (key+'.json'))
        if phase == 'label':
            content = result['prediction'] if result['prediction'] in ('safe', 'unsafe') else 'undetermined'
        else:
            content = json.dumps({'protocol': result['protocol'], 'decision': result['prediction'],
                                  'reason': result['reason'], 'scope': result['scope']}, ensure_ascii=False)
        response = {'id': 'review-'+key[:16], 'object': 'chat.completion', 'created': int(time.time()),
                    'model': body.get('model', 'icbguard-review'),
                    'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': content},
                                 'finish_reason': 'stop'}]}
        metadata = {'protocol': 'review', 'phase': phase, 'transcript_sha256': key,
                    'cache_hit': cache_hit, 'prediction': result['prediction'], 'reason': result['reason'],
                    'record_seconds': result['elapsed_seconds'], 'review_seconds': result['review_seconds'],
                    'review_requests': result['review_requests']}
        return 200, json.dumps(response, ensure_ascii=False).encode(), 'application/json', metadata


def _json_error(message: str, *, error_type: str = "invalid_request_error") -> bytes:
    return json.dumps({"error": {"message": message, "type": error_type}},
                      ensure_ascii=False).encode("utf-8")


def make_handler(proxy: GuardProxy):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ICBGuardRJudgeProxy/1.0"

        def _write(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            expected = proxy.config.client_token
            if not expected:
                return True
            value = self.headers.get("Authorization", "")
            supplied = value[7:] if value.startswith("Bearer ") else ""
            return hmac.compare_digest(supplied, expected)

        def do_GET(self) -> None:  # noqa: N802
            if self.path in ("/health", "/healthz"):
                body = json.dumps({
                    "status": "ok",
                    "service": "rjudge-guard-proxy",
                    "protocol": proxy.config.protocol,
                    "upstream_model": proxy.config.upstream_model,
                    "policy_rules": proxy.config.protocol == 'policy-assisted' and proxy.config.enable_rules,
                    "policy_effects": proxy.config.protocol == 'policy-assisted' and proxy.config.enable_effects,
                }).encode("utf-8")
                self._write(200, body)
                return
            if self.path == "/v1/models":
                body = json.dumps({"object": "list", "data": [{
                    "id": "icbguard-rjudge", "object": "model", "owned_by": "local"
                }]}).encode("utf-8")
                self._write(200, body)
                return
            self._write(404, _json_error("not found", error_type="not_found"))

        def do_POST(self) -> None:  # noqa: N802
            if self.path not in ("/v1/chat/completions", "/chat/completions"):
                self._write(404, _json_error("not found", error_type="not_found"))
                return
            if not self._authorized():
                self._write(401, _json_error("invalid proxy token", error_type="authentication_error"))
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > proxy.config.max_body_bytes:
                    raise RequestValidationError("invalid request size")
                body = json.loads(self.rfile.read(length))
                started = time.perf_counter()
                status, response, content_type, metadata = proxy.forward(body)
                metadata.update(status=status, total_ms=round((time.perf_counter() - started) * 1000, 2))
                print(json.dumps({"event": "rjudge_guard_proxy", **metadata}, ensure_ascii=False), flush=True)
                self._write(status, response, content_type)
            except (RequestValidationError, json.JSONDecodeError) as exc:
                self._write(400, _json_error(str(exc)))
            except Exception as exc:
                print(json.dumps({"event": "rjudge_guard_proxy_error",
                                  "error_type": type(exc).__name__}), flush=True)
                self._write(500, _json_error("guard proxy failed", error_type="server_error"))

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    return Handler


def _build_config(args: argparse.Namespace) -> ProxyConfig:
    return ProxyConfig(
        upstream_base_url=args.upstream_base_url,
        upstream_model=args.upstream_model,
        upstream_api_key=os.environ.get("RJUDGE_PROXY_UPSTREAM_API_KEY", os.environ.get("RJUDGE_API_KEY", "")),
        client_token=os.environ.get("RJUDGE_PROXY_CLIENT_TOKEN", ""),
        enable_rules=not args.no_rules,
        enable_effects=not args.no_effects,
        business_policy=args.business_policy,
        cache_size=args.cache_size,
        upstream_timeout=args.upstream_timeout,
        max_body_bytes=args.max_body_bytes,
        protocol=args.protocol,
        trace_dir=args.trace_dir,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="ICB-Guard proxy for the official R-Judge evaluator")
    parser.add_argument('--protocol', choices=('review', 'policy-assisted'), default='review')
    parser.add_argument('--trace-dir', default=str(ROOT/'results'/('rjudge_review_'+str(time.time_ns()))))
    parser.add_argument("--upstream-base-url", default=os.environ.get("RJUDGE_PROXY_UPSTREAM_BASE_URL"))
    parser.add_argument("--upstream-model", default=os.environ.get("RJUDGE_PROXY_UPSTREAM_MODEL"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8098)
    parser.add_argument("--business-policy")
    parser.add_argument("--no-rules", action="store_true")
    parser.add_argument("--no-effects", action="store_true")
    parser.add_argument("--cache-size", type=int, default=1024)
    parser.add_argument("--upstream-timeout", type=float, default=120.0)
    parser.add_argument("--max-body-bytes", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()

    if args.protocol == 'policy-assisted' and (not args.upstream_base_url or not args.upstream_model):
        parser.error("set --upstream-base-url and --upstream-model")
    if args.protocol == 'review' and (args.no_rules or args.no_effects):
        parser.error('review does not generate rules/effects; omit these legacy switches')
    if args.host not in ("127.0.0.1", "::1", "localhost") and not os.environ.get("RJUDGE_PROXY_CLIENT_TOKEN"):
        parser.error("non-loopback binding requires RJUDGE_PROXY_CLIENT_TOKEN")
    if (args.protocol == 'review' or not args.no_rules or not args.no_effects) and not intent_llm_configured():
        parser.error("set ICB_INTENT_LLM_API_KEY, or explicitly disable both policy LLM components")

    config = _build_config(args)
    proxy = GuardProxy(config)
    summary = {
        "status": "configuration_valid",
        "protocol": config.protocol,
        "trace_dir": config.trace_dir,
        "listen": f"http://{args.host}:{args.port}/v1",
        "upstream_base_url": config.upstream_base_url,
        "upstream_model": config.upstream_model,
        "upstream_api_key_configured": bool(config.upstream_api_key),
        "intent_llm_configured": intent_llm_configured(),
        "rules": config.protocol == 'policy-assisted' and config.enable_rules,
        "effects": config.protocol == 'policy-assisted' and config.enable_effects,
        "business_policy": bool(config.business_policy),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    if args.check_config:
        return

    server = ThreadingHTTPServer((args.host, args.port), make_handler(proxy))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
