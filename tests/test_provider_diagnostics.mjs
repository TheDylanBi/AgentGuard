import test from "node:test";
import assert from "node:assert/strict";
import { errorDiagnostic, prepareRequest } from "../adapters/agentdojo_pi/provider_diagnostics.mjs";

test("errors are classified without exposing provider body, key or URL", () => {
  const raw = "400 maximum context length exceeded https://private.example sk-sensitive";
  const data = errorDiagnostic(raw);
  assert.equal(data.category, "context_limit");
  assert.equal(data.message_sha256.length, 64);
  assert.ok(!JSON.stringify(data).includes("private.example"));
  assert.ok(!JSON.stringify(data).includes("sk-sensitive"));
  assert.equal(errorDiagnostic("Tool call JSON parsing failed").category, "tool_parse_error");
  assert.equal(errorDiagnostic("Connection timeout").category, "transport_error");
});

test("configured budget changes only output cap and preserves original payload", () => {
  const payload = { model: "fixture", max_tokens: 1, messages: [{role:"user", content:"original"}], tools: [] };
  const model = { api: "openai-completions", maxTokens: 2048, contextWindow: 16384 };
  const out = prepareRequest(payload, model, "model");
  assert.equal(payload.max_tokens, 1);
  assert.deepEqual(out.payload, { ...payload, max_tokens: 1 });
  assert.equal(out.diagnostic.context_budget_exhausted, true);
  assert.equal(model.contextWindow, 16384);
  assert.equal(prepareRequest(payload, model).payload, payload);
  assert.throws(() => prepareRequest(payload, {...model,api:"unsupported"}, "model"));
});

test("both token fields respect SDK remaining budget and configured ceiling", () => {
  const model = { api: "openai-completions", maxTokens: 2048, contextWindow: 16384 };
  for (const field of ["max_tokens", "max_completion_tokens"]) {
    for (const [budget, expected] of [[512,512], [4096,2048], [1,1]]) {
      const result = prepareRequest({[field]: budget}, model, "model");
      assert.equal(result.payload[field], expected);
    }
  }
});

test("a small remaining cap is diagnosed without overriding the SDK", () => {
  const model = { api: "openai-completions", maxTokens: 2048, contextWindow: 32768 };
  const result = prepareRequest({ max_tokens: 52 }, model, "model");
  assert.equal(result.payload.max_tokens, 52);
  assert.equal(result.diagnostic.context_output_budget_low, true);
  assert.equal(result.diagnostic.context_budget_exhausted, false);
  assert.equal(prepareRequest({max_tokens:2048}, model, "model").diagnostic.context_output_budget_low, false);
});
