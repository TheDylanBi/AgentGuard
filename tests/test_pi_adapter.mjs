// Run with Node >=22.13: node tests/test_pi_adapter.mjs
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stripTypeScriptTypes } from "node:module";

process.env.ICB_EXECUTOR_TOKEN = "executor-test";
process.env.ICB_INTENT_TOKEN = "intent-test";
process.env.ICB_APPROVER_TOKEN = "approver-test";
process.env.ICB_CAPABILITY_CERT_ID = "cert-test";
let source = readFileSync(new URL("../adapters/pi_extension.ts", import.meta.url), "utf8");
source = source.replace('import { Type } from "typebox";',
  'const Type = new Proxy({}, { get: () => (...args) => args });');
const javascript = stripTypeScriptTypes(source, { mode: "transform" });
const { default: install, validateToolMappings } = await import(`data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}`);

async function scenario(responses, { confirm = true, toolName = "read" } = {}) {
  const callbacks = {}, requests = [];
  install({ on: (name, fn) => callbacks[name] = fn, registerTool: () => {} });
  const ctx = { sessionManager: { getSessionId: () => "session-test" }, ui: { confirm: async () => confirm } };
  globalThis.fetch = async (url, init) => {
    requests.push({ url, ...init, body: init.body ? JSON.parse(init.body) : null });
    if (url.endsWith("/anchor_intent")) return { ok: true, json: async () => ({ profile: {} }) };
    const next = responses.shift();
    if (next instanceof Error) throw next;
    assert.ok(next, `Unexpected request: ${url}`);
    return { ok: next.ok ?? true, status: next.status ?? 200, json: async () => next.body ?? next };
  };
  await callbacks.before_agent_start({ prompt: "read test file" }, ctx);
  const input = { path: "C:/workspace/test.txt", offset: 5, limit: 10 };
  const result = await callbacks.tool_call({ toolName, input }, ctx);
  return { result, requests, input };
}

for (const response of [{ ok: false, status: 500 }, { verdict: "INVALID" }, new Error("offline"),
                        { verdict: "ALLOW" }, { verdict: "BLOCK", reason: "denied" }]) {
  const { result } = await scenario([response]);
  assert.equal(result.block, true);
}
assert.equal((await scenario([{ verdict: "CONFIRM", confirm_token: "c" },
  { status: "stale" }])).result.block, true);
assert.equal((await scenario([{ verdict: "CONFIRM", confirm_token: "c" }], { confirm: false })).result.block, true);
assert.equal((await scenario([{ verdict: "ALLOW", execution_ticket: "e" },
  { ok: false, status: 403 }])).result.block, true);
assert.equal((await scenario([], { toolName: "unregistered_tool" })).result.block, true);
const controlled = await scenario([{ verdict: "ALLOW", execution_ticket: "e", execution_mode: "controlled" }]);
assert.equal(controlled.result.block, true);
assert.equal(controlled.requests.some(r => r.url.endsWith("/consume")), false);

const success = await scenario([{ verdict: "CONFIRM", confirm_token: "c" },
  { status: "approved", ticket: "a" }, { verdict: "ALLOW", execution_ticket: "e" }, { status: "consumed" }]);
assert.equal(success.result, undefined);
const authRequests = success.requests.filter(r => r.url.endsWith("/authorize"));
assert.deepEqual(authRequests[0].body.action.payload, success.input);
assert.equal(authRequests[1].body.approval_ticket, "a");
assert.equal(success.requests.find(r => r.url.endsWith("/confirm")).headers.Authorization, "Bearer approver-test");
assert.equal(success.requests.at(-1).headers.Authorization, "Bearer executor-test");
console.log("pi adapter scenarios passed (failure, approval, full arguments, controlled-mode refusal, single-use consumption)");
const temp = mkdtempSync(join(tmpdir(), "icb-mapping-test-"));
try {
  const path = join(temp, "mappings.json");
  writeFileSync(path, JSON.stringify({ custom_reader: { action_type: "read_file", target_field: "path" } }));
  process.env.ICB_PI_TOOL_MAPPINGS = path;
  const mapped = await scenario([{ verdict: "ALLOW", execution_ticket: "e" }, { status: "consumed" }], { toolName: "custom_reader" });
  assert.equal(mapped.result, undefined);
  assert.equal(mapped.requests.find(r => r.url.endsWith("/authorize")).body.action.type, "read_file");
  const denied = await scenario([{ verdict: "BLOCK", reason: "hard boundary" }], { toolName: "custom_reader" });
  assert.equal(denied.result.block, true);
  assert.equal(denied.requests.some(r => r.url.endsWith("/consume")), false);
  for (const value of [{ read: { action_type: "anything", target_field: "path" } },
    { arbitrary: { action_type: "read_file", target_field: "nested.path" } }, []])
    assert.throws(() => validateToolMappings(value));
  console.log("declared tool mappings passed (new tool, hard denial, no built-in override)");
} finally {
  delete process.env.ICB_PI_TOOL_MAPPINGS;
  rmSync(temp, { recursive: true });
}
