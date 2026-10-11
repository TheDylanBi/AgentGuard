/**
 * ICB-Guard adapter for pi (deployment mode).
 *
 * Gates pi's BUILT-IN tools (bash/read/write/edit) at the tool_call boundary:
 * before each tool executes, the gateway authorizes it against
 *   capability (Effect Envelope) + intent anchor + policy.
 *
 * Also registers a `gui_click` tool for the visual-evidence demo.
 *
 * Load with:
 *   pi -e "F:\Code\MLLM Agent\adapters\pi_extension.ts"
 *
 * Config (environment variables):
 *   ICB_GATEWAY_URL     default http://127.0.0.1:8099
 *   ICB_CAPABILITY_CERT_ID  administrator-provisioned tool grant
 *   ICB_EXECUTOR_TOKEN / ICB_INTENT_TOKEN / ICB_APPROVER_TOKEN  separate roles
 *   ICB_DEFAULT_SCREENSHOT  for gui_click
 */
import { Type } from "typebox";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const GATEWAY_URL = process.env.ICB_GATEWAY_URL ?? "http://127.0.0.1:8099";
const GATEWAY_TOKEN = process.env.ICB_EXECUTOR_TOKEN ?? "";

// P0-2: shared-secret auth header for the mutating gateway endpoints. The
// agent LLM must never hold this token — only the trusted adapter channel does.
const authHeaders = (): Record<string, string> =>
  GATEWAY_TOKEN ? { "content-type": "application/json", Authorization: `Bearer ${GATEWAY_TOKEN}` }
                : { "content-type": "application/json" };
const controlHeaders = (role: "INTENT" | "APPROVER"): Record<string, string> => {
  const token = process.env[`ICB_${role}_TOKEN`];
  if (!token) throw new Error(`Missing trusted ${role} identity`);
  return { "content-type": "application/json", Authorization: `Bearer ${token}` };
};
const DEFAULT_SCREENSHOT =
  process.env.ICB_DEFAULT_SCREENSHOT ?? "F:/Code/MLLM Agent/demo/attacks/data/images/ip-click-upload-web-explicit.png";

// P4 TOCTOU: canonical hash of a tool input, used to verify the action the
// executor is about to run is EXACTLY the action that was authorized.
function actionHash(input: unknown): string {
  return createHash("sha256").update(JSON.stringify(input ?? {})).digest("hex");
}

export default function (pi: ExtensionAPI) {
  let intentAnchor = "";
  let intentProfile: any = null;
  let capabilityCertId = process.env.ICB_CAPABILITY_CERT_ID ?? "";
  let anchored = false;
  // Per-session policy key. Each pi session gets its own gateway policy, and
  // re-anchoring on every user turn REVOKES the previous turn's rules (no
  // multi-turn permission accumulation -> no injection surface for old grants).
  let sessionId = "pi-session";

  pi.on("before_agent_start", async (event, ctx) => {
    anchored = false;
    intentProfile = null;
    intentAnchor = event.prompt;
    sessionId = ctx.sessionManager.getSessionId() ?? "pi-session";
    // 方案 C: anchor the intent once per turn (semantic -> structured profile).
    // Revoke-on-new-input: /anchor_intent REPLACES (never unions) the session
    // policy, so old turn permissions cannot be abused by later injection.
    // Failure leaves the adapter blocked until a trusted anchor succeeds.
    try {
      const resp = await fetch(`${GATEWAY_URL}/anchor_intent`, {
        method: "POST",
        headers: controlHeaders("INTENT"),
        body: JSON.stringify({ session_id: sessionId, prompt: event.prompt }),
      });
      if (resp.ok) {
        const data = (await resp.json()) as { profile: any };
        intentProfile = data.profile;
        anchored = true;
      }
    } catch (e) {
      intentProfile = null;
    }
  });

  async function ensureCapabilityCert(): Promise<string> {
    if (!capabilityCertId) throw new Error("An administrator must provision ICB_CAPABILITY_CERT_ID");
    return capabilityCertId;
  }

  async function authorize(actionType: string, target: string, payload: any, approvalTicket?: string) {
    if (!anchored) throw new Error("Trusted intent is not available");
    const certId = await ensureCapabilityCert();
    const body: any = {
      session_id: sessionId,
      intent_anchor: { text: intentAnchor || "(no intent recorded)", signer: "session-bound" },
      tool: { tool_id: "pi_agent", capability_cert_id: certId },
      action: { type: actionType, target, payload },
      approval_ticket: approvalTicket,
      visual_state: { mode: "screenshot" }, // non-visual: no screenshot needed
    };
    if (intentProfile) body.intent_profile = intentProfile;
    const resp = await fetch(`${GATEWAY_URL}/authorize`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(body),
    });
    if (!resp.ok) throw new Error(`Authorization failed: HTTP ${resp.status}`);
    return (await resp.json()) as {
      verdict: string;
      reason: string;
      confirm_token?: string;
      policy_update?: any;
      decision_id?: string;
      execution_ticket?: string;
    };
  }

  // ---- gate built-in tools (the "same effect in the agent") ----
  pi.on("tool_call", async (event, ctx) => {
    if (!anchored) return { block: true, reason: "ICB-Guard: 可信用户意图尚未建立" };

    const mapping: Record<string, { type: string; target: (input: any) => string }> = {
      bash: { type: "shell", target: (i) => i?.command ?? "" },
      read: { type: "read_file", target: (i) => i?.path ?? "" },
      write: { type: "write_file", target: (i) => i?.path ?? "" },
      edit: { type: "write_file", target: (i) => i?.path ?? "" },
    };
    const m = mapping[event.toolName];
    if (!m) {
      if (["gui_click", "browser_read", "browser_click", "browser_type"].includes(event.toolName)) return;
      return { block: true, reason: "ICB-Guard: 未接入授权的工具" };
    }

    // P4 TOCTOU: capture the input hash BEFORE authorization; re-check it AFTER,
    // right before the tool runs, so an action changed between check and use is
    // blocked (the executor must run exactly what was authorized).
    const target = m.target(event.input);
    const inputHash = actionHash(event.input);
    let verdict;
    try {
      verdict = await authorize(m.type, target, event.input);
    } catch {
      return { block: true, reason: "ICB-Guard: 授权服务不可用，已停止执行" };
    }
    if (!verdict || !["ALLOW", "BLOCK", "CONFIRM"].includes(verdict.verdict)) {
      return { block: true, reason: "ICB-Guard: 无效授权结果" };
    }

    if (verdict.verdict === "BLOCK") {
      return { block: true, reason: `ICB-Guard: ${verdict.reason}` };
    }
    if (verdict.verdict === "CONFIRM") {
      const pu = verdict.policy_update;
      const puText = pu
        ? `\n\n[最小权限扩张] ${pu.classification ?? "expansion"}` +
          (pu.rule ? `\n规则: ${pu.rule.tool} / ${pu.rule.decision}` : "")
        : "";
      const ok = await ctx.ui.confirm(
        "ICB-Guard 授权",
        `动作: ${m.type}(${target})\n参数: ${JSON.stringify(event.input)}\n\n${verdict.reason}${puText}\n\n仅允许本次执行？`
      );
      if (!ok) return { block: true, reason: "ICB-Guard: 用户拒绝" };
      // Approval covers only this exact call. Re-authorize and consume before use.
      if (!verdict.confirm_token) return { block: true, reason: "ICB-Guard: 缺少审批凭证" };
      try {
        const response = await fetch(`${GATEWAY_URL}/confirm`, {
          method: "POST", headers: controlHeaders("APPROVER"),
          body: JSON.stringify({ token: verdict.confirm_token, approve: true }),
        });
        if (!response.ok) throw new Error("Approval failed");
        const approval = await response.json() as any;
        if (approval.status !== "approved" || !approval.ticket) throw new Error("Stale approval");
        verdict = await authorize(m.type, target, event.input, approval.ticket);
      } catch {
        return { block: true, reason: "ICB-Guard: 无法验证审批" };
      }
    }
    if (verdict.verdict !== "ALLOW" || !verdict.execution_ticket || actionHash(event.input) !== inputHash) {
      return { block: true, reason: "ICB-Guard: 授权失效或动作已改变" };
    }
    try {
      const response = await fetch(`${GATEWAY_URL}/consume`, {
        method: "POST", headers: authHeaders(),
        body: JSON.stringify({ ticket: verdict.execution_ticket, session_id: sessionId,
          tool: { tool_id: "pi_agent", capability_cert_id: capabilityCertId },
          action: { type: m.type, target, payload: event.input } }),
      });
      if (!response.ok || (await response.json() as any).status !== "consumed") throw new Error("Rejected");
      if (actionHash(event.input) !== inputHash) throw new Error("Changed input");
    } catch {
      return { block: true, reason: "ICB-Guard: 执行凭证校验失败" };
    }
  });

  // ---- visual demo tool ----
  pi.registerTool({
    name: "gui_click",
    label: "GUI Click (ICB-Guard)",
    description:
      "Preview authorization for a click; this demo does not execute clicks. The proposal is " +
      "authorized by the ICB-Guard pre-action gate using visual evidence " +
      "(screenshot + optional a11y snapshot for role verification).",
    parameters: Type.Object({
      target: Type.String(),
      a11y_snapshot: Type.Optional(Type.Array(Type.Object({
        role: Type.String(),
        name: Type.String(),
        value: Type.Optional(Type.String()),
        region: Type.Optional(Type.Array(Type.Number())),
      }))),
    }),
    async execute(toolCallId, params, signal) {
      const screenshotPath = DEFAULT_SCREENSHOT;
      let imageB64: string;
      try {
        imageB64 = readFileSync(resolve(screenshotPath)).toString("base64");
      } catch (e) {
        return { isError: true, content: [{ type: "text", text: `无法读取截图: ${screenshotPath}` }] };
      }

      // a11y snapshot: inline param, or load from a JSON file (array of nodes)
      let a11y = params.a11y_snapshot ?? undefined;

      const certId = await ensureCapabilityCert();
      const visualState: any = { mode: "screenshot", screenshot_b64: imageB64 };
      if (a11y) visualState.a11y_snapshot = a11y;

      const resp = await fetch(`${GATEWAY_URL}/authorize`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          session_id: sessionId,
          intent_anchor: { text: intentAnchor || "(no intent recorded)", signer: "session-bound" },
          tool: { tool_id: "pi_agent", capability_cert_id: certId },
          action: { type: "click", target: params.target, payload: {} },
          visual_state: visualState,
        }),
        signal,
      });
      if (!resp.ok) return { isError: true, content: [{ type: "text", text: `网关错误 ${resp.status}` }] };
      const v = (await resp.json()) as { verdict: string; reason: string };
      return {
        content: [{ type: "text", text: `${v.verdict}: ${v.reason}` }],
        details: v,
        isError: v.verdict !== "ALLOW",
      };
    },
  });

  // ---- read the live browser page (a11y + text) for the web-agent loop ----
  pi.registerTool({
    name: "browser_read",
    label: "Browser Read (page content)",
    description:
      "Read the current browser page: extract the accessibility tree and " +
      "interactive elements so the agent can understand what is on the page " +
      "and decide its next action.",
    parameters: Type.Object({
      cdp_endpoint: Type.Optional(Type.String()),
    }),
    async execute(toolCallId, params, signal) {
      const cdp = params.cdp_endpoint ?? "http://localhost:9222";
      // The gateway exposes the captured a11y snapshot via attached mode.
      // Reuse /authorize-free path: fetch the page state through the gateway.
      const resp = await fetch(`${GATEWAY_URL}/browser_state?cdp=${encodeURIComponent(cdp)}`, {
        method: "GET",
        headers: authHeaders(),
        signal,
      });
      if (!resp.ok) {
        return { isError: true, content: [{ type: "text", text: `browser_read 失败 ${resp.status}` }] };
      }
      const state = (await resp.json()) as { title?: string; elements?: Array<{ role: string; name: string }> };
      const lines = (state.elements ?? []).map(
        (e) => `[${e.role}] ${e.name}`
      );
      return {
        content: [{
          type: "text",
          text: `页面: ${state.title || "?"}\n可交互元素:\n` + (lines.join("\n") || "(无)"),
        }],
        details: state,
      };
    },
  });

  // ---- live-browser click (attached mode: gateway pulls a11y via CDP) ----
  pi.registerTool({
    name: "browser_click",
    label: "Browser Click (ICB-Guard attached)",
    description:
      "Preview click authorization without executing it. The gateway connects to Chrome " +
      "via CDP, extracts the REAL accessibility tree + screenshot, and " +
      "authorizes the click before it happens. Use this instead of browser " +
      "JS clicks so visual role-manipulation attacks are caught.",
    parameters: Type.Object({
      target: Type.String(),
      cdp_endpoint: Type.Optional(Type.String()),
    }),
    async execute(toolCallId, params, signal) {
      const cdp = params.cdp_endpoint ?? "http://localhost:9222";
      const certId = await ensureCapabilityCert();
      const resp = await fetch(`${GATEWAY_URL}/authorize`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          session_id: sessionId,
          intent_anchor: { text: intentAnchor || "(no intent recorded)", signer: "session-bound" },
          tool: { tool_id: "pi_agent", capability_cert_id: certId },
          action: { type: "click", target: params.target, payload: {} },
          visual_state: { mode: "attached", cdp_endpoint: cdp },
        }),
        signal,
      });
      if (!resp.ok) {
        return { isError: true, content: [{ type: "text", text: `网关错误 ${resp.status}: ${await resp.text()}` }] };
      }
      const v = (await resp.json()) as { verdict: string; reason: string; certificates?: any[] };
      const cert = v.certificates?.[0];
      const summary = cert
        ? `roles=${cert.roles?.join(",") || "?"} trust=${cert.trust} sources=${(cert.sources || []).map((s: any) => s.type).join(",")}`
        : "";
      return {
        content: [{
          type: "text",
          text: `${v.verdict}: ${v.reason}${summary ? ` | ${summary}` : ""}`,
        }],
        details: v,
        isError: v.verdict !== "ALLOW",
      };
    },
  });

  // ---- live-browser type (attached mode: gateway verifies the textbox) ----
  pi.registerTool({
    name: "browser_type",
    label: "Browser Type (ICB-Guard attached)",
    description:
      "Preview typing authorization without entering text. The gateway " +
      "connects to Chrome via CDP, extracts the accessibility tree, verifies " +
      "the field is a real textbox and consistent with the intent, then " +
      "authorizes the typing before it happens.",
    parameters: Type.Object({
      target: Type.String(),
      text: Type.String(),
      cdp_endpoint: Type.Optional(Type.String()),
    }),
    async execute(toolCallId, params, signal) {
      const cdp = params.cdp_endpoint ?? "http://localhost:9222";
      const certId = await ensureCapabilityCert();
      const resp = await fetch(`${GATEWAY_URL}/authorize`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          session_id: sessionId,
          intent_anchor: { text: intentAnchor || "(no intent recorded)", signer: "session-bound" },
          tool: { tool_id: "pi_agent", capability_cert_id: certId },
          action: { type: "type", target: params.target, payload: { text: params.text } },
          visual_state: { mode: "attached", cdp_endpoint: cdp },
        }),
        signal,
      });
      if (!resp.ok) {
        return { isError: true, content: [{ type: "text", text: `网关错误 ${resp.status}: ${await resp.text()}` }] };
      }
      const v = (await resp.json()) as { verdict: string; reason: string; certificates?: any[] };
      const cert = v.certificates?.[0];
      const summary = cert
        ? `roles=${cert.roles?.join(",") || "?"} trust=${cert.trust}`
        : "";
      return {
        content: [{
          type: "text",
          text: `${v.verdict}: ${v.reason}${summary ? ` | ${summary}` : ""}`,
        }],
        details: v,
        isError: v.verdict !== "ALLOW",
      };
    },
  });
}
