// Never copy provider error bodies, request prompts, headers or URLs to summary.
import { createHash } from "node:crypto";

export function errorDiagnostic(message) {
  const text = String(message ?? "");
  let category = "unknown";
  if (/maximum context|context.length.exceed|context window|too many tokens|longer than.*context|max_tokens.*(?:exceed|large)/i.test(text)) {
    category = "context_limit";
  } else if (/tool.*(?:pars|json)|(?:pars|json).*tool/i.test(text)) {
    category = "tool_parse_error";
  } else if (/content_filter/i.test(text)) {
    category = "content_filter";
  } else if (/network_error|connection|timed?\s*out|fetch failed/i.test(text)) {
    category = "transport_error";
  }
  const status = text.match(/^\s*(?:HTTP\s+)?([45]\d\d)\b/i);
  return { category, ...(status ? { http_status: Number(status[1]) } : {}), message_chars: text.length,
    message_sha256: createHash("sha256").update(text).digest("hex") };
}

export function prepareRequest(payload, model, mode = "sdk") {
  const field = Object.hasOwn(payload, "max_tokens") ? "max_tokens" : "max_completion_tokens";
  const sdkBudget = payload[field];
  if (mode === "model") {
    if (model.api !== "openai-completions" || !Number.isInteger(model.maxTokens) || model.maxTokens < 1) {
      throw new Error("Model output budget requires an OpenAI-compatible model with maxTokens");
    }
    // The configured cap must never override the SDK's remaining-context cap.
    payload = { ...payload, [field]: Number.isInteger(sdkBudget)
      ? Math.min(model.maxTokens, Math.max(1, sdkBudget)) : model.maxTokens };
  }
  return { payload, diagnostic: { output_budget_mode: mode, sdk_max_tokens: sdkBudget,
    sent_max_tokens: payload[field], context_window: model.contextWindow,
    budget_source: "sdk_context_cap",
    context_budget_exhausted: Number.isInteger(sdkBudget) && sdkBudget <= 1,
    context_output_budget_low: Number.isInteger(sdkBudget) && sdkBudget < Math.min(256, model.maxTokens ?? 256),
    ...(Number.isInteger(sdkBudget) && sdkBudget <= 1
      ? { budget_reason: "sdk_remaining_output_budget_at_floor" } : {}),
    message_count: payload.messages?.length, tool_count: payload.tools?.length ?? 0 } };
}
