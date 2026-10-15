// Private stdio worker. Only suite tools exist; policy lives in the Python host.
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const send = (value) => process.stdout.write(JSON.stringify(value) + "\n");
const requests = new Map();
const proposals = new Map();
let buffer = "", started = false, toolQueue = Promise.resolve();
let session, finalizing = false;
function fail(error) {
  send({ type: "fatal", error: String(error?.message ?? error) });
  process.exitCode = 1;
  session?.abort();
  for (const { reject } of requests.values()) reject(new Error("Bridge stopped"));
  requests.clear();
  process.stdin.destroy();
}
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  if (Buffer.byteLength(buffer) > 16 * 1024 * 1024) return fail(new Error("Protocol limit"));
  let index;
  // LF only: tool text can legitimately contain Unicode line separators.
  while ((index = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, index);
    buffer = buffer.slice(index + 1);
    try {
      const message = JSON.parse(line);
      if (message.type === "init" && !started) {
        started = true;
        main(message).catch(fail);
      } else if (message.type === "tool_result" && requests.has(message.id)) {
        if (message.finalize) {
          finalizing = true;
          session.setActiveToolsByName([]);
        }
        const entry = requests.get(message.id);
        requests.delete(message.id);
        entry.resolve(message);
      } else throw new Error("Unexpected bridge message");
    } catch (error) { fail(error); }
  }
});
process.stdin.on("end", () => { if (requests.size) fail(new Error("Bridge disconnected")); });

export function suiteExtension(tools) {
  return (pi) => {
    for (const tool of tools) pi.registerTool({
      name: tool.name, label: tool.name, description: tool.description,
      parameters: tool.parameters,
      async execute(id, args) {
        const run = async () => {
          if (finalizing) {
            proposals.delete(id);
            return { content: [{ type: "text", text: "Not executed: controller stopped tool execution. Answer using existing results only." }],
                     details: {}, isError: true };
          }
          // pi may coerce null to "" (or other primitive values) before
          // execute(). The trusted Python host owns validation/defaulting.
          // Forward the original proposal, never the SDK-transformed args.
          const proposal = proposals.get(id);
          if (!proposal || proposal.name !== tool.name) throw new Error("Unmatched tool proposal");
          proposals.delete(id);
          const response = await new Promise((resolve, reject) => {
            if (requests.has(id)) return reject(new Error("Duplicate call ID"));
            requests.set(id, { resolve, reject });
            send({ type: "tool_call", id, name: tool.name, arguments: proposal.arguments });
          });
          return { content: [{ type: "text", text: response.error || response.text }],
                   details: {}, isError: Boolean(response.error) };
        };
        const result = toolQueue.then(run);
        toolQueue = result.catch(() => {});
        return result;
      },
    });
  };
}

async function main(config) {
  const sdk = await import(pathToFileURL(join(config.piPackage, "dist/index.js")).href);
  const { createAgentSession, DefaultResourceLoader, ModelRuntime, SessionManager, SettingsManager } = sdk;
  const settingsManager = SettingsManager.inMemory({ compaction: { enabled: false }, retry: { enabled: false } });
  const modelRuntime = await ModelRuntime.create({
    authPath: join(config.piAgentDir, "auth.json"), modelsPath: join(config.piAgentDir, "models.json"),
    modelsStorePath: join(config.scratch, "models-cache"), allowModelNetwork: false,
  });
  const model = modelRuntime.getModel(config.provider, config.model);
  if (!model) throw new Error("Requested pi provider/model is unavailable; no fallback permitted");
  const loader = new DefaultResourceLoader({
    cwd: config.scratch, agentDir: config.scratch, settingsManager,
    noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
    extensionFactories: [suiteExtension(config.tools)],
    systemPromptOverride: () => config.systemPrompt,
    appendSystemPromptOverride: () => [], agentsFilesOverride: () => ({ agentsFiles: [] }),
  });
  await loader.reload();
  const created = await createAgentSession({
    cwd: config.scratch, agentDir: config.scratch, modelRuntime, model,
    thinkingLevel: "off", settingsManager, resourceLoader: loader,
    sessionManager: SessionManager.inMemory(config.scratch),
    tools: config.tools.map((tool) => tool.name),
  });
  session = created.session;
  const actual = session.getActiveToolNames().sort();
  const expected = config.tools.map((tool) => tool.name).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error("Unexpected active tools");
  let turns = 0, invalid = null;
  session.subscribe((event) => {
    // SDK rejects unknown tools/invalid schemas before extension execute().
    // Only still-pending proposals can take this path; executed calls were
    // removed by execute() and their results belong exclusively to Python.
    if (event.type === "tool_execution_end" && proposals.has(event.toolCallId) && !finalizing) {
      const proposal = proposals.get(event.toolCallId);
      if (!event.isError || proposal.name !== event.toolName) {
        fail(new Error("Unmatched SDK tool result"));
        return;
      }
      proposals.delete(event.toolCallId);
      send({ type: "tool_rejected", id: event.toolCallId, name: proposal.name,
        arguments: proposal.arguments });
    }
    if (event.type === "message_end" && event.message.role === "assistant") {
      const message = event.message;
      for (const block of message.content) {
        if (block.type === "toolCall") {
          if (proposals.has(block.id)) throw new Error("Duplicate tool proposal");
          proposals.set(block.id, structuredClone(block));
        }
      }
      if (["error", "aborted"].includes(message.stopReason)) invalid = "Model call failed or aborted";
      if (++turns > config.maxTurns + (finalizing ? 1 : 0)) { invalid = "Turn limit exceeded"; session.abort(); }
      send({ type: "assistant", content: message.content, stopReason: message.stopReason,
        usage: { input: message.usage?.input, output: message.usage?.output } });
    }
  });
  send({ type: "ready", tools: actual, provider: model.provider, model: model.id });
  await session.prompt(config.query);
  if (invalid) throw new Error(invalid);
  await toolQueue;
  send({ type: "done" });
  session.dispose();
  process.stdin.destroy();
}
