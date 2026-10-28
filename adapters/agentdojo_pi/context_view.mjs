// Remove redundant actor planning only. Original session/audit and ALL tool
// calls, results, user text, final answers and reasoning signatures stay intact.
export function planningContextView(messages) {
  let lastAssistant = -1;
  messages.forEach((message, index) => { if (message.role === 'assistant') lastAssistant = index; });
  let removedChars = 0;
  const reduced = messages.map((message, index) => {
    if (index >= lastAssistant || message.role !== 'assistant' ||
        !Array.isArray(message.content) || !message.content.some(block => block.type === 'toolCall')) return message;
    const content = message.content.filter(block => {
      if (block.type !== 'text') return true;
      removedChars += block.text.length;
      return false;
    });
    return content.length === message.content.length ? message : { ...message, content };
  });
  if (!removedChars) return { messages, diagnostic: { planning_chars_removed: 0, original_tool_history_retained: true } };
  // Prior token usage describes the unmodified prefix and cannot measure this
  // view. Invalidate usage in copies only so the SDK runs its normal complete
  // context estimator (including system/tools and its 4096-token reserve).
  // Never raise contextWindow, override its computed cap or mutate real usage.
  const view = reduced.map(message => message.role === 'assistant' && message.usage
    ? { ...message, usage: { ...message.usage, input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0 } }
    : message);
  return { messages: view, diagnostic: { planning_chars_removed: removedChars,
    prior_usage_invalidated_for_changed_prefix: true, original_tool_history_retained: true } };
}
