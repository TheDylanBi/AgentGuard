"""Parse R-Judge agent-action strings into (tool, target, payload).

R-Judge actions are free-form and heterogeneous. This module normalizes the
common formats into a uniform ``(tool, target, payload)`` triple so the
symbolic least-privilege layer can check them at the parameter level:

  - ``ToolName / Action Input: {json}``        e.g. GmailSendEmail / Action Input: {...}
  - ``ToolName Input: {json}``                 e.g. TerminalExecute Input: {...}
  - ``ToolName: {json}``                       e.g. TerminalExecute: {"command": "..."}
  - ``ToolName{py-dict or json}``              e.g. GmailReadEmail{'email_id': '...'}
  - ``{"ToolName": {args}}``                   tool name as the JSON key
  - ``` ```bash ... ``` ``` and ``bash`` fences -> shell
  - ``write_to_file: {...}`` / ``execute_python_code`` -> write_file / shell

Anything else (free text, UI strings, "Final Answer", refusals) maps to [].
"""
import ast
import json
import re
from typing import Any, Dict, List, Optional, Tuple

_TOOL_ACTION_INPUT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:/\s*)?Action\s*Input\s*:", re.I)
_TOOL_INPUT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s+Input\s*:", re.I)
_TOOL_COLON = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*", re.I)
_TOOL_BRACE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\{", re.I)
_BASH_FENCE = re.compile(r"```(?:bash|sh|shell)?\s*\n?(.*?)```", re.DOTALL)

# UI-ish verbs that are NOT domain tools; skip them (they need visual evidence).
_UI_VERBS = {"click", "open", "search", "delete", "set", "type", "press", "swipe"}


def _field(text: str, key: str) -> Optional[str]:
    m = re.search(r'["\']' + re.escape(key) + r'["\']\s*:\s*"((?:[^"\\]|\\.)*)"',
                  text, re.DOTALL)
    return m.group(1) if m else None


def _balanced_braces(s: str, start: int) -> Optional[str]:
    """Return the balanced ``{...}`` substring beginning at ``start``."""
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return s[start:i + 1]
    return None


def _parse_args(brace: str) -> Optional[Dict[str, Any]]:
    if not brace:
        return None
    try:
        d = json.loads(brace)
        if isinstance(d, dict):
            return d
    except Exception:
        pass
    try:
        d = ast.literal_eval(brace)  # single-quoted python dicts
        if isinstance(d, dict):
            return d
    except Exception:
        pass
    return None


def _norm_tool(tool: str) -> str:
    # keep a stable, readable name; lowercase snake for rule matching
    return re.sub(r"(?<!^)(?=[A-Z])", "_", tool).lower()


def _target_of(tool: str, args: Dict[str, Any]) -> str:
    """Human-readable target summary for the gateway action."""
    for k in ("to", "recipient", "email_address", "command", "path", "url",
              "filename", "item_path", "user_cloud_file_path", "payee_id",
              "destination_address", "account_number", "from_account_number"):
        if k in args:
            return str(args[k])
    if args:
        return json.dumps(args, ensure_ascii=False)[:200]
    return tool


def parse_action(raw) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Parse one agent action string -> list of (tool, target, payload)."""
    if not raw or not isinstance(raw, str):
        return []
    s = raw.strip()
    if not s:
        return []

    # 1) execute_python_code -> shell
    if "execute_python_code" in s:
        code = _field(s, "code")
        if code:
            return [("shell", code, {"command": code})]
        return []

    # 2) write_to_file -> write_file
    if re.search(r"\bwrite_to_file\s*:", s):
        fn = _field(s, "filename")
        if fn:
            return [("write_file", fn, {"filename": fn})]
        return []

    # 3) TerminalExecute -> shell
    if "TerminalExecute" in s:
        cmd = _field(s, "command")
        if cmd:
            return [("shell", cmd, {"command": cmd})]
        return []

    # 4) bash fence -> shell
    m = _BASH_FENCE.search(s)
    if m and m.group(1).strip():
        cmd = m.group(1).strip()
        return [("shell", cmd, {"command": cmd})]

    # 5) ToolName / Action Input: {...}
    m = _TOOL_ACTION_INPUT.match(s)
    if m:
        tool = _norm_tool(m.group(1))
        rest = s[m.end():]
        bi = rest.find("{")
        args = _parse_args(_balanced_braces(rest, bi)) if bi >= 0 else None
        if args is not None:
            return [(tool, _target_of(tool, args), args)]
        return []

    # 6) ToolName Input: {...}
    m = _TOOL_INPUT.match(s)
    if m:
        tool = _norm_tool(m.group(1))
        rest = s[m.end():]
        bi = rest.find("{")
        args = _parse_args(_balanced_braces(rest, bi)) if bi >= 0 else None
        if args is not None:
            return [(tool, _target_of(tool, args), args)]
        return []

    # 7) {"ToolName": {...}}
    if s.startswith("{"):
        b = _balanced_braces(s, 0)
        d = json.loads(b) if b else None
        if isinstance(d, dict) and len(d) == 1:
            tool, args = next(iter(d.items()))
            if isinstance(args, dict):
                t = _norm_tool(str(tool))
                return [(t, _target_of(t, args), args)]
        return []

    # 8) ToolName: {...}
    m = _TOOL_COLON.match(s)
    if m and m.group(1).lower() not in _UI_VERBS:
        tool = _norm_tool(m.group(1))
        rest = s[m.end():]
        bi = rest.find("{")
        args = _parse_args(_balanced_braces(rest, bi)) if bi >= 0 else None
        if args is not None:
            return [(tool, _target_of(tool, args), args)]
        return []

    # 9) ToolName{...}
    m = _TOOL_BRACE.match(s)
    if m:
        tool = _norm_tool(m.group(1))
        bi = s.find("{")
        args = _parse_args(_balanced_braces(s, bi)) if bi >= 0 else None
        if args is not None:
            return [(tool, _target_of(tool, args), args)]
        return []

    return []


def classify_unparsed(raw) -> str:
    """Coarse reason string for a non-parsed action (for reporting)."""
    if not raw or not isinstance(raw, str) or not raw.strip():
        return "empty"
    s = raw.strip()
    low = s.lower()
    if any(low.startswith(v) for v in _UI_VERBS) or "<" in s:
        return "ui"
    if re.match(r"^(final answer|the |i |your |here |this )", low):
        return "free_text"
    if "```" in s:
        return "fence"
    return "other"
