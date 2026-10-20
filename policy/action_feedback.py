"""Deterministic repair advice; advice never grants execution authority."""
from attestation.hashing import object_hash

REPAIR_INSTRUCTION = """Tool results may contain safety_feedback from the execution controller.
Such a call was not executed. If retryable, correct the identified arguments using
the published tool schema and the original user's authorization, then resubmit.
Every revision is checked again. Never repeat a rejected call or switch tools to
bypass a restriction. If feedback provides authorized prerequisite calls, use
only a relevant listed lookup to obtain the missing resource before resubmitting;
the denied call has not executed and every subsequent call is checked again.
If feedback lists alternative_calls, the rejected action remains unauthorized;
use a listed read only when relevant to the original task, or explain the unmet
requirement using existing results. Without such alternatives or prerequisites,
stop when authorization is missing. Do not claim that a rejected action succeeded."""


def make_feedback(verdict, rule, fields=(), contract=None, has_allow=False):
    known = set(contract.fields) if contract else set()
    fields = sorted({"payload." + f.removeprefix("payload.") for f in fields
                     if isinstance(f, str) and f.removeprefix("payload.") in known})
    issue, retryable = "authorization_required", False
    guidance = "Stop: this action needs trusted authorization; changing arguments cannot grant it."
    if rule == "bridge.arguments":
        issue, retryable = "invalid_arguments", True
        guidance = "Use the published schema: supply required fields, correct types, and remove unknown arguments."
    elif rule in ("symbolic.expansion", "contract.intent", "behavior_alignment") and has_allow:
        issue, retryable = "outside_intent", True
        guidance = "Match the original user's authorized targets and values; remove unauthorized extras. Do not guess missing authorization."
    elif rule == "contract.value_type":
        issue, retryable = "intent_value_type", True
        guidance = "Use the authorized values with their correct JSON types, then resubmit."
    elif rule in ("symbolic.underconstrained", "contract.coverage"):
        issue = "missing_parameter_authorization"
        guidance = "Stop: the listed parameters lack trusted bounds. Explicit authorization or a trusted resource binding is required; reformatting cannot supply it."
    elif rule == "p5.taint":
        issue = "data_flow_restricted"
        guidance = "Stop: this data flow is restricted. Do not re-encode data or use another tool to bypass the restriction."
    elif rule in ("policy.missing", "intent.missing"):
        issue = "missing_authorization"
        guidance = "This tool lacks task authorization. Do not execute it; answer from existing results or explain what authorization is missing."
    elif verdict == "BLOCK":
        issue = "hard_policy_boundary"
        guidance = "Stop: a safety boundary blocks this action. No parameter revision is authorized by this feedback."
    return dict(version=1, verdict=verdict, executed=False, issue=issue, fields=fields,
                guidance=guidance, retryable=retryable)


class RepairBudget:
    def __init__(self, repairs=2, max_denials=6):
        self.repairs, self.max_denials = repairs, max_denials
        self.seen, self.issues = set(), {}
        self.dependency_seen = set()
        self.denials = 0
        self.stop_reason = None

    def before(self, tool, arguments, *, dependency_context=None):
        if (object_hash([tool, arguments]) in self.seen or
                object_hash([tool, arguments, dependency_context]) in self.dependency_seen) and not self.stop_reason:
            self.stop_reason = "repeated_rejected_call"
        return self.stop_reason

    def record(self, tool, arguments, feedback, *, dependency_context=None):
        if feedback["issue"] == "binding_prerequisite":
            self.dependency_seen.add(object_hash([tool, arguments, dependency_context]))
        else:
            self.seen.add(object_hash([tool, arguments]))
        key = object_hash([tool, feedback["issue"], feedback["fields"]])
        self.issues[key] = self.issues.get(key, 0) + 1
        self.denials += 1
        left = max(0, self.repairs + 1 - self.issues[key])
        if not self.stop_reason:
            if not feedback["retryable"]:
                self.stop_reason = feedback["issue"]
            elif not left or self.denials >= self.max_denials:
                self.stop_reason = "repair_budget_exhausted"
        return {**feedback, "repairs_remaining": 0 if self.stop_reason else left,
                "retryable": feedback["retryable"] and not bool(self.stop_reason),
                "stop_task": bool(self.stop_reason), "stop_reason": self.stop_reason}
