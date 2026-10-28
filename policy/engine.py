"""Deterministic action policy gate.

Hard capability, path, deny, direct-taint and certificate checks precede soft
approval decisions. Missing intent never implies permission. Human approvals
are single-action grants managed by the gateway, not persistent rule updates.
"""
import re
from attestation.hashing import object_hash
from .paths import within_envelope
import time
from pathlib import Path

import yaml

from . import symbolic
from . import taint
from .parameter_constraints import check_constraints
from .business_rules import BusinessPolicy

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class PolicyEngine:
    def __init__(self, policy_dir, business_policy_path=None):
        self.policy_dir = Path(policy_dir)
        self.business_policy = BusinessPolicy(business_policy_path)
        self._cache = {}

    def _load(self, action_type: str):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", action_type):
            return None
        if action_type not in self._cache:
            path = self.policy_dir / f"{action_type}.yaml"
            if not path.exists():
                self._cache[action_type] = None
            else:
                self._cache[action_type] = yaml.safe_load(
                    path.read_text(encoding="utf-8")
                )
        return self._cache[action_type]

    # ---- declarative capability (hard BLOCK) ----
    @staticmethod
    def _check_capability(policy, capability, action, require_capability):
        if capability is None:
            if require_capability:
                return False, "no capability certificate presented"
            return True, None

        declared_actions = capability.get("actions", [])
        if action.type not in declared_actions:
            return (
                False,
                f"action '{action.type}' not in declared capabilities {declared_actions}",
            )

        for cap_name, expected in (policy.get("capability_requirements") or {}).items():
            actual = capability.get(cap_name)
            if actual != expected:
                return (
                    False,
                    f"capability '{cap_name}' is {actual!r}, requires {expected!r}",
                )
        return True, None

    # ---- declarative path envelope (now a HARD capability boundary) ----
    @staticmethod
    def _path_in_envelope(policy, capability, action):
        glob_field = (policy.get("path_globs") or {}).get("field")
        if not glob_field:
            return True, None, None
        allowed = capability.get(glob_field, []) or []
        if within_envelope(action.target, allowed):
            return True, glob_field, allowed
        return False, glob_field, allowed

    # ---- risk tier + sink detection (effect-based, NOT tool-name-based) ----
    def _risk_tier(self, policy, capability, action) -> str:
        r = (policy or {}).get("risk")
        if r in _RISK_ORDER:
            return r
        caps = capability or {}
        score = 0
        if caps.get("credential") == "allowed":
            score += 2
        if caps.get("process") == "allowed":
            score += 2
        if caps.get("persistence") == "allowed":
            score += 2
        if caps.get("network") == "allowed":
            score += 1
        if caps.get("filesystem_write"):
            score += 1
        # fallback action-type hints when the capability envelope is absent
        if action.type in ("shell", "upload", "write_file"):
            score += 1
        if score >= 4:
            return "critical"
        if score >= 3:
            return "high"
        if score >= 2:
            return "medium"
        return "low"

    @staticmethod
    def _is_sink(capability) -> bool:
        """A sink lets data LEAVE the current security domain.

        Determined by the capability EFFECT envelope. Credential ACCESS is a
        high-risk SOURCE, NOT a sink (reading a key does not exfiltrate data).
        """
        return taint.is_sink(capability)

    @staticmethod
    def _sensitive_params(policy, capability):
        """Field names that an allow rule MUST constrain (parameter-level).

        Declared by the operator, either in the per-tool policy YAML or in the
        tool's capability certificate (``sensitive_params``). Bare payload keys
        are normalized to ``"payload.<key>"``.
        """
        sp = (policy or {}).get("sensitive_params") or []
        if not sp:
            sp = (capability or {}).get("sensitive_params") or []
        return symbolic.normalize_sensitive_fields(sp)

    # ---- P4: evidence certificate verification (the trust root) ----------------
    @staticmethod
    def _verify_certificate(certificate, action, certificate_verifier=None):
        if certificate is None or certificate_verifier is None:
            return False, None, "verified evidence certificate required"
        cert = certificate if isinstance(certificate, dict) else certificate.model_dump()
        ok, why = certificate_verifier(cert)
        if not ok:
            return False, None, why
        payload = cert.get("payload") or {}
        # Reject inconsistent display/envelope fields as well as unsigned binding.
        for field in ("trust", "predicate", "action_type", "action_target", "expires_at"):
            if field not in payload or cert.get(field) != payload[field]:
                return False, None, f"unsigned or inconsistent certificate field: {field}"
        if payload["action_type"] != action.type or payload["action_target"] != action.target:
            return False, None, "certificate action binding mismatch"
        if payload.get("action_hash") != object_hash({"type": action.type, "target": action.target,
                                                       "payload": getattr(action, "payload", {}) or {}}):
            return False, None, "certificate arguments changed"
        if not isinstance(payload["expires_at"], int) or payload["expires_at"] <= int(time.time()):
            return False, None, "certificate expired"
        trust = payload["trust"]
        if trust not in ("trusted", "untrusted", "unknown", "conflict"):
            return False, None, "invalid certificate trust"
        return True, trust, "certificate verified"

    def _operator_constraints(self, action, capability):
        denial = self.business_policy.check(action)
        if denial:
            return denial
        error = check_constraints(action, (capability or {}).get("parameter_constraints", {}))
        if error:
            return {"verdict": "BLOCK", "reason": error, "rule": "capability.parameters"}

    def _boundary_context(self, action, capability, policy, effective, *, require_capability,
                          certificate, certificate_verifier, taint_state, taint_reference_fields=(), taint_flow_fields=()):
        """Shared mandatory checks. A context is not permission to execute."""
        def deny(reason, rule=None, verdict="BLOCK"):
            return {"verdict": verdict, "reason": reason, "rule": rule or policy.get("name")}, None
        ok, why = self._check_capability(policy, capability, action, require_capability)
        if not ok:
            return deny(why, "capability.declaration")
        inside, _, allowed = self._path_in_envelope(policy, capability or {}, action)
        if not inside:
            return deny(f"Path outside capability envelope: {allowed}", "capability.path")
        payload = getattr(action, "payload", None) or {}
        alias = {"read_file": "path", "write_file": "path", "shell": "command"}.get(action.type)
        if alias in payload and payload[alias] != action.target:
            return deny("Conflicting target and execution argument", "action.binding")
        fields = symbolic.action_fields(action.type, action.target, payload)
        rv, matched = symbolic.check_rules(action.type, fields, effective)
        if rv == "deny":
            return deny("Explicit deny rule matched", "symbolic.deny")
        tr = taint.classify(action, capability, taint_state,
                           reference_fields=taint_reference_fields, flow_fields=taint_flow_fields) if taint_state is not None else None
        if tr and tr[0] == "BLOCK":
            return deny(tr[1], "p5.taint")
        requires, verified = policy.get("requires", []), "unknown"
        if certificate is not None or requires:
            ok, verified, why = self._verify_certificate(certificate, action, certificate_verifier)
            if not ok:
                return deny(why, "p4.certificate")
        if requires and verified in ("unknown", "conflict"):
            return deny("Missing or conflicting visual evidence", "evidence.invalid")
        return None, {"fields": fields, "rv": rv, "matched": matched, "taint": tr,
                      "requires": requires, "verified_trust": verified}

    def check_hard(self, action, *, capability, taint_state=None, denies=None,
                   certificate=None, certificate_verifier=None, require_capability=True,
                   taint_reference_fields=(), taint_flow_fields=()):
        """PASS means eligible for a task-authority decision, never ALLOW.

        Accepts deny-only policies: no synthetic/task allow is needed or used.
        Schema normalization and capability-certificate verification remain the
        trusted caller's responsibility, as for evaluate().
        taint_reference_fields is trusted-host input only, after independent
        receipt/binding validation; never populate it from proposed arguments.
        taint_flow_fields requires verified resource receipts and a separate
        exact-call data-use authorization. PASS still never means execution.
        """
        denial = self._operator_constraints(action, capability)
        if denial:
            return denial
        if any(rule.get("decision") != "deny" for rule in (denies or [])):
            raise ValueError("Hard checks accept deny-only rules")
        effective = symbolic.validate_rules(denies or [], capability)
        policy = self._load(action.type) or {"name": "hard.default", "requires": []}
        decision, context = self._boundary_context(action, capability, policy, effective,
            require_capability=require_capability, certificate=certificate,
            certificate_verifier=certificate_verifier, taint_state=taint_state,
            taint_reference_fields=taint_reference_fields, taint_flow_fields=taint_flow_fields)
        if decision:
            return decision
        if context["taint"]:
            return {"verdict": context["taint"][0], "reason": context["taint"][1], "rule": "p5.taint"}
        if context["requires"] and context["verified_trust"] != "trusted":
            return {"verdict": "CONFIRM", "reason": "Trusted evidence required", "rule": "evidence.review"}
        if action.type == "shell" or (capability or {}).get("process") == "allowed":
            return {"verdict": "CONFIRM", "reason": "Executable effects need independently enforced bounds",
                    "rule": "execution.review"}
        return {"verdict": "PASS", "reason": "Mandatory boundaries passed; task authorization pending",
                "rule": "hard.pending_authorization"}

    def evaluate(self, action, trust: str, evidence_count: int, intent_text: str = "",
                 capability=None, require_capability=True, intent_profile=None,
                 llm_danger=None, llm_reason=None, rules=None, enable_rules=True,
                 certificate=None, certificate_verifier=None, taint_state=None, taint_reference_fields=()):
        """Evaluate every hard boundary before returning a soft approval request."""
        operator_denial = self._operator_constraints(action, capability)
        if operator_denial:
            return operator_denial
        effective = rules if rules is not None else (intent_profile or {}).get("rules", [])
        effective = symbolic.validate_rules(effective or [], capability) if enable_rules else []
        policy = self._load(action.type)
        if policy is None:
            if not effective:
                return {"verdict": "BLOCK", "reason": "No policy for action", "rule": "policy.missing"}
            policy = {"name": "symbolic.default", "requires": [], "no_evidence_verdict": "ALLOW"}
        name = policy.get("name")
        def result(verdict, reason, rule=None):
            return {"verdict": verdict, "reason": reason, "rule": rule or name}

        denial, context = self._boundary_context(action, capability, policy, effective,
            require_capability=require_capability, certificate=certificate,
            certificate_verifier=certificate_verifier, taint_state=taint_state,
            taint_reference_fields=taint_reference_fields)
        if denial:
            # Preserve the legacy public rule identifier for capability failures.
            if denial["rule"] == "capability.declaration":
                denial["rule"] = name
            return denial
        fields, rv, matched = context["fields"], context["rv"], context["matched"]
        tr, requires, verified_trust = context["taint"], context["requires"], context["verified_trust"]
        risk, sink = self._risk_tier(policy, capability, action), taint.is_sink(capability)
        if not effective:
            if sink or risk in ("high", "critical"):
                return result("BLOCK", "No trusted intent rules for sensitive action", "intent.missing")
            return result("CONFIRM", "No trusted intent rules; single-action approval required", "intent.missing")
        if rv != "allow" or not matched or matched.get("tool") != action.type:
            return result("CONFIRM", "Action outside intent; approve this action only", "symbolic.expansion")
        sensitive = self._sensitive_params(policy, capability)
        present = set(fields)
        missing = (set(sensitive) & present) - symbolic.constrained_fields(matched.get("predicate") or {})
        if missing or (sink and not sensitive):
            return {**result("CONFIRM", f"Sensitive arguments not bounded: {sorted(missing)}", "symbolic.underconstrained"),
                    "fields": sorted(missing)}
        if tr:
            return result(tr[0], tr[1], "p5.taint")
        if action.type == "shell" and llm_danger is not False:
            return result("CONFIRM", llm_reason or "Command analysis unavailable or unsafe", "shell.review")
        if requires and verified_trust != "trusted":
            return result("CONFIRM", "Visual evidence is not from a trusted collector", "evidence.review")
        return result("ALLOW", "All mandatory checks passed")
