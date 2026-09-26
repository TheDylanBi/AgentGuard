"""Deterministic policy engine — semantic authorization, no keyword blacklists.

The independent LLM *proposes* (intent profile, action-intent consistency,
command danger); the gate *enforces* deterministically. Nothing is matched by
keyword.

Hard boundary vs soft signal (the core invariant):
  - BLOCK  = declarative CAPABILITY violation (the tool never declared this
             action type / effect / resource / path) or an explicit DENY rule
             or an unauthorized SINK (data egress) / high-risk expansion.
  - CONFIRM = the action is OUTSIDE the current least-privilege policy
             (an expansion the human may approve), or an LLM soft signal
             (consistency / danger / allowed_actions / roles).
  - ALLOW  = a SPECIFIC, parameter-constrained symbolic allow rule matched and
             every declarative + semantic check passed.

Order:
  1.  Capability (declarative, hard)     — undeclared type/effect -> BLOCK
  1.5 Symbolic least-privilege rules     — deny->BLOCK; no/broad rule->CONFIRM
                                            (BLOCK if sink/high-risk);
                                            specific allow must constrain
                                            sensitive params -> else CONFIRM/BLOCK
  2.  Intent consistency (LLM, soft)     — inconsistent -> CONFIRM
  3.  Command danger (LLM, soft)         — dangerous shell -> CONFIRM
  4.  Intent allowed_actions (LLM, soft) — not allowed -> CONFIRM
  4.5 Intent forbidden_targets (LLM)     — matched -> CONFIRM
  5.  Path envelope (declarative, hard)  — outside -> BLOCK (capability)
  6.  Element roles (LLM, soft)          — not allowed -> CONFIRM
  7.  Evidence trust                     — per-policy (certificate in P4)
"""
import fnmatch
import time
from pathlib import Path

import yaml

from . import symbolic
from . import taint

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class PolicyEngine:
    def __init__(self, policy_dir):
        self.policy_dir = Path(policy_dir)
        self._cache = {}

    def _load(self, action_type: str):
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
        if not allowed:
            return True, glob_field, allowed
        if any(fnmatch.fnmatch(action.target, g) for g in allowed):
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
        caps = capability or {}
        # explicit fine-grained effect fields take precedence
        if "network_egress" in caps or "external_share" in caps:
            return caps.get("network_egress") == "allowed" or caps.get("external_share") == "allowed"
        # legacy fallback: network allowed => egress (sink); persistence => sink;
        # credential allowed => NOT a sink (source)
        return caps.get("network") == "allowed" or caps.get("persistence") == "allowed"

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
        """Verify an Evidence Certificate; return ``(ok, trust, reason)``.

        The engine never trusts a caller-provided ``trust`` string when a
        certificate is present. Trust is the RESULT of verification:
          1. signature      -> the certificate really came from a trusted verifier
          2. verifier       -> (handled by the injected ``certificate_verifier``)
          3. predicate/scope-> the certificate proves THIS target, not another
          4. binding        -> the certificate is bound to THIS action/args
          5. freshness      -> an expired certificate is rejected
        """
        if certificate is None:
            return True, None, "no certificate presented"
        cert = certificate if isinstance(certificate, dict) else (
            certificate.model_dump() if hasattr(certificate, "model_dump") else {}
        )

        # 1+2. signature + verifier-in-registry (the caller injects this, since
        #       it owns the signer + the trusted verifier registry)
        if certificate_verifier is not None:
            ok, why = certificate_verifier(cert)
            if not ok:
                return False, None, why

        # 3. scope/binding: the certificate must prove exactly this action+target
        bound_type = cert.get("action_type")
        if bound_type and bound_type != action.type:
            return False, None, (
                f"certificate bound to action '{bound_type}', not '{action.type}'"
            )
        bound_target = cert.get("action_target")
        if bound_target and bound_target != action.target:
            return False, None, (
                f"certificate proves target '{bound_target}', not '{action.target}'"
            )

        # 4. freshness
        expires_at = cert.get("expires_at")
        if expires_at is not None and int(expires_at) < int(time.time()):
            return False, None, "certificate expired"

        # 5. the verified trust is read from the certificate, not the caller
        trust = cert.get("trust", "unknown")
        if trust not in ("trusted", "untrusted", "unknown", "conflict"):
            return False, None, f"invalid trust value '{trust}'"
        return True, trust, "certificate verified"

    def evaluate(
        self,
        action,
        trust: str,
        evidence_count: int,
        intent_text: str = "",
        capability=None,
        require_capability: bool = True,
        roles=None,
        intent_profile=None,
        consistency=None,
        consistency_reason=None,
        llm_danger=None,
        llm_reason=None,
        rules=None,
        enable_rules: bool = True,
        certificate=None,
        certificate_verifier=None,
        taint_state=None,
    ) -> dict:
        effective_rules = rules if rules is not None else (
            (intent_profile or {}).get("rules") if isinstance(intent_profile, dict) else None
        )

        policy = self._load(action.type)
        if policy is None:
            if enable_rules and effective_rules:
                # A tool with no dedicated YAML is governed ONLY by symbolic
                # rules. ``no_evidence_verdict`` is reached only after a
                # SPECIFIC, parameter-covered allow rule (see step 1.5); any
                # other path returns early. So this is NOT a default-allow.
                policy = {
                    "name": "symbolic.default",
                    "requires": [],
                    "no_evidence_verdict": "ALLOW",
                    "capability_requirements": {},
                    "path_globs": {},
                    "fallback": {},
                }
            else:
                return {
                    "verdict": "BLOCK",
                    "reason": f"no policy defined for action type '{action.type}'",
                    "rule": None,
                }

        risk = self._risk_tier(policy, capability, action)
        sink = self._is_sink(capability)

        # 1. Declarative capability (hard BLOCK only here)
        ok, why = self._check_capability(policy, capability, action, require_capability)
        if not ok:
            return {"verdict": "BLOCK", "reason": why, "rule": policy.get("name")}

        # 1.5 Symbolic least-privilege rules (parameter level).
        if enable_rules and effective_rules:
            fields = symbolic.action_fields(
                action.type, action.target, getattr(action, "payload", None) or {}
            )
            rv, matched = symbolic.check_rules(action.type, fields, effective_rules)

            if rv == "deny":
                return {
                    "verdict": "BLOCK",
                    "reason": "违反最小权限策略：" + (matched.get("reason") or "deny 规则命中"),
                    "rule": "symbolic.deny",
                    "matched_rule": matched,
                }

            # A SPECIFIC allow (tool == action.type) is a real authorization.
            # A wildcard allow (tool == "*") is broad -> treat as "outside".
            specific = matched is not None and matched.get("tool") == action.type

            if rv == "outside" or not specific:
                # Not specifically authorized: no rule, or only a broad rule.
                # P1: LLM-inferred policy gap -> CONFIRM (never BLOCK), even for
                # sink/high-risk. Item-7 feedback loop: attach a GENERALIZED rule
                # (sensitive pinned, non-sensitive relaxed).
                sensitive = self._sensitive_params(policy, capability)
                update_rule = symbolic.make_generalized_rule(
                    action.type, fields, sensitive_fields=sensitive, decision="allow"
                )
                classification = symbolic.classify_update(update_rule, effective_rules)
                risk_note = ""
                if sink or risk in ("high", "critical"):
                    risk_note = f"（{'数据出口(sink)' if sink else f'{risk} 风险'}，需谨慎审批）"
                return {
                    "verdict": "CONFIRM",
                    "reason": "动作超出当前最小权限策略（扩张），需人工批准" + risk_note,
                    "rule": "symbolic.expansion",
                    "policy_update": {
                        "rule": update_rule,
                        "classification": classification,
                        "request_id": "",
                    },
                }

            # Specific allow matched -> enforce parameter-level constraint (P3).
            sensitive = self._sensitive_params(policy, capability)
            if sensitive:
                # P1-2: only check sensitive params the action ACTUALLY provides;
                # an absent param (e.g. no cc/bcc set) is not a "missing" constraint.
                payload_keys = {f"payload.{k}" for k in (getattr(action, "payload", None) or {})}
                sensitive_present = [s for s in sensitive
                                     if s in payload_keys or s == "target"]
                covered = symbolic.predicate_fields(matched.get("predicate") or {})
                # P3 robustness: "target" is an alias for url/path/command — the
                # parser stores the primary subject in target for these tools, and
                # the intent LLM may reference "target" instead of "payload.<key>".
                if "target" in covered:
                    covered = covered | {"payload.url", "payload.path", "payload.command"}
                missing = [s for s in sensitive_present if s not in covered]
                if missing:
                    if sink:
                        return {
                            "verdict": "CONFIRM",
                            "reason": (
                                f"数据出口(sink)动作 '{action.type}' 的敏感参数 {missing} "
                                "未被最小权限规则约束，需人工确认"
                            ),
                            "rule": "symbolic.sink.underconstrained",
                        }
                    return {
                        "verdict": "CONFIRM",
                        "reason": f"动作的敏感参数 {missing} 未被最小权限规则约束，需人工批准",
                        "rule": "symbolic.underconstrained",
                    }
            elif sink:
                # Sink tools must declare sensitive params; without them the
                # engine cannot verify parameter-level authorization.
                return {
                    "verdict": "CONFIRM",
                    "reason": (
                        f"数据出口(sink)动作 '{action.type}' 未声明敏感参数，"
                        "无法验证参数级授权，需人工确认"
                    ),
                    "rule": "symbolic.sink.nosensitive",
                }

        # 2. Semantic action-intent consistency (LLM) -> CONFIRM, never BLOCK
        if consistency is False:
            return {
                "verdict": "CONFIRM",
                "reason": f"动作与用户意图不一致：{consistency_reason or '无具体原因'}",
                "rule": policy.get("name"),
            }

        # 3. Semantic command danger (LLM) -> CONFIRM with the concrete harm
        if action.type == "shell" and llm_danger:
            return {
                "verdict": "CONFIRM",
                "reason": f"该命令存在风险：{llm_reason or '未知危险'}",
                "rule": policy.get("name"),
            }

        # 4. Intent allowed_actions (LLM-generated) -> CONFIRM
        if intent_profile:
            allowed_actions = [
                a.lower() for a in (intent_profile.get("allowed_actions") or [])
            ]
            if allowed_actions and action.type.lower() not in allowed_actions:
                return {
                    "verdict": "CONFIRM",
                    "reason": (
                        f"动作类型 '{action.type}' 超出用户意图的范围 "
                        f"（允许：{allowed_actions}）"
                    ),
                    "rule": policy.get("name"),
                }

        # 4.5 Intent forbidden_targets (LLM-generated) -> CONFIRM
        if intent_profile:
            forbidden = intent_profile.get("forbidden_targets") or []
            if forbidden and any(fnmatch.fnmatch(action.target, g) for g in forbidden):
                return {
                    "verdict": "CONFIRM",
                    "reason": f"目标 '{action.target}' 命中用户意图的禁止目标 {forbidden}",
                    "rule": policy.get("name"),
                }

        # 5. Declarative path envelope -> BLOCK (capability is a hard boundary)
        if capability is not None:
            in_env, glob_field, allowed = self._path_in_envelope(policy, capability, action)
            if not in_env:
                return {
                    "verdict": "BLOCK",
                    "reason": (
                        f"目标 '{action.target}' 超出工具声明的能力范围 {allowed}"
                        "（能力违规，不是审批项）"
                    ),
                    "rule": policy.get("name"),
                }

        # 5.5 Lightweight taint (P5): high-risk SOURCE -> SINK flow.
        # Level 1 deterministic (direct reference) -> BLOCK;
        # Level 2 derived (TAINT_UNKNOWN) -> CONFIRM. Never an LLM judgment.
        if taint_state is not None:
            tr = taint.classify(action, capability, taint_state)
            if tr is not None:
                tverdict, treason = tr
                return {"verdict": tverdict, "reason": treason, "rule": "p5.taint"}

        # 6. Element roles (LLM-generated allowed_roles) -> CONFIRM
        if intent_profile and roles:
            allowed_roles = [
                r.lower() for r in (intent_profile.get("allowed_roles") or [])
            ]
            if allowed_roles and not any(r in allowed_roles for r in roles):
                return {
                    "verdict": "CONFIRM",
                    "reason": (
                        f"元素角色 {roles} 超出用户意图允许的角色 {allowed_roles}"
                    ),
                    "rule": policy.get("name"),
                }

        # 7. Evidence trust — P4: verify the certificate, not the trust string.
        verified_trust = trust
        if certificate is not None:
            ok, vtrust, why = self._verify_certificate(certificate, action, certificate_verifier)
            if not ok:
                return {"verdict": "BLOCK", "reason": why, "rule": "p4.certificate"}
            verified_trust = vtrust if vtrust is not None else trust

        requires = policy.get("requires", [])
        if not requires:
            verdict = policy.get("no_evidence_verdict", "ALLOW")
            reason = "能力、参数级最小权限、语义一致性与意图检查均通过"
            # P1: NO least-privilege rules (intent LLM failed, or rules disabled)
            # -> fail-closed. A YAML's ``no_evidence_verdict: ALLOW`` must NOT
            # become a silent allow when there is no intent-derived policy.
            # sink/high-risk -> BLOCK; low/medium -> CONFIRM. (Tools that
            # REQUIRE evidence go through the ``requires`` branch below and are
            # unaffected — their ALLOW is gated by a verified certificate.)
            if enable_rules and not effective_rules and verdict == "ALLOW":
                if sink or risk in ("high", "critical"):
                    verdict = "BLOCK"
                    reason = (
                        "无最小权限规则（意图解析失败），且是 "
                        f"{'数据出口(sink)' if sink else f'{risk} 风险'} 操作，拒绝"
                    )
                else:
                    verdict = "CONFIRM"
                    reason = "无最小权限规则（意图解析失败），需人工批准"
            return {
                "verdict": verdict,
                "reason": reason,
                "rule": policy.get("name"),
            }

        for req in requires:
            min_trust = req.get("min_trust", "trusted")
            if verified_trust != min_trust:
                fallback = policy.get("fallback", {})
                verdict = fallback.get(verified_trust, "CONFIRM")
                reason = (
                    f"action '{action.type}' requires predicate "
                    f"'{req.get('predicate')}' with trust>={min_trust}, "
                    f"but evidence trust is '{verified_trust}' "
                    f"({evidence_count} evidence item(s))"
                )
                return {"verdict": verdict, "reason": reason, "rule": policy.get("name")}

        return {
            "verdict": "ALLOW",
            "reason": "all required predicates satisfied",
            "rule": policy.get("name"),
        }
