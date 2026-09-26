"""ICB-Guard Gateway P3.

Pipeline:
  visual context (current + optional previous capture, optionally attached)
  -> verifiers (a11y_tree [structured] + OCR/Tesseract/grounding [perceptual])
  -> cross-source fusion (structured-first, containment-aware)
  -> cross-time consistency (stable / unstable / n/a)
  -> deterministic evidence payload (reproducible)
  -> sign certificate (id = content hash), append to hash-chained log
  -> deterministic policy gate (intent anchor + evidence trust)
  -> verdict
"""
import base64
import io
import os
import time

from fastapi import FastAPI
from PIL import Image

from attestation.hashing import crop_hash, object_hash
from attestation.log import CertificateLog
from attestation.signer import Signer
from attestation.verifier_registry import VerifierRegistry
from fusion.consensus import fuse, region_overlap
from gateway.api_schema import (
    AnchorIntentRequest,
    AnchorIntentResponse,
    AuthorizeRequest,
    AuthorizeResponse,
    CapabilityCertificate,
    Certificate,
    ConfirmRequest,
    EvidenceSource,
    IntentProfile,
    PolicyRule,
    PolicyUpdate,
    ToolRegistrationRequest,
)
from gateway.config import (
    CERTIFICATE_LOG_PATH,
    CONFIDENCE_THRESHOLD,
    CONFIRM_TTL,
    ENABLE_RULES,
    EVIDENCE_TTL,
    OVERLAP_THRESHOLD,
    POLICY_DIR,
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_PATH,
    REQUIRE_CAPABILITY,
    TEXT_MATCH_THRESHOLD,
)
from policy.capability_registry import CapabilityRegistry
from policy.engine import PolicyEngine
from policy.intent_anchor import (
    analyze_action_intent_consistency,
    analyze_command_danger,
    anchor_effect_llm,
    anchor_intent,
    intent_llm_configured,
)
from policy import symbolic
from policy import taint
from policy.authorize import authorize_action
from verifiers.a11y_tree import A11yTreeVerifier
from verifiers.base import Evidence, VisualContext
from verifiers.grounding import GroundingVerifier
from verifiers.ocr import OCRVerifier
from verifiers.tesseract import TesseractVerifier

app = FastAPI(title="ICB-Guard Gateway", version="0.4.0")

ocr_verifier = OCRVerifier(
    text_match_threshold=TEXT_MATCH_THRESHOLD,
    conf_threshold=CONFIDENCE_THRESHOLD,
)
tesseract_verifier = TesseractVerifier()
grounding_verifier = GroundingVerifier()
a11y_verifier = A11yTreeVerifier()

signer = Signer(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
policy_engine = PolicyEngine(POLICY_DIR)
capability_registry = CapabilityRegistry(signer)
registry = VerifierRegistry({
    "ocr": ocr_verifier,
    "tesseract": tesseract_verifier,
    "grounding": grounding_verifier,
    "a11y_tree": a11y_verifier,
})
log = CertificateLog(CERTIFICATE_LOG_PATH)

# Offline demo shim: when neither GroundingDINO nor Tesseract is available,
# ICB_MOCK_GROUNDING=1 simulates an independent perceptual source at the OCR
# region. With P1's structured source and P2's cross-model OCR this is no
# longer required, but remains useful for screenshot-only tests.
USE_MOCK_GROUNDING = os.environ.get("ICB_MOCK_GROUNDING", "0") == "1"

# Minimum containment between current and previous regions for "stable".
STABILITY_OVERLAP = 0.3

# P4: pending human confirmations (token -> payload)
PENDING_CONFIRMS = {}

# Progent-style runtime policy evolution: session_id -> latest intent profile
# (server-owned; /anchor_intent seeds it, approved expansions update it).
SESSION_POLICIES = {}

# Per-session epoch, bumped on every /anchor_intent. Pending confirm tokens
# carry the epoch they were issued under; a token from an earlier turn is
# stale and must NOT apply to the re-anchored (revoked) policy. This is the
# multi-turn intent-inflation guard: old permissions die on new user input.
SESSION_EPOCHS = {}

# P5 lightweight taint state, keyed by session: which high-risk objects have
# been READ this turn. Reset on every re-anchor (data flow is turn-scoped).
SESSION_TAINT = {}

# P6 behavior-alignment intent-effect profiles, keyed by session. Reset on
# every re-anchor (intent is turn-scoped).
SESSION_EFFECTS = {}

# Item-7 escalation budget (minimal): per-session CONFIRM counter. When the
# counter exceeds the threshold, low-risk CONFIRMs auto-downgrade to ALLOW
# (audited) so human attention is reserved for high-risk actions.
SESSION_CONFIRM_BUDGET = {}
CONFIRM_BUDGET_THRESHOLD = int(os.environ.get("ICB_CONFIRM_BUDGET", "10"))


def _reset_session_policy(session_id: str, profile_dict: dict) -> None:
    """Revoke-on-new-input + item-8 incremental anchoring.

    Security boundary (kept): the INTENT-DERIVED LLM rules are REPLACED every
    turn, so old permissions cannot be abused by a later turn's injection.

    Item-8 (added): FEEDBACK-LOOP rules (item 7's learned approvals/denials,
    tagged ``reason = "feedback loop ..."``) SURVIVE across turns, so the user
    is not re-asked for the same class of operation. Taint also persists (a
    high-risk read keeps affecting later sinks until session end).
    """
    SESSION_EPOCHS[session_id] = SESSION_EPOCHS.get(session_id, 0) + 1
    old = SESSION_POLICIES.get(session_id, {})
    fb_rules = [r for r in (old.get("rules") or [])
                if str(r.get("reason", "")).startswith("feedback loop")]
    profile_dict["rules"] = list(profile_dict.get("rules") or []) + fb_rules
    SESSION_POLICIES[session_id] = profile_dict
    # taint persists across turns (item 8); effects + budget stay turn-scoped
    SESSION_EFFECTS.pop(session_id, None)
    SESSION_CONFIRM_BUDGET.pop(session_id, None)


def _apply_policy_update(session_id: str, update: dict) -> bool:
    """Merge an approved expansion rule into the session's symbolic policy."""
    st = SESSION_POLICIES.get(session_id)
    new_rule = (update or {}).get("rule")
    if st is None or not isinstance(new_rule, dict):
        return False
    st["rules"] = symbolic.apply_update(st.get("rules", []), new_rule)
    return True


def _issue_confirm_token(session_id: str, certificate_id: str, policy_update=None) -> str:
    payload = {
        "session_id": session_id,
        "certificate_id": certificate_id,
        "expires_at": int(time.time()) + CONFIRM_TTL,
        "policy_update": policy_update,
        "epoch": SESSION_EPOCHS.get(session_id, 0),
    }
    token = signer.sign(payload)
    PENDING_CONFIRMS[token] = payload
    return token


def _verify_evidence_certificate(cert: dict):
    """P4 trust root: the certificate must be signed by the gateway's own key.

    The signed payload includes the evidence SOURCES (verifiers), so a valid
    signature proves the evidence came from the gateway's registered verifiers
    — not from a caller-provided ``trust="trusted"`` string.
    """
    payload = cert.get("payload")
    sig = cert.get("signature")
    if payload is None or sig is None:
        return False, "certificate missing payload/signature"
    if not signer.verify(payload, sig):
        return False, "certificate signature invalid"
    return True, "certificate verified"


def _decision_id(action, capability_cert_id, certificate_id, session_id, intent_text):
    """P4 TOCTOU binding: a decision hash over the exact authorized action.

    The executor must re-hash the action it is about to run and compare it to
    this id; a mismatch means the action changed after authorization (TOCTOU).
    """
    payload = {
        "action_type": action.type,
        "action_target": action.target,
        "action_payload": action.payload,
        "capability_cert_id": capability_cert_id,
        "certificate_id": certificate_id,
        "session_id": session_id,
        "intent_text": intent_text,
    }
    return "decision:" + object_hash(payload)


def _decode_image(b64: str):
    if not b64:
        return None
    raw = base64.b64decode(b64)
    return Image.open(io.BytesIO(raw)).convert("RGB")


def _playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


def context_from_visual_state(vs: dict) -> VisualContext:
    """Build a VisualContext from a plain-dict visual_state (used both by the
    API path and by the reproduction tool, so results stay reproducible)."""
    image = _decode_image(vs.get("screenshot_b64"))
    snapshot = vs.get("a11y_snapshot") or None
    prev_image = _decode_image(vs.get("previous_screenshot_b64"))
    prev_snapshot = vs.get("previous_a11y_snapshot") or None
    cdp = vs.get("cdp_endpoint")

    if vs.get("mode") == "attached" and cdp:
        from browser.capture import capture_attached

        cap_image, cap_snapshot = capture_attached(cdp)
        image = image or cap_image
        snapshot = snapshot or cap_snapshot

    return VisualContext(
        image=image,
        a11y_snapshot=snapshot,
        cdp_endpoint=cdp,
        previous_image=prev_image,
        previous_a11y_snapshot=prev_snapshot,
    )


def _mock_grounding_evidence(target: str, ocr_evidences):
    # NOT real evidence. Demo scaffolding only.
    out = []
    for e in ocr_evidences:
        out.append(Evidence(
            source="grounding",
            verifier="mock-grounding-0.0.1",
            predicate="UI_ELEMENT",
            value=target,
            region=e.region,
            confidence=0.95,
        ))
    return out


def _run_verifiers(ctx: VisualContext, target: str):
    evidences = []
    # 1. Structured source (highest trust tier) — no heavy deps.
    evidences.extend(a11y_verifier.verify(ctx, target))

    # 2. Perceptual sources (pixels).
    if ctx.image is not None:
        evidences.extend(ocr_verifier.verify(ctx, target))
        if tesseract_verifier.available():
            evidences.extend(tesseract_verifier.verify(ctx, target))
        if grounding_verifier.available():
            evidences.extend(grounding_verifier.verify(ctx, target))
        elif USE_MOCK_GROUNDING:
            ocr_only = [e for e in evidences if e.source == "ocr"]
            evidences.extend(_mock_grounding_evidence(target, ocr_only))
    return evidences


def _compute_stability(cur_fused: dict, prev_fused) -> str:
    """stable / unstable / n/a based on the previous (t-Δt) capture."""
    if prev_fused is None:
        return "n/a"
    if cur_fused["trust"] in ("unknown", "conflict"):
        return "n/a"
    if prev_fused["trust"] == "unknown":
        # target present now but absent in the previous frame -> transient
        return "unstable"
    if cur_fused["region"] and prev_fused["region"]:
        if region_overlap(cur_fused["region"], prev_fused["region"]) >= STABILITY_OVERLAP:
            return "stable"
        return "unstable"  # element moved/drifted between frames
    return "stable"


def compute_evidence_payload(ctx: VisualContext, target: str) -> dict:
    """Deterministic, reproducible evidence payload (P3).

    Everything here must be a pure function of (visual state, target,
    verifier versions) so the reproduction tool can recompute it exactly.
    """
    evidences = _run_verifiers(ctx, target)
    fused = fuse(evidences, overlap_threshold=OVERLAP_THRESHOLD)

    has_previous = ctx.previous_image is not None or ctx.previous_a11y_snapshot is not None
    prev_fused = None
    if has_previous:
        prev_ctx = VisualContext(
            image=ctx.previous_image,
            a11y_snapshot=ctx.previous_a11y_snapshot,
        )
        prev_fused = fuse(
            _run_verifiers(prev_ctx, target), overlap_threshold=OVERLAP_THRESHOLD
        )

    stability = _compute_stability(fused, prev_fused)

    trust = fused["trust"]
    downgraded = False
    if stability == "unstable" and trust == "trusted":
        trust = "untrusted"
        downgraded = True

    region = fused["region"]
    sources = [e.to_source_dict() for e in fused["matched"]]
    # P6: element roles from the structured source (e.g. button vs link)
    roles = sorted({
        e.value.split(":", 1)[0]
        for e in fused["matched"]
        if e.source == "a11y_tree" and ":" in e.value
    })
    return {
        "predicate": f"UI_ELEMENT(target={target!r})",
        "sources": sources,
        "region": region,
        "trust": trust,
        "stability": stability,
        "consensus_count": len(fused["matched"]),
        "downgraded": downgraded,
        "roles": roles,
        "crop_hash": crop_hash(ctx.image, region) if (ctx.image is not None and region) else None,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "ocr": ocr_verifier.available(),
        "tesseract": tesseract_verifier.available(),
        "grounding": grounding_verifier.available(),
        "a11y_tree": a11y_verifier.available(),
        "playwright": _playwright_available(),
        "intent_llm": intent_llm_configured(),
        "mock_grounding": USE_MOCK_GROUNDING,
        "log_chain": log.verify_chain(),
    }


@app.get("/certificates")
def list_certificates():
    return {"ids": log.ids(), "chain": log.verify_chain()}


@app.get("/certificates/{certificate_id}")
def get_certificate(certificate_id: str):
    entry = log.get(certificate_id)
    return entry if entry is not None else {"error": "not found", "id": certificate_id}


@app.post("/register_tool", response_model=CapabilityCertificate)
def register_tool(req: ToolRegistrationRequest):
    return capability_registry.register(req)


@app.post("/anchor_intent", response_model=AnchorIntentResponse)
def anchor_intent_endpoint(req: AnchorIntentRequest):
    """Parse the user's prompt into a signed IntentProfile (方案 C)."""
    profile_dict = anchor_intent(req.prompt)
    profile = IntentProfile(intent_text=req.prompt, **profile_dict)
    payload = profile.model_dump(exclude={"signature"})
    profile.signature = signer.sign(payload)
    # Revoke-on-new-input: REPLACE the session policy and bump the epoch, so
    # prior rules + prior approved expansions + prior pending confirm tokens
    # all die on this new user input (multi-turn intent-inflation guard).
    _reset_session_policy(req.session_id, profile.model_dump())
    # P6: generate the intent-EFFECT profile (trajectory-free) for Behavior
    # Alignment. Failure is non-fatal: behavior alignment simply degrades to
    # the P0-P5 engine alone.
    try:
        SESSION_EFFECTS[req.session_id] = anchor_effect_llm(req.prompt)
    except Exception:
        SESSION_EFFECTS[req.session_id] = None
    return AnchorIntentResponse(profile=profile)


@app.get("/browser_state")
def browser_state(cdp: str = "http://localhost:9222"):
    """Return the live page's title + interactive a11y elements (no screenshot)."""
    try:
        from browser.capture import capture_a11y
        return capture_a11y(cdp)
    except Exception as e:
        return {"title": "", "elements": [], "error": str(e)}


@app.post("/confirm")
def confirm(req: ConfirmRequest):
    payload = PENDING_CONFIRMS.get(req.token)
    if payload is None:
        return {"status": "invalid", "reason": "unknown or used token"}
    if payload["expires_at"] < int(time.time()):
        PENDING_CONFIRMS.pop(req.token, None)
        return {"status": "expired"}

    session_id = payload["session_id"]
    # Stale-token guard: a new /anchor_intent bumps the epoch, revoking the
    # policy this approval belongs to. Never apply an old turn's approval to
    # the new turn's policy.
    stale = payload.get("epoch", -1) != SESSION_EPOCHS.get(session_id, 0)
    if stale:
        PENDING_CONFIRMS.pop(req.token, None)
        return {"status": "stale", "reason": "policy was re-anchored; this approval no longer applies"}

    if not req.approve:
        # Item-7 feedback loop (rejection): generalize into a NARROWING deny
        # rule (same pinned sensitive params, decision flipped), SMT-verified,
        # so the same class of action is not asked again.
        pu = payload.get("policy_update")
        if pu and pu.get("rule"):
            deny_rule = dict(pu["rule"])
            deny_rule["decision"] = "deny"
            deny_rule["reason"] = "feedback loop: rejected -> narrowing deny"
            current = SESSION_POLICIES.get(session_id, {}).get("rules", [])
            if symbolic.classify_update(deny_rule, current) == "narrowing":
                _apply_policy_update(session_id, {"rule": deny_rule, "classification": "narrowing"})
        PENDING_CONFIRMS.pop(req.token, None)
        return {"status": "denied", "learned": "deny_rule"}

    # Approval: apply the generalized expansion rule (item-7 feedback loop).
    if payload.get("policy_update"):
        _apply_policy_update(session_id, payload["policy_update"])
    ticket = signer.sign({"approved": payload, "at": int(time.time())})
    PENDING_CONFIRMS.pop(req.token, None)
    return {"status": "approved", "ticket": ticket}


@app.post("/authorize", response_model=AuthorizeResponse)
def authorize(req: AuthorizeRequest):
    vs = req.visual_state.model_dump()
    ctx = context_from_visual_state(vs)
    target = req.action.target

    evidence = compute_evidence_payload(ctx, target)

    cert_payload = {**evidence, "timestamp": int(time.time())}
    signature = signer.sign(cert_payload)
    certificate_id = object_hash(cert_payload)

    certificate = Certificate(
        id=certificate_id,
        predicate=evidence["predicate"],
        sources=[EvidenceSource(**s) for s in evidence["sources"]],
        region=evidence["region"],
        trust=evidence["trust"],
        stability=evidence["stability"],
        consensus_count=evidence["consensus_count"],
        downgraded=evidence["downgraded"],
        roles=evidence.get("roles", []),
        crop_hash=evidence["crop_hash"],
        signature=signature,
        timestamp=cert_payload["timestamp"],
        # P4 trust root: bind the certificate to the exact action it proves.
        action_type=req.action.type,
        action_target=target,
        expires_at=int(time.time()) + EVIDENCE_TTL,
        payload=cert_payload,
    )

    # P4: capability check (action must stay inside the declared envelope)
    capability = None
    re_registered = False
    capability_cert_id = req.tool.capability_cert_id
    if capability_cert_id:
        cert = capability_registry.get(capability_cert_id)
        if cert and cert["tool_id"] == req.tool.tool_id:
            capability = cert["declared_capabilities"]
            re_registered = cert.get("re_registered", False)

    # 方案 C: verify the signed intent profile (if provided). The server-side
    # evolving policy is authoritative (Progent-style): approved expansions
    # live there and must NOT be clobbered by a client re-passing its stale
    # signed profile. The client profile only seeds the session policy once.
    client_profile = None
    if req.intent_profile is not None:
        payload = req.intent_profile.model_dump(exclude={"signature"})
        if req.intent_profile.signature and signer.sign(payload) == req.intent_profile.signature:
            client_profile = req.intent_profile.model_dump()

    if client_profile is not None and req.session_id not in SESSION_POLICIES:
        SESSION_POLICIES[req.session_id] = client_profile

    intent_profile = SESSION_POLICIES.get(req.session_id, client_profile)

    # Semantic command danger (P pillar): independent LLM proposes, gate enforces.
    llm_danger = None
    llm_reason = None
    if req.action.type == "shell":
        danger = analyze_command_danger(req.action.target)
        if danger:
            llm_danger = danger.get("dangerous")
            llm_reason = danger.get("reason")

    # Semantic action-intent consistency (I pillar): LLM judges, gate enforces.
    consistency = None
    consistency_reason = None
    if intent_llm_configured():
        c = analyze_action_intent_consistency(
            req.intent_anchor.text, req.action.type, req.action.target
        )
        if c:
            consistency = c.get("consistent")
            consistency_reason = c.get("reason")

    st = SESSION_TAINT.get(req.session_id)
    taint_state = (
        {"tainted_objects": list(st["tainted_objects"]), "dirty": st["dirty"]}
        if st else None
    )
    effect_profile = SESSION_EFFECTS.get(req.session_id)

    # Unified decision: Behavior Alignment (P6) -> P0-P5 engine.
    decision = authorize_action(
        req.action,
        capability=capability,
        engine=policy_engine,
        effect_profile=effect_profile,
        taint_state=taint_state,
        trust=evidence["trust"],
        evidence_count=evidence["consensus_count"],
        intent_text=req.intent_anchor.text,
        intent_profile=intent_profile,
        certificate=certificate,
        certificate_verifier=_verify_evidence_certificate,
        consistency=consistency,
        consistency_reason=consistency_reason,
        llm_danger=llm_danger,
        llm_reason=llm_reason,
        roles=evidence.get("roles", []),
        enable_rules=ENABLE_RULES,
        require_capability=REQUIRE_CAPABILITY,
    )

    # P5: record a high-risk SOURCE read once it is actually authorized, so a
    # later SINK in the same turn can be checked for taint flow.
    if decision["verdict"] == "ALLOW" and taint.is_source(capability):
        st = SESSION_TAINT.setdefault(req.session_id, {"tainted_objects": [], "dirty": False})
        src = (capability or {}).get("sources", [])
        taint.record_source_read(st, target, source=src)

    # P6: a re-registered tool (implementation hash changed) requires
    # re-verification, even if capability + intent + evidence all pass.
    if decision["verdict"] == "ALLOW" and re_registered:
        decision = {
            "verdict": "CONFIRM",
            "reason": "tool implementation changed (re-registered); re-verification required",
            "rule": "capability.re-registration",
        }

    confirm_token = None
    policy_update = None
    if decision.get("policy_update"):
        pu = decision["policy_update"]
        policy_update = PolicyUpdate(
            rule=PolicyRule(**pu["rule"]),
            classification=pu.get("classification", "expansion"),
            request_id=certificate_id,
        )
    if decision["verdict"] == "CONFIRM":
        # Item-7 escalation budget (minimal): over threshold, low-risk CONFIRMs
        # auto-downgrade to ALLOW (audited); high-risk (sink/taint) stays.
        budget = SESSION_CONFIRM_BUDGET.setdefault(req.session_id, {"count": 0})
        budget["count"] += 1
        high_risk = taint.is_sink(capability) or decision.get("rule") == "p5.taint"
        if budget["count"] > CONFIRM_BUDGET_THRESHOLD and not high_risk:
            decision = {
                "verdict": "ALLOW",
                "reason": "升级预算已用尽，低风险动作自动放行（审计）: " + decision["reason"],
                "rule": "escalation.budget.allow",
            }
        else:
            confirm_token = _issue_confirm_token(
                req.session_id,
                certificate_id,
                policy_update=policy_update.model_dump() if policy_update else None,
            )

    # Append to the tamper-evident log (includes request + verifier snapshot
    # so the certificate can be reproduced later).
    log.append({
        "id": certificate_id,
        "timestamp": cert_payload["timestamp"],
        "verdict": decision["verdict"],
        "reason": decision["reason"],
        "capability_cert_id": capability_cert_id,
        "request": {"target": target, "visual_state": vs},
        "verifiers": registry.snapshot(),
        "evidence": evidence,
        "signature": signature,
    })

    reason = decision["reason"]
    if evidence["downgraded"]:
        reason = "cross-time: evidence is transient (absent at t-Δt); trust downgraded; " + reason

    decision_id = _decision_id(
        req.action, capability_cert_id, certificate_id, req.session_id, req.intent_anchor.text
    )

    return AuthorizeResponse(
        verdict=decision["verdict"],
        certificates=[certificate],
        reason=reason,
        decision_rule=decision["rule"],
        confirm_token=confirm_token,
        policy_update=policy_update,
        decision_id=decision_id,
    )
