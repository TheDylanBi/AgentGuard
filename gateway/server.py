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
import secrets
import threading
from functools import wraps
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
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
    ConsumeRequest,
    EvidenceSource,
    IntentProfile,
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
from gateway import config
from gateway.security import require_executor, require_admin, require_intent, require_approver
from policy.capability_registry import CapabilityRegistry
from policy.engine import PolicyEngine
from policy.intent_anchor import (
    analyze_command_danger,
    anchor_effect_llm,
    anchor_intent,
    intent_llm_configured,
)
from policy import taint
from policy.authorize import authorize_action
from policy.action_feedback import make_feedback
from execution.files import BoundFile, ResourceRejected, validate_action as validate_execution_action
from verifiers.a11y_tree import A11yTreeVerifier
from verifiers.base import Evidence, VisualContext
from verifiers.grounding import GroundingVerifier
from verifiers.ocr import OCRVerifier
from verifiers.tesseract import TesseractVerifier

@asynccontextmanager
async def lifespan(app):
    config.validate_security_config()
    yield


app = FastAPI(title="ICB-Guard Gateway", version="0.5.0", lifespan=lifespan)
STATE_LOCK = threading.RLock()


def serialized(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        with STATE_LOCK:
            return fn(*args, **kwargs)
    return wrapper


ocr_verifier = OCRVerifier(
    text_match_threshold=TEXT_MATCH_THRESHOLD,
    conf_threshold=CONFIDENCE_THRESHOLD,
)
tesseract_verifier = TesseractVerifier()
grounding_verifier = GroundingVerifier()
a11y_verifier = A11yTreeVerifier()

signer = Signer(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH, allow_create=config.DEV_MODE)
policy_engine = PolicyEngine(POLICY_DIR, business_policy_path=config.BUSINESS_POLICY_PATH)
capability_registry = CapabilityRegistry(signer)
registry = VerifierRegistry({
    "ocr": ocr_verifier,
    "tesseract": tesseract_verifier,
    "grounding": grounding_verifier,
    "a11y_tree": a11y_verifier,
})
log = CertificateLog(CERTIFICATE_LOG_PATH, signer=signer)

# Offline demo shim: when neither GroundingDINO nor Tesseract is available,
# ICB_MOCK_GROUNDING=1 simulates an independent perceptual source at the OCR
# region. With P1's structured source and P2's cross-model OCR this is no
# longer required, but remains useful for screenshot-only tests.
USE_MOCK_GROUNDING = os.environ.get("ICB_MOCK_GROUNDING", "0") == "1"

# Minimum containment between current and previous regions for "stable".
STABILITY_OVERLAP = 0.3

# P4: pending human confirmations (token -> payload)
PENDING_CONFIRMS = {}
APPROVAL_TICKETS = {}
EXECUTION_TICKETS = {}

# Progent-style runtime policy evolution: session_id -> latest intent profile
# (server-owned; only the trusted intent endpoint replaces it).
SESSION_POLICIES = {}

# Per-session epoch, bumped on every /anchor_intent. Pending confirm tokens
# carry the epoch they were issued under; a token from an earlier turn is
# stale and must NOT apply to the re-anchored (revoked) policy. This is the
# multi-turn intent-inflation guard: old permissions die on new user input.
SESSION_EPOCHS = {}

# P5 lightweight taint state, keyed by session: which high-risk objects have
# been read this session. Retained across user turns until session closure.
SESSION_TAINT = {}

# P6 behavior-alignment intent-effect profiles, keyed by session. Reset on
# every re-anchor (intent is turn-scoped).
SESSION_EFFECTS = {}

# Approval flooding pauses the session; it never relaxes authorization.
SESSION_CONFIRM_BUDGET = {}
CONFIRM_BUDGET_THRESHOLD = int(os.environ.get("ICB_CONFIRM_BUDGET", "10"))


def _reset_session_policy(session_id: str, profile_dict: dict) -> None:
    """Replace turn permissions; taint survives until explicit session closure."""
    SESSION_EPOCHS[session_id] = SESSION_EPOCHS.get(session_id, 0) + 1
    SESSION_POLICIES[session_id] = profile_dict
    # taint persists across turns (item 8); effects + budget stay turn-scoped
    SESSION_EFFECTS.pop(session_id, None)
    SESSION_CONFIRM_BUDGET.pop(session_id, None)


def _binding(req):
    return object_hash({"session_id": req.session_id, "tool": req.tool.model_dump(),
                        "action": req.action.model_dump()})


def _context_version(session_id):
    return object_hash({"business_policy": policy_engine.business_policy.fingerprint,
                        "policy": SESSION_POLICIES.get(session_id),
                        "taint": SESSION_TAINT.get(session_id),
                        "effects": SESSION_EFFECTS.get(session_id)})


def _cleanup_tickets():
    now = time.time()
    for mapping in (PENDING_CONFIRMS, APPROVAL_TICKETS, EXECUTION_TICKETS):
        for token in list(mapping):
            if mapping[token]["expires_at"] <= now:
                mapping.pop(token, None)
        if len(mapping) >= 10000:
            raise HTTPException(429, "Too many pending requests")


def _issue_confirm_token(req, resource_binding=None):
    _cleanup_tickets()
    token = secrets.token_urlsafe(32)
    PENDING_CONFIRMS[token] = {"session_id": req.session_id, "binding": _binding(req),
        "request": req.model_dump(), "resource_binding": resource_binding,
        "epoch": SESSION_EPOCHS.get(req.session_id, 0),
        "context_version": _context_version(req.session_id),
        "expires_at": time.time() + CONFIRM_TTL}
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
    """Audit identifier; execution authority is the one-time server-owned ticket."""
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

    if vs.get("mode") == "attached":
        if not cdp or cdp not in config.CDP_ENDPOINTS:
            raise HTTPException(403, "Unregistered browser endpoint")
        from browser.capture import capture_attached

        cap_image, cap_snapshot = capture_attached(cdp)
        image = cap_image
        snapshot = cap_snapshot
        prev_image = None
        prev_snapshot = None

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
        "execution_mode": "controlled" if config.controlled_execution_enabled() else "trusted-client",
        "ocr": ocr_verifier.available(),
        "tesseract": tesseract_verifier.available(),
        "grounding": grounding_verifier.available(),
        "a11y_tree": a11y_verifier.available(),
        "playwright": _playwright_available(),
        "intent_llm": intent_llm_configured(),
        "mock_grounding": USE_MOCK_GROUNDING,
        "log_chain": log.verify_chain(),
    }


@app.get("/certificates", dependencies=[Depends(require_admin)])
def list_certificates():
    return {"ids": log.ids(), "chain": log.verify_chain()}


@app.get("/certificates/{certificate_id}", dependencies=[Depends(require_admin)])
def get_certificate(certificate_id: str):
    entry = log.get(certificate_id)
    return entry if entry is not None else {"error": "not found", "id": certificate_id}


@app.post("/register_tool", response_model=CapabilityCertificate, dependencies=[Depends(require_admin)])
@serialized
def register_tool(req: ToolRegistrationRequest):
    try:
        return capability_registry.register(req)
    except (OSError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc


@app.delete("/tools/{tool_id}", dependencies=[Depends(require_admin)])
@serialized
def revoke_tool(tool_id: str):
    capability_registry._by_tool.pop(tool_id, None)
    return {"status": "revoked"}


@app.delete("/sessions/{session_id}", dependencies=[Depends(require_intent)])
@serialized
def close_session(session_id: str):
    for mapping in (PENDING_CONFIRMS, APPROVAL_TICKETS, EXECUTION_TICKETS):
        for token in list(mapping):
            if mapping[token]["session_id"] == session_id:
                mapping.pop(token, None)
    for mapping in (SESSION_POLICIES, SESSION_EFFECTS, SESSION_TAINT, SESSION_EPOCHS, SESSION_CONFIRM_BUDGET):
        mapping.pop(session_id, None)
    return {"status": "closed"}


@app.post("/anchor_intent", response_model=AnchorIntentResponse, dependencies=[Depends(require_intent)])
@serialized
def anchor_intent_endpoint(req: AnchorIntentRequest):
    """Parse the user's prompt into a signed IntentProfile (方案 C)."""
    if req.session_id not in SESSION_POLICIES and len(SESSION_POLICIES) >= 1000:
        raise HTTPException(429, "Session limit reached")
    # Revoke first, including when the intent service fails.
    _reset_session_policy(req.session_id, {"intent_text": req.prompt, "rules": []})
    profile_dict = anchor_intent(req.prompt)
    profile = IntentProfile(intent_text=req.prompt, **profile_dict)
    payload = profile.model_dump(exclude={"signature"})
    profile.signature = signer.sign(payload)
    # Revoke-on-new-input: REPLACE the session policy and bump the epoch, so
    # prior rules + prior approved expansions + prior pending confirm tokens
    # all die on this new user input (multi-turn intent-inflation guard).
    SESSION_POLICIES[req.session_id] = profile.model_dump()
    # P6: generate the intent-EFFECT profile (trajectory-free) for Behavior
    # Alignment. Failure is non-fatal: behavior alignment simply degrades to
    # the P0-P5 engine alone.
    try:
        SESSION_EFFECTS[req.session_id] = anchor_effect_llm(req.prompt)
    except Exception:
        SESSION_EFFECTS[req.session_id] = None
    return AnchorIntentResponse(profile=profile)


@app.get("/browser_state", dependencies=[Depends(require_executor)])
def browser_state(cdp: str = "http://localhost:9222"):
    """Return the live page's title + interactive a11y elements (no screenshot)."""
    if cdp not in config.CDP_ENDPOINTS:
        raise HTTPException(403, "Unregistered browser endpoint")
    try:
        from browser.capture import capture_a11y
        return capture_a11y(cdp)
    except Exception as e:
        return {"title": "", "elements": [], "error": str(e)}


@app.post("/confirm", dependencies=[Depends(require_approver)])
@serialized
def confirm(req: ConfirmRequest):
    payload = PENDING_CONFIRMS.pop(req.token, None)
    if payload is None:
        return {"status": "invalid"}
    if payload["expires_at"] <= time.time():
        return {"status": "expired"}
    if payload["epoch"] != SESSION_EPOCHS.get(payload["session_id"], 0):
        return {"status": "stale"}
    if payload["context_version"] != _context_version(payload["session_id"]):
        return {"status": "stale"}
    log.append({"id": "approval:" + secrets.token_hex(16), "event": "approval",
                "approved": req.approve, "binding": payload["binding"],
                "session_id": payload["session_id"], "epoch": payload["epoch"],
                "timestamp": int(time.time())})
    if not req.approve:
        return {"status": "denied"}
    _cleanup_tickets()
    ticket = secrets.token_urlsafe(32)
    APPROVAL_TICKETS[ticket] = payload
    return {"status": "approved", "ticket": ticket, "scope": "single_action"}


@app.post("/consume", dependencies=[Depends(require_executor)])
@serialized
def consume(req: ConsumeRequest):
    if config.controlled_execution_enabled():
        raise HTTPException(403, "Client-side execution is disabled; use /execute")
    return _consume(req, controlled=False)


@app.post("/execute", dependencies=[Depends(require_executor)])
@serialized
def execute(req: ConsumeRequest):
    if not config.controlled_execution_enabled():
        raise HTTPException(403, "Controlled execution is not enabled")
    return _consume(req, controlled=True)


def _consume(req, controlled):
    entry = EXECUTION_TICKETS.pop(req.ticket, None)
    if (not entry or entry["expires_at"] <= time.time()
            or entry["epoch"] != SESSION_EPOCHS.get(req.session_id, 0)
            or entry["context_version"] != _context_version(req.session_id)
            or entry["binding"] != _binding(req)
            or entry.get("execution_mode", "trusted-client") != ("controlled" if controlled else "trusted-client")):
        raise HTTPException(403, "Invalid, expired, revoked or already consumed execution ticket")
    if not controlled:
        return _check_consumption(req, entry)
    # Acquire pinned handles before the final policy check; no mutation yet.
    try:
        bound = BoundFile(req.action, config.executor_protected_paths())
    except (OSError, ValueError) as exc:
        raise HTTPException(409, "Cannot bind controlled file resource") from exc
    with bound:
        if bound.binding != entry.get("resource_binding"):
            raise HTTPException(409, "File identity or content changed; authorize again")
        result = _check_consumption(req, entry)
        execution_id = "controlled:" + secrets.token_hex(16)
        metadata = {"session_id": req.session_id, "binding": entry["binding"],
                    "resource_hash": object_hash(bound.binding), "execution_id": execution_id}
        log.append({**metadata, "id": execution_id + ":started", "event": "execution_started",
                    "timestamp": int(time.time())})
        try:
            output = bound.run()
        except Exception as exc:
            log.append({**metadata, "id": execution_id + ":failed", "event": "execution_failed",
                        "timestamp": int(time.time()), "error_type": type(exc).__name__})
            raise HTTPException(500, "Execution failed; effects may be partial; ticket cannot be retried") from exc
        log.append({**metadata, "id": execution_id + ":completed", "event": "execution_completed",
                    "timestamp": int(time.time())})
        return {"status": "executed", "decision_id": result["decision_id"], "output": output}


def _check_consumption(req, entry):
    original = AuthorizeRequest(**entry["request"])
    # Re-evaluate hard boundaries, current capability, taint and live evidence.
    result = _authorize(original, approved=entry["approved"], issue=False)
    if result.verdict != "ALLOW":
        raise HTTPException(403, "Authorization changed before execution")
    evidence = result.certificates[0].payload
    if object_hash({k: evidence.get(k) for k in ("trust", "crop_hash", "region", "roles", "sources")}) != entry["evidence_hash"]:
        raise HTTPException(403, "Visual state changed before execution")
    cert = capability_registry.verify(req.tool.capability_cert_id)
    capability = cert["declared_capabilities"] if cert else None
    # Conservatively taint before execution: a failed read can over-taint but
    # a completed/partially completed read must never be missed.
    if taint.is_source(capability):
        st = SESSION_TAINT.setdefault(req.session_id, {"tainted_objects": [], "dirty": False})
        taint.record_source_read(st, req.action.target, source=capability.get("sources", []))
    log.append({"id": "execution:" + secrets.token_hex(16), "event": "execution_consumed",
                "session_id": req.session_id, "binding": entry["binding"], "timestamp": int(time.time())})
    return {"status": "consumed", "decision_id": result.decision_id}


@app.post("/authorize", response_model=AuthorizeResponse, dependencies=[Depends(require_executor)])
@serialized
def authorize(req: AuthorizeRequest):
    return _authorize(req)


def _authorize(req: AuthorizeRequest, approved=False, issue=True):
    if req.session_id not in SESSION_POLICIES:
        raise HTTPException(403, "Intent must be anchored by the trusted user channel")
    if issue:
        _cleanup_tickets()
    grant = None
    if req.approval_ticket and issue:
        grant = APPROVAL_TICKETS.pop(req.approval_ticket, None)
        if (not grant or grant["expires_at"] <= time.time()
                or grant["epoch"] != SESSION_EPOCHS.get(req.session_id, 0)
                or grant["context_version"] != _context_version(req.session_id)
                or grant["binding"] != _binding(req)):
            raise HTTPException(403, "Approval does not cover this action")
        approved = True
    controlled = config.controlled_execution_enabled()
    if controlled:
        try:
            validate_execution_action(req.action)
        except ResourceRejected as exc:
            return AuthorizeResponse(verdict="BLOCK", reason=str(exc),
                                     decision_rule="executor.unsupported", execution_mode="controlled")
    # A host shell has no enforceable effect envelope. Production disables it;
    # use a separately sandboxed executor before enabling process capabilities.
    if req.action.type == "shell" and not config.DEV_MODE:
        return AuthorizeResponse(verdict="BLOCK", reason="Host shell execution is disabled in production",
                                 decision_rule="executor.sandbox.required")
    vs = req.visual_state.model_dump()
    ctx = context_from_visual_state(vs)
    target = req.action.target

    evidence = compute_evidence_payload(ctx, target)

    if vs.get("mode") != "attached" and evidence["trust"] == "trusted":
        evidence["trust"] = "untrusted"  # caller-origin evidence cannot establish provenance
    cert_payload = {**evidence, "timestamp": int(time.time()),
        "action_type": req.action.type, "action_target": target,
        "action_hash": object_hash(req.action.model_dump()),
        "session_id": req.session_id, "epoch": SESSION_EPOCHS.get(req.session_id, 0),
        "expires_at": int(time.time()) + EVIDENCE_TTL}
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
        expires_at=cert_payload["expires_at"],
        payload=cert_payload,
    )

    # P4: capability check (action must stay inside the declared envelope)
    capability = None
    re_registered = False
    capability_cert_id = req.tool.capability_cert_id
    if capability_cert_id:
        cert = capability_registry.verify(capability_cert_id)  # signed & trusted (change 4)
        if cert and cert["tool_id"] == req.tool.tool_id:
            capability = cert["declared_capabilities"]
            re_registered = cert.get("re_registered", False)

    intent_profile = SESSION_POLICIES[req.session_id]
    if capability and capability.get("effect_type") == "arbitrary_process_execution" and not config.DEV_MODE:
        return AuthorizeResponse(verdict="BLOCK", reason="Host process execution is disabled in production",
                                 decision_rule="executor.sandbox.required")

    # Semantic command danger (P pillar): independent LLM proposes, gate enforces.
    llm_danger = None
    llm_reason = None
    if req.action.type == "shell":
        danger = analyze_command_danger(req.action.target)
        if danger:
            llm_danger = danger.get("dangerous")
            llm_reason = danger.get("reason")

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
        intent_text=intent_profile.get("intent_text", ""),
        intent_profile=intent_profile,
        certificate=certificate,
        certificate_verifier=_verify_evidence_certificate,
        llm_danger=llm_danger,
        llm_reason=llm_reason,
        enable_rules=ENABLE_RULES,
        require_capability=REQUIRE_CAPABILITY,
    )

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
    resource_binding = None
    if controlled and issue and decision["verdict"] != "BLOCK":
        try:
            with BoundFile(req.action, config.executor_protected_paths()) as bound:
                resource_binding = bound.binding
            if grant is not None and resource_binding != grant.get("resource_binding"):
                raise ResourceRejected("Resource changed after approval")
        except (OSError, ValueError):
            decision = {"verdict": "BLOCK", "reason": "File resource unavailable, unsupported or changed after approval",
                        "rule": "executor.resource"}
    if approved and decision["verdict"] == "CONFIRM":
        decision = {"verdict": "ALLOW", "reason": "Explicit single-action approval; hard checks passed",
                    "rule": "approval.single_action"}
    if decision["verdict"] == "CONFIRM" and issue:
        budget = SESSION_CONFIRM_BUDGET.setdefault(req.session_id, {"count": 0})
        budget["count"] += 1
        if budget["count"] > CONFIRM_BUDGET_THRESHOLD:
            decision = {"verdict": "BLOCK", "reason": "Confirmation budget exhausted",
                        "rule": "escalation.budget.exhausted"}
        else:
            confirm_token = _issue_confirm_token(req, resource_binding)

    # Keep decision metadata, not raw screenshots, request bodies or credentials.
    log.append({
        "id": certificate_id,
        "timestamp": cert_payload["timestamp"],
        "verdict": decision["verdict"],
        "decision_rule": decision["rule"],
        "business_policy_hash": policy_engine.business_policy.fingerprint,
        "execution_mode": "controlled" if controlled else "trusted-client",
        "resource_hash": object_hash(resource_binding) if resource_binding is not None else None,
        "capability_cert_id": capability_cert_id,
        "session_id": req.session_id,
        "action_hash": object_hash(req.action.model_dump()),
        "request_hash": object_hash(req.model_dump(exclude={"approval_ticket"})),
        "verifiers": registry.snapshot(),
        "evidence": {k: v for k, v in evidence.items() if k != "predicate"},
        "signature": signature,
    })

    reason = decision["reason"]
    if evidence["downgraded"]:
        reason = "cross-time: evidence is transient (absent at t-Δt); trust downgraded; " + reason

    decision_id = _decision_id(
        req.action, capability_cert_id, certificate_id, req.session_id, req.intent_anchor.text
    )

    execution_ticket = None
    if decision["verdict"] == "ALLOW" and issue:
        execution_ticket = secrets.token_urlsafe(32)
        EXECUTION_TICKETS[execution_ticket] = {"session_id": req.session_id, "binding": _binding(req),
            "execution_mode": "controlled" if controlled else "trusted-client",
            "resource_binding": resource_binding,
            "epoch": SESSION_EPOCHS.get(req.session_id, 0), "approved": approved,
            "context_version": _context_version(req.session_id),
            "expires_at": time.time() + config.EXECUTION_TTL,
            "request": req.model_dump(exclude={"approval_ticket"}),
            "evidence_hash": object_hash({k: evidence.get(k) for k in ("trust", "crop_hash", "region", "roles", "sources")})}
    return AuthorizeResponse(
        execution_mode="controlled" if controlled else "trusted-client",
        safety_feedback=(None if decision["verdict"] == "ALLOW" else make_feedback(
            decision["verdict"], decision["rule"], has_allow=any(
                r.get("tool") == req.action.type and r.get("decision") == "allow"
                for r in intent_profile.get("rules", [])))),
        execution_ticket=execution_ticket,
        verdict=decision["verdict"],
        certificates=[certificate],
        reason=reason,
        decision_rule=decision["rule"],
        confirm_token=confirm_token,
        policy_update=policy_update,
        decision_id=decision_id,
    )
