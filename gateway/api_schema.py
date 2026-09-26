"""The portability contract.

This module is the single source of truth for the wire format. Every agent
framework only needs to translate its native tool call into an
``AuthorizeRequest`` and read the ``AuthorizeResponse`` verdict.
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IntentAnchor(BaseModel):
    """User intent, anchored at session start and immune to visual content."""

    text: str
    signer: str = "session-bound"


class ToolRef(BaseModel):
    tool_id: str
    capability_cert_id: Optional[str] = None


class Action(BaseModel):
    type: str  # click | type | upload | shell | ...
    target: str  # human-readable target description
    payload: Dict[str, Any] = Field(default_factory=dict)


class A11yNode(BaseModel):
    """One node of a region-annotated accessibility snapshot."""

    role: str = ""
    name: str = ""
    value: str = ""
    region: Optional[List[int]] = None  # [x1, y1, x2, y2]
    confidence: Optional[float] = None


class VisualState(BaseModel):
    # attached      -> gateway pulls evidence itself via cdp_endpoint (P1)
    # screenshot     -> agent sends the pixels
    # a11y_snapshot  -> agent sends a structured accessibility snapshot
    # Screenshot and a11y_snapshot may be combined; attached mode may
    # additionally fill both from a live browser.
    mode: str = "screenshot"
    screenshot_b64: Optional[str] = None
    cdp_endpoint: Optional[str] = None
    a11y_snapshot: Optional[List[A11yNode]] = None
    # P2 cross-time consistency: a second capture at t-Δt.
    previous_screenshot_b64: Optional[str] = None
    previous_a11y_snapshot: Optional[List[A11yNode]] = None


class IntentProfile(BaseModel):
    """Structured intent envelope produced once at session start (方案 C).

    Signed by the gateway; deterministic rules check every action against it.
    Empty lists mean "no restriction from intent" for that dimension.
    """

    intent_text: str
    allowed_actions: List[str] = Field(default_factory=list)   # hard
    allowed_paths: List[str] = Field(default_factory=list)      # soft (-> CONFIRM)
    forbidden_targets: List[str] = Field(default_factory=list)  # hard (-> BLOCK)
    allowed_roles: List[str] = Field(default_factory=list)      # hard
    # Progent-style symbolic least-privilege rules over (tool, arguments).
    # Empty list => the symbolic check is skipped (legacy behaviour).
    rules: List["PolicyRule"] = Field(default_factory=list)
    signature: Optional[str] = None


class RulePredicate(BaseModel):
    """A symbolic predicate over action fields (Progent-style least privilege).

    ``op`` is one of: true | and | or | not | eq | ne | le | ge | in | not_in |
    glob | contains. ``field`` refers to ``"type"``, ``"target"``, or
    ``"payload.<key>"``.
    """

    op: str = "true"
    field: Optional[str] = None
    value: Optional[Any] = None
    args: List["RulePredicate"] = Field(default_factory=list)


class PolicyRule(BaseModel):
    """One symbolic least-privilege rule: a decision over (tool, arguments)."""

    tool: str = "*"
    decision: str = "allow"  # allow | deny
    predicate: RulePredicate = Field(default_factory=RulePredicate)
    reason: str = ""


class PolicyUpdate(BaseModel):
    """A proposed policy change, SMT-classified as narrowing or expansion.

    ``narrowing`` auto-applies; ``expansion`` requires explicit approval via
    ``/confirm``. Ties to the concrete tool call via ``request_id``.
    """

    rule: PolicyRule
    classification: str = "expansion"  # narrowing | expansion
    request_id: str = ""


class AnchorIntentRequest(BaseModel):
    session_id: str
    prompt: str


class AnchorIntentResponse(BaseModel):
    profile: IntentProfile


class AuthorizeRequest(BaseModel):
    session_id: str
    intent_anchor: IntentAnchor
    tool: ToolRef
    action: Action
    visual_state: VisualState
    # Optional signed IntentProfile (方案 C). When present it replaces the
    # keyword-based intent matching; when absent the engine falls back.
    intent_profile: Optional["IntentProfile"] = None


class CapabilityDeclaration(BaseModel):
    """The tool's declared Effect Envelope (P4)."""

    actions: List[str] = Field(default_factory=list)  # click | type | upload | read_file | shell | ...
    filesystem_read: List[str] = Field(default_factory=list)  # path globs
    filesystem_write: List[str] = Field(default_factory=list)
    network: str = "denied"  # denied | allowed (legacy coarse)
    credential: str = "denied"
    process: str = "denied"
    persistence: str = "denied"
    # Progent-style P3: field names an allow rule MUST constrain (parameter-level
    # least privilege). Declared by the OPERATOR (not the tool publisher).
    sensitive_params: List[str] = Field(default_factory=list)
    # P4 explicit Effect / Source model (finer than the legacy flags above).
    # A SINK is "data leaves the security domain": network egress, external
    # share, or persistence. Credential access is a high-risk SOURCE, NOT a sink.
    network_egress: str = "denied"    # denied | allowed -> data leaves via network
    external_share: str = "denied"    # denied | allowed -> send/post/upload/forward
    credential_access: str = "denied"  # denied | allowed -> reads credentials (source)
    sources: List[str] = Field(default_factory=list)  # credential | private_file | PII | financial


class ToolRegistrationRequest(BaseModel):
    tool_id: str
    label: str = ""
    declared_capabilities: CapabilityDeclaration
    implementation_version: str = "0.0.0"
    implementation_hash: Optional[str] = None


class CapabilityCertificate(BaseModel):
    capability_cert_id: str
    tool_id: str
    label: str
    declared_capabilities: CapabilityDeclaration
    implementation_version: str
    implementation_hash: Optional[str] = None
    re_registered: bool = False  # same tool_id re-registered with a different hash (P6)
    previous_hash: Optional[str] = None
    issued_at: int
    signature: str


class ConfirmRequest(BaseModel):
    token: str
    approve: bool


class EvidenceSource(BaseModel):
    type: str  # ocr | grounding | a11y_tree | dom | ...
    verifier: str  # e.g. "rapidocr-1.3.8"
    confidence: float


class Certificate(BaseModel):
    id: Optional[str] = None  # content hash of the certificate payload (P3)
    predicate: str
    sources: List[EvidenceSource] = Field(default_factory=list)
    region: Optional[List[int]] = None  # [x1, y1, x2, y2]
    trust: str  # trusted | untrusted | unknown | conflict
    stability: Optional[str] = None  # stable | unstable | n/a (P2)
    consensus_count: int = 0  # number of agreeing sources (P2)
    downgraded: bool = False  # trust downgraded due to transient evidence (P2)
    roles: List[str] = Field(default_factory=list)  # element roles from structured evidence (P6)
    crop_hash: Optional[str] = None
    signature: Optional[str] = None
    timestamp: int
    # P4 trust root: what this certificate is bound to + freshness. The engine
    # verifies these (not caller-provided trust strings).
    action_type: Optional[str] = None   # the action type this cert authorizes
    action_target: Optional[str] = None  # the exact target this cert proves
    expires_at: Optional[int] = None     # freshness deadline (unix seconds)
    payload: Optional[Dict[str, Any]] = None  # the exact signed payload (for re-verification)


class AuthorizeResponse(BaseModel):
    verdict: str  # ALLOW | CONFIRM | BLOCK
    certificates: List[Certificate] = Field(default_factory=list)
    reason: str
    decision_rule: Optional[str] = None
    confirm_token: Optional[str] = None  # present when verdict == CONFIRM (P4)
    # Progent-style least-privilege: present when the action is OUTSIDE the
    # current symbolic policy (an expansion requiring approval).
    policy_update: Optional[PolicyUpdate] = None
    # P4 TOCTOU binding: hash over the exact authorized action. The executor
    # must re-hash the action it runs and compare against this id.
    decision_id: Optional[str] = None
