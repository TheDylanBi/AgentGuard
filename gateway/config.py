"""Central configuration for the ICB-Guard gateway.

Every value can be overridden with an environment variable, so the gateway
stays deterministic and reproducible across deployments. A ``.env`` file in
the project root is loaded only with explicit development opt-in.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path):
    """Minimal .env loader (no external deps). Does not override real env."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


DEV_MODE = os.environ.get("ICB_DEV_MODE", "0") == "1"
if DEV_MODE and os.environ.get("ICB_LOAD_DOTENV", "0") == "1":
    _load_dotenv(BASE_DIR / ".env")

STATE_DIR = Path(os.environ.get("ICB_STATE_DIR", str(Path.home() / ".icb-guard"))).resolve()
KEYS_DIR = STATE_DIR / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "gateway_ed25519.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "gateway_ed25519.pub"

LOG_DIR = STATE_DIR / "logs"
CERTIFICATE_LOG_PATH = LOG_DIR / "certificates.jsonl"

POLICY_DIR = BASE_DIR / "policy" / "policies"
_business_policy_file = os.environ.get("ICB_BUSINESS_POLICY_FILE")
BUSINESS_POLICY_PATH = Path(_business_policy_file).resolve() if _business_policy_file else None

GATEWAY_HOST = os.environ.get("ICB_HOST", "127.0.0.1")
GATEWAY_PORT = int(os.environ.get("ICB_PORT", "8099"))

# Fusion thresholds (containment-based agreement)
OVERLAP_THRESHOLD = float(os.environ.get("ICB_OVERLAP_THRESHOLD", "0.5"))

# P4: require a capability certificate for every authorization (fail-closed)
REQUIRE_CAPABILITY = os.environ.get("ICB_REQUIRE_CAPABILITY", "1") == "1"
# P4: CONFIRM token lifetime in seconds
CONFIRM_TTL = int(os.environ.get("ICB_CONFIRM_TTL", "300"))
TEXT_MATCH_THRESHOLD = float(os.environ.get("ICB_TEXT_MATCH", "0.7"))
CONFIDENCE_THRESHOLD = float(os.environ.get("ICB_CONF", "0.5"))

# Progent-style symbolic least-privilege rules (borrowed, adapted).
# When enabled and a session's intent profile carries symbolic rules, every
# tool call is checked against them (deny->BLOCK, outside->CONFIRM+expansion).
ENABLE_RULES = os.environ.get("ICB_ENABLE_RULES", "1") == "1"

# P4: evidence certificate freshness window (seconds).
EVIDENCE_TTL = int(os.environ.get("ICB_EVIDENCE_TTL", "300"))

# Dedicated credentials for each trusted control-plane role.
def _credential(role):
    value = os.environ.get(f"ICB_{role}_TOKEN", "")
    filename = os.environ.get(f"ICB_{role}_TOKEN_FILE", "")
    if filename:
        path = Path(filename).resolve()
        if not DEV_MODE and path.is_relative_to(BASE_DIR):
            raise RuntimeError("Credential files must be outside the agent workspace")
        value = path.read_text(encoding="utf-8").strip()
    return value


EXECUTOR_TOKEN = _credential("EXECUTOR")
ADMIN_TOKEN = _credential("ADMIN")
INTENT_TOKEN = _credential("INTENT")
APPROVER_TOKEN = _credential("APPROVER")
# Deliberately no fallback to the old all-powerful shared token.
GATEWAY_TOKEN = EXECUTOR_TOKEN
CDP_ENDPOINTS = frozenset(x.strip() for x in os.environ.get("ICB_CDP_ENDPOINTS", "").split(",") if x.strip())
EXECUTION_TTL = 30
# Production always uses server-owned primitives. Development may opt in too.
CONTROLLED_EXECUTION = os.environ.get("ICB_CONTROLLED_EXECUTION", "0") == "1"


def controlled_execution_enabled():
    return not DEV_MODE or CONTROLLED_EXECUTION


def executor_protected_paths():
    paths = [BASE_DIR, STATE_DIR]
    if BUSINESS_POLICY_PATH is not None:
        paths.append(BUSINESS_POLICY_PATH)
    paths.extend(Path(os.environ[key]).resolve() for key in (
        "ICB_EXECUTOR_TOKEN_FILE", "ICB_ADMIN_TOKEN_FILE", "ICB_INTENT_TOKEN_FILE",
        "ICB_APPROVER_TOKEN_FILE") if os.environ.get(key))
    return paths


def validate_security_config():
    if DEV_MODE:
        return
    tokens = [EXECUTOR_TOKEN, ADMIN_TOKEN, INTENT_TOKEN, APPROVER_TOKEN]
    if any(len(t) < 32 for t in tokens) or len(set(tokens)) != len(tokens):
        raise RuntimeError("Configure four distinct ICB_*_TOKEN credentials (at least 32 characters)")
    if STATE_DIR.is_relative_to(BASE_DIR):
        raise RuntimeError("ICB_STATE_DIR must be outside the agent workspace")
    if BUSINESS_POLICY_PATH is not None and BUSINESS_POLICY_PATH.is_relative_to(BASE_DIR):
        raise RuntimeError("Production business policy must be outside the agent workspace")
    if not PRIVATE_KEY_PATH.is_file():
        raise RuntimeError("Provision a new private key in ICB_STATE_DIR; repository keys are not accepted")
    if not REQUIRE_CAPABILITY or not ENABLE_RULES:
        raise RuntimeError("Production requires capability and intent policy checks")
    if os.environ.get("ICB_MOCK_GROUNDING", "0") == "1":
        raise RuntimeError("Mock evidence is prohibited in production")
