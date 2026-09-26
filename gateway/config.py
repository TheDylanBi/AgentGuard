"""Central configuration for the ICB-Guard gateway.

Every value can be overridden with an environment variable, so the gateway
stays deterministic and reproducible across deployments. A ``.env`` file in
the project root is also loaded (existing env vars take precedence).
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


_load_dotenv(BASE_DIR / ".env")

KEYS_DIR = BASE_DIR / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "gateway_ed25519.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "gateway_ed25519.pub"

LOG_DIR = BASE_DIR / "logs"
CERTIFICATE_LOG_PATH = LOG_DIR / "certificates.jsonl"

POLICY_DIR = BASE_DIR / "policy" / "policies"

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
