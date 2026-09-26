"""Reproduce a certificate from the append-only log (P3).

Given a certificate id, re-runs the current verifiers on the exact stored
visual state and compares the deterministic evidence. Reports REPRODUCED
or MISMATCH (the latter usually means a verifier/model changed).

Usage:
  python -m attestation.reproduce <certificate_id>
"""
import sys

from attestation.log import CertificateLog
from gateway.config import CERTIFICATE_LOG_PATH


def reproduce(certificate_id: str) -> dict:
    log = CertificateLog(CERTIFICATE_LOG_PATH)
    entry = log.get(certificate_id)
    if entry is None:
        return {"status": "NOT_FOUND", "id": certificate_id}

    # Imported lazily to avoid a heavy import when only inspecting the log.
    from gateway.server import compute_evidence_payload, context_from_visual_state

    vs = entry["request"]["visual_state"]
    target = entry["request"]["target"]
    ctx = context_from_visual_state(vs)
    evidence = compute_evidence_payload(ctx, target)

    stored = entry["evidence"]
    if evidence == stored:
        return {
            "status": "REPRODUCED",
            "id": certificate_id,
            "trust": evidence["trust"],
            "stability": evidence["stability"],
            "consensus_count": evidence["consensus_count"],
        }

    diffs = [k for k in stored if stored.get(k) != evidence.get(k)]
    diffs += [k for k in evidence if k not in stored]
    return {
        "status": "MISMATCH",
        "id": certificate_id,
        "diff_keys": sorted(set(diffs)),
        "stored": stored,
        "current": evidence,
    }


def main(argv):
    if len(argv) < 2:
        print("usage: python -m attestation.reproduce <certificate_id>")
        return 1
    result = reproduce(argv[1])
    print(result["status"], "->", result.get("id", ""))
    if result["status"] == "REPRODUCED":
        print(f"  trust={result['trust']} stability={result['stability']} "
              f"consensus={result['consensus_count']}")
    elif result["status"] == "MISMATCH":
        print("  differing keys:", result["diff_keys"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
