"""Verifier registry: records the exact version + model fingerprint of every
verifier that participated in evidence production (P3).

The snapshot is embedded in each certificate log entry so that a certificate
can later be reproduced against the exact same verifier configuration — or a
mismatch can be detected when a verifier has changed.
"""


class VerifierRegistry:
    def __init__(self, verifiers: dict):
        # name -> verifier instance
        self.verifiers = verifiers

    def snapshot(self) -> dict:
        out = {}
        for name, v in self.verifiers.items():
            entry = {
                "name": v.name,
                "version": v.version,
                "available": v.available(),
            }
            try:
                fp = v.fingerprint()
            except Exception:  # pragma: no cover - fingerprint must never break
                fp = None
            if fp:
                entry["fingerprint"] = fp
            out[name] = entry
        return out
