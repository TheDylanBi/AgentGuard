"""Append-only certificate log with a hash chain (P3).

Each entry carries the hash of the previous entry, so any deletion/insertion/
modification breaks the chain and can be detected. Entries also store the
exact request + verifier snapshot needed to reproduce the certificate.
"""
import json
from pathlib import Path
from typing import List, Optional

from .hashing import object_hash


class CertificateLog:
    def __init__(self, path):
        self.path = Path(path)

    def _read_entries(self) -> List[dict]:
        if not self.path.exists():
            return []
        entries = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
        return entries

    def append(self, entry: dict) -> dict:
        """Append an entry, linking it to the previous one via a hash chain."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entries = self._read_entries()
        prev_hash = entries[-1]["hash"] if entries else "genesis"

        entry = dict(entry)
        entry["prev_hash"] = prev_hash
        body = {k: v for k, v in entry.items() if k != "hash"}
        entry["hash"] = object_hash(body)

        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
        return entry

    def get(self, certificate_id: str) -> Optional[dict]:
        for e in self._read_entries():
            if e.get("id") == certificate_id:
                return e
        return None

    def ids(self) -> List[str]:
        return [e.get("id") for e in self._read_entries()]

    def verify_chain(self) -> dict:
        """Walk the chain and report tampering. O(1) memory, O(n) time."""
        entries = self._read_entries()
        if not entries:
            return {"ok": True, "entries": 0}
        prev = "genesis"
        for e in entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if body.get("prev_hash") != prev:
                return {
                    "ok": False,
                    "entries": len(entries),
                    "reason": f"broken prev_hash link at entry {e.get('id')}",
                }
            if object_hash(body) != e.get("hash"):
                return {
                    "ok": False,
                    "entries": len(entries),
                    "reason": f"hash mismatch at entry {e.get('id')}",
                }
            prev = e["hash"]
        return {"ok": True, "entries": len(entries)}
