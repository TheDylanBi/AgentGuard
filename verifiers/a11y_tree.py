"""Accessibility Tree verifier (structured source, highest trust tier).

Consumes a region-annotated a11y snapshot (list of node dicts) and produces
UI_ELEMENT evidence. Pure Python: the snapshot is produced either by the
agent itself or by the Playwright attached-mode capture helper
(``browser/capture.py``).
"""
import difflib
from typing import List

from .base import Evidence, Verifier
from .ocr import _normalize


def _name_match(a: str, b: str) -> float:
    """Strict element-name matching (no substring false positives).

    A11y names are exact (from DOM/ARIA), so a target like "Post comment"
    must NOT match a textbox named "comment". Exact match -> 1.0; near-exact
    (ratio >= 0.85) -> the ratio; otherwise 0.
    """
    a, b = _normalize(a), _normalize(b)
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    ratio = difflib.SequenceMatcher(None, a, b).ratio()
    return ratio if ratio >= 0.85 else 0.0


class A11yTreeVerifier(Verifier):
    name = "a11y-tree"
    version = "1.0.0"

    def __init__(self, match_threshold: float = 0.85, confidence: float = 0.99):
        self.match_threshold = match_threshold
        self.confidence = confidence

    def available(self) -> bool:
        # Parsing a snapshot requires no external dependencies.
        return True

    def verify(self, ctx, target: str) -> List[Evidence]:
        snapshot = ctx.a11y_snapshot
        if not snapshot:
            return []

        evidences: List[Evidence] = []
        for node in snapshot:
            if not isinstance(node, dict):
                continue
            role = node.get("role") or ""
            name = node.get("name") or ""
            value = node.get("value") or ""
            best = max(
                (_name_match(c, target) for c in (name, value)),
                default=0.0,
            )
            if best < self.match_threshold:
                continue
            region = node.get("region")
            conf = node.get("confidence") or self.confidence
            evidences.append(Evidence(
                source="a11y_tree",
                verifier=f"{self.name}-{self.version}",
                predicate="UI_ELEMENT",
                value=f"{role}:{name}".strip(":"),
                region=region if isinstance(region, list) else None,
                confidence=float(conf) * best,
            ))
        return evidences
