"""Cross-source consensus fusion (P1: structured-source priority).

trust levels:
  trusted   - a structured source (a11y_tree/dom/...) confirms, OR
              >=2 orthogonal perceptual sources agree on the same region
  untrusted - exactly one perceptual source produced evidence
  conflict  - a structured source disagrees with perceptual evidence, OR
              >=2 perceptual sources disagree
  unknown   - no evidence at all

Region agreement uses *containment* (intersection over the smaller region)
instead of IoU, because perceptual text evidence (small box) normally sits
*inside* a structured element (large box) — IoU would wrongly mark that
containment relationship as disagreement.
"""
from typing import List, Optional

from verifiers.base import Evidence

STRUCTURED_SOURCES = {"a11y_tree", "dom", "uia", "ax", "accessibility"}


def _area(r: Optional[list]) -> float:
    if not r:
        return 0.0
    return max(0, r[2] - r[0]) * max(0, r[3] - r[1])


def _inter(a: Optional[list], b: Optional[list]) -> float:
    if not a or not b:
        return 0.0
    iw = max(0, min(a[2], b[2]) - max(a[0], b[0]))
    ih = max(0, min(a[3], b[3]) - max(a[1], b[1]))
    return iw * ih


def _containment(a: Optional[list], b: Optional[list]) -> float:
    """Intersection over the smaller region (containment-aware).

    1.0 = one box fully contains the other; 0.0 = disjoint.
    """
    inter = _inter(a, b)
    if inter == 0:
        return 0.0
    smaller = min(_area(a), _area(b))
    return inter / smaller if smaller > 0 else 0.0


def region_overlap(a: Optional[list], b: Optional[list]) -> float:
    """Public wrapper for containment-based region agreement."""
    return _containment(a, b)


def merge_regions(regions: List[Optional[list]]) -> Optional[list]:
    regions = [r for r in regions if r]
    if not regions:
        return None
    xs = [p for r in regions for p in (r[0], r[2])]
    ys = [p for r in regions for p in (r[1], r[3])]
    return [min(xs), min(ys), max(xs), max(ys)]


def fuse(evidences: List[Evidence], overlap_threshold: float = 0.5) -> dict:
    if not evidences:
        return {"trust": "unknown", "region": None, "matched": []}

    structured = [e for e in evidences if e.source in STRUCTURED_SOURCES]
    perceptual = [e for e in evidences if e.source not in STRUCTURED_SOURCES]

    # ---- structured source present (highest trust tier) ----
    if structured:
        best_s = max(structured, key=lambda e: e.confidence)
        agreeing = [
            p for p in perceptual
            if _containment(p.region, best_s.region) >= overlap_threshold
        ]
        if agreeing:
            region = merge_regions([best_s.region] + [p.region for p in agreeing])
            return {"trust": "trusted", "region": region, "matched": [best_s] + agreeing}
        if perceptual:
            # structured says "here", perceptual says "somewhere else"
            return {"trust": "conflict", "region": None, "matched": evidences}
        # structured alone is sufficient
        return {"trust": "trusted", "region": best_s.region, "matched": [best_s]}

    # ---- perceptual sources only (P0 logic) ----
    by_source = {}
    for e in evidences:
        by_source.setdefault(e.source, []).append(e)
    source_types = list(by_source.keys())

    if len(source_types) == 1:
        best = max(evidences, key=lambda e: e.confidence)
        return {"trust": "untrusted", "region": best.region, "matched": [best]}

    best_pair = None
    for i, s1 in enumerate(source_types):
        for s2 in source_types[i + 1:]:
            for e1 in by_source[s1]:
                for e2 in by_source[s2]:
                    v = _containment(e1.region, e2.region)
                    if v >= overlap_threshold and (best_pair is None or v > best_pair["overlap"]):
                        best_pair = {"overlap": v, "e1": e1, "e2": e2}

    if best_pair:
        e1, e2 = best_pair["e1"], best_pair["e2"]
        region = merge_regions([e1.region, e2.region])
        return {"trust": "trusted", "region": region, "matched": [e1, e2]}

    return {"trust": "conflict", "region": None, "matched": evidences}
