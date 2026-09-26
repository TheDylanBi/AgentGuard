"""Verifier abstraction, Evidence, and VisualContext.

An Evidence is a *structured, sourced, reproducible* claim, never free text
from the planning MLLM. Verifiers are independent of the agent context.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Evidence:
    source: str          # "ocr" | "grounding" | "a11y_tree" | ...
    verifier: str        # "rapidocr-1.3.8"
    predicate: str       # "TEXT_PRESENT" | "UI_ELEMENT" | ...
    value: str           # the matched value, e.g. "Log In"
    region: Optional[list]  # [x1, y1, x2, y2] in pixels
    confidence: float

    def to_source_dict(self) -> dict:
        return {
            "type": self.source,
            "verifier": self.verifier,
            "confidence": round(float(self.confidence), 4),
        }


@dataclass
class VisualContext:
    """Everything the verifiers can observe about the current visual state.

    - image:         PIL screenshot (pixel evidence: OCR / grounding)
    - a11y_snapshot: region-annotated accessibility nodes (structured evidence)
    - cdp_endpoint:  WebSocket URL for attached-mode capture (P1)
    - previous_image / previous_a11y_snapshot: a second capture at t-Δt
      for cross-time consistency (P2).
    """
    image: Optional[object] = None
    a11y_snapshot: Optional[list] = None
    cdp_endpoint: Optional[str] = None
    previous_image: Optional[object] = None
    previous_a11y_snapshot: Optional[list] = None


class Verifier(ABC):
    name: str = "base"
    version: str = "0.0.0"

    @abstractmethod
    def available(self) -> bool:
        """Whether this verifier can run in the current environment."""

    @abstractmethod
    def verify(self, ctx: VisualContext, target: str) -> List[Evidence]:
        """Produce evidence for ``target`` from the visual context."""

    def fingerprint(self) -> Optional[str]:
        """Stable identifier of the underlying model/implementation (P3).

        Returns None for pure parsers (e.g. a11y tree) whose version string
        is already sufficient for reproducibility.
        """
        return None
