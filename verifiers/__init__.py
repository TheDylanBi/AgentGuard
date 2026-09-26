"""Evidence verifiers. All are zero-training / off-the-shelf."""
from .a11y_tree import A11yTreeVerifier
from .base import Evidence, Verifier, VisualContext
from .grounding import GroundingVerifier
from .ocr import OCRVerifier
from .tesseract import TesseractVerifier

__all__ = [
    "Evidence",
    "Verifier",
    "VisualContext",
    "OCRVerifier",
    "GroundingVerifier",
    "A11yTreeVerifier",
    "TesseractVerifier",
]
