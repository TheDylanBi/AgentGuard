"""Tesseract OCR verifier (cross-model ensemble partner for RapidOCR).

Tesseract is a genuinely independent OCR engine with different failure modes
from RapidOCR (PaddleOCR models), so agreement between the two is strong
evidence. Optional: requires the system Tesseract binary + ``pytesseract``.

Windows: winget install UB-Mannheim.TesseractOCR  (or the installer), then
pip install pytesseract.
"""
from typing import List

from .base import Evidence, Verifier
from .ocr import _text_similarity

try:
    import pytesseract
    _HAS_PYTESSERACT = True
except Exception:  # pragma: no cover - depends on install
    _HAS_PYTESSERACT = False


class TesseractVerifier(Verifier):
    name = "tesseract"
    version = "5.x"

    def __init__(self, match_threshold: float = 0.7, conf_threshold: float = 50.0):
        self.match_threshold = match_threshold
        self.conf_threshold = conf_threshold
        self._load_error = None

    def available(self) -> bool:
        if not _HAS_PYTESSERACT:
            return False
        try:
            pytesseract.get_tesseract_version()
            return True
        except Exception as exc:  # pragma: no cover
            self._load_error = str(exc)
            return False

    def fingerprint(self):
        try:
            return f"tesseract-{pytesseract.get_tesseract_version()}"
        except Exception:  # pragma: no cover
            return None

    def verify(self, ctx, target: str) -> List[Evidence]:
        if not self.available():
            return []
        image = ctx.image
        if image is None:
            return []

        data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
        evidences: List[Evidence] = []
        n = len(data.get("text", []) or [])
        for i in range(n):
            text = (data["text"][i] or "").strip()
            try:
                conf = float(data["conf"][i])
            except (TypeError, ValueError):
                conf = 0.0
            if conf < self.conf_threshold:
                continue
            similarity = _text_similarity(text, target)
            if similarity < self.match_threshold:
                continue
            left = int(data["left"][i])
            top = int(data["top"][i])
            w = int(data["width"][i])
            h = int(data["height"][i])
            if w <= 0 or h <= 0:
                continue
            evidences.append(Evidence(
                source="tesseract",
                verifier=f"{self.name}-{self.version}",
                predicate="TEXT_PRESENT",
                value=text,
                region=[left, top, left + w, top + h],
                confidence=(conf / 100.0) * similarity,
            ))
        return evidences
