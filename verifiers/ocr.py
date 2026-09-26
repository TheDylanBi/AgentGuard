"""OCR verifier (RapidOCR, ONNX-based, no torch/paddle needed).

Produces TEXT_PRESENT evidence with pixel regions and confidence.
"""
import difflib
import hashlib
import io
from pathlib import Path
from typing import List

from .base import Evidence, Verifier

try:
    from rapidocr_onnxruntime import RapidOCR
    _HAS_RAPIDOCR = True
except Exception:  # pragma: no cover - depends on install
    _HAS_RAPIDOCR = False


def _normalize(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum() or ch.isspace()).strip()


def _text_similarity(a: str, b: str) -> float:
    a, b = _normalize(a), _normalize(b)
    if not a or not b:
        return 0.0
    if a in b or b in a:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


class OCRVerifier(Verifier):
    name = "rapidocr"
    version = "1.3.8"

    def __init__(self, text_match_threshold: float = 0.7, conf_threshold: float = 0.5):
        self.text_match_threshold = text_match_threshold
        self.conf_threshold = conf_threshold
        self._engine = None
        self._load_error = None

    def available(self) -> bool:
        if not _HAS_RAPIDOCR:
            return False
        try:
            self._get_engine()
            return True
        except Exception as exc:  # pragma: no cover
            self._load_error = str(exc)
            return False

    def _get_engine(self):
        if self._engine is None:
            self._engine = RapidOCR()
        return self._engine

    def fingerprint(self):
        """Hash of the bundled RapidOCR ONNX model files."""
        try:
            import rapidocr_onnxruntime as r
            pkg = Path(r.__file__).parent
            onnx_files = sorted(pkg.rglob("*.onnx"))
            if not onnx_files:
                return None
            h = hashlib.sha256()
            for f in onnx_files:
                rel = f.relative_to(pkg).as_posix()
                fh = hashlib.sha256(f.read_bytes()).hexdigest()
                h.update(f"{rel}:{fh}".encode("utf-8"))
            return "sha256:" + h.hexdigest()
        except Exception:  # pragma: no cover
            return None

    def verify(self, ctx, target: str) -> List[Evidence]:
        if not self.available():
            return []
        image = ctx.image
        if image is None:
            return []

        buf = io.BytesIO()
        image.save(buf, format="PNG")
        result, _ = self._get_engine()(buf.getvalue())

        evidences: List[Evidence] = []
        if not result:
            return evidences

        for box, text, score in result:
            similarity = _text_similarity(text, target)
            if similarity < self.text_match_threshold:
                continue
            if float(score) < self.conf_threshold:
                continue
            xs = [p[0] for p in box]
            ys = [p[1] for p in box]
            region = [int(min(xs)), int(min(ys)), int(max(xs)), int(max(ys))]
            evidences.append(Evidence(
                source="ocr",
                verifier=f"{self.name}-{self.version}",
                predicate="TEXT_PRESENT",
                value=str(text),
                region=region,
                confidence=float(score) * similarity,
            ))
        return evidences
