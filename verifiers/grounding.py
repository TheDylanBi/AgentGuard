"""Grounding verifier (GroundingDINO, zero-shot, pre-trained).

Produces UI_ELEMENT evidence with pixel regions. Requires ``torch`` and
``transformers``; gracefully reports unavailable otherwise.
"""
from typing import List

from .base import Evidence, Verifier

try:
    import torch  # noqa: F401
    from transformers import AutoModelForZeroShotObjectDetection, AutoProcessor
    _DEPS_OK = True
except Exception:  # pragma: no cover - depends on install
    _DEPS_OK = False


class GroundingVerifier(Verifier):
    name = "grounding-dino"
    version = "base"
    # "IDEA-Research/grounding-dino-tiny" is a faster, smaller alternative.
    model_id = "IDEA-Research/grounding-dino-base"

    def __init__(self, box_threshold: float = 0.30, text_threshold: float = 0.25):
        self.box_threshold = box_threshold
        self.text_threshold = text_threshold
        self._processor = None
        self._model = None
        self._load_error = None

    def available(self) -> bool:
        if not _DEPS_OK:
            return False
        try:
            self._load()
            return True
        except Exception as exc:  # pragma: no cover
            self._load_error = str(exc)
            return False

    def _load(self):
        if self._model is None:
            self._processor = AutoProcessor.from_pretrained(self.model_id)
            self._model = AutoModelForZeroShotObjectDetection.from_pretrained(self.model_id)
            self._model.eval()
        return self._model

    def fingerprint(self):
        # Hashing multi-GB weights would be too slow; the model id + framework
        # version is the practical reproducibility anchor.
        return f"model:{self.model_id}"

    def verify(self, ctx, target: str) -> List[Evidence]:
        if not self.available():
            return []
        image = ctx.image
        if image is None:
            return []

        import torch  # local import; guarded by available()

        text = target.strip()
        if not text.endswith("."):
            text = text + "."

        inputs = self._processor(images=image, text=text, return_tensors="pt")
        with torch.no_grad():
            outputs = self._model(**inputs)

        w, h = image.size
        results = self._processor.post_process_grounded_object_detection(
            outputs,
            inputs.input_ids,
            box_threshold=self.box_threshold,
            text_threshold=self.text_threshold,
            target_sizes=torch.tensor([[h, w]]),
        )[0]

        evidences: List[Evidence] = []
        for box, label, score in zip(results["boxes"], results["labels"], results["scores"]):
            x1, y1, x2, y2 = [int(round(float(v))) for v in box.tolist()]
            evidences.append(Evidence(
                source="grounding",
                verifier=f"{self.name}-{self.version}",
                predicate="UI_ELEMENT",
                value=str(label),
                region=[x1, y1, x2, y2],
                confidence=float(score),
            ))
        return evidences
