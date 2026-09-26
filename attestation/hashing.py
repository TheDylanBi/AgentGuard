"""Content-addressed hashing for reproducibility."""
import hashlib
import io
import json


def crop_hash(image, region=None) -> str:
    """SHA-256 of the evidence crop (or the whole image when region is None)."""
    img = image
    if region is not None:
        img = image.crop(tuple(region))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "sha256:" + hashlib.sha256(buf.getvalue()).hexdigest()


def canonical_json(obj) -> str:
    """Deterministic JSON serialization (sorted keys, no spaces)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def object_hash(obj) -> str:
    """Content hash of any JSON-serializable object."""
    return "sha256:" + hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()
