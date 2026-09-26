"""Ed25519 signer. Keypair is generated once and reused across restarts."""
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class Signer:
    def __init__(self, private_key_path, public_key_path):
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)
        self._key = None

    def _load_or_create(self):
        if self._key is not None:
            return self._key
        if self.private_key_path.exists():
            self._key = serialization.load_pem_private_key(
                self.private_key_path.read_bytes(), password=None
            )
        else:
            self.private_key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key = ed25519.Ed25519PrivateKey.generate()
            self.private_key_path.write_bytes(
                self._key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            self.public_key_path.write_bytes(
                self._key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        return self._key

    def sign(self, obj: dict) -> str:
        key = self._load_or_create()
        canonical = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = key.sign(canonical)
        return "ed25519:" + base64.b64encode(sig).decode("ascii")

    def verify(self, obj: dict, signature: str) -> bool:
        """Verify an ed25519 signature over the canonical serialization."""
        if not signature or not signature.startswith("ed25519:"):
            return False
        try:
            key = self._load_or_create()
            canonical = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
            raw = base64.b64decode(signature.split(":", 1)[1])
            key.public_key().verify(raw, canonical)
            return True
        except Exception:
            return False
