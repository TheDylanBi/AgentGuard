"""Capability registry (P4).

Tools register their declared Effect Envelope (CapabilityDeclaration) once;
the gateway issues a signed CapabilityCertificate. At authorization time the
gateway checks that the proposed action stays inside the declared envelope,
which is how the Capability-Effect Gap is addressed *before* execution.
"""
import time
import secrets

from attestation.hashing import object_hash
from gateway.api_schema import CapabilityCertificate
from policy.paths import resolved_path


class CapabilityRegistry:
    def __init__(self, signer):
        self.signer = signer
        self.certs = {}  # capability_cert_id -> dict
        self._by_tool = {}  # tool_id -> latest cert dict (for re-registration detection)

    def register(self, req) -> CapabilityCertificate:
        declaration = req.declared_capabilities.model_dump()
        # Freeze the resolved roots when the administrator grants them. A later
        # replacement of a symlink/junction must not move the capability root.
        for field in ("filesystem_read", "filesystem_write"):
            normalized = []
            for grant in declaration[field]:
                directory = grant.endswith(("/*", "\\*"))
                root = grant[:-2] if directory else grant
                root = root or "/"
                if any(c in root for c in "*?[]"):
                    raise ValueError("Only exact paths and trailing /* directory grants are supported")
                normalized.append(str(resolved_path(root)) + ("/*" if directory else ""))
            declaration[field] = normalized
        payload = {
            "registration_id": secrets.token_hex(16),
            "tool_id": req.tool_id,
            "label": req.label,
            "declared_capabilities": declaration,
            "implementation_version": req.implementation_version,
            "implementation_hash": req.implementation_hash,
            "issued_at": int(time.time()),
        }
        prev = self._by_tool.get(req.tool_id)
        if prev is not None and prev.get("implementation_hash") != req.implementation_hash:
            # same tool_id, different implementation -> re-registration
            payload["re_registered"] = True
            payload["previous_hash"] = prev.get("implementation_hash")
        else:
            payload["re_registered"] = False
            payload["previous_hash"] = None

        cert_id = object_hash(payload)
        signature = self.signer.sign(payload)
        cert = CapabilityCertificate(
            capability_cert_id=cert_id,
            signature=signature,
            **payload,
        )
        self.certs[cert_id] = cert.model_dump()
        self._by_tool[req.tool_id] = cert.model_dump()
        return cert

    def get(self, capability_cert_id: str):
        return self.certs.get(capability_cert_id)

    def verify(self, capability_cert_id: str):
        """Change 4: the capability is NOT trusted just because the agent passed
        a cert_id. It must be a certificate the gateway itself signed.

        Reconstructs the signed payload from the stored cert and verifies the
        ed25519 signature; returns the cert dict only if valid, else None.
        """
        cert = self.certs.get(capability_cert_id)
        if cert is None:
            return None
        latest = self._by_tool.get(cert["tool_id"])
        if latest is None or latest["capability_cert_id"] != capability_cert_id:
            return None  # replaced implementations/capabilities revoke old grants
        payload = {
            "registration_id": cert["registration_id"],
            "tool_id": cert["tool_id"],
            "label": cert["label"],
            "declared_capabilities": cert["declared_capabilities"],
            "implementation_version": cert["implementation_version"],
            "implementation_hash": cert["implementation_hash"],
            "issued_at": cert["issued_at"],
            "re_registered": cert.get("re_registered", False),
            "previous_hash": cert.get("previous_hash"),
        }
        if not self.signer.verify(payload, cert.get("signature", "")):
            return None
        return cert
