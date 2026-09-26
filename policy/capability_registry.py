"""Capability registry (P4).

Tools register their declared Effect Envelope (CapabilityDeclaration) once;
the gateway issues a signed CapabilityCertificate. At authorization time the
gateway checks that the proposed action stays inside the declared envelope,
which is how the Capability-Effect Gap is addressed *before* execution.
"""
import time

from attestation.hashing import object_hash
from gateway.api_schema import CapabilityCertificate


class CapabilityRegistry:
    def __init__(self, signer):
        self.signer = signer
        self.certs = {}  # capability_cert_id -> dict
        self._by_tool = {}  # tool_id -> latest cert dict (for re-registration detection)

    def register(self, req) -> CapabilityCertificate:
        payload = {
            "tool_id": req.tool_id,
            "label": req.label,
            "declared_capabilities": req.declared_capabilities.model_dump(),
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
