"""Separate control-plane identities from the executor. No implicit auth bypass."""
import secrets
from fastapi import Header, HTTPException
from gateway import config


def require_role(role):
    def dependency(authorization: str = Header(default="")):
        expected = getattr(config, role.upper() + "_TOKEN")
        if not expected:
            raise HTTPException(503, "Security identity is not configured")
        actual = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
        if not secrets.compare_digest(actual, expected):
            raise HTTPException(403, "This identity cannot perform this operation")
        return role
    return dependency


require_executor = require_role("executor")
require_admin = require_role("admin")
require_intent = require_role("intent")
require_approver = require_role("approver")
