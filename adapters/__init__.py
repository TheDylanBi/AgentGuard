"""Portability adapters (P5): generic SDK + per-framework thin wrappers."""
from .sdk import (
    AuthorizationBlocked,
    AuthorizationNeedsConfirm,
    AuthorizeResult,
    ICBGuardClient,
    guard,
)

__all__ = [
    "ICBGuardClient",
    "AuthorizeResult",
    "AuthorizationBlocked",
    "AuthorizationNeedsConfirm",
    "guard",
]
