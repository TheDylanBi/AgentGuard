"""Filesystem-aware envelope checks. Empty envelopes never grant access.

Only absolute exact paths and trailing /* directory grants are supported.
Executors must revalidate immediately before use and isolate mutable mounts.
"""
import os
from pathlib import Path, PureWindowsPath


def resolved_path(value: str) -> Path:
    if not value or "\x00" in value:
        raise ValueError("Invalid path")
    # Refuse foreign-platform paths: resolving them against our cwd is unsafe.
    if os.name != "nt" and (PureWindowsPath(value).drive or "\\" in value):
        raise ValueError("Foreign-platform path")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("Absolute path required")
    if os.name == "nt" and ":" in value[2:]:
        raise ValueError("Alternate data streams are not supported")
    return path.resolve(strict=False)


def within_envelope(target: str, grants) -> bool:
    try:
        actual = resolved_path(target)
        for grant in grants or []:
            directory = grant.endswith(("/*", "\\*"))
            root_text = grant[:-2] if directory else grant
            if not root_text:
                root_text = "/"
            if any(c in root_text for c in "*?[]"):
                continue
            root = resolved_path(root_text)
            matches = (actual != root and actual.is_relative_to(root)) if directory else actual == root
            if matches:
                return True
    except (OSError, ValueError, RuntimeError):
        return False
    return False
