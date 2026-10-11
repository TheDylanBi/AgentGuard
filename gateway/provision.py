"""Provision fresh credentials outside the workspace; never prints secrets.

Run as the dedicated gateway service identity. Windows administrators must
restrict the directory ACL to that identity before starting the gateway.
"""
import argparse
import os
import secrets
from pathlib import Path
from attestation.signer import Signer


def provision(state_dir):
    root = Path(state_dir).resolve()
    workspace = Path(__file__).resolve().parent.parent
    if root.is_relative_to(workspace):
        raise ValueError("State directory must be outside the agent workspace")
    destinations = [root / "keys" / "gateway_ed25519.pem", root / "keys" / "gateway_ed25519.pub"]
    destinations += [root / "credentials" / f"{role}.token" for role in ("executor", "admin", "intent", "approver")]
    if any(p.exists() for p in destinations):
        raise ValueError("Refusing to overwrite credentials; choose a new state directory for rotation")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    (root / "keys").mkdir(mode=0o700, exist_ok=True)
    (root / "credentials").mkdir(mode=0o700, exist_ok=True)
    signer = Signer(destinations[0], destinations[1])
    signer.sign({"purpose": "provisioning"})
    os.chmod(destinations[0], 0o600)
    for path in destinations[2:]:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(secrets.token_urlsafe(48))
    return root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True)
    root = provision(parser.parse_args().state_dir)
    print(f"Fresh keys and four role credentials created in {root}. No existing credentials were overwritten.")
