"""Sign a reviewed ASB tool contract with an existing operator key."""
import argparse
import base64
import json
import os
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import serialization
from attestation.signer import Signer
from .tool_contracts import ToolContracts, _object


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--private-key', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError('Signature output already exists')
    # The signer never generates a trust root. Provision keys independently.
    ToolContracts(args.contract)
    data = json.loads(args.contract.read_text(encoding='utf-8-sig'), object_pairs_hook=_object)
    signature = Signer(args.private_key, args.public_key, allow_create=False).sign(data)
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    public_key = serialization.load_pem_public_key(args.public_key.read_bytes())
    try:
        public_key.verify(base64.b64decode(signature.split(':', 1)[1], validate=True), canonical)
    except Exception:
        raise ValueError('Signing key does not match the independently supplied public key') from None
    args.output.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=args.output.name + '.', suffix='.tmp',
                                         dir=str(args.output.parent))
    try:
        with os.fdopen(handle, 'w', encoding='ascii', newline='\n') as stream:
            stream.write(signature + '\n')
        ToolContracts(args.contract, temporary, args.public_key)
        os.replace(temporary, args.output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print('Signed tool contract:', args.output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
