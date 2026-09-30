#!/usr/bin/env python3
"""Generate an Ed25519 dev keypair for ULPF pack signing.

Usage:
    python tools/keygen.py [output_dir]

Default output: keys/
  - keys/dev_signing.key (private, PEM)
  - keys/dev_signing.pub (public, PEM)

WARNING: The private key is for MVP development ONLY.
See architecture.md Decisions Log and agent.md §8 for the security constraints.
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def generate_keypair(output_dir: Path) -> None:
    """Generate and write an Ed25519 key pair."""
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = output_dir / "dev_signing.key"
    pub_path = output_dir / "dev_signing.pub"

    priv_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    pub_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)

    print("Ed25519 dev keypair generated:")
    print(f"  Private key: {priv_path}")
    print(f"  Public key:  {pub_path}")
    print()
    print("WARNING: This is a development key. See agent.md §8 for security rules.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("keys")
    generate_keypair(out)
