import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_pack_json(pack_dict: dict[str, Any]) -> bytes:
    clean = {k: v for k, v in pack_dict.items() if k not in ("signature", "chain_provenance_tx")}
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_pack_hash(pack_dict: dict[str, Any]) -> str:
    canonical = canonical_pack_json(pack_dict)
    return hashlib.sha256(canonical).hexdigest()


def sign_pack(pack_dict: dict[str, Any], private_key_pem: bytes | str) -> str:
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode("utf-8")
    priv_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(priv_key, Ed25519PrivateKey):
        raise ValueError("Key is not Ed25519")
    pack_hash = compute_pack_hash(pack_dict).encode("utf-8")
    sig = priv_key.sign(pack_hash)
    return sig.hex()


def verify_pack_signature(pack_dict: dict[str, Any], public_key_pem: bytes | str) -> bool:
    sig_hex = pack_dict.get("signature")
    if not sig_hex:
        return False
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(pub_key, Ed25519PublicKey):
            return False
        pack_hash = compute_pack_hash(pack_dict).encode("utf-8")
        sig = bytes.fromhex(sig_hex)
        pub_key.verify(sig, pack_hash)
        return True
    except Exception:
        return False


def generate_keypair() -> tuple[bytes, bytes]:
    """Generates an ephemeral Ed25519 keypair for signing and verification."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem

