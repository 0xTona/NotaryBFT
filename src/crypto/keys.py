"""Ed25519 key management and utilities."""

from dataclasses import dataclass
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass
class KeyPair:
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey
    public_key_hex: str

    @classmethod
    def generate(cls) -> "KeyPair":
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        pub_hex = pub.public_bytes_raw().hex()
        return cls(private_key=priv, public_key=pub, public_key_hex=pub_hex)

    @classmethod
    def from_seed(cls, seed: bytes | str) -> "KeyPair":
        if isinstance(seed, str):
            seed_bytes = hashlib.sha256(seed.encode("utf-8")).digest()
        else:
            if len(seed) != 32:
                seed_bytes = hashlib.sha256(seed).digest()
            else:
                seed_bytes = seed
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes)
        pub = priv.public_key()
        pub_hex = pub.public_bytes_raw().hex()
        return cls(private_key=priv, public_key=pub, public_key_hex=pub_hex)


def public_key_from_hex(pk_hex: str) -> ed25519.Ed25519PublicKey:
    """Loads an Ed25519 public key from a 64-character hexadecimal string."""
    raw = bytes.fromhex(pk_hex)
    if len(raw) != 32:
        raise ValueError(f"Expected 32-byte public key, got {len(raw)} bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)
