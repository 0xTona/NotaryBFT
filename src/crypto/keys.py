"""Ed25519 key management and utilities.

Identities are raw 32-byte Ed25519 public keys rendered as 64 lowercase hex
characters. The lowercase form is the only accepted spelling, so one key maps to
exactly one identity string (and therefore one state namespace).
"""

from dataclasses import dataclass
import hashlib
import re
from cryptography.hazmat.primitives.asymmetric import ed25519

PUBLIC_KEY_HEX_LEN = 64
SIGNATURE_HEX_LEN = 128
_PUBKEY_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class KeyPair:
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey
    public_key_hex: str

    @classmethod
    def generate(cls) -> "KeyPair":
        """Generates a fresh random key pair (OS randomness, not reproducible)."""
        priv = ed25519.Ed25519PrivateKey.generate()
        return cls._from_private(priv)

    @classmethod
    def from_seed(cls, seed: bytes | str) -> "KeyPair":
        """Derives a reproducible key pair from a seed.

        Simulation only: the simulator seed is not a source of cryptographic
        randomness, so keys derived this way must never protect real assets.
        """
        if isinstance(seed, str):
            seed_bytes = hashlib.sha256(seed.encode("utf-8")).digest()
        elif len(seed) != 32:
            seed_bytes = hashlib.sha256(seed).digest()
        else:
            seed_bytes = bytes(seed)
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed_bytes)
        return cls._from_private(priv)

    @classmethod
    def _from_private(cls, priv: ed25519.Ed25519PrivateKey) -> "KeyPair":
        pub = priv.public_key()
        return cls(private_key=priv, public_key=pub, public_key_hex=pub.public_bytes_raw().hex())

    def sign(self, message: bytes) -> bytes:
        """Signs raw bytes. Prefer the domain-separated helpers in src.crypto.sign."""
        return self.private_key.sign(message)


def is_valid_public_key_hex(pk_hex: object) -> bool:
    """True if pk_hex is the canonical 64-char lowercase hex form of a valid Ed25519 key."""
    if not isinstance(pk_hex, str) or not _PUBKEY_RE.match(pk_hex):
        return False
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
        return True
    except ValueError:
        return False


def public_key_from_hex(pk_hex: str) -> ed25519.Ed25519PublicKey:
    """Loads an Ed25519 public key from its canonical 64-character lowercase hex string."""
    if not isinstance(pk_hex, str) or not _PUBKEY_RE.match(pk_hex):
        raise ValueError("Public key must be 64 lowercase hexadecimal characters")
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
