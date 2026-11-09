"""Domain-separated signature signing and verification."""

from typing import Any
from cryptography.exceptions import InvalidSignature
from src.crypto.encoding import canonical_encode
from src.crypto.keys import KeyPair, public_key_from_hex

DOMAIN_TX_PREFIX = "TX:"
DOMAIN_HEADER_PREFIX = "HEADER:"
DOMAIN_VOTE_PREFIX = "VOTE:"


def get_tx_domain(chain_id: str) -> str:
    return f"{DOMAIN_TX_PREFIX}{chain_id}"


def get_header_domain(chain_id: str) -> str:
    return f"{DOMAIN_HEADER_PREFIX}{chain_id}"


def get_vote_domain(chain_id: str) -> str:
    return f"{DOMAIN_VOTE_PREFIX}{chain_id}"


def construct_domain_payload(domain_str: str, message_bytes: bytes) -> bytes:
    """Combines explicit domain string with payload bytes."""
    domain_bytes = domain_str.encode("utf-8")
    return len(domain_bytes).to_bytes(4, "big") + domain_bytes + message_bytes


def sign_payload(keypair: KeyPair, domain_str: str, payload: Any) -> str:
    """Deterministically signs a canonical payload under a domain separation string."""
    encoded_bytes = canonical_encode(payload)
    bound_message = construct_domain_payload(domain_str, encoded_bytes)
    sig = keypair.private_key.sign(bound_message)
    return sig.hex()


def verify_payload_signature(
    public_key_hex: str, domain_str: str, payload: Any, signature_hex: str
) -> bool:
    """Verifies a signature under the specified domain separation string."""
    try:
        pub_key = public_key_from_hex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        encoded_bytes = canonical_encode(payload)
        bound_message = construct_domain_payload(domain_str, encoded_bytes)
        pub_key.verify(sig_bytes, bound_message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
