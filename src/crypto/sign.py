"""Domain-separated signature signing and verification.

Signed message layout (all multi-byte integers big-endian):

    u32(len(domain)) || domain_utf8 || canonical_encode(payload)

``domain`` is one of ``TX:<chain_id>``, ``HEADER:<chain_id>`` or ``VOTE:<chain_id>``.
The length prefix makes the domain/payload boundary unambiguous, so a signature
produced in one context (or for one chain) never verifies in another.

Signatures are Ed25519 (deterministic, RFC 8032) and are exchanged as 128
lowercase hex characters; any other spelling is rejected to keep a single
canonical form per signature.
"""

import re
from typing import Any
from cryptography.exceptions import InvalidSignature
from src.crypto.encoding import CanonicalEncodingError, canonical_encode
from src.crypto.keys import KeyPair, public_key_from_hex

DOMAIN_TX_PREFIX = "TX:"
DOMAIN_HEADER_PREFIX = "HEADER:"
DOMAIN_VOTE_PREFIX = "VOTE:"

_SIG_RE = re.compile(r"^[0-9a-f]{128}$")


def _check_chain_id(chain_id: str) -> None:
    if not isinstance(chain_id, str) or not chain_id:
        raise ValueError("chain_id must be a non-empty string")


def get_tx_domain(chain_id: str) -> str:
    _check_chain_id(chain_id)
    return f"{DOMAIN_TX_PREFIX}{chain_id}"


def get_header_domain(chain_id: str) -> str:
    _check_chain_id(chain_id)
    return f"{DOMAIN_HEADER_PREFIX}{chain_id}"


def get_vote_domain(chain_id: str) -> str:
    _check_chain_id(chain_id)
    return f"{DOMAIN_VOTE_PREFIX}{chain_id}"


def construct_domain_payload(domain_str: str, message_bytes: bytes) -> bytes:
    """Combines explicit domain string with payload bytes."""
    domain_bytes = domain_str.encode("utf-8")
    return len(domain_bytes).to_bytes(4, "big") + domain_bytes + message_bytes


def signing_bytes(domain_str: str, payload: Any) -> bytes:
    """Exact bytes that are signed for ``payload`` under ``domain_str``."""
    return construct_domain_payload(domain_str, canonical_encode(payload))


def sign_payload(keypair: KeyPair, domain_str: str, payload: Any) -> str:
    """Deterministically signs a canonical payload under a domain separation string."""
    sig = keypair.private_key.sign(signing_bytes(domain_str, payload))
    return sig.hex()


def verify_payload_signature(
    public_key_hex: str, domain_str: str, payload: Any, signature_hex: str
) -> bool:
    """Verifies a signature under the specified domain separation string."""
    try:
        if not isinstance(signature_hex, str) or not _SIG_RE.match(signature_hex):
            return False
        pub_key = public_key_from_hex(public_key_hex)
        pub_key.verify(bytes.fromhex(signature_hex), signing_bytes(domain_str, payload))
        return True
    except (InvalidSignature, ValueError, TypeError, CanonicalEncodingError):
        return False


# ---------------------------------------------------------------------------
# Typed helpers. They bind each message type to its own domain so callers cannot
# accidentally sign or verify in the wrong context. Objects are duck-typed
# (anything with ``signing_payload()``, ``signature`` and the identity field) to
# avoid an import cycle with src.core.types.
# ---------------------------------------------------------------------------

def sign_transaction(keypair: KeyPair, tx: Any, chain_id: str) -> str:
    """Signs a transaction under TX:chain_id, stores and returns the signature."""
    if tx.sender != keypair.public_key_hex:
        raise ValueError("Transaction sender does not match signing key")
    tx.signature = sign_payload(keypair, get_tx_domain(chain_id), tx.signing_payload())
    return tx.signature


def verify_transaction_signature(tx: Any, chain_id: str) -> bool:
    return verify_payload_signature(
        tx.sender, get_tx_domain(chain_id), tx.signing_payload(), tx.signature
    )


def sign_header(keypair: KeyPair, header: Any) -> str:
    """Signs a block header under HEADER:<header.chain_id>."""
    if header.proposer != keypair.public_key_hex:
        raise ValueError("Header proposer does not match signing key")
    header.signature = sign_payload(
        keypair, get_header_domain(header.chain_id), header.signing_payload()
    )
    return header.signature


def verify_header_signature(header: Any, chain_id: str) -> bool:
    return verify_payload_signature(
        header.proposer, get_header_domain(chain_id), header.signing_payload(), header.signature
    )


def sign_vote(keypair: KeyPair, vote: Any) -> str:
    """Signs a vote under VOTE:<vote.chain_id>.

    The signed payload binds chain_id, height, round, phase, block_hash and
    validator_id, so a vote cannot be replayed at another height/round/phase.
    Local Rule 1/2/6 guards (src.consensus.rules) must run before calling this.
    """
    if vote.validator_id != keypair.public_key_hex:
        raise ValueError("Vote validator_id does not match signing key")
    vote.signature = sign_payload(keypair, get_vote_domain(vote.chain_id), vote.signing_payload())
    return vote.signature


def verify_vote_signature(vote: Any, chain_id: str) -> bool:
    return verify_payload_signature(
        vote.validator_id, get_vote_domain(chain_id), vote.signing_payload(), vote.signature
    )
