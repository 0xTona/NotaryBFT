"""Deterministic Key-Value state and Merkle root calculation for Document Notarization.

State layout (all keys and values are strings):

    <sender>/nonce           -> "<uint64>"         last applied nonce of the sender
    <sender>/docs/<doc_id>   -> "0x<hex digest>"   notarized document digest

``<sender>`` is the sender's Ed25519 public key in canonical lowercase hex. A
transaction can only ever write the two keys above under its own sender prefix,
so it can never touch data owned by another participant.

State commitment (binary Merkle tree, RFC 6962 style):

    leaf(k, v)  = SHA256(0x00 || u32(len(k)) || k || u32(len(v)) || v)   (UTF-8, big-endian)
    node(l, r)  = SHA256(0x01 || l || r)
    empty root  = SHA256("")

Leaves are ordered by the UTF-8 bytes of the key (ascending). Each level pairs
nodes left-to-right; an unpaired last node is promoted unchanged to the next
level. The 0x00/0x01 prefixes keep leaves and inner nodes in separate hash
domains, and length prefixes make the key/value boundary unambiguous.
"""

import re
from copy import deepcopy
from typing import Dict, List, Optional, Tuple
from src.core.types import Transaction
from src.crypto.encoding import length_prefixed, sha256
from src.crypto.keys import is_valid_public_key_hex
from src.crypto.sign import get_tx_domain, verify_payload_signature

MAX_NONCE = 2**64 - 1
MAX_DOC_ID_LEN = 128
DOC_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DOC_HASH_RE = re.compile(r"^0x[0-9a-f]{1,64}$")

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = sha256(b"").hex()


def nonce_key(sender: str) -> str:
    return f"{sender}/nonce"


def doc_key(sender: str, doc_id: str) -> str:
    return f"{sender}/docs/{doc_id}"


def merkle_leaf_hash(key: str, value: str) -> bytes:
    return sha256(
        LEAF_PREFIX
        + length_prefixed(key.encode("utf-8"))
        + length_prefixed(value.encode("utf-8"))
    )


def merkle_node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_PREFIX + left + right)


def validate_transaction_format(tx: Transaction) -> Tuple[bool, str]:
    """Stateless structural checks: field types, canonical encodings, ownership scope."""
    if not isinstance(tx, Transaction):
        return False, "Malformed transaction object"
    if not is_valid_public_key_hex(tx.sender):
        return False, "Transaction sender must be a canonical lowercase Ed25519 public key"
    if not isinstance(tx.doc_id, str) or not tx.doc_id:
        return False, "Transaction doc_id cannot be empty"
    if len(tx.doc_id) > MAX_DOC_ID_LEN or not DOC_ID_RE.match(tx.doc_id):
        # Forbids '/', so the written key can never escape <sender>/docs/
        return False, f"Invalid doc_id {tx.doc_id!r}: allowed characters are [A-Za-z0-9._-], max {MAX_DOC_ID_LEN}"
    if not isinstance(tx.doc_hash, str) or not DOC_HASH_RE.match(tx.doc_hash):
        return False, "Invalid doc_hash: expected '0x' followed by 1-64 lowercase hex digits"
    if isinstance(tx.nonce, bool) or not isinstance(tx.nonce, int) or not (1 <= tx.nonce <= MAX_NONCE):
        return False, f"Invalid nonce: must be an integer in [1, {MAX_NONCE}]"
    return True, ""


def validate_transaction_stateless(tx: Transaction, chain_id: str) -> Tuple[bool, str]:
    """Format checks plus signature verification under TX:chain_id (no state needed).

    Used for mempool admission; the nonce/replay check needs state and happens in
    State.apply_transaction.
    """
    ok, err = validate_transaction_format(tx)
    if not ok:
        return False, err
    domain = get_tx_domain(chain_id)
    if not verify_payload_signature(tx.sender, domain, tx.signing_payload(), tx.signature):
        return False, f"Invalid transaction signature under domain {domain}"
    return True, ""


class State:
    def __init__(self, initial_data: Optional[Dict[str, str]] = None):
        self.data: Dict[str, str] = {}
        for k, v in (initial_data or {}).items():
            self.set(k, v)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.data.get(key, default)

    def set(self, key: str, value: str) -> None:
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("State keys and values must be strings")
        self.data[key] = value

    def clone(self) -> "State":
        return State(deepcopy(self.data))

    def get_nonce(self, sender: str) -> int:
        return int(self.data.get(nonce_key(sender), "0"))

    def compute_merkle_root(self) -> str:
        """Computes the canonical binary Merkle root over all key-value records."""
        if not self.data:
            return EMPTY_ROOT

        sorted_keys = sorted(self.data.keys(), key=lambda k: k.encode("utf-8"))
        level: List[bytes] = [merkle_leaf_hash(k, self.data[k]) for k in sorted_keys]

        while len(level) > 1:
            next_level: List[bytes] = []
            for i in range(0, len(level) - 1, 2):
                next_level.append(merkle_node_hash(level[i], level[i + 1]))
            if len(level) % 2 == 1:
                next_level.append(level[-1])  # promote unpaired node unchanged
            level = next_level

        return level[0].hex()

    def apply_transaction(self, tx: Transaction, chain_id: str) -> Tuple[bool, str]:
        """Validates and applies a document notarization transaction to the state.

        All checks run before any write, so a rejected transaction leaves the
        state untouched. Returns (ok, error_reason).
        """
        # 1-2. Structure, ownership scope and TX:chain_id signature
        ok, err = validate_transaction_stateless(tx, chain_id)
        if not ok:
            return False, err

        # 3. Nonce sequentiality (replay protection): each nonce is usable exactly once
        current_nonce = self.get_nonce(tx.sender)
        if tx.nonce != current_nonce + 1:
            return False, f"Invalid nonce: expected {current_nonce + 1}, got {tx.nonce}"

        # 4. Writes are confined to the sender's own namespace
        self.data[nonce_key(tx.sender)] = str(tx.nonce)
        self.data[doc_key(tx.sender, tx.doc_id)] = tx.doc_hash
        return True, ""
