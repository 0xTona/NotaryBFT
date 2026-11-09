"""Deterministic Key-Value state and Merkle root calculation for Document Notarization."""

from copy import deepcopy
from typing import Dict, List, Optional, Tuple
from src.core.types import Transaction
from src.crypto.encoding import canonical_hash, sha256
from src.crypto.sign import get_tx_domain, verify_payload_signature


class State:
    def __init__(self, initial_data: Optional[Dict[str, str]] = None):
        self.data: Dict[str, str] = dict(initial_data) if initial_data else {}

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.data.get(key, default)

    def set(self, key: str, value: str) -> None:
        self.data[key] = value

    def clone(self) -> "State":
        return State(deepcopy(self.data))

    def compute_merkle_root(self) -> str:
        """Computes a deterministic binary Merkle root over all sorted key-value pairs."""
        if not self.data:
            return canonical_hash({})

        sorted_keys = sorted(self.data.keys())
        nodes: List[bytes] = [
            sha256(f"{k}={self.data[k]}".encode("utf-8")) for k in sorted_keys
        ]

        while len(nodes) > 1:
            if len(nodes) % 2 != 0:
                nodes.append(nodes[-1])
            new_level: List[bytes] = []
            for i in range(0, len(nodes), 2):
                new_level.append(sha256(nodes[i] + nodes[i + 1]))
            nodes = new_level

        return nodes[0].hex()

    def apply_transaction(self, tx: Transaction, chain_id: str) -> Tuple[bool, str]:
        """Validates and applies a document notarization transaction to the state."""
        # 1. Access control: Target doc and nonce must be strictly under sender's namespace
        prefix = f"{tx.sender}/"
        nonce_key = f"{prefix}nonce"
        doc_key = f"{prefix}docs/{tx.doc_id}"

        if not tx.doc_id:
            return False, "Transaction doc_id cannot be empty"

        # 2. Cryptographic signature check under TX:chain_id domain
        domain = get_tx_domain(chain_id)
        if not verify_payload_signature(tx.sender, domain, tx.signing_payload(), tx.signature):
            return False, f"Invalid transaction signature under domain {domain}"

        # 3. Nonce sequentiality check (replay protection)
        current_nonce = int(self.data.get(nonce_key, "0"))
        if tx.nonce != current_nonce + 1:
            return False, f"Invalid nonce: expected {current_nonce + 1}, got {tx.nonce}"

        # 4. Apply state modifications
        self.data[nonce_key] = str(tx.nonce)
        self.data[doc_key] = tx.doc_hash
        return True, ""
