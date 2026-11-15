"""Core data types for transactions, blocks, headers, and votes."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from src.crypto.encoding import canonical_hash


class _StrValueEnum(str, Enum):
    """str-valued Enum whose str()/format() is the bare value on every Python version.

    Since Python 3.11, format() of a (str, Enum) member yields "Phase.PREVOTE"
    instead of "PREVOTE". Signed payloads and logs must not depend on the
    interpreter version, so the textual form is pinned to the value here.
    """

    def __str__(self) -> str:
        return str(self.value)

    def __format__(self, format_spec: str) -> str:
        return format(str(self.value), format_spec)


class Phase(_StrValueEnum):
    PREVOTE = "PREVOTE"
    PRECOMMIT = "PRECOMMIT"


class Step(_StrValueEnum):
    NEW_ROUND = "NEW_ROUND"
    PROPOSE = "PROPOSE"
    PREVOTE = "PREVOTE"
    PRECOMMIT = "PRECOMMIT"
    COMMIT = "COMMIT"


@dataclass
class Transaction:
    sender: str  # public key hex
    doc_id: str  # identifier for the notarized document
    doc_hash: str  # SHA-256 digest in hex (with or without '0x')
    nonce: int  # strictly incrementing uint64 per sender
    signature: str = ""

    def signing_payload(self) -> Dict[str, Any]:
        """Payload signed by the transaction sender under TX:chain_id."""
        return {
            "doc_hash": self.doc_hash,
            "doc_id": self.doc_id,
            "nonce": self.nonce,
            "sender": self.sender,
        }

    def hash(self) -> str:
        """Deterministic transaction hash."""
        return canonical_hash({
            **self.signing_payload(),
            "signature": self.signature,
        })


def compute_txs_hash(txs: List[Transaction]) -> str:
    """Computes a deterministic hash committing to the ordered list of transactions."""
    return canonical_hash([tx.hash() for tx in txs])


@dataclass
class BlockHeader:
    chain_id: str
    height: int
    round: int
    parent_hash: str
    state_root: str
    txs_hash: str
    proposer: str  # public key hex
    timestamp: int  # virtual simulator timestamp
    signature: str = ""

    def signing_payload(self) -> Dict[str, Any]:
        """Payload signed by the block proposer under HEADER:chain_id."""
        return {
            "chain_id": self.chain_id,
            "height": self.height,
            "parent_hash": self.parent_hash,
            "proposer": self.proposer,
            "round": self.round,
            "state_root": self.state_root,
            "timestamp": self.timestamp,
            "txs_hash": self.txs_hash,
        }

    def hash(self) -> str:
        """Deterministic block hash covering header fields and proposer signature."""
        return canonical_hash({
            **self.signing_payload(),
            "signature": self.signature,
        })


@dataclass
class Block:
    header: BlockHeader
    txs: List[Transaction] = field(default_factory=list)

    def hash(self) -> str:
        return self.header.hash()


@dataclass
class Vote:
    chain_id: str
    height: int
    round: int
    phase: str  # "PREVOTE" or "PRECOMMIT"
    block_hash: Optional[str]  # None or hex hash; None indicates NIL
    validator_id: str  # public key hex
    signature: str = ""

    def signing_payload(self) -> Dict[str, Any]:
        """Payload signed by the validator under VOTE:chain_id."""
        return {
            "block_hash": self.block_hash,
            "chain_id": self.chain_id,
            "height": self.height,
            "phase": self.phase.value if isinstance(self.phase, Enum) else str(self.phase),
            "round": self.round,
            "validator_id": self.validator_id,
        }

    def is_nil(self) -> bool:
        return self.block_hash is None or self.block_hash == "" or str(self.block_hash).upper() == "NIL"
