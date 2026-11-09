"""Byzantine Fault Injection Engine: equivocation, silent proposer, invalid blocks, and replays."""

from copy import deepcopy
from enum import Enum
from typing import List, Optional, Tuple
from src.core.types import Block, BlockHeader, Phase, Transaction, Vote, compute_txs_hash
from src.crypto.keys import KeyPair
from src.crypto.sign import get_header_domain, get_vote_domain, sign_payload


class ByzantineMode(str, Enum):
    HONEST = "HONEST"
    EQUIVOCATE_VOTES = "EQUIVOCATE_VOTES"
    SILENT_PROPOSER = "SILENT_PROPOSER"
    INVALID_BLOCK_STATE_ROOT = "INVALID_BLOCK_STATE_ROOT"
    INVALID_BLOCK_TX = "INVALID_BLOCK_TX"
    INVALID_BLOCK_PARENT = "INVALID_BLOCK_PARENT"
    INVALID_BLOCK_SIGNATURE = "INVALID_BLOCK_SIGNATURE"
    REPLAY_ATTACK = "REPLAY_ATTACK"


def create_equivocating_prevotes(
    keypair: KeyPair,
    chain_id: str,
    height: int,
    round_num: int,
    block_hash_a: Optional[str],
    block_hash_b: Optional[str],
) -> Tuple[Vote, Vote]:
    """
    Creates two conflicting PREVOTE messages for the same (height, round) signed by the same validator.
    Used to inject equivocation attacks across different peer subsets.
    """
    domain = get_vote_domain(chain_id)

    vote_a = Vote(
        chain_id=chain_id,
        height=height,
        round=round_num,
        phase=Phase.PREVOTE,
        block_hash=block_hash_a,
        validator_id=keypair.public_key_hex,
    )
    vote_a.signature = sign_payload(keypair, domain, vote_a.signing_payload())

    vote_b = Vote(
        chain_id=chain_id,
        height=height,
        round=round_num,
        phase=Phase.PREVOTE,
        block_hash=block_hash_b,
        validator_id=keypair.public_key_hex,
    )
    vote_b.signature = sign_payload(keypair, domain, vote_b.signing_payload())

    return vote_a, vote_b


def create_equivocating_precommits(
    keypair: KeyPair,
    chain_id: str,
    height: int,
    round_num: int,
    block_hash_a: Optional[str],
    block_hash_b: Optional[str],
) -> Tuple[Vote, Vote]:
    """Creates two conflicting PRECOMMIT messages for the same (height, round)."""
    domain = get_vote_domain(chain_id)

    vote_a = Vote(
        chain_id=chain_id,
        height=height,
        round=round_num,
        phase=Phase.PRECOMMIT,
        block_hash=block_hash_a,
        validator_id=keypair.public_key_hex,
    )
    vote_a.signature = sign_payload(keypair, domain, vote_a.signing_payload())

    vote_b = Vote(
        chain_id=chain_id,
        height=height,
        round=round_num,
        phase=Phase.PRECOMMIT,
        block_hash=block_hash_b,
        validator_id=keypair.public_key_hex,
    )
    vote_b.signature = sign_payload(keypair, domain, vote_b.signing_payload())

    return vote_a, vote_b


def create_invalid_state_root_proposal(
    base_block: Block,
    keypair: KeyPair,
    chain_id: str,
    tampered_state_root: str = "deadbeef" * 8,
) -> Block:
    """Creates a proposal block with a forged/mismatched state root commitment."""
    header = deepcopy(base_block.header)
    header.state_root = tampered_state_root
    # Re-sign the header with the proposer's key
    domain = get_header_domain(chain_id)
    header.signature = sign_payload(keypair, domain, header.signing_payload())
    return Block(header=header, txs=deepcopy(base_block.txs))


def create_invalid_tx_proposal(
    base_block: Block,
    keypair: KeyPair,
    chain_id: str,
    invalid_tx: Transaction,
) -> Block:
    """Creates a proposal block containing an invalid transaction (bad sig, unauthorized state modification, or invalid nonce)."""
    txs = deepcopy(base_block.txs)
    txs.append(invalid_tx)
    header = deepcopy(base_block.header)
    header.txs_hash = compute_txs_hash(txs)
    domain = get_header_domain(chain_id)
    header.signature = sign_payload(keypair, domain, header.signing_payload())
    return Block(header=header, txs=txs)


def create_invalid_parent_proposal(
    base_block: Block,
    keypair: KeyPair,
    chain_id: str,
    corrupted_parent_hash: str = "badparent" * 7 + "bad0",
) -> Block:
    """Creates a proposal block referencing an invalid parent hash."""
    header = deepcopy(base_block.header)
    header.parent_hash = corrupted_parent_hash
    domain = get_header_domain(chain_id)
    header.signature = sign_payload(keypair, domain, header.signing_payload())
    return Block(header=header, txs=deepcopy(base_block.txs))


def create_invalid_header_signature_proposal(
    base_block: Block,
    forged_signature: str = "00" * 64,
) -> Block:
    """Creates a proposal block with an invalid/forged signature."""
    header = deepcopy(base_block.header)
    header.signature = forged_signature
    return Block(header=header, txs=deepcopy(base_block.txs))


def create_replayed_vote(
    vote: Vote,
    tamper_height: Optional[int] = None,
    tamper_round: Optional[int] = None,
) -> Vote:
    """Creates an outdated/replayed vote (e.g. from a past height or round) retaining its old signature."""
    replayed = deepcopy(vote)
    if tamper_height is not None:
        replayed.height = tamper_height
    if tamper_round is not None:
        replayed.round = tamper_round
    return replayed
