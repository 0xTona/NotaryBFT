"""Implementation of Consensus Locking Rules 1 to 7 and validation helpers."""

from typing import Dict, List, Optional, Tuple
from src.core.executor import Executor
from src.core.state import State
from src.core.types import Block, Phase, Vote
from src.crypto.sign import (
    get_header_domain,
    get_vote_domain,
    verify_payload_signature,
)
from src.consensus.proposer import get_proposer


class VoteSet:
    """
    Manages votes for a specific (height, round, phase).
    Enforces Rule 7: Duplicate vote suppression (at most one vote per validator).
    """

    def __init__(
        self,
        height: int,
        round_num: int,
        phase: str,
        validators: List[str],
        quorum: int,
    ):
        self.height = height
        self.round = round_num
        self.phase = phase
        self.validators = set(validators)
        self.quorum = quorum
        # Key: validator_id -> Vote
        self.votes: Dict[str, Vote] = {}

    def add_vote(self, vote: Vote) -> Tuple[bool, str]:
        """
        Adds an incoming vote if valid.
        Rule 7: Duplicate votes are ignored; at most one vote per validator is counted.
        """
        if vote.height != self.height or vote.round != self.round or vote.phase != self.phase:
            return False, f"Vote context mismatch: expected ({self.height},{self.round},{self.phase}), got ({vote.height},{vote.round},{vote.phase})"

        if vote.validator_id not in self.validators:
            return False, f"Validator {vote.validator_id} not in validator set"

        # Rule 7: Ignore duplicate votes
        if vote.validator_id in self.votes:
            return False, f"Duplicate vote from {vote.validator_id} suppressed"

        self.votes[vote.validator_id] = vote
        return True, ""

    def has_vote_from(self, validator_id: str) -> bool:
        return validator_id in self.votes

    def count_for_block(self, block_hash: Optional[str]) -> int:
        """Counts distinct votes for the specified block hash (or NIL if block_hash is None/NIL)."""
        target_nil = block_hash is None or block_hash == "" or str(block_hash).upper() == "NIL"
        count = 0
        for v in self.votes.values():
            if target_nil:
                if v.is_nil():
                    count += 1
            else:
                if not v.is_nil() and v.block_hash == block_hash:
                    count += 1
        return count

    def has_quorum_for(self, block_hash: Optional[str]) -> bool:
        return self.count_for_block(block_hash) >= self.quorum

    def get_quorum_block(self) -> Tuple[bool, Optional[str]]:
        """
        Checks if any block (or NIL) has achieved a quorum of 2f + 1 votes.
        Returns (True, block_hash) or (False, None).
        """
        counts: Dict[Optional[str], int] = {}
        for v in self.votes.values():
            key = None if v.is_nil() else v.block_hash
            counts[key] = counts.get(key, 0) + 1
            if counts[key] >= self.quorum:
                return True, key
        return False, None

    def total_votes(self) -> int:
        return len(self.votes)


class LocalSigningTracker:
    """
    Enforces Rule 1, Rule 2, and Rule 6 on the local signing path.
    Prevents double-signing Prevotes (Rule 1) or Precommits (Rule 2),
    and rejects signing with mismatched context/domain (Rule 6).
    """

    def __init__(self, chain_id: str):
        self.chain_id = chain_id
        # Key: (height, round) -> Vote
        self.signed_prevotes: Dict[Tuple[int, int], Vote] = {}
        self.signed_precommits: Dict[Tuple[int, int], Vote] = {}

    def guard_local_signing(
        self,
        vote: Vote,
        current_chain_id: str,
        current_height: int,
        current_round: int,
        domain_string: str,
    ) -> Tuple[bool, str]:
        """
        Rule 6: A validator must not sign a vote from an incorrect chain, height, round, phase, or domain.
        Rule 1: Signs at most one PREVOTE for each (height, round).
        Rule 2: Signs at most one PRECOMMIT for each (height, round).
        """
        # Rule 6 checks
        if vote.chain_id != current_chain_id or vote.chain_id != self.chain_id:
            return False, f"Rule 6 guard failed: chain ID mismatch (expected {self.chain_id}, got {vote.chain_id})"

        if vote.height != current_height:
            return False, f"Rule 6 guard failed: height mismatch (expected {current_height}, got {vote.height})"

        if vote.round != current_round:
            return False, f"Rule 6 guard failed: round mismatch (expected {current_round}, got {vote.round})"

        expected_domain = get_vote_domain(self.chain_id)
        if domain_string != expected_domain:
            return False, f"Rule 6 guard failed: domain mismatch (expected {expected_domain}, got {domain_string})"

        if vote.phase == Phase.PREVOTE or vote.phase == "PREVOTE":
            key = (vote.height, vote.round)
            if key in self.signed_prevotes:
                return False, f"Rule 1 violation: already signed PREVOTE for height {vote.height}, round {vote.round}"
            self.signed_prevotes[key] = vote
            return True, ""

        elif vote.phase == Phase.PRECOMMIT or vote.phase == "PRECOMMIT":
            key = (vote.height, vote.round)
            if key in self.signed_precommits:
                return False, f"Rule 2 violation: already signed PRECOMMIT for height {vote.height}, round {vote.round}"
            self.signed_precommits[key] = vote
            return True, ""

        else:
            return False, f"Rule 6 guard failed: unknown vote phase {vote.phase}"


def validate_incoming_vote(
    vote: Vote,
    expected_chain_id: str,
    validators: List[str],
    domain_string: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Rule 6: Validates incoming votes before counting.
    Checks chain ID, validator membership, phase, domain, and cryptographic signature.
    """
    if vote.chain_id != expected_chain_id:
        return False, f"Rule 6 validation failed: chain ID mismatch (expected {expected_chain_id}, got {vote.chain_id})"

    if vote.phase not in (Phase.PREVOTE, Phase.PRECOMMIT, "PREVOTE", "PRECOMMIT"):
        return False, f"Rule 6 validation failed: invalid phase {vote.phase}"

    if vote.validator_id not in validators:
        return False, f"Rule 6 validation failed: unknown validator {vote.validator_id}"

    domain = domain_string if domain_string is not None else get_vote_domain(expected_chain_id)
    if not verify_payload_signature(
        vote.validator_id, domain, vote.signing_payload(), vote.signature
    ):
        return False, f"Rule 6 validation failed: invalid vote signature under domain {domain}"

    return True, ""


def validate_block_proposal(
    block: Block,
    chain_id: str,
    current_height: int,
    current_round: int,
    parent_block: Optional[Block],
    parent_state: State,
    validators: List[str],
) -> Tuple[bool, str, Optional[State]]:
    """
    Rule 3: Accepts and prevotes only for a block with:
    - Valid parent hash
    - Valid transactions
    - Correct state hash
    - Correct proposer for (height, round)
    - Valid header signature
    Rejection must leave committed parent state completely unchanged.
    """
    header = block.header

    # 1. Proposer check
    expected_proposer = get_proposer(validators, current_height, current_round)
    if header.proposer != expected_proposer:
        return False, f"Rule 3 failed: proposer mismatch (expected {expected_proposer}, got {header.proposer})", None

    # 2. Chain ID, Height, Round checks
    if header.chain_id != chain_id:
        return False, f"Rule 3 failed: chain ID mismatch (expected {chain_id}, got {header.chain_id})", None
    if header.height != current_height:
        return False, f"Rule 3 failed: height mismatch (expected {current_height}, got {header.height})", None
    if header.round != current_round:
        return False, f"Rule 3 failed: round mismatch (expected {current_round}, got {header.round})", None

    # 3. Parent hash check
    expected_parent_hash = parent_block.hash() if parent_block is not None else "0" * 64
    if header.parent_hash != expected_parent_hash:
        return False, f"Rule 3 failed: parent hash mismatch (expected {expected_parent_hash}, got {header.parent_hash})", None

    # 4. Header signature check under HEADER:chain_id
    header_domain = get_header_domain(chain_id)
    if not verify_payload_signature(
        header.proposer, header_domain, header.signing_payload(), header.signature
    ):
        return False, f"Rule 3 failed: invalid header signature under {header_domain}", None

    # 5. Deterministic transaction execution and state root check
    ok, new_state, _, receipts, err = Executor.execute_block(parent_state, block, chain_id)
    if not ok:
        return False, f"Rule 3 failed: block execution rejected: {err}", None

    # Successfully validated; parent_state remains unchanged while new_state is returned
    return True, "", new_state


def can_prevote_block(
    candidate_block: Block,
    locked_block: Optional[Block],
    locked_round: int,
    polka_evidence: Optional[VoteSet],
    current_height: int,
) -> Tuple[bool, str]:
    """
    Enforces Rule 4 and Rule 5:
    Rule 4: Lock on quorum of PREVOTEs for non-NIL block at current round.
    Rule 5: While locked on block B, prevote a different block B' only after observing
            a quorum (2f + 1) of valid PREVOTEs for THAT REPLACEMENT BLOCK B' at the same height,
            in a round > locked_round.
            A later-round quorum for the already locked block or any other block does not authorize switching.
    """
    # If not locked, validator is free to prevote the candidate block
    if locked_block is None:
        return True, "Not locked"

    # If candidate block is the already locked block, validator can prevote it
    if locked_block.hash() == candidate_block.hash():
        return True, "Candidate matches currently locked block"

    # Node is locked on a different block B, trying to switch to candidate block B'
    # Must observe valid quorum evidence strictly satisfying Rule 5
    if polka_evidence is None:
        return False, "Rule 5 violation: locked on different block with no polka evidence"

    # Evidence must be at the same height
    if polka_evidence.height != current_height:
        return False, f"Rule 5 violation: evidence height {polka_evidence.height} != current height {current_height}"

    # Evidence round must be strictly greater than locked_round
    if polka_evidence.round <= locked_round:
        return False, f"Rule 5 violation: evidence round {polka_evidence.round} <= locked_round {locked_round}"

    # Evidence phase must be PREVOTE
    if polka_evidence.phase != Phase.PREVOTE and polka_evidence.phase != "PREVOTE":
        return False, f"Rule 5 violation: evidence phase must be PREVOTE, got {polka_evidence.phase}"

    # Crucial Rule 5 condition: Quorum must be specifically FOR candidate_block (replacement B')
    # A quorum for the locked block or any other block does not authorize switching to B'
    if not polka_evidence.has_quorum_for(candidate_block.hash()):
        return False, f"Rule 5 violation: evidence does not contain a 2f+1 quorum for replacement block {candidate_block.hash()}"

    return True, "Rule 5 satisfied: observed valid later-round quorum for replacement block"
