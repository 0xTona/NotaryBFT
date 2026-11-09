"""Unit tests for Consensus Locking Rules 1 to 7, vote counting, and signing guards (Member 1)."""

import pytest
from src.consensus.engine import ConsensusEngine
from src.consensus.proposer import TimeoutConfig, get_proposer
from src.consensus.rules import (
    LocalSigningTracker,
    VoteSet,
    can_prevote_block,
    validate_incoming_vote,
)
from src.core.types import Block, BlockHeader, Phase, Vote
from src.crypto.keys import KeyPair
from src.crypto.sign import (
    get_tx_domain,
    get_vote_domain,
    sign_payload,
)


@pytest.fixture
def test_setup():
    chain_id = "test-chain"
    # 10 validators: n=10, f=3, quorum=7
    keypairs = [KeyPair.from_seed(f"validator_{i}") for i in range(10)]
    validators = [kp.public_key_hex for kp in keypairs]
    return {
        "chain_id": chain_id,
        "keypairs": keypairs,
        "validators": validators,
        "quorum": 7,
    }


def make_dummy_block(chain_id: str, height: int, round_num: int, proposer_kp: KeyPair, parent_hash: str = "0" * 64) -> Block:
    from src.core.state import State
    from src.core.types import compute_txs_hash
    state_root = State().compute_merkle_root()
    txs_hash = compute_txs_hash([])
    header = BlockHeader(
        chain_id=chain_id,
        height=height,
        round=round_num,
        parent_hash=parent_hash,
        state_root=state_root,
        txs_hash=txs_hash,
        proposer=proposer_kp.public_key_hex,
        timestamp=100,
    )
    domain = f"HEADER:{chain_id}"
    header.signature = sign_payload(proposer_kp, domain, header.signing_payload())
    return Block(header=header, txs=[])


def test_validator_configuration_constraints(test_setup):
    """Rejects validator configurations violating n >= 8 or n = 3f + 1."""
    chain_id = test_setup["chain_id"]
    validators = test_setup["validators"]

    # Baseline n=10, f=3, quorum=7 is valid
    engine = ConsensusEngine(
        node_id=validators[0],
        chain_id=chain_id,
        validators=validators,
    )
    assert engine.f == 3
    assert engine.quorum == 7

    # n < 8 must be rejected
    with pytest.raises(ValueError, match="n >= 8 and n = 3f \\+ 1"):
        ConsensusEngine(node_id=validators[0], chain_id=chain_id, validators=validators[:7])

    # n = 9 fails (9-1)%3 != 0
    with pytest.raises(ValueError, match="n >= 8 and n = 3f \\+ 1"):
        ConsensusEngine(node_id=validators[0], chain_id=chain_id, validators=validators[:9])


def test_rule_7_duplicate_vote_suppression(test_setup):
    """Rule 7: Nodes must ignore duplicate votes and count at most one valid vote per validator per (height, round, phase)."""
    validators = test_setup["validators"]
    keypairs = test_setup["keypairs"]
    chain_id = test_setup["chain_id"]
    quorum = test_setup["quorum"]

    vset = VoteSet(height=1, round_num=0, phase=Phase.PREVOTE, validators=validators, quorum=quorum)

    v1 = Vote(
        chain_id=chain_id,
        height=1,
        round=0,
        phase=Phase.PREVOTE,
        block_hash="block_a_hash",
        validator_id=keypairs[0].public_key_hex,
    )

    # First vote from validator 0 is added
    added1, msg1 = vset.add_vote(v1)
    assert added1 is True
    assert vset.total_votes() == 1
    assert vset.count_for_block("block_a_hash") == 1

    # Duplicate vote from same validator (even with different block hash) must be suppressed
    v1_dup = Vote(
        chain_id=chain_id,
        height=1,
        round=0,
        phase=Phase.PREVOTE,
        block_hash="block_b_hash",
        validator_id=keypairs[0].public_key_hex,
    )
    added2, msg2 = vset.add_vote(v1_dup)
    assert added2 is False
    assert "Duplicate vote" in msg2
    assert vset.total_votes() == 1
    assert vset.count_for_block("block_a_hash") == 1
    assert vset.count_for_block("block_b_hash") == 0


def test_rule_1_and_rule_2_local_signing_guards(test_setup):
    """
    Rule 1: Signs at most one PREVOTE for each (height, round).
    Rule 2: Signs at most one PRECOMMIT for each (height, round).
    """
    chain_id = test_setup["chain_id"]
    kp = test_setup["keypairs"][0]
    tracker = LocalSigningTracker(chain_id)
    domain = get_vote_domain(chain_id)

    # Sign PREVOTE for (height=1, round=0)
    vote1 = Vote(chain_id=chain_id, height=1, round=0, phase=Phase.PREVOTE, block_hash="hash1", validator_id=kp.public_key_hex)
    ok1, _ = tracker.guard_local_signing(vote1, chain_id, 1, 0, domain)
    assert ok1 is True

    # Rule 1: Attempt to sign another PREVOTE for same (height=1, round=0) must be rejected
    vote1_conflict = Vote(chain_id=chain_id, height=1, round=0, phase=Phase.PREVOTE, block_hash="hash2", validator_id=kp.public_key_hex)
    ok1_bad, msg1_bad = tracker.guard_local_signing(vote1_conflict, chain_id, 1, 0, domain)
    assert ok1_bad is False
    assert "Rule 1 violation" in msg1_bad

    # Sign PRECOMMIT for (height=1, round=0) is allowed
    vote2 = Vote(chain_id=chain_id, height=1, round=0, phase=Phase.PRECOMMIT, block_hash="hash1", validator_id=kp.public_key_hex)
    ok2, _ = tracker.guard_local_signing(vote2, chain_id, 1, 0, domain)
    assert ok2 is True

    # Rule 2: Attempt to sign another PRECOMMIT for same (height=1, round=0) must be rejected
    vote2_conflict = Vote(chain_id=chain_id, height=1, round=0, phase=Phase.PRECOMMIT, block_hash="hash2", validator_id=kp.public_key_hex)
    ok2_bad, msg2_bad = tracker.guard_local_signing(vote2_conflict, chain_id, 1, 0, domain)
    assert ok2_bad is False
    assert "Rule 2 violation" in msg2_bad

    # Signing for next round (height=1, round=1) is allowed
    vote_next_round = Vote(chain_id=chain_id, height=1, round=1, phase=Phase.PREVOTE, block_hash="hash3", validator_id=kp.public_key_hex)
    ok_nr, _ = tracker.guard_local_signing(vote_next_round, chain_id, 1, 1, domain)
    assert ok_nr is True


def test_rule_6_local_signing_guards(test_setup):
    """Rule 6 local signing guards: reject incorrect chain ID, height, round, phase, or domain."""
    chain_id = test_setup["chain_id"]
    kp = test_setup["keypairs"][0]
    tracker = LocalSigningTracker(chain_id)
    correct_domain = get_vote_domain(chain_id)

    base_vote = Vote(
        chain_id=chain_id,
        height=2,
        round=1,
        phase=Phase.PREVOTE,
        block_hash="hash_a",
        validator_id=kp.public_key_hex,
    )

    # 1. Incorrect chain ID
    bad_chain_vote = Vote(chain_id="wrong-chain", height=2, round=1, phase=Phase.PREVOTE, block_hash="hash_a", validator_id=kp.public_key_hex)
    ok, msg = tracker.guard_local_signing(bad_chain_vote, chain_id, 2, 1, correct_domain)
    assert ok is False and "chain ID mismatch" in msg

    # 2. Incorrect height
    ok, msg = tracker.guard_local_signing(base_vote, chain_id, current_height=3, current_round=1, domain_string=correct_domain)
    assert ok is False and "height mismatch" in msg

    # 3. Incorrect round
    ok, msg = tracker.guard_local_signing(base_vote, chain_id, current_height=2, current_round=2, domain_string=correct_domain)
    assert ok is False and "round mismatch" in msg

    # 4. Incorrect domain
    ok, msg = tracker.guard_local_signing(base_vote, chain_id, current_height=2, current_round=1, domain_string="TX:test-chain")
    assert ok is False and "domain mismatch" in msg

    # 5. Incorrect phase
    bad_phase_vote = Vote(chain_id=chain_id, height=2, round=1, phase="PROPOSE", block_hash="hash_a", validator_id=kp.public_key_hex)
    ok, msg = tracker.guard_local_signing(bad_phase_vote, chain_id, 2, 1, correct_domain)
    assert ok is False and "unknown vote phase" in msg


def test_rule_6_incoming_vote_validation(test_setup):
    """Rule 6 incoming validation: reject incorrect chain ID, phase, unknown validator, or invalid signature."""
    chain_id = test_setup["chain_id"]
    validators = test_setup["validators"]
    kp = test_setup["keypairs"][0]
    vote_domain = get_vote_domain(chain_id)

    # Valid signed vote
    valid_vote = Vote(chain_id=chain_id, height=1, round=0, phase=Phase.PREVOTE, block_hash="hash_ok", validator_id=kp.public_key_hex)
    valid_vote.signature = sign_payload(kp, vote_domain, valid_vote.signing_payload())

    ok, msg = validate_incoming_vote(valid_vote, chain_id, validators)
    assert ok is True and msg == ""

    # Incorrect chain ID
    bad_chain_vote = Vote(chain_id="wrong_chain", height=1, round=0, phase=Phase.PREVOTE, block_hash="hash_ok", validator_id=kp.public_key_hex)
    bad_chain_vote.signature = sign_payload(kp, get_vote_domain("wrong_chain"), bad_chain_vote.signing_payload())
    ok, msg = validate_incoming_vote(bad_chain_vote, chain_id, validators)
    assert ok is False and "chain ID mismatch" in msg

    # Invalid phase
    bad_phase_vote = Vote(chain_id=chain_id, height=1, round=0, phase="UNKNOWN", block_hash="hash_ok", validator_id=kp.public_key_hex)
    bad_phase_vote.signature = valid_vote.signature
    ok, msg = validate_incoming_vote(bad_phase_vote, chain_id, validators)
    assert ok is False and "invalid phase" in msg

    # Unknown validator
    foreign_kp = KeyPair.from_seed("outsider")
    foreign_vote = Vote(chain_id=chain_id, height=1, round=0, phase=Phase.PREVOTE, block_hash="hash_ok", validator_id=foreign_kp.public_key_hex)
    foreign_vote.signature = sign_payload(foreign_kp, vote_domain, foreign_vote.signing_payload())
    ok, msg = validate_incoming_vote(foreign_vote, chain_id, validators)
    assert ok is False and "unknown validator" in msg

    # Invalid signature
    tampered_sig_vote = Vote(chain_id=chain_id, height=1, round=0, phase=Phase.PREVOTE, block_hash="hash_tampered", validator_id=kp.public_key_hex)
    tampered_sig_vote.signature = valid_vote.signature  # Signature over hash_ok, not hash_tampered
    ok, msg = validate_incoming_vote(tampered_sig_vote, chain_id, validators)
    assert ok is False and "invalid vote signature" in msg

    # Cross-domain signature: signed with TX:chain_id instead of VOTE:chain_id
    cross_domain_vote = Vote(chain_id=chain_id, height=1, round=0, phase=Phase.PREVOTE, block_hash="hash_ok", validator_id=kp.public_key_hex)
    cross_domain_vote.signature = sign_payload(kp, get_tx_domain(chain_id), cross_domain_vote.signing_payload())
    ok, msg = validate_incoming_vote(cross_domain_vote, chain_id, validators)
    assert ok is False and "invalid vote signature" in msg


def test_rule_4_quorum_locks_block(test_setup):
    """Rule 4: Observing a 2f + 1 quorum of PREVOTEs for non-NIL block locks that block and records locked_round."""
    validators = test_setup["validators"]
    keypairs = test_setup["keypairs"]
    chain_id = test_setup["chain_id"]
    quorum = test_setup["quorum"]

    engine = ConsensusEngine(
        node_id=validators[0],
        chain_id=chain_id,
        validators=validators,
        keypair=keypairs[0],
    )
    engine.start_height(1)
    assert engine.locked_block is None
    assert engine.locked_round == -1

    proposer_kp = keypairs[get_proposer_index(validators, 1, 0)]
    proposal = make_dummy_block(chain_id, 1, 0, proposer_kp)
    engine.on_receive_proposal(proposal)

    # Deliver 6 prevotes (less than quorum 7)
    for i in range(quorum - 1):
        v = Vote(chain_id=chain_id, height=1, round=0, phase=Phase.PREVOTE, block_hash=proposal.hash(), validator_id=keypairs[i].public_key_hex)
        v.signature = sign_payload(keypairs[i], get_vote_domain(chain_id), v.signing_payload())
        engine.on_receive_vote(v)

    # Still not locked
    assert engine.locked_block is None

    # Deliver 7th vote (reaching quorum 2f + 1 = 7)
    v7 = Vote(chain_id=chain_id, height=1, round=0, phase=Phase.PREVOTE, block_hash=proposal.hash(), validator_id=keypairs[quorum - 1].public_key_hex)
    v7.signature = sign_payload(keypairs[quorum - 1], get_vote_domain(chain_id), v7.signing_payload())
    engine.on_receive_vote(v7)

    # Now locked on proposal block at round 0
    assert engine.locked_block is not None
    assert engine.locked_block.hash() == proposal.hash()
    assert engine.locked_round == 0


def test_rule_5_locking_and_switching_guards(test_setup):
    """
    Rule 5 exhaustive guard tests:
    - While locked on B, prevote replacement B' only after observing 2f + 1 valid PREVOTEs for that replacement block B' in a round > locked_round.
    - A later-round quorum for the already locked block or another block does not authorize switching to B'.
    - Refuse switching when evidence is at another height, has insufficient votes, or is at/below locked_round.
    """
    validators = test_setup["validators"]
    keypairs = test_setup["keypairs"]
    chain_id = test_setup["chain_id"]
    quorum = test_setup["quorum"]

    block_b = make_dummy_block(chain_id, height=1, round_num=0, proposer_kp=keypairs[0])
    block_b_prime = make_dummy_block(chain_id, height=1, round_num=1, proposer_kp=keypairs[1])
    block_b_double_prime = make_dummy_block(chain_id, height=1, round_num=1, proposer_kp=keypairs[2])

    assert block_b.hash() != block_b_prime.hash()
    assert block_b_prime.hash() != block_b_double_prime.hash()

    locked_round = 1

    # Case 0: Not locked -> always allowed
    ok, _ = can_prevote_block(block_b_prime, locked_block=None, locked_round=-1, polka_evidence=None, current_height=1)
    assert ok is True

    # Case 1: Locked on B, candidate is B -> always allowed
    ok, _ = can_prevote_block(block_b, locked_block=block_b, locked_round=locked_round, polka_evidence=None, current_height=1)
    assert ok is True

    # Case 2: Locked on B, candidate is B', no evidence -> REFUSE
    ok, msg = can_prevote_block(block_b_prime, locked_block=block_b, locked_round=locked_round, polka_evidence=None, current_height=1)
    assert ok is False and "no polka evidence" in msg

    # Helper to construct a VoteSet evidence
    def make_evidence(height: int, round_num: int, phase: str, target_block_hash: str, vote_count: int) -> VoteSet:
        vs = VoteSet(height=height, round_num=round_num, phase=phase, validators=validators, quorum=quorum)
        for i in range(vote_count):
            v = Vote(chain_id=chain_id, height=height, round=round_num, phase=phase, block_hash=target_block_hash, validator_id=keypairs[i].public_key_hex)
            vs.add_vote(v)
        return vs

    # Case 3: Evidence round <= locked_round (round 1 <= 1) -> REFUSE
    ev_at_locked_round = make_evidence(height=1, round_num=1, phase=Phase.PREVOTE, target_block_hash=block_b_prime.hash(), vote_count=7)
    ok, msg = can_prevote_block(block_b_prime, locked_block=block_b, locked_round=1, polka_evidence=ev_at_locked_round, current_height=1)
    assert ok is False and "<= locked_round" in msg

    # Case 4: Evidence at another height (height 2 != 1) -> REFUSE
    ev_diff_height = make_evidence(height=2, round_num=2, phase=Phase.PREVOTE, target_block_hash=block_b_prime.hash(), vote_count=7)
    ok, msg = can_prevote_block(block_b_prime, locked_block=block_b, locked_round=1, polka_evidence=ev_diff_height, current_height=1)
    assert ok is False and "evidence height" in msg

    # Case 5: Evidence phase is PRECOMMIT not PREVOTE -> REFUSE
    ev_precommit = make_evidence(height=1, round_num=2, phase=Phase.PRECOMMIT, target_block_hash=block_b_prime.hash(), vote_count=7)
    ok, msg = can_prevote_block(block_b_prime, locked_block=block_b, locked_round=1, polka_evidence=ev_precommit, current_height=1)
    assert ok is False and "phase must be PREVOTE" in msg

    # Case 6: Evidence has insufficient votes (6 < 7) -> REFUSE
    ev_insufficient = make_evidence(height=1, round_num=2, phase=Phase.PREVOTE, target_block_hash=block_b_prime.hash(), vote_count=6)
    ok, msg = can_prevote_block(block_b_prime, locked_block=block_b, locked_round=1, polka_evidence=ev_insufficient, current_height=1)
    assert ok is False and "does not contain a 2f+1 quorum" in msg

    # Case 7: Evidence is for the ALREADY LOCKED block B in later round (does NOT authorize switching to B') -> REFUSE
    ev_for_already_locked = make_evidence(height=1, round_num=2, phase=Phase.PREVOTE, target_block_hash=block_b.hash(), vote_count=7)
    ok, msg = can_prevote_block(block_b_prime, locked_block=block_b, locked_round=1, polka_evidence=ev_for_already_locked, current_height=1)
    assert ok is False and "does not contain a 2f+1 quorum for replacement block" in msg

    # Case 8: Evidence is for ANOTHER block B'' (neither B nor B') -> REFUSE
    ev_for_other_block = make_evidence(height=1, round_num=2, phase=Phase.PREVOTE, target_block_hash=block_b_double_prime.hash(), vote_count=7)
    ok, msg = can_prevote_block(block_b_prime, locked_block=block_b, locked_round=1, polka_evidence=ev_for_other_block, current_height=1)
    assert ok is False and "does not contain a 2f+1 quorum for replacement block" in msg

    # Case 9: Valid 2f + 1 quorum for replacement block B' in round > locked_round (round 2 > 1) -> PERMIT!
    ev_valid_replacement = make_evidence(height=1, round_num=2, phase=Phase.PREVOTE, target_block_hash=block_b_prime.hash(), vote_count=7)
    ok, msg = can_prevote_block(block_b_prime, locked_block=block_b, locked_round=1, polka_evidence=ev_valid_replacement, current_height=1)
    assert ok is True and "observed valid later-round quorum for replacement block" in msg


def get_proposer_index(validators, height, round_num):
    return (height + round_num) % len(validators)


def test_proposer_rotation():
    """Verifies deterministic round-robin proposer rotation across heights and rounds."""
    validators = [f"val_{i}" for i in range(10)]
    assert get_proposer(validators, height=1, round_num=0) == "val_1"
    assert get_proposer(validators, height=1, round_num=1) == "val_2"
    assert get_proposer(validators, height=2, round_num=0) == "val_2"
    assert get_proposer(validators, height=2, round_num=8) == "val_0"
