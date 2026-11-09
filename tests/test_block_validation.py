"""Unit tests for Block Proposal Validation under Rule 3 (Member 1)."""

import pytest
from src.byzantine.behaviors import (
    create_invalid_header_signature_proposal,
    create_invalid_parent_proposal,
    create_invalid_state_root_proposal,
    create_invalid_tx_proposal,
)
from src.consensus.proposer import get_proposer
from src.consensus.rules import validate_block_proposal
from src.core.state import State
from src.core.types import Block, BlockHeader, Transaction, compute_txs_hash
from src.crypto.keys import KeyPair
from src.crypto.sign import (
    get_header_domain,
    get_tx_domain,
    get_vote_domain,
    sign_payload,
)


@pytest.fixture
def fixtures():
    chain_id = "test-chain"
    # 10 validators: n=10, f=3
    validator_kps = [KeyPair.from_seed(f"val_seed_{i}") for i in range(10)]
    validators = [kp.public_key_hex for kp in validator_kps]

    user_alice = KeyPair.from_seed("alice_seed")
    user_bob = KeyPair.from_seed("bob_seed")

    return {
        "chain_id": chain_id,
        "validator_kps": validator_kps,
        "validators": validators,
        "alice": user_alice,
        "bob": user_bob,
    }


def create_signed_tx(
    sender_kp: KeyPair,
    doc_id: str,
    doc_hash: str,
    nonce: int,
    chain_id: str,
    override_domain: str = None,
) -> Transaction:
    tx = Transaction(
        sender=sender_kp.public_key_hex,
        doc_id=doc_id,
        doc_hash=doc_hash,
        nonce=nonce,
    )
    domain = override_domain if override_domain is not None else get_tx_domain(chain_id)
    tx.signature = sign_payload(sender_kp, domain, tx.signing_payload())
    return tx


def build_valid_proposal(
    fixtures,
    height: int = 1,
    round_num: int = 0,
    parent_block: Block = None,
    parent_state: State = None,
    txs: list = None,
) -> tuple[Block, State]:
    chain_id = fixtures["chain_id"]
    validators = fixtures["validators"]
    validator_kps = fixtures["validator_kps"]

    if parent_state is None:
        parent_state = State()

    if txs is None:
        # Default valid transaction from Alice
        tx1 = create_signed_tx(
            sender_kp=fixtures["alice"],
            doc_id="whitepaper_v1",
            doc_hash="0xabcdef1234567890",
            nonce=1,
            chain_id=chain_id,
        )
        txs = [tx1]

    # Deterministically execute transactions to compute correct state_root
    working_state = parent_state.clone()
    for tx in txs:
        ok, err = working_state.apply_transaction(tx, chain_id)
        assert ok, f"Setup transaction application failed: {err}"

    expected_state_root = working_state.compute_merkle_root()
    expected_txs_hash = compute_txs_hash(txs)
    parent_hash = parent_block.hash() if parent_block is not None else "0" * 64

    # Determine correct proposer
    proposer_addr = get_proposer(validators, height, round_num)
    proposer_kp = next(kp for kp in validator_kps if kp.public_key_hex == proposer_addr)

    header = BlockHeader(
        chain_id=chain_id,
        height=height,
        round=round_num,
        parent_hash=parent_hash,
        state_root=expected_state_root,
        txs_hash=expected_txs_hash,
        proposer=proposer_addr,
        timestamp=1000,
    )
    header_domain = get_header_domain(chain_id)
    header.signature = sign_payload(proposer_kp, header_domain, header.signing_payload())

    block = Block(header=header, txs=txs)
    return block, working_state


def test_accept_fully_valid_proposal(fixtures):
    """Rule 3: Accepts a fully valid block proposal and produces correct updated state."""
    chain_id = fixtures["chain_id"]
    validators = fixtures["validators"]
    initial_state = State()
    committed_snapshot = initial_state.clone()

    valid_block, expected_state = build_valid_proposal(fixtures, parent_state=initial_state)

    is_valid, err, new_state = validate_block_proposal(
        block=valid_block,
        chain_id=chain_id,
        current_height=1,
        current_round=0,
        parent_block=None,
        parent_state=initial_state,
        validators=validators,
    )

    assert is_valid is True
    assert err == ""
    assert new_state is not None
    assert new_state.compute_merkle_root() == expected_state.compute_merkle_root()
    # Ensure initial state was unchanged
    assert initial_state.data == committed_snapshot.data


def test_reject_invalid_parent(fixtures):
    """Rule 3: Independently reject proposal with invalid parent hash."""
    chain_id = fixtures["chain_id"]
    validators = fixtures["validators"]
    validator_kps = fixtures["validator_kps"]
    initial_state = State()
    committed_snapshot = initial_state.clone()

    valid_block, _ = build_valid_proposal(fixtures, parent_state=initial_state)
    proposer_kp = next(kp for kp in validator_kps if kp.public_key_hex == valid_block.header.proposer)

    bad_block = create_invalid_parent_proposal(valid_block, proposer_kp, chain_id, corrupted_parent_hash="bad_parent_hash" * 4)

    is_valid, err, new_state = validate_block_proposal(
        block=bad_block,
        chain_id=chain_id,
        current_height=1,
        current_round=0,
        parent_block=None,
        parent_state=initial_state,
        validators=validators,
    )

    assert is_valid is False
    assert "parent hash mismatch" in err
    assert new_state is None
    assert initial_state.data == committed_snapshot.data


def test_reject_invalid_transaction_signature(fixtures):
    """Rule 3: Independently reject proposal containing transaction with invalid signature."""
    chain_id = fixtures["chain_id"]
    validators = fixtures["validators"]
    validator_kps = fixtures["validator_kps"]
    initial_state = State()
    committed_snapshot = initial_state.clone()

    # Valid tx, then tamper signature
    bad_tx = create_signed_tx(fixtures["alice"], "doc_bad_sig", "0x1234", 1, chain_id)
    bad_tx.signature = "ff" * 64

    valid_block, _ = build_valid_proposal(fixtures, parent_state=initial_state, txs=[])
    proposer_kp = next(kp for kp in validator_kps if kp.public_key_hex == valid_block.header.proposer)
    bad_block = create_invalid_tx_proposal(valid_block, proposer_kp, chain_id, bad_tx)

    is_valid, err, new_state = validate_block_proposal(
        block=bad_block,
        chain_id=chain_id,
        current_height=1,
        current_round=0,
        parent_block=None,
        parent_state=initial_state,
        validators=validators,
    )

    assert is_valid is False
    assert "Invalid transaction signature" in err
    assert new_state is None
    assert initial_state.data == committed_snapshot.data


def test_reject_invalid_transaction_domain(fixtures):
    """Rule 3: Independently reject transaction signed with incorrect domain separation (e.g. VOTE: instead of TX:)."""
    chain_id = fixtures["chain_id"]
    validators = fixtures["validators"]
    validator_kps = fixtures["validator_kps"]
    initial_state = State()
    committed_snapshot = initial_state.clone()

    # Sign tx using VOTE domain instead of TX domain
    bad_tx = create_signed_tx(
        fixtures["alice"],
        "doc_wrong_domain",
        "0x5555",
        1,
        chain_id,
        override_domain=get_vote_domain(chain_id),
    )

    valid_block, _ = build_valid_proposal(fixtures, parent_state=initial_state, txs=[])
    proposer_kp = next(kp for kp in validator_kps if kp.public_key_hex == valid_block.header.proposer)
    bad_block = create_invalid_tx_proposal(valid_block, proposer_kp, chain_id, bad_tx)

    is_valid, err, new_state = validate_block_proposal(
        block=bad_block,
        chain_id=chain_id,
        current_height=1,
        current_round=0,
        parent_block=None,
        parent_state=initial_state,
        validators=validators,
    )

    assert is_valid is False
    assert "Invalid transaction signature under domain TX:" in err
    assert new_state is None
    assert initial_state.data == committed_snapshot.data


def test_reject_unauthorized_state_ownership(fixtures):
    """Rule 3: Reject empty doc_id and transactions that do not conform to owner namespace."""
    chain_id = fixtures["chain_id"]
    validators = fixtures["validators"]
    validator_kps = fixtures["validator_kps"]
    initial_state = State()
    committed_snapshot = initial_state.clone()

    # Transaction with empty doc_id
    bad_tx = create_signed_tx(fixtures["alice"], "", "0x9999", 1, chain_id)

    valid_block, _ = build_valid_proposal(fixtures, parent_state=initial_state, txs=[])
    proposer_kp = next(kp for kp in validator_kps if kp.public_key_hex == valid_block.header.proposer)
    bad_block = create_invalid_tx_proposal(valid_block, proposer_kp, chain_id, bad_tx)

    is_valid, err, new_state = validate_block_proposal(
        block=bad_block,
        chain_id=chain_id,
        current_height=1,
        current_round=0,
        parent_block=None,
        parent_state=initial_state,
        validators=validators,
    )

    assert is_valid is False
    assert "cannot be empty" in err
    assert new_state is None
    assert initial_state.data == committed_snapshot.data


def test_reject_replayed_transaction(fixtures):
    """Rule 3: Independently reject proposal with replayed or out-of-order nonce transaction."""
    chain_id = fixtures["chain_id"]
    validators = fixtures["validators"]
    validator_kps = fixtures["validator_kps"]

    # Initial state already has Alice at nonce 1
    initial_state = State()
    initial_state.set(f"{fixtures['alice'].public_key_hex}/nonce", "1")
    committed_snapshot = initial_state.clone()

    # Replay nonce 1
    replayed_tx = create_signed_tx(fixtures["alice"], "doc_replay", "0xaaaa", nonce=1, chain_id=chain_id)

    valid_block, _ = build_valid_proposal(fixtures, parent_state=initial_state, txs=[])
    proposer_kp = next(kp for kp in validator_kps if kp.public_key_hex == valid_block.header.proposer)
    bad_block = create_invalid_tx_proposal(valid_block, proposer_kp, chain_id, replayed_tx)

    is_valid, err, new_state = validate_block_proposal(
        block=bad_block,
        chain_id=chain_id,
        current_height=1,
        current_round=0,
        parent_block=None,
        parent_state=initial_state,
        validators=validators,
    )

    assert is_valid is False
    assert "Invalid nonce: expected 2, got 1" in err
    assert new_state is None
    assert initial_state.data == committed_snapshot.data


def test_reject_mismatched_state_commitment(fixtures):
    """Rule 3: Independently reject proposal with mismatched/forged state commitment hash."""
    chain_id = fixtures["chain_id"]
    validators = fixtures["validators"]
    validator_kps = fixtures["validator_kps"]
    initial_state = State()
    committed_snapshot = initial_state.clone()

    valid_block, _ = build_valid_proposal(fixtures, parent_state=initial_state)
    proposer_kp = next(kp for kp in validator_kps if kp.public_key_hex == valid_block.header.proposer)

    bad_block = create_invalid_state_root_proposal(
        base_block=valid_block,
        keypair=proposer_kp,
        chain_id=chain_id,
        tampered_state_root="deadbeef" * 8,
    )

    is_valid, err, new_state = validate_block_proposal(
        block=bad_block,
        chain_id=chain_id,
        current_height=1,
        current_round=0,
        parent_block=None,
        parent_state=initial_state,
        validators=validators,
    )

    assert is_valid is False
    assert "State root mismatch" in err
    assert new_state is None
    assert initial_state.data == committed_snapshot.data


def test_reject_wrong_proposer(fixtures):
    """Rule 3: Independently reject proposal proposed by unauthorized validator for (height, round)."""
    chain_id = fixtures["chain_id"]
    validators = fixtures["validators"]
    validator_kps = fixtures["validator_kps"]
    initial_state = State()
    committed_snapshot = initial_state.clone()

    valid_block, _ = build_valid_proposal(fixtures, parent_state=initial_state)

    # Correct proposer is val_1 for (height=1, round=0). We tamper proposer to val_9.
    wrong_kp = validator_kps[9]
    bad_header = valid_block.header
    bad_header.proposer = wrong_kp.public_key_hex
    bad_header.signature = sign_payload(wrong_kp, get_header_domain(chain_id), bad_header.signing_payload())
    bad_block = Block(header=bad_header, txs=valid_block.txs)

    is_valid, err, new_state = validate_block_proposal(
        block=bad_block,
        chain_id=chain_id,
        current_height=1,
        current_round=0,
        parent_block=None,
        parent_state=initial_state,
        validators=validators,
    )

    assert is_valid is False
    assert "proposer mismatch" in err
    assert new_state is None
    assert initial_state.data == committed_snapshot.data


def test_reject_invalid_header_signature(fixtures):
    """Rule 3: Independently reject proposal with invalid header signature."""
    chain_id = fixtures["chain_id"]
    validators = fixtures["validators"]
    initial_state = State()
    committed_snapshot = initial_state.clone()

    valid_block, _ = build_valid_proposal(fixtures, parent_state=initial_state)
    bad_block = create_invalid_header_signature_proposal(valid_block, forged_signature="00" * 64)

    is_valid, err, new_state = validate_block_proposal(
        block=bad_block,
        chain_id=chain_id,
        current_height=1,
        current_round=0,
        parent_block=None,
        parent_state=initial_state,
        validators=validators,
    )

    assert is_valid is False
    assert "invalid header signature" in err
    assert new_state is None
    assert initial_state.data == committed_snapshot.data
