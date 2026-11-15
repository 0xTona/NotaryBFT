"""Unit tests for state update rules, ownership, replay protection and Merkle commitment (Member 3)."""

import pytest
from src.core.executor import Executor
from src.core.state import (
    EMPTY_ROOT,
    State,
    merkle_leaf_hash,
    merkle_node_hash,
    validate_transaction_stateless,
)
from src.core.types import Block, BlockHeader, Transaction, compute_txs_hash
from src.crypto.encoding import sha256_hex
from src.crypto.keys import KeyPair
from src.crypto.sign import get_vote_domain, sign_payload, sign_transaction

CHAIN = "test-chain"


@pytest.fixture
def alice():
    return KeyPair.from_seed("state_alice")


@pytest.fixture
def bob():
    return KeyPair.from_seed("state_bob")


def tx(kp, doc_id="doc", nonce=1, content="hello", chain=CHAIN):
    t = Transaction(sender=kp.public_key_hex, doc_id=doc_id,
                    doc_hash="0x" + sha256_hex(content.encode()), nonce=nonce)
    sign_transaction(kp, t, chain)
    return t


# --- Merkle commitment ----------------------------------------------------------

def test_empty_root_is_sha256_of_empty_string():
    assert State().compute_merkle_root() == EMPTY_ROOT == sha256_hex(b"")


def test_root_independent_of_insertion_order():
    a = State({"k1": "v1", "k2": "v2", "k3": "v3"})
    b = State({"k3": "v3", "k1": "v1", "k2": "v2"})
    assert a.compute_merkle_root() == b.compute_merkle_root()


def test_root_matches_specified_tree_shape():
    s = State({"b": "2", "a": "1", "c": "3"})
    la, lb, lc = merkle_leaf_hash("a", "1"), merkle_leaf_hash("b", "2"), merkle_leaf_hash("c", "3")
    # Sorted leaves [a, b, c]; odd last node is promoted, not duplicated
    expected = merkle_node_hash(merkle_node_hash(la, lb), lc)
    assert s.compute_merkle_root() == expected.hex()
    assert State({"a": "1"}).compute_merkle_root() == la.hex()


def test_root_changes_with_any_key_or_value():
    base = State({"a": "1", "b": "2"}).compute_merkle_root()
    assert State({"a": "1", "b": "3"}).compute_merkle_root() != base
    assert State({"a": "1", "c": "2"}).compute_merkle_root() != base
    assert State({"a": "1"}).compute_merkle_root() != base


def test_leaf_encoding_is_unambiguous():
    # Naive "k=v" concatenation would make these two maps collide
    assert State({"a=b": "c"}).compute_merkle_root() != State({"a": "b=c"}).compute_merkle_root()
    # Duplicating the odd leaf must not be equivalent to the 3-leaf tree
    assert State({"a": "1", "b": "2", "c": "3"}).compute_merkle_root() != \
        merkle_node_hash(merkle_node_hash(merkle_leaf_hash("a", "1"), merkle_leaf_hash("b", "2")),
                         merkle_node_hash(merkle_leaf_hash("c", "3"), merkle_leaf_hash("c", "3"))).hex()


def test_leaf_and_inner_nodes_are_domain_separated():
    l1, l2 = merkle_leaf_hash("a", "1"), merkle_leaf_hash("b", "2")
    assert merkle_node_hash(l1, l2) != merkle_leaf_hash(l1.hex(), l2.hex())


def test_state_rejects_non_string_entries():
    with pytest.raises(TypeError):
        State().set("k", 1)


# --- Transaction application ------------------------------------------------------

def test_valid_tx_writes_only_sender_namespace(alice):
    s = State()
    t = tx(alice, "contract")
    ok, err = s.apply_transaction(t, CHAIN)
    assert ok, err
    assert s.data == {f"{alice.public_key_hex}/nonce": "1", f"{alice.public_key_hex}/docs/contract": t.doc_hash}


def test_example_two_participants_in_order_give_same_state(alice, bob):
    t1, t2 = tx(alice, "message", content="hello"), tx(bob, "message", content="hi")
    s1, s2 = State(), State()
    for s in (s1, s2):
        assert s.apply_transaction(t1, CHAIN)[0] and s.apply_transaction(t2, CHAIN)[0]
    assert s1.data == s2.data and len(s1.data) == 4
    assert s1.compute_merkle_root() == s2.compute_merkle_root()


def test_replay_applied_at_most_once(alice):
    s = State()
    t = tx(alice)
    assert s.apply_transaction(t, CHAIN)[0]
    snapshot = dict(s.data)
    ok, err = s.apply_transaction(t, CHAIN)
    assert not ok and "Invalid nonce: expected 2, got 1" in err
    assert s.data == snapshot


def test_nonce_gap_and_out_of_order_rejected(alice):
    s = State()
    assert not s.apply_transaction(tx(alice, nonce=2), CHAIN)[0]
    assert s.apply_transaction(tx(alice, nonce=1), CHAIN)[0]
    assert s.apply_transaction(tx(alice, "doc2", nonce=2), CHAIN)[0]
    assert s.get_nonce(alice.public_key_hex) == 2


def test_nonces_are_per_sender(alice, bob):
    s = State()
    assert s.apply_transaction(tx(alice), CHAIN)[0]
    assert s.apply_transaction(tx(bob), CHAIN)[0]


def test_overwrite_own_document_with_new_nonce(alice):
    s = State()
    s.apply_transaction(tx(alice, "d", 1, "v1"), CHAIN)
    t2 = tx(alice, "d", 2, "v2")
    assert s.apply_transaction(t2, CHAIN)[0]
    assert s.get(f"{alice.public_key_hex}/docs/d") == t2.doc_hash


def test_cannot_write_into_another_owner_namespace(alice, bob):
    # Bob signs a tx claiming Alice as sender: signature check fails, Alice's data untouched
    forged = Transaction(sender=alice.public_key_hex, doc_id="doc", doc_hash="0x01", nonce=1)
    forged.signature = sign_payload(bob, "TX:" + CHAIN, forged.signing_payload())
    s = State()
    ok, err = s.apply_transaction(forged, CHAIN)
    assert not ok and "Invalid transaction signature" in err and s.data == {}


@pytest.mark.parametrize("doc_id", ["", "../nonce", "a/b", "x" * 129, "sp ace"])
def test_doc_id_cannot_escape_namespace(alice, doc_id):
    t = Transaction(sender=alice.public_key_hex, doc_id=doc_id, doc_hash="0x01", nonce=1)
    sign_transaction(alice, t, CHAIN)
    ok, _ = State().apply_transaction(t, CHAIN)
    assert not ok


@pytest.mark.parametrize("doc_hash", ["1234", "0x", "0xZZ", "0xABCD", "0x" + "a" * 65, 5])
def test_doc_hash_format_enforced(alice, doc_hash):
    t = Transaction(sender=alice.public_key_hex, doc_id="d", doc_hash=doc_hash, nonce=1)
    t.signature = sign_payload(alice, "TX:" + CHAIN, t.signing_payload())
    assert not State().apply_transaction(t, CHAIN)[0]


@pytest.mark.parametrize("nonce", [0, -1, 2**64, True, "1"])
def test_nonce_range_enforced(alice, nonce):
    t = Transaction(sender=alice.public_key_hex, doc_id="d", doc_hash="0x01", nonce=nonce)
    t.signature = sign_payload(alice, "TX:" + CHAIN, t.signing_payload())
    assert not State().apply_transaction(t, CHAIN)[0]


def test_non_canonical_sender_rejected(alice):
    t = Transaction(sender=alice.public_key_hex.upper(), doc_id="d", doc_hash="0x01", nonce=1)
    assert not State().apply_transaction(t, CHAIN)[0]


def test_wrong_domain_and_wrong_chain_rejected(alice):
    t = Transaction(sender=alice.public_key_hex, doc_id="d", doc_hash="0x01", nonce=1)
    t.signature = sign_payload(alice, get_vote_domain(CHAIN), t.signing_payload())
    ok, err = validate_transaction_stateless(t, CHAIN)
    assert not ok and "under domain TX:test-chain" in err
    assert not State().apply_transaction(tx(alice, chain="other-chain"), CHAIN)[0]


# --- Block execution ------------------------------------------------------------------

def _block(txs, state_root):
    h = BlockHeader(chain_id=CHAIN, height=1, round=0, parent_hash="0" * 64, state_root=state_root,
                    txs_hash=compute_txs_hash(txs), proposer="00" * 32, timestamp=0)
    return Block(header=h, txs=txs)


def test_execute_block_success_and_receipts(alice, bob):
    txs = [tx(alice), tx(bob)]
    expected = State()
    for t in txs:
        expected.apply_transaction(t, CHAIN)
    parent = State()
    ok, new_state, root, receipts, err = Executor.execute_block(parent, _block(txs, expected.compute_merkle_root()), CHAIN)
    assert ok, err
    assert root == expected.compute_merkle_root() and new_state.data == expected.data
    assert [r.status for r in receipts] == [True, True] and receipts[0].tx_hash == txs[0].hash()
    assert parent.data == {}  # parent state is never mutated


def test_execute_block_is_atomic_on_invalid_tx(alice):
    good, replay = tx(alice), tx(alice)
    parent = State()
    ok, returned, _, receipts, err = Executor.execute_block(parent, _block([good, replay], EMPTY_ROOT), CHAIN)
    assert not ok and "Invalid nonce" in err
    assert returned is parent and parent.data == {}
    assert [r.status for r in receipts] == [True, False]


def test_execute_block_rejects_state_root_and_txs_hash_mismatch(alice):
    t = tx(alice)
    ok, _, _, _, err = Executor.execute_block(State(), _block([t], "ff" * 32), CHAIN)
    assert not ok and "State root mismatch" in err
    b = _block([t], EMPTY_ROOT)
    b.txs = []
    ok, _, _, _, err = Executor.execute_block(State(), b, CHAIN)
    assert not ok and "txs_hash mismatch" in err


def test_execution_deterministic_across_independent_nodes(alice, bob):
    txs = [tx(alice, "a", 1), tx(bob, "b", 1), tx(alice, "c", 2)]
    roots = set()
    for _ in range(3):
        s = State()
        for t in txs:
            assert s.apply_transaction(t, CHAIN)[0]
        roots.add(s.compute_merkle_root())
    assert len(roots) == 1
