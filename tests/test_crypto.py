"""Unit tests for the cryptography layer: keys, canonical encoding, domain separation (Member 3)."""

import pytest
from src.core.types import BlockHeader, Phase, Transaction, Vote
from src.crypto.encoding import CanonicalEncodingError, canonical_encode, canonical_hash
from src.crypto.keys import KeyPair, is_valid_public_key_hex, public_key_from_hex
from src.crypto.sign import (
    construct_domain_payload,
    get_header_domain,
    get_tx_domain,
    get_vote_domain,
    sign_header,
    sign_payload,
    sign_transaction,
    sign_vote,
    verify_header_signature,
    verify_payload_signature,
    verify_transaction_signature,
    verify_vote_signature,
)

CHAIN = "test-chain"


@pytest.fixture
def kp():
    return KeyPair.from_seed("crypto_test_key")


def _vote(kp, **overrides):
    fields = dict(chain_id=CHAIN, height=5, round=2, phase=Phase.PREVOTE, block_hash="ab" * 32,
                  validator_id=kp.public_key_hex)
    fields.update(overrides)
    return Vote(**fields)


# --- Keys -------------------------------------------------------------------

def test_seeded_keys_are_reproducible_and_distinct():
    assert KeyPair.from_seed("a").public_key_hex == KeyPair.from_seed("a").public_key_hex
    assert KeyPair.from_seed("a").public_key_hex != KeyPair.from_seed("b").public_key_hex
    assert is_valid_public_key_hex(KeyPair.from_seed("a").public_key_hex)


def test_public_key_hex_must_be_canonical_lowercase(kp):
    assert not is_valid_public_key_hex(kp.public_key_hex.upper())
    assert not is_valid_public_key_hex(kp.public_key_hex[:-2])
    assert not is_valid_public_key_hex(None)
    with pytest.raises(ValueError):
        public_key_from_hex(kp.public_key_hex.upper())


# --- Canonical encoding ---------------------------------------------------------

def test_encoding_is_independent_of_key_insertion_order():
    assert canonical_encode({"b": 1, "a": [1, 2], "c": None}) == canonical_encode({"c": None, "a": [1, 2], "b": 1})
    assert canonical_encode({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'


def test_encoding_escapes_non_ascii_deterministically():
    assert canonical_encode({"k": "Việt"}) == b'{"k":"Vi\\u1ec7t"}'


def test_encoding_normalizes_enums():
    assert canonical_encode({"phase": Phase.PREVOTE}) == canonical_encode({"phase": "PREVOTE"})
    assert str(Phase.PREVOTE) == "PREVOTE" and f"{Phase.PRECOMMIT}" == "PRECOMMIT"


@pytest.mark.parametrize("bad", [1.5, float("nan"), b"raw", {1: "int key"}, {"s": {1, 2}}])
def test_encoding_rejects_non_canonical_types(bad):
    with pytest.raises(CanonicalEncodingError):
        canonical_encode(bad)


def test_canonical_hash_differs_on_any_field_change():
    assert canonical_hash({"a": 1}) != canonical_hash({"a": 2})
    assert canonical_hash({"a": "1"}) != canonical_hash({"a": 1})


# --- Domain separation ------------------------------------------------------------

def test_domain_strings():
    assert get_tx_domain(CHAIN) == "TX:test-chain"
    assert get_header_domain(CHAIN) == "HEADER:test-chain"
    assert get_vote_domain(CHAIN) == "VOTE:test-chain"
    with pytest.raises(ValueError):
        get_vote_domain("")


def test_domain_payload_is_length_prefixed():
    # Without the prefix "TX:a" + "bc" and "TX:ab" + "c" would collide
    assert construct_domain_payload("TX:a", b"bc") != construct_domain_payload("TX:ab", b"c")
    assert construct_domain_payload("TX:a", b"bc")[:4] == (4).to_bytes(4, "big")


def test_sign_and_verify_roundtrip(kp):
    payload = {"x": 1}
    sig = sign_payload(kp, get_tx_domain(CHAIN), payload)
    assert len(sig) == 128
    assert sig == sign_payload(kp, get_tx_domain(CHAIN), payload)  # Ed25519 is deterministic
    assert verify_payload_signature(kp.public_key_hex, get_tx_domain(CHAIN), payload, sig)


@pytest.mark.parametrize("signed_in,verified_in", [
    ("TX", "VOTE"), ("TX", "HEADER"), ("VOTE", "TX"), ("VOTE", "HEADER"), ("HEADER", "TX"), ("HEADER", "VOTE"),
])
def test_signature_never_validates_in_another_domain(kp, signed_in, verified_in):
    domains = {"TX": get_tx_domain, "VOTE": get_vote_domain, "HEADER": get_header_domain}
    payload = {"height": 1, "block_hash": "ab" * 32}
    sig = sign_payload(kp, domains[signed_in](CHAIN), payload)
    assert not verify_payload_signature(kp.public_key_hex, domains[verified_in](CHAIN), payload, sig)


def test_signature_never_validates_on_another_chain(kp):
    sig = sign_payload(kp, get_vote_domain("chain-a"), {"h": 1})
    assert not verify_payload_signature(kp.public_key_hex, get_vote_domain("chain-b"), {"h": 1}, sig)


def test_verification_rejects_wrong_key_tampering_and_malformed_input(kp):
    other = KeyPair.from_seed("other")
    domain = get_tx_domain(CHAIN)
    sig = sign_payload(kp, domain, {"v": 1})
    assert not verify_payload_signature(other.public_key_hex, domain, {"v": 1}, sig)
    assert not verify_payload_signature(kp.public_key_hex, domain, {"v": 2}, sig)
    assert not verify_payload_signature(kp.public_key_hex, domain, {"v": 1}, sig.upper())
    assert not verify_payload_signature(kp.public_key_hex, domain, {"v": 1}, "zz" * 64)
    assert not verify_payload_signature(kp.public_key_hex, domain, {"v": 1}, "")
    assert not verify_payload_signature("not-a-key", domain, {"v": 1}, sig)
    assert not verify_payload_signature(kp.public_key_hex, domain, {"v": 1.5}, sig)


# --- Typed helpers ------------------------------------------------------------------

def test_transaction_helpers(kp):
    tx = Transaction(sender=kp.public_key_hex, doc_id="d", doc_hash="0x01", nonce=1)
    sign_transaction(kp, tx, CHAIN)
    assert verify_transaction_signature(tx, CHAIN)
    assert not verify_transaction_signature(tx, "other-chain")
    tx.nonce = 2
    assert not verify_transaction_signature(tx, CHAIN)
    with pytest.raises(ValueError):
        sign_transaction(KeyPair.from_seed("x"), tx, CHAIN)


def test_header_helpers(kp):
    h = BlockHeader(chain_id=CHAIN, height=1, round=0, parent_hash="0" * 64, state_root="11" * 32,
                    txs_hash="22" * 32, proposer=kp.public_key_hex, timestamp=0)
    sign_header(kp, h)
    assert verify_header_signature(h, CHAIN)
    h.state_root = "33" * 32
    assert not verify_header_signature(h, CHAIN)


@pytest.mark.parametrize("field,value", [
    ("chain_id", "other-chain"), ("height", 6), ("round", 3), ("phase", Phase.PRECOMMIT), ("block_hash", None),
])
def test_vote_signature_binds_every_identifying_field(kp, field, value):
    v = _vote(kp)
    sign_vote(kp, v)
    assert verify_vote_signature(v, CHAIN)
    setattr(v, field, value)
    assert not verify_vote_signature(v, CHAIN), f"replay with changed {field} must fail"


def test_vote_phase_enum_and_string_sign_identically(kp):
    a, b = _vote(kp, phase=Phase.PREVOTE), _vote(kp, phase="PREVOTE")
    assert sign_vote(kp, a) == sign_vote(kp, b)
