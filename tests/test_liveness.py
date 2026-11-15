"""Regression tests for catch-up / liveness paths (late proposals, future headers,
reproposals, block sync and commit-certificate serving)."""

import pytest
from src.consensus.engine import ConsensusEngine
from src.consensus.proposer import get_proposer
from src.core.state import State
from src.core.types import Block, BlockHeader, Phase, Vote, compute_txs_hash
from src.crypto.keys import KeyPair
from src.crypto.sign import sign_header, sign_vote
from tests.run_e2e import RunConfig, _default_genesis, run_scenario_t1, run_scenario_t5, run_scenario_t8

CHAIN = "liveness-chain"


@pytest.fixture
def net():
    kps = [KeyPair.from_seed(f"live_{i}") for i in range(10)]
    return {"kps": kps, "vals": [k.public_key_hex for k in kps]}


def make_block(net, height, round_num, parent_hash="0" * 64):
    vals, kps = net["vals"], net["kps"]
    proposer = get_proposer(vals, height, round_num)
    h = BlockHeader(chain_id=CHAIN, height=height, round=round_num, parent_hash=parent_hash,
                    state_root=State().compute_merkle_root(), txs_hash=compute_txs_hash([]),
                    proposer=proposer, timestamp=0)
    sign_header(kps[vals.index(proposer)], h)
    return Block(header=h, txs=[])


def precommits(net, height, round_num, block_hash, count=7, start=0):
    out = []
    for kp in net["kps"][start:start + count]:
        v = Vote(chain_id=CHAIN, height=height, round=round_num, phase=Phase.PRECOMMIT,
                 block_hash=block_hash, validator_id=kp.public_key_hex)
        sign_vote(kp, v)
        out.append(v)
    return out


def engine(net, idx=9, **kw):
    return ConsensusEngine(node_id=net["vals"][idx], chain_id=CHAIN, validators=net["vals"],
                           keypair=net["kps"][idx], **kw)


def test_late_proposal_after_precommit_quorum_is_finalized(net):
    e = engine(net)
    requested = []
    e.request_block_fn = lambda *a: requested.append(a)
    e.start_height(1)
    block = make_block(net, 1, 0)
    for v in precommits(net, 1, 0, block.hash()):
        e.on_receive_vote(v)
    assert e.ledger == [] and requested and requested[0][0] == block.hash()
    e.on_receive_proposal(block)  # body arrives after the votes
    assert [b.hash() for b in e.ledger] == [block.hash()] and e.height == 2


def test_future_height_proposal_is_buffered_and_used(net):
    e = engine(net)
    e.start_height(1)
    b1 = make_block(net, 1, 0)
    b2 = make_block(net, 2, 0, parent_hash=b1.hash())
    e.on_receive_proposal(b2)  # arrives while still at height 1
    assert e.proposal_blocks[(2, 0)] is b2
    e.on_receive_proposal(b1)
    for v in precommits(net, 1, 0, b1.hash()):
        e.on_receive_vote(v)
    assert e.height == 2 and e.step.value == "PREVOTE"  # prevoted the buffered block at once
    assert e.signing_tracker.signed_prevotes[(2, 0)].block_hash == b2.hash()


def test_buffered_precommits_for_next_height_commit_on_arrival(net):
    e = engine(net)
    e.start_height(1)
    b1 = make_block(net, 1, 0)
    b2 = make_block(net, 2, 0, parent_hash=b1.hash())
    e.on_receive_proposal(b2)
    for v in precommits(net, 2, 0, b2.hash()):   # next height decided before we finish h1
        e.on_receive_vote(v)
    e.on_receive_proposal(b1)
    for v in precommits(net, 1, 0, b1.hash()):
        e.on_receive_vote(v)
    assert [b.hash() for b in e.ledger] == [b1.hash(), b2.hash()] and e.height == 3


def test_reproposal_keeps_block_hash(net):
    vals = net["vals"]
    # Validator that proposes at (height 1, round 1)
    idx = vals.index(get_proposer(vals, 1, 1))
    e = engine(net, idx)
    e.start_height(1)
    b0 = make_block(net, 1, 0)
    e.valid_block, e.valid_round = b0, 0
    e.locked_block, e.locked_round = b0, 0
    assert e._create_proposal() is b0  # same header, same signature, same hash


def test_locked_validator_prevotes_reproposal_in_later_round(net):
    e = engine(net)
    e.start_height(1)
    b0 = make_block(net, 1, 0)
    e.on_receive_proposal(b0)
    e.locked_block, e.locked_round = b0, 0
    e.start_round(1)
    e.on_receive_proposal(b0, proposal_round=1)
    assert e.signing_tracker.signed_prevotes[(1, 1)].block_hash == b0.hash()


def test_finalize_records_commit_certificate(net):
    e = engine(net)
    e.start_height(1)
    b = make_block(net, 1, 0)
    e.on_receive_proposal(b)
    for v in precommits(net, 1, 0, b.hash()):
        e.on_receive_vote(v)
    cert = e.commit_certificates[1]
    assert len(cert) >= 7 and all(v.block_hash == b.hash() for v in cert)


@pytest.mark.parametrize("seed", [1, 3, 6, 8, 10])
def test_scenarios_live_across_seeds(seed, tmp_path):
    """Seeds that previously stalled (lagging nodes, lock splits, lost precommits)."""
    cfg = RunConfig(genesis=_default_genesis(), seed=seed, log_dir=str(tmp_path))
    assert run_scenario_t1(cfg)
    assert run_scenario_t5(cfg)
    assert run_scenario_t8(cfg)
