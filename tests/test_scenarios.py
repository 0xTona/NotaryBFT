"""Integration tests for scenarios T1, T6, and T7 (Member 1)."""

import pytest
from src.byzantine.behaviors import ByzantineMode
from src.consensus.proposer import TimeoutConfig, get_proposer
from src.core.types import Transaction, Vote
from src.crypto.keys import KeyPair
from src.crypto.sign import get_tx_domain, sign_payload
from src.logging.logger import DeterministicLogger
from src.network.link import NetworkFaultConfig, UnreliableTransport
from src.network.p2p import Node
from src.network.simulator import Simulator


def create_scenario_network(
    num_validators: int = 10,
    byzantine_count: int = 0,
    byzantine_mode: ByzantineMode = ByzantineMode.HONEST,
    seed: int = 42,
    fault_config: NetworkFaultConfig = None,
):
    chain_id = "layer1-testnet"
    simulator = Simulator(seed=seed)
    logger = DeterministicLogger()

    if fault_config is None:
        fault_config = NetworkFaultConfig(
            drop_rate=0.0,
            duplicate_rate=0.0,
            min_delay=0.05,
            max_delay=0.15,
            t_stabilize=0.0,  # network is stabilized from start for T1, T6, T7
            delta=0.2,
        )

    transport = UnreliableTransport(simulator, fault_config, logger, seed=seed)

    keypairs = [KeyPair.from_seed(f"val_{i}_seed_{seed}") for i in range(num_validators)]
    validators = [kp.public_key_hex for kp in keypairs]

    timeout_cfg = TimeoutConfig(
        timeout_propose_base=0.8,
        timeout_propose_delta=0.4,
        timeout_prevote_base=0.8,
        timeout_prevote_delta=0.4,
        timeout_precommit_base=0.8,
        timeout_precommit_delta=0.4,
    )

    nodes: list[Node] = []
    for i in range(num_validators):
        mode = ByzantineMode.HONEST
        if i < byzantine_count:
            mode = byzantine_mode

        node = Node(
            node_id=validators[i],
            chain_id=chain_id,
            validators=validators,
            keypair=keypairs[i],
            simulator=simulator,
            transport=transport,
            logger=logger,
            timeout_config=timeout_cfg,
            byzantine_mode=mode,
        )
        nodes.append(node)

    return {
        "chain_id": chain_id,
        "simulator": simulator,
        "transport": transport,
        "logger": logger,
        "nodes": nodes,
        "validators": validators,
        "keypairs": keypairs,
    }


def add_tx(nodes: list[Node], sender_kp: KeyPair, doc_id: str, doc_hash: str, nonce: int, chain_id: str):
    tx = Transaction(
        sender=sender_kp.public_key_hex,
        doc_id=doc_id,
        doc_hash=doc_hash,
        nonce=nonce,
    )
    tx.signature = sign_payload(sender_kp, get_tx_domain(chain_id), tx.signing_payload())
    for node in nodes:
        node.engine.mempool.append(tx)


def test_scenario_t1_normal_run():
    """T1: Normal run with no faults. All honest nodes finalize the exact same chain and state hash."""
    net = create_scenario_network(num_validators=10, byzantine_count=0)
    nodes = net["nodes"]
    sim = net["simulator"]
    chain_id = net["chain_id"]

    client_alice = KeyPair.from_seed("client_alice")
    client_bob = KeyPair.from_seed("client_bob")

    # Add transactions
    add_tx(nodes, client_alice, "doc_alice_1", "0x1111", 1, chain_id)
    add_tx(nodes, client_bob, "doc_bob_1", "0x2222", 1, chain_id)

    # Start consensus height 1 on all nodes
    for node in nodes:
        node.engine.start_height(1)

    # Run until height 1 finalized by all nodes
    sim.run_until_condition(
        condition=lambda: all(len(n.engine.ledger) >= 1 for n in nodes),
        max_time=15.0,
    )

    # Verify all nodes finalized height 1
    assert all(len(n.engine.ledger) >= 1 for n in nodes), "All nodes must finalize height 1"

    # Verify exact block hash convergence
    finalized_hashes = {n.engine.ledger[0].hash() for n in nodes}
    assert len(finalized_hashes) == 1, f"Expected 1 unique block hash, got: {finalized_hashes}"

    # Verify identical state hash across all nodes
    final_state_roots = {n.engine.committed_state.compute_merkle_root() for n in nodes}
    assert len(final_state_roots) == 1, f"Expected 1 unique state root, got: {final_state_roots}"

    # Verify documents in state
    alice_doc = nodes[0].engine.committed_state.get(f"{client_alice.public_key_hex}/docs/doc_alice_1")
    bob_doc = nodes[0].engine.committed_state.get(f"{client_bob.public_key_hex}/docs/doc_bob_1")
    assert alice_doc == "0x1111"
    assert bob_doc == "0x2222"


def test_scenario_t6_silent_crashed_proposer():
    """T6: Proposer is silent/crashed. Round timeouts trigger and next honest proposer finalizes block."""
    net = create_scenario_network(num_validators=10, byzantine_count=0)
    nodes = net["nodes"]
    sim = net["simulator"]
    validators = net["validators"]

    # Proposer for height 1, round 0 is val_1: index (1 + 0) % 10 = 1
    r0_proposer_id = get_proposer(validators, height=1, round_num=0)
    r0_proposer_node = next(n for n in nodes if n.node_id == r0_proposer_id)

    # Set round 0 proposer to SILENT_PROPOSER
    r0_proposer_node.byzantine_mode = ByzantineMode.SILENT_PROPOSER
    r0_proposer_node.transport.mark_byzantine(r0_proposer_node.node_id)

    # Start consensus height 1
    for node in nodes:
        node.engine.start_height(1)

    honest_nodes = [n for n in nodes if n != r0_proposer_node]

    # Run simulator: round 0 must time out, advance to round 1, where proposer is val_2 (honest)
    sim.run_until_condition(
        condition=lambda: all(len(n.engine.ledger) >= 1 for n in honest_nodes),
        max_time=25.0,
    )
    assert all(len(n.engine.ledger) >= 1 for n in honest_nodes), "Honest nodes must finalize height 1"

    # Assert block finalized at round 1, not round 0
    finalized_round = honest_nodes[0].engine.ledger[0].header.round
    assert finalized_round == 1, f"Expected block finalized at round 1 after round 0 timeout, got round {finalized_round}"

    # All honest nodes agree on finalized block hash
    honest_hashes = {n.engine.ledger[0].hash() for n in honest_nodes}
    assert len(honest_hashes) == 1, "Honest nodes must agree on block hash"


def test_scenario_t2_duplicate_and_reordered_messages():
    """T2: Duplicate and reordered messages. No double-counted votes, no conflicting finalization."""
    fault_cfg = NetworkFaultConfig(
        drop_rate=0.0,
        duplicate_rate=0.4,
        min_delay=0.02,
        max_delay=0.15,
        t_stabilize=0.0,
        delta=0.2,
    )
    net = create_scenario_network(num_validators=10, fault_config=fault_cfg, seed=123)
    nodes = net["nodes"]
    sim = net["simulator"]
    chain_id = net["chain_id"]

    client = KeyPair.from_seed("client_t2")
    add_tx(nodes, client, "doc_t2", "0x2222", 1, chain_id)

    for node in nodes:
        node.engine.start_height(1)

    sim.run_until_condition(
        condition=lambda: all(len(n.engine.ledger) >= 1 for n in nodes),
        max_time=20.0,
    )

    assert all(len(n.engine.ledger) >= 1 for n in nodes), "All nodes must finalize height 1"
    finalized_hashes = {n.engine.ledger[0].hash() for n in nodes}
    assert len(finalized_hashes) == 1, "Duplicate messages must not cause forks"
    state_roots = {n.engine.committed_state.compute_merkle_root() for n in nodes}
    assert len(state_roots) == 1, "State roots must match identically"


def test_scenario_t3_invalid_signature_and_cross_domain():
    """T3: Invalid signature and cross-domain replay rejection."""
    net = create_scenario_network(num_validators=10, seed=456)
    nodes = net["nodes"]
    chain_id = net["chain_id"]
    validators = net["validators"]

    # Injected vote with wrong domain (TX: instead of VOTE:)
    val_kp = net["keypairs"][0]
    bad_domain_vote = Vote(
        chain_id=chain_id,
        height=1,
        round=0,
        phase="PREVOTE",
        block_hash="0xabcd" * 16,
        validator_id=val_kp.public_key_hex,
    )
    bad_domain_vote.signature = sign_payload(val_kp, get_tx_domain(chain_id), bad_domain_vote.signing_payload())

    node1 = nodes[1]
    # Receiver validates and rejects
    node1.engine.on_receive_vote(bad_domain_vote)
    # The bad vote must not be added to vote sets
    vset = node1.engine.vote_sets.get((1, 0, "PREVOTE"))
    assert (vset is None) or (val_kp.public_key_hex not in vset.votes)


def test_scenario_t4_replayed_transaction_rejection():
    """T4: Replayed and duplicate transaction rejection; state changes applied at most once."""
    from src.core.state import State
    state = State()
    chain_id = "test-chain"
    client = KeyPair.from_seed("client_t4")

    # Apply transaction nonce 1
    tx1 = Transaction(sender=client.public_key_hex, doc_id="doc1", doc_hash="0x1111", nonce=1)
    tx1.signature = sign_payload(client, get_tx_domain(chain_id), tx1.signing_payload())

    ok1, _ = state.apply_transaction(tx1, chain_id)
    assert ok1 is True
    assert state.get(f"{client.public_key_hex}/nonce") == "1"

    # Replay same transaction with nonce 1
    ok2, err2 = state.apply_transaction(tx1, chain_id)
    assert ok2 is False
    assert "Invalid nonce: expected 2, got 1" in err2
    # Nonce remained 1, applied at most once
    assert state.get(f"{client.public_key_hex}/nonce") == "1"


def test_scenario_t5_unreliable_network_before_stabilization():
    """T5: Drop and delay before T_stabilize. Safety holds throughout, liveness recovered after stabilization."""
    fault_cfg = NetworkFaultConfig(
        drop_rate=0.25,
        duplicate_rate=0.2,
        min_delay=0.05,
        max_delay=0.25,
        t_stabilize=2.0,  # network stabilizes at 2.0s
        delta=0.2,
    )
    net = create_scenario_network(num_validators=10, fault_config=fault_cfg, seed=789)
    nodes = net["nodes"]
    sim = net["simulator"]
    chain_id = net["chain_id"]

    client = KeyPair.from_seed("client_t5")
    add_tx(nodes, client, "doc_t5", "0x5555", 1, chain_id)

    for node in nodes:
        node.engine.start_height(1)

    # Run past stabilization until finalization
    sim.run_until_condition(
        condition=lambda: all(len(n.engine.ledger) >= 1 for n in nodes),
        max_time=30.0,
    )

    # Check that safety holds: no conflicting finalized blocks
    for n in nodes:
        assert len(n.engine.ledger) >= 1, "Liveness failed: node did not finalize after stabilization"

    finalized_hashes = {n.engine.ledger[0].hash() for n in nodes}
    assert len(finalized_hashes) == 1, f"Safety violation under T5! Hashes: {finalized_hashes}"


def test_scenario_t7_byzantine_equivocation():
    """T7: Up to f (f=3 for n=10) Byzantine validators equivocate simultaneously. Safety preserved, zero forks."""
    # 10 validators, f = 3 Byzantine validators equivocating
    net = create_scenario_network(
        num_validators=10,
        byzantine_count=3,
        byzantine_mode=ByzantineMode.EQUIVOCATE_VOTES,
    )
    nodes = net["nodes"]
    sim = net["simulator"]
    chain_id = net["chain_id"]

    client = KeyPair.from_seed("client_t7")
    add_tx(nodes, client, "doc_t7", "0x7777", 1, chain_id)

    # Honest nodes are nodes[3..9] (7 honest nodes = 2f + 1 quorum)
    honest_nodes = nodes[3:]
    assert len(honest_nodes) == 7

    # Ensure round 0 proposer is an honest node (height=1, round=0 -> proposer is val_1, which is Byzantine!)
    # To test equivocation against honest proposer, choose height=3 (proposer is (3+0)%10 = val_3, honest!)
    for node in nodes:
        node.engine.start_height(3)

    sim.run_until_condition(
        condition=lambda: all(len(n.engine.ledger) >= 1 for n in honest_nodes),
        max_time=20.0,
    )

    assert all(len(n.engine.ledger) >= 1 for n in honest_nodes), "All honest nodes must reach finality"

    # Safety check: Zero forks! All honest nodes must agree on exact same finalized block hash
    finalized_hashes = {n.engine.ledger[0].hash() for n in honest_nodes}
    assert len(finalized_hashes) == 1, f"Safety violation! Found conflicting finalized hashes: {finalized_hashes}"
