"""Unified test runner and CLI entry point for Unit tests and scenarios T1-T8."""

import argparse
import hashlib
import os
import sys

# Ensure repository root and site-packages are in sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if "/tmp/site-packages" not in sys.path and os.path.exists("/tmp/site-packages"):
    sys.path.insert(0, "/tmp/site-packages")

import pytest
from src.byzantine.behaviors import ByzantineMode
from src.consensus.proposer import get_proposer
from src.core.types import Transaction, Vote
from src.crypto.keys import KeyPair
from src.crypto.sign import get_tx_domain, sign_payload
from src.logging.logger import DeterministicLogger
from src.network.link import NetworkFaultConfig, UnreliableTransport
from src.network.p2p import Node
from src.network.simulator import Simulator


def run_unit_tests() -> bool:
    print("\n=== Running Unit Test Suites (Member 1 & Member 2) ===")
    ret = pytest.main([
        "tests/test_consensus.py",
        "tests/test_block_validation.py",
        "tests/test_network.py",
        "-v",
    ])
    return ret == 0


def setup_simulation(
    num_nodes: int = 10,
    byzantine_count: int = 0,
    byzantine_mode: ByzantineMode = ByzantineMode.HONEST,
    seed: int = 42,
    t_stabilize: float = 0.0,
    delta: float = 0.2,
    drop_rate: float = 0.0,
    duplicate_rate: float = 0.0,
    log_file: str = None,
):
    if num_nodes < 8 or (num_nodes - 1) % 3 != 0:
        raise ValueError(f"Invalid validator configuration: n={num_nodes} must satisfy n >= 8 and n = 3f + 1")

    chain_id = "layer1-chain"
    simulator = Simulator(seed=seed)
    logger = DeterministicLogger()

    fault_cfg = NetworkFaultConfig(
        drop_rate=drop_rate,
        duplicate_rate=duplicate_rate,
        min_delay=0.05,
        max_delay=0.15,
        t_stabilize=t_stabilize,
        delta=delta,
    )
    transport = UnreliableTransport(simulator, fault_cfg, logger, seed=seed)

    keypairs = [KeyPair.from_seed(f"val_key_{i}_seed_{seed}") for i in range(num_nodes)]
    validators = [kp.public_key_hex for kp in keypairs]

    nodes: list[Node] = []
    for i in range(num_nodes):
        mode = byzantine_mode if i < byzantine_count else ByzantineMode.HONEST
        node = Node(
            node_id=validators[i],
            chain_id=chain_id,
            validators=validators,
            keypair=keypairs[i],
            simulator=simulator,
            transport=transport,
            logger=logger,
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
        "log_file": log_file,
    }


def run_scenario_t1(seed: int = 42, log_file: str = None) -> bool:
    print(f"\n--- Running Scenario T1 (Normal Run, seed={seed}) ---")
    sim_data = setup_simulation(num_nodes=10, byzantine_count=0, seed=seed, log_file=log_file)
    nodes = sim_data["nodes"]
    sim = sim_data["simulator"]
    chain_id = sim_data["chain_id"]

    # Add client transactions
    alice = KeyPair.from_seed("alice")
    bob = KeyPair.from_seed("bob")
    for kp, doc, hsh, nonce in [(alice, "doc_a", "0x1111", 1), (bob, "doc_b", "0x2222", 1)]:
        tx = Transaction(sender=kp.public_key_hex, doc_id=doc, doc_hash=hsh, nonce=nonce)
        tx.signature = sign_payload(kp, get_tx_domain(chain_id), tx.signing_payload())
        for n in nodes:
            n.engine.mempool.append(tx)

    for n in nodes:
        n.engine.start_height(1)

    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in nodes), max_time=15.0)

    hashes = {n.engine.ledger[0].hash() for n in nodes if n.engine.ledger}
    state_roots = {n.engine.committed_state.compute_merkle_root() for n in nodes}

    ok = len(hashes) == 1 and len(state_roots) == 1 and all(len(n.engine.ledger) >= 1 for n in nodes)
    if ok:
        print(f"[SUCCESS] T1 Passed: 10/10 nodes finalized block {list(hashes)[0][:12]} with state root {list(state_roots)[0][:12]}")
    else:
        print(f"[FAILED] T1 Failed: hashes={hashes}, state_roots={state_roots}")

    if log_file:
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        sim_data["logger"].write_to_file(log_file)
    return ok


def run_scenario_t2(seed: int = 42) -> bool:
    print(f"\n--- Running Scenario T2 (Duplicate/Reordered Messages, seed={seed}) ---")
    fault_cfg = NetworkFaultConfig(
        drop_rate=0.0,
        duplicate_rate=0.4,
        min_delay=0.02,
        max_delay=0.15,
        t_stabilize=0.0,
        delta=0.2,
    )
    sim_data = setup_simulation(num_nodes=10, seed=seed, duplicate_rate=0.4)
    nodes = sim_data["nodes"]
    sim = sim_data["simulator"]
    chain_id = sim_data["chain_id"]

    client = KeyPair.from_seed("client_t2")
    tx = Transaction(sender=client.public_key_hex, doc_id="doc_t2", doc_hash="0x2222", nonce=1)
    tx.signature = sign_payload(client, get_tx_domain(chain_id), tx.signing_payload())
    for n in nodes:
        n.engine.mempool.append(tx)

    for n in nodes:
        n.engine.start_height(1)

    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in nodes), max_time=20.0)
    ok = all(len(n.engine.ledger) >= 1 for n in nodes)
    if ok:
        hashes = {n.engine.ledger[0].hash() for n in nodes}
        ok = len(hashes) == 1
        if ok:
            print(f"[SUCCESS] T2 Passed: No double counting or forks under duplicate messages. Block {list(hashes)[0][:12]}")
    return ok


def run_scenario_t3(seed: int = 42) -> bool:
    print(f"\n--- Running Scenario T3 (Invalid Signature / Wrong Domain, seed={seed}) ---")
    sim_data = setup_simulation(num_nodes=10, seed=seed)
    nodes = sim_data["nodes"]
    chain_id = sim_data["chain_id"]
    val_kp = sim_data["keypairs"][0]

    # Injected vote with wrong domain (TX: instead of VOTE:)
    bad_vote = Vote(
        chain_id=chain_id,
        height=1,
        round=0,
        phase="PREVOTE",
        block_hash="0xabcd" * 16,
        validator_id=val_kp.public_key_hex,
    )
    bad_vote.signature = sign_payload(val_kp, get_tx_domain(chain_id), bad_vote.signing_payload())

    node1 = nodes[1]
    node1.engine.on_receive_vote(bad_vote)
    vset = node1.engine.vote_sets.get((1, 0, "PREVOTE"))
    ok = (vset is None) or (val_kp.public_key_hex not in vset.votes)
    if ok:
        print("[SUCCESS] T3 Passed: Invalid domain signature rejected by consensus guard")
    return ok


def run_scenario_t4(seed: int = 42) -> bool:
    print(f"\n--- Running Scenario T4 (Replayed/Duplicate Tx Rejection, seed={seed}) ---")
    from src.core.state import State
    state = State()
    chain_id = "test-chain"
    client = KeyPair.from_seed("client_t4")

    tx1 = Transaction(sender=client.public_key_hex, doc_id="doc1", doc_hash="0x1111", nonce=1)
    tx1.signature = sign_payload(client, get_tx_domain(chain_id), tx1.signing_payload())

    ok1, _ = state.apply_transaction(tx1, chain_id)
    ok2, err2 = state.apply_transaction(tx1, chain_id)
    ok = ok1 and (not ok2) and ("Invalid nonce" in err2)
    if ok:
        print(f"[SUCCESS] T4 Passed: Replayed tx rejected correctly ({err2})")
    return ok


def run_scenario_t5(seed: int = 42) -> bool:
    print(f"\n--- Running Scenario T5 (Drop & Delay Before Stabilize, seed={seed}) ---")
    sim_data = setup_simulation(
        num_nodes=10,
        seed=seed,
        drop_rate=0.25,
        duplicate_rate=0.2,
        t_stabilize=2.0,
        delta=0.2,
    )
    nodes = sim_data["nodes"]
    sim = sim_data["simulator"]
    transport = sim_data["transport"]
    chain_id = sim_data["chain_id"]

    client = KeyPair.from_seed("client_t5")
    tx = Transaction(sender=client.public_key_hex, doc_id="doc_t5", doc_hash="0x5555", nonce=1)
    tx.signature = sign_payload(client, get_tx_domain(chain_id), tx.signing_payload())
    for n in nodes:
        n.engine.mempool.append(tx)

    for n in nodes:
        n.engine.start_height(1)

    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in nodes), max_time=30.0)

    # 1. Assert liveness: all honest nodes finalized height 1
    all_finalized = all(len(n.engine.ledger) >= 1 for n in nodes)

    # 2. Assert safety: no conflicting blocks or state roots at height 1
    hashes = {n.engine.ledger[0].hash() for n in nodes} if all_finalized else set()
    state_roots = {n.engine.committed_state.compute_merkle_root() for n in nodes} if all_finalized else set()
    safety_ok = (len(hashes) == 1) and (len(state_roots) == 1)

    # 3. Assert partial synchrony bound: zero drops post-stabilization for honest nodes
    zero_drops = (transport.stabilized_drops == 0)

    # 4. Assert Delta delivery bound for all post-stabilization deliveries
    deliveries = transport.stabilized_deliveries
    delta_bound_ok = (len(deliveries) > 0) and all(d["delay"] <= transport.config.delta + 1e-6 for d in deliveries)

    ok = all_finalized and safety_ok and zero_drops and delta_bound_ok
    if ok:
        print(f"[SUCCESS] T5 Passed: Safety preserved during drops, liveness achieved after stabilization. Zero drops post-stabilization ({len(deliveries)} msgs within delta={transport.config.delta}s). Block {list(hashes)[0][:12]}")
    else:
        print(f"[FAILED] T5 Failed: all_finalized={all_finalized}, safety_ok={safety_ok}, zero_drops={zero_drops}, delta_bound_ok={delta_bound_ok}")
    return ok


def run_scenario_t6(seed: int = 42) -> bool:
    print(f"\n--- Running Scenario T6 (Silent Proposer Timeout, seed={seed}) ---")
    sim_data = setup_simulation(num_nodes=10, byzantine_count=0, seed=seed)
    nodes = sim_data["nodes"]
    sim = sim_data["simulator"]
    validators = sim_data["validators"]

    # Proposer for height 1, round 0 is val_1
    proposer_addr = get_proposer(validators, 1, 0)
    proposer_node = next(n for n in nodes if n.node_id == proposer_addr)
    proposer_node.byzantine_mode = ByzantineMode.SILENT_PROPOSER
    proposer_node.transport.mark_byzantine(proposer_node.node_id)

    honest_nodes = [n for n in nodes if n != proposer_node]

    for n in nodes:
        n.engine.start_height(1)

    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in honest_nodes), max_time=25.0)

    ok = all(len(n.engine.ledger) >= 1 for n in honest_nodes)
    if ok:
        finalized_round = honest_nodes[0].engine.ledger[0].header.round
        hashes = {n.engine.ledger[0].hash() for n in honest_nodes}
        ok = (finalized_round == 1) and (len(hashes) == 1)
        if ok:
            print(f"[SUCCESS] T6 Passed: Round 0 timed out, block finalized at Round 1 with hash {list(hashes)[0][:12]}")
        else:
            print(f"[FAILED] T6 Failed: expected round 1, got {finalized_round}, hashes={hashes}")
    else:
        print("[FAILED] T6 Failed: honest nodes failed to finalize block")
    return ok


def run_scenario_t7(seed: int = 42) -> bool:
    print(f"\n--- Running Scenario T7 (Byzantine Equivocation, f=3, seed={seed}) ---")
    # n=10, f=3 Byzantine nodes equivocating
    sim_data = setup_simulation(
        num_nodes=10,
        byzantine_count=3,
        byzantine_mode=ByzantineMode.EQUIVOCATE_VOTES,
        seed=seed,
    )
    nodes = sim_data["nodes"]
    sim = sim_data["simulator"]
    chain_id = sim_data["chain_id"]

    client = KeyPair.from_seed("client_t7")
    tx = Transaction(sender=client.public_key_hex, doc_id="doc_t7", doc_hash="0x7777", nonce=1)
    tx.signature = sign_payload(client, get_tx_domain(chain_id), tx.signing_payload())
    for n in nodes:
        n.engine.mempool.append(tx)

    honest_nodes = nodes[3:]  # 7 honest nodes
    for n in nodes:
        n.engine.start_height(3)  # Height 3 has honest proposer val_3

    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in honest_nodes), max_time=20.0)

    hashes = {n.engine.ledger[0].hash() for n in honest_nodes if n.engine.ledger}
    ok = all(len(n.engine.ledger) >= 1 for n in honest_nodes) and len(hashes) == 1
    if ok:
        print(f"[SUCCESS] T7 Passed: Safety preserved under 3 equivocating validators. Unique block hash {list(hashes)[0][:12]}")
    else:
        print(f"[FAILED] T7 Failed: Safety violation or liveness failure. hashes={hashes}")
    return ok


def run_scenario_t8(seed: int = 42) -> bool:
    print(f"\n--- Running Scenario T8 (Determinism Replay Check, seed={seed}) ---")
    log1 = "logs/t8_run1.log"
    log2 = "logs/t8_run2.log"

    def execute_deterministic_simulation(out_log: str) -> tuple[bool, str]:
        sim_data = setup_simulation(
            num_nodes=10,
            seed=seed,
            drop_rate=0.2,
            duplicate_rate=0.1,
            t_stabilize=1.5,
            delta=0.2,
            log_file=out_log,
        )
        nodes = sim_data["nodes"]
        sim = sim_data["simulator"]
        logger = sim_data["logger"]
        chain_id = sim_data["chain_id"]

        # Schedule overactive peer burst to exercise BLOCK and UNBLOCK events deterministically
        sim.schedule_event(
            0.05,
            lambda: [nodes[0].handle_message("spam_test_peer", {"type": "SPAM", "seq": i}) for i in range(35)],
        )

        client = KeyPair.from_seed("client_t8")
        tx = Transaction(sender=client.public_key_hex, doc_id="doc_t8", doc_hash="0x8888", nonce=1)
        tx.signature = sign_payload(client, get_tx_domain(chain_id), tx.signing_payload())
        for n in nodes:
            n.engine.mempool.append(tx)

        for n in nodes:
            n.engine.start_height(1)

        sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in nodes), max_time=25.0)

        all_finalized = all(len(n.engine.ledger) >= 1 for n in nodes)
        state_root = nodes[0].engine.committed_state.compute_merkle_root() if all_finalized else ""

        if out_log:
            os.makedirs(os.path.dirname(out_log) or ".", exist_ok=True)
            logger.write_to_file(out_log)

        return all_finalized, state_root

    ok1, state_root1 = execute_deterministic_simulation(log1)
    ok2, state_root2 = execute_deterministic_simulation(log2)

    if not (ok1 and ok2):
        print("[FAILED] T8 Failed: one of the simulation runs failed to finalize")
        return False

    if state_root1 != state_root2:
        print(f"[FAILED] T8 Failed: state roots differed across identical seeds! {state_root1} != {state_root2}")
        return False

    with open(log1, "rb") as f1, open(log2, "rb") as f2:
        bytes1 = f1.read()
        bytes2 = f2.read()

    sha1 = hashlib.sha256(bytes1).hexdigest()
    sha2 = hashlib.sha256(bytes2).hexdigest()

    if bytes1 != bytes2:
        print(f"[FAILED] T8 Failed: Log output differed across identical seeds!\n  Run 1 SHA256: {sha1}\n  Run 2 SHA256: {sha2}")
        return False

    log_str = bytes1.decode("utf-8")
    missing_events = [
        evt for evt in ["SEND", "DROP", "DELAY", "BLOCK", "UNBLOCK", "PROPOSE", "PREVOTE", "PRECOMMIT", "FINALIZE"]
        if f"[{evt}]" not in log_str
    ]
    if missing_events:
        print(f"[FAILED] T8 Failed: Log output missing required events: {missing_events}")
        return False

    print(f"[SUCCESS] T8 Passed: Byte-identical logs verified!\n  Run 1 SHA256: {sha1}\n  Run 2 SHA256: {sha2}\n  Identical final state root: {state_root1[:12]}\n  Verified presence of all required event types: SEND, DROP, DELAY, BLOCK, UNBLOCK, PROPOSE, PREVOTE, PRECOMMIT, FINALIZE")
    return True


def main():
    parser = argparse.ArgumentParser(description="Lab 01 Consensus Simulator CLI")
    parser.add_argument("--all", action="store_true", help="Run full suite: unit tests and scenarios")
    parser.add_argument("--scenario", type=str, choices=["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8"], help="Run a specific scenario")
    parser.add_argument("--nodes", type=int, default=10, help="Number of validator nodes (default: 10)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for simulation determinism")
    args = parser.parse_args()

    scenarios = {
        "T1": lambda: run_scenario_t1(seed=args.seed),
        "T2": lambda: run_scenario_t2(seed=args.seed),
        "T3": lambda: run_scenario_t3(seed=args.seed),
        "T4": lambda: run_scenario_t4(seed=args.seed),
        "T5": lambda: run_scenario_t5(seed=args.seed),
        "T6": lambda: run_scenario_t6(seed=args.seed),
        "T7": lambda: run_scenario_t7(seed=args.seed),
        "T8": lambda: run_scenario_t8(seed=args.seed),
    }

    success = True
    if args.all or not args.scenario:
        success = run_unit_tests() and success
        for name, fn in scenarios.items():
            success = fn() and success
    elif args.scenario in scenarios:
        success = scenarios[args.scenario]()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
