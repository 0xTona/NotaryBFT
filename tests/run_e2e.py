"""Unified test runner and CLI entry point for Unit tests and scenarios T1-T8."""

import argparse
import hashlib
import os
import sys
import pytest
from src.byzantine.behaviors import ByzantineMode
from src.consensus.proposer import get_proposer
from src.core.types import Transaction
from src.crypto.keys import KeyPair
from src.crypto.sign import get_tx_domain, sign_payload
from src.logging.logger import DeterministicLogger
from src.network.link import NetworkFaultConfig, UnreliableTransport
from src.network.p2p import Node
from src.network.simulator import Simulator


def run_unit_tests() -> bool:
    print("\n=== Running Member 1 Unit Tests ===")
    ret = pytest.main([
        "tests/test_consensus.py",
        "tests/test_block_validation.py",
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

    ok1 = run_scenario_t1(seed=seed, log_file=log1)
    ok2 = run_scenario_t1(seed=seed, log_file=log2)

    if not (ok1 and ok2):
        print("[FAILED] T8 Failed: one of the simulation runs failed")
        return False

    with open(log1, "rb") as f1, open(log2, "rb") as f2:
        bytes1 = f1.read()
        bytes2 = f2.read()

    sha1 = hashlib.sha256(bytes1).hexdigest()
    sha2 = hashlib.sha256(bytes2).hexdigest()

    if bytes1 == bytes2:
        print(f"[SUCCESS] T8 Passed: Byte-identical logs verified!\n  Run 1 SHA256: {sha1}\n  Run 2 SHA256: {sha2}")
        return True
    else:
        print(f"[FAILED] T8 Failed: Log output differed across identical seeds!\n  Run 1 SHA256: {sha1}\n  Run 2 SHA256: {sha2}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Lab 01 Consensus Simulator CLI")
    parser.add_argument("--all", action="store_true", help="Run full suite: unit tests and scenarios")
    parser.add_argument("--scenario", type=str, choices=["T1", "T6", "T7", "T8"], help="Run a specific scenario")
    parser.add_argument("--nodes", type=int, default=10, help="Number of validator nodes (default: 10)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for simulation determinism")
    args = parser.parse_args()

    success = True
    if args.all or not args.scenario:
        success = run_unit_tests() and success
        success = run_scenario_t1(seed=args.seed) and success
        success = run_scenario_t6(seed=args.seed) and success
        success = run_scenario_t7(seed=args.seed) and success
        success = run_scenario_t8(seed=args.seed) and success
    elif args.scenario == "T1":
        success = run_scenario_t1(seed=args.seed)
    elif args.scenario == "T6":
        success = run_scenario_t6(seed=args.seed)
    elif args.scenario == "T7":
        success = run_scenario_t7(seed=args.seed)
    elif args.scenario == "T8":
        success = run_scenario_t8(seed=args.seed)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
