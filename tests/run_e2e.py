"""Unified test runner and CLI entry point for unit tests and scenarios T1-T8.

Examples (run from the repository root):

    python -m tests.run_e2e --all                    # unit suites + T1..T8
    python -m tests.run_e2e --unit                   # unit suites only
    python -m tests.run_e2e --scenario T1 T8         # selected scenarios
    python -m tests.run_e2e --scenario T5 --nodes 13 --seed 7 --t-stabilize 3 --delta 0.25

Network flags (--t-stabilize, --delta, --drop-rate, --duplicate-rate, --min-delay,
--max-delay) are optional overrides; when omitted each scenario uses its own
fault profile. Logs are written to <log-dir>/<scenario>.log.
"""

import argparse
from dataclasses import dataclass, field
import hashlib
import os
import sys
from typing import Callable, Dict, List, Optional

# Ensure repository root and site-packages are in sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if "/tmp/site-packages" not in sys.path and os.path.exists("/tmp/site-packages"):
    sys.path.insert(0, "/tmp/site-packages")

import pytest
from src.byzantine.behaviors import ByzantineMode, create_invalid_tx_proposal
from src.consensus.proposer import get_proposer
from src.consensus.rules import validate_block_proposal
from src.core.genesis import Genesis, load_genesis, validate_validator_count
from src.core.state import State
from src.core.types import Block, BlockHeader, Phase, Transaction, Vote, compute_txs_hash
from src.crypto.encoding import sha256_hex
from src.crypto.keys import KeyPair
from src.crypto.sign import (
    get_header_domain,
    get_tx_domain,
    get_vote_domain,
    sign_payload,
    sign_transaction,
)
from src.logging.logger import DeterministicLogger
from src.network.link import NetworkFaultConfig, UnreliableTransport
from src.network.p2p import Node
from src.network.simulator import Simulator

DEFAULT_GENESIS_PATH = os.path.join(REPO_ROOT, "config", "genesis.json")
REQUIRED_LOG_EVENTS = ["SEND", "DROP", "DELAY", "BLOCK", "UNBLOCK", "PROPOSE", "PREVOTE", "PRECOMMIT", "FINALIZE"]


# ---------------------------------------------------------------------------
# Run configuration
# ---------------------------------------------------------------------------

@dataclass
class RunConfig:
    genesis: Genesis = field(default_factory=Genesis)
    seed: int = 42
    t_stabilize: Optional[float] = None
    delta: Optional[float] = None
    drop_rate: Optional[float] = None
    duplicate_rate: Optional[float] = None
    min_delay: Optional[float] = None
    max_delay: Optional[float] = None
    byzantine: Optional[int] = None
    max_time: Optional[float] = None
    log_dir: str = os.path.join(REPO_ROOT, "logs")
    topology: Optional[str] = None

    @property
    def nodes(self) -> int:
        return self.genesis.num_validators

    @property
    def f(self) -> int:
        return self.genesis.f

    def network(self, **scenario_defaults) -> Dict:
        """Scenario fault profile with any CLI overrides applied on top."""
        params = dict(
            t_stabilize=0.0, delta=0.2, drop_rate=0.0, duplicate_rate=0.0, min_delay=0.05, max_delay=0.15
        )
        params.update(scenario_defaults)
        for k in params:
            override = getattr(self, k)
            if override is not None:
                params[k] = override
        return params

    def time_limit(self, default: float) -> float:
        return self.max_time if self.max_time is not None else default

    def log_path(self, name: str) -> str:
        return os.path.join(self.log_dir, f"{name}.log")

    def validate(self) -> None:
        validate_validator_count(self.nodes)
        for name in ("drop_rate", "duplicate_rate"):
            v = getattr(self, name)
            if v is not None and not (0.0 <= v < 1.0):
                raise ValueError(f"--{name.replace('_', '-')} must be in [0, 1)")
        if self.delta is not None and self.delta <= 0.01:
            raise ValueError("--delta must be greater than 0.01 s (minimum simulated link latency)")
        if self.t_stabilize is not None and self.t_stabilize < 0:
            raise ValueError("--t-stabilize must be >= 0")
        if self.min_delay is not None and self.min_delay < 0:
            raise ValueError("--min-delay must be >= 0")
        if self.min_delay is not None and self.max_delay is not None and self.max_delay < self.min_delay:
            raise ValueError("--max-delay must be >= --min-delay")
        if self.byzantine is not None and not (0 <= self.byzantine <= self.f):
            raise ValueError(f"--byzantine must be between 0 and f={self.f}")


def _default_genesis() -> Genesis:
    return load_genesis(DEFAULT_GENESIS_PATH) if os.path.exists(DEFAULT_GENESIS_PATH) else Genesis()


# ---------------------------------------------------------------------------
# Simulation harness
# ---------------------------------------------------------------------------

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
    min_delay: float = 0.05,
    max_delay: float = 0.15,
    genesis: Optional[Genesis] = None,
    topology: Optional[str] = None,
):
    """Builds a simulator, unreliable transport and n validator nodes from genesis."""
    genesis = (genesis or _default_genesis()).with_validators(num_nodes)
    chain_id = genesis.chain_id
    simulator = Simulator(seed=seed)
    logger = DeterministicLogger()

    if topology:
        fault_cfg = NetworkFaultConfig.from_json_file(topology)
        fault_cfg.drop_rate = drop_rate
        fault_cfg.duplicate_rate = duplicate_rate
        fault_cfg.t_stabilize = t_stabilize
        fault_cfg.delta = delta
    else:
        fault_cfg = NetworkFaultConfig(
            drop_rate=drop_rate,
            duplicate_rate=duplicate_rate,
            min_delay=min_delay,
            max_delay=max_delay,
            t_stabilize=t_stabilize,
            delta=delta,
        )
    transport = UnreliableTransport(simulator, fault_cfg, logger, seed=seed)

    keypairs = genesis.validator_keypairs(seed)
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
        if genesis.initial_state:
            node.engine.committed_state = State(genesis.initial_state)
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
        "genesis": genesis,
    }


def _setup(cfg: RunConfig, net: Dict, byzantine_count: int = 0,
           byzantine_mode: ByzantineMode = ByzantineMode.HONEST) -> Dict:
    return setup_simulation(
        num_nodes=cfg.nodes,
        byzantine_count=byzantine_count,
        byzantine_mode=byzantine_mode,
        seed=cfg.seed,
        genesis=cfg.genesis,
        topology=cfg.topology,
        **net,
    )


def make_tx(kp: KeyPair, doc_id: str, content: str, nonce: int, chain_id: str) -> Transaction:
    """Builds a signed notarization tx whose doc_hash is the SHA-256 of `content`."""
    tx = Transaction(
        sender=kp.public_key_hex,
        doc_id=doc_id,
        doc_hash="0x" + sha256_hex(content.encode("utf-8")),
        nonce=nonce,
    )
    sign_transaction(kp, tx, chain_id)
    return tx


def submit_to_all(nodes: List[Node], tx: Transaction) -> List[bool]:
    return [n.submit_transaction(tx)[0] for n in nodes]


def write_log(sim_data: Dict, path: Optional[str]) -> None:
    if path:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        sim_data["logger"].write_to_file(path)


def check_safety(nodes: List[Node]) -> tuple[bool, str]:
    """Safety: at every height finalized by >1 node, all finalized hashes are equal,
    and nodes with equal ledger length hold the same state root."""
    by_height: Dict[int, set] = {}
    for n in nodes:
        for b in n.engine.ledger:
            by_height.setdefault(b.header.height, set()).add(b.hash())
    for h, hashes in sorted(by_height.items()):
        if len(hashes) > 1:
            return False, f"conflicting finalization at height {h}: {sorted(x[:12] for x in hashes)}"
    roots: Dict[int, set] = {}
    for n in nodes:
        roots.setdefault(len(n.engine.ledger), set()).add(n.engine.committed_state.compute_merkle_root())
    for length, rs in roots.items():
        if len(rs) > 1:
            return False, f"state root divergence at ledger length {length}"
    return True, ""


def _report(name: str, ok: bool, msg: str) -> bool:
    print(f"[{'SUCCESS' if ok else 'FAILED'}] {name} {'Passed' if ok else 'Failed'}: {msg}")
    return ok


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def run_scenario_t1(cfg: Optional[RunConfig] = None) -> bool:
    """T1: normal run, no faults. All nodes finalize the same chain and state hash."""
    cfg = cfg or RunConfig(genesis=_default_genesis())
    target = 3
    print(f"\n--- Running Scenario T1 (Normal Run, n={cfg.nodes}, seed={cfg.seed}) ---")
    sim_data = _setup(cfg, cfg.network())
    nodes, sim, chain_id = sim_data["nodes"], sim_data["simulator"], sim_data["chain_id"]

    alice, bob = KeyPair.from_seed("alice"), KeyPair.from_seed("bob")
    tx_a = make_tx(alice, "contract_a", "Alice's contract v1", 1, chain_id)
    tx_b = make_tx(bob, "thesis_b", "Bob's thesis draft", 1, chain_id)
    submit_to_all(nodes, tx_a)
    submit_to_all(nodes, tx_b)

    for n in nodes:
        n.engine.start_height(1)
    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= target for n in nodes), max_time=cfg.time_limit(30.0))
    write_log(sim_data, cfg.log_path("T1"))

    if not all(len(n.engine.ledger) >= target for n in nodes):
        return _report("T1", False, f"not all nodes reached height {target}")
    chains = {tuple(b.hash() for b in n.engine.ledger[:target]) for n in nodes}
    roots = {n.engine.committed_state.compute_merkle_root() for n in nodes if len(n.engine.ledger) == target}
    s0 = nodes[0].engine.committed_state
    docs_ok = (s0.get(f"{alice.public_key_hex}/docs/contract_a") == tx_a.doc_hash
               and s0.get(f"{bob.public_key_hex}/docs/thesis_b") == tx_b.doc_hash)
    safe, why = check_safety(nodes)
    ok = len(chains) == 1 and len(roots) <= 1 and docs_ok and safe
    return _report("T1", ok, (
        f"{cfg.nodes}/{cfg.nodes} nodes finalized identical chain of {target} blocks, "
        f"head {list(chains)[0][-1][:12]}, state root {s0.compute_merkle_root()[:12]}"
        if ok else f"chains={len(chains)} roots={len(roots)} docs_ok={docs_ok} {why}"
    ))


def run_scenario_t2(cfg: Optional[RunConfig] = None) -> bool:
    """T2: duplicated/reordered messages. No double counting, no conflicting finalization."""
    cfg = cfg or RunConfig(genesis=_default_genesis())
    print(f"\n--- Running Scenario T2 (Duplicate/Reordered Messages, seed={cfg.seed}) ---")
    sim_data = _setup(cfg, cfg.network(duplicate_rate=0.4, min_delay=0.02, max_delay=0.15))
    nodes, sim, chain_id = sim_data["nodes"], sim_data["simulator"], sim_data["chain_id"]

    submit_to_all(nodes, make_tx(KeyPair.from_seed("client_t2"), "doc_t2", "T2 document", 1, chain_id))
    for n in nodes:
        n.engine.start_height(1)
    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in nodes), max_time=cfg.time_limit(20.0))
    write_log(sim_data, cfg.log_path("T2"))

    if not all(len(n.engine.ledger) >= 1 for n in nodes):
        return _report("T2", False, "not all nodes finalized height 1")
    # No vote set may hold more than one entry per validator, nor more entries than validators
    counted_ok = all(
        len(vs.votes) <= cfg.nodes and len(set(vs.votes)) == len(vs.votes)
        for n in nodes for vs in n.engine.vote_sets.values()
    )
    safe, why = check_safety(nodes)
    ok = counted_ok and safe
    return _report("T2", ok, (
        f"no double counting or forks under duplicate messages. Block {nodes[0].engine.ledger[0].hash()[:12]}"
        if ok else f"counted_ok={counted_ok} {why}"
    ))


def run_scenario_t3(cfg: Optional[RunConfig] = None) -> bool:
    """T3: invalid signature / wrong domain. Message rejected and reason logged."""
    cfg = cfg or RunConfig(genesis=_default_genesis())
    print(f"\n--- Running Scenario T3 (Invalid Signature / Wrong Domain, seed={cfg.seed}) ---")
    sim_data = _setup(cfg, cfg.network())
    nodes, sim, chain_id = sim_data["nodes"], sim_data["simulator"], sim_data["chain_id"]
    keypairs, validators, logger = sim_data["keypairs"], sim_data["validators"], sim_data["logger"]
    target = nodes[2]           # honest receiver under test
    val_kp = keypairs[0]        # validator whose identity is abused
    fake_hash = "ab" * 32

    def vote(chain: str = chain_id) -> Vote:
        return Vote(chain_id=chain, height=1, round=0, phase=Phase.PREVOTE,
                    block_hash=fake_hash, validator_id=val_kp.public_key_hex)

    # (a) vote signed under TX: instead of VOTE:
    v_domain = vote()
    v_domain.signature = sign_payload(val_kp, get_tx_domain(chain_id), v_domain.signing_payload())
    # (b) vote signed correctly then tampered (signature no longer matches)
    v_tamper = vote()
    v_tamper.signature = sign_payload(val_kp, get_vote_domain(chain_id), v_tamper.signing_payload())
    v_tamper.block_hash = "cd" * 32
    # (c) vote validly signed for another chain (VOTE:other-chain)
    v_chain = vote("other-chain")
    v_chain.signature = sign_payload(val_kp, get_vote_domain("other-chain"), v_chain.signing_payload())
    # (d) vote forged by an outsider key claiming a validator identity
    outsider = KeyPair.from_seed("outsider")
    v_forged = vote()
    v_forged.signature = sign_payload(outsider, get_vote_domain(chain_id), v_forged.signing_payload())

    # (e) header from the correct proposer but signed under VOTE: instead of HEADER:
    prop_idx = validators.index(get_proposer(validators, 1, 0))
    prop_kp = keypairs[prop_idx]
    hdr = BlockHeader(chain_id=chain_id, height=1, round=0, parent_hash="0" * 64,
                      state_root=State().compute_merkle_root(), txs_hash=compute_txs_hash([]),
                      proposer=prop_kp.public_key_hex, timestamp=0)
    hdr.signature = sign_payload(prop_kp, get_vote_domain(chain_id), hdr.signing_payload())

    # (f) transaction signed under VOTE: and (g) transaction tampered after signing
    client = KeyPair.from_seed("client_t3")
    tx_domain = Transaction(sender=client.public_key_hex, doc_id="doc_bad_domain",
                            doc_hash="0x" + sha256_hex(b"bad domain"), nonce=1)
    tx_domain.signature = sign_payload(client, get_vote_domain(chain_id), tx_domain.signing_payload())
    tx_tamper = make_tx(client, "doc_tampered", "original", 1, chain_id)
    tx_tamper.doc_hash = "0x" + sha256_hex(b"forged")
    tx_good = make_tx(client, "doc_good", "legit document", 1, chain_id)

    bad_votes = [v_domain, v_tamper, v_chain, v_forged]
    for v in bad_votes:
        target.handle_message(validators[0], {"type": "VOTE", "vote": v})
    target.handle_message(prop_kp.public_key_hex, {"type": "HEADER", "header": hdr})
    tx_results = [target.submit_transaction(tx_domain)[0], target.submit_transaction(tx_tamper)[0]]

    # Immediate checks: nothing counted, no header accepted, nothing in mempool
    vset = target.engine.vote_sets.get((1, 0, "PREVOTE"))
    votes_rejected = vset is None or val_kp.public_key_hex not in vset.votes
    header_rejected = hdr.hash() not in target.accepted_headers
    txs_rejected = not any(tx_results) and len(target.engine.mempool) == 0

    # The chain keeps working with honest traffic
    submit_to_all(nodes, tx_good)
    for n in nodes:
        n.engine.start_height(1)
    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in nodes), max_time=cfg.time_limit(15.0))
    write_log(sim_data, cfg.log_path("T3"))

    log = logger.get_full_log()
    reasons = {
        "vote wrong domain/tampered/forged": log.count("REJECT_VOTE: Rule 6 validation failed: invalid vote signature") >= 3,
        "vote wrong chain": "REJECT_VOTE: Rule 6 validation failed: chain ID mismatch" in log,
        "header wrong domain": "REJECT_HEADER: invalid header signature under HEADER:" in log,
        "tx wrong domain/tampered": log.count("REJECT_TX: Invalid transaction signature under domain TX:") >= 2,
    }
    s = target.engine.committed_state
    state_ok = (s.get(f"{client.public_key_hex}/docs/doc_good") == tx_good.doc_hash
                and s.get(f"{client.public_key_hex}/docs/doc_bad_domain") is None
                and s.get(f"{client.public_key_hex}/docs/doc_tampered") is None)
    # Bad signatures never ended up counted, even after the run
    vset = target.engine.vote_sets.get((1, 0, "PREVOTE"))
    never_counted = vset is None or vset.votes.get(val_kp.public_key_hex) is None or \
        vset.votes[val_kp.public_key_hex].signature not in {v.signature for v in bad_votes}
    finalized = all(len(n.engine.ledger) >= 1 for n in nodes)

    ok = votes_rejected and header_rejected and txs_rejected and all(reasons.values()) and state_ok and never_counted and finalized
    return _report("T3", ok, (
        "4 bad votes, 1 wrong-domain header and 2 bad transactions rejected with logged reasons; "
        "chain finalized only the valid transaction"
        if ok else f"votes={votes_rejected} header={header_rejected} txs={txs_rejected} "
                   f"reasons={reasons} state_ok={state_ok} never_counted={never_counted} finalized={finalized}"
    ))


def run_scenario_t4(cfg: Optional[RunConfig] = None) -> bool:
    """T4: replayed/duplicate transaction. Applied at most once."""
    cfg = cfg or RunConfig(genesis=_default_genesis())
    print(f"\n--- Running Scenario T4 (Replayed/Duplicate Tx Rejection, seed={cfg.seed}) ---")
    sim_data = _setup(cfg, cfg.network())
    nodes, sim, chain_id = sim_data["nodes"], sim_data["simulator"], sim_data["chain_id"]
    keypairs, validators, logger = sim_data["keypairs"], sim_data["validators"], sim_data["logger"]

    client = KeyPair.from_seed("client_t4")
    tx1 = make_tx(client, "doc1", "first document", 1, chain_id)
    tx2 = make_tx(client, "doc2", "second document", 2, chain_id)

    # Duplicate submission: second copy of tx1 must be refused by every mempool
    first = submit_to_all(nodes, tx1)
    dup = submit_to_all(nodes, tx1)
    submit_to_all(nodes, tx2)
    # A Byzantine-style injection that bypasses admission: raw duplicate in the mempool
    for n in nodes:
        n.engine.mempool.append(tx1)

    for n in nodes:
        n.engine.start_height(1)
    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in nodes), max_time=cfg.time_limit(20.0))

    # Replay after finalization: re-submission refused; raw re-injection must be filtered out
    replay_submit = [n.submit_transaction(tx1)[0] for n in nodes]
    for n in nodes:
        n.engine.mempool.extend([tx1, tx2])
    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 2 for n in nodes), max_time=cfg.time_limit(40.0))
    write_log(sim_data, cfg.log_path("T4"))

    # Direct check: an otherwise valid proposal containing the replayed tx is rejected (Rule 3)
    n0 = nodes[0]
    h = len(n0.engine.ledger) + 1
    prop_kp = keypairs[validators.index(get_proposer(validators, h, 0))]
    base_header = BlockHeader(chain_id=chain_id, height=h, round=0, parent_hash=n0.engine.ledger[-1].hash(),
                              state_root=n0.engine.committed_state.compute_merkle_root(),
                              txs_hash=compute_txs_hash([]), proposer=prop_kp.public_key_hex, timestamp=0)
    replay_block = create_invalid_tx_proposal(Block(header=base_header, txs=[]), prop_kp, chain_id, tx1)
    before = dict(n0.engine.committed_state.data)
    rb_ok, rb_err, _ = validate_block_proposal(replay_block, chain_id, h, 0, n0.engine.ledger[-1],
                                               n0.engine.committed_state, validators)
    unchanged = before == n0.engine.committed_state.data

    finalized = all(len(n.engine.ledger) >= 2 for n in nodes)
    applied_once = all(
        sum(1 for b in n.engine.ledger for t in b.txs if t.hash() == tx1.hash()) == 1 for n in nodes
    )
    nonce_ok = all(n.engine.committed_state.get(f"{client.public_key_hex}/nonce") == "2" for n in nodes)
    admission_ok = all(first) and not any(dup) and not any(replay_submit)
    logged = "REJECT_TX: duplicate transaction already in mempool" in logger.get_full_log() and \
        "REJECT_TX: Invalid nonce: already applied" in logger.get_full_log()
    safe, why = check_safety(nodes)
    ok = (finalized and applied_once and nonce_ok and admission_ok and logged and not rb_ok
          and "Invalid nonce" in rb_err and unchanged and safe)
    return _report("T4", ok, (
        f"tx applied exactly once on all {cfg.nodes} nodes across 2 heights; duplicate and replay rejected "
        f"({rb_err.split(': ', 2)[-1]})"
        if ok else f"finalized={finalized} once={applied_once} nonce={nonce_ok} admission={admission_ok} "
                   f"logged={logged} replay_block_rejected={not rb_ok} unchanged={unchanged} {why}"
    ))


def run_scenario_t5(cfg: Optional[RunConfig] = None) -> bool:
    """T5: drop/delay before synchrony. Safety always; delivery within delta and liveness after."""
    cfg = cfg or RunConfig(genesis=_default_genesis())
    print(f"\n--- Running Scenario T5 (Drop & Delay Before Stabilize, seed={cfg.seed}) ---")
    net = cfg.network(drop_rate=0.25, duplicate_rate=0.2, t_stabilize=2.0, delta=0.2)
    sim_data = _setup(cfg, net)
    nodes, sim, transport, chain_id = (sim_data["nodes"], sim_data["simulator"],
                                       sim_data["transport"], sim_data["chain_id"])

    submit_to_all(nodes, make_tx(KeyPair.from_seed("client_t5"), "doc_t5", "T5 document", 1, chain_id))
    for n in nodes:
        n.engine.start_height(1)

    # Safety is checked at every event, not only at the end
    safety_violations: List[str] = []

    def cond() -> bool:
        safe, why = check_safety(nodes)
        if not safe and not safety_violations:
            safety_violations.append(f"t={sim.now():.3f}s {why}")
        return all(len(n.engine.ledger) >= 2 for n in nodes)

    sim.run_until_condition(cond, max_time=cfg.time_limit(40.0))
    write_log(sim_data, cfg.log_path("T5"))

    live = all(len(n.engine.ledger) >= 2 for n in nodes)
    safe, why = check_safety(nodes)
    safety_ok = safe and not safety_violations
    zero_drops = transport.stabilized_drops == 0
    deliveries = transport.stabilized_deliveries
    delta_ok = len(deliveries) > 0 and all(d["delay"] <= transport.config.delta + 1e-6 for d in deliveries)
    ok = live and safety_ok and zero_drops and delta_ok
    return _report("T5", ok, (
        f"safety held throughout; after t_stabilize={net['t_stabilize']}s, {len(deliveries)} msgs delivered "
        f"with 0 drops within delta={transport.config.delta}s; all nodes finalized 2 heights"
        if ok else f"live={live} safety={safety_ok} {why or safety_violations} zero_drops={zero_drops} delta_ok={delta_ok}"
    ))


def run_scenario_t6(cfg: Optional[RunConfig] = None) -> bool:
    """T6: proposer silent/crashed. Round timeout triggers, chain continues."""
    cfg = cfg or RunConfig(genesis=_default_genesis())
    print(f"\n--- Running Scenario T6 (Silent Proposer Timeout, seed={cfg.seed}) ---")
    sim_data = _setup(cfg, cfg.network())
    nodes, sim, validators, chain_id = (sim_data["nodes"], sim_data["simulator"],
                                        sim_data["validators"], sim_data["chain_id"])

    proposer_addr = get_proposer(validators, 1, 0)
    proposer_node = next(n for n in nodes if n.node_id == proposer_addr)
    proposer_node.byzantine_mode = ByzantineMode.SILENT_PROPOSER
    proposer_node.transport.mark_byzantine(proposer_node.node_id)
    honest_nodes = [n for n in nodes if n is not proposer_node]

    submit_to_all(nodes, make_tx(KeyPair.from_seed("client_t6"), "doc_t6", "T6 document", 1, chain_id))
    for n in nodes:
        n.engine.start_height(1)
    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in honest_nodes), max_time=cfg.time_limit(25.0))
    write_log(sim_data, cfg.log_path("T6"))

    if not all(len(n.engine.ledger) >= 1 for n in honest_nodes):
        return _report("T6", False, "honest nodes failed to finalize block")
    finalized_round = honest_nodes[0].engine.ledger[0].header.round
    timeout_logged = "[TIMEOUT_PROPOSE] [1] [0]" in sim_data["logger"].get_full_log()
    safe, why = check_safety(honest_nodes)
    ok = finalized_round >= 1 and timeout_logged and safe
    return _report("T6", ok, (
        f"round 0 timed out (TIMEOUT_PROPOSE logged), block finalized at round {finalized_round} "
        f"with hash {honest_nodes[0].engine.ledger[0].hash()[:12]}"
        if ok else f"round={finalized_round} timeout_logged={timeout_logged} {why}"
    ))


def run_scenario_t7(cfg: Optional[RunConfig] = None) -> bool:
    """T7: up to f Byzantine validators equivocate. No conflicting finalization."""
    cfg = cfg or RunConfig(genesis=_default_genesis())
    byz = cfg.byzantine if cfg.byzantine is not None else cfg.f
    print(f"\n--- Running Scenario T7 (Byzantine Equivocation, {byz} of f={cfg.f}, seed={cfg.seed}) ---")
    sim_data = _setup(cfg, cfg.network(), byzantine_count=byz, byzantine_mode=ByzantineMode.EQUIVOCATE_VOTES)
    nodes, sim, chain_id = sim_data["nodes"], sim_data["simulator"], sim_data["chain_id"]

    submit_to_all(nodes, make_tx(KeyPair.from_seed("client_t7"), "doc_t7", "T7 document", 1, chain_id))
    honest_nodes = nodes[byz:]
    # Byzantine validators occupy indices [0, byz); start at the first height whose
    # round-0 proposer (index = height mod n) is honest.
    start_h = max(byz, 1)
    for n in nodes:
        n.engine.start_height(start_h)
    sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in honest_nodes), max_time=cfg.time_limit(20.0))
    write_log(sim_data, cfg.log_path("T7"))

    finalized = all(len(n.engine.ledger) >= 1 for n in honest_nodes)
    safe, why = check_safety(honest_nodes)
    ok = finalized and safe
    return _report("T7", ok, (
        f"safety preserved under {byz} equivocating validators. Unique block hash "
        f"{honest_nodes[0].engine.ledger[0].hash()[:12]}"
        if ok else f"finalized={finalized} {why}"
    ))


def run_scenario_t8(cfg: Optional[RunConfig] = None) -> bool:
    """T8: same seed run twice. Byte-identical logs and final state hash."""
    cfg = cfg or RunConfig(genesis=_default_genesis())
    print(f"\n--- Running Scenario T8 (Determinism Replay Check, seed={cfg.seed}) ---")
    log1, log2 = cfg.log_path("T8_run1"), cfg.log_path("T8_run2")
    net = cfg.network(drop_rate=0.2, duplicate_rate=0.1, t_stabilize=1.5, delta=0.2)

    def execute(out_log: str) -> tuple[bool, str]:
        sim_data = _setup(cfg, net)
        nodes, sim, chain_id = sim_data["nodes"], sim_data["simulator"], sim_data["chain_id"]
        # Overactive peer burst exercises BLOCK and UNBLOCK events deterministically
        sim.schedule_event(
            0.05,
            lambda: [nodes[0].handle_message("spam_test_peer", {"type": "SPAM", "seq": i}) for i in range(35)],
        )
        submit_to_all(nodes, make_tx(KeyPair.from_seed("client_t8"), "doc_t8", "T8 document", 1, chain_id))
        for n in nodes:
            n.engine.start_height(1)
        sim.run_until_condition(lambda: all(len(n.engine.ledger) >= 1 for n in nodes), max_time=cfg.time_limit(25.0))
        write_log(sim_data, out_log)
        all_finalized = all(len(n.engine.ledger) >= 1 for n in nodes)
        return all_finalized, nodes[0].engine.committed_state.compute_merkle_root() if all_finalized else ""

    ok1, root1 = execute(log1)
    ok2, root2 = execute(log2)
    if not (ok1 and ok2):
        return _report("T8", False, "one of the simulation runs failed to finalize")
    if root1 != root2:
        return _report("T8", False, f"state roots differ: {root1} != {root2}")

    with open(log1, "rb") as f1, open(log2, "rb") as f2:
        bytes1, bytes2 = f1.read(), f2.read()
    sha1, sha2 = hashlib.sha256(bytes1).hexdigest(), hashlib.sha256(bytes2).hexdigest()
    if bytes1 != bytes2:
        return _report("T8", False, f"logs differ\n  Run 1 SHA256: {sha1}\n  Run 2 SHA256: {sha2}")

    log_str = bytes1.decode("utf-8")
    missing = [e for e in REQUIRED_LOG_EVENTS if f"[{e}]" not in log_str]
    if missing:
        return _report("T8", False, f"log missing required events: {missing}")
    return _report("T8", True, (
        f"byte-identical logs ({len(bytes1)} bytes)\n  Run 1 SHA256: {sha1}\n  Run 2 SHA256: {sha2}\n"
        f"  Identical final state root: {root1}\n  Events present: {', '.join(REQUIRED_LOG_EVENTS)}"
    ))


SCENARIOS: Dict[str, Callable[[RunConfig], bool]] = {
    "T1": run_scenario_t1,
    "T2": run_scenario_t2,
    "T3": run_scenario_t3,
    "T4": run_scenario_t4,
    "T5": run_scenario_t5,
    "T6": run_scenario_t6,
    "T7": run_scenario_t7,
    "T8": run_scenario_t8,
}


def run_unit_tests() -> bool:
    print("\n=== Running Unit & Integration Test Suites (pytest) ===")
    ret = pytest.main(["-q", os.path.join(REPO_ROOT, "tests"), "-p", "no:cacheprovider"])
    return ret == 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Lab 01 NotaryBFT simulator: unit tests and scenarios T1-T8")
    p.add_argument("--all", action="store_true", help="Run unit suites and all scenarios (default)")
    p.add_argument("--unit", action="store_true", help="Run only the pytest unit/integration suites")
    p.add_argument("--scenario", nargs="+", choices=list(SCENARIOS), metavar="T#",
                   help="Run one or more scenarios, e.g. --scenario T1 T8")
    p.add_argument("--genesis", default=DEFAULT_GENESIS_PATH, help="Genesis file (chain ID, validator count)")
    p.add_argument("--topology", default=None, help="Optional topology JSON with latency matrix, e.g. config/network_topology.json")
    p.add_argument("--nodes", type=int, default=None, help="Number of validators n (n >= 8, n = 3f + 1; default from genesis: 10)")
    p.add_argument("--seed", type=int, default=42, help="Simulation seed (default 42)")
    p.add_argument("--t-stabilize", type=float, default=None, help="Override stabilization instant T_stabilize (s)")
    p.add_argument("--delta", type=float, default=None, help="Override post-stabilization delivery bound Delta (s)")
    p.add_argument("--drop-rate", type=float, default=None, help="Override pre-stabilization drop probability")
    p.add_argument("--duplicate-rate", type=float, default=None, help="Override pre-stabilization duplication probability")
    p.add_argument("--min-delay", type=float, default=None, help="Override minimum link delay (s)")
    p.add_argument("--max-delay", type=float, default=None, help="Override maximum link delay (s)")
    p.add_argument("--byzantine", type=int, default=None, help="Byzantine validators in T7 (0..f, default f)")
    p.add_argument("--max-time", type=float, default=None, help="Override virtual-time limit per scenario (s)")
    p.add_argument("--log-dir", default=os.path.join(REPO_ROOT, "logs"), help="Directory for scenario logs")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        genesis = load_genesis(args.genesis)
        if args.nodes is not None:
            genesis = genesis.with_validators(args.nodes)
        cfg = RunConfig(
            genesis=genesis, seed=args.seed, t_stabilize=args.t_stabilize, delta=args.delta,
            drop_rate=args.drop_rate, duplicate_rate=args.duplicate_rate, min_delay=args.min_delay,
            max_delay=args.max_delay, byzantine=args.byzantine, max_time=args.max_time,
            log_dir=os.path.abspath(args.log_dir), topology=args.topology,
        )
        cfg.validate()
    except (ValueError, OSError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    print(f"Config: chain_id={genesis.chain_id} n={cfg.nodes} f={cfg.f} quorum={genesis.quorum} "
          f"seed={cfg.seed} logs={cfg.log_dir}")

    results: Dict[str, bool] = {}
    run_all = args.all or (not args.unit and not args.scenario)
    if args.unit or run_all:
        results["unit"] = run_unit_tests()
    for name in (list(SCENARIOS) if run_all else (args.scenario or [])):
        results[name] = SCENARIOS[name](cfg)

    print("\n=== Summary ===")
    for name, ok in results.items():
        print(f"  {name:5s} {'PASS' if ok else 'FAIL'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
