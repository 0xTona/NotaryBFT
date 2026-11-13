"""Unit tests for Network Simulation, P2P Layer, Traffic Control, and Deterministic Logging (Member 2)."""

import json
import os
import sys
import unittest

# Ensure repository root is in sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if "/tmp/site-packages" not in sys.path and os.path.exists("/tmp/site-packages"):
    sys.path.insert(0, "/tmp/site-packages")

from src.consensus.proposer import get_proposer
from src.core.types import Block, BlockHeader, Transaction, compute_txs_hash
from src.crypto.keys import KeyPair
from src.crypto.sign import get_header_domain, sign_payload
from src.logging.logger import DeterministicLogger
from src.network.link import NetworkFaultConfig, UnreliableTransport
from src.network.p2p import Node, OutboundRateLimiter, TrafficControlConfig
from src.network.simulator import Simulator


class TestNetworkLayer(unittest.TestCase):
    """
    Comprehensive test suite for Member 2 deliverables:
    1. Outbound rate limiting (token bucket)
    2. Overactive peer blocking & quarantine (BLOCK/UNBLOCK)
    3. Header-First gossip propagation (HEADER -> GET_BODY -> BODY)
    4. Strict rejection of invalid headers
    5. Topology configuration file parsing and latency matrix lookup
    """

    def setUp(self):
        self.chain_id = "layer1-testnet"
        self.sim = Simulator(seed=42)
        self.logger = DeterministicLogger()
        self.fault_cfg = NetworkFaultConfig(
            drop_rate=0.0,
            duplicate_rate=0.0,
            min_delay=0.01,
            max_delay=0.02,
            t_stabilize=0.0,
            delta=0.1,
        )
        self.transport = UnreliableTransport(self.sim, self.fault_cfg, self.logger, seed=42)

        # 10 validator baseline (n = 10, f = 3, quorum = 7)
        self.keypairs = [KeyPair.from_seed(f"val_net_{i}") for i in range(10)]
        self.validators = [kp.public_key_hex for kp in self.keypairs]

        self.nodes: list[Node] = []
        for i in range(10):
            node = Node(
                node_id=self.validators[i],
                chain_id=self.chain_id,
                validators=self.validators,
                keypair=self.keypairs[i],
                simulator=self.sim,
                transport=self.transport,
                logger=self.logger,
            )
            self.nodes.append(node)

    def _create_signed_header(
        self,
        proposer_kp: KeyPair,
        height: int = 1,
        round_num: int = 0,
        parent_hash: str = "0" * 64,
        chain_id: str = None,
        txs: list = None,
    ) -> BlockHeader:
        cid = chain_id or self.chain_id
        tx_list = txs if txs is not None else []
        hdr = BlockHeader(
            chain_id=cid,
            height=height,
            round=round_num,
            parent_hash=parent_hash,
            state_root="0" * 64,
            txs_hash=compute_txs_hash(tx_list),
            proposer=proposer_kp.public_key_hex,
            timestamp=0,
        )
        domain = get_header_domain(cid)
        hdr.signature = sign_payload(proposer_kp, domain, hdr.signing_payload())
        return hdr

    def test_rate_limiting(self):
        """1. test_rate_limiting: Verifies deterministic delays when outbound rate limit is exceeded."""
        sim = Simulator(seed=123)
        # Test limiter configured for rate = 50 msgs/s, burst = 5
        limiter = OutboundRateLimiter(simulator=sim, rate=50.0, burst=5.0)

        # First 5 messages consume burst capacity with 0.0s delay
        for i in range(5):
            delay = limiter.schedule_send_delay()
            self.assertEqual(delay, 0.0, f"Message {i} within burst should have 0 delay")

        # 6th message exceeds burst capacity -> must wait for 1 token: 1/50 = 0.02s
        delay_6 = limiter.schedule_send_delay()
        self.assertAlmostEqual(delay_6, 0.02, places=4)

        # 7th message queued after 6th -> delay = 0.04s
        delay_7 = limiter.schedule_send_delay()
        self.assertAlmostEqual(delay_7, 0.04, places=4)

        # Schedule event to advance virtual time to 1.0s (replenishing window)
        sim.schedule_event(1.0, lambda: None)
        sim.run_until(1.0)
        self.assertEqual(sim.now(), 1.0)

        # Tokens are replenished back to burst 5 -> immediate send with 0.0s delay
        for i in range(5):
            delay = limiter.schedule_send_delay()
            self.assertEqual(delay, 0.0)

    def test_peer_blocking_and_unblocking(self):
        """2. test_peer_blocking_and_unblocking: Verifies quarantine of overactive peer and automatic unblock."""
        sim = Simulator(seed=456)
        logger = DeterministicLogger()
        transport = UnreliableTransport(sim, self.fault_cfg, logger, seed=456)

        # Use strict thresholds for testing: threshold = 5 msgs/s, penalty = 0.5s
        traffic_cfg = TrafficControlConfig(
            outbound_rate_limit=100.0,
            outbound_burst_capacity=50.0,
            peer_block_threshold=5,
            peer_window_size=1.0,
            peer_penalty_duration=0.5,
        )

        test_kp = KeyPair.from_seed("test_receiver")
        validators = [test_kp.public_key_hex] + [KeyPair.from_seed(f"v_{i}").public_key_hex for i in range(9)]
        bad_peer = validators[1]
        good_peer = validators[2]

        receiver_node = Node(
            node_id=test_kp.public_key_hex,
            chain_id=self.chain_id,
            validators=validators,
            keypair=test_kp,
            simulator=sim,
            transport=transport,
            logger=logger,
            traffic_config=traffic_cfg,
        )

        # Good peer sends 3 messages: well below threshold -> not blocked
        for i in range(3):
            receiver_node.handle_message(good_peer, {"type": "TEST", "seq": i})
        self.assertFalse(receiver_node.is_peer_blocked(good_peer))

        # Bad peer sends 5 messages: at threshold -> not blocked yet
        for i in range(5):
            receiver_node.handle_message(bad_peer, {"type": "TEST", "seq": i})
        self.assertFalse(receiver_node.is_peer_blocked(bad_peer))

        # Bad peer sends 6th message: exceeds threshold -> BLOCK event triggered!
        receiver_node.handle_message(bad_peer, {"type": "TEST", "seq": 5})
        self.assertTrue(receiver_node.is_peer_blocked(bad_peer))

        # Bad peer sends 7th message while blocked -> dropped immediately
        receiver_node.handle_message(bad_peer, {"type": "TEST", "seq": 6})
        self.assertTrue(receiver_node.is_peer_blocked(bad_peer))

        # Verify logs contain [BLOCK] and [DROP]
        full_log = logger.get_full_log()
        self.assertIn("[BLOCK]", full_log)
        self.assertIn(f"peer={bad_peer}", full_log)
        self.assertIn("[DROP]", full_log)

        # Advance virtual time by penalty duration (0.5s + 0.1s jitter) -> UNBLOCK triggered!
        sim.run_until(sim.now() + 0.6)
        self.assertFalse(receiver_node.is_peer_blocked(bad_peer))

        # Verify [UNBLOCK] event was logged
        log_after = logger.get_full_log()
        self.assertIn("[UNBLOCK]", log_after)

        # Bad peer can send messages normally after being unblocked
        receiver_node.handle_message(bad_peer, {"type": "TEST", "seq": 100})
        self.assertFalse(receiver_node.is_peer_blocked(bad_peer))

    def test_header_first_flow(self):
        """3. test_header_first_flow: Verifies HEADER -> GET_BODY -> BODY gossip propagation."""
        # For height 1, round 0, designated proposer is val_1: (1 + 0) % 10 = 1
        proposer_idx = 1
        proposer_node = self.nodes[proposer_idx]
        peer_node = self.nodes[0]

        # Intercept outbound transmissions from peer to verify GET_BODY issuance
        peer_outbox = []
        orig_send = peer_node.send_outbound
        peer_node.send_outbound = lambda r, m, h=0, rnd=0: (peer_outbox.append((r, m)), orig_send(r, m, h, rnd))

        # Proposer creates valid proposal
        hdr = self._create_signed_header(self.keypairs[proposer_idx], height=1, round_num=0)
        valid_block = Block(header=hdr, txs=[])
        proposer_node.known_blocks[valid_block.hash()] = valid_block

        # Proposer transmits HEADER to peer
        peer_node.handle_message(proposer_node.node_id, {"type": "HEADER", "header": hdr})

        # Assert peer accepted header and dispatched GET_BODY
        self.assertIn(hdr.hash(), peer_node.accepted_headers)
        get_body_requests = [m for _, m in peer_outbox if m.get("type") == "GET_BODY"]
        self.assertEqual(len(get_body_requests), 1)
        self.assertEqual(get_body_requests[0]["hash"], hdr.hash())

        # Proposer responds with BODY
        peer_node.handle_message(proposer_node.node_id, {"type": "BODY", "block": valid_block})

        # Assert peer verified block body and forwarded to ConsensusEngine
        self.assertIn(valid_block.hash(), peer_node.known_blocks)
        self.assertIn((1, 0), peer_node.engine.proposal_blocks)

    def test_header_first_invalid_rejected(self):
        """4. test_header_first_invalid_rejected: Header with invalid signature/proposer/parent must not trigger GET_BODY."""
        peer_node = self.nodes[0]
        proposer_kp = self.keypairs[1]

        # Case A: Header with corrupted cryptographic signature
        hdr_bad_sig = self._create_signed_header(proposer_kp, height=1, round_num=0)
        hdr_bad_sig.signature = "corrupted_sig_" + "0" * 96

        peer_outbox = []
        peer_node.send_outbound = lambda r, m, h=0, rnd=0: peer_outbox.append((r, m))
        peer_node.handle_message(proposer_kp.public_key_hex, {"type": "HEADER", "header": hdr_bad_sig})

        self.assertNotIn(hdr_bad_sig.hash(), peer_node.accepted_headers)
        self.assertEqual(len(peer_outbox), 0, "Corrupted signature must not trigger GET_BODY")

        # Case B: Header signed by wrong proposer (val_5 instead of val_1)
        imposter_kp = self.keypairs[5]
        hdr_wrong_proposer = self._create_signed_header(imposter_kp, height=1, round_num=0)

        peer_outbox.clear()
        peer_node.handle_message(imposter_kp.public_key_hex, {"type": "HEADER", "header": hdr_wrong_proposer})

        self.assertNotIn(hdr_wrong_proposer.hash(), peer_node.accepted_headers)
        self.assertEqual(len(peer_outbox), 0, "Wrong proposer must not trigger GET_BODY")

        # Case C: Header with invalid parent_hash
        hdr_wrong_parent = self._create_signed_header(proposer_kp, height=1, round_num=0, parent_hash="f" * 64)

        peer_outbox.clear()
        peer_node.handle_message(proposer_kp.public_key_hex, {"type": "HEADER", "header": hdr_wrong_parent})

        self.assertNotIn(hdr_wrong_parent.hash(), peer_node.accepted_headers)
        self.assertEqual(len(peer_outbox), 0, "Wrong parent hash must not trigger GET_BODY")

        # Case D: Unrequested Body (without prior accepted Header) must be rejected
        valid_hdr = self._create_signed_header(proposer_kp, height=1, round_num=0)
        unrequested_block = Block(header=valid_hdr, txs=[])
        peer_node.handle_message(proposer_kp.public_key_hex, {"type": "BODY", "block": unrequested_block})

        self.assertNotIn(unrequested_block.hash(), peer_node.known_blocks)
        self.assertNotIn((1, 0), peer_node.engine.proposal_blocks)

        # Case E: Header signed with wrong domain (e.g. cross-domain replay attack)
        hdr_wrong_domain = self._create_signed_header(proposer_kp, height=1, round_num=0)
        wrong_domain = f"VOTE:{self.chain_id}"
        hdr_wrong_domain.signature = sign_payload(proposer_kp, wrong_domain, hdr_wrong_domain.signing_payload())

        peer_outbox.clear()
        peer_node.handle_message(proposer_kp.public_key_hex, {"type": "HEADER", "header": hdr_wrong_domain})

        self.assertNotIn(hdr_wrong_domain.hash(), peer_node.accepted_headers)
        self.assertEqual(len(peer_outbox), 0, "Wrong domain signature must not trigger GET_BODY")

    def test_load_topology_config(self):
        """5. test_load_topology_config: Verifies loading and parsing config/network_topology.json."""
        config_path = os.path.join(REPO_ROOT, "config", "network_topology.json")
        self.assertTrue(os.path.exists(config_path), f"Topology file missing at {config_path}")

        # Test direct JSON structure
        with open(config_path, "r", encoding="utf-8") as f:
            topo = json.load(f)

        self.assertEqual(topo["validator_configuration"]["num_validators"], 10)
        self.assertEqual(topo["validator_configuration"]["f"], 3)
        self.assertEqual(topo["validator_configuration"]["quorum"], 7)
        self.assertEqual(len(topo["nodes"]), 10)
        self.assertEqual(len(topo["latency_matrix"]), 10)

        # Test UnreliableTransport factory initialization
        transport = UnreliableTransport.from_config_file(
            config_path=config_path,
            simulator=self.sim,
            logger=self.logger,
            seed=789,
        )

        self.assertEqual(transport.config.delta, 0.2)
        self.assertEqual(transport.config.t_stabilize, 2.0)

        # Register node aliases and verify pair-specific latency lookup from matrix
        transport.register_node("val_0_addr", lambda s, m: None, alias="val_0")
        transport.register_node("val_1_addr", lambda s, m: None, alias="val_1")

        min_d, max_d = transport.get_link_bounds("val_0_addr", "val_1_addr")
        # According to network_topology.json, val_0 -> val_1 has bounds [0.04, 0.10]
        self.assertEqual(min_d, 0.04)
        self.assertEqual(max_d, 0.10)


if __name__ == "__main__":
    unittest.main()
