"""P2P layer: Header-first gossip propagation, traffic control (rate limiting), and node harness."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from src.byzantine.behaviors import ByzantineMode, create_equivocating_prevotes
from src.consensus.engine import ConsensusEngine
from src.consensus.proposer import TimeoutConfig, get_proposer
from src.core.types import Block, BlockHeader, Vote, compute_txs_hash
from src.crypto.keys import KeyPair
from src.crypto.sign import get_header_domain, verify_payload_signature
from src.logging.logger import DeterministicLogger
from src.network.link import UnreliableTransport
from src.network.simulator import Simulator


@dataclass
class TrafficControlConfig:
    """Configuration for outbound rate limiting and overactive peer blocking."""
    outbound_rate_limit: float = 80.0       # messages per second
    outbound_burst_capacity: float = 40.0   # burst capacity in tokens
    peer_block_threshold: int = 30          # max incoming msgs per window from a single peer
    peer_window_size: float = 1.0           # observation window in seconds
    peer_penalty_duration: float = 1.0      # quarantine/block duration in seconds


class OutboundRateLimiter:
    """
    Deterministic Token Bucket Outbound Rate Limiter.
    Limits outbound message rate per node according to virtual_time.
    When burst capacity is exceeded, messages are deterministically delayed/queued.
    """

    def __init__(self, simulator: Simulator, rate: float = 80.0, burst: float = 40.0):
        self.simulator = simulator
        self.rate = float(rate)
        self.burst = float(burst)
        self.tokens = float(burst)
        self.last_refill: float = simulator.now()
        self.next_available_time: float = simulator.now()

    def schedule_send_delay(self) -> float:
        """
        Calculates and reserves send delay based on token availability.
        Returns delay (in seconds >= 0.0) until the message can be sent.
        """
        now = self.simulator.now()
        # Refill tokens according to virtual time progression
        elapsed = max(0.0, now - self.last_refill)
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            base_time = max(now, self.next_available_time)
            self.next_available_time = base_time
            return max(0.0, base_time - now)
        else:
            # Deficit: wait until 1 full token accumulates
            wait_time = (1.0 - self.tokens) / self.rate
            base_time = max(now, self.next_available_time)
            send_time = base_time + wait_time
            self.next_available_time = send_time
            self.tokens = 0.0
            return max(0.0, send_time - now)


class Node:
    """Represents a network node hosting a Tendermint ConsensusEngine and P2P stack."""

    def __init__(
        self,
        node_id: str,
        chain_id: str,
        validators: List[str],
        keypair: KeyPair,
        simulator: Simulator,
        transport: UnreliableTransport,
        logger: Optional[DeterministicLogger] = None,
        timeout_config: Optional[TimeoutConfig] = None,
        byzantine_mode: ByzantineMode = ByzantineMode.HONEST,
        traffic_config: Optional[TrafficControlConfig] = None,
    ):
        self.node_id = node_id
        self.chain_id = chain_id
        self.validators = list(validators)
        self.keypair = keypair
        self.simulator = simulator
        self.transport = transport
        self.logger = logger
        self.byzantine_mode = byzantine_mode

        # Traffic control and peer quarantine configuration
        if traffic_config is None:
            tc_data = transport.config.raw_config.get("traffic_control", {})
            traffic_config = TrafficControlConfig(
                outbound_rate_limit=float(tc_data.get("outbound_rate_limit_per_sec", 80.0)),
                outbound_burst_capacity=float(tc_data.get("outbound_burst_capacity", 40.0)),
                peer_block_threshold=int(tc_data.get("peer_block_threshold", 30)),
                peer_window_size=float(tc_data.get("peer_window_size", 1.0)),
                peer_penalty_duration=float(tc_data.get("peer_block_duration", 1.0)),
            )
        self.traffic_config = traffic_config
        self.rate_limiter = OutboundRateLimiter(
            simulator=self.simulator,
            rate=self.traffic_config.outbound_rate_limit,
            burst=self.traffic_config.outbound_burst_capacity,
        )

        # Peer quarantine state
        self.blocked_peers: set[str] = set()
        self.incoming_msg_history: Dict[str, List[float]] = {}

        # Active timers: (timer_type, height, round) -> timer_id
        self.active_timers: Dict[tuple[str, int, int], int] = {}
        # Cached blocks for serving GET_BODY requests
        self.known_blocks: Dict[str, Block] = {}
        # Accepted headers tracking for Header-First protocol
        self.accepted_headers: Dict[str, BlockHeader] = {}

        # Instantiate Consensus State Machine
        self.engine = ConsensusEngine(
            node_id=self.node_id,
            chain_id=self.chain_id,
            validators=self.validators,
            keypair=self.keypair,
            timeout_config=timeout_config,
            broadcast_proposal_fn=self.broadcast_proposal,
            broadcast_vote_fn=self.broadcast_vote,
            schedule_timeout_fn=self.schedule_timeout,
            cancel_timeout_fn=self.cancel_timeout,
            on_finalized_fn=self.on_finalized,
        )

        self.transport.register_node(self.node_id, self.handle_message)
        if self.byzantine_mode != ByzantineMode.HONEST:
            self.transport.mark_byzantine(self.node_id)

    def is_peer_blocked(self, peer_id: str) -> bool:
        """Returns True if peer is currently quarantined."""
        return peer_id in self.blocked_peers

    def schedule_timeout(self, timer_type: str, height: int, round_num: int, duration: float) -> None:
        key = (timer_type, height, round_num)
        self.cancel_timeout(timer_type, height, round_num)

        def cb():
            if key in self.active_timers:
                del self.active_timers[key]
            if self.logger:
                self.logger.log(
                    self.simulator.now(),
                    self.node_id,
                    f"TIMEOUT_{timer_type}",
                    height,
                    round_num,
                    f"duration={duration:.2f}",
                )
            if timer_type == "PROPOSE":
                self.engine.on_timeout_propose(height, round_num)
            elif timer_type == "PREVOTE":
                self.engine.on_timeout_prevote(height, round_num)
            elif timer_type == "PRECOMMIT":
                self.engine.on_timeout_precommit(height, round_num)

        timer_id = self.simulator.schedule_event(duration, cb)
        self.active_timers[key] = timer_id

    def cancel_timeout(self, timer_type: str, height: int, round_num: int) -> None:
        key = (timer_type, height, round_num)
        if key in self.active_timers:
            self.simulator.cancel_event(self.active_timers[key])
            del self.active_timers[key]

    def send_outbound(
        self,
        recipient_id: str,
        message: Any,
        height: int = 0,
        round_num: int = 0,
    ) -> None:
        """Sends an outbound message to a peer, respecting outbound rate limiting."""
        delay = self.rate_limiter.schedule_send_delay()
        if delay <= 0.0:
            self.transport.send(self.node_id, recipient_id, message, height, round_num)
        else:
            self.simulator.schedule_event(
                delay,
                lambda r=recipient_id, m=message, h=height, rnd=round_num: self.transport.send(
                    self.node_id, r, m, h, rnd
                ),
            )

    def broadcast_outbound(
        self,
        recipients: List[str],
        message: Any,
        height: int = 0,
        round_num: int = 0,
    ) -> None:
        """Broadcasts message to multiple peers, rate limiting each outbound transmission."""
        for r in recipients:
            if r != self.node_id:
                self.send_outbound(r, message, height, round_num)

    def broadcast_proposal(self, block: Block) -> None:
        """Header-first broadcast: Proposer first broadcasts BlockHeader."""
        if self.byzantine_mode == ByzantineMode.SILENT_PROPOSER:
            if self.logger:
                self.logger.log(
                    self.simulator.now(),
                    self.node_id,
                    "SILENT_PROPOSER_DROP",
                    block.header.height,
                    block.header.round,
                    f"Dropped proposal {block.hash()[:8]}",
                )
            return

        self.known_blocks[block.hash()] = block
        self.accepted_headers[block.hash()] = block.header
        if self.logger:
            self.logger.log(
                self.simulator.now(),
                self.node_id,
                "PROPOSE",
                block.header.height,
                block.header.round,
                f"block_hash={block.hash()[:8]}",
            )

        # Header-first message broadcast via rate-limited outbound channel
        msg = {"type": "HEADER", "header": block.header}
        self.broadcast_outbound(
            self.validators, msg, block.header.height, block.header.round
        )

    def broadcast_vote(self, vote: Vote) -> None:
        """Broadcasts a PREVOTE or PRECOMMIT via rate-limited outbound channel."""
        if self.logger:
            self.logger.log(
                self.simulator.now(),
                self.node_id,
                vote.phase,
                vote.height,
                vote.round,
                f"block_hash={(vote.block_hash or 'NIL')[:8]}",
            )

        if self.byzantine_mode == ByzantineMode.EQUIVOCATE_VOTES and vote.phase == "PREVOTE":
            # Split peers in half and send conflicting votes
            vote_a, vote_b = create_equivocating_prevotes(
                keypair=self.keypair,
                chain_id=self.chain_id,
                height=vote.height,
                round_num=vote.round,
                block_hash_a=vote.block_hash,
                block_hash_b="conflicting_hash_" + "0" * 48,
            )
            peers = [v for v in self.validators if v != self.node_id]
            half = len(peers) // 2
            for p in peers[:half]:
                self.send_outbound(p, {"type": "VOTE", "vote": vote_a}, vote.height, vote.round)
            for p in peers[half:]:
                self.send_outbound(p, {"type": "VOTE", "vote": vote_b}, vote.height, vote.round)
            return

        msg = {"type": "VOTE", "vote": vote}
        self.broadcast_outbound(self.validators, msg, vote.height, vote.round)

    def _unblock_peer(self, peer_id: str) -> None:
        """Unblocks a quarantined peer after penalty duration expires."""
        if peer_id in self.blocked_peers:
            self.blocked_peers.remove(peer_id)
            if self.logger:
                self.logger.log(
                    self.simulator.now(),
                    self.node_id,
                    "UNBLOCK",
                    self.engine.height,
                    self.engine.round,
                    f"peer={peer_id}",
                )

    def handle_message(self, sender_id: str, msg: Dict[str, Any]) -> None:
        """Handles incoming messages, enforcing peer quarantine and Header-First propagation."""
        now = self.simulator.now()
        cur_h = self.engine.height
        cur_r = self.engine.round

        # 1. Overactive peer blocking check
        if sender_id in self.blocked_peers:
            if self.logger:
                self.logger.log(
                    now,
                    self.node_id,
                    "DROP",
                    cur_h,
                    cur_r,
                    f"blocked peer={sender_id[:12]}",
                )
            return

        # 2. Track incoming message rate
        if sender_id not in self.incoming_msg_history:
            self.incoming_msg_history[sender_id] = []

        window = self.traffic_config.peer_window_size
        cutoff = now - window
        self.incoming_msg_history[sender_id] = [
            t for t in self.incoming_msg_history[sender_id] if t >= cutoff
        ]
        self.incoming_msg_history[sender_id].append(now)

        # 3. Check if threshold exceeded
        if len(self.incoming_msg_history[sender_id]) > self.traffic_config.peer_block_threshold:
            self.blocked_peers.add(sender_id)
            if self.logger:
                self.logger.log(
                    now,
                    self.node_id,
                    "BLOCK",
                    cur_h,
                    cur_r,
                    f"peer={sender_id}",
                )

            self.incoming_msg_history[sender_id] = []
            penalty = self.traffic_config.peer_penalty_duration
            self.simulator.schedule_event(
                penalty,
                lambda s=sender_id: self._unblock_peer(s),
            )

            if self.logger:
                self.logger.log(
                    now,
                    self.node_id,
                    "DROP",
                    cur_h,
                    cur_r,
                    f"blocked peer={sender_id[:12]}",
                )
            return

        # 4. Message dispatch
        mtype = msg.get("type")

        if mtype == "HEADER":
            header: BlockHeader = msg.get("header")
            if not isinstance(header, BlockHeader):
                if self.logger:
                    self.logger.log(now, self.node_id, "DROP", cur_h, cur_r, "REJECT_HEADER: malformed header object")
                return

            # 1. Chain ID check
            if header.chain_id != self.chain_id:
                if self.logger:
                    self.logger.log(now, self.node_id, "DROP", cur_h, cur_r, f"REJECT_HEADER: chain_id mismatch (expected {self.chain_id}, got {header.chain_id})")
                return

            # 2. Height check: must match current engine height
            if header.height != self.engine.height:
                if self.logger:
                    self.logger.log(now, self.node_id, "DROP", cur_h, cur_r, f"REJECT_HEADER: height mismatch (current {self.engine.height}, header {header.height})")
                return

            # 3. Proposer check: must be designated proposer for (header.height, header.round)
            expected_proposer = get_proposer(self.validators, header.height, header.round)
            if header.proposer != expected_proposer:
                if self.logger:
                    self.logger.log(now, self.node_id, "DROP", cur_h, cur_r, f"REJECT_HEADER: proposer mismatch (expected {expected_proposer[:8]}, got {header.proposer[:8]})")
                return

            # 4. Parent Hash check
            expected_parent = self.engine.ledger[-1].hash() if self.engine.ledger else "0" * 64
            if header.parent_hash != expected_parent:
                if self.logger:
                    self.logger.log(now, self.node_id, "DROP", cur_h, cur_r, f"REJECT_HEADER: parent_hash mismatch (expected {expected_parent[:8]}, got {header.parent_hash[:8]})")
                return

            # 5. Header signature check under HEADER:chain_id domain
            header_domain = get_header_domain(self.chain_id)
            if not verify_payload_signature(header.proposer, header_domain, header.signing_payload(), header.signature):
                if self.logger:
                    self.logger.log(now, self.node_id, "DROP", cur_h, cur_r, f"REJECT_HEADER: invalid header signature under {header_domain}")
                return

            # Header is verified and accepted!
            block_h = header.hash()
            self.accepted_headers[block_h] = header

            # Header-first flow: receiver requests body only after header is accepted
            if block_h not in self.known_blocks:
                req = {"type": "GET_BODY", "hash": block_h, "header": header}
                self.send_outbound(sender_id, req, header.height, header.round)

        elif mtype == "GET_BODY":
            block_h = msg.get("hash")
            if block_h in self.known_blocks:
                resp = {"type": "BODY", "block": self.known_blocks[block_h]}
                self.send_outbound(sender_id, resp, self.engine.height, self.engine.round)

        elif mtype == "BODY":
            block: Block = msg.get("block")
            if not isinstance(block, Block) or not hasattr(block, "header") or not hasattr(block, "txs"):
                if self.logger:
                    self.logger.log(now, self.node_id, "DROP", cur_h, cur_r, "REJECT_BODY: malformed block structure")
                return

            block_h = block.hash()

            # 1. Header-First check: body must match an accepted header
            if block_h not in self.accepted_headers and block_h not in self.known_blocks:
                if self.logger:
                    self.logger.log(now, self.node_id, "DROP", cur_h, cur_r, f"REJECT_BODY: header {block_h[:8]} not accepted")
                return

            # 2. Transactions hash consistency check
            computed_txs_hash = compute_txs_hash(block.txs)
            if computed_txs_hash != block.header.txs_hash:
                if self.logger:
                    self.logger.log(now, self.node_id, "DROP", cur_h, cur_r, f"REJECT_BODY: txs_hash mismatch (expected {block.header.txs_hash[:8]}, computed {computed_txs_hash[:8]})")
                return

            # Valid body -> store and forward to Consensus Engine
            self.known_blocks[block_h] = block
            self.engine.on_receive_proposal(block)

        elif mtype == "VOTE":
            vote: Vote = msg["vote"]
            self.engine.on_receive_vote(vote)

    def on_finalized(self, block: Block, state: Any) -> None:
        if self.logger:
            self.logger.log(
                self.simulator.now(),
                self.node_id,
                "FINALIZE",
                block.header.height,
                block.header.round,
                f"block_hash={block.hash()[:8]} state_root={block.header.state_root[:8]}",
            )
