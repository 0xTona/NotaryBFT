"""P2P layer: Header-first gossip propagation and node harness."""

from typing import Any, Dict, List, Optional
from src.byzantine.behaviors import ByzantineMode, create_equivocating_prevotes
from src.consensus.engine import ConsensusEngine
from src.consensus.proposer import TimeoutConfig
from src.core.types import Block, BlockHeader, Vote
from src.crypto.keys import KeyPair
from src.logging.logger import DeterministicLogger
from src.network.link import UnreliableTransport
from src.network.simulator import Simulator


class Node:
    """Represents a network node hosting a Tendermint ConsensusEngine."""

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
    ):
        self.node_id = node_id
        self.chain_id = chain_id
        self.validators = list(validators)
        self.keypair = keypair
        self.simulator = simulator
        self.transport = transport
        self.logger = logger
        self.byzantine_mode = byzantine_mode

        # Active timers: (timer_type, height, round) -> timer_id
        self.active_timers: Dict[tuple[str, int, int], int] = {}
        # Cached blocks for serving GET_BODY requests
        self.known_blocks: Dict[str, Block] = {}

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
        if self.logger:
            self.logger.log(
                self.simulator.now(),
                self.node_id,
                "PROPOSE",
                block.header.height,
                block.header.round,
                f"block_hash={block.hash()[:8]}",
            )

        # Header-first message
        msg = {"type": "HEADER", "header": block.header}
        self.transport.broadcast(
            self.node_id, self.validators, msg, block.header.height, block.header.round
        )

    def broadcast_vote(self, vote: Vote) -> None:
        """Broadcasts a PREVOTE or PRECOMMIT."""
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
                self.transport.send(self.node_id, p, {"type": "VOTE", "vote": vote_a}, vote.height, vote.round)
            for p in peers[half:]:
                self.transport.send(self.node_id, p, {"type": "VOTE", "vote": vote_b}, vote.height, vote.round)
            return

        msg = {"type": "VOTE", "vote": vote}
        self.transport.broadcast(self.node_id, self.validators, msg, vote.height, vote.round)

    def handle_message(self, sender_id: str, msg: Dict[str, Any]) -> None:
        mtype = msg.get("type")

        if mtype == "HEADER":
            header: BlockHeader = msg["header"]
            # Header-first flow: receiver requests body if not already present
            block_h = header.hash()
            if block_h not in self.known_blocks:
                req = {"type": "GET_BODY", "hash": block_h, "header": header}
                self.transport.send(self.node_id, sender_id, req, header.height, header.round)

        elif mtype == "GET_BODY":
            block_h = msg["hash"]
            if block_h in self.known_blocks:
                resp = {"type": "BODY", "block": self.known_blocks[block_h]}
                self.transport.send(self.node_id, sender_id, resp)

        elif mtype == "BODY":
            block: Block = msg["block"]
            self.known_blocks[block.hash()] = block
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
