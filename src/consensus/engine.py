"""Tendermint-style 2-phase BFT Consensus State Machine."""

from copy import deepcopy
from typing import Callable, Dict, List, Optional, Tuple
from src.consensus.proposer import TimeoutConfig, get_proposer
from src.consensus.rules import (
    LocalSigningTracker,
    VoteSet,
    can_prevote_block,
    validate_block_proposal,
    validate_incoming_vote,
)
from src.core.executor import Executor
from src.core.state import State
from src.core.types import (
    Block,
    BlockHeader,
    Phase,
    Step,
    Transaction,
    Vote,
    compute_txs_hash,
)
from src.crypto.keys import KeyPair
from src.crypto.sign import get_header_domain, get_vote_domain, sign_payload


class ConsensusEngine:
    """
    Tendermint-style 2-phase BFT Consensus Engine.
    Enforces locking rules 1-7, deterministic proposer rotation, and step transitions.
    """

    def __init__(
        self,
        node_id: str,
        chain_id: str,
        validators: List[str],
        keypair: Optional[KeyPair] = None,
        timeout_config: Optional[TimeoutConfig] = None,
        broadcast_proposal_fn: Optional[Callable[[Block], None]] = None,
        broadcast_vote_fn: Optional[Callable[[Vote], None]] = None,
        schedule_timeout_fn: Optional[Callable[[str, int, int, float], None]] = None,
        cancel_timeout_fn: Optional[Callable[[str, int, int], None]] = None,
        on_finalized_fn: Optional[Callable[[Block, State], None]] = None,
    ):
        n = len(validators)
        if n < 8 or (n - 1) % 3 != 0:
            raise ValueError(
                f"Invalid validator configuration: n={n} must satisfy n >= 8 and n = 3f + 1"
            )

        self.node_id = node_id
        self.chain_id = chain_id
        self.validators = list(validators)
        self.keypair = keypair
        self.f = (n - 1) // 3
        self.quorum = 2 * self.f + 1
        self.timeout_config = timeout_config or TimeoutConfig()

        # Callbacks for network / simulation interaction
        self.broadcast_proposal_fn = broadcast_proposal_fn
        self.broadcast_vote_fn = broadcast_vote_fn
        self.schedule_timeout_fn = schedule_timeout_fn
        self.cancel_timeout_fn = cancel_timeout_fn
        self.on_finalized_fn = on_finalized_fn

        # Consensus state variables
        self.height: int = 1
        self.round: int = 0
        self.step: Step = Step.NEW_ROUND

        self.locked_block: Optional[Block] = None
        self.locked_round: int = -1
        self.valid_block: Optional[Block] = None
        self.valid_round: int = -1

        # Ledger & committed state
        self.committed_state: State = State()
        self.ledger: List[Block] = []

        # Local signing guards & vote tracking
        self.signing_tracker = LocalSigningTracker(self.chain_id)
        # Key: (height, round, phase) -> VoteSet
        self.vote_sets: Dict[Tuple[int, int, str], VoteSet] = {}
        # Key: (height, round) -> Block
        self.proposal_blocks: Dict[Tuple[int, int], Block] = {}

        # Pending transactions pool
        self.mempool: List[Transaction] = []

    def start_height(self, height: int) -> None:
        """Initializes a new consensus height and enters round 0."""
        self.height = height
        self.round = 0
        self.step = Step.NEW_ROUND

        self.locked_block = None
        self.locked_round = -1
        self.valid_block = None
        self.valid_round = -1

        self.start_round(0)

    def start_round(self, round_num: int) -> None:
        """Enters a round at the current height."""
        self.round = round_num
        self.step = Step.PROPOSE

        current_proposer = get_proposer(self.validators, self.height, self.round)
        if self.node_id == current_proposer and self.keypair is not None:
            # This node is the elected proposer
            proposal = self._create_proposal()
            self._broadcast_proposal(proposal)
            # Locally handle the proposal
            self.on_receive_proposal(proposal)

        # Schedule TimeoutPropose
        timeout_dur = self.timeout_config.timeout_propose(self.round)
        self._schedule_timeout("PROPOSE", self.height, self.round, timeout_dur)

    def _create_proposal(self) -> Block:
        """Constructs a block proposal. If valid_block exists, reproposes it; otherwise creates a new block."""
        parent_hash = self.ledger[-1].hash() if self.ledger else "0" * 64

        if self.valid_block is not None:
            # Repropose valid_block with updated round
            txs = deepcopy(self.valid_block.txs)
            state_root = self.valid_block.header.state_root
            txs_hash = self.valid_block.header.txs_hash
        else:
            # Select pending valid transactions
            txs = []
            temp_state = self.committed_state.clone()
            for tx in list(self.mempool):
                ok, _ = temp_state.apply_transaction(tx, self.chain_id)
                if ok:
                    txs.append(tx)
            state_root = temp_state.compute_merkle_root()
            txs_hash = compute_txs_hash(txs)

        header = BlockHeader(
            chain_id=self.chain_id,
            height=self.height,
            round=self.round,
            parent_hash=parent_hash,
            state_root=state_root,
            txs_hash=txs_hash,
            proposer=self.node_id,
            timestamp=0,
        )

        domain = get_header_domain(self.chain_id)
        header.signature = sign_payload(self.keypair, domain, header.signing_payload())
        return Block(header=header, txs=txs)

    def on_timeout_propose(self, height: int, round_num: int) -> None:
        """Handles expiration of TimeoutPropose."""
        if self.height == height and self.round == round_num and self.step == Step.PROPOSE:
            # Propose timed out without valid proposal -> prevote NIL
            self._cast_prevote(None)
            self.step = Step.PREVOTE

    def on_receive_proposal(self, block: Block) -> None:
        """Processes an incoming block proposal."""
        h = block.header
        if h.height != self.height:
            return

        # Record proposal
        self.proposal_blocks[(h.height, h.round)] = block

        if self.step == Step.PROPOSE and h.round == self.round:
            self._cancel_timeout("PROPOSE", self.height, self.round)

            parent_block = self.ledger[-1] if self.ledger else None
            is_valid, err, _ = validate_block_proposal(
                block=block,
                chain_id=self.chain_id,
                current_height=self.height,
                current_round=self.round,
                parent_block=parent_block,
                parent_state=self.committed_state,
                validators=self.validators,
            )

            if is_valid:
                polka_evidence = self._find_polka_evidence(block.hash(), self.height)
                can_prevote, _ = can_prevote_block(
                    candidate_block=block,
                    locked_block=self.locked_block,
                    locked_round=self.locked_round,
                    polka_evidence=polka_evidence,
                    current_height=self.height,
                )
                if can_prevote:
                    self._cast_prevote(block.hash())
                else:
                    self._cast_prevote(None)
            else:
                # Invalid proposal -> prevote NIL
                self._cast_prevote(None)

            self.step = Step.PREVOTE

    def _cast_prevote(self, block_hash: Optional[str]) -> None:
        """Signs and broadcasts a PREVOTE message if not already signed for this round."""
        if self.keypair is None or self.node_id not in self.validators:
            return

        vote = Vote(
            chain_id=self.chain_id,
            height=self.height,
            round=self.round,
            phase=Phase.PREVOTE,
            block_hash=block_hash,
            validator_id=self.node_id,
        )

        domain = get_vote_domain(self.chain_id)
        ok, err = self.signing_tracker.guard_local_signing(
            vote=vote,
            current_chain_id=self.chain_id,
            current_height=self.height,
            current_round=self.round,
            domain_string=domain,
        )
        if not ok:
            return

        vote.signature = sign_payload(self.keypair, domain, vote.signing_payload())
        self._broadcast_vote(vote)
        self.on_receive_vote(vote)

    def _cast_precommit(self, block_hash: Optional[str]) -> None:
        """Signs and broadcasts a PRECOMMIT message if not already signed for this round."""
        if self.keypair is None or self.node_id not in self.validators:
            return

        vote = Vote(
            chain_id=self.chain_id,
            height=self.height,
            round=self.round,
            phase=Phase.PRECOMMIT,
            block_hash=block_hash,
            validator_id=self.node_id,
        )

        domain = get_vote_domain(self.chain_id)
        ok, err = self.signing_tracker.guard_local_signing(
            vote=vote,
            current_chain_id=self.chain_id,
            current_height=self.height,
            current_round=self.round,
            domain_string=domain,
        )
        if not ok:
            return

        vote.signature = sign_payload(self.keypair, domain, vote.signing_payload())
        self._broadcast_vote(vote)
        self.on_receive_vote(vote)

    def on_receive_vote(self, vote: Vote) -> None:
        """Validates and processes an incoming vote."""
        # Rule 6 incoming validation
        ok, err = validate_incoming_vote(vote, self.chain_id, self.validators)
        if not ok:
            return

        key = (vote.height, vote.round, vote.phase)
        if key not in self.vote_sets:
            self.vote_sets[key] = VoteSet(
                height=vote.height,
                round_num=vote.round,
                phase=vote.phase,
                validators=self.validators,
                quorum=self.quorum,
            )

        vote_set = self.vote_sets[key]
        added, _ = vote_set.add_vote(vote)
        if not added:
            return

        if vote.height != self.height:
            return

        # Check PREVOTE transitions
        if vote.phase == Phase.PREVOTE and vote.round == self.round:
            has_quorum, q_block_hash = vote_set.get_quorum_block()
            if has_quorum:
                self._cancel_timeout("PREVOTE", self.height, self.round)
                if q_block_hash is not None:
                    # Rule 4: Quorum for non-NIL block -> lock block and record locked_round
                    prop_block = self.proposal_blocks.get((self.height, self.round))
                    if prop_block and prop_block.hash() == q_block_hash:
                        self.locked_block = prop_block
                        self.locked_round = self.round
                        self.valid_block = prop_block
                        self.valid_round = self.round

                    if self.step == Step.PREVOTE:
                        self._cast_precommit(q_block_hash)
                        self.step = Step.PRECOMMIT
                else:
                    # Quorum for NIL
                    if self.step == Step.PREVOTE:
                        self._cast_precommit(None)
                        self.step = Step.PRECOMMIT
            elif vote_set.total_votes() >= self.quorum and self.step == Step.PREVOTE:
                timeout_dur = self.timeout_config.timeout_prevote(self.round)
                self._schedule_timeout("PREVOTE", self.height, self.round, timeout_dur)

        # Check PRECOMMIT transitions
        elif vote.phase == Phase.PRECOMMIT and vote.round == self.round:
            has_quorum, q_block_hash = vote_set.get_quorum_block()
            if has_quorum:
                self._cancel_timeout("PRECOMMIT", self.height, self.round)
                if q_block_hash is not None:
                    prop_block = self.proposal_blocks.get((self.height, self.round))
                    if prop_block and prop_block.hash() == q_block_hash:
                        self._finalize_block(prop_block)
                else:
                    if self.step == Step.PRECOMMIT:
                        self._advance_round()
            elif vote_set.total_votes() >= self.quorum and self.step == Step.PRECOMMIT:
                timeout_dur = self.timeout_config.timeout_precommit(self.round)
                self._schedule_timeout("PRECOMMIT", self.height, self.round, timeout_dur)

    def on_timeout_prevote(self, height: int, round_num: int) -> None:
        """Handles expiration of TimeoutPrevote."""
        if self.height == height and self.round == round_num and self.step == Step.PREVOTE:
            self._cast_precommit(None)
            self.step = Step.PRECOMMIT

    def on_timeout_precommit(self, height: int, round_num: int) -> None:
        """Handles expiration of TimeoutPrecommit."""
        if self.height == height and self.round == round_num and self.step == Step.PRECOMMIT:
            self._advance_round()

    def _advance_round(self) -> None:
        """Moves to the next round at the current height."""
        self.start_round(self.round + 1)

    def _finalize_block(self, block: Block) -> None:
        """Finalizes block, executes state transition, updates ledger, and advances height."""
        ok, new_state, _, receipts, err = Executor.execute_block(
            self.committed_state, block, self.chain_id
        )
        if not ok:
            return

        self.committed_state = new_state
        self.ledger.append(block)

        # Prune applied transactions from mempool
        applied_hashes = {tx.hash() for tx in block.txs}
        self.mempool = [tx for tx in self.mempool if tx.hash() not in applied_hashes]

        if self.on_finalized_fn:
            self.on_finalized_fn(block, self.committed_state)

        # Advance to next height
        self.start_height(self.height + 1)

    def _find_polka_evidence(self, block_hash: str, height: int) -> Optional[VoteSet]:
        """Finds any VoteSet in a prior round (> locked_round) with a 2f+1 quorum for block_hash."""
        for (h, r, phase), vset in self.vote_sets.items():
            if h == height and phase == Phase.PREVOTE and r > self.locked_round:
                if vset.has_quorum_for(block_hash):
                    return vset
        return None

    def _broadcast_proposal(self, block: Block) -> None:
        if self.broadcast_proposal_fn:
            self.broadcast_proposal_fn(block)

    def _broadcast_vote(self, vote: Vote) -> None:
        if self.broadcast_vote_fn:
            self.broadcast_vote_fn(vote)

    def _schedule_timeout(self, timer_type: str, height: int, round_num: int, duration: float) -> None:
        if self.schedule_timeout_fn:
            self.schedule_timeout_fn(timer_type, height, round_num, duration)

    def _cancel_timeout(self, timer_type: str, height: int, round_num: int) -> None:
        if self.cancel_timeout_fn:
            self.cancel_timeout_fn(timer_type, height, round_num)
