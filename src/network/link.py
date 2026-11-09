"""Simulated unreliable network transport with drop, delay, duplication, and reordering."""

from dataclasses import dataclass
import random
from typing import Any, Callable, Dict, Optional
from src.logging.logger import DeterministicLogger
from src.network.simulator import Simulator


@dataclass
class NetworkFaultConfig:
    drop_rate: float = 0.0
    duplicate_rate: float = 0.0
    min_delay: float = 0.1
    max_delay: float = 0.5
    t_stabilize: float = 1000.0
    delta: float = 0.5  # Maximum delivery delay after stabilization


class UnreliableTransport:
    """
    Simulated network transport layer.
    Prior to t_stabilize, messages may be dropped, duplicated, delayed, or reordered.
    At or after t_stabilize, messages between correct nodes are delivered without loss within delta.
    """

    def __init__(
        self,
        simulator: Simulator,
        config: NetworkFaultConfig,
        logger: Optional[DeterministicLogger] = None,
        seed: int = 42,
    ):
        self.simulator = simulator
        self.config = config
        self.logger = logger
        self.rng = random.Random(seed)
        self.handlers: Dict[str, Callable[[str, Any], None]] = {}
        # Fault injection overrides per node pair or sender
        self.byzantine_nodes: set[str] = set()

    def register_node(self, node_id: str, handler: Callable[[str, Any], None]) -> None:
        self.handlers[node_id] = handler

    def mark_byzantine(self, node_id: str) -> None:
        self.byzantine_nodes.add(node_id)

    def send(
        self,
        sender_id: str,
        recipient_id: str,
        message: Any,
        height: int = 0,
        round_num: int = 0,
    ) -> None:
        now = self.simulator.now()

        if self.logger:
            self.logger.log(now, sender_id, "SEND", height, round_num, f"to={recipient_id[:8]}")

        # Post-stabilization for correct nodes
        is_stabilized = now >= self.config.t_stabilize
        is_both_honest = (sender_id not in self.byzantine_nodes) and (
            recipient_id not in self.byzantine_nodes
        )

        if not is_stabilized or not is_both_honest:
            # Pre-stabilization fault pipeline
            if self.rng.random() < self.config.drop_rate:
                if self.logger:
                    self.logger.log(
                        now, sender_id, "DROP", height, round_num, f"to={recipient_id[:8]}"
                    )
                return  # Message dropped

            delay = self.rng.uniform(self.config.min_delay, self.config.max_delay)
            if self.logger:
                self.logger.log(
                    now, sender_id, "DELAY", height, round_num, f"delay={delay:.3f} to={recipient_id[:8]}"
                )

            # Check duplication
            if self.rng.random() < self.config.duplicate_rate:
                # Schedule duplicate with additional jitter
                dup_delay = delay + self.rng.uniform(0.01, 0.05)
                self.simulator.schedule_event(
                    dup_delay,
                    lambda s=sender_id, r=recipient_id, m=message: self._deliver(s, r, m),
                )
        else:
            # Stabilized: delivered without drop within delta
            delay = self.rng.uniform(0.01, min(self.config.delta, self.config.max_delay))

        self.simulator.schedule_event(
            delay,
            lambda s=sender_id, r=recipient_id, m=message: self._deliver(s, r, m),
        )

    def broadcast(
        self,
        sender_id: str,
        recipients: list[str],
        message: Any,
        height: int = 0,
        round_num: int = 0,
    ) -> None:
        for r in recipients:
            if r != sender_id:
                self.send(sender_id, r, message, height, round_num)

    def _deliver(self, sender_id: str, recipient_id: str, message: Any) -> None:
        if recipient_id in self.handlers:
            self.handlers[recipient_id](sender_id, message)
