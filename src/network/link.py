"""Simulated unreliable network transport with drop, delay, duplication, and reordering."""

from dataclasses import dataclass, field
import json
import random
from typing import Any, Callable, Dict, List, Optional, Tuple
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
    latency_matrix: Dict[str, Dict[str, List[float]]] = field(default_factory=dict)
    raw_config: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json_file(cls, path: str) -> "NetworkFaultConfig":
        """Loads network parameters and latency matrix from a JSON topology file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        sync = data.get("synchrony_parameters", {})
        matrix = data.get("latency_matrix", {})
        return cls(
            drop_rate=sync.get("drop_rate", 0.0),
            duplicate_rate=sync.get("duplicate_rate", 0.0),
            min_delay=sync.get("default_min_delay", 0.05),
            max_delay=sync.get("default_max_delay", 0.15),
            t_stabilize=sync.get("t_stabilize", 2.0),
            delta=sync.get("delta", 0.2),
            latency_matrix=matrix,
            raw_config=data,
        )


class UnreliableTransport:
    """
    Simulated network transport layer.
    Prior to t_stabilize, messages may be dropped, duplicated, delayed, or reordered.
    At or after t_stabilize, messages between correct nodes are delivered without loss within delta.
    Supports file-driven topology configurations and pair-specific latencies.
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
        # Node alias map: allows mapping public key hex to aliases like "val_0"
        self.node_alias_map: Dict[str, str] = {}
        # Fault injection overrides per node pair or sender
        self.byzantine_nodes: set[str] = set()
        # Post-stabilization verification metrics
        self.stabilized_deliveries: List[Dict[str, Any]] = []
        self.stabilized_drops: int = 0

    @classmethod
    def from_config_file(
        cls,
        config_path: str,
        simulator: Simulator,
        logger: Optional[DeterministicLogger] = None,
        seed: int = 42,
    ) -> "UnreliableTransport":
        """Factory method to instantiate transport directly from topology JSON."""
        cfg = NetworkFaultConfig.from_json_file(config_path)
        return cls(simulator=simulator, config=cfg, logger=logger, seed=seed)

    def register_node(
        self,
        node_id: str,
        handler: Callable[[str, Any], None],
        alias: Optional[str] = None,
    ) -> None:
        self.handlers[node_id] = handler
        if alias is not None:
            self.node_alias_map[node_id] = alias
        elif node_id not in self.node_alias_map:
            # Auto-assign index-based alias "val_i" if alias not provided
            auto_idx = len(self.handlers) - 1
            self.node_alias_map[node_id] = f"val_{auto_idx}"

    def set_alias(self, node_id: str, alias: str) -> None:
        self.node_alias_map[node_id] = alias

    def mark_byzantine(self, node_id: str) -> None:
        self.byzantine_nodes.add(node_id)

    def get_link_bounds(self, sender_id: str, recipient_id: str) -> Tuple[float, float]:
        """Looks up pair-specific latency bounds from matrix if available, else returns defaults."""
        matrix = self.config.latency_matrix
        if matrix:
            s_alias = self.node_alias_map.get(sender_id, sender_id)
            r_alias = self.node_alias_map.get(recipient_id, recipient_id)
            if s_alias in matrix and r_alias in matrix[s_alias]:
                bounds = matrix[s_alias][r_alias]
                return float(bounds[0]), float(bounds[1])
        return self.config.min_delay, self.config.max_delay

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

        # Post-stabilization check for correct nodes
        is_stabilized = now >= self.config.t_stabilize
        is_both_honest = (sender_id not in self.byzantine_nodes) and (
            recipient_id not in self.byzantine_nodes
        )

        min_d, max_d = self.get_link_bounds(sender_id, recipient_id)

        if not is_stabilized or not is_both_honest:
            # Pre-stabilization fault pipeline
            if self.rng.random() < self.config.drop_rate:
                if self.logger:
                    self.logger.log(
                        now, sender_id, "DROP", height, round_num, f"to={recipient_id[:8]}"
                    )
                return  # Message dropped

            delay = self.rng.uniform(min_d, max_d)
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

            self.simulator.schedule_event(
                delay,
                lambda s=sender_id, r=recipient_id, m=message: self._deliver(s, r, m),
            )
        else:
            # Stabilized: delivered without drop within delta bound
            delay = self.rng.uniform(0.01, min(self.config.delta, max_d))
            self.simulator.schedule_event(
                delay,
                lambda s=sender_id, r=recipient_id, m=message, st=now: self._deliver_and_track(s, r, m, st),
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

    def _deliver_and_track(
        self, sender_id: str, recipient_id: str, message: Any, send_time: float
    ) -> None:
        actual_delay = self.simulator.now() - send_time
        self.stabilized_deliveries.append({
            "sender": sender_id,
            "recipient": recipient_id,
            "send_time": send_time,
            "delivery_time": self.simulator.now(),
            "delay": actual_delay,
        })
        self._deliver(sender_id, recipient_id, message)

    def _deliver(self, sender_id: str, recipient_id: str, message: Any) -> None:
        if recipient_id in self.handlers:
            self.handlers[recipient_id](sender_id, message)
