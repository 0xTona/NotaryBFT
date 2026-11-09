"""Proposer selection and round timeout management."""

from dataclasses import dataclass
from typing import List


def get_proposer(validators: List[str], height: int, round_num: int) -> str:
    """
    Deterministically selects the proposer for a given height and round using round-robin rotation.
    Formula: index = (height + round_num) % len(validators).
    """
    if not validators:
        raise ValueError("Validator set cannot be empty")
    index = (height + round_num) % len(validators)
    return validators[index]


@dataclass
class TimeoutConfig:
    timeout_propose_base: float = 1.0
    timeout_propose_delta: float = 0.5
    timeout_prevote_base: float = 1.0
    timeout_prevote_delta: float = 0.5
    timeout_precommit_base: float = 1.0
    timeout_precommit_delta: float = 0.5

    def timeout_propose(self, round_num: int) -> float:
        return self.timeout_propose_base + round_num * self.timeout_propose_delta

    def timeout_prevote(self, round_num: int) -> float:
        return self.timeout_prevote_base + round_num * self.timeout_prevote_delta

    def timeout_precommit(self, round_num: int) -> float:
        return self.timeout_precommit_base + round_num * self.timeout_precommit_delta
