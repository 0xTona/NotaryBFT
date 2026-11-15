"""Genesis configuration: chain ID, fixed validator set and initial state."""

from dataclasses import dataclass, field, replace
import json
from typing import Dict, List
from src.crypto.keys import KeyPair


@dataclass(frozen=True)
class Genesis:
    chain_id: str = "layer1-chain"
    num_validators: int = 10
    validator_key_seed_template: str = "val_key_{index}_seed_{seed}"
    initial_state: Dict[str, str] = field(default_factory=dict)

    @property
    def f(self) -> int:
        return (self.num_validators - 1) // 3

    @property
    def quorum(self) -> int:
        return 2 * self.f + 1

    def with_validators(self, num_validators: int) -> "Genesis":
        g = replace(self, num_validators=num_validators)
        g.validate()
        return g

    def validate(self) -> None:
        validate_validator_count(self.num_validators)
        if not isinstance(self.chain_id, str) or not self.chain_id:
            raise ValueError("chain_id must be a non-empty string")
        if "{index}" not in self.validator_key_seed_template:
            raise ValueError("validator_key_seed_template must contain {index}")
        for k, v in self.initial_state.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValueError("initial_state keys and values must be strings")

    def validator_keypairs(self, seed: int) -> List[KeyPair]:
        """Derives the fixed validator key pairs for a run (simulation-only seeds)."""
        return [
            KeyPair.from_seed(self.validator_key_seed_template.format(index=i, seed=seed))
            for i in range(self.num_validators)
        ]


def validate_validator_count(n: int) -> None:
    """Rejects configurations violating n >= 8 and n = 3f + 1."""
    if not isinstance(n, int) or isinstance(n, bool):
        raise ValueError("Validator count must be an integer")
    if n < 8 or (n - 1) % 3 != 0:
        raise ValueError(
            f"Invalid validator configuration: n={n} must satisfy n >= 8 and n = 3f + 1 (e.g. 10, 13, 16)"
        )


def load_genesis(path: str) -> Genesis:
    with open(path, "r", encoding="utf-8-sig") as fh:  # tolerate a BOM from Windows editors
        data = json.load(fh)
    g = Genesis(
        chain_id=data.get("chain_id", "layer1-chain"),
        num_validators=int(data.get("num_validators", 10)),
        validator_key_seed_template=data.get("validator_key_seed_template", "val_key_{index}_seed_{seed}"),
        initial_state=dict(data.get("initial_state", {})),
    )
    g.validate()
    # Stated f/quorum (if present) must agree with the derived values
    if "f" in data and int(data["f"]) != g.f:
        raise ValueError(f"genesis f={data['f']} inconsistent with n={g.num_validators} (expected {g.f})")
    if "quorum" in data and int(data["quorum"]) != g.quorum:
        raise ValueError(f"genesis quorum={data['quorum']} inconsistent with f={g.f} (expected {g.quorum})")
    return g
