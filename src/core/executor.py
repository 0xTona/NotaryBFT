"""State transition function and block execution receipts."""

from dataclasses import dataclass
from typing import List, Tuple
from src.core.state import State
from src.core.types import Block, compute_txs_hash


@dataclass
class Receipt:
    tx_hash: str
    status: bool
    error: str = ""


class Executor:
    @staticmethod
    def execute_block(
        parent_state: State, block: Block, chain_id: str
    ) -> Tuple[bool, State, str, List[Receipt], str]:
        """
        Executes all transactions in a block deterministically against the parent state.
        Returns:
            (success, new_state, new_state_root, receipts, error_message)
        If any transaction fails or state root mismatches, the parent state is preserved intact.
        """
        # Verify txs_hash matches transactions in body
        expected_txs_hash = compute_txs_hash(block.txs)
        if block.header.txs_hash != expected_txs_hash:
            return (
                False,
                parent_state,
                "",
                [],
                f"Block txs_hash mismatch: expected {expected_txs_hash}, got {block.header.txs_hash}",
            )

        new_state = parent_state.clone()
        receipts: List[Receipt] = []

        for tx in block.txs:
            tx_h = tx.hash()
            ok, err = new_state.apply_transaction(tx, chain_id)
            if not ok:
                receipts.append(Receipt(tx_hash=tx_h, status=False, error=err))
                # Block execution fails on any invalid transaction
                return False, parent_state, "", receipts, f"Tx {tx_h} failed: {err}"
            receipts.append(Receipt(tx_hash=tx_h, status=True, error=""))

        computed_state_root = new_state.compute_merkle_root()
        if block.header.state_root != computed_state_root:
            return (
                False,
                parent_state,
                computed_state_root,
                receipts,
                f"State root mismatch: header commits to {block.header.state_root}, computed {computed_state_root}",
            )

        return True, new_state, computed_state_root, receipts, ""
