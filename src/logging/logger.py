"""Deterministic structured event logger."""

from typing import List, Optional, Set


class DeterministicLogger:
    """
    Structured logger conforming to the Lab 01 specification format:
    [TIMESTAMP] [NODE_ID] [EVENT_TYPE] [HEIGHT] [ROUND] [DETAILS]
    
    Timestamps are standardized in milliseconds with fixed-width formatting
    to maintain sub-millisecond precision and byte-level determinism.
    """

    SUPPORTED_EVENT_TYPES: Set[str] = {
        "SEND",
        "DROP",
        "DELAY",
        "BLOCK",
        "UNBLOCK",
        "PROPOSE",
        "PREVOTE",
        "PRECOMMIT",
        "FINALIZE",
        "TIMEOUT_PROPOSE",
        "TIMEOUT_PREVOTE",
        "TIMEOUT_PRECOMMIT",
        "SILENT_PROPOSER_DROP",
    }

    def __init__(self, log_to_console: bool = False):
        self.entries: List[str] = []
        self.log_to_console = log_to_console

    def format_timestamp(self, timestamp: int | float) -> str:
        """Converts virtual time seconds to standardized fixed-width milliseconds."""
        # e.g., 0.050s -> 0000050.0ms (fixed width for deterministic alignment)
        ms = float(timestamp) * 1000.0
        return f"{ms:09.1f}ms"

    def log(
        self,
        timestamp: int | float,
        node_id: str,
        event_type: str,
        height: int,
        round_num: int,
        details: str,
    ) -> str:
        # Standardize node_id display (e.g. truncated hex for readability if 64 chars)
        nid = node_id[:12] if len(node_id) > 12 else node_id
        ts_str = self.format_timestamp(timestamp)
        line = f"[{ts_str}] [{nid}] [{event_type}] [{height}] [{round_num}] [{details}]"
        self.entries.append(line)
        if self.log_to_console:
            print(line)
        return line

    def log_block(self, timestamp: int | float, node_id: str, peer_id: str, height: int, round_num: int, reason: str = "") -> str:
        """Helper to log BLOCK event when an overactive peer is quarantined."""
        details = f"peer={peer_id[:12]}" + (f" reason={reason}" if reason else "")
        return self.log(timestamp, node_id, "BLOCK", height, round_num, details)

    def log_unblock(self, timestamp: int | float, node_id: str, peer_id: str, height: int, round_num: int) -> str:
        """Helper to log UNBLOCK event when quarantine expires."""
        return self.log(timestamp, node_id, "UNBLOCK", height, round_num, f"peer={peer_id[:12]}")

    def get_full_log(self) -> str:
        return "\n".join(self.entries) + ("\n" if self.entries else "")

    def write_to_file(self, file_path: str) -> None:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.get_full_log())
