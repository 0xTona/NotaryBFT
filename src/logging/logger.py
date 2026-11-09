"""Deterministic structured event logger."""

from typing import List, Optional


class DeterministicLogger:
    """
    Structured logger conforming to the Lab 01 specification format:
    [TIMESTAMP] [NODE_ID] [EVENT_TYPE] [HEIGHT] [ROUND] [DETAILS]
    """

    def __init__(self, log_to_console: bool = False):
        self.entries: List[str] = []
        self.log_to_console = log_to_console

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
        # Format timestamp to 6 digits integer or fixed float
        ts_str = f"{int(timestamp):06d}"
        line = f"[{ts_str}] [{nid}] [{event_type}] [{height}] [{round_num}] [{details}]"
        self.entries.append(line)
        if self.log_to_console:
            print(line)
        return line

    def get_full_log(self) -> str:
        return "\n".join(self.entries) + ("\n" if self.entries else "")

    def write_to_file(self, file_path: str) -> None:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.get_full_log())
