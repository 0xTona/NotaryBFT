"""Canonical deterministic byte serializer and hashing utilities."""

import hashlib
import json
from typing import Any


def canonical_encode(data: Any) -> bytes:
    """Deterministically serializes data into bytes with sorted keys and no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256(data: bytes) -> bytes:
    """Computes SHA-256 raw bytes digest."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Computes SHA-256 hexadecimal string digest."""
    return hashlib.sha256(data).hexdigest()


def canonical_hash(data: Any) -> str:
    """Serializes data canonically and returns its SHA-256 hexadecimal digest."""
    return sha256_hex(canonical_encode(data))
