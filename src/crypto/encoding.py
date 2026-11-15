"""Canonical deterministic byte serializer and hashing utilities.

Encoding specification (used for every hash and signature in the system):

* Output is canonical JSON encoded as UTF-8 bytes.
* Object keys must be strings and are emitted in ascending code-point order
  (identical to UTF-8 byte order), with no insignificant whitespace.
* Non-ASCII characters are escaped as ``\\uXXXX`` so the output is pure ASCII.
* Allowed value types: ``None``, ``bool``, ``int``, ``str``, ``list``/``tuple``
  and ``dict`` with ``str`` keys. ``Enum`` members are replaced by their value.
* ``float`` (including NaN/Infinity), ``bytes`` and any other type are rejected,
  because their textual form is not guaranteed to be identical across runtimes.
  Callers must hex-encode binary data before encoding.

Two logically equal payloads therefore always produce the same bytes on every node.
"""

import hashlib
import json
from enum import Enum
from typing import Any


class CanonicalEncodingError(TypeError):
    """Raised when a payload contains a value with no canonical encoding."""


def _normalize(value: Any, path: str = "$") -> Any:
    """Recursively validates a payload and converts it to plain JSON-safe types."""
    if isinstance(value, Enum):
        return _normalize(value.value, path)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [_normalize(v, f"{path}[{i}]") for i, v in enumerate(value)]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, Enum):
                k = k.value
            if not isinstance(k, str):
                raise CanonicalEncodingError(f"Non-string map key {k!r} at {path}")
            out[str(k)] = _normalize(v, f"{path}.{k}")
        return out
    raise CanonicalEncodingError(
        f"Unsupported type {type(value).__name__} at {path}; only None/bool/int/str/list/dict are canonical"
    )


def canonical_encode(data: Any) -> bytes:
    """Deterministically serializes data into bytes with sorted keys and no whitespace."""
    normalized = _normalize(data)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256(data: bytes) -> bytes:
    """Computes SHA-256 raw bytes digest."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Computes SHA-256 hexadecimal string digest."""
    return hashlib.sha256(data).hexdigest()


def canonical_hash(data: Any) -> str:
    """Serializes data canonically and returns its SHA-256 hexadecimal digest."""
    return sha256_hex(canonical_encode(data))


def length_prefixed(data: bytes) -> bytes:
    """Encodes a byte string as a 4-byte big-endian length followed by the bytes."""
    if len(data) > 0xFFFFFFFF:
        raise ValueError("Field too large for 4-byte length prefix")
    return len(data).to_bytes(4, "big") + data
