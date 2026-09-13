"""Strict JSON parsing and RFC 8785 (JCS) canonicalization.

Strict mode rejects: duplicate object keys, non-integer numbers (NaN,
Infinity, floats), unsafe integer literals (>2^53-1), and non-str keys.
Canonical form: UTF-8, keys sorted by UTF-16BE code units, minimal
separators, integers as bare decimals. Floats never appear in this
protocol's signed domain, so JCS here implements the integer/string/
bool/null/array/object profile used by Mint documents.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .errors import malformed

MAX_SAFE_INT = 9007199254740991  # 2^53 - 1

_AMOUNT_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_ID_RE = re.compile(r"^[a-zA-Z0-9:_-]{1,96}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if not isinstance(k, str):
            raise malformed("non-string object key")
        if k in out:
            raise malformed(f"duplicate object key: {k!r}")
        out[k] = v
    return out


def _reject_number(x: Any) -> Any:
    raise malformed(f"non-integer or non-finite number literal: {x!r}")


def parse_strict(data: bytes | str) -> Any:
    """Parse JSON with duplicate-key, NaN/Infinity, and float rejection."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise malformed("request body is not valid UTF-8") from e
    try:
        obj = json.loads(
            data,
            object_pairs_hook=_reject_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except json.JSONDecodeError as e:
        raise malformed(f"invalid JSON: {e}") from e
    _check_ints(obj)
    return obj


def _check_ints(x: Any) -> None:
    if isinstance(x, bool):
        return
    if isinstance(x, int):
        if abs(x) > MAX_SAFE_INT:
            raise malformed("unsafe integer literal (>2^53-1)")
        return
    if isinstance(x, list):
        for v in x:
            _check_ints(v)
    elif isinstance(x, dict):
        for v in x.values():
            _check_ints(v)


def jcs(obj: Any) -> bytes:
    """RFC 8785 canonical JSON for Mint's signed domain."""
    if obj is None or isinstance(obj, (bool, str)):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
    if isinstance(obj, int) and not isinstance(obj, bool):
        if abs(obj) > MAX_SAFE_INT:
            raise ValueError("integer outside safe JSON range")
        return str(obj).encode("ascii")
    if isinstance(obj, list):
        return b"[" + b",".join(jcs(v) for v in obj) + b"]"
    if isinstance(obj, dict):
        if not all(isinstance(k, str) for k in obj):
            raise ValueError("non-string key")
        keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be"))
        return (
            b"{"
            + b",".join(jcs(k) + b":" + jcs(obj[k]) for k in keys)
            + b"}"
        )
    raise ValueError(f"value outside canonical JSON profile: {type(obj)}")


def jcs_text(obj: Any) -> str:
    return jcs(obj).decode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def domain_hash(tag: str, obj: Any) -> str:
    """SHA256(tag || 0x00 || JCS(obj)) — Mint's domain-separated digest."""
    return sha256_hex(tag.encode("ascii") + b"\x00" + jcs(obj))


def parse_amount(value: Any, field: str = "amount") -> int:
    """Amounts: unsigned decimal strings `0|[1-9][0-9]*`, bounded by 2^63-1."""
    if not isinstance(value, str) or not _AMOUNT_RE.match(value):
        raise malformed(
            f"{field} must be an unsigned decimal string matching 0|[1-9][0-9]*"
        )
    n = int(value)
    if n > 2**63 - 1:
        raise malformed(f"{field} exceeds 2^63-1")
    return n


def fmt_amount(n: int) -> str:
    if n < 0:
        raise ValueError("negative amount")
    return str(n)


def check_id(value: Any, field: str = "id") -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise malformed(
            f"{field} must match [a-zA-Z0-9:_-]{{1,96}}", {"field": field}
        )
    return value


def check_hex64(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        raise malformed(f"{field} must be 64 lowercase hex characters")
    return value


def check_nonce(value: Any) -> str:
    if not isinstance(value, str) or not _NONCE_RE.match(value):
        raise malformed("nonce must be 32 lowercase hex characters")
    return value


def check_fields(obj: dict, allowed: set[str], required: set[str]) -> None:
    """Closed-schema argument validation: unknown fields rejected."""
    for k in obj:
        if k not in allowed:
            raise malformed(f"unknown field: {k}")
    for k in required:
        if k not in obj:
            raise malformed(f"missing required field: {k}")
