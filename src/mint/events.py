"""Event encoding, hash chain, Merkle trees, checkpoints (spec §9.2-9.3).

event_hash = SHA256(UTF8("mint.log.v1") || 0x00 || JCS(event_without_hash))
Merkle leaf = SHA256(0x00 || raw_32_byte_event_hash)
Merkle node = SHA256(0x01 || left || right), split at largest power of two
smaller than the leaf count; odd leaves are never duplicated.
"""

from __future__ import annotations

from .jsonutil import domain_hash, sha256, sha256_hex

ZERO_HASH = "0" * 64
EMPTY_ROOT = sha256_hex(b"")


def event_hash(event_without_hash: dict) -> str:
    return domain_hash("mint.log.v1", event_without_hash)


def make_event(seq: int, prev: str, time_str: str, etype: str, data: dict) -> dict:
    ev = {"seq": seq, "prev": prev, "time": time_str, "type": etype, "data": data}
    ev["hash"] = event_hash(ev)
    return ev


def merkle_leaves(event_hashes: list[str]) -> list[bytes]:
    return [sha256(b"\x00" + bytes.fromhex(h)) for h in event_hashes]


def _largest_pow2_lt(n: int) -> int:
    p = 1
    while p * 2 < n:
        p *= 2
    return p


def merkle_root(event_hashes: list[str]) -> str:
    leaves = merkle_leaves(event_hashes)
    if not leaves:
        return EMPTY_ROOT
    return _subroot(leaves).hex()


def _subroot(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = _largest_pow2_lt(len(leaves))
    left, right = leaves[:k], leaves[k:]
    return sha256(b"\x01" + _subroot(left) + _subroot(right))


def merkle_path(event_hashes: list[str], leaf_index: int) -> list[str]:
    """Inclusion path for leaf_index (sibling hashes, bottom-up)."""
    leaves = merkle_leaves(event_hashes)
    if not (0 <= leaf_index < len(leaves)):
        raise IndexError("leaf_index out of range")
    return _path(leaves, leaf_index)


def _path(leaves: list[bytes], idx: int) -> list[str]:
    if len(leaves) == 1:
        return []
    k = _largest_pow2_lt(len(leaves))
    if idx < k:
        return _path(leaves[:k], idx) + [_subroot(leaves[k:]).hex()]
    return _path(leaves[k:], idx - k) + [_subroot(leaves[:k]).hex()]


def merkle_verify(leaf_hash_hex: str, leaf_index: int, tree_size: int,
                  path: list[str]) -> str:
    """Recompute the root from a leaf and inclusion path.

    The path is emitted bottom-up (deepest sibling first), so compute the
    leaf's descent directions top-down, then consume them in reverse."""
    if tree_size == 0:
        return EMPTY_ROOT
    node = sha256(b"\x00" + bytes.fromhex(leaf_hash_hex))
    dirs: list[bool] = []  # True = leaf descended into the left subtree
    idx, n = leaf_index, tree_size
    while n > 1:
        k = _largest_pow2_lt(n)
        if idx < k:
            dirs.append(True)
            n = k
        else:
            dirs.append(False)
            idx -= k
            n -= k
    if len(dirs) != len(path):
        raise ValueError("inclusion path length does not match tree size")
    for sib_hex in path:
        sib = bytes.fromhex(sib_hex)
        if dirs.pop():
            node = sha256(b"\x01" + node + sib)
        else:
            node = sha256(b"\x01" + sib + node)
    return node.hex()


def checkpoint_body(checkpoint_id: str, market_id: str, size: int,
                    chain_head: str, root: str, time_str: str,
                    witness_key_epoch: int) -> dict:
    return {
        "checkpoint_id": checkpoint_id,
        "market_id": market_id,
        "size": size,
        "chain_head": chain_head,
        "merkle_root": root,
        "time": time_str,
        "witness_key_epoch": witness_key_epoch,
    }


def checkpoint_signing_bytes(body: dict) -> bytes:
    from .jsonutil import jcs

    return b"mint.checkpoint.v1\x00" + jcs(body)
