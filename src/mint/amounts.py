"""Exact integer money arithmetic (spec §1.1).

ceil_bps(x,b) = (x*b + 9999) div 10000
floor_bps(x,b) = (x*b) div 10000
Python ints are arbitrary precision, satisfying the >=128-bit checked
arithmetic requirement; every public amount is a decimal string.
"""

from __future__ import annotations


def ceil_bps(x: int, b: int) -> int:
    return (x * b + 9999) // 10000


def floor_bps(x: int, b: int) -> int:
    return (x * b) // 10000


def lower_median(values: list[int]) -> int:
    """Sorted index (n-1) div 2; requires n >= 1."""
    if not values:
        raise ValueError("lower median of empty set")
    s = sorted(values)
    return s[(len(s) - 1) // 2]


def largest_remainder_shares(pool: int, weights: list[int]) -> list[int]:
    """Distribute `pool` proportional to weights: floor, then largest
    remainders; ties broken by lower index (caller orders indexes by
    principal-ID byte order for the tie rule)."""
    total = sum(weights)
    if total <= 0 or pool <= 0:
        return [0] * len(weights)
    shares = [pool * w // total for w in weights]
    remainder = pool - sum(shares)
    # largest fractional remainders first; ties -> lower index
    order = sorted(
        range(len(weights)),
        key=lambda i: (-(pool * weights[i] - shares[i] * total), i),
    )
    for i in range(remainder):
        shares[order[i % len(order)]] += 1
    return shares
