"""Penalty selection, ceiling, and distribution vectors
(TV-M-29, 30, 31, 32, 62, 63, 72)."""

from __future__ import annotations

from mint.penalty import (
    authorized_total, compute_penalty, distribute, select_fraction)


# TV-M-29: non-flipping E2, Be=5000, victim loss 750, one reporter
def test_tvm29_e2_distribution():
    # selected 2500 bps of Be=5000 -> S=1250
    res = compute_penalty("E2", V=10000, stipulated_loss=750,
                          reporters=["reporter-1"])
    assert res["total"] == 1250
    d = res["distribution"]
    assert d["victims"] == {"claimant": 750}
    assert d["bounty"] == 12 or d["bounty"] == 100
    # bounty = min(100, floor_bps(1250,1000)=125) -> 100? floor_bps(1250,1000)=125 -> min(100,125)=100
    assert d["reporters"] == {"reporter-1": 100}
    assert d["reserve"] == 1250 - 750 - 100


# TV-M-30: E2+E4 same incident -> select max (10000) not sum
def test_tvm30_same_incident_max_fraction():
    bps = select_fraction([("E2", False), ("E4", False)])
    assert bps == 10000


# TV-M-31: independent E1+E2 incidents -> combined 3500 bps
def test_tvm31_independent_incidents_combine():
    s = authorized_total(5000, [1000, 2500])
    assert s["combined_bps"] == 3500
    assert s["authorized_total"] == 1750
    assert s["new_slash"] == 1750


# TV-M-32: ceiling applied once on combined total
def test_tvm32_single_ceiling():
    s = authorized_total(1001, [1000, 2500])
    # ceil_bps(1001,3500) = ceil(1001*0.35) = 351
    assert s["authorized_total"] == 351


# TV-M-62: three victims, demands exceed the 60% pool
def test_tvm62_victim_pool_proportional():
    d = distribute(1167,
                   [{"principal": f"v-{c}", "loss": 300}
                    for c in "abc"],
                   [])
    assert d["victim_pool"] == 700
    # 900 > 700 -> floor 233 each, remainder 1 to lowest principal id
    assert sum(d["victims"].values()) == 700
    assert d["victims"]["v-a"] == 234
    assert d["victims"]["v-b"] == 233
    assert d["victims"]["v-c"] == 233
    assert d["reserve"] == 1167 - 700


# TV-M-63: two reporters split the single bounty
def test_tvm63_reporter_bounty_split():
    d = distribute(1250, [], ["r1", "r2"])
    assert d["bounty"] == 100
    assert d["reporters"] == {"r1": 50, "r2": 50}
    assert d["reserve"] == 1150


# TV-M-72: flipping E2 picks 5000 bps
def test_tvm72_flipping_e2():
    bps = select_fraction([("E2", True)])
    assert bps == 5000
    res = compute_penalty("E2", V=10000, disposition_flipped=True)
    assert res["total"] == 2500  # 5000bps of Be=5000


def test_e1_proposed_penalty():
    # TV-M-19/28 scale: E1 at 1000bps of Be=5000 -> 500
    res = compute_penalty("E1", V=10000)
    assert res["total"] == 500
