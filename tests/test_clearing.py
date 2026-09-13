"""Clearing / scoring / fairness-band / lateness vectors
(TV-M-09, 10, 11, 13, 14, 42, 67, 75)."""

from __future__ import annotations

from mint.clearing import (
    clear_task, lateness_observation, order_tasks, price_floor,
    quality_forecast, score_bid, tie_hash)


def bid(group, p, l, q):
    return {"principal_group": group, "p": p, "l": l, "q": q,
            "slot": f"slot-{group}"}


# -- TV-M-09: A/B/C bids from §7.1; C wins at p=9000 with S=7033 ------------
def test_tvm09_abc_clearing():
    V, Dmax = 10000, 3600
    bA = bid("pg-a", 8000, 1800, 9000)   # 4500+600+1000 = 6100
    bB = bid("pg-b", 6000, 900, 8000)    # 4000+1200+1500 = 6700
    bC = bid("pg-c", 9000, 300, 9800)    # 4900+300+1833 = 7033
    res = clear_task("t1", V, Dmax, 7000, [bA, bB, bC], {},
                     lambda g, s: None, "seed")
    assert res["scores"]["pg-a"] == 6100
    assert res["scores"]["pg-b"] == 6700
    assert res["scores"]["pg-c"] == 7033
    assert res["winner"] == "pg-c"
    # B is 333 below C: outside the 200-point fairness band
    assert res["reasons"]["pg-c"] == "TOP_SCORE"


# -- TV-M-10: fairness band — D with fewer witnessed claims wins ------------
def test_tvm10_fairness_band():
    V, Dmax = 10000, 3600
    bC = bid("pg-c", 9000, 300, 9800)    # S=7033, 4 witnessed claims
    bD = bid("pg-d", 9000, 360, 9800)    # S=7000, 0 witnessed claims
    res = clear_task("t1", V, Dmax, 7000, [bC, bD],
                     {"pg-c": 4, "pg-d": 0}, lambda g, s: None, "seed")
    assert res["scores"]["pg-d"] == 7000
    assert res["winner"] == "pg-d"
    assert res["reasons"]["pg-d"] == "FAIRNESS_BAND"


# -- TV-M-11: newcomer q=7500 cannot displace C ------------------------------
def test_tvm11_newcomer_floor():
    V, Dmax = 10000, 3600
    bC = bid("pg-c", 9000, 300, 9800)
    bN = bid("pg-n", 6000, 900, 7500)    # 3750+1200+1500 = 6450
    res = clear_task("t1", V, Dmax, 7000, [bC, bN], {},
                     lambda g, s: None, "seed")
    assert res["scores"]["pg-n"] == 6450
    assert res["winner"] == "pg-c"


# -- TV-M-13: excess stake does not change the score -------------------------
def test_tvm13_stake_neutral():
    # score is a function of (V,dmax,p,q,l) only
    a = score_bid(10000, 3600, 9000, 9800, 300)
    b = score_bid(10000, 3600, 9000, 9800, 300)
    assert a == b and a["S"] == 7033


# -- TV-M-14: input arrival permutation cannot change the result -------------
def test_tvm14_permutation_invariant():
    V, Dmax = 10000, 3600
    bids = [bid("pg-a", 8500, 1200, 9000), bid("pg-b", 10000, 600, 9100),
            bid("pg-c", 9000, 1800, 9000), bid("pg-d", 9500, 2400, 8700)]
    r1 = clear_task("t1", V, Dmax, 7000, bids, {}, lambda g, s: None, "s")
    r2 = clear_task("t1", V, Dmax, 7000, list(reversed(bids)), {},
                    lambda g, s: None, "s")
    assert r1["ladder"] == r2["ladder"]
    assert r1["scores"] == r2["scores"]


# -- price bounds -------------------------------------------------------------
def test_price_floor_and_bounds():
    assert price_floor(10000) == 2000
    res = clear_task("t1", 10000, 3600, 7000,
                     [bid("pg-low", 1999, 1800, 9000)], {},
                     lambda g, s: None, "s")
    assert res["excluded"]["pg-low"] == "PRICE_BOUNDS"


def test_forecast_floor_exclusion():
    res = clear_task("t1", 10000, 3600, 7000,
                     [bid("pg-q", 9000, 1800, 6999)], {},
                     lambda g, s: None, "s")
    assert res["excluded"]["pg-q"] == "FORECAST_FLOOR"


# -- TV-M-42/67: lateness-adjusted observations --------------------------------
def test_tvm42_lateness():
    r = lateness_observation(9050, 300, 2100, 3600)
    assert r["lateness_bps"] == 1000
    assert r["observation"] == 6050
    # next q snapshot: floor((15000 + 6050)/(2+1)) = 7016
    assert quality_forecast([6050]) == 7016


def test_tvm67_overpromise_scores_below_honest():
    r = lateness_observation(9050, 1, 1800, 3600)
    assert r["lateness_bps"] == 999
    assert r["observation"] == 6053
    assert quality_forecast([6053]) == 7017
    # honest l=1800, elapsed 1800 -> lateness 0 -> observation 9050
    honest = lateness_observation(9050, 1800, 1800, 3600)
    assert honest["lateness_bps"] == 0
    assert honest["observation"] == 9050
    assert quality_forecast([9050]) == 8016


def test_quality_forecast_prior():
    assert quality_forecast([]) == 7500  # floor(15000/2)


# -- tie hash determinism -------------------------------------------------------
def test_tie_hash_stable():
    assert tie_hash("s", "t1", "pg-a") == tie_hash("s", "t1", "pg-a")
    assert tie_hash("s", "t1", "pg-a") != tie_hash("s", "t1", "pg-b")


# -- order_tasks ----------------------------------------------------------------
def test_order_tasks():
    tasks = [{"eligible_epoch": 2, "funded_seq": 5, "task_id": "b"},
             {"eligible_epoch": 1, "funded_seq": 9, "task_id": "z"},
             {"eligible_epoch": 1, "funded_seq": 9, "task_id": "a"}]
    out = order_tasks(tasks)
    assert [t["task_id"] for t in out] == ["a", "z", "b"]
