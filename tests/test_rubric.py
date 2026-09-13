"""Rubric R1 + quorum conformance vectors
(TV-M-21..27, 61, 64, 65, 66, 73, 78, 79)."""

from __future__ import annotations

from mint.rubric import (
    component, compute_q, coverage_inconclusive, derive_components,
    derive_disposition, evaluate_judgment, quorum_evaluate)


def obs(tests_p, tests_d, cl_s, cl_d, rr_m, rr_d, ct_p, ct_d):
    return {"tests_passed": tests_p, "tests_determinate": tests_d,
            "clauses_satisfied": cl_s, "clauses_determinate": cl_d,
            "reruns_matched": rr_m, "reruns_determinate": rr_d,
            "controls_passed": ct_p, "controls_determinate": ct_d}


GATES_OK = {"content": True, "license": True, "integrity": True}


def j(obs_, gates=GATES_OK):
    return {"observations": obs_, "mandatory_gates": gates}


def scored(q, disposition=None, threshold=8500):
    """A scored judgment whose derived disposition follows the rubric
    unless overridden (e.g. an honest dissenting REJECT)."""
    if disposition is None:
        disposition = "ACCEPT" if q >= threshold else "REJECT"
    return {"q": q, "disposition": disposition, "coverage_bad": False,
            "raw": {}}


# -- TV-M-21: 19/20 tests, 3/4 clauses, 5/5 reruns, 2/2 controls -----------
def test_tvm21_components_and_q():
    o = obs(19, 20, 3, 4, 5, 5, 2, 2)
    c = derive_components(o)
    assert c == {"correctness": 9500, "completeness": 7500,
                 "reproducibility": 10000, "safety": 10000}
    assert compute_q(c["correctness"], c["completeness"],
                     c["reproducibility"], c["safety"]) == 9050
    r = evaluate_judgment(j(o), 8500)
    assert r["q"] == 9050 and r["disposition"] == "ACCEPT"


# -- TV-M-22: Q=8400 below the 8500 acceptance score -> REJECT --------------
def test_tvm22_reject_below_threshold():
    o = obs(16, 20, 4, 4, 3, 5, 2, 2)
    c = derive_components(o)
    q = compute_q(c["correctness"], c["completeness"],
                  c["reproducibility"], c["safety"])
    assert q == 8400
    r = evaluate_judgment(j(o), 8500)
    assert r["disposition"] == "REJECT"


# -- TV-M-23: mandatory gate failure forces REJECT regardless of score -----
def test_tvm23_gate_overrides_score():
    o = obs(20, 20, 4, 4, 5, 5, 1, 2)  # one control fails
    gates = {"content": True, "license": True, "integrity": False}
    r = evaluate_judgment(j(o, gates), 8500)
    assert r["disposition"] == "REJECT"
    assert r["q"] is not None and r["q"] >= 8500  # score alone insufficient


# -- TV-M-24: median + spread on five valid accepts -------------------------
def test_tvm24_five_valid_accepts():
    res = quorum_evaluate(
        [scored(q) for q in (8800, 9000, 9050, 9200, 9800)], 8500)
    assert res["aggregate_q"] == 9050
    assert res["spread"] == 1000
    assert res["outcome"] == "ACCEPT"


# -- TV-M-25: wide spread + no disposition quorum -> review -----------------
def test_tvm25_spread_review():
    # 7000/7100 derive REJECT below the 8500 threshold; force the vector's
    # all-ACCEPT dispositions to isolate the spread trigger.
    js = [scored(q, "ACCEPT") for q in (7000, 7100, 9050, 9200, 9400)]
    res = quorum_evaluate(js, 8500)
    assert res["spread"] == 2400
    assert res["outcome"] == "REVIEW"
    assert "spread" in res["review_reasons"]


# -- TV-M-26: four valid scores, only three ACCEPTs -> no unreviewed accept
def test_tvm26_no_unreviewed_accept():
    # 8400 < 8500 derives REJECT; only three ACCEPTs remain -> no quorum
    res = quorum_evaluate(
        [scored(q) for q in (8400, 8600, 8650, 8800)], 8500)
    assert res["aggregate_q"] == 8600
    assert res["outcome"] == "NON_QUORATE_REVIEW"


# -- TV-M-61: spread 1600 > 1500 with 4 ACCEPT + 1 REJECT -> review ---------
def test_tvm61_material_disagreement_review():
    # 8300 derives REJECT; force it ACCEPT for the 4xACCEPT + 1xREJECT mix
    js = [scored(8300, "ACCEPT"), scored(9000), scored(9100),
          scored(9200), scored(9900, "REJECT")]
    res = quorum_evaluate(js, 8500)
    assert res["spread"] == 1600
    assert res["outcome"] == "REVIEW"
    assert "spread" in res["review_reasons"]


# -- TV-M-64/65/66: unmatched hidden-test commitment handling ---------------
def test_tvm64_partial_test_coverage():
    # 1 commitment unmatched: 16/19 valid tests -> c = floor(160000/19)
    o = obs(16, 19, 4, 4, 3, 5, 2, 2)
    c = derive_components(o)
    assert c["correctness"] == 8421
    q = compute_q(c["correctness"], c["completeness"],
                  c["reproducibility"], c["safety"])
    assert q == 8568


def test_tvm65_coverage_five_unmatched():
    o = obs(13, 15, 4, 4, 3, 5, 2, 2)
    c = derive_components(o)
    assert c["correctness"] == 8666
    q = compute_q(*[c[k] for k in
                    ("correctness", "completeness", "reproducibility",
                     "safety")])
    assert q == 8666


def test_tvm66_eight_unmatched_is_inconclusive():
    # only 12 valid determinate tests < floor 15 -> INCONCLUSIVE
    o = obs(12, 12, 4, 4, 3, 3, 2, 2)
    assert coverage_inconclusive(o)
    r = evaluate_judgment(j(o), 8500)
    assert r["disposition"] == "INCONCLUSIVE"


# -- TV-M-78: determinate-denominator on environment-blocked reruns ---------
def test_tvm78_rerun_determinate_denominator():
    o = obs(19, 20, 4, 4, 3, 3, 2, 2)  # 2 blocked excluded entirely
    c = derive_components(o)
    assert c["reproducibility"] == 10000
    q = compute_q(*[c[k] for k in
                    ("correctness", "completeness", "reproducibility",
                     "safety")])
    assert q == 9800
    assert evaluate_judgment(j(o), 8500)["disposition"] == "ACCEPT"


# -- TV-M-79: inexecutable mandatory control -> INCONCLUSIVE not REJECT -----
def test_tvm79_indeterminate_control_inconclusive():
    o = obs(19, 20, 4, 4, 5, 5, 0, 0)  # control tool cannot execute
    r = evaluate_judgment(j(o), 8500)
    assert r["disposition"] == "INCONCLUSIVE"
    assert r["coverage_bad"]


def test_component_zero_determinate_is_none():
    assert component(0, 0) is None
    assert component(3, 4) == 7500


# -- TV-M-73: dissent on objective counts is rerun-checkable -----------------
def test_objective_counts_extract():
    from mint.rubric import objective_counts
    o = obs(19, 20, 4, 4, 5, 5, 2, 2)
    oc = objective_counts(o)
    assert oc == {"tests_passed": 19, "tests_determinate": 20,
                  "reruns_matched": 5, "reruns_determinate": 5,
                  "controls_passed": 2, "controls_determinate": 2}
    # clauses deliberately absent — subjective, not rerun-checkable
