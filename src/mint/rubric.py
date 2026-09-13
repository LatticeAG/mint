"""Reference rubric R1 arithmetic, quorum, and review triggers (§3.3-3.5).

Every component uses the determinate-denominator rule: units that cannot be
evaluated for evidenced environmental/access reasons are excluded from both
numerator and denominator. Coverage floors produce INCONCLUSIVE, never a
forced REJECT.
"""

from __future__ import annotations

from .amounts import lower_median
from .policy import POLICY

P = POLICY


def component(passed: int, determinate: int) -> int | None:
    """floor(10000 * passed / determinate); None if wholly indeterminate."""
    if determinate <= 0:
        return None
    return 10000 * passed // determinate


def compute_q(c: int, k: int, r: int, s: int) -> int:
    return (4000 * c + 3000 * k + 2000 * r + 1000 * s) // 10000


def coverage_inconclusive(obs: dict) -> bool:
    """Per-component determinate floors (of rubric-declared unit counts)."""
    return (
        obs["tests_determinate"] < P["r1_test_floor"]
        or obs["clauses_determinate"] < P["r1_clause_floor"]
        or obs["reruns_determinate"] < P["r1_rerun_floor"]
        or obs["controls_determinate"] < P["r1_control_floor"]
    )


def derive_components(obs: dict) -> dict | None:
    """Components from observations; None if any component indeterminate."""
    c = component(obs["tests_passed"], obs["tests_determinate"])
    k = component(obs["clauses_satisfied"], obs["clauses_determinate"])
    r = component(obs["reruns_matched"], obs["reruns_determinate"])
    s = component(obs["controls_passed"], obs["controls_determinate"])
    if None in (c, k, r, s):
        return None
    return {"correctness": c, "completeness": k, "reproducibility": r,
            "safety": s}


def derive_disposition(components: dict | None, q: int | None,
                       gates: dict, coverage_bad: bool,
                       acceptance_score: int) -> str:
    """Derived disposition from derived score, gates, and coverage."""
    if not all(gates.get(g) is True for g in ("content", "license", "integrity")):
        return "REJECT"
    if coverage_bad or components is None or q is None:
        return "INCONCLUSIVE"
    return "ACCEPT" if q >= acceptance_score else "REJECT"


def evaluate_judgment(judgment: dict, acceptance_score: int) -> dict:
    """Recompute Q and disposition for a revealed judgment.

    Returns {components, q, disposition, coverage_bad}. When `observations`
    are present they are authoritative for component derivation; otherwise
    the stated component fields are used.
    """
    obs = judgment.get("observations")
    if obs is not None:
        components = derive_components(obs)
        coverage_bad = coverage_inconclusive(obs)
    else:
        try:
            components = {
                "correctness": int(judgment["correctness"]),
                "completeness": int(judgment["completeness"]),
                "reproducibility": int(judgment["reproducibility"]),
                "safety": int(judgment["safety"]),
            }
        except (KeyError, TypeError, ValueError):
            components = None
        coverage_bad = bool(judgment.get("coverage_inconclusive", False))
    if components is None:
        q = None
    else:
        q = compute_q(components["correctness"], components["completeness"],
                      components["reproducibility"], components["safety"])
    gates = judgment.get("mandatory_gates") or {}
    disposition = derive_disposition(components, q, gates, coverage_bad,
                                   acceptance_score)
    return {"components": components, "q": q, "disposition": disposition,
            "coverage_bad": coverage_bad}


def objective_counts(obs: dict) -> dict:
    """Objective, rerun-checkable observations (§3.5): passing test count,
    seeded-rerun match count, control result."""
    return {
        "tests_passed": obs["tests_passed"],
        "tests_determinate": obs["tests_determinate"],
        "reruns_matched": obs["reruns_matched"],
        "reruns_determinate": obs["reruns_determinate"],
        "controls_passed": obs["controls_passed"],
        "controls_determinate": obs["controls_determinate"],
    }


def quorum_evaluate(judgments: list[dict], acceptance_score: int) -> dict:
    """Apply §3.5 quorum/spread/proximity/disagreement rules.

    Input: list of evaluated judgments (evaluate_judgment output plus
    the original judgment object under key "raw").
    Returns a dict with:
      outcome: ACCEPT | REJECT | INCONCLUSIVE | REVIEW | NON_QUORATE_REVIEW
      aggregate_q: lower median of scored judgments (or None)
      spread, scored, dispositions, review_reasons,
      rerun_required: objective-component disagreement exists
    """
    valid = judgments
    scored = [j for j in valid if j["disposition"] != "INCONCLUSIVE"
              and j["q"] is not None]
    dispositions = [j["disposition"] for j in valid]
    counts = {d: dispositions.count(d) for d in ("ACCEPT", "REJECT",
                                               "INCONCLUSIVE")}
    result = {
        "outcome": None, "aggregate_q": None, "spread": 0,
        "scored": len(scored), "dispositions": counts,
        "review_reasons": [], "rerun_required": False,
    }
    # objective-component disagreement -> mandatory rerun before ACCEPT
    obs_list = [j["raw"].get("observations") for j in valid
                if j["raw"].get("observations")]
    if obs_list:
        base = objective_counts(obs_list[0])
        if any(objective_counts(o) != base for o in obs_list[1:]):
            result["rerun_required"] = True
    if len(scored) < P["min_scored_judgments"]:
        if counts["INCONCLUSIVE"] >= P["primary_quorum"]:
            result["outcome"] = "INCONCLUSIVE"
            result["review_reasons"].append("coverage_quorum")
            return result
        result["outcome"] = "NON_QUORATE_REVIEW"
        result["review_reasons"].append("non_quorate")
        return result
    qs = [j["q"] for j in scored]
    med = lower_median(qs)
    result["aggregate_q"] = med
    result["spread"] = max(qs) - min(qs)
    if counts["INCONCLUSIVE"] >= P["primary_quorum"]:
        result["outcome"] = "INCONCLUSIVE"
        result["review_reasons"].append("inconclusive_quorum")
        return result
    # disposition quorum: >=4 matching ACCEPT or >=4 matching REJECT
    if counts["ACCEPT"] >= P["primary_quorum"]:
        provisional = "ACCEPT"
    elif counts["REJECT"] >= P["primary_quorum"]:
        provisional = "REJECT"
    else:
        result["outcome"] = "NON_QUORATE_REVIEW"
        result["review_reasons"].append("no_disposition_quorum")
        return result
    review = []
    if result["spread"] > P["spread_review_points"]:
        review.append("spread")
    if (abs(med - acceptance_score) <= P["proximity_band_points"]
            and any(d != provisional for d in dispositions)):
        review.append("proximity_dissent")
    if provisional == "ACCEPT" and med < acceptance_score:
        review.append("below_threshold")
    if review:
        result["outcome"] = "REVIEW"
        result["provisional"] = provisional
        result["review_reasons"] = review
        return result
    if provisional == "ACCEPT" and result["rerun_required"]:
        # rerun mandatory before ACCEPT executes; verdict stays pending
        result["outcome"] = "RERUN_PENDING"
        result["provisional"] = "ACCEPT"
        return result
    result["outcome"] = provisional
    return result
