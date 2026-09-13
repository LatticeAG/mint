"""mint-policy-1 protocol constants (spec §1.2, §1.4, §3, §5, §8.7).

All omitted protocol constants are fixed by the policy profile; this module
is that profile. Values are integer cents (SIMUSD) or integer seconds/bps.
"""

from __future__ import annotations

from .amounts import ceil_bps
from .jsonutil import domain_hash

POLICY_ID = "mint-policy-1"

# --- reservation schedule (spec §1.2) --------------------------------------
def schedule(V: int) -> dict:
    Bp = max(1000, ceil_bps(V, 2000))
    Bw = max(1000, ceil_bps(V, 2000))
    C = max(100, ceil_bps(V, 100))
    Be = max(1000, ceil_bps(V, 5000))
    f = max(100, ceil_bps(V, 100))
    E = 5 * f
    F = max(100, ceil_bps(V, 200))
    D = max(200, ceil_bps(V, 200))
    A = max(500, ceil_bps(V, 500))
    Bj = max(1000, V)
    Rt = V + 2500
    return {
        "V": V, "Bp": Bp, "Bw": Bw, "C": C, "Be": Be, "f": f, "E": E,
        "F": F, "D": D, "A": A, "Bj": Bj, "Rt": Rt,
        "poster_reserve": V + Bp + E + F,
        "bidder_reserve": Bw + C,
    }


# --- protocol constants -----------------------------------------------------
POLICY = {
    "policy_id": POLICY_ID,
    "min_value": 1000,
    "max_value": 100000,
    "max_active_claims_per_principal": 3,
    "max_commits_per_epoch": 20,
    "max_artifact_chunk_bytes": 1_048_576,   # 1 MiB
    "max_artifact_chunks": 256,
    "max_artifact_bytes": 268_435_456,       # 256 MiB
    "max_evidence_per_filing": 32,
    "absolute_task_days": 45,
    "max_acceptance_score": 9500,
    "default_acceptance_score": 8500,
    "default_forecast_floor": 7000,
    "dmax_min_seconds": 3600,
    "dmax_max_seconds": 259200,
    # time model
    "posting_funding_seconds": 600,
    "epoch_seconds": 1200,
    "commit_seconds": 900,
    "reveal_seconds": 300,
    "claim_offer_seconds": 300,
    "maximum_offers": 3,
    "beacon_wait_seconds": 900,
    "beacon_round_seconds": 60,
    "evaluator_commit_seconds": 7200,
    "evaluator_reveal_seconds": 3600,
    "seat_acceptance_seconds": 300,
    "evidence_access_seconds": 300,
    "review_hours": 24,
    "challenge_seconds": 172800,
    "appeal_filing_seconds": 172800,
    "trial_decision_seconds": 259200,   # 72h
    "appeal_decision_seconds": 259200,
    "supervisory_decision_seconds": 259200,
    "recovery_challenge_seconds": 172800,
    "answer_min_seconds": 86400,        # >= 24h to answer inside trial window
    "p2_cure_seconds": 7200,
    "withdrawal_cooldown_seconds": 86400,
    "key_rotation_cooldown_seconds": 86400,
    "registry_freeze_seconds": 86400,   # snapshot frozen 24h before epoch
    "witness_freshness_seconds": 30,
    "signed_window_seconds": 300,
    "issued_clock_skew_seconds": 30,
    # judgment
    "primary_seats": 5,
    "primary_replacements": 5,
    "primary_quorum": 4,
    "min_scored_judgments": 3,
    "trial_seats": 7,
    "trial_quorum": 5,
    "appeal_seats": 9,
    "appeal_quorum": 7,
    "supervisory_seats": 9,
    "supervisory_quorum": 7,
    "recovery_seats": 7,
    "recovery_quorum": 4,
    "policy_activation_min_epochs": 504,   # 7 days at 1200s epochs
    "key_rotation_delay_seconds": 604800,  # 7-day scheduled rotation
    "answer_seconds": 86400,
    "court_acceptance_seconds": 300,
    "spread_review_points": 1500,
    "proximity_band_points": 500,
    "court_stipend": 100,
    "min_judging_groups": 35,
    "max_same_family_seats": 2,
    # clearing weights
    "quality_weight_bps": 5000,
    "price_weight_bps": 3000,
    "latency_weight_bps": 2000,
    "fairness_band_points": 200,
    "price_floor_bps": 2000,
    "bid_floor_min": 1000,
    "quality_prior": 15000,
    "quality_prior_weight": 2,
    "quality_history_max": 50,
    "new_entrant_q": 7500,
    "lateness_cap_bps": 2000,
    "lateness_penalty_factor": 3,
    "witnessed_claims_window_seconds": 86400,
    # witness / ledger
    "witness_seats": 5,
    "witness_quorum": 4,
    "checkpoint_seconds": 1,
    "max_checkpoint_age_seconds": 30,
    # settlement / recovery
    "settlement_signer_seats": 5,
    "settlement_quorum": 3,
    "recovery_authority_seats": 7,
    "recovery_authority_quorum": 4,
    # reserves
    "reserve_initial": 10_000_000,
    "court_stipend_capacity": 25,      # 7 trial + 9 appeal + 9 supervisory
    "rt_stipend_component": 2500,
    "min_evaluator_pool": 35,
    # distribution
    "victim_pool_bps": 6000,
    "reporter_bounty_bps": 1000,
    "reporter_bounty_cap": 100,
    # rubric R1 declared unit counts
    "r1_tests": 20,
    "r1_clauses": 4,
    "r1_reruns": 5,
    "r1_controls": 2,
    "r1_test_floor": 15,
    "r1_clause_floor": 3,
    "r1_rerun_floor": 3,
    "r1_control_floor": 2,
    "r1_weights": {"c": 4000, "k": 3000, "r": 2000, "s": 1000},
}

POLICY_HASH = domain_hash("mint.policy.v1", POLICY)

# --- offense schedule (spec §4.1) ------------------------------------------
# code -> (liable bond kind, fraction bps, evidence class)
# evidence class: OBJECTIVE (verifiable bytes/receipts) or CONTEXTUAL.
OFFENSES = {
    "P1": {"bond": "Bp", "bps": 2500, "class": "OBJECTIVE",
           "name": "materially impossible or misrepresented posted requirements"},
    "P2": {"bond": "Bp", "bps": 5000, "class": "OBJECTIVE",
           "name": "post-claim withholding of promised data/access"},
    "P3": {"bond": "Bp", "bps": 10000, "class": "CONTEXTUAL",
           "name": "forged task evidence, offered bribe, or self-dealing"},
    "W1": {"bond": "Bw", "bps": 2000, "class": "OBJECTIVE",
           "name": "abandonment/no submission by execution cap"},
    "W2": {"bond": "Bw", "bps": 2500, "class": "OBJECTIVE",
           "name": "fraudulent provenance or falsified execution receipt"},
    "W3": {"bond": "Bw", "bps": 10000, "class": "CONTEXTUAL",
           "name": "artifact substitution after commitment or evaluator bribery"},
    "E1": {"bond": "Be", "bps": 1000, "class": "OBJECTIVE",
           "name": "accepted assignment but missed commit/reveal"},
    "E2": {"bond": "Be", "bps": 2500, "class": "OBJECTIVE",
           "name": "material false factual judgment", "flip_bps": 5000},
    "E3": {"bond": "Be", "bps": 5000, "class": "CONTEXTUAL",
           "name": "concealed disqualifying affiliation"},
    "E4": {"bond": "Be", "bps": 10000, "class": "CONTEXTUAL",
           "name": "equivocation, fabricated evidence, or bribery"},
    "B1": {"bond": "C", "bps": 10000, "class": "OBJECTIVE",
           "name": "committed bid not revealed, or offered winner refusing claim"},
    "J1": {"bond": "Bj", "bps": 1000, "class": "OBJECTIVE",
           "name": "accepted court seat but withheld required decision"},
    "J2": {"bond": "Bj", "bps": 2500, "class": "OBJECTIVE",
           "name": "material evidence-backed false factual court finding"},
    "J3": {"bond": "Bj", "bps": 10000, "class": "CONTEXTUAL",
           "name": "judicial equivocation, fabrication, or bribery"},
    "X1": {"bond": "D|A", "bps": 10000, "class": "CONTEXTUAL",
           "name": "forged challenge/appeal evidence or coordinated harassment"},
    "NONE": {"bond": None, "bps": 0, "class": "OBJECTIVE",
             "name": "payment challenge / automatic review docket"},
}

OFFENSE_SCHEDULE_HASH = domain_hash("mint.offenses.v1", OFFENSES)

# Auto-evidenced offenses: complete objective evidence is attached at
# allegation time, so an unanswered challenge window authorizes them.
AUTO_EVIDENCED = {"B1", "W1", "E1"}

# Offenses whose proof additionally forfeits a task-level claim.
WORKER_CLAIM_FORFEIT = {"W2", "W3"}
POSTER_V_FORFEIT = {"P3"}
EVALUATOR_FEE_FORFEIT = {"E2", "E3", "E4"}

# Rubric component -> observation fields (spec §3.3 R1)
R1_COMPONENTS = ("correctness", "completeness", "reproducibility", "safety")
R1_GATES = ("content", "license", "integrity")
