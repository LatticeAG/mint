"""Open allocation and clearing (spec §5).

Deterministic multi-attribute first-price procurement:
  P  = floor(3000*(V-p)/V)
  L  = floor(2000*(Dmax-l)/Dmax)
  Qp = floor(5000*q/10000)
  S  = Qp + P + L
Fairness band: bids with S >= best_S - 200; within band the winner is the
principal with fewest witnessed claims in the market's preceding 24h;
remaining ties break on the seed-derived hash.
"""

from __future__ import annotations

from .jsonutil import domain_hash
from .policy import POLICY

P = POLICY


def price_floor(V: int) -> int:
    return max(P["bid_floor_min"], (V * P["price_floor_bps"] + 9999) // 10000)


def score_bid(V: int, dmax: int, p: int, q: int, l: int) -> dict:
    Pterm = P["price_weight_bps"] * (V - p) // V
    Lterm = P["latency_weight_bps"] * (dmax - l) // dmax
    Qp = P["quality_weight_bps"] * q // 10000
    return {"P": Pterm, "L": Lterm, "Qp": Qp, "S": Qp + Pterm + Lterm}


def quality_forecast(observations: list[int]) -> int:
    """q = floor((15000 + sum(last<=50 observations)) / (2+n))."""
    obs = observations[-P["quality_history_max"]:]
    n = len(obs)
    return (P["quality_prior"] + sum(obs)) // (P["quality_prior_weight"] + n)


def lateness_observation(q: int, l: int, elapsed: int, dmax: int) -> dict:
    """§7.2: lateness_bps = min(2000, floor(2000*max(0,elapsed-l)/Dmax));
    observation = max(0, Q - 3*lateness_bps)."""
    lateness = min(P["lateness_cap_bps"],
                   P["lateness_cap_bps"] * max(0, elapsed - l) // dmax)
    return {"lateness_bps": lateness,
            "observation": max(0, q - P["lateness_penalty_factor"] * lateness)}


def bid_commitment(network: str, market_id: str, epoch: int, task_id: str,
                   principal_group: str, key_epoch: int, p: int, l: int,
                   slot: str, salt: str) -> str:
    return domain_hash("mint.bid.commit.v1", {
        "network": network, "market_id": market_id, "epoch": epoch,
        "task_id": task_id, "principal_group": principal_group,
        "key_epoch": key_epoch, "p": p, "l": l, "slot": slot, "salt": salt,
    })


def tie_hash(seed: str, task_id: str, principal_group: str) -> str:
    return domain_hash("mint.alloc.tie.v1", {
        "seed": seed, "task_id": task_id,
        "principal_group": principal_group,
    })


def clear_task(task_id: str, V: int, dmax: int, floor_q: int,
               bids: list[dict], claims_24h: dict[str, int],
               capacity_ok, seed: str) -> dict:
    """Rank one task's revealed bids.

    bids: [{principal_group, p, l, q, slot, ...}]
    claims_24h: {principal_group: witnessed claim count in window}
    capacity_ok: callable(group, slot) -> None or exclusion reason
    Returns {ladder: [groups ordered], winner, excluded: {group: reason},
             scores: {group: S}, reason}
    """
    excluded: dict[str, str] = {}
    eligible: list[dict] = []
    pf = price_floor(V)
    for b in bids:
        g = b["principal_group"]
        if not (pf <= b["p"] <= V):
            excluded[g] = "PRICE_BOUNDS"
            continue
        if not (1 <= b["l"] <= dmax):
            excluded[g] = "LATENCY_BOUNDS"
            continue
        if b["q"] < floor_q:
            excluded[g] = "FORECAST_FLOOR"
            continue
        cap_reason = capacity_ok(g, b["slot"])
        if cap_reason:
            excluded[g] = cap_reason
            continue
        comp = score_bid(V, dmax, b["p"], b["q"], b["l"])
        eligible.append({**b, **comp})
    scores = {b["principal_group"]: b["S"] for b in eligible}
    ladder: list[str] = []
    reasons: dict[str, str] = {}
    remaining = list(eligible)
    while remaining and len(ladder) < P["maximum_offers"]:
        best = max(b["S"] for b in remaining)
        band = [b for b in remaining if b["S"] >= best - P["fairness_band_points"]]
        fewest = min(claims_24h.get(b["principal_group"], 0) for b in band)
        tied = [b for b in band
                if claims_24h.get(b["principal_group"], 0) == fewest]
        if len(tied) > 1:
            tied.sort(key=lambda b: tie_hash(seed, task_id,
                                             b["principal_group"]))
        chosen = tied[0]
        reasons[chosen["principal_group"]] = (
            "TOP_SCORE" if chosen["S"] == best and fewest == max(
                claims_24h.get(b["principal_group"], 0) for b in band)
            else ("FAIRNESS_BAND" if chosen["S"] < best else "TOP_SCORE"))
        ladder.append(chosen["principal_group"])
        remaining.remove(chosen)
    return {
        "ladder": ladder, "winner": ladder[0] if ladder else None,
        "excluded": excluded, "scores": scores, "reasons": reasons,
    }


def order_tasks(tasks: list[dict]) -> list[dict]:
    """§5.4 batch order: funded eligible epoch, witnessed funding sequence,
    then task ID bytes."""
    return sorted(tasks, key=lambda t: (t["eligible_epoch"],
                                        t["funded_seq"], t["task_id"]))
