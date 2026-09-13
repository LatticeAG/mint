"""Deterministic penalty calculation and slash distribution (§4.2-4.3)."""

from __future__ import annotations

from .amounts import ceil_bps, floor_bps, largest_remainder_shares
from .jsonutil import domain_hash
from .policy import OFFENSES, POLICY

P = POLICY


def select_fraction(offenses: list[tuple[str, bool]]) -> int:
    """Per-incident selected fraction = max applicable bps.

    `offenses` is a list of (offense_code, disposition_flipped) tuples; for
    E2 the materiality finding picks 2500 vs 5000 bps before grouping.
    """
    best = 0
    for code, flips in offenses:
        row = OFFENSES[code]
        bps = row["bps"]
        if code == "E2" and flips:
            bps = row["flip_bps"]
        best = max(best, bps)
    return best


def authorized_total(b0: int, incident_bps: list[int],
                     already_applied: int = 0) -> dict:
    """§4.2: one ceiling after combining incident fractions."""
    total_bps = min(10000, sum(incident_bps))
    total = min(b0, ceil_bps(b0, total_bps))
    new_slash = max(0, total - already_applied)
    return {"authorized_total": total, "new_slash": new_slash,
            "combined_bps": total_bps}


def slash_id(network: str, task_id: str, reservation_id: str,
             incident_ids: list[str], order_id: str) -> str:
    return domain_hash("mint.slash.v1", {
        "network": network, "task_id": task_id,
        "reservation_id": reservation_id,
        "incidents": sorted(incident_ids), "order_id": order_id,
    })


def bond_for(code: str) -> str | None:
    """Bond kind liable for an offense code; raises for unknown codes."""
    if code not in OFFENSES:
        raise ValueError(f"unknown offense {code}")
    return OFFENSES[code]["bond"]


def evaluator_fee(V: int) -> int:
    """The reserved per-task evaluator fee pool E = 5*f."""
    from .policy import schedule
    return schedule(V)["E"]


def auditor_share(V: int) -> int:
    """Auditor-seat payment on a completed rerun: one seat fee f."""
    from .policy import schedule
    return schedule(V)["f"]


def compute_penalty(code: str, V: int, stipulated_loss: int = 0,
                    claimant_present: bool = True,
                    disposition_flipped: bool = False,
                    reporters: list[str] | None = None) -> dict:
    """Full §4.2/§4.3 computation for one sustained docket entry.

    total = ceil_bps(B0, selected_bps), then distribute: victims first
    (60% pool, proportional by proved loss, largest-remainder),
    reporter bounty (1% capped at 100), remainder to the reserve.
    """
    bond_kind = bond_for(code)
    from .policy import schedule
    sch = schedule(V)
    b0 = sch.get(bond_kind, 0) if bond_kind else 0
    bps = OFFENSES[code]["bps"]
    if code == "E2" and disposition_flipped:
        bps = OFFENSES["E2"]["flip_bps"]
    total = min(b0, ceil_bps(b0, bps))
    victims = ([{"principal": "claimant", "loss": stipulated_loss}]
               if claimant_present and stipulated_loss > 0 else [])
    dist = distribute(total, victims, sorted(reporters or []))
    parties = {
        "claimant": sum(dist["victims"].values()),
        "reporters": sum(dist["reporters"].values()),
        "fund": dist["reserve"],
        "burned": 0,
    }
    return {"total": total, "parties": parties, "distribution": dist}


def distribute(S: int, victims: list[dict], reporters: list[str]) -> dict:
    """§4.3 distribution: victims first, reporter bounty, remainder reserve.

    victims: [{principal, loss}] — documented uncompensated loss.
    reporters: eligible nonaffiliated external reporter principals.
    Returns {victims: {principal: amt}, reporters: {principal: amt},
             reserve: amt, victim_pool, bounty}.
    """
    victim_pool = floor_bps(S, P["victim_pool_bps"])
    demands = [min(v["loss"], victim_pool) for v in victims]
    total_demand = sum(demands)
    payouts: dict[str, int] = {}
    spent = 0
    if total_demand <= victim_pool:
        for v, d in zip(victims, demands):
            payouts[v["principal"]] = d
            spent += d
    else:
        # proportional by proved loss, floor then largest remainders;
        # ties in principal-ID byte order -> sort indexes by principal first
        order = sorted(range(len(victims)),
                       key=lambda i: victims[i]["principal"])
        weights = [demands[i] for i in order]
        shares = largest_remainder_shares(victim_pool, weights)
        for i, share in zip(order, shares):
            payouts[victims[i]["principal"]] = share
            spent += share
    bounty = 0
    rep_pay: dict[str, int] = {}
    if reporters:
        bounty = min(P["reporter_bounty_cap"],
                     floor_bps(S, P["reporter_bounty_bps"]))
        shares = largest_remainder_shares(bounty, [1] * len(reporters))
        for r, share in zip(sorted(reporters), shares):
            rep_pay[r] = share
        spent += bounty
    return {
        "victims": payouts, "reporters": rep_pay,
        "reserve": S - spent, "victim_pool": victim_pool, "bounty": bounty,
    }
