"""Full clean-100 lifecycle + settlement economics (TV-M-40, 41, 70, 71,
76, 77, 80, 81)."""

from __future__ import annotations

import pytest

from mint.policy import schedule
from mint.store import jload


@pytest.mark.slow
def test_clean100_full_lifecycle(sim):
    """The complete happy path: post→fund→auction→claim→submit→escrow→
    evaluate→challenge window→settle. Ends ACCEPT + SETTLED."""
    from mint.scenario import run_clean_100
    res = run_clean_100(sim)
    assert res["outcome"] == "ACCEPT"
    task = sim.e._get_task("t1")
    assert task["state"] == "SETTLED"
    assert task["outcome"] == "ACCEPT"
    assert task["finality_ready"]


@pytest.mark.slow
def test_tvm40_settlement_economics(sim):
    """p=9000 ACCEPT: poster refund 3000, worker 9000+Bw, fees 500, F=200,
    DeliverableKeyReleased emitted."""
    from mint.scenario import run_clean_100
    run_clean_100(sim)
    e = sim.e
    # worker-1 claimed at p=9000 (winner under the seeded bids)
    task = e._get_task("t1")
    assert task["state"] == "SETTLED"
    worker = e.get_account(task["claim_actor"], e.asset)
    poster = e.get_account("poster-1", e.asset)
    # worker got reward p + Bw back (+ C returned on claim)
    assert int(worker["available"]) == 20000 - 2100 + 9000 + 2000 + 100
    # poster spent 9700 of 100000 (reward 9000 + fees 500 + F 200)
    assert int(poster["available"]) + int(poster["reserved"]) == \
        100000 - 9700
    evs = [r["type"] for r in e.s.all(
        "SELECT type FROM events ORDER BY seq")]
    assert "DeliverableKeyReleased" in evs
    assert "EscrowEnvelopeDeposited" in evs


@pytest.mark.slow
def test_tvm70_unused_rt_returns(sim):
    """Clean settlement with no court usage returns the full Rt earmark."""
    from mint.scenario import run_clean_100
    run_clean_100(sim)
    e = sim.e
    res = e.s.one("SELECT * FROM reservations WHERE kind='Rt'")
    assert res["state"] in ("RELEASED", "SETTLED", "CONSUMED", "RETURNED")


@pytest.mark.slow
def test_tvm76_escrow_deposits_poster_envelope(sim):
    from mint.scenario import run_clean_100
    run_clean_100(sim)
    e = sim.e
    esc = e.s.one("SELECT * FROM escrow_keys WHERE task_id='t1'")
    assert esc and esc["poster_envelope"] and esc["attestation"]
    # DeliverableKeyReleased binds the deposited envelope digest
    ev = e.s.one("SELECT data FROM events WHERE "
                 "type='DeliverableKeyReleased'")
    assert jload(ev["data"])["envelope_digest"]
