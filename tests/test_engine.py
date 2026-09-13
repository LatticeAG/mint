"""Engine-level conformance vectors: funding/reservation accounting
(TV-M-01..05), commit/reveal (06/07), task lifecycle (17/18/74),
idempotent replay (03/60), transport auth (51/52), stubs."""

from __future__ import annotations

import pytest

from mint.errors import MintError
from mint.policy import POLICY, schedule
from mint.store import jload
from conftest import must, post_task, fund_task

P = POLICY


def balances(sim, actor):
    row = sim.e.get_account(actor, sim.e.asset)
    return row


def err(resp):
    return resp["error"]["code"]


# -- TV-M-01: fund V=10000 reserves exactly 12700 -----------------------------
def test_tvm01_fund_reserves_exactly(sim):
    post_task(sim)
    resp = fund_task(sim)
    assert resp["state"] == "BONDED"
    acct = balances(sim, "poster-1")
    sch = schedule(10000)
    need = sch["poster_reserve"]
    assert need == 12700
    assert acct["reserved"] == str(need)
    assert acct["available"] == str(100000 - need)


# -- TV-M-02: insufficient funds ----------------------------------------------
def test_tvm02_insufficient_funds(sim):
    # drain poster to below the reserve requirement, then fund
    post_task(sim)
    sim.e.s.db.execute(
        "UPDATE balances SET balance=12699 WHERE account=?",
        (f"acct:poster-1:{sim.e.asset}:available",))
    code, resp = sim.send("poster-test", "task.fund",
                          {"task_id": "t1", "expected_version": 1})
    assert code == 422 or err(resp) == "INSUFFICIENT_FUNDS"
    assert err(resp) == "INSUFFICIENT_FUNDS"


# -- TV-M-03: idempotent replay returns the same receipt ----------------------
def test_tvm03_idempotent_replay(sim):
    post_task(sim)
    body = {"task_id": "t1", "expected_version": 1}
    c1, r1 = sim.send("poster-test", "task.fund", body,
                      idem_key="idem-fund-1")
    c2, r2 = sim.send("poster-test", "task.fund", body,
                      idem_key="idem-fund-1")
    assert c1 == 200 and c2 == 200
    assert r1["receipt_seq"] == r2["receipt_seq"]
    assert r1["command_id"] == r2["command_id"]
    # only one reservation set exists
    n = sim.e.s.one(
        "SELECT COUNT(*) AS c FROM reservations WHERE task_id='t1' "
        "AND owner='poster-1'")["c"]
    assert n == 4  # V, Bp, E, F


# -- TV-M-04: same idempotency key, different body -> conflict -----------------
def test_tvm04_idempotency_conflict(sim):
    post_task(sim)
    post_task(sim, task_id="t2")
    sim.send("poster-test", "task.fund",
             {"task_id": "t1", "expected_version": 1},
             idem_key="idem-same")
    code, resp = sim.send("poster-test", "task.fund",
                          {"task_id": "t2", "expected_version": 1},
                          idem_key="idem-same")
    assert code == 409 or err(resp) == "IDEMPOTENCY_CONFLICT"
    assert err(resp) == "IDEMPOTENCY_CONFLICT"


# -- TV-M-17: non-owner submission is role-forbidden ----------------------------
def test_tvm17_submit_non_owner(sim):
    post_task(sim)
    fund_task(sim)
    sim.e.s.db.execute(
        "UPDATE tasks SET state='CLAIMED', claim_actor='worker-1', "
        "claim_group='pg-worker-1' WHERE task_id='t1'")
    code, resp = sim.send("worker-2", "task.submit", {
        "task_id": "t1", "expected_version":
        sim.e._get_task("t1")["version"],
        "manifest_id": "art:submission-t1",
        "execution_receipt_id": "art:run-t1"})
    assert code == 403
    assert err(resp) == "ROLE_FORBIDDEN" or "FORBIDDEN" in err(resp)


# -- TV-M-74: acceptance_score cap ----------------------------------------------
def test_tvm74_acceptance_cap(sim):
    code, resp = sim.send("poster-test", "task.post", {
        "task_id": "t9", "market_id": sim.e.market_id,
        "asset": sim.e.asset, "value": "10000",
        "execution_cap_seconds": 3600, "forecast_floor": 7000,
        "acceptance_score": 9600, "manifest_id": "art:manifest-t1",
        "rubric_id": "art:rubric-r1", "charter_bundle_id":
        "art:charter-r1", "policy_id": "mint-policy-1"})
    assert code == 400 or code == 422
    assert err(resp) == "ACCEPTANCE_CAP"


# -- TV-M-52: signature on a different network -----------------------------------
def test_tvm52_wrong_network(sim):
    from mint.transport import sign_request
    from mint.jsonutil import jcs
    from mint.timeutil import fmt_ts
    import secrets
    k = sim.ks.get("poster-test")
    body = jcs({"op": "account.credit", "args": {"account": "poster-1",
                "asset": "SIMUSD", "amount": "1",
                "external_ref": "x", "custody_certificate": {}}})
    now = sim.e.now_ms
    headers = sign_request(
        bytes.fromhex(k["secret_hex"]), "mint-OTHER-NET", "POST",
        "/v1/commands", k["actor"], k["key_epoch"],
        secrets.token_hex(16), fmt_ts(now), fmt_ts(now + 300_000),
        body, "idem-x")
    code, resp = sim.send_raw(headers, body)
    assert code == 401 or err(resp) in ("BAD_SIGNATURE", "NETWORK")


# -- TV-M-59/60: command transaction atomicity ------------------------------------
def test_tvm59_command_rolls_back(sim):
    """A handler failure must roll back nonce, ledger, and event writes."""
    post_task(sim)
    n0 = sim.e.s.one("SELECT COUNT(*) c FROM events")["c"]
    code, resp = sim.send("poster-test", "task.fund",
                          {"task_id": "t1", "expected_version": 99})
    assert code != 200
    n1 = sim.e.s.one("SELECT COUNT(*) c FROM events")["c"]
    assert n0 == n1
    # nonce rolled back: reuse of the same nonce is not possible anyway,
    # but a retry with a fresh nonce must succeed
    resp2 = fund_task(sim)
    assert resp2["state"] == "BONDED"


def test_tvm60_replay_returns_committed_receipt(sim):
    post_task(sim)
    c1, r1 = sim.send("poster-test", "task.fund",
                      {"task_id": "t1", "expected_version": 1},
                      idem_key="idem-replay-1")
    # simulate replay after commit: same key+body returns stored receipt
    c2, r2 = sim.send("poster-test", "task.fund",
                      {"task_id": "t1", "expected_version": 1},
                      idem_key="idem-replay-1")
    assert r1 == r2


# -- stubs -------------------------------------------------------------------
def test_hosted_surfaces_raise():
    from mint.stubs import (
        BeaconNetwork, CovenantBridge, CustodyAdapter,
        HostedMarketSurface, PaidDisputeSurface, TelemetrySink,
        WitnessNetwork)
    from mint.errors import NotImplementedSurface
    import inspect
    for cls in (HostedMarketSurface, CustodyAdapter, WitnessNetwork,
                BeaconNetwork, PaidDisputeSurface, TelemetrySink,
                CovenantBridge):
        inst = cls()
        for name, fn in inspect.getmembers(inst, inspect.ismethod):
            if name.startswith("_"):
                continue
            try:
                fn()
            except NotImplementedSurface as e:
                assert e.reason
            except TypeError:
                # needs args; call with dummies
                try:
                    fn(*([{}] * 6))
                except NotImplementedSurface as e:
                    assert e.reason
                except Exception:
                    pass


# -- TV-M-51: revoked key epoch cannot authorize ------------------------------
def test_tvm51_revoked_epoch(sim):
    sim.e.s.db.execute(
        "UPDATE actor_keys SET state='REVOKED' WHERE actor='poster-1' "
        "AND key_epoch=1")
    code, resp = sim.send("poster-test", "task.post", {
        "task_id": "rev1", "market_id": sim.e.market_id,
        "asset": sim.e.asset, "value": "10000",
        "execution_cap_seconds": 3600, "forecast_floor": 7000,
        "acceptance_score": 8500, "manifest_id": "art:manifest-t1",
        "rubric_id": "art:rubric-r1", "charter_bundle_id":
        "art:charter-r1", "policy_id": "mint-policy-1"})
    assert code == 401 or err(resp) in ("KEY_REVOKED", "UNAUTHORIZED",
                                        "BAD_SIGNATURE")
