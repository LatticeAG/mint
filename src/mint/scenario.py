"""clean-100 end-to-end scenario: post -> fund -> auction -> claim ->
submit -> escrow -> evaluation -> ACCEPT -> settle -> withdraw.

Deterministic: keys derive from the run seed, judgments come from the
rubric oracle (spec §10.1), and the local witness quorum checkpoints
every step.
"""

from __future__ import annotations

import base64
from pathlib import Path

from .crypto import (
    deliverable_commitment, seal_chunk, tk_commitment, wrap_key,
)
from .errors import MintError
from .jsonutil import domain_hash, jcs, jcs_text, sha256_hex
from .policy import POLICY, schedule
from .sim import Sim, _derive_ed25519, _derive_x25519
from .store import jload
from .timeutil import fmt_ts

P = POLICY


def ok(code: int, resp: dict, what: str) -> dict:
    if code != 200:
        raise MintError(code, "SCENARIO", f"{what} failed: {resp}")
    return resp


def bootstrap(sim: Sim, poster_credit: int = 100_000,
              worker_credit: int = 20_000,
              evaluator_credit: int = 20_000,
              judge_credit: int = 50_000) -> None:
    """Enroll the fixture roster and fund accounts."""
    e = sim.e
    # operator first (self-cert via registrar is not needed for operator:
    # registrar cert still required — the pinned registrar signs it)
    _enroll_all(sim)
    _seed_reserve(sim, P["reserve_initial"])
    # artifact set published by the operator
    _publish_core_artifacts(sim)
    # fund accounts (encryption sub-keys share the actor; skip them)
    seen: set[str] = set()
    for key_id, k in sim.ks.keys.items():
        actor = k["actor"]
        if key_id.endswith("-enc") or actor in seen:
            continue
        seen.add(actor)
        roles = jload(e.s.one(
            "SELECT roles FROM actors WHERE actor=?", (actor,))["roles"])
        amt = {"poster": poster_credit, "worker": worker_credit,
               "evaluator": evaluator_credit,
               "judge": judge_credit}.get(roles[0], 10_000)
        if roles[0] == "operator":
            continue
        _credit(sim, actor, amt)
    e.create_checkpoint()


def _enroll_all(sim: Sim) -> None:
    e = sim.e
    for key_id, k in sim.ks.keys.items():
        if key_id.endswith("-enc"):
            continue
        actor = k["actor"]
        group = "pg-" + actor.replace("-", "-") if not \
            actor.startswith("pg-") else actor
        group = {
            "poster-1": "pg-poster-1",
            "operator-1": "pg-operator",
        }.get(actor, "pg-" + actor)
        roles = _roles_for(actor)
        extra = {}
        if "poster" in roles:
            extra["encryption_key_hex"] = sim.ks.keys[
                "poster-test-enc"]["public_key_hex"]
        if "evaluator" in roles:
            # spread across provider families so the §3.1 same-family
            # seat cap does not starve the panel
            extra["model_family"] = \
                f"fam-{int(actor.rsplit('-', 1)[1]) % 5}"
        args = {"actor": actor, "principal_group": group,
                "roles": roles, "key_epoch": 1,
                "public_key_hex": k["public_key_hex"],
                "identity_attestation": f"att:{actor}",
                "registrar_certificate": "", **extra}
        cert_args = {kk: vv for kk, vv in args.items()
                     if kk != "registrar_certificate"}
        cert = sim.registrar_cert(key_id, cert_args)
        args["registrar_certificate"] = cert  # inline cert object
        code, resp = sim.send(key_id, "actor.enroll", args)
        if code != 200:
            raise MintError(code, "SCENARIO",
                            f"enroll {actor} failed: {resp}")


def _roles_for(actor: str) -> list[str]:
    if actor.startswith("poster"):
        return ["poster"]
    if actor.startswith("worker"):
        return ["worker"]
    if actor.startswith("evaluator"):
        return ["evaluator"]
    if actor.startswith("judge"):
        return ["judge"]
    return ["operator"]


def _seed_reserve(sim: Sim, amount: int) -> None:
    """Operator reserve + custody backing seeded as the genesis funding
    entry (fixture-only: documented in the log as OperatorReserveSeeded)."""
    e = sim.e
    with e.s.tx():
        txn = "txn-genesis-reserve"
        e.ledger.post(txn, e.asset, f"custody:cash:{e.asset}",
                      f"op:reserve:{e.asset}", amount)
        e._emit("OperatorReserveSeeded", {"amount": str(amount)})


def _credit(sim: Sim, actor: str, amount: int) -> None:
    subject = {"account": actor, "asset": sim.e.asset,
               "amount": str(amount),
               "external_ref": f"sim-deposit-{actor}"}
    cert = sim.custody_cert(subject, "mint.credit.v1")
    code, resp = sim.send("operator", "account.credit", {
        "account": actor, "asset": sim.e.asset, "amount": str(amount),
        "external_ref": subject["external_ref"],
        "custody_certificate": cert})
    if code != 200:
        raise MintError(code, "SCENARIO", f"credit {actor}: {resp}")


def _publish_core_artifacts(sim: Sim) -> None:
    from .sim import RUBRIC_R1
    e = sim.e
    charter = {
        "charter_id": "charter-r1",
        "constitution_hash": domain_hash(
            "mint.constitution.v1", {"text": "sim constitution"}),
        "precedent_root": domain_hash("mint.precedent.v1", {"empty": True}),
        "offense_schedule_hash": __import__("mint.policy",
                                            fromlist=["OFFENSE_SCHEDULE_HASH"]).OFFENSE_SCHEDULE_HASH,
        "policy_hash": __import__("mint.policy",
                                  fromlist=["POLICY_HASH"]).POLICY_HASH,
    }
    for aid, obj in (("art:charter-r1", charter),
                     ("art:rubric-r1", RUBRIC_R1),
                     ("art:manifest-t1", {
                         "manifest_id": "art:manifest-t1",
                         "task_class": "code",
                         "deliverable_spec": {"format": "tar.gz"},
                         "requirements": ["build a thing"],
                         "hidden_test_commitments":
                             ["art:hidden-tests-commit-t1"]})):
        code, resp = sim.publish("operator", aid, obj)
        if code != 200:
            raise MintError(code, "SCENARIO", f"publish {aid}: {resp}")
    hidden = {"tests": ["t-check-1", "t-check-2"],
              "sha256_of_pack": sha256_hex(b"hidden-test-pack")}
    sim.publish("poster-test", "art:hidden-tests-t1", hidden)
    sim.publish("poster-test", "art:hidden-tests-commit-t1",
                {"sha256": sha256_hex(jcs(hidden))})


def run_clean_100(sim: Sim) -> dict:
    """Drive the complete happy-path scenario; returns a run summary."""
    e = sim.e
    trace: list[dict] = []

    def step(name, fn):
        r = fn()
        trace.append({"step": name, "result": r})
        return r

    # 0. age the registry past the 24h draw-freeze snapshot
    sim.advance(P["registry_freeze_seconds"] + 120)

    # 1. post + fund ------------------------------------------------------
    step("task.post", lambda: ok(*sim.send("poster-test", "task.post", {
        "task_id": "t1", "market_id": e.market_id, "asset": e.asset,
        "value": "10000", "execution_cap_seconds": 3600,
        "forecast_floor": 7000, "acceptance_score": 8500,
        "manifest_id": "art:manifest-t1", "rubric_id": "art:rubric-r1",
        "charter_bundle_id": "art:charter-r1",
        "policy_id": "mint-policy-1"}), "task.post"))
    e.create_checkpoint()
    fund = step("task.fund", lambda: ok(*sim.send(
        "poster-test", "task.fund",
        {"task_id": "t1", "expected_version": 1}), "task.fund"))
    assert fund["state"] == "BONDED"

    # 2. auction ----------------------------------------------------------
    epoch = e.s.one("SELECT auction_epoch FROM tasks WHERE task_id='t1'"
                    )["auction_epoch"]
    sim.advance_to(e.epoch_start(epoch) + 60_000)
    bids = {}
    for i, (wid, price, lat) in enumerate(
            (("worker-1", 9000, 1800), ("worker-2", 9500, 2400),
             ("worker-3", 8500, 3600))):
        salt = sha256_hex(f"salt-{wid}".encode())
        k = sim.ks.get(wid)
        commit = domain_hash("mint.bid.commit.v1", {
            "network": e.network, "market_id": e.market_id,
            "epoch": epoch, "task_id": "t1",
            "principal_group": f"pg-{wid}",
            "key_epoch": k["key_epoch"], "p": price, "l": lat,
            "slot": f"slot-{wid}", "salt": salt})
        ok(*sim.publish(wid, f"art:commit-{wid}",
                        {"commitment": commit}), "publish commit")
        ok(*sim.send(wid, "bid.commit", {
            "task_id": "t1", "epoch": epoch, "expected_version": 1,
            "slot": f"slot-{wid}",
            "commitment_id": f"art:commit-{wid}"}), "bid.commit")
        bids[wid] = (price, lat, salt)
    sim.advance_to(e.epoch_start(epoch) + 1_000_000)
    for wid, (price, lat, salt) in bids.items():
        ok(*sim.send(wid, "bid.reveal", {
            "task_id": "t1", "epoch": epoch, "price": str(price),
            "latency_seconds": lat, "slot": f"slot-{wid}",
            "salt": salt}), "bid.reveal")
    # close: witnessed checkpoint at reveal close, beacon artifact,
    # clearing artifact
    reveal_close = e.epoch_start(epoch) + P["epoch_seconds"] * 1000
    sim.advance_to(reveal_close)
    cp = e.create_checkpoint()
    round_no = reveal_close // (P["beacon_round_seconds"] * 1000) + 1
    from .trust import beacon_value
    beacon_art = {"tag": "simulation", "round": round_no,
                  "rand": beacon_value(e.trust, round_no)}
    ok(*sim.publish("operator", f"art:beacon-{epoch}", beacon_art),
       "publish beacon")
    clearing = e._compute_clearing(epoch, cp["size"],
                                 beacon_art["rand"], round_no)
    ok(*sim.publish("operator", f"art:clearing-{epoch}",
                    {"clearing": clearing}), "publish clearing")
    ok(*sim.send("operator", "epoch.clear", {
        "market_id": e.market_id, "epoch": epoch,
        "closure_checkpoint_id": cp["checkpoint_id"],
        "beacon_artifact_id": f"art:beacon-{epoch}",
        "clearing_artifact_id": f"art:clearing-{epoch}"}), "epoch.clear")

    # 3. claim --------------------------------------------------------------
    task = e._get_task("t1")
    winner = task["offer_group"]
    winner_key = winner.replace("pg-", "")
    ok(*sim.send(winner_key, "task.claim", {
        "task_id": "t1", "offer_id": task["offer_id"],
        "expected_version": task["version"]}), "task.claim")

    # 4. submit -------------------------------------------------------------
    sim.advance(1200)
    deliverable = b"clean-100 deliverable bytes\n" * 4
    tk = sha256_hex(b"tk-t1").encode()[:32].ljust(32, b"\x00")
    tk = bytes.fromhex(domain_hash("mint.sim.tk.v1",
                                   {"task": "t1"}))[:32]
    chunk = seal_chunk(tk, deliverable)
    salt = sha256_hex(b"deliv-salt-t1")
    pc = deliverable_commitment(salt, [sha256_hex(deliverable)])
    escrow_pub = bytes.fromhex(
        e.trust["panel_escrow"]["public_key_hex"])
    envelope = {"tk_wrap": wrap_key(tk, escrow_pub),
                "tk_commitment": tk_commitment(tk)}
    ok(*sim.publish("worker-1", "art:envelope-t1", envelope),
       "publish envelope")
    ok(*sim.publish("worker-1", "art:chunk-t1-0", chunk,
                    media_type="application/octet-stream"),
       "publish chunk")
    ok(*sim.publish("worker-1", "art:run-t1",
                    {"receipt": "sim-execution", "task_id": "t1"}),
       "publish run")
    manifest = {
        "ciphertext_artifacts": ["art:chunk-t1-0"],
        "ciphertext_digests": [sha256_hex(chunk)],
        "plaintext_commitment": pc, "salt": salt,
        "envelope_artifact": "art:envelope-t1",
    }
    ok(*sim.publish("worker-1", "art:submission-t1", manifest),
       "publish submission")
    task = e._get_task("t1")
    ok(*sim.send(winner_key, "task.submit", {
        "task_id": "t1", "expected_version": task["version"],
        "manifest_id": "art:submission-t1",
        "execution_receipt_id": "art:run-t1"}), "task.submit")

    # 5. roster + escrow + accept -------------------------------------------
    sim.advance(P["beacon_round_seconds"] * 3)
    task = e._get_task("t1")
    assert task["escrow_status"] == "DEPOSITED", \
        f"escrow: {task['escrow_status']}"
    seats = e.s.all("SELECT * FROM seats WHERE task_id='t1' AND "
                    "role='PRIMARY' AND state='DRAWN'")
    for seat in seats:
        kid = seat["actor"]
        ok(*sim.send(kid, "seat.accept", {
            "task_id": "t1", "seat_id": seat["seat_id"],
            "stage": "EVALUATION",
            "conflict_attestation_id": "art:none"}), "seat.accept")

    # 6. evaluator commit/reveal --------------------------------------------
    judgment = {
        "observations": {
            "tests_passed": 19, "tests_determinate": 20,
            "clauses_satisfied": 3, "clauses_determinate": 4,
            "reruns_matched": 5, "reruns_determinate": 5,
            "controls_passed": 2, "controls_determinate": 2},
        "mandatory_gates": {"content": True, "license": True,
                            "integrity": True},
        "evidence_ids": ["art:tests-t1", "art:run-t1"],
        "conflict": False, "reason": "RUBRIC_PASS"}
    sim.publish("operator", "art:tests-t1", {"results": "19/20"})
    salts = {}
    for seat in seats:
        seat = e.s.one("SELECT * FROM seats WHERE seat_id=?",
                       (seat["seat_id"],))
        actor = seat["actor"]
        salt = sha256_hex(f"evalsalt-{seat['seat_id']}".encode())
        salts[seat["seat_id"]] = salt
        k = sim.ks.get(actor)
        commit = domain_hash("mint.eval.commit.v1", {
            "network": e.network, "market_id": e.market_id,
            "task_id": "t1", "round": 1, "seat_id": seat["seat_id"],
            "key_epoch": k["key_epoch"], "judgment": judgment,
            "salt": salt})
        ok(*sim.publish(actor, f"art:eval-commit-{seat['seat_id']}",
                        {"commitment": commit}), "publish eval commit")
        ok(*sim.send(actor, "evaluation.commit", {
            "task_id": "t1", "seat_id": seat["seat_id"], "round": 1,
            "commitment_id": f"art:eval-commit-{seat['seat_id']}"}),
            "evaluation.commit")
    # advance past access close + commit window
    task = e._get_task("t1")
    sim.advance_to(task["access_close_ms"] +
                   P["evaluator_commit_seconds"] * 1000 + 1000)
    for seat in seats:
        seat = e.s.one("SELECT * FROM seats WHERE seat_id=?",
                       (seat["seat_id"],))
        ok(*sim.send(seat["actor"], "evaluation.reveal", {
            "task_id": "t1", "seat_id": seat["seat_id"], "round": 1,
            "judgment": judgment, "salt": salts[seat["seat_id"]]}),
            "evaluation.reveal")
    # reveal close -> finalize
    sim.advance(P["evaluator_reveal_seconds"] + 60)
    task = e._get_task("t1")
    assert task["state"] == "EVALUATED" and task["outcome"] == "ACCEPT", \
        f"expected ACCEPT, got {task['state']}/{task['outcome']}"

    # 7. challenge window -> finality ----------------------------------------
    sim.advance(P["challenge_seconds"] + 60)
    task = e._get_task("t1")
    assert task["finality_ready"], "finality not ready"

    # 8. settlement -----------------------------------------------------------
    inst = e.settlement_instruction("t1")
    ok(*sim.publish("operator", "art:settlement-t1", inst),
       "publish settlement")
    cert = sim.settlement_cert(inst)
    ok(*sim.publish("operator", "cert:settle-t1", cert),
       "publish settle cert")
    task = e._get_task("t1")
    res = ok(*sim.send("operator", "settlement.execute", {
        "task_id": "t1", "expected_version": task["version"],
        "settlement_artifact_id": "art:settlement-t1",
        "certificate_id": "cert:settle-t1"}), "settlement.execute")
    assert res["state"] == "SETTLED"
    return {"scenario": "clean-100", "task_id": "t1",
            "outcome": "ACCEPT", "events": e._seq(), "trace": trace}
