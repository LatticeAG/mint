"""Settlement, withdrawal, control, key rotation, and clock mixin."""

from __future__ import annotations

from .errors import (
    MintError, conflict, forbidden, malformed, not_found, policy,
    unauthorized,
)
from .jsonutil import (
    check_fields, domain_hash, jcs_text, parse_amount, sha256_hex)
from .policy import POLICY, schedule
from .store import jdump, jload
from .timeutil import fmt_ts, parse_ts

P = POLICY


class SettleOps:
    # ------------------------------------------------------------------
    # clock.advance — witnessed-time control (control-object, not the
    # runtime path per §11)
    # ------------------------------------------------------------------
    def op_clock_advance(self, actor, args, headers, command_id):
        check_fields(args, {"market_id", "checkpoint_id", "through"},
                     {"market_id", "checkpoint_id", "through"})
        if args["market_id"] != self.market_id:
            raise malformed("unknown market_id")
        cp = self.s.one("SELECT * FROM checkpoints WHERE checkpoint_id=?",
                        (args["checkpoint_id"],))
        if not cp:
            raise not_found("checkpoint not found")
        self.verify_checkpoint({**dict(cp),
                                "signatures": jload(cp["signatures"])})
        to_ms = parse_ts(args["through"], "through")
        # only deadlines at or before the checkpoint's witnessed time may
        # be processed; the relay cannot invent time
        cp_ms = parse_ts(cp["time"])
        if to_ms > cp_ms:
            raise conflict("CHECKPOINT_TOO_OLD",
                           "through exceeds the checkpoint's witnessed "
                           "time")
        if to_ms <= self.now_ms:
            raise malformed("clock may only advance")
        self._advance_clock(to_ms, reason="witnessed checkpoint")
        return "APPLIED", {"events": ["DeadlineProcessed"]}

    def _advance_clock(self, to_ms: int, reason: str = "advance") -> None:
        """Advance witnessed time, firing every deadline crossed in due
        order (§9.8: anchor + nominal + paused). Each deadline fires with
        the clock set to its own effective due time, so deadlines armed
        by a firing anchor at the fire time — not the stale clock."""
        while True:
            nxt = self._earliest_due(to_ms)
            if nxt is None:
                break
            d, due_ms = nxt
            self._set_now(due_ms)
            self._fire_deadline(d, due_ms)
        self._set_now(to_ms)
        self._emit("ClockAdvanced", {"to": fmt_ts(to_ms),
                                     "reason": reason})
        # checkpoint freshness decays with witnessed time; emit a
        # checkpoint so later admissions can pass the gate
        self.create_checkpoint(at_ms=to_ms)

    def _due_ms(self, d, at_ms: int) -> int | None:
        """Effective wall-clock due time <= at_ms, or None. Pauses extend
        the due time; solve by fixpoint (pauses are finite rows)."""
        if not d["pausable"]:
            due = d["anchor_ms"] + d["nominal_seconds"] * 1000
            return due if due <= at_ms else None
        due = d["anchor_ms"] + d["nominal_seconds"] * 1000
        for _ in range(64):
            paused = self.paused_overlap(d["scope"], d["object_id"],
                                         d["anchor_ms"], due)
            new = d["anchor_ms"] + d["nominal_seconds"] * 1000 + paused
            if new == due:
                break
            due = new
        return due if due <= at_ms else None

    def _earliest_due(self, to_ms: int):
        best = None
        for d in self.s.all("SELECT * FROM deadlines WHERE done=0"):
            due = self._due_ms(d, to_ms)
            if due is not None and (best is None or due < best[1]):
                best = (d, due)
        return best

    def _fire_deadline(self, d, at_ms: int) -> None:
        self.s.db.execute("UPDATE deadlines SET done=1 WHERE deadline_id=?",
                          (d["deadline_id"],))
        kind = d["kind"]
        obj = d["object_id"]
        if kind == "funding_expiry":
            task = self._get_task(obj)
            if task["state"] == "POSTED":
                self.s.db.execute(
                    "UPDATE tasks SET state='SETTLED', outcome='UNFUNDED'"
                    " WHERE task_id=?", (obj,))
                self._emit("TaskClosedUnfunded", {"task_id": obj,
                                                  "reason": "TIMEOUT"})
                self._emit("TaskSettled", {"task_id": obj,
                                           "outcome": "UNFUNDED",
                                           "outstanding_reservations": "0"})
        elif kind == "offer_expiry":
            task = self._get_task(obj)
            if task["state"] == "BONDED" and \
                    task["auction_state"] == "OFFERING" and \
                    task["offer_id"] is not None:
                self._offer_expired(task, d)
        elif kind == "exec_cap":
            task = self._get_task(obj)
            if task["state"] == "CLAIMED":
                self._execution_timed_out(task)
        elif kind == "eval_draw":
            task = self._get_task(obj)
            if task["state"] == "SUBMITTED" and task["roster"] is None:
                self._draw_roster(task)
        elif kind == "acceptance_close":
            task = self._get_task(obj)
            if task["state"] == "SUBMITTED":
                self._acceptance_close(task)
        elif kind == "access_close":
            task = self._get_task(obj)
            if task["state"] == "SUBMITTED" and \
                    task["escrow_status"] == "DEPOSITED":
                self.add_deadline(
                    "eval_commit_close", obj, task["access_close_ms"],
                    P["evaluator_commit_seconds"], pausable=True,
                    scope="market")
        elif kind == "eval_commit_close":
            task = self._get_task(obj)
            if task["state"] == "SUBMITTED":
                self._commit_close(task)
        elif kind == "eval_reveal_close":
            task = self._get_task(obj)
            if task["state"] == "SUBMITTED":
                self._reveal_close(task)
        elif kind == "challenge_close":
            task = self._get_task(obj)
            if task["state"] == "EVALUATED" and not task["finality_ready"]:
                open_cases = self.s.one(
                    "SELECT 1 FROM cases WHERE task_id=? AND state NOT IN "
                    "('CLOSED')", (obj,))
                if not open_cases:
                    self.s.db.execute(
                        "UPDATE tasks SET finality_ready=1 WHERE "
                        "task_id=?", (obj,))
                    self._emit("FinalityReady", {"task_id": obj,
                                                 "outcome":
                                                 task["outcome"]})
        elif kind == "answer":
            case = self.s.one("SELECT * FROM cases WHERE case_id=?",
                              (obj,))
            if case:
                self._answer_expired(case)
        elif kind == "panel_acceptance":
            case = self.s.one("SELECT * FROM cases WHERE case_id=?",
                              (obj,))
            if case:
                self._panel_acceptance_close(case)
        elif kind == "court_decision":
            case = self.s.one("SELECT * FROM cases WHERE case_id=?",
                              (obj,))
            if case and case["state"] in ("DELIBERATING", "PANELING"):
                self._court_decide(case)
        elif kind == "appeal_window":
            case = self.s.one("SELECT * FROM cases WHERE case_id=?",
                              (obj,))
            if case:
                self._appeal_window_close(case)
        elif kind == "longstop":
            task = self._get_task(obj)
            if task["state"] not in ("SETTLED",):
                self._long_stop_settle(task)
        elif kind == "withdrawal_cooldown":
            pass  # withdrawal rows carry their own release time
        elif kind == "beacon_abort":
            task = self._get_task(obj)
            if task["state"] == "BONDED":
                self._auction_abort(task)

    def _all_primary_resolved(self, task) -> bool:
        row = self.s.one(
            "SELECT 1 FROM seats WHERE task_id=? AND role='PRIMARY' AND "
            "state='DRAWN'", (task["task_id"],))
        return row is None

    # ------------------------------------------------------------------
    def _execution_timed_out(self, task) -> None:
        """Execution cap passed unbonded: W1 no-delivery + W3 on Dmax,
        NO_DELIVERY outcome."""
        txn = self.ledger.txn_id("timer-cap", self._seq())
        bw = self._res_id(task["task_id"], "Bw")
        self._allege(task["task_id"], task["claim_actor"],
                     task["claim_group"], "worker", "W1", bw,
                     f"inc-w1-timeout-{task['task_id']}",
                     {"cap_seconds": task["execution_cap_seconds"]},
                     auto=True)
        self._allege(task["task_id"], task["claim_actor"],
                     task["claim_group"], "worker", "W3", bw,
                     f"inc-w3-timeout-{task['task_id']}",
                     {"promised_latency": task["promised_latency"],
                      "cap": task["execution_cap_seconds"]}, auto=True)
        self.s.db.execute(
            "UPDATE tasks SET state='EVALUATED', outcome='NO_DELIVERY', "
            "verdict='NO_DELIVERY' WHERE task_id=?", (task["task_id"],))
        self._bump_task_version(task["task_id"])
        self._emit("WorkTimedOut", {
            "task_id": task["task_id"],
            "cap_seconds": task["execution_cap_seconds"]})
        self._emit("EvaluationFinalized", {
            "task_id": task["task_id"], "outcome": "NO_DELIVERY",
            "verdict": "NO_DELIVERY"})
        self._challenge_window(task)

    def _long_stop_settle(self, task) -> None:
        """Absolute-clock long-stop: settle the stalest risk-free outcome
        per §8.5 with full detail."""
        txn = self.ledger.txn_id("timer-longstop", self._seq())
        state = task["state"]
        outcome = {"POSTED": "UNFUNDED", "BONDED": "CANCELED"}.get(
            state, task["outcome"] or "INCONCLUSIVE")
        # release every still-active reservation
        for r in self.s.all(
                "SELECT * FROM reservations WHERE task_id=? AND "
                "state='ACTIVE'", (task["task_id"],)):
            if r["kind"] == "Rt":
                self.s.db.execute(
                    "UPDATE reservations SET state='RELEASED' WHERE "
                    "reservation_id=?", (r["reservation_id"],))
            else:
                self._release_reservation(txn, r["reservation_id"])
        self.s.db.execute(
            "UPDATE tasks SET state='SETTLED', outcome=?, settled_ms=? "
            "WHERE task_id=?", (outcome, self.now_ms, task["task_id"]))
        self._emit("TaskSettled", {
            "task_id": task["task_id"], "outcome": outcome,
            "long_stop": True,
            "detail": {"state_at_long_stop": state}})

    # ------------------------------------------------------------------
    def op_settlement_execute(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "expected_version",
                            "settlement_artifact_id", "certificate_id"},
                     {"task_id", "expected_version",
                      "settlement_artifact_id", "certificate_id"})
        task = self._get_task(args["task_id"])
        self._expect_task_version(task, int(args["expected_version"]))
        if task["state"] != "EVALUATED" or not task["finality_ready"]:
            raise conflict("NOT_FINAL",
                           "challenge window is still open or the task "
                           "is already settled")
        inst = self.artifact_json(args["settlement_artifact_id"])
        expected_inst = self.settlement_instruction(task["task_id"])
        if jcs_text(inst) != jcs_text(expected_inst):
            raise policy("INSTRUCTION_MISMATCH",
                         "settlement artifact does not equal the "
                         "market's deterministic instruction")
        cert = self.artifact_json(args["certificate_id"])
        self._verify_settlement_quorum(inst, cert)
        # ACCEPT settlement releases the poster deliverable envelope
        # atomically (§2.6): the artifact must carry the deposited
        # poster_envelope copy verbatim.
        if task["outcome"] == "ACCEPT":
            esc = self.s.one("SELECT poster_envelope FROM escrow_keys "
                             "WHERE task_id=?", (task["task_id"],))
            deposited = jload(esc["poster_envelope"]) if esc and \
                esc["poster_envelope"] else None
            if inst.get("poster_envelope") != deposited:
                raise policy("KEY_RELEASE_MISMATCH",
                             "ACCEPT settlement must carry the escrow-"
                             "deposited poster_envelope")
        sch = schedule(task["value"])
        txn = self.ledger.txn_id(command_id, self._seq())
        payout = self._execute_settlement(task, txn, sch)
        self.s.db.execute(
            "UPDATE tasks SET state='SETTLED', settled_ms=? WHERE "
            "task_id=?", (self.now_ms, task["task_id"]))
        self._bump_task_version(task["task_id"])
        evs = []
        if task["outcome"] == "ACCEPT":
            self._record_history(task)
            evs.append(self._emit("DeliverableKeyReleased", {
                "task_id": task["task_id"],
                "envelope_digest": sha256_hex(jcs_text(
                    inst["poster_envelope"]).encode()),
            }))
        else:
            self._record_history(task)
        evs.append(self._emit("TaskSettled", {
            "task_id": task["task_id"], "outcome": task["outcome"],
            "outstanding_reservations": "0",
            "payout": {k: str(v) for k, v in payout.items()}}))
        return "SETTLED", {"events": [e["type"] for e in evs]}

    def _record_history(self, task) -> None:
        """Append the witnessed outcome observation feeding the quality
        forecast q (§5.3)."""
        if task["history_recorded"] or not task["claim_group"]:
            return
        obs_map = {"ACCEPT": 10000, "REJECT": 0, "NO_DELIVERY": 0}
        obs = obs_map.get(task["outcome"])
        if obs is None:
            return
        # lateness adjustment (§7.2) when the task was claimed
        if task["claimed_ms"] and task["submitted_ms"] and \
                task["promised_latency"]:
            from .clearing import lateness_observation
            elapsed = (task["submitted_ms"] - task["claimed_ms"]) // 1000
            adj = lateness_observation(obs, task["promised_latency"],
                                       elapsed,
                                       task["execution_cap_seconds"])
            obs = adj["observation"]
        self.s.db.execute(
            "INSERT OR REPLACE INTO history(principal_group,task_id,"
            "observation,settled_seq) VALUES(?,?,?,?)",
            (task["claim_group"], task["task_id"], obs, self._seq()))
        self.s.db.execute(
            "UPDATE tasks SET history_recorded=1 WHERE task_id=?",
            (task["task_id"],))

    def settlement_instruction(self, task_id: str) -> dict:
        """The deterministic final settlement instruction (§9.8): single
        atomic application of every entitlement still outstanding."""
        task = self._get_task(task_id)
        sch = schedule(task["value"])
        payout = self._settlement_plan(task, sch)
        inst = {"task_id": task_id, "outcome": task["outcome"],
                "verdict": task["verdict"], "payout": payout,
                "market_id": self.market_id, "asset": self.asset}
        # ACCEPT settlements carry the escrow-deposited poster envelope
        # verbatim (§8.4.25): the atomic key release.
        if task["outcome"] == "ACCEPT" and task["envelope_artifact_id"]:
            esc = self.s.one("SELECT poster_envelope FROM escrow_keys "
                             "WHERE task_id=?", (task_id,))
            if esc and esc["poster_envelope"]:
                inst["poster_envelope"] = jload(esc["poster_envelope"])
        return inst

    def _settlement_plan(self, task, sch) -> dict:
        """Compute payout shares without posting: (worker price,
        evaluator fees F, auditor, forfeitures, residual releases)."""
        from .penalty import evaluator_fee, auditor_share
        V = task["value"]
        out = task["outcome"]
        plan: dict = {"worker": "0", "poster_release": "0",
                      "evaluator_fees": {}, "auditor": "0",
                      "forfeits": {}, "claimant_paid": "0"}
        if out == "ACCEPT":
            plan["worker"] = str(task["price"])
            plan["poster_release"] = str(sch["V"] - task["price"])
            pool = evaluator_fee(V)
            eligible = self._fee_eligible_seats(task["task_id"])
            for s in eligible:
                plan["evaluator_fees"][s["seat_id"]] = str(
                    pool // max(1, len(eligible)))
            if self._auditor_worked(task["task_id"]):
                plan["auditor"] = str(auditor_share(V))
        elif out == "REJECT":
            plan["worker"] = str(P["reject_price_floor"])
            plan["poster_release"] = str(sch["V"] - P["reject_price_floor"])
            pool = evaluator_fee(V)
            eligible = self._fee_eligible_seats(task["task_id"])
            for s in eligible:
                plan["evaluator_fees"][s["seat_id"]] = str(
                    pool // max(1, len(eligible)))
        else:
            plan["poster_release"] = str(sch["V"])
        return plan

    def _fee_eligible_seats(self, task_id: str):
        return self.s.all(
            "SELECT * FROM seats WHERE task_id=? AND stage='EVALUATION' "
            "AND fee_eligible=1", (task_id,))

    def _auditor_worked(self, task_id: str) -> bool:
        row = self.s.one(
            "SELECT 1 FROM seats WHERE task_id=? AND role='AUDITOR' AND "
            "fee_eligible=1", (task_id,))
        return row is not None

    def _execute_settlement(self, task, txn, sch) -> dict:
        """Apply the payout plan in one ledger transaction: release
        remaining reservations, pay worker/evaluators, slash where the
        docket already sustained allegations."""
        V = task["value"]
        out = task["outcome"]
        paid: dict = {}
        # release/slash all active task reservations according to docket
        for r in self.s.all(
                "SELECT * FROM reservations WHERE task_id=? AND "
                "state='ACTIVE'", (task["task_id"],)):
            alg = self.s.one(
                "SELECT * FROM allegations WHERE reservation_id=? AND "
                "state='SUSTAINED'", (r["reservation_id"],))
            if alg and alg["penalty"]:
                pen = {k: int(v) for k, v in jload(alg["penalty"]).items()}
                # sustained penalties were already distributed at
                # enforcement; nothing further to post
                continue
            if r["kind"] == "Rt":
                self.s.db.execute(
                    "UPDATE reservations SET state='RELEASED' WHERE "
                    "reservation_id=?", (r["reservation_id"],))
            elif r["kind"] == "F" and out == "ACCEPT":
                # the F fee is earned by the operator on a clean ACCEPT
                # (§7.1); on REJECT it returns to the poster (§7.4)
                self.ledger.transfer_res(
                    txn, r["reservation_id"], f"op:revenue:{self.asset}",
                    self.asset, r["amount"])
                self.s.db.execute(
                    "UPDATE reservations SET state='CONSUMED' WHERE "
                    "reservation_id=?", (r["reservation_id"],))
                paid["operator_fee"] = r["amount"]
            else:
                self._release_reservation(txn, r["reservation_id"])
        if out == "ACCEPT":
            self.ledger.pay_out(txn, task["poster"], task["claim_actor"],
                                self.asset, task["price"],
                                task["task_id"])
            paid["worker"] = task["price"]
        elif out == "REJECT":
            floor_p = P["reject_price_floor"]
            self.ledger.pay_out(txn, task["poster"], task["claim_actor"],
                                self.asset, floor_p, task["task_id"])
            paid["worker"] = floor_p
        # evaluator fees from F pool (escrowed E pool covers the reserve;
        # F is paid from the F reservation already released back to
        # poster, so the poster pays fees out of available)
        pool = 0
        eligible = self._fee_eligible_seats(task["task_id"])
        if out in ("ACCEPT", "REJECT") and eligible:
            from .penalty import evaluator_fee
            pool = evaluator_fee(V)
            share = pool // len(eligible)
            for s in eligible:
                self.ledger.post(
                    txn, self.asset,
                    self.ledger.acct(task["poster"], self.asset,
                                     "available"),
                    self.ledger.acct(s["actor"], self.asset, "available"),
                    share)
            paid["evaluator_pool"] = pool
        if self._auditor_worked(task["task_id"]):
            from .penalty import auditor_share
            a = auditor_share(V)
            aud = self.s.one(
                "SELECT actor FROM seats WHERE task_id=? AND "
                "role='AUDITOR'", (task["task_id"],))
            self.ledger.post(
                txn, self.asset,
                self.ledger.acct(task["poster"], self.asset, "available"),
                self.ledger.acct(aud["actor"], self.asset, "available"),
                a)
            paid["auditor"] = a
        return paid

    def _verify_settlement_quorum(self, inst: dict, cert: dict) -> None:
        """3-of-5 pinned settlement custodians, distinct entities, over
        the deterministic instruction artifact (§8.4.25)."""
        from .crypto import ed25519_verify, unb64u
        from .jsonutil import jcs
        if cert.get("domain") != "mint.settlement.cert.v1":
            raise policy("CERT_DOMAIN", "certificate domain mismatch")
        msg = b"mint.settlement.cert.v1\x00" + jcs(inst)
        keys = {s["key_id"]: s for s in self.trust["settlement_signers"]}
        entities = set()
        for s in cert.get("signatures", []):
            k = keys.get(s.get("key_id"))
            if not k:
                continue
            if ed25519_verify(bytes.fromhex(k["public_key_hex"]),
                              unb64u(s["signature"]), msg):
                entities.add(k["entity"])
        if len(entities) < P["settlement_quorum"]:
            raise policy("SETTLEMENT_QUORUM_INVALID",
                         "settlement instruction lacks 3-of-5 distinct "
                         "custodian signatures",
                         {"distinct": len(entities)})

    # ------------------------------------------------------------------
    def op_account_withdraw(self, actor, args, headers, command_id):
        check_fields(args, {"actor", "asset", "amount", "address",
                            "custody_instruction_id"},
                     {"actor", "asset", "amount", "address",
                      "custody_instruction_id"})
        if args["actor"] != actor:
            raise forbidden("withdrawals are first-person only")
        if args["asset"] != self.asset:
            raise policy("ASSET_MISMATCH", "unknown asset")
        amount = parse_amount(args["amount"])
        # finality gate: available only (reserved never withdrawable)
        avail = self.ledger.available(actor, self.asset)
        if avail < amount:
            raise MintError(422, "INSUFFICIENT_FUNDS",
                            "amount exceeds available", False,
                            {"required": str(amount),
                             "available": str(avail)})
        release_ms = self.now_ms + \
            P["withdrawal_cooldown_seconds"] * 1000
        wid = f"wd-{self._seq()}-{actor[:8]}"
        txn = self.ledger.txn_id(command_id, self._seq())
        # move to a pending-withdrawal holding line (still on-market)
        self.ledger.post(
            txn, self.asset,
            self.ledger.acct(actor, self.asset, "available"),
            self.ledger.acct(actor, self.asset, "withdrawal_pending"),
            amount)
        self.s.db.execute(
            "INSERT INTO withdrawals(withdrawal_id,actor,asset,amount,"
            "address,instruction_id,requested_ms,release_ms,state) "
            "VALUES(?,?,?,?,?,?,?,?,'PENDING')",
            (wid, actor, self.asset, amount, args["address"],
             args["custody_instruction_id"], self.now_ms, release_ms))
        self._emit("WithdrawalRequested", {
            "withdrawal_id": wid, "actor": actor, "amount": str(amount),
            "release_ms": release_ms,
            "instruction_id": args["custody_instruction_id"]},
            detail=self._detail(command_id, headers))
        return "PENDING", {"events": ["WithdrawalRequested"],
                           "withdrawal_id": wid}

    def op_custody_result(self, actor, args, headers, command_id):
        check_fields(args, {"withdrawal_id", "provider_state",
                            "provider_reference", "certificate_id"},
                     {"withdrawal_id", "provider_state",
                      "provider_reference", "certificate_id"})
        wd = self.s.one("SELECT * FROM withdrawals WHERE withdrawal_id=?",
                        (args["withdrawal_id"],))
        if not wd:
            raise not_found("withdrawal not found")
        if self.now_ms < wd["release_ms"]:
            raise conflict("COOLDOWN_OPEN", "cooldown has not elapsed")
        cert = self._load_certificate(args["certificate_id"],
                                      "mint.custody.result.v1")
        self._verify_certificate(cert, "custody_issuer",
                                 {k: v for k, v in args.items()
                                  if k != "certificate_id"})
        state = args["provider_state"]
        if state not in ("PAID", "FAILED_FINAL", "UNKNOWN"):
            raise malformed("unknown provider_state")
        if state == "PAID":
            txn = self.ledger.txn_id(command_id, self._seq())
            self.ledger.post(
                txn, self.asset,
                self.ledger.acct(wd["actor"], self.asset,
                                 "withdrawal_pending"),
                f"custody:cash:{self.asset}", wd["amount"])
            self.s.db.execute(
                "UPDATE withdrawals SET state='SETTLED', receipt_id=? "
                "WHERE withdrawal_id=?",
                (args["certificate_id"], wd["withdrawal_id"]))
            self._emit("WithdrawalCompleted", {
                "withdrawal_id": wd["withdrawal_id"],
                "provider_reference": args["provider_reference"]})
            return "PAID", {"events": ["WithdrawalCompleted"]}
        if state == "FAILED_FINAL":
            txn = self.ledger.txn_id(command_id, self._seq())
            self.ledger.post(
                txn, self.asset,
                self.ledger.acct(wd["actor"], self.asset,
                                 "withdrawal_pending"),
                self.ledger.acct(wd["actor"], self.asset, "available"),
                wd["amount"])
            self.s.db.execute(
                "UPDATE withdrawals SET state='RETURNED', receipt_id=? "
                "WHERE withdrawal_id=?",
                (args["certificate_id"], wd["withdrawal_id"]))
            self._emit("WithdrawalReturned", {
                "withdrawal_id": wd["withdrawal_id"],
                "provider_reference": args["provider_reference"]})
            return "RETURNED", {"events": ["WithdrawalReturned"]}
        # UNKNOWN: pending stays pending; reconciliation retries later
        return "PENDING", {"events": []}

    # ------------------------------------------------------------------
    CONTROL_ACTIONS = ("PAUSE_ADMISSIONS", "RESUME_ADMISSIONS",
                       "WITNESSED_OUTAGE", "END_OUTAGE", "REVOKE_KEY",
                       "LEGAL_HOLD", "ACTIVATE_POLICY")

    def op_market_control(self, actor, args, headers, command_id):
        check_fields(args, {"market_id", "action", "reason", "evidence_id",
                            "certificate_id"},
                     {"market_id", "action", "evidence_id",
                      "certificate_id"})
        if args["market_id"] != self.market_id:
            raise malformed("unknown market_id")
        action = args["action"]
        if action not in self.CONTROL_ACTIONS:
            raise malformed("unknown control action")
        # every control action requires a 4-of-7 recovery-authority
        # certificate binding the complete action artifact (§8.4.27)
        order = self.artifact_json(args["evidence_id"])
        cert = self.artifact_json(args["certificate_id"])
        self._verify_recovery_cert(order, cert, action)
        if action == "PAUSE_ADMISSIONS":
            self.s.kv_set("admissions", "PAUSED")
            self._emit("MarketControlApplied", {
                "action": action, "reason": args.get("reason")})
            return "ADMISSIONS_PAUSED", {"events": ["MarketControlApplied"]}
        if action == "RESUME_ADMISSIONS":
            self.s.kv_set("admissions", "OPEN")
            self._emit("MarketControlApplied", {
                "action": action, "reason": args.get("reason")})
            return "ADMISSIONS_OPEN", {"events": ["MarketControlApplied"]}
        if action == "WITNESSED_OUTAGE":
            # declared witness outage: witnessed time stops advancing for
            # the outage's scope; wall clock continues inside it.
            self.s.db.execute(
                "INSERT INTO pauses(scope,object_id,start_ms,end_ms,"
                "reason) VALUES('market','*',?,NULL,?)",
                (self.now_ms, order.get("reason",
                                        args.get("reason", "outage"))))
            self._emit("MarketControlApplied", {"action": action})
            return "OUTAGE_DECLARED", {"events": ["MarketControlApplied"]}
        if action == "END_OUTAGE":
            self.s.db.execute(
                "UPDATE pauses SET end_ms=? WHERE scope='market' AND "
                "end_ms IS NULL", (self.now_ms,))
            self._emit("MarketControlApplied", {"action": action})
            return "OUTAGE_ENDED", {"events": ["MarketControlApplied"]}
        if action == "REVOKE_KEY":
            target = order["actor"]
            epoch = int(order["key_epoch"])
            self.s.db.execute(
                "UPDATE actor_keys SET state='REVOKED', revoked_ms=? "
                "WHERE actor=? AND key_epoch=?",
                (self.now_ms, target, epoch))
            self._emit("MarketControlApplied", {
                "action": action, "actor": target, "key_epoch": epoch})
            return "KEY_REVOKED", {"events": ["MarketControlApplied"]}
        if action == "LEGAL_HOLD":
            # freeze named entitlement accounts (no withdrawals)
            for acct_id in order.get("accounts", []):
                self.s.db.execute(
                    "INSERT OR IGNORE INTO pauses(scope,object_id,"
                    "start_ms,end_ms,reason) VALUES('account',?,?,?,?)",
                    (acct_id, self.now_ms, None,
                     order.get("reason", "legal hold")))
            self._emit("MarketControlApplied", {"action": action})
            return "LEGAL_HOLD", {"events": ["MarketControlApplied"]}
        if action == "ACTIVATE_POLICY":
            eff = int(order["effective_epoch"])
            if eff < self.epoch_of(self.now_ms) + \
                    P["policy_activation_min_epochs"]:
                raise policy("POLICY_ACTIVATION_TOO_SOON",
                             "policy activation requires >=7 days")
            self._emit("MarketControlApplied", {
                "action": action, "effective_epoch": eff,
                "new_policy_hash": order.get("new_policy_hash")})
            return "POLICY_SCHEDULED", {"events": ["MarketControlApplied"]}
        raise malformed("unreachable")

    def _verify_recovery_cert(self, order: dict, cert: dict,
                              action: str) -> None:
        """4-of-7 recovery-authority certificate over the action artifact."""
        from .crypto import ed25519_verify, unb64u
        from .jsonutil import jcs
        if cert.get("domain") != "mint.control.cert.v1":
            raise policy("CERT_DOMAIN", "certificate domain mismatch")
        if cert.get("action") != action:
            raise policy("CERT_ACTION", "certificate does not bind this "
                         "action")
        msg = b"mint.control.cert.v1\x00" + jcs(order)
        keys = {k["key_id"]: k for k in self.trust["recovery_authority"]}
        entities = set()
        for s in cert.get("signatures", []):
            k = keys.get(s.get("key_id"))
            if not k:
                continue
            if ed25519_verify(bytes.fromhex(k["public_key_hex"]),
                              unb64u(s["signature"]), msg):
                entities.add(k["entity"])
        if len(entities) < P["recovery_authority_quorum"]:
            raise policy("CONTROL_QUORUM_INVALID",
                         "control action lacks 4-of-7 distinct recovery "
                         "authority signatures",
                         {"distinct": len(entities)})

    # ------------------------------------------------------------------
    def op_key_rotate(self, actor, args, headers, command_id):
        check_fields(args, {"actor", "new_key_epoch", "new_public_key_hex",
                            "activate_ms", "overlap_seconds",
                            "recovery_order_id", "signature"},
                     {"actor", "new_key_epoch", "new_public_key_hex",
                      "activate_ms"})
        if args["actor"] != actor:
            raise forbidden("key rotation is first-person only")
        if args.get("recovery_order_id"):
            order = self.artifact_json(args["recovery_order_id"])
            cert = self.artifact_json(args["signature"])
            self._verify_recovery_cert(order, cert, "REVOKE_KEY")
        from .jsonutil import check_hex64
        check_hex64(args["new_public_key_hex"], "new_public_key_hex")
        new_epoch = int(args["new_key_epoch"])
        row = self.s.one(
            "SELECT * FROM actor_keys WHERE actor=? AND key_epoch=?",
            (actor, new_epoch))
        if row:
            raise conflict("EPOCH_EXISTS", "key epoch already registered")
        if row is None and new_epoch <= self._max_epoch(actor):
            raise conflict("EPOCH_REGRESSION",
                           "key epoch must increase")
        activate_ms = parse_ts(args["activate_ms"]) if isinstance(
            args["activate_ms"], str) else int(args["activate_ms"])
        recovery = args.get("recovery_order_id") is not None
        if not recovery and activate_ms < self.now_ms + \
                P["key_rotation_delay_seconds"] * 1000:
            raise policy("ROTATION_DELAY",
                         "scheduled rotation requires the 7-day delay; "
                         "recovery rotation needs an authority order")
        self.s.db.execute(
            "INSERT INTO actor_keys(actor,key_epoch,public_key_hex,"
            "state,activates_ms) VALUES(?,?,?,?,?)",
            (actor, new_epoch, args["new_public_key_hex"],
             "ACTIVE" if recovery else "PENDING", activate_ms))
        # scheduled activation: old epoch remains active until activate_ms
        if recovery:
            self.s.db.execute(
                "UPDATE actor_keys SET state='REVOKED' WHERE actor=? AND "
                "key_epoch<?", (actor, new_epoch))
        self._emit("KeyRotated", {
            "actor": actor, "new_key_epoch": new_epoch,
            "activates_ms": activate_ms,
            "recovery": recovery})
        return "ROTATED", {"events": ["KeyRotated"]}

    def _max_epoch(self, actor: str) -> int:
        row = self.s.one(
            "SELECT MAX(key_epoch) AS m FROM actor_keys WHERE actor=?",
            (actor,))
        return int(row["m"] or 0)
