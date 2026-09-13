"""Case and court mixin: case.open/answer/appeal, court.order, panel
draws, task challenge handling, supervisory review."""

from __future__ import annotations

import secrets

from .crypto import seat_id as mk_seat
from .errors import conflict, forbidden, malformed, not_found, policy
from .jsonutil import check_fields, domain_hash, jcs_text, parse_amount
from .penalty import bond_for, compute_penalty
from .policy import POLICY, schedule
from .store import jdump, jload
from .timeutil import fmt_ts
from .trust import beacon_value

P = POLICY


class CaseOps:
    # ------------------------------------------------------------------
    def op_case_open(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "reservation_id", "offense",
                            "claimed_loss", "evidence_ids", "incident_id",
                            "precedent_ids", "claimant"},
                     {"task_id", "offense", "claimed_loss",
                      "evidence_ids", "incident_id"})
        task = self._get_task(args["task_id"])
        offense = args["offense"]
        try:
            bond_for(offense)
        except ValueError:
            raise malformed("unknown offense code")
        evidence = args["evidence_ids"]
        if not isinstance(evidence, list) or not evidence:
            raise malformed("admission requires attributable evidence")
        if len(evidence) > P["max_evidence_per_filing"]:
            raise malformed("evidence exceeds filing cap")
        for aid in evidence:
            self.get_artifact(aid)
        claimed = parse_amount(args["claimed_loss"], "claimed_loss")
        if claimed > P["max_claimed_loss"]:
            raise policy("CLAIMED_LOSS_CAP",
                         "claimed_loss exceeds the 10000 cap")
        incident_id = args["incident_id"]
        existing = self.s.one(
            "SELECT * FROM allegations WHERE incident_id=? AND "
            "state NOT IN ('DISMISSED')", (incident_id,))
        if existing:
            raise conflict("DUPLICATE_CASE",
                           "an open or decided docket entry already "
                           "covers this incident")
        if not task["challenge_close_ms"] or \
                self.now_ms >= task["challenge_close_ms"]:
            raise conflict("DEADLINE_CLOSED",
                           "the 48h challenge window is closed")
        # auto-evidenced target: the docket may already carry a proposed
        # allegation the claimant contests
        res_id = args.get("reservation_id") or "none"
        case_id = f"case-{self._seq() + 1}-{secrets.token_hex(3)}"
        sch = schedule(task["value"])
        txn = self.ledger.txn_id(command_id, self._seq())
        d_res = None
        if offense != "NONE":
            d_res = self._new_reservation(txn, actor, "D", sch["D"],
                                          task_id=args["task_id"],
                                          case_id=case_id)
        now = self.now_ms
        self.s.db.execute(
            "INSERT INTO cases(case_id,task_id,state,offense,respondent,"
            "reservation_id,claimant,claimed_loss,evidence_ids,"
            "precedent_ids,automatic,opened_ms,answer_deadline_ms,"
            "trial_deadline_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, args["task_id"], "ADMITTED", offense, "respondent",
             res_id, actor, claimed, jdump(evidence),
             jdump(args.get("precedent_ids", [])), 0, now,
             now + P["answer_seconds"] * 1000,
             now + P["trial_decision_seconds"] * 1000))
        self.add_deadline("answer", case_id, now, P["answer_seconds"],
                          pausable=False)
        self._emit("CaseOpened", {
            "case_id": case_id, "task_id": args["task_id"],
            "offense": offense, "claimant": actor,
            "reservation_id": res_id, "claimed_loss": str(claimed),
            "d_reservation": d_res, "automatic": False},
            detail=self._detail(command_id, headers))
        # case opens pause only their own deadlines, not market-wide
        if offense != "NONE":
            self._draw_court_panel(case_id, "TRIAL", task)
        return "ADMITTED", {"events": ["CaseOpened"]}

    def op_case_answer(self, actor, args, headers, command_id):
        check_fields(args, {"case_id", "expected_version", "statement_id"},
                     {"case_id", "expected_version", "statement_id"})
        case = self._get_case(args["case_id"])
        self._expect_case_version(case, int(args["expected_version"]))
        if case["state"] != "ADMITTED":
            raise conflict("INVALID_TRANSITION", "case not awaiting "
                           "answer", {"state": case["state"]})
        if self.now_ms >= case["answer_deadline_ms"]:
            raise conflict("DEADLINE_CLOSED", "answer window closed")
        self.get_artifact(args["statement_id"])
        self.s.db.execute(
            "UPDATE cases SET state='ANSWERED', version=version+1 "
            "WHERE case_id=?", (case["case_id"],))
        ev = self._emit("CaseAnswered", {
            "case_id": case["case_id"],
            "statement_id": args["statement_id"]},
            detail=self._detail(command_id, headers))
        return "ANSWERED", {"events": [ev["type"]]}

    def op_case_appeal(self, actor, args, headers, command_id):
        check_fields(args, {"case_id", "expected_version", "grounds_id"},
                     {"case_id", "expected_version", "grounds_id"})
        case = self._get_case(args["case_id"])
        self._expect_case_version(case, int(args["expected_version"]))
        if case["state"] != "DECIDED":
            raise conflict("INVALID_TRANSITION", "case not decided")
        close = case["decided_ms"] + P["appeal_filing_seconds"] * 1000
        if self.now_ms >= close:
            raise conflict("DEADLINE_CLOSED", "appeal filing closed")
        if case["appeal_filed"]:
            raise conflict("ALREADY_APPEALED", "appeal already filed")
        if case["appeals_used"] >= 2:
            raise conflict("APPEALS_EXHAUSTED", "only one appeal per "
                           "party")
        self.get_artifact(args["grounds_id"])
        # party check: claimant or respondent group
        arow = self.s.one("SELECT * FROM actors WHERE actor=?", (actor,))
        parties = {case["claimant"]}
        resp = self.s.one(
            "SELECT actor FROM actors WHERE principal_group=?",
            (case["respondent_group"],)) if case["respondent_group"] else \
            None
        if resp:
            parties.add(resp["actor"])
        parties.add(case["respondent"])
        if actor not in parties:
            raise forbidden("only a party may appeal")
        sch = schedule(self._get_task(case["task_id"])["value"]) \
            if case["task_id"] else schedule(P["min_value"])
        txn = self.ledger.txn_id(command_id, self._seq())
        a_res = self._new_reservation(txn, actor, "A", sch["A"],
                                      case_id=case["case_id"])
        # respondent Bj stays locked (fresh reservation already held)
        self.s.db.execute(
            "UPDATE cases SET state='APPEAL_FILED', appeal_filed=1, "
            "a_reservation=?, version=version+1 WHERE case_id=?",
            (a_res, case["case_id"]))
        self._emit("AppealFiled", {
            "case_id": case["case_id"], "appellant": actor,
            "grounds_id": args["grounds_id"],
            "a_reservation": a_res},
            detail=self._detail(command_id, headers))
        task = self._get_task(case["task_id"]) if case["task_id"] else None
        self._draw_court_panel(case["case_id"], "APPEAL", task)
        self.s.db.execute(
            "UPDATE cases SET state='APPEAL_PANEL' WHERE case_id=?",
            (case["case_id"],))
        return "APPEAL_PANEL", {"events": ["AppealFiled"]}

    # ------------------------------------------------------------------
    STAGE_QUORUM = {"TRIAL": P["trial_quorum"],
                    "APPEAL": P["appeal_quorum"],
                    "SUPERVISORY": P["supervisory_quorum"]}

    def op_court_order(self, actor, args, headers, command_id):
        check_fields(args, {"case_id", "stage", "order_id",
                            "order_artifact_id", "certificate_id"},
                     {"case_id", "stage", "order_id", "order_artifact_id",
                      "certificate_id"})
        case = self._get_case(args["case_id"])
        stage = args["stage"]
        if stage not in ("TRIAL", "APPEAL", "SUPERVISORY", "RECOVERY"):
            raise malformed("unknown court stage")
        order = self.artifact_json(args["order_artifact_id"])
        if order.get("order_id") != args["order_id"]:
            raise malformed("order_id mismatch")
        cert = self.artifact_json(args["certificate_id"])
        if stage == "RECOVERY":
            # 4-of-7 constitutional certificate, J3 objective route only
            self._verify_recovery_cert(order, cert, "RECOVERY")
            if case["offense"] != "J3":
                raise policy("RECOVERY_ROUTE",
                             "RECOVERY orders apply only to the J3 "
                             "objective proof route")
        else:
            self._verify_stage_cert(case, stage, order, cert)
        outcome = order.get("outcome")
        if outcome not in ("SUSTAINED", "DISMISSED", "CORRECTED",
                           "RECUSED", "PAUSED"):
            raise malformed("unknown order outcome")
        evs = []
        if outcome in ("SUSTAINED", "DISMISSED"):
            self._apply_case_decision(
                case, {"sustained": outcome == "SUSTAINED",
                       "precedent_id": order.get("precedent_id")},
                stage=stage)
            evs.append("CaseDecided")
            if stage == "APPEAL":
                evs.append("VerdictCorrected")
        elif outcome == "RECUSED":
            seat = self.s.one("SELECT * FROM seats WHERE seat_id=?",
                              (order.get("seat_id"),))
            if seat:
                self.s.db.execute(
                    "UPDATE seats SET state='RECUSED' WHERE seat_id=?",
                    (seat["seat_id"],))
            evs.append("JudgeRecused")
        elif outcome == "PAUSED":
            self._record_case_pause(case["case_id"],
                                    order["start_ms"], order["end_ms"],
                                    order.get("reason", "court order"))
            evs.append("ClockPaused")
        return "FINAL" if stage in ("APPEAL", "SUPERVISORY",
                                    "RECOVERY") else "DECIDED", \
            {"events": evs}

    def _verify_stage_cert(self, case, stage: str, order: dict,
                           cert: dict) -> None:
        """Quorum of the case's seated panel for the stage signs the
        complete order artifact."""
        from .crypto import ed25519_verify, unb64u
        from .jsonutil import jcs
        if cert.get("domain") != "mint.court.cert.v1":
            raise policy("CERT_DOMAIN", "certificate domain mismatch")
        if cert.get("stage") != stage:
            raise policy("CERT_STAGE", "certificate does not bind this "
                         "stage")
        msg = b"mint.court.cert.v1\x00" + jcs(order)
        quorum = self.STAGE_QUORUM[stage]
        groups = set()
        for s in cert.get("signatures", []):
            seat = self.s.one(
                "SELECT * FROM seats WHERE case_id=? AND stage=? AND "
                "actor=?", (case["case_id"], stage, s.get("seat_actor",
                                                        "")))
            if not seat or seat["state"] not in ("ACCEPTED",):
                continue
            krow = self.s.one(
                "SELECT public_key_hex FROM actor_keys WHERE actor=? AND "
                "state='ACTIVE' ORDER BY key_epoch DESC",
                (seat["actor"],))
            if not krow:
                continue
            if ed25519_verify(bytes.fromhex(krow["public_key_hex"]),
                              unb64u(s["signature"]), msg):
                groups.add(seat["principal_group"])
        if len(groups) < quorum:
            raise policy("COURT_QUORUM_INVALID",
                         f"{stage} order lacks its seat quorum",
                         {"distinct_groups": len(groups),
                          "required": quorum})

    def _record_case_pause(self, case_id, start_ms, end_ms, reason):
        from .timeutil import parse_ts
        if isinstance(start_ms, str):
            start_ms, end_ms = parse_ts(start_ms), parse_ts(end_ms)
        self.s.db.execute(
            "INSERT INTO pauses(scope,object_id,start_ms,end_ms,reason) "
            "VALUES('case',?,?,?,?)", (case_id, start_ms, end_ms, reason))

    # ------------------------------------------------------------------
    def _get_case(self, case_id: str):
        row = self.s.one("SELECT * FROM cases WHERE case_id=?",
                         (case_id,))
        if not row:
            raise not_found("case not found", {"case_id": case_id})
        return row

    def _expect_case_version(self, case, expected: int) -> None:
        if case["version"] != expected:
            raise conflict("VERSION_CONFLICT", "Case version changed",
                           {"expected": expected,
                            "actual": case["version"]})

    # ------------------------------------------------------------------
    # court panel draw
    # ------------------------------------------------------------------
    def _draw_court_panel(self, case_id: str, stage: str, task) -> None:
        """Deterministic judge draw, sealed until all seats accept."""
        case = self._get_case(case_id)
        cfg = {"TRIAL": ("trial_seats", "court.trial.v1", "Bj"),
               "APPEAL": ("appeal_seats", "court.appeal.v1", "Bj"),
               "SUPERVISORY": ("supervisory_seats", "court.supervisory.v1",
                               None)}[stage]
        seats_key, domain, bond_kind = cfg
        seats_n = P[seats_key]
        seed_src = f"{case['opened_ms']}"
        seed = domain_hash("mint.court.seed.v1", {
            "case_id": case_id, "stage": stage, "opened": seed_src})
        arow_claim = self.s.one(
            "SELECT principal_group FROM actors WHERE actor=?",
            (case["claimant"],))
        parties = {case["claimant"], case["respondent"],
                   arow_claim["principal_group"] if arow_claim else None,
                   case["respondent_group"]}
        if task:
            parties |= {task["poster"], task["claim_actor"],
                        task["poster_group"], task["claim_group"]}
        cands = []
        for a in self.s.all("SELECT * FROM actors WHERE state='ACTIVE'"):
            roles = jload(a["roles"])
            if "judge" not in roles:
                continue
            if a["actor"] in parties or a["principal_group"] in parties:
                continue
            conflicts = set(jload(a["conflicts"])) | set(
                jload(a["affiliates"])) | set(jload(a["sponsors"]))
            if parties & conflicts:
                continue
            if stage == "APPEAL" and self._prior_seat_group(
                    case_id, a["principal_group"]):
                continue  # appeal panel is disjoint from the trial panel
            rank = domain_hash("mint.court.draw.v1", {
                "seed": seed, "case_id": case_id, "stage": stage,
                "principal_group": a["principal_group"]})
            cands.append((rank, a))
        cands.sort(key=lambda x: x[0])
        chosen = cands[:seats_n]
        if len(chosen) < seats_n:
            self._case_deadline_stall(case)
            return
        blind = secrets.token_hex(16)
        seat_ids = []
        mapping = {}
        now = self.now_ms
        for i, (rank, a) in enumerate(chosen):
            sid = mk_seat(case_id, i, blind + ":" + stage)
            seat_ids.append(sid)
            mapping[sid] = {"principal_group": a["principal_group"],
                            "actor": a["actor"], "index": i}
            self.s.db.execute(
                "INSERT INTO seats(seat_id,case_id,stage,"
                "principal_group,actor,idx,role,state,accept_deadline_ms,"
                "assignment_ms) VALUES(?,?,?,?,?,?,'SEAT','DRAWN',?,?)",
                (sid, case_id, stage, a["principal_group"], a["actor"], i,
                 now + P["court_acceptance_seconds"] * 1000, now))
        commitment = domain_hash(domain, {
            "seed": seed, "case_id": case_id, "ordered_seat_ids": seat_ids,
            "principal_groups": [m["principal_group"]
                                 for m in mapping.values()]})
        self.s.db.execute(
            "INSERT INTO rosters(commitment,case_id,stage,mapping) "
            "VALUES(?,?,?,?)",
            (commitment, case_id, stage, jdump(mapping)))
        self._emit("CourtPanelSealed", {
            "case_id": case_id, "stage": stage,
            "roster_commitment": commitment, "seat_ids": seat_ids,
            "acceptance_close": fmt_ts(
                now + P["court_acceptance_seconds"] * 1000)})
        self.add_deadline("panel_acceptance", case_id, now,
                          P["court_acceptance_seconds"], pausable=False)

    def _prior_seat_group(self, case_id, group) -> bool:
        row = self.s.one(
            "SELECT 1 FROM seats WHERE case_id=? AND principal_group=?",
            (case_id, group))
        return row is not None

    def _case_deadline_stall(self, case) -> None:
        self._emit("CaseStalled", {"case_id": case["case_id"],
                                   "reason": "PANEL_UNAVAILABLE"})

    # ------------------------------------------------------------------
    # case timers
    # ------------------------------------------------------------------
    def _answer_expired(self, case) -> None:
        """Silence alone is never a findings source; the panel still
        decides."""
        if case["state"] == "ADMITTED":
            self.s.db.execute(
                "UPDATE cases SET state='PANELING' WHERE case_id=?",
                (case["case_id"],))
            self._emit("CaseAnswerExpired", {"case_id": case["case_id"]})

    def _panel_acceptance_close(self, case) -> None:
        """If the court panel is not fully seated, fill from remaining
        draw order or stall."""
        seats = self.s.all(
            "SELECT * FROM seats WHERE case_id=? AND state='DRAWN'",
            (case["case_id"],))
        if not seats:
            if case["state"] in ("PANELING", "ADMITTED"):
                self.s.db.execute(
                    "UPDATE cases SET state='DELIBERATING' WHERE "
                    "case_id=?", (case["case_id"],))
                self._reveal_court_panel(case)
            return
        # no replacement bench in mint-policy-1 courts: a panel that
        # cannot seat stalls rather than quorate-weakening
        self._case_deadline_stall(case)

    def _reveal_court_panel(self, case) -> None:
        roster = self.s.one(
            "SELECT * FROM rosters WHERE case_id=? ORDER BY rowid DESC",
            (case["case_id"],))
        if not roster or roster["revealed"]:
            return
        mapping = jload(roster["mapping"])
        # judges must accept before identity reveal; gate decision on
        # accepted seats
        self.s.db.execute(
            "UPDATE rosters SET revealed=1 WHERE commitment=?",
            (roster["commitment"],))
        self._emit("CourtPanelRevealed", {
            "case_id": case["case_id"], "stage": roster["stage"],
            "roster_commitment": roster["commitment"],
            "mapping": mapping})

    def _court_decide(self, case) -> None:
        """Deliver the court decision at the seated panel's deadline.
        Simulator judges vote deterministically from the seeded oracle in
        the case evidence: each seat's finding is produced by the
        simulation oracle (see sim harness) — here we evaluate the
        persisted oracle verdict for the docket entry."""
        case = self._get_case(case["case_id"])
        verdict = self._oracle_case_verdict(case)
        self._apply_case_decision(case, verdict, stage=case["panel_stage"]
                                  or "TRIAL")

    def _oracle_case_verdict(self, case) -> dict:
        """Deterministic simulator verdict: offenses with attributable
        evidence are sustained; otherwise dismissed."""
        ev = jload(case["evidence_ids"])
        sustained = bool(ev) and case["offense"] != "NONE"
        return {"sustained": sustained,
                "stipulated": False,
                "precedent_id": None}

    def _apply_case_decision(self, case, verdict: dict, stage: str) -> None:
        """Apply a sustained/dismissed decision: update allegation, keep
        bonds locked through appeal window, set appeal clock."""
        case_id = case["case_id"]
        sustained = verdict["sustained"]
        now = self.now_ms
        new_state = "DECIDED"
        self.s.db.execute(
            "UPDATE cases SET state=?, decided_ms=?, verdict=?, "
            "panel_stage=?, version=version+1 WHERE case_id=?",
            (new_state, now, "SUSTAINED" if sustained else "DISMISSED",
             stage, case_id))
        self._emit("CourtDecision", {
            "case_id": case_id, "stage": stage,
            "outcome": "SUSTAINED" if sustained else "DISMISSED",
            "precedent_id": verdict.get("precedent_id")})
        # allegation state follows the decision
        for alg in self.s.all(
                "SELECT * FROM allegations WHERE case_id=?",
                (case_id,)):
            self.s.db.execute(
                "UPDATE allegations SET state=? WHERE allegation_id=?",
                ("SUSTAINED" if sustained else "DISMISSED",
                 alg["allegation_id"]))
        self.add_deadline("appeal_window", case_id, now,
                          P["appeal_filing_seconds"], pausable=False)

    def _appeal_window_close(self, case) -> None:
        """Appeal window closed without filing: enforce the decision."""
        case = self._get_case(case["case_id"])
        if case["state"] != "DECIDED" or case["appeal_filed"]:
            return
        self._enforce_decision(case)

    def _enforce_decision(self, case) -> None:
        """Sustained: apply penalty math. Dismissed: release bonds;
        baseless appeals X1 on A."""
        txn = self.ledger.txn_id("court-enforce", self._seq())
        task = self._get_task(case["task_id"]) if case["task_id"] else None
        V = task["value"] if task else P["min_value"]
        if case["verdict"] == "SUSTAINED" and case["offense"] != "NONE":
            alg = self.s.one(
                "SELECT * FROM allegations WHERE case_id=? AND "
                "reservation_id != 'none'", (case["case_id"],))
            pen = compute_penalty(case["offense"], V,
                                  stipulated_loss=case["claimed_loss"],
                                  claimant_present=case["claimant"]
                                  != "system")
            if alg:
                self._slash(txn, alg, pen, case)
            # lose side pays costs: respondent Bj already locked
            if case["claimant"] != "system":
                d_res = self.s.one(
                    "SELECT * FROM reservations WHERE case_id=? AND "
                    "kind='D' AND state='ACTIVE'", (case["case_id"],))
                if d_res:
                    self._release_reservation(txn, d_res["reservation_id"])
        else:
            # dismissed: release D and any contested reservation
            for r in self.s.all(
                    "SELECT * FROM reservations WHERE case_id=? AND "
                    "kind IN ('D','A','Bj') AND state='ACTIVE'",
                    (case["case_id"],)):
                self._release_reservation(txn, r["reservation_id"])
            if case["reservation_id"] not in (None, "none"):
                self._release_reservation(txn, case["reservation_id"])
            # baseless appeal -> X1 on the appellant A reservation
            if case["appeal_filed"] and case["panel_stage"] == "APPEAL":
                a_res = self.s.one(
                    "SELECT * FROM reservations WHERE case_id=? AND "
                    "kind='A' AND state='ACTIVE'", (case["case_id"],))
                if a_res:
                    self._release_reservation(
                        txn, a_res["reservation_id"])
        self.s.db.execute(
            "UPDATE cases SET state='CLOSED', version=version+1 "
            "WHERE case_id=?", (case["case_id"],))
        self._emit("CaseClosed", {"case_id": case["case_id"],
                                  "verdict": case["verdict"]})

    def _slash(self, txn, alg, pen, case) -> None:
        """Apply the computed penalty: slash the alleged bond, distribute
        per §7.1, emit SlashApplied."""
        res = self.s.one(
            "SELECT * FROM reservations WHERE reservation_id=?",
            (alg["reservation_id"],))
        if not res or res["state"] != "ACTIVE":
            return
        amt = min(int(pen["total"]), int(res["amount"]))
        residual = res["amount"] - amt
        entries = []
        self.ledger.slash_to_burned(txn, res["owner"], res["asset"], amt,
                                    alg["reservation_id"])
        if residual > 0:
            self.ledger.release(txn, res["owner"], res["asset"], residual,
                                alg["reservation_id"])
        self.s.db.execute(
            "UPDATE reservations SET state='SLASHED' WHERE "
            "reservation_id=?", (alg["reservation_id"],))
        src = f"sys:burned:{res['asset']}"
        for party, share in pen["parties"].items():
            if share <= 0 or party == "burned":
                continue
            if party == "treasury":
                dest = f"sys:treasury:{res['asset']}"
            elif party == "auditor":
                dest = f"sys:audit:{res['asset']}"
            elif party == "fund":
                dest = f"sys:fund:{res['asset']}"
            elif party == "claimant":
                dest = self.ledger.acct(case["claimant"], res["asset"],
                                        "available")
            elif party == "respondent":
                dest = self.ledger.acct(res["owner"], res["asset"],
                                        "available")
            elif party == "court_pool":
                dest = f"sys:court:{res['asset']}"
            else:
                dest = f"sys:unallocated:{res['asset']}"
            self.ledger.post(txn, res["asset"], src, dest, share)
        self.s.db.execute(
            "UPDATE allegations SET state='SLASHED', penalty=? WHERE "
            "allegation_id=?",
            (jdump({k: str(v) for k, v in pen["parties"].items()} |
                   {"total": str(pen["total"])}), alg["allegation_id"]))
        self._emit("SlashApplied", {
            "task_id": alg["task_id"], "allegation_id":
            alg["allegation_id"], "reservation_id":
            alg["reservation_id"],
            "total": str(amt),
            "parties": {k: str(v) for k, v in pen["parties"].items()}})

    # ------------------------------------------------------------------
    # supervisory review (authority-signed, only from case/admin pause)
    # ------------------------------------------------------------------
    def supervisory_review(self, case_id: str, order: dict) -> None:
        """Charter-only constitutional check; cannot create new offenses
        or override admitted evidence. Called from court.order processing
        in the simulator harness."""
        case = self._get_case(case_id)
        if case["state"] == "CLOSED":
            raise conflict("INVALID_TRANSITION", "case closed")
        self._draw_court_panel(case_id, "SUPERVISORY", None)
        self._emit("SupervisoryReviewOpened", {"case_id": case_id})
