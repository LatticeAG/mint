"""Auction operations mixin: bid.commit, bid.reveal, epoch.clear,
task.claim, offer-ladder expiry, and beacon-abort processing."""

from __future__ import annotations

from .clearing import bid_commitment, clear_task, order_tasks
from .errors import conflict, forbidden, malformed, not_found, policy
from .jsonutil import check_fields, jcs_text, parse_amount, sha256_hex
from .policy import POLICY, schedule
from .store import jdump, jload
from .timeutil import fmt_ts
from .trust import beacon_value

P = POLICY


class AuctionOps:
    # ------------------------------------------------------------------
    def op_bid_commit(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "epoch", "expected_version", "slot",
                            "commitment_id"},
                     {"task_id", "epoch", "expected_version", "slot",
                      "commitment_id"})
        task = self._get_task(args["task_id"])
        if task["state"] != "BONDED":
            raise conflict("INVALID_TRANSITION", "task not in auction",
                           {"state": task["state"]})
        if task["terms_version"] != int(args["expected_version"]):
            raise conflict("VERSION_CONFLICT", "terms version changed",
                           {"expected": int(args["expected_version"]),
                            "actual": task["terms_version"]})
        epoch = int(args["epoch"])
        if epoch != task["auction_epoch"]:
            raise conflict("WRONG_EPOCH",
                           "task is not bidding in that epoch",
                           {"task_epoch": task["auction_epoch"]})
        start = self.epoch_start(epoch)
        if not (start <= self.now_ms < start + P["commit_seconds"] * 1000):
            raise conflict("DEADLINE_CLOSED",
                           "commitment window closed for this epoch")
        arow = self.s.one("SELECT * FROM actors WHERE actor=?", (actor,))
        if not arow or "worker" not in jload(arow["roles"]):
            raise forbidden("actor is not an enrolled worker")
        group = arow["principal_group"]
        if group in (task["poster_group"],):
            raise policy("ROLE_CONFLICT",
                         "poster group cannot bid its own task")
        # commitment artifact holds the 32-byte digest of the §5.2 object
        cmeta = self.artifact_json(args["commitment_id"])
        digest = cmeta.get("commitment")
        if not isinstance(digest, str) or len(digest) != 64:
            raise malformed("commitment artifact must carry 64-hex digest")
        if self.s.one("SELECT 1 FROM bids WHERE task_id=? AND "
                      "principal_group=?", (task["task_id"], group)):
            raise conflict("DUPLICATE_BID",
                           "one immutable commitment per principal per task")
        n = self.s.one(
            "SELECT COUNT(*) AS c FROM bids WHERE principal_group=? AND "
            "epoch=?", (group, epoch))["c"]
        if n >= P["max_commits_per_epoch"]:
            from .errors import rate_limited
            raise rate_limited("Epoch commitment limit reached",
                               P["max_commits_per_epoch"],
                               P["epoch_seconds"])
        sch = schedule(task["value"])
        txn = self.ledger.txn_id(command_id, self._seq())
        bw_res = self._new_reservation(txn, actor, "Bw", sch["Bw"],
                                       task_id=task["task_id"])
        c_res = self._new_reservation(txn, actor, "C", sch["C"],
                                      task_id=task["task_id"])
        first = not self.s.one(
            "SELECT 1 FROM bids WHERE task_id=?", (task["task_id"],))
        self.s.db.execute(
            "INSERT INTO bids(task_id,principal_group,actor,epoch,slot,"
            "commitment_digest,commitment_id,bw_reservation,"
            "c_reservation,committed_ms) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (task["task_id"], group, actor, epoch, args["slot"], digest,
             args["commitment_id"], bw_res, c_res, self.now_ms))
        if first:
            # the first eligible commitment closes cancellation atomically
            self.s.db.execute(
                "UPDATE tasks SET cancellation_open=0 WHERE task_id=?",
                (task["task_id"],))
            self._bump_task_version(task["task_id"])
        ev = self._emit("BidCommitted", {
            "task_id": task["task_id"], "principal_group": group,
            "epoch": epoch, "commitment_id": args["commitment_id"],
            "first": first,
        }, detail=self._detail(command_id, headers))
        return "COMMITTED", {"events": [ev["type"]]}

    def op_bid_reveal(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "epoch", "price", "latency_seconds",
                            "slot", "salt"},
                     {"task_id", "epoch", "price", "latency_seconds",
                      "slot", "salt"})
        task = self._get_task(args["task_id"])
        if task["state"] != "BONDED":
            raise conflict("INVALID_TRANSITION", "task not in auction")
        epoch = int(args["epoch"])
        if epoch != task["auction_epoch"]:
            raise conflict("WRONG_EPOCH", "task is not revealing in that "
                           "epoch")
        start = self.epoch_start(epoch)
        reveal_open = start + P["commit_seconds"] * 1000
        reveal_close = start + P["epoch_seconds"] * 1000
        if not (reveal_open <= self.now_ms < reveal_close):
            raise conflict("DEADLINE_CLOSED",
                           "reveal window closed for this epoch")
        arow = self.s.one("SELECT * FROM actors WHERE actor=?", (actor,))
        if not arow:
            raise unauthorized_(actor)
        group = arow["principal_group"]
        bid = self.s.one("SELECT * FROM bids WHERE task_id=? AND "
                         "principal_group=?",
                         (task["task_id"], group))
        if not bid:
            raise not_found("no commitment for this principal")
        if bid["actor"] != actor:
            raise forbidden("commitment belongs to a different actor")
        if bid["revealed"]:
            raise conflict("ALREADY_REVEALED", "bid already revealed")
        price = parse_amount(args["price"], "price")
        latency = int(args["latency_seconds"])
        salt = args["salt"]
        if not isinstance(salt, str) or len(salt) != 64:
            raise malformed("salt must be 64 lowercase hex characters")
        try:
            bytes.fromhex(salt)
        except ValueError:
            raise malformed("salt must be 64 lowercase hex characters")
        key_epoch = int(headers["Mint-Key-Epoch"])
        expect = bid_commitment(self.network, self.market_id, epoch,
                                task["task_id"], group, key_epoch, price,
                                latency, args["slot"], salt)
        if expect != bid["commitment_digest"]:
            raise conflict("COMMITMENT_MISMATCH",
                           "reveal does not open the commitment")
        self.s.db.execute(
            "UPDATE bids SET revealed=1, price=?, latency=?, salt=? "
            "WHERE task_id=? AND principal_group=?",
            (price, latency, salt, task["task_id"], group))
        ev = self._emit("BidRevealed", {
            "task_id": task["task_id"], "principal_group": group,
            "epoch": epoch, "price": str(price), "latency_seconds": latency,
            "slot": args["slot"],
        }, detail=self._detail(command_id, headers))
        return "REVEALED", {"events": [ev["type"]]}

    # ------------------------------------------------------------------
    def op_epoch_clear(self, actor, args, headers, command_id):
        check_fields(args, {"market_id", "epoch", "closure_checkpoint_id",
                            "beacon_artifact_id", "clearing_artifact_id"},
                     {"market_id", "epoch", "closure_checkpoint_id",
                      "beacon_artifact_id", "clearing_artifact_id"})
        if args["market_id"] != self.market_id:
            raise malformed("unknown market_id")
        epoch = int(args["epoch"])
        cp = self.s.one("SELECT * FROM checkpoints WHERE checkpoint_id=?",
                        (args["closure_checkpoint_id"],))
        if not cp:
            raise not_found("closure checkpoint not found")
        self.verify_checkpoint({**dict(cp),
                                "signatures": jload(cp["signatures"])})
        reveal_close = self.epoch_start(epoch) + P["epoch_seconds"] * 1000
        if self.now_ms < reveal_close:
            raise conflict("DEADLINE_OPEN",
                           "reveal window has not closed")
        # beacon: first pinned round strictly after reveal close
        round_no = reveal_close // (P["beacon_round_seconds"] * 1000) + 1
        if self._beacon_down(round_no):
            raise conflict("BEACON_UNAVAILABLE",
                           "beacon round unavailable; auction aborts at "
                           "the 15-minute limit")
        beacon = self.artifact_json(args["beacon_artifact_id"])
        expected = beacon_value(self.trust, round_no)
        if beacon.get("tag") != "simulation" or \
                beacon.get("round") != round_no or \
                beacon.get("rand") != expected:
            raise policy("BEACON_PROOF_INVALID",
                         "beacon artifact is not the pinned round's value")
        candidate = self.artifact_json(args["clearing_artifact_id"])
        recomputed = self._compute_clearing(epoch, cp["size"], expected,
                                            round_no)
        if jcs_text(candidate.get("clearing")) != \
                jcs_text(recomputed):
            raise policy("CLEARING_MISMATCH",
                         "relayed clearing artifact does not equal the "
                         "reproducible recomputation")
        # apply: emit events, open offer round 1
        events = []
        for t in recomputed["tasks"]:
            task = self._get_task(t["task_id"])
            self.s.db.execute(
                "UPDATE tasks SET auction_state='OFFERING', "
                "consecutive_aborts=0 WHERE task_id=?",
                (task["task_id"],))
            self._mark_deadline_done("beacon_abort", task["task_id"])
            events.append(("ClearingPublished", {
                "task_id": task["task_id"], "epoch": epoch,
                "artifact_id": args["clearing_artifact_id"],
                "seed": expected, "round": round_no,
                "ladder": t["ladder"], "reasons": t["reasons"],
                "excluded": t["excluded"], "scores": t["scores"],
            }))
        self._open_offer_round(recomputed["tasks"], 1, command_id,
                               headers)
        return "OFFERING", {"events": [e[0] for e in events]
                            + ["ClaimOffered"]}

    def _compute_clearing(self, epoch: int, closure_size: int, seed: str,
                          round_no: int) -> dict:
        """Recompute the epoch clearing from the closed input set."""
        tasks = [dict(r) for r in self.s.all(
            "SELECT * FROM tasks WHERE auction_epoch=? AND state='BONDED'"
            " AND auction_state IN ('SCHEDULED','COMMIT','REVEAL',"
            "'WAIT_RANDOMNESS')", (epoch,))]
        # witnessed funding sequence: order by funded event seq via id
        for t in tasks:
            t["funded_seq"] = t["funded_ms"]
        ordered = order_tasks(tasks)
        # q snapshot at the closure checkpoint: history rows recorded by
        # settlements with seq <= closure_size.
        hist: dict[str, list[int]] = {}
        for r in self.s.all(
                "SELECT * FROM history WHERE settled_seq<=? ORDER BY "
                "settled_seq", (closure_size,)):
            hist.setdefault(r["principal_group"], []).append(
                r["observation"])
        from .clearing import quality_forecast
        claims_24h = self._witnessed_claims()
        # slot/claim capacity consumed as we allocate serially
        used_slots: set[tuple[str, str]] = set()
        won_this_epoch: set[str] = set()

        def capacity_ok(group, slot, _used=used_slots, _won=won_this_epoch):
            if (group, slot) in _used:
                return "SLOT_CONSUMED"
            if group in _won:
                return "ONE_WIN_PER_EPOCH"
            if self._active_claims(group) >= \
                    P["max_active_claims_per_principal"]:
                return "NO_CAPACITY"
            return None

        out_tasks = []
        for t in ordered:
            bids = []
            for b in self.s.all(
                    "SELECT * FROM bids WHERE task_id=? AND revealed=1",
                    (t["task_id"],)):
                # only receipts inside the closure checkpoint count
                rev_seq = self._event_seq("BidRevealed", t["task_id"],
                                          b["principal_group"])
                if rev_seq is None or rev_seq > closure_size:
                    continue
                qobs = hist.get(b["principal_group"], [])
                bids.append({
                    "principal_group": b["principal_group"],
                    "actor": b["actor"], "p": b["price"], "l": b["latency"],
                    "q": quality_forecast(qobs), "slot": b["slot"],
                })
            res = clear_task(t["task_id"], t["value"],
                             t["execution_cap_seconds"],
                             t["forecast_floor"], bids, claims_24h,
                             capacity_ok, seed)
            for g in res["ladder"]:
                pass
            if res["winner"]:
                # provisional: reserve winner capacity now
                wgroup = res["winner"]
                wbid = self.s.one(
                    "SELECT * FROM bids WHERE task_id=? AND "
                    "principal_group=?", (t["task_id"], wgroup))
                used_slots.add((wgroup, wbid["slot"]))
                won_this_epoch.add(wgroup)
            for g, reason in res["excluded"].items():
                self.s.db.execute(
                    "UPDATE bids SET state='EXCLUDED', exclusion=? WHERE "
                    "task_id=? AND principal_group=?",
                    (reason, t["task_id"], g))
            for g in res["scores"]:
                self.s.db.execute(
                    "UPDATE bids SET score=? WHERE task_id=? AND "
                    "principal_group=?",
                    (res["scores"][g], t["task_id"], g))
            out_tasks.append({
                "task_id": t["task_id"], "ladder": res["ladder"],
                "excluded": res["excluded"], "scores": res["scores"],
                "reasons": res["reasons"],
            })
        return {"market_id": self.market_id, "epoch": epoch,
                "seed": seed, "round": round_no,
                "closure_size": closure_size, "tasks": out_tasks}

    def _event_seq(self, etype: str, task_id: str, group: str):
        row = self.s.one(
            "SELECT seq FROM events WHERE type=? AND "
            "json_extract(data,'$.task_id')=? AND "
            "json_extract(data,'$.principal_group')=? ORDER BY seq DESC",
            (etype, task_id, group))
        return row["seq"] if row else None

    def _witnessed_claims(self) -> dict[str, int]:
        """TaskClaimed events in the preceding 24h (witnessed), including
        still-claimed tasks (TV-M-75)."""
        since = self.now_ms - P["witnessed_claims_window_seconds"] * 1000
        out: dict[str, int] = {}
        for r in self.s.all(
                "SELECT data FROM events WHERE type='TaskClaimed'"):
            d = jload(r["data"])
            if parse_ms(d["time"]) >= since:
                out[d["principal_group"]] = out.get(
                    d["principal_group"], 0) + 1
        return out

    def _active_claims(self, group: str) -> int:
        row = self.s.one(
            "SELECT COUNT(*) AS c FROM tasks WHERE claim_group=? AND "
            "state='CLAIMED'", (group,))
        return int(row["c"])

    def _open_offer_round(self, cleared_tasks: list[dict], rnd: int,
                          command_id, headers):
        idx = rnd - 1
        for t in cleared_tasks:
            if idx >= len(t["ladder"]):
                continue
            group = t["ladder"][idx]
            bid = self.s.one(
                "SELECT * FROM bids WHERE task_id=? AND principal_group=?",
                (t["task_id"], group))
            if not bid:
                continue
            task = self._get_task(t["task_id"])
            if task["state"] != "BONDED":
                continue
            # re-check eligibility/capacity under frozen seed/history
            if self._active_claims(group) >= \
                    P["max_active_claims_per_principal"]:
                continue
            offer_id = f"offer-{task['task_id']}-{bid['actor']}" \
                if rnd == 1 else \
                f"offer-{task['task_id']}-{bid['actor']}-r{rnd}"
            deadline = self.now_ms + P["claim_offer_seconds"] * 1000
            self.s.db.execute(
                "UPDATE tasks SET offer_round=?, offer_id=?, "
                "offer_group=?, offer_deadline_ms=? WHERE task_id=?",
                (rnd, offer_id, group, deadline, task["task_id"]))
            self.s.db.execute(
                "UPDATE bids SET offer_round=? WHERE task_id=? AND "
                "principal_group=?", (rnd, t["task_id"], group))
            self._bump_task_version(task["task_id"])
            self.add_deadline("offer_expiry", task["task_id"], self.now_ms,
                              P["claim_offer_seconds"], pausable=True,
                              scope="market",
                              payload={"offer_id": offer_id,
                                       "round": rnd})
            self._emit("ClaimOffered", {
                "task_id": task["task_id"], "offer_id": offer_id,
                "principal_group": group, "round": rnd,
                "price": str(bid["price"]),
                "deadline": fmt_ts(deadline),
            }, detail=self._detail(command_id, headers))

    # ------------------------------------------------------------------
    def op_task_claim(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "offer_id", "expected_version"},
                     {"task_id", "offer_id", "expected_version"})
        task = self._get_task(args["task_id"])
        self._expect_task_version(task, int(args["expected_version"]))
        if task["state"] != "BONDED" or task["auction_state"] != "OFFERING":
            raise conflict("INVALID_TRANSITION", "no open offer",
                           {"state": task["state"]})
        if task["offer_id"] != args["offer_id"]:
            raise conflict("OFFER_CONSUMED",
                           "offer token is not the current open offer")
        if self.now_ms >= task["offer_deadline_ms"]:
            raise conflict("DEADLINE_CLOSED", "offer window expired")
        arow = self.s.one("SELECT * FROM actors WHERE actor=?", (actor,))
        if not arow or arow["principal_group"] != task["offer_group"]:
            raise forbidden("Actor is not the offered worker",
                            {"task_id": task["task_id"]})
        if self._active_claims(task["offer_group"]) >= \
                P["max_active_claims_per_principal"]:
            raise policy("NO_CAPACITY", "claim limit reached")
        bid = self.s.one("SELECT * FROM bids WHERE task_id=? AND "
                         "principal_group=?",
                         (task["task_id"], task["offer_group"]))
        txn = self.ledger.txn_id(command_id, self._seq())
        # consume offer once; bind Bw, return winner C
        self._release_reservation(txn, bid["c_reservation"])
        # release losing bids' reservations
        released = []
        for b in self.s.all("SELECT * FROM bids WHERE task_id=? AND "
                            "principal_group != ?",
                            (task["task_id"], task["offer_group"])):
            self._release_reservation(txn, b["bw_reservation"])
            if not self._case_pending_for(b["c_reservation"]):
                self._release_reservation(txn, b["c_reservation"])
            released.append(b["principal_group"])
            self.s.db.execute(
                "UPDATE bids SET state='LOST' WHERE task_id=? AND "
                "principal_group=?", (task["task_id"],
                                      b["principal_group"]))
        self.s.db.execute(
            "UPDATE bids SET state='WON' WHERE task_id=? AND "
            "principal_group=?",
            (task["task_id"], task["offer_group"]))
        self._mark_deadline_done("offer_expiry", task["task_id"])
        self.s.db.execute(
            "UPDATE tasks SET state='CLAIMED', claim_group=?, "
            "claim_actor=?, claimed_ms=?, slot=?, price=?, "
            "promised_latency=?, offer_id=NULL, offer_group=NULL, "
            "offer_deadline_ms=NULL WHERE task_id=?",
            (task["offer_group"], actor, self.now_ms, bid["slot"],
             bid["price"], bid["latency"], task["task_id"]))
        self._bump_task_version(task["task_id"])
        self.add_deadline("exec_cap", task["task_id"], self.now_ms,
                          task["execution_cap_seconds"], pausable=True,
                          scope="task")
        e1 = self._emit("TaskClaimed", {
            "task_id": task["task_id"], "principal_group":
            task["offer_group"], "actor": actor, "price": str(bid["price"]),
            "promised_latency": bid["latency"], "time": self.now_str(),
        }, detail=self._detail(command_id, headers))
        e2 = self._emit("BidReservationsReleased", {
            "task_id": task["task_id"], "released": released,
            "winner_c_returned": True})
        return "CLAIMED", {"events": [e1["type"], e2["type"]]}

    def _case_pending_for(self, reservation_id: str) -> bool:
        """A contested/automatically-evidenced B1 keeps C reserved through
        its docket; the unclaimed Bw returns."""
        row = self.s.one(
            "SELECT 1 FROM allegations WHERE reservation_id=? AND "
            "state IN ('PROPOSED','CONTESTED','AUTHORIZED')",
            (reservation_id,))
        return row is not None

    # ------------------------------------------------------------------
    def _offer_expired(self, task, deadline) -> None:
        """Offered winner missed the claim window: queue B1 on C, release
        Bw, advance to next offer or close."""
        group = task["offer_group"]
        bid = self.s.one("SELECT * FROM bids WHERE task_id=? AND "
                         "principal_group=?",
                         (task["task_id"], group))
        txn = self.ledger.txn_id("timer-offer", self._seq())
        if bid:
            self._release_reservation(txn, bid["bw_reservation"])
            self._allege(task["task_id"], bid["actor"], group, "worker",
                         "B1", bid["c_reservation"],
                         f"inc-b1-noshow-{task['task_id']}-{group}",
                         {"offer_id": task["offer_id"],
                          "deadline": fmt_ts(task["offer_deadline_ms"])},
                         auto=True)
        rnd = task["offer_round"]
        clearing = self._last_clearing(task["task_id"])
        ladder = (clearing or {}).get("ladder", [])
        # find next eligible ladder entry after the expired round
        nxt = None
        nbid = None
        for i in range(rnd, min(len(ladder), P["maximum_offers"])):
            cand = ladder[i]
            cb = self.s.one("SELECT * FROM bids WHERE task_id=? AND "
                            "principal_group=?", (task["task_id"], cand))
            if cb and cb["revealed"] and cb["state"] not in ("LOST",) and \
                    self._active_claims(cand) < \
                    P["max_active_claims_per_principal"]:
                nxt, nbid = cand, cb
                rnd_next = i + 1
                break
        if nxt is None or rnd_next > P["maximum_offers"]:
            self._auction_exhausted(task)
            return
        actor = nbid["actor"]
        offer_id = f"offer-{task['task_id']}-{actor}-r{rnd_next}"
        dl = self.now_ms + P["claim_offer_seconds"] * 1000
        self.s.db.execute(
            "UPDATE tasks SET offer_round=?, offer_id=?, offer_group=?, "
            "offer_deadline_ms=? WHERE task_id=?",
            (rnd_next, offer_id, nxt, dl, task["task_id"]))
        self._bump_task_version(task["task_id"])
        self.add_deadline("offer_expiry", task["task_id"], self.now_ms,
                          P["claim_offer_seconds"], pausable=True,
                          scope="market",
                          payload={"offer_id": offer_id, "round": rnd_next})
        self._emit("ClaimOffered", {
            "task_id": task["task_id"], "offer_id": offer_id,
            "principal_group": nxt, "round": rnd_next,
            "price": str(nbid["price"]), "deadline": fmt_ts(dl)})

    def _last_clearing(self, task_id: str):
        row = self.s.one(
            "SELECT data FROM events WHERE type='ClearingPublished' AND "
            "json_extract(data,'$.task_id')=? ORDER BY seq DESC",
            (task_id,))
        if not row:
            return None
        d = jload(row["data"])
        return d

    def _auction_exhausted(self, task) -> None:
        """No valid fourth bidder: ladder exhaustion settles CANCELED."""
        txn = self.ledger.txn_id("timer-exhaust", self._seq())
        for b in self.s.all("SELECT * FROM bids WHERE task_id=? AND "
                            "state NOT IN ('LOST')", (task["task_id"],)):
            self._release_reservation(txn, b["bw_reservation"])
            if not self._case_pending_for(b["c_reservation"]):
                self._release_reservation(txn, b["c_reservation"])
        self.s.db.execute(
            "UPDATE tasks SET state='EVALUATED', outcome='CANCELED', "
            "auction_state='CLOSED', finality_ready=1 WHERE task_id=?",
            (task["task_id"],))
        self._bump_task_version(task["task_id"])
        self._emit("AuctionClosed", {"task_id": task["task_id"],
                                     "reason": "OFFERS_EXHAUSTED"})
        self._emit("EvaluationFinalized", {
            "task_id": task["task_id"], "outcome": "CANCELED",
            "verdict": "NONE"})

    def _auction_abort(self, task) -> None:
        """Beacon unavailable 15 min after reveal close: abort without B1,
        release that epoch's reservations, re-enter next epoch."""
        txn = self.ledger.txn_id("timer-abort", self._seq())
        for b in self.s.all("SELECT * FROM bids WHERE task_id=?",
                            (task["task_id"],)):
            self._release_reservation(txn, b["bw_reservation"])
            if not self._case_pending_for(b["c_reservation"]):
                self._release_reservation(txn, b["c_reservation"])
            self.s.db.execute(
                "UPDATE bids SET state='RELEASED' WHERE task_id=? AND "
                "principal_group=?",
                (task["task_id"], b["principal_group"]))
        aborts = task["consecutive_aborts"] + 1
        if aborts >= 3:
            self.s.db.execute(
                "UPDATE tasks SET state='EVALUATED', outcome='CANCELED', "
                "auction_state='ABORTED', consecutive_aborts=?, "
                "finality_ready=1 WHERE task_id=?",
                (aborts, task["task_id"]))
            self._bump_task_version(task["task_id"])
            self._emit("AuctionAborted", {
                "task_id": task["task_id"],
                "epoch": task["auction_epoch"], "consecutive": aborts})
            self._emit("AuctionClosed", {"task_id": task["task_id"],
                                         "reason": "BEACON_ABORTS"})
            self._emit("EvaluationFinalized", {
                "task_id": task["task_id"], "outcome": "CANCELED",
                "verdict": "NONE"})
            return
        nxt = task["auction_epoch"] + 1
        self.s.db.execute(
            "UPDATE tasks SET auction_state='SCHEDULED', auction_epoch=?, "
            "consecutive_aborts=? WHERE task_id=?",
            (nxt, aborts, task["task_id"]))
        self._emit("AuctionAborted", {
            "task_id": task["task_id"], "epoch": task["auction_epoch"],
            "consecutive": aborts})
        self._emit("AuctionScheduled", {
            "task_id": task["task_id"], "epoch": nxt,
            "commit_close": fmt_ts(self.epoch_start(nxt)
                                   + P["commit_seconds"] * 1000),
            "reveal_close": fmt_ts(self.epoch_start(nxt)
                                   + P["epoch_seconds"] * 1000)})
        rc = self.epoch_start(nxt) + P["epoch_seconds"] * 1000
        self.add_deadline("beacon_abort", task["task_id"], rc,
                          P["beacon_wait_seconds"], pausable=False)

    def _mark_deadline_done(self, kind: str, object_id: str) -> None:
        self.s.db.execute(
            "UPDATE deadlines SET done=1 WHERE kind=? AND object_id=? "
            "AND done=0", (kind, object_id))


def parse_ms(s: str) -> int:
    from .timeutil import parse_ts
    return parse_ts(s)


def unauthorized_(actor):
    from .errors import unauthorized
    return unauthorized(f"unknown actor {actor}")
