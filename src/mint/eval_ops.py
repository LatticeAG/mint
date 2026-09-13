"""Evaluation mixin: submission freeze, deliverable-key escrow ceremony,
sealed roster draw, seat acceptance, judgment commit/reveal, quorum and
review processing, objective reruns, hidden-test reveals."""

from __future__ import annotations

import secrets

from .crypto import (
    open_chunk, tk_commitment, unwrap_key, wrap_key,
)
from .errors import conflict, forbidden, malformed, not_found, policy
from .jsonutil import (
    check_fields, domain_hash, jcs_text, sha256_hex,
)
from .policy import (
    AUTO_EVIDENCED, POLICY, schedule,
)
from .rubric import evaluate_judgment, objective_counts, quorum_evaluate
from .store import jdump, jload
from .timeutil import fmt_ts
from .trust import beacon_value

P = POLICY


class EvalOps:
    # ------------------------------------------------------------------
    def op_task_submit(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "expected_version", "manifest_id",
                            "execution_receipt_id"},
                     {"task_id", "expected_version", "manifest_id",
                      "execution_receipt_id"})
        task = self._get_task(args["task_id"])
        self._expect_task_version(task, int(args["expected_version"]))
        if task["state"] != "CLAIMED":
            raise conflict("INVALID_TRANSITION", "task not CLAIMED",
                           {"state": task["state"]})
        if task["claim_actor"] != actor:
            raise forbidden("Actor is not the claim owner",
                            {"task_id": task["task_id"]})
        # execution cap check with pauses (half-open)
        paused = self.paused_overlap("task", task["task_id"],
                                     task["claimed_ms"], self.now_ms)
        if self.now_ms - task["claimed_ms"] - paused >= \
                task["execution_cap_seconds"] * 1000:
            raise conflict("DEADLINE_CLOSED",
                           "execution cap already passed")
        manifest = self.artifact_json(args["manifest_id"])
        self.get_artifact(args["execution_receipt_id"])
        # §2.6 manifest requirements
        for f in ("ciphertext_digests", "plaintext_commitment", "salt",
                  "envelope_artifact"):
            if f not in manifest:
                raise malformed(f"submission manifest missing {f}")
        env = self.artifact_json(manifest["envelope_artifact"])
        for f in ("tk_wrap", "tk_commitment"):
            if f not in env:
                raise malformed(f"envelope artifact missing {f}")
        _check_tk_commitment_shape(env["tk_commitment"])
        if task["submission_manifest_id"] is not None:
            raise conflict("SUBMISSION_FROZEN",
                           "a different manifest was already accepted")
        # already-submitted idempotent same-manifest replay is handled by
        # idempotency; a same-content second manifest returns the receipt.
        sub_hash = sha256_hex(
            self.get_artifact(args["manifest_id"])["content"])
        self.s.db.execute(
            "UPDATE tasks SET state='SUBMITTED', "
            "submission_manifest_id=?, submission_hash=?, "
            "submitted_ms=?, envelope_artifact_id=?, "
            "escrow_status='PENDING' WHERE task_id=?",
            (args["manifest_id"], sub_hash, self.now_ms,
             manifest["envelope_artifact"], task["task_id"]))
        self._bump_task_version(task["task_id"])
        # draw anchors to first beacon round strictly after submission
        round_s = P["beacon_round_seconds"]
        draw_round = self.now_ms // (round_s * 1000) + 1
        self.s.db.execute(
            "UPDATE tasks SET draw_beacon_round=? WHERE task_id=?",
            (draw_round, task["task_id"]))
        self.add_deadline("eval_draw", task["task_id"], self.now_ms,
                          P["beacon_round_seconds"] * 2, pausable=True,
                          scope="market")
        e1 = self._emit("WorkSubmitted", {
            "task_id": task["task_id"], "manifest_id": args["manifest_id"],
            "submission_hash": sub_hash,
            "execution_receipt_id": args["execution_receipt_id"],
        }, detail=self._detail(command_id, headers))
        e2 = self._emit("EvaluatorDrawRequested", {
            "task_id": task["task_id"], "beacon_round": draw_round})
        return "SUBMITTED", {"events": [e1["type"], e2["type"]]}

    def op_task_abandon(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "expected_version", "reason",
                            "evidence_id"},
                     {"task_id", "expected_version", "reason"})
        task = self._get_task(args["task_id"])
        self._expect_task_version(task, int(args["expected_version"]))
        if task["state"] != "CLAIMED":
            raise conflict("INVALID_TRANSITION", "task not CLAIMED")
        if task["claim_actor"] != actor:
            raise forbidden("Actor is not the claim owner")
        if args.get("evidence_id"):
            self.get_artifact(args["evidence_id"])
        txn = self.ledger.txn_id(command_id, self._seq())
        self._allege(task["task_id"], actor, task["claim_group"], "worker",
                     "W1", self._res_id(task["task_id"], "Bw"),
                     f"inc-w1-abandon-{task['task_id']}",
                     {"reason": args["reason"],
                      "evidence_id": args.get("evidence_id")}, auto=True)
        self.s.db.execute(
            "UPDATE tasks SET state='EVALUATED', outcome='NO_DELIVERY' "
            "WHERE task_id=?", (task["task_id"],))
        self._bump_task_version(task["task_id"])
        self._mark_deadline_done("exec_cap", task["task_id"])
        self._challenge_window(task)
        e1 = self._emit("WorkAbandoned", {
            "task_id": task["task_id"], "reason": args["reason"],
            "evidence_id": args.get("evidence_id")})
        e2 = self._emit("EvaluationFinalized", {
            "task_id": task["task_id"], "outcome": "NO_DELIVERY",
            "verdict": "NO_DELIVERY"})
        return "EVALUATED", {"events": [e1["type"], e2["type"]]}

    # ------------------------------------------------------------------
    # roster draw + escrow ceremony (driven by eval_draw deadline)
    # ------------------------------------------------------------------
    def _draw_roster(self, task) -> None:
        """Evaluator roster: rank eligible groups, take 5 primaries + 5
        ordered replacements, commit sealed roster (§3.1)."""
        seed = beacon_value(self.trust, task["draw_beacon_round"])
        snap_ms = task["submitted_ms"]
        cands = []
        for a in self.s.all("SELECT * FROM actors WHERE state='ACTIVE'"):
            roles = jload(a["roles"])
            if "evaluator" not in roles:
                continue
            grp = a["principal_group"]
            grow = self.s.one(
                "SELECT created_ms FROM principal_groups WHERE "
                "principal_group=?", (grp,))
            if not grow or grow["created_ms"] > snap_ms - \
                    P["registry_freeze_seconds"] * 1000:
                continue  # snapshot frozen 24h before the draw epoch
            quals = jload(a["qualifications"])
            if task["qualification"] and task["qualification"] not in quals:
                continue
            if grp in (task["poster_group"], task["claim_group"]):
                continue
            conflicts = set(jload(a["conflicts"])) | set(
                jload(a["affiliates"])) | set(jload(a["sponsors"]))
            if {task["poster"], task["claim_actor"],
                task["poster_group"], task["claim_group"]} & (
                    conflicts | {a["actor"], grp}):
                continue
            rank = domain_hash("mint.eval.draw.v1", {
                "seed": seed, "task_id": task["task_id"],
                "round": task["draw_beacon_round"],
                "principal_group": grp})
            cands.append((rank, a))
        cands.sort(key=lambda x: x[0])
        # minimum eligible pool for the profile (spec §3.1)
        pool = self.s.one(
            "SELECT COUNT(DISTINCT principal_group) AS c FROM actors "
            "WHERE state='ACTIVE'")["c"]
        skip_reasons: dict[str, str] = {}
        primaries: list = []
        fam: dict[str, int] = {}
        rest = []
        for rank, a in cands:
            g = a["principal_group"]
            if len(primaries) < P["primary_seats"]:
                mf = a["model_family"] or "unknown"
                if fam.get(mf, 0) >= P["max_same_family_seats"]:
                    skip_reasons[g] = "PROVIDER_FAMILY_CAP"
                    continue
                fam[mf] = fam.get(mf, 0) + 1
                primaries.append((rank, a))
            else:
                rest.append((rank, a))
        replacements = rest[:P["primary_replacements"]]
        if len(primaries) < P["primary_seats"] or \
                self._judging_groups() < P["min_judging_groups"]:
            self._panel_unavailable(task)
            return
        blind = secrets.token_hex(16)
        seat_ids = []
        mapping = {}
        now = self.now_ms
        for i, (rank, a) in enumerate(primaries + replacements):
            from .crypto import seat_id as mk_seat
            sid = mk_seat(task["task_id"], i, blind)
            role = "PRIMARY" if i < P["primary_seats"] else "REPLACEMENT"
            seat_ids.append(sid)
            mapping[sid] = {"principal_group": a["principal_group"],
                            "actor": a["actor"], "index": i, "role": role}
            self.s.db.execute(
                "INSERT INTO seats(seat_id,task_id,stage,"
                "principal_group,actor,idx,role,state,accept_deadline_ms,"
                "assignment_ms) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (sid, task["task_id"], "EVALUATION",
                 a["principal_group"], a["actor"], i, role,
                 "DRAWN" if role == "PRIMARY" else "STANDBY",
                 now + P["seat_acceptance_seconds"] * 1000
                 if role == "PRIMARY" else None, now))
        commitment = domain_hash("mint.eval.roster.v1", {
            "seed": seed, "task_id": task["task_id"],
            "round": task["draw_beacon_round"],
            "ordered_seat_ids": seat_ids,
            "principal_groups": [m["principal_group"]
                                 for m in mapping.values()],
            "skip_reasons": skip_reasons})
        self.s.db.execute(
            "INSERT INTO rosters(commitment,task_id,stage,mapping) "
            "VALUES(?,?,'EVALUATION',?)",
            (commitment, task["task_id"], jdump(mapping)))
        self.s.db.execute(
            "UPDATE tasks SET roster=? WHERE task_id=?",
            (commitment, task["task_id"]))
        self._emit("EvaluatorRosterCommitted", {
            "task_id": task["task_id"], "round": task["draw_beacon_round"],
            "roster_commitment": commitment, "seat_ids": seat_ids,
            "acceptance_close": fmt_ts(
                now + P["seat_acceptance_seconds"] * 1000)})
        self.add_deadline("acceptance_close", task["task_id"], now,
                          P["seat_acceptance_seconds"], pausable=True,
                          scope="market")
        # deliverable-key escrow ceremony (§2.6) — must complete before
        # evidence access opens.
        self._escrow_ceremony(task)

    def _judging_groups(self) -> int:
        row = self.s.one(
            "SELECT COUNT(DISTINCT principal_group) AS c FROM actors "
            "WHERE state='ACTIVE' AND (roles LIKE '%evaluator%' OR "
            "roles LIKE '%judge%')")
        return int(row["c"])

    def _panel_unavailable(self, task) -> None:
        """Insufficient independent seats: explicit unavailable-panel
        result, never a weakened quorum."""
        self.s.db.execute(
            "UPDATE tasks SET state='EVALUATED', outcome='INCONCLUSIVE', "
            "verdict='INCONCLUSIVE', escrow_status='PANEL_UNAVAILABLE' "
            "WHERE task_id=?", (task["task_id"],))
        self._bump_task_version(task["task_id"])
        self._emit("EvaluationFinalized", {
            "task_id": task["task_id"], "outcome": "INCONCLUSIVE",
            "verdict": "INCONCLUSIVE", "reason": "PANEL_UNAVAILABLE"})
        self._challenge_window(task)

    def _escrow_ceremony(self, task) -> None:
        """Panel escrow unwraps TK, verifies plaintext commitment, deposits
        the poster envelope before evidence access may open (§2.6)."""
        manifest = self.artifact_json(task["submission_manifest_id"])
        env = self.artifact_json(manifest["envelope_artifact"])
        failure = None
        tk = None
        escrow_secret = bytes.fromhex(
            self.trust["panel_escrow"]["secret_key_hex"])
        try:
            tk = unwrap_key(env["tk_wrap"], escrow_secret)
            if tk_commitment(tk) != env["tk_commitment"]:
                raise ValueError("tk_commitment mismatch")
            # decrypt each deliverable chunk and verify the salted
            # plaintext commitment over per-chunk digests
            digests = []
            for i, cd in enumerate(manifest["ciphertext_digests"]):
                cid = manifest["ciphertext_artifacts"][i]
                blob = self.get_artifact(cid)["content"]
                if sha256_hex(blob) != cd:
                    raise ValueError("ciphertext digest mismatch")
                pt = open_chunk(tk, blob)
                digests.append(sha256_hex(pt))
            from .crypto import deliverable_commitment
            if deliverable_commitment(manifest["salt"], digests) != \
                    manifest["plaintext_commitment"]:
                raise ValueError("plaintext commitment mismatch")
        except Exception as e:
            failure = str(e)
        if failure or tk is None:
            self._escrow_failure(task, manifest, failure or "unwrap failed")
            return
        # success: retain TK, deposit the poster envelope alongside the
        # retained key (published artifacts are content-addressed and
        # immutable — the deposit is a new escrow record, not an edit)
        poster_key = bytes.fromhex(task["poster_enc_key"])
        poster_env = wrap_key(tk, poster_key)
        att = self._escrow_attestation(task, env["tk_commitment"], True)
        self.s.db.execute(
            "INSERT INTO escrow_keys(task_id,tk_hex,status,"
            "poster_envelope,attestation) VALUES(?,?,'RETAINED',?,?)",
            (task["task_id"], tk.hex(), jcs_text(poster_env), att))
        self.s.db.execute(
            "UPDATE tasks SET escrow_status='DEPOSITED', "
            "access_close_ms=? WHERE task_id=?",
            (self.now_ms + (P["seat_acceptance_seconds"]
                            + P["evidence_access_seconds"]) * 1000,
             task["task_id"]))
        self.add_deadline("access_close", task["task_id"], self.now_ms,
                          P["seat_acceptance_seconds"]
                          + P["evidence_access_seconds"],
                          pausable=True, scope="market")
        self._emit("EscrowEnvelopeDeposited", {
            "task_id": task["task_id"],
            "envelope_artifact": manifest["envelope_artifact"],
            "tk_commitment": env["tk_commitment"],
            "poster_envelope_digest": sha256_hex(jcs_text(
                poster_env).encode())})

    def _escrow_attestation(self, task, commitment: str, ok: bool) -> str:
        from .crypto import ed25519_sign, b64u
        from .jsonutil import jcs
        msg = b"mint.escrow.attest.v1\x00" + jcs({
            "task_id": task["task_id"], "tk_commitment": commitment,
            "ok": ok})
        key = self.trust["panel_escrow"]["attestation_key"]
        return b64u(ed25519_sign(bytes.fromhex(key["secret_hex"]), msg))

    def _escrow_failure(self, task, manifest, reason: str) -> None:
        """Signed decryption-failure receipt: attributable evidence, the
        access clock never started, processed as NO_DELIVERY (W2 path)."""
        env = self.artifact_json(manifest["envelope_artifact"])
        receipt = self._escrow_attestation(task, env["tk_commitment"], False)
        self.s.db.execute(
            "UPDATE tasks SET state='EVALUATED', outcome='NO_DELIVERY', "
            "verdict='NO_DELIVERY', escrow_status='DECRYPTION_FAILED' "
            "WHERE task_id=?", (task["task_id"],))
        self._bump_task_version(task["task_id"])
        self._emit("EscrowDecryptionFailed", {
            "task_id": task["task_id"], "receipt": receipt,
            "tk_commitment": env["tk_commitment"]})
        self._allege(task["task_id"], task["claim_actor"],
                     task["claim_group"], "worker", "W2",
                     self._res_id(task["task_id"], "Bw"),
                     f"inc-w2-envelope-{task['task_id']}",
                     {"receipt": receipt}, auto=True)
        self._emit("EvaluationFinalized", {
            "task_id": task["task_id"], "outcome": "NO_DELIVERY",
            "verdict": "NO_DELIVERY",
            "reason": "ENVELOPE_DECRYPTION_FAILED"})
        self._challenge_window(task)

    # ------------------------------------------------------------------
    def op_seat_accept(self, actor, args, headers, command_id):
        allowed = {"task_id", "seat_id", "stage", "assignment_version",
                   "conflict_attestation_id", "case_id"}
        check_fields(args, allowed, {"seat_id", "stage",
                                     "conflict_attestation_id"})
        seat = self.s.one("SELECT * FROM seats WHERE seat_id=?",
                          (args["seat_id"],))
        if not seat:
            raise not_found("seat not found")
        stage = args["stage"]
        if seat["stage"] != stage:
            raise malformed("stage mismatch")
        if stage == "EVALUATION":
            if args.get("task_id") != seat["task_id"]:
                raise malformed("task_id mismatch")
        else:
            if stage not in ("TRIAL", "APPEAL", "SUPERVISORY"):
                raise malformed("unknown court stage")
            if args.get("case_id") != seat["case_id"]:
                raise malformed("case_id mismatch")
        # sealed: only the drawn principal's actor may accept
        if seat["actor"] != actor:
            raise forbidden("actor is not the drawn seat holder")
        if seat["state"] not in ("DRAWN", "ACTIVATED"):
            raise conflict("INVALID_TRANSITION", "seat not awaiting "
                           "acceptance", {"state": seat["state"]})
        if seat["accept_deadline_ms"] is not None and \
                self.now_ms >= seat["accept_deadline_ms"]:
            raise conflict("DEADLINE_CLOSED", "seat acceptance expired")
        task_id = seat["task_id"]
        task = self._get_task(task_id) if task_id else None
        if stage == "EVALUATION" and task["escrow_status"] != "DEPOSITED":
            raise conflict("ESCROW_PENDING",
                           "evidence access has not opened")
        amt = schedule(task["value"])["Be"] if stage == "EVALUATION" \
            else schedule(task["value"])["Bj"] if task else 0
        txn = self.ledger.txn_id(command_id, self._seq())
        rid = self._new_reservation(
            txn, actor, "Be" if stage == "EVALUATION" else "Bj", amt,
            task_id=task_id, case_id=seat["case_id"])
        self.s.db.execute(
            "UPDATE seats SET state='ACCEPTED', bond_reservation=?, "
            "access_deadline_ms=? WHERE seat_id=?",
            (rid, self.now_ms + P["evidence_access_seconds"] * 1000,
             args["seat_id"]))
        ev = self._emit("SeatAccepted", {
            "seat_id": args["seat_id"], "stage": stage,
            "task_id": task_id, "case_id": seat["case_id"],
        }, detail=self._sealed_detail(command_id, headers, seat))
        return "BONDED", {"events": [ev["type"]]}

    def _sealed_detail(self, command_id, headers, seat) -> dict:
        """Seat-scoped detail artifact: public form carries only the sealed
        seat_id, a salted envelope commitment, and a redacted actor until
        roster reveal (§9.2 deferred-envelope verification)."""
        env_canon = jcs_text({"command_id": command_id,
                              "headers": dict(headers)})
        salt = secrets.token_hex(32)
        commit = sha256_hex(
            b"mint.sealed.detail.v1\x00" + bytes.fromhex(salt)
            + env_canon.encode())
        self.s.db.execute(
            "INSERT INTO artifacts(artifact_id,sha256,media_type,"
            "visibility,content,owner,created_seq) VALUES(?,?,?,?,?,?,?)"
            " ON CONFLICT(artifact_id) DO NOTHING",
            (f"sealed:{command_id}", sha256_hex(env_canon.encode()),
             "application/vnd.mint.sealed-envelope", "private",
             jcs_text({"envelope": {"command_id": command_id,
                                    "headers": dict(headers)},
                       "salt": salt, "seat_id": seat["seat_id"],
                       "actor": seat["actor"],
                       "principal_group": seat["principal_group"]}).encode(),
             None, self._seq()))
        return {"command_id": command_id, "seat_id": seat["seat_id"],
                "actor": "REDACTED", "envelope_commitment": commit,
                "envelope_sha256": sha256_hex(env_canon.encode())}

    # ------------------------------------------------------------------
    def op_evaluation_commit(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "seat_id", "round",
                            "commitment_id"},
                     {"task_id", "seat_id", "round", "commitment_id"})
        task = self._get_task(args["task_id"])
        if task["state"] != "SUBMITTED":
            raise conflict("INVALID_TRANSITION",
                           "task not in evaluation")
        seat = self.s.one("SELECT * FROM seats WHERE seat_id=?",
                          (args["seat_id"],))
        if not seat or seat["task_id"] != task["task_id"]:
            raise not_found("seat not found")
        if seat["actor"] != actor:
            raise forbidden("actor is not the seat holder")
        if seat["state"] != "ACCEPTED":
            raise conflict("INVALID_TRANSITION", "seat not accepted")
        if int(args["round"]) != 1:
            raise malformed("unknown round")
        close = self._seat_commit_close(seat, task)
        if self.now_ms >= close:
            raise conflict("DEADLINE_CLOSED", "commit window closed")
        cmeta = self.artifact_json(args["commitment_id"])
        digest = cmeta.get("commitment")
        if not isinstance(digest, str) or len(digest) != 64:
            raise malformed("commitment artifact must carry digest")
        if seat["committed"]:
            raise conflict("ALREADY_COMMITTED", "seat already committed")
        self.s.db.execute(
            "UPDATE seats SET committed=1, commitment_digest=? WHERE "
            "seat_id=?", (digest, seat["seat_id"]))
        ev = self._emit("EvaluationCommitted", {
            "task_id": task["task_id"], "seat_id": seat["seat_id"],
            "round": 1, "commitment_id": args["commitment_id"]},
            detail=self._sealed_detail(command_id, headers, seat))
        return "COMMITTED", {"events": [ev["type"]]}

    def _seat_commit_close(self, seat, task) -> int:
        if seat["role"] == "PRIMARY":
            # commit clock starts at the fixed access-window close
            return task["access_close_ms"] + \
                P["evaluator_commit_seconds"] * 1000
        # replacement: windows measured from its assignment event
        return seat["assignment_ms"] + (
            P["seat_acceptance_seconds"] + P["evidence_access_seconds"]
            + P["evaluator_commit_seconds"]) * 1000

    def op_evaluation_reveal(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "seat_id", "round", "judgment",
                            "salt"},
                     {"task_id", "seat_id", "round", "judgment", "salt"})
        task = self._get_task(args["task_id"])
        if task["state"] != "SUBMITTED":
            raise conflict("INVALID_TRANSITION", "task not in evaluation")
        seat = self.s.one("SELECT * FROM seats WHERE seat_id=?",
                          (args["seat_id"],))
        if not seat or seat["task_id"] != task["task_id"]:
            raise not_found("seat not found")
        if seat["actor"] != actor:
            raise forbidden("actor is not the seat holder")
        if not seat["committed"]:
            raise conflict("NOT_COMMITTED", "seat has no commitment")
        if seat["revealed"]:
            raise conflict("ALREADY_REVEALED", "seat already revealed")
        close = self._seat_reveal_close(seat, task)
        if self.now_ms >= close:
            raise conflict("DEADLINE_CLOSED", "reveal window closed")
        judgment = args["judgment"]
        salt = args["salt"]
        if not isinstance(salt, str) or len(salt) != 64:
            raise malformed("salt must be 64 lowercase hex characters")
        expect = domain_hash("mint.eval.commit.v1", {
            "network": self.network, "market_id": self.market_id,
            "task_id": task["task_id"], "round": int(args["round"]),
            "seat_id": seat["seat_id"],
            "key_epoch": int(headers["Mint-Key-Epoch"]),
            "judgment": judgment, "salt": salt})
        if expect != seat["commitment_digest"]:
            raise conflict("COMMITMENT_MISMATCH",
                           "reveal does not open the commitment")
        ev_j = evaluate_judgment(judgment, task["acceptance_score"])
        if "score" in judgment and judgment["score"] != ev_j["q"]:
            raise malformed("derived score mismatch")
        if judgment.get("disposition") is not None and \
                judgment["disposition"] != ev_j["disposition"]:
            raise malformed("derived disposition mismatch")
        self.s.db.execute(
            "UPDATE seats SET revealed=1, judgment=?, fee_eligible=1 "
            "WHERE seat_id=?",
            (jdump({"judgment": judgment, "derived": ev_j}),
             seat["seat_id"]))
        ev = self._emit("EvaluationRevealed", {
            "task_id": task["task_id"], "seat_id": seat["seat_id"],
            "round": int(args["round"]),
            "disposition": ev_j["disposition"], "q": ev_j["q"]},
            detail=self._sealed_detail(command_id, headers, seat))
        return "REVEALED", {"events": [ev["type"]]}

    def _seat_reveal_close(self, seat, task) -> int:
        # common reveal window opens after the last commit close
        rows = self.s.all(
            "SELECT * FROM seats WHERE task_id=? AND stage='EVALUATION'",
            (task["task_id"],))
        closes = [self._seat_commit_close(r, task) for r in rows
                  if r["state"] in ("ACCEPTED",)]
        base = max(closes) if closes else task["access_close_ms"]
        return base + P["evaluator_reveal_seconds"] * 1000

    # ------------------------------------------------------------------
    def op_test_reveal(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "expected_version",
                            "test_commitment_id", "test_artifact_id"},
                     {"task_id", "expected_version", "test_commitment_id",
                      "test_artifact_id"})
        task = self._get_task(args["task_id"])
        self._expect_task_version(task, int(args["expected_version"]))
        if task["poster"] != actor:
            raise forbidden("only the poster reveals hidden tests")
        if task["state"] != "SUBMITTED":
            raise conflict("INVALID_TRANSITION",
                           "hidden tests reveal during evaluation only")
        if task["access_close_ms"] is None or \
                self.now_ms >= task["access_close_ms"]:
            raise conflict("DEADLINE_CLOSED",
                           "evidence-access window closed")
        commit = self.artifact_json(args["test_commitment_id"])
        art = self.get_artifact(args["test_artifact_id"])
        if commit.get("sha256") != art["sha256"]:
            raise policy("TEST_COMMITMENT_MISMATCH",
                         "revealed bytes do not match the commitment")
        self._emit("HiddenTestsRevealed", {
            "task_id": task["task_id"],
            "test_commitment_id": args["test_commitment_id"],
            "test_artifact_id": args["test_artifact_id"]},
            detail=self._detail(command_id, headers))
        return "SUBMITTED", {"events": ["HiddenTestsRevealed"]}

    def op_evidence_attach(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "case_id", "artifact_ids", "role"},
                     {"artifact_ids"})
        ids = args["artifact_ids"]
        if not isinstance(ids, list) or len(ids) > \
                P["max_evidence_per_filing"]:
            raise malformed("evidence exceeds the 32-artifact filing cap")
        for aid in ids:
            self.get_artifact(aid)
        if args.get("case_id"):
            case = self.s.one("SELECT * FROM cases WHERE case_id=?",
                              (args["case_id"],))
            if not case:
                raise not_found("case not found")
            self.s.db.execute(
                "UPDATE cases SET evidence_ids=? WHERE case_id=?",
                (jdump(jload(case["evidence_ids"]) + ids),
                 case["case_id"]))
            state = case["state"]
        else:
            task = self._get_task(args["task_id"])
            if task["state"] != "SUBMITTED":
                raise conflict("INVALID_TRANSITION",
                               "task evidence attaches during evaluation")
            state = task["state"]
            # a witnessed poster access failure is a task-level pause
            for aid in ids:
                art = self.get_artifact(aid)
                if art["media_type"] == "application/vnd.mint.outage-proof":
                    pr = self.artifact_json(aid)
                    self._record_task_pause(
                        task["task_id"], pr["start_ms"], pr["end_ms"],
                        aid)
        self._emit("EvidenceAttached", {
            "task_id": args.get("task_id"), "case_id": args.get("case_id"),
            "artifact_ids": ids, "role": args.get("role")},
            detail=self._detail(command_id, headers))
        return state, {"events": ["EvidenceAttached"]}

    def _record_task_pause(self, task_id: str, start_ms: int, end_ms: int,
                           evidence: str) -> None:
        """Evidenced poster-side access failure pauses the task's ordinary
        deadlines (P2 evaluated separately)."""
        if isinstance(start_ms, str):
            from .timeutil import parse_ts
            start_ms = parse_ts(start_ms)
            end_ms = parse_ts(end_ms)
        self.s.db.execute(
            "INSERT INTO pauses(scope,object_id,start_ms,end_ms,reason) "
            "VALUES('task',?,?,?,?)", (task_id, start_ms, end_ms,
                                      evidence))

    # ------------------------------------------------------------------
    # deadline handlers
    # ------------------------------------------------------------------
    def _acceptance_close(self, task) -> None:
        """End of the primary acceptance window: never-accepted seats are
        replaced once (one replacement round)."""
        open_seats = self.s.all(
            "SELECT * FROM seats WHERE task_id=? AND role='PRIMARY' AND "
            "state='DRAWN'", (task["task_id"],))
        if not open_seats:
            return
        if task["replacement_done"]:
            return
        self.s.db.execute(
            "UPDATE tasks SET replacement_done=1 WHERE task_id=?",
            (task["task_id"],))
        # activate replacements in committed order
        for seat in open_seats:
            repl = self.s.one(
                "SELECT * FROM seats WHERE task_id=? AND "
                "role='REPLACEMENT' AND state='STANDBY' ORDER BY idx",
                (task["task_id"],))
            if not repl:
                self.s.db.execute(
                    "UPDATE seats SET state='EXPIRED' WHERE seat_id=?",
                    (seat["seat_id"],))
                continue
            now = self.now_ms
            self.s.db.execute(
                "UPDATE seats SET state='REPLACED' WHERE seat_id=?",
                (seat["seat_id"],))
            self.s.db.execute(
                "UPDATE seats SET state='ACTIVATED', replaced_by=?, "
                "accept_deadline_ms=?, assignment_ms=? WHERE seat_id=?",
                (seat["seat_id"],
                 now + P["seat_acceptance_seconds"] * 1000, now,
                 repl["seat_id"]))
            self._emit("EvaluatorReplaced", {
                "task_id": task["task_id"], "old_seat": seat["seat_id"],
                "new_seat": repl["seat_id"],
                "acceptance_close": fmt_ts(
                    now + P["seat_acceptance_seconds"] * 1000)})
            self.add_deadline("acceptance_close", task["task_id"], now,
                              P["seat_acceptance_seconds"], pausable=True,
                              scope="market")

    def _commit_close(self, task) -> None:
        """Commit window closed for the current seat set: replace
        accepted-but-uncommitted seats once (one replacement round), then
        either reschedule for replacement windows or arm the common
        reveal close. Committed-but-unrevealed seats are not replaced."""
        if task["state"] != "SUBMITTED" or task["escrow_status"] != \
                "DEPOSITED":
            return
        now = self.now_ms
        if not task["replacement_done"]:
            self.s.db.execute(
                "UPDATE tasks SET replacement_done=1 WHERE task_id=?",
                (task["task_id"],))
            silent = self.s.all(
                "SELECT * FROM seats WHERE task_id=? AND "
                "stage='EVALUATION' AND state='ACCEPTED' AND committed=0 "
                "AND role!='AUDITOR'", (task["task_id"],))
            for seat in silent:
                repl = self.s.one(
                    "SELECT * FROM seats WHERE task_id=? AND "
                    "role='REPLACEMENT' AND state IN ('STANDBY','DRAWN') "
                    "ORDER BY idx", (task["task_id"],))
                if not repl:
                    continue
                self.s.db.execute(
                    "UPDATE seats SET state='ACTIVATED', replaced_by=?, "
                    "accept_deadline_ms=?, assignment_ms=? WHERE "
                    "seat_id=?",
                    (seat["seat_id"],
                     now + P["seat_acceptance_seconds"] * 1000, now,
                     repl["seat_id"]))
                self._emit("EvaluatorReplaced", {
                    "task_id": task["task_id"],
                    "old_seat": seat["seat_id"],
                    "new_seat": repl["seat_id"]})
                self.add_deadline(
                    "acceptance_close", task["task_id"], now,
                    P["seat_acceptance_seconds"], pausable=True,
                    scope="market")
        # any seat whose commit close is still in the future reschedules
        future = 0
        for seat in self.s.all(
                "SELECT * FROM seats WHERE task_id=? AND "
                "stage='EVALUATION' AND state IN ('ACCEPTED','ACTIVATED')",
                (task["task_id"],)):
            c = self._seat_commit_close(seat, task)
            if not seat["committed"] and c > now:
                future = max(future, c)
        if future:
            self.add_deadline(
                "eval_commit_close", task["task_id"], now,
                (future - now + 999) // 1000, pausable=True,
                scope="market")
            return
        self.add_deadline(
            "eval_reveal_close", task["task_id"], now,
            P["evaluator_reveal_seconds"], pausable=True, scope="market")

    def _reveal_close(self, task) -> None:
        """Common reveal window closed: reveal roster, finalize the
        provisional outcome under §3.5."""
        if task["state"] != "SUBMITTED":
            return
        # committed-but-unrevealed accepted seats -> E1 allegations
        for seat in self.s.all(
                "SELECT * FROM seats WHERE task_id=? AND "
                "stage='EVALUATION' AND state='ACCEPTED'",
                (task["task_id"],)):
            if not seat["committed"] or not seat["revealed"]:
                self._allege(task["task_id"], seat["actor"],
                             seat["principal_group"], "evaluator", "E1",
                             seat["bond_reservation"],
                             f"inc-e1-{seat['seat_id']}",
                             {"seat_id": seat["seat_id"],
                              "missing": "reveal" if seat["committed"]
                              else "commit"}, auto=True)
        self._reveal_roster(task)
        self._finalize_evaluation(task)

    def _reveal_roster(self, task) -> None:
        roster = self.s.one("SELECT * FROM rosters WHERE task_id=? AND "
                            "stage='EVALUATION'", (task["task_id"],))
        if not roster or roster["revealed"]:
            return
        mapping = jload(roster["mapping"])
        self.s.db.execute(
            "UPDATE rosters SET revealed=1 WHERE commitment=?",
            (roster["commitment"],))
        self.s.db.execute(
            "UPDATE tasks SET roster_revealed=1 WHERE task_id=?",
            (task["task_id"],))
        # publish the deferred envelopes for every sealed seat command
        envelopes = {}
        for sid in mapping:
            for ev in self.s.all(
                    "SELECT detail_artifact_id FROM events WHERE "
                    "json_extract(data,'$.seat_id')=?",
                    (sid,)):
                if ev["detail_artifact_id"]:
                    det = self.artifact_json(ev["detail_artifact_id"])
                    if "envelope_sha256" in det:
                        sealed = self.artifact_json(
                            f"sealed:{det['command_id']}")
                        envelopes[sid] = envelopes.get(sid, []) + [
                            sealed["envelope"]]
        self._emit("EvaluatorRosterRevealed", {
            "task_id": task["task_id"],
            "roster_commitment": roster["commitment"],
            "mapping": mapping, "envelopes": envelopes})

    def _finalize_evaluation(self, task) -> None:
        judgments = []
        for seat in self.s.all(
                "SELECT * FROM seats WHERE task_id=? AND "
                "stage='EVALUATION' AND revealed=1 AND role IN "
                "('PRIMARY','ACTIVATED','REPLACEMENT','AUDITOR')",
                (task["task_id"],)):
            j = jload(seat["judgment"])
            judgments.append({**j["derived"], "raw": j["judgment"],
                              "seat_id": seat["seat_id"]})
        res = quorum_evaluate(judgments, task["acceptance_score"])
        if res["outcome"] == "RERUN_PENDING":
            self._objective_rerun(task, judgments)
            return
        if res["outcome"] in ("REVIEW", "NON_QUORATE_REVIEW"):
            verdict = "REVIEW"
            self.s.db.execute(
                "UPDATE tasks SET state='EVALUATED', outcome='REVIEW', "
                "aggregate_q=? WHERE task_id=?",
                (res["aggregate_q"], task["task_id"]))
            self._bump_task_version(task["task_id"])
            self._emit("EvaluationFinalized", {
                "task_id": task["task_id"], "outcome": "REVIEW",
                "aggregate_q": res["aggregate_q"],
                "spread": res["spread"],
                "review_reasons": res["review_reasons"],
                "rerun_required": res["rerun_required"]})
            self._open_review_case(task, res["review_reasons"])
            return
        outcome = res["outcome"]
        self.s.db.execute(
            "UPDATE tasks SET state='EVALUATED', outcome=?, verdict=?, "
            "aggregate_q=? WHERE task_id=?",
            (outcome, outcome, res["aggregate_q"], task["task_id"]))
        self._bump_task_version(task["task_id"])
        self._emit("EvaluationFinalized", {
            "task_id": task["task_id"], "outcome": outcome,
            "verdict": outcome, "aggregate_q": res["aggregate_q"],
            "spread": res["spread"],
            "dispositions": res["dispositions"]})
        if outcome == "INCONCLUSIVE" and "coverage_quorum" in \
                res["review_reasons"]:
            self._open_review_case(task, ["coverage_quorum"])
        self._challenge_window(task)

    def _objective_rerun(self, task, judgments) -> None:
        """Mandatory independent rerun of disputed objective components
        before any ACCEPT executes (§3.5)."""
        # auditor seat = first unused replacement in committed order
        auditor = self.s.one(
            "SELECT * FROM seats WHERE task_id=? AND role='REPLACEMENT' "
            "AND state IN ('STANDBY','DRAWN') ORDER BY idx",
            (task["task_id"],))
        source = "sequencer_sandbox"
        corrected = self._oracle_observations(task)
        trace_sig = None
        if auditor is not None:
            source = "auditor_seat"
            now = self.now_ms
            self.s.db.execute(
                "UPDATE seats SET role='AUDITOR', state='ACTIVATED', "
                "accept_deadline_ms=?, assignment_ms=? WHERE seat_id=?",
                (now + P["seat_acceptance_seconds"] * 1000, now,
                 auditor["seat_id"]))
            # auditor bond lock + activation; trace delivery modeled as
            # an immediate signed trace in the deterministic simulation
            txn = self.ledger.txn_id("auditor", self._seq())
            rid = self._new_reservation(txn, auditor["actor"], "Be",
                                        schedule(task["value"])["Be"],
                                        task_id=task["task_id"])
            self.s.db.execute(
                "UPDATE seats SET bond_reservation=?, state='ACCEPTED', "
                "fee_eligible=1 WHERE seat_id=?",
                (rid, auditor["seat_id"]))
            trace_sig = self._auditor_trace(task, auditor, corrected)
        # corrected components stand: recompute every judgment's derived
        # Q/disposition from corrected objective counts
        for j in judgments:
            obs = j["raw"].get("observations")
            if obs is None:
                continue
            for k, v in corrected.items():
                obs[k] = v
            ev = evaluate_judgment(j["raw"], task["acceptance_score"])
            self.s.db.execute(
                "UPDATE seats SET judgment=? WHERE seat_id=?",
                (jdump({"judgment": j["raw"], "derived": ev}),
                 j["seat_id"]))
            j["derived"] = ev
            j["q"], j["disposition"] = ev["q"], ev["disposition"]
        self._emit("ObjectiveRerunPublished", {
            "task_id": task["task_id"], "source": source,
            "corrected_observations": corrected, "trace": trace_sig})
        res = quorum_evaluate(judgments, task["acceptance_score"])
        outcome = res["outcome"]
        if outcome in ("REVIEW", "NON_QUORATE_REVIEW", "RERUN_PENDING"):
            outcome = "REVIEW"
            self._open_review_case(
                task, res["review_reasons"] or ["post_rerun_review"])
        self.s.db.execute(
            "UPDATE tasks SET state='EVALUATED', outcome=?, verdict=?, "
            "aggregate_q=? WHERE task_id=?",
            (outcome, outcome, res["aggregate_q"], task["task_id"]))
        self._bump_task_version(task["task_id"])
        self._emit("EvaluationFinalized", {
            "task_id": task["task_id"], "outcome": outcome,
            "verdict": outcome, "aggregate_q": res["aggregate_q"],
            "spread": res["spread"], "rerun": True})
        if outcome != "REVIEW":
            self._challenge_window(task)

    def _oracle_observations(self, task) -> dict:
        rubric = self.artifact_json(task["rubric_id"])
        return rubric["expected_observations"]

    def _auditor_trace(self, task, seat, corrected) -> str:
        """Simulator-signed auditor trace. In simulation the sandbox
        co-signs the trace; a real auditor seat produces its own."""
        from .crypto import ed25519_sign, b64u
        from .jsonutil import jcs
        key = self.trust["panel_escrow"]["attestation_key"]
        msg = b"mint.auditor.trace.v1\x00" + jcs({
            "task_id": task["task_id"], "seat_id": seat["seat_id"],
            "corrected_observations": corrected})
        return b64u(ed25519_sign(bytes.fromhex(key["secret_hex"]), msg))

    def _open_review_case(self, task, reasons) -> str:
        """Automatic disagreement review: task-linked NONE-offense docket
        entry without charging anyone D."""
        case_id = f"case-{task['task_id']}-review"
        if self.s.one("SELECT 1 FROM cases WHERE case_id=?", (case_id,)):
            return case_id
        now = self.now_ms
        self.s.db.execute(
            "INSERT INTO cases(case_id,task_id,state,offense,respondent,"
            "reservation_id,claimant,claimed_loss,evidence_ids,"
            "precedent_ids,automatic,opened_ms,trial_deadline_ms) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, task["task_id"], "ADMITTED", "NONE", "none",
             "none", "system", 0, "[]", "[]", 1, now,
             now + P["trial_decision_seconds"] * 1000))
        self._emit("CaseOpened", {
            "case_id": case_id, "task_id": task["task_id"],
            "offense": "NONE", "automatic": True,
            "reasons": reasons})
        self._draw_court_panel(case_id, "TRIAL", task)
        return case_id

    def _challenge_window(self, task) -> None:
        """Verdict-bearing outcomes get the 48h challenge window;
        CANCELED/UNFUNDED become FinalityReady immediately."""
        outcome = self.s.one("SELECT outcome FROM tasks WHERE task_id=?",
                             (task["task_id"],))["outcome"]
        if outcome in ("CANCELED", "UNFUNDED"):
            self.s.db.execute(
                "UPDATE tasks SET finality_ready=1 WHERE task_id=?",
                (task["task_id"],))
            self._emit("FinalityReady", {"task_id": task["task_id"],
                                         "outcome": outcome})
            return
        close = self.now_ms + P["challenge_seconds"] * 1000
        self.s.db.execute(
            "UPDATE tasks SET challenge_close_ms=? WHERE task_id=?",
            (close, task["task_id"]))
        self.add_deadline("challenge_close", task["task_id"], self.now_ms,
                          P["challenge_seconds"], pausable=True,
                          scope="market")

    # -- allegations --------------------------------------------------------
    def _allege(self, task_id, actor, group, role, offense, reservation_id,
                incident_id, evidence, auto=False, case_id=None) -> str:
        aid = "alg-" + sha256_hex(
            f"{task_id}:{reservation_id}:{incident_id}:{offense}".encode()
        )[:20]
        if self.s.one("SELECT 1 FROM allegations WHERE allegation_id=?",
                      (aid,)):
            return aid
        self.s.db.execute(
            "INSERT INTO allegations(allegation_id,task_id,case_id,"
            "offender,offender_group,role,offense,reservation_id,"
            "incident_id,evidence,auto,state,created_ms) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,'PROPOSED',?)",
            (aid, task_id, case_id, actor, group, role, offense,
             reservation_id, incident_id, jdump(evidence),
             1 if auto else 0, self.now_ms))
        self._emit("OffenseAlleged", {
            "allegation_id": aid, "task_id": task_id, "offense": offense,
            "role": role, "reservation_id": reservation_id,
            "incident_id": incident_id, "automatic": auto})
        return aid

    def _res_id(self, task_id: str, kind: str) -> str | None:
        row = self.s.one(
            "SELECT reservation_id FROM reservations WHERE task_id=? AND "
            "kind=? AND state='ACTIVE'", (task_id, kind))
        return row["reservation_id"] if row else None


def _check_tk_commitment_shape(v):
    if not isinstance(v, str) or len(v) != 64:
        raise malformed("tk_commitment must be 64 hex")
    return v
