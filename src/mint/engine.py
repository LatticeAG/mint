"""Mint zone core engine — the single-market sequencer reducer.

Processes signed commands inside serializable SQLite transactions, appends
witnessed events, drives every state machine (task, auction, case, payout),
and produces the deterministic artifacts a verifier replays.

Simulation scope: witnesses, beacon, panel escrow, custody, and Charter are
local pinned fixtures; real deployments are stubs (see stubs.py).
"""

from __future__ import annotations

import json
import secrets
from typing import Any, Callable

from .crypto import ed25519_verify, unb64u
from .errors import (
    MintError, conflict, forbidden, malformed, not_found, policy,
    unauthorized, unavailable, insufficient,
)
from .events import ZERO_HASH, event_hash, make_event, merkle_path, merkle_root
from .jsonutil import (
    check_fields, check_hex64, check_id, check_nonce, domain_hash, jcs,
    jcs_text, parse_amount, parse_strict, sha256_hex,
)
from .ledger import Ledger
from .policy import OFFENSES, POLICY, POLICY_HASH, schedule
from .store import Store, jdump, jload
from .timeutil import fmt_ts, parse_ts
from .transport import check_time_bounds, verify_request

COMMAND_METHOD = "POST"
COMMAND_TARGET = "/v1/commands"

OPS = {
    "actor.enroll", "artifact.publish", "account.credit", "task.post",
    "task.fund", "task.cancel", "bid.commit", "bid.reveal", "task.claim",
    "task.submit", "task.abandon", "seat.accept", "evaluation.commit",
    "evaluation.reveal", "case.open", "case.answer", "case.appeal",
    "account.withdraw", "key.rotate", "test.reveal", "evidence.attach",
    "epoch.clear", "clock.advance", "court.order", "settlement.execute",
    "custody.result", "market.control",
}

# Commands that admit new escrow and therefore require a fresh checkpoint.
# Ops that admit new obligations into the market require a fresh witness
# checkpoint (§11.2: no new admissions on a stale quorum). Read routes and
# clock/control ops that only process already-witnessed time are exempt.
ADMISSION_OPS = {
    "account.credit", "account.withdraw", "actor.enroll",
    "artifact.publish", "bid.commit", "bid.reveal", "case.answer",
    "case.appeal", "case.open", "court.order", "custody.result",
    "epoch.clear", "evaluation.commit", "evaluation.reveal",
    "evidence.attach", "key.rotate", "seat.accept",
    "settlement.execute", "task.abandon", "task.cancel", "task.claim",
    "task.fund", "task.post", "task.submit", "test.reveal",
}

# Event types that bump task.version once per accepted transaction.
TASK_VERSION_EVENTS = {
    "TaskPosted", "TaskFunded", "TaskClosedUnfunded", "TaskCancelled",
    "FirstBidCommitted", "ClaimOffered", "TaskClaimed", "WorkSubmitted",
    "WorkAbandoned", "WorkTimedOut", "TaskBlocked", "EvaluationFinalized",
    "VerdictCorrected", "SlashApplied", "TaskSettled",
}


def _gen_command_id(actor: str, nonce: str) -> str:
    return "cmd-" + sha256_hex(f"{actor}:{nonce}".encode())[:24]


class EngineBase:
    def __init__(self, store: Store, config: "Config", trust: dict,
                 beacon_down: Callable[[int], bool] | None = None):
        self.s = store
        self.cfg = config
        # launch gate (TV-M-58): the simulation profile runs only the
        # SIMUSD fixture asset; any live profile requires an explicit
        # Covenant v1 attestation — there is no silent upgrade path.
        if config.mode == "simulation":
            if config.asset != "SIMUSD":
                raise malformed(
                    "simulation mode requires asset SIMUSD; a real asset "
                    "identifier refuses to launch without a real profile")
        elif config.covenant_v1_attestation != "met":
            raise policy("COVENANT_GATE",
                         "non-simulation launch requires a met Covenant v1 "
                         "attestation")
        if "canonical" not in trust:
            from .trust import parse_trust
            trust = parse_trust(trust)
        self.trust = trust
        self.ledger = Ledger(store)
        self._beacon_down = beacon_down or (lambda r: False)
        if self.s.kv_get("genesis_done") != "1":
            self._genesis()

    # ------------------------------------------------------------------
    # basics
    # ------------------------------------------------------------------
    @property
    def network(self) -> str:
        return self.cfg.network

    @property
    def market_id(self) -> str:
        return self.cfg.market_id

    @property
    def asset(self) -> str:
        return self.cfg.asset

    @property
    def now_ms(self) -> int:
        """Witnessed time: only advances via witnessed checkpoints, except
        inside a declared witness outage where the wall clock continues."""
        return int(self.s.kv_get("sim_now", "0"))

    def _set_now(self, ms: int) -> None:
        self.s.kv_set("sim_now", str(ms))

    def now_str(self) -> str:
        return fmt_ts(self.now_ms)

    def epoch_of(self, ms: int) -> int:
        return (ms - self.genesis_ms) // POLICY["epoch_seconds"]

    def epoch_start(self, epoch: int) -> int:
        return self.genesis_ms + epoch * POLICY["epoch_seconds"]

    @property
    def genesis_ms(self) -> int:
        return int(self.s.kv_get("genesis_ms"))

    def _genesis(self) -> None:
        trust_digest = sha256_hex(jcs(self.trust["canonical"]))
        self.s.kv_set("genesis_ms", str(self.trust["genesis_ms"]))
        self.s.kv_set("sim_now", str(self.trust["genesis_ms"]))
        self.s.kv_set("trust_digest", trust_digest)
        self.s.kv_set("admissions", "OPEN")
        with self.s.tx():
            self._emit("MarketOpened", {
                "market_id": self.market_id, "asset": self.asset,
                "policy": self.cfg.policy_id, "trust_digest": trust_digest,
            })
            self.s.kv_set("genesis_done", "1")

    # ------------------------------------------------------------------
    # events, checkpoints, deadlines
    # ------------------------------------------------------------------
    def _emit(self, etype: str, data: dict, detail: dict | None = None) -> dict:
        row = self.s.one("SELECT MAX(seq) AS m FROM events")
        seq = (row["m"] or 0) + 1
        prev = ZERO_HASH
        if seq > 1:
            prev = self.s.one("SELECT hash FROM events WHERE seq=?",
                              (seq - 1,))["hash"]
        ev = make_event(seq, prev, self.now_str(), etype, data)
        detail_id = None
        if detail is not None:
            detail_id = f"det:{seq}"
            self._store_artifact(
                detail_id, "application/vnd.mint.event-detail",
                "restricted", jcs_text(detail).encode(), owner=None,
                check=False)
            if hasattr(self, "_pending_details"):
                self._pending_details.append(detail_id)
        self.s.db.execute(
            "INSERT INTO events(seq,prev,time,type,data,hash,"
            "detail_artifact_id) VALUES(?,?,?,?,?,?,?)",
            (seq, prev, ev["time"], etype, jcs_text(data), ev["hash"],
             detail_id))
        return ev

    def event_hashes(self, upto_seq: int | None = None) -> list[str]:
        q = "SELECT hash FROM events ORDER BY seq"
        rows = self.s.all(q)
        hs = [r["hash"] for r in rows]
        return hs if upto_seq is None else hs[:upto_seq]

    def create_checkpoint(self, at_ms: int | None = None,
                          signed: bool = True) -> dict:
        """Local witness quorum: produce a signed checkpoint. Simulation
        only — the real multi-operator witness network is a stub."""
        at = self.now_ms if at_ms is None else at_ms
        row = self.s.one("SELECT MAX(seq) AS m FROM events")
        size = row["m"] or 0
        head = ZERO_HASH if size == 0 else self.s.one(
            "SELECT hash FROM events WHERE seq=?", (size,))["hash"]
        root = merkle_root(self.event_hashes())
        cps = self.s.all("SELECT checkpoint_id FROM checkpoints")
        cid = f"cp-{size}"
        n = 1
        while any(c["checkpoint_id"] == cid for c in cps):
            n += 1
            cid = f"cp-{size}-{n}"
        body = {
            "checkpoint_id": cid, "market_id": self.market_id,
            "size": size, "chain_head": head, "merkle_root": root,
            "time": fmt_ts(at), "witness_key_epoch": 1,
        }
        from .events import checkpoint_signing_bytes
        msg = checkpoint_signing_bytes(body)
        sigs = []
        if signed:
            for w in self.trust["witnesses"]:
                from .crypto import ed25519_sign, b64u
                sigs.append({"key_id": w["key_id"],
                             "signature": b64u(ed25519_sign(
                                 bytes.fromhex(w["secret"]), msg))})
        self.s.db.execute(
            "INSERT INTO checkpoints(checkpoint_id,market_id,size,"
            "chain_head,merkle_root,time,witness_key_epoch,signatures) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (cid, self.market_id, size, head, root, body["time"], 1,
             jdump(sigs)))
        return {**body, "signatures": sigs}

    def verify_checkpoint(self, cp: dict) -> None:
        if cp["market_id"] != self.market_id:
            raise malformed("checkpoint market mismatch")
        sigs = cp["signatures"]
        if len(sigs) != len({s["key_id"] for s in sigs}):
            raise policy("WITNESS_QUORUM_INVALID",
                         "duplicate witness signatures")
        wkeys = {w["key_id"]: w for w in self.trust["witnesses"]}
        from .events import checkpoint_signing_bytes
        body = {k: cp[k] for k in ("checkpoint_id", "market_id", "size",
                                   "chain_head", "merkle_root", "time",
                                   "witness_key_epoch")}
        msg = checkpoint_signing_bytes(body)
        distinct = set()
        for s in sigs:
            w = wkeys.get(s["key_id"])
            if not w:
                continue
            if ed25519_verify(bytes.fromhex(w["public_key_hex"]),
                              unb64u(s["signature"]), msg):
                distinct.add(w["entity"])
        if len(distinct) < POLICY["witness_quorum"]:
            raise policy("WITNESS_QUORUM_INVALID",
                         "fewer than 4 distinct witness entities signed",
                         {"distinct": len(distinct)})

    def checkpoint_fresh(self) -> bool:
        """Freshness gate for new admissions: a checkpoint no older than
        30s relative to current witnessed time."""
        row = self.s.one(
            "SELECT time FROM checkpoints ORDER BY rowid DESC LIMIT 1")
        if not row:
            return False
        age = self.now_ms - parse_ts(row["time"])
        return age <= POLICY["witness_freshness_seconds"] * 1000

    # -- deadlines ----------------------------------------------------------
    def add_deadline(self, kind: str, object_id: str, anchor_ms: int,
                     nominal_seconds: int, pausable: bool = True,
                     scope: str = "task", payload: dict | None = None) -> str:
        did = "dl-" + sha256_hex(
            f"{kind}:{object_id}:{anchor_ms}:{nominal_seconds}:{len(kind)}"
            .encode())[:20] + "-" + secrets.token_hex(3)
        self.s.db.execute(
            "INSERT INTO deadlines(deadline_id,kind,object_id,anchor_ms,"
            "nominal_seconds,pausable,scope,payload) VALUES(?,?,?,?,?,?,?,?)",
            (did, kind, object_id, anchor_ms, nominal_seconds,
             1 if pausable else 0, scope, jdump(payload or {})))
        return did

    def paused_overlap(self, scope: str, object_id: str,
                       start_ms: int, end_ms: int) -> int:
        """Paused milliseconds inside [start_ms,end_ms] for the given
        scope/object (market-wide pauses always apply)."""
        total = 0
        rows = self.s.all(
            "SELECT start_ms,end_ms FROM pauses WHERE "
            "(scope='market' OR (scope=? AND object_id=?))",
            (scope, object_id))
        for r in rows:
            a = max(start_ms, r["start_ms"])
            b = min(end_ms, r["end_ms"] if r["end_ms"] is not None
                    else self.now_ms)
            if b > a:
                total += b - a
        return total

    def deadline_due(self, d, at_ms: int) -> bool:
        """Half-open rule: an action must be included at t < deadline; at
        equality the timeout wins -> the deadline is due at T >= effective
        fire time."""
        if d["pausable"]:
            paused = self.paused_overlap(d["scope"], d["object_id"],
                                         d["anchor_ms"], at_ms)
            return at_ms - d["anchor_ms"] - paused >= \
                d["nominal_seconds"] * 1000
        return at_ms - d["anchor_ms"] >= d["nominal_seconds"] * 1000

    def effective_deadline(self, d, at_ms: int | None = None) -> int:
        """Wall time at which the deadline fires given pauses so far."""
        at = self.now_ms if at_ms is None else at_ms
        paused = self.paused_overlap(d["scope"], d["object_id"],
                                     d["anchor_ms"], at)
        return d["anchor_ms"] + d["nominal_seconds"] * 1000 + paused

    # ------------------------------------------------------------------
    # storage helpers
    # ------------------------------------------------------------------
    def _store_artifact(self, artifact_id: str, media_type: str,
                        visibility: str, content: bytes,
                        owner: str | None, check: bool = True) -> None:
        digest = sha256_hex(content)
        existing = self.s.one("SELECT artifact_id,sha256 FROM artifacts "
                              "WHERE artifact_id=?", (artifact_id,))
        if existing:
            if existing["sha256"] != digest:
                raise conflict("ARTIFACT_IMMUTABLE",
                               "artifact alias already bound to other bytes")
            return
        self.s.db.execute(
            "INSERT INTO artifacts(artifact_id,sha256,media_type,"
            "visibility,content,owner,created_seq) VALUES(?,?,?,?,?,?,?)",
            (artifact_id, digest, media_type, visibility, content, owner,
             self._seq()))
        return digest

    def get_artifact(self, artifact_id: str):
        row = self.s.one("SELECT * FROM artifacts WHERE artifact_id=?",
                         (artifact_id,))
        if not row:
            raise not_found("artifact not found", {"artifact_id": artifact_id})
        return row

    def artifact_json(self, artifact_id: str) -> Any:
        return parse_strict(self.get_artifact(artifact_id)["content"])

    def _seq(self) -> int:
        return self.s.one("SELECT MAX(seq) AS m FROM events")["m"] or 0

    def _new_reservation(self, txn: str, owner: str, kind: str, amount: int,
                         task_id: str | None = None,
                         case_id: str | None = None,
                         from_available: bool = True,
                         note: str | None = None) -> str:
        rid = "res-" + sha256_hex(
            f"{owner}:{kind}:{task_id}:{case_id}:{self._seq()}:"
            f"{secrets.token_hex(4)}".encode())[:24]
        self.s.db.execute(
            "INSERT INTO reservations(reservation_id,owner,task_id,"
            "case_id,kind,asset,amount,state,created_seq,note) "
            "VALUES(?,?,?,?,?,?,?,'ACTIVE',?,?)",
            (rid, owner, task_id, case_id, kind, self.asset, amount,
             self._seq(), note))
        if from_available:
            self.ledger.reserve(txn, owner, self.asset, amount, rid)
        return rid

    def _release_reservation(self, txn: str, rid: str,
                             to: str | None = None) -> None:
        r = self.s.one("SELECT * FROM reservations WHERE reservation_id=?",
                       (rid,))
        if not r or r["state"] != "ACTIVE":
            return
        owner = to or r["owner"]
        self.ledger.release(txn, owner, r["asset"], r["amount"], rid)
        self.s.db.execute(
            "UPDATE reservations SET state='RELEASED' WHERE reservation_id=?",
            (rid,))

    def _bump_task_version(self, task_id: str, by: int = 1) -> None:
        self.s.db.execute(
            "UPDATE tasks SET version=version+? WHERE task_id=?",
            (by, task_id))

    # ------------------------------------------------------------------
    # transport + dispatch
    # ------------------------------------------------------------------
    def execute(self, headers: dict, body_bytes: bytes,
                local_mode: bool = False) -> tuple[int, dict]:
        """POST /v1/commands entry point. Returns (http_status, body)."""
        try:
            return self._execute(headers, body_bytes)
        except MintError as e:
            return e.http, e.body()

    def _execute(self, headers: dict, body_bytes: bytes) -> tuple[int, dict]:
        body = parse_strict(body_bytes)
        if not isinstance(body, dict):
            raise malformed("command body must be an object")
        check_fields(body, {"op", "args"}, {"op", "args"})
        op = body["op"]
        if op not in OPS:
            raise malformed(f"unknown op: {op}")
        args = body["args"]
        if not isinstance(args, dict):
            raise malformed("args must be an object")

        # ---- transport auth ------------------------------------------------
        actor = headers.get("Mint-Actor", "")
        if not actor:
            raise unauthorized("missing Mint-Actor")
        pub = self._actor_public_key(actor, headers, op, args)
        signed = verify_request(headers, body_bytes, self.network,
                                COMMAND_METHOD, COMMAND_TARGET, pub)
        check_time_bounds(signed, self.now_ms)
        key_epoch = int(headers["Mint-Key-Epoch"])
        nonce = signed["nonce"]
        check_nonce(nonce)
        idem_key = signed["idempotency_key"]
        check_id(idem_key, "idempotency_key")

        body_hash = sha256_hex(body_bytes)
        # nonce permanence within key epoch
        prior = self.s.one(
            "SELECT command_hash FROM nonces WHERE actor=? AND key_epoch=?"
            " AND nonce=?", (actor, key_epoch, nonce))
        if prior and prior["command_hash"] != body_hash:
            raise conflict("NONCE_CONFLICT",
                           "nonce reused with a different payload")
        # idempotent replay: identical key + canonical body -> original receipt
        prior_idem = self.s.one(
            "SELECT body_sha256,response,receipt_seq FROM idempotency "
            "WHERE actor=? AND op=? AND idem_key=?",
            (actor, op, idem_key))
        if prior_idem:
            if prior_idem["body_sha256"] != body_hash:
                raise conflict("IDEMPOTENCY_CONFLICT",
                               "idempotency key reused with different bytes")
            return 200, jload(prior_idem["response"])

        if op in ADMISSION_OPS:
            if self.s.kv_get("admissions") != "OPEN":
                raise unavailable("admissions paused",
                                  {"reason": self.s.kv_get("admissions")})
            if not self.checkpoint_fresh():
                raise MintError(503, "CHECKPOINT_UNAVAILABLE",
                                "No fresh witness quorum", retryable=True,
                                details={"max_age_seconds":
                                         POLICY["max_checkpoint_age_seconds"]})

        command_id = _gen_command_id(actor, nonce)
        with self.s.tx():
            self.s.db.execute(
                "INSERT INTO nonces(actor,key_epoch,nonce,command_hash) "
                "VALUES(?,?,?,?)", (actor, key_epoch, nonce, body_hash))
            self._pending_body = body
            self._pending_details = []
            marker = (self.s.one("SELECT MAX(entry_seq) AS m FROM "
                                 "postings")["m"] or 0)
            handler = getattr(self, f"op_{op.replace('.', '_')}")
            state, response_extra = handler(actor, args, headers,
                                            command_id)
            # bind the command's ledger entries into its detail artifacts
            entries = [dict(r) for r in self.s.all(
                "SELECT * FROM postings WHERE entry_seq>? ORDER BY "
                "entry_seq", (marker,))]
            for det_id in self._pending_details:
                self._attach_entries(det_id, entries)
            receipt_seq = self._seq()
            response = {"command_id": command_id, "state": state,
                        "receipt_seq": receipt_seq}
            response.update(response_extra)
            self.s.db.execute(
                "INSERT INTO commands(command_id,actor,op,body_sha256,"
                "receipt_seq,created_seq) VALUES(?,?,?,?,?,?)",
                (command_id, actor, op, body_hash, receipt_seq,
                 self._seq()))
            self.s.db.execute(
                "INSERT INTO idempotency(actor,op,idem_key,body_sha256,"
                "response,receipt_seq) VALUES(?,?,?,?,?,?)",
                (actor, op, idem_key, body_hash, jdump(response),
                 receipt_seq))
        return 200, response

    def _actor_public_key(self, actor: str, headers: dict, op: str,
                          args: dict) -> bytes:
        """Resolve the verifying key. actor.enroll is the sole op that may
        authenticate with a not-yet-enrolled key (proof of possession)."""
        if op == "actor.enroll" and args.get("actor") == actor:
            try:
                return bytes.fromhex(args["public_key_hex"])
            except (KeyError, ValueError) as e:
                raise malformed("actor.enroll requires public_key_hex") from e
        row = self.s.one("SELECT * FROM actors WHERE actor=?", (actor,))
        if not row:
            raise unauthorized("unknown actor")
        if row["state"] != "ACTIVE":
            raise unauthorized("actor suspended")
        try:
            key_epoch = int(headers["Mint-Key-Epoch"])
        except (KeyError, ValueError):
            raise malformed("invalid Mint-Key-Epoch")
        krow = self.s.one(
            "SELECT * FROM actor_keys WHERE actor=? AND key_epoch=?",
            (actor, key_epoch))
        if not krow or krow["state"] != "ACTIVE":
            raise unauthorized("key epoch not active")
        if krow["activates_ms"] and self.now_ms < krow["activates_ms"]:
            raise unauthorized("key epoch not yet active")
        return bytes.fromhex(krow["public_key_hex"])

    # -- version guards -------------------------------------------------------
    def _expect_task_version(self, task, expected: int) -> None:
        if task["version"] != expected:
            raise conflict("VERSION_CONFLICT", "Task version changed",
                           {"expected": expected, "actual": task["version"]})

    def _get_task(self, task_id: str):
        row = self.s.one("SELECT * FROM tasks WHERE task_id=?", (task_id,))
        if not row:
            raise not_found("task not found", {"task_id": task_id})
        return row

    # ======================================================================
    # Actor ops (engine.py-local): enroll, artifact, credit
    # ======================================================================
    def op_actor_enroll(self, actor, args, headers, command_id):
        check_fields(args,
                     {"actor", "principal_group", "roles", "key_epoch",
                      "public_key_hex", "encryption_key_hex",
                      "identity_attestation", "registrar_certificate",
                      "qualifications", "model_family", "regions",
                      "conflicts", "affiliates", "sponsors"},
                     {"actor", "principal_group", "roles", "key_epoch",
                      "public_key_hex", "identity_attestation",
                      "registrar_certificate"})
        check_id(args["actor"], "actor")
        check_id(args["principal_group"], "principal_group")
        check_hex64(args["public_key_hex"], "public_key_hex")
        if args.get("encryption_key_hex") is not None:
            check_hex64(args["encryption_key_hex"], "encryption_key_hex")
        roles = args["roles"]
        if not isinstance(roles, list) or not all(isinstance(r, str)
                                                  for r in roles):
            raise malformed("roles must be a list of strings")
        allowed_roles = {"poster", "worker", "evaluator", "judge",
                         "auditor", "relay", "operator"}
        if not set(roles) <= allowed_roles:
            raise malformed("unknown role", {"roles": roles})
        if "poster" in roles and not args.get("encryption_key_hex"):
            raise policy("ENCRYPTION_KEY_REQUIRED",
                         "poster enrollment requires encryption_key_hex")
        if self.s.one("SELECT actor FROM actors WHERE actor=?",
                      (args["actor"],)):
            raise conflict("ACTOR_EXISTS", "actor already enrolled")
        # registrar certificate: artifact signed by pinned registrar key over
        # the enrollment fields.
        cert = self._load_certificate(args["registrar_certificate"],
                                      "mint.enroll.v1")
        subject = {k: v for k, v in args.items()
                   if k != "registrar_certificate"}
        self._verify_certificate(cert, "registrar", subject)
        txn = self.ledger.txn_id(command_id, self._seq())
        self.s.db.execute(
            "INSERT INTO actors(actor,principal_group,roles,"
            "encryption_key_hex,attestation,qualifications,model_family,"
            "regions,conflicts,affiliates,sponsors,enrolled_ms) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (args["actor"], args["principal_group"], jdump(sorted(roles)),
             args.get("encryption_key_hex"), args["identity_attestation"],
             jdump(args.get("qualifications", [])),
             args.get("model_family"), jdump(args.get("regions", [])),
             jdump(args.get("conflicts", [])),
             jdump(args.get("affiliates", [])),
             jdump(args.get("sponsors", [])), self.now_ms))
        self.s.db.execute(
            "INSERT INTO actor_keys(actor,key_epoch,public_key_hex,state)"
            " VALUES(?,?,?,'ACTIVE')",
            (args["actor"], int(args["key_epoch"]), args["public_key_hex"]))
        self.s.db.execute(
            "INSERT OR IGNORE INTO principal_groups(principal_group,"
            "created_ms) VALUES(?,?)",
            (args["principal_group"], self.now_ms))
        self.s.db.execute(
            "INSERT OR IGNORE INTO accounts(actor,asset) VALUES(?,?)",
            (args["actor"], self.asset))
        ev = self._emit("ActorEnrolled", {
            "actor": args["actor"],
            "principal_group": args["principal_group"],
            "roles": sorted(roles), "key_epoch": int(args["key_epoch"]),
            "public_key_hex": args["public_key_hex"],
        }, detail=self._detail(command_id, headers))
        return "ENROLLED", {"events": [ev["type"]]}

    def op_artifact_publish(self, actor, args, headers, command_id):
        check_fields(args, {"artifact_id", "media_type", "visibility",
                            "content_base64", "sha256"},
                     {"artifact_id", "media_type", "visibility",
                      "content_base64", "sha256"})
        check_id(args["artifact_id"], "artifact_id")
        check_hex64(args["sha256"], "sha256")
        if args["visibility"] not in ("public", "restricted", "private"):
            raise malformed("unknown visibility")
        import base64
        try:
            content = base64.b64decode(args["content_base64"], validate=True)
        except Exception as e:
            raise malformed("content_base64 invalid") from e
        if len(content) > POLICY["max_artifact_chunk_bytes"]:
            raise malformed("artifact chunk exceeds 1 MiB")
        if sha256_hex(content) != args["sha256"]:
            raise malformed("sha256 does not match content")
        self._store_artifact(args["artifact_id"], args["media_type"],
                             args["visibility"], content, actor)
        ev = self._emit("ArtifactPublished", {
            "artifact_id": args["artifact_id"], "sha256": args["sha256"],
            "media_type": args["media_type"],
            "visibility": args["visibility"],
        }, detail=self._detail(command_id, headers))
        return "AVAILABLE", {"events": [ev["type"]]}

    def op_account_credit(self, actor, args, headers, command_id):
        check_fields(args, {"account", "asset", "amount", "external_ref",
                            "custody_certificate"},
                     {"account", "asset", "amount", "external_ref",
                      "custody_certificate"})
        check_id(args["account"], "account")
        if args["asset"] != self.asset:
            raise policy("ASSET_MISMATCH", "unknown asset")
        amount = parse_amount(args["amount"])
        cert = self._load_certificate(args["custody_certificate"],
                                      "mint.credit.v1")
        subject = {k: v for k, v in args.items()
                   if k != "custody_certificate"}
        self._verify_certificate(cert, "custody_issuer", subject)
        if not self.s.one("SELECT actor FROM actors WHERE actor=?",
                          (args["account"],)):
            raise not_found("account not found")
        txn = self.ledger.txn_id(command_id, self._seq())
        self.ledger.credit_deposit(txn, args["account"], self.asset, amount)
        ev = self._emit("AccountCredited", {
            "actor": args["account"], "amount": str(amount),
            "external_ref": args["external_ref"],
        }, detail=self._detail(command_id, headers))
        return "CREDITED", {"events": [ev["type"]]}

    # -- certificates ---------------------------------------------------------
    def _load_certificate(self, cert_ref, domain: str) -> dict:
        """A certificate may be an artifact id or an inline certificate
        object (enrollment bootstrap predates the artifact store)."""
        if isinstance(cert_ref, dict):
            cert = cert_ref
        else:
            row = self.s.one(
                "SELECT * FROM artifacts WHERE artifact_id=?",
                (cert_ref,))
            if not row:
                raise not_found("certificate not found",
                                {"certificate_id": cert_ref})
            cert = parse_strict(row["content"])
        if cert.get("domain") != domain:
            raise policy("CERT_DOMAIN", "certificate domain mismatch")
        return cert

    def _verify_certificate(self, cert: dict, signer_role: str,
                            subject_args: dict) -> None:
        """Verify a single-signer certificate issued by a trust-pinned role
        key (registrar, custody issuer)."""
        keys = {k["key_id"]: k for k in self.trust["authority_keys"]
                if k["role"] == signer_role}
        signer = keys.get(cert.get("signer"))
        if not signer:
            raise unauthorized("certificate signer is not the pinned role")
        msg = cert["domain"].encode() + b"\x00" + jcs(subject_args)
        if not ed25519_verify(bytes.fromhex(signer["public_key_hex"]),
                              unb64u(cert["signature"]), msg):
            raise unauthorized("certificate signature invalid")

    def _attach_entries(self, detail_id: str, entries: list) -> None:
        row = self.s.one("SELECT content FROM artifacts WHERE "
                         "artifact_id=?", (detail_id,))
        if not row:
            return
        det = parse_strict(row["content"])
        det["ledger_entries"] = [
            {"entry_id": e["entry_seq"], "transaction_id":
             e["transaction_id"], "asset": e["asset"],
             "debit_account": e["debit_account"],
             "credit_account": e["credit_account"],
             "amount": str(e["amount"]),
             "reservation_id": e["reservation_id"]}
            for e in entries]
        self.s.db.execute(
            "UPDATE artifacts SET content=?, sha256=? WHERE "
            "artifact_id=?",
            (jcs_text(det).encode(), sha256_hex(jcs_text(det).encode()),
             detail_id))

    def _detail(self, command_id: str, headers: dict,
                extra: dict | None = None) -> dict:
        d = {"command_id": command_id,
             "envelope": {"headers": dict(headers),
                          "body": getattr(self, "_pending_body", None)},
             "versions": {}, "ledger_entries": [], "result": {}}
        if extra:
            d.update(extra)
        return d

    # ==================================================================
    # task.post / task.fund / task.cancel
    # ==================================================================
    def op_task_post(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "market_id", "asset", "value",
                            "execution_cap_seconds", "forecast_floor",
                            "acceptance_score", "manifest_id", "rubric_id",
                            "charter_bundle_id", "policy_id",
                            "qualification"},
                     {"task_id", "market_id", "asset", "value",
                      "execution_cap_seconds", "forecast_floor",
                      "acceptance_score", "manifest_id", "rubric_id",
                      "charter_bundle_id", "policy_id"})
        check_id(args["task_id"], "task_id")
        if args["market_id"] != self.market_id:
            raise malformed("unknown market_id")
        if args["asset"] != self.asset:
            raise policy("ASSET_MISMATCH", "unknown asset")
        V = parse_amount(args["value"], "value")
        if not (POLICY["min_value"] <= V <= POLICY["max_value"]):
            raise policy("VALUE_BOUNDS", "task value outside 1000..100000")
        dmax = int(args["execution_cap_seconds"])
        if not (POLICY["dmax_min_seconds"] <= dmax
                <= POLICY["dmax_max_seconds"]):
            raise policy("DMAX_BOUNDS", "execution cap outside bounds")
        acc = int(args["acceptance_score"])
        if acc > POLICY["max_acceptance_score"]:
            raise policy("ACCEPTANCE_CAP",
                         "acceptance_score above 9500 must be expressed "
                         "as published objective gates",
                         {"acceptance_score": acc,
                          "max": POLICY["max_acceptance_score"]})
        floor_q = int(args["forecast_floor"])
        if args["policy_id"] != self.cfg.policy_id:
            raise policy("POLICY_MISMATCH", "unknown policy")
        arow = self.s.one("SELECT * FROM actors WHERE actor=?", (actor,))
        if not arow or "poster" not in jload(arow["roles"]):
            raise forbidden("actor is not an enrolled poster")
        if not arow["encryption_key_hex"]:
            raise policy("ENCRYPTION_KEY_REQUIRED",
                         "poster must enroll encryption_key_hex before "
                         "task.post")
        # referenced artifacts must exist (manifest, rubric, charter bundle)
        manifest = self.artifact_json(args["manifest_id"])
        rubric = self.artifact_json(args["rubric_id"])
        charter = self.artifact_json(args["charter_bundle_id"])
        for f in ("constitution_hash", "precedent_root",
                  "offense_schedule_hash", "policy_hash"):
            check_hex64(charter[f], f"charter.{f}")
        rubric_hash = sha256_hex(self.get_artifact(args["rubric_id"])
                                 ["content"])
        if self.s.one("SELECT task_id FROM tasks WHERE task_id=?",
                      (args["task_id"],)):
            raise conflict("TASK_EXISTS", "task id already allocated")
        self.s.db.execute(
            "INSERT INTO tasks(task_id,state,poster,poster_group,"
            "poster_enc_key,market_id,asset,value,execution_cap_seconds,"
            "forecast_floor,acceptance_score,manifest_id,rubric_id,"
            "charter_bundle_id,policy_id,qualification,constitution_hash,"
            "precedent_root,rubric_hash,offense_schedule_hash,policy_hash,"
            "posted_ms,funding_deadline_ms) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (args["task_id"], "POSTED", actor, arow["principal_group"],
             arow["encryption_key_hex"], args["market_id"], self.asset, V,
             dmax, floor_q, acc, args["manifest_id"], args["rubric_id"],
             args["charter_bundle_id"], args["policy_id"],
             args.get("qualification"), charter["constitution_hash"],
             charter["precedent_root"], rubric_hash,
             charter["offense_schedule_hash"], charter["policy_hash"],
             self.now_ms, self.now_ms
             + POLICY["posting_funding_seconds"] * 1000))
        self.add_deadline("funding_expiry", args["task_id"], self.now_ms,
                          POLICY["posting_funding_seconds"], pausable=False)
        ev = self._emit("TaskPosted", {
            "task_id": args["task_id"], "poster": actor,
            "value": str(V), "acceptance_score": acc,
            "execution_cap_seconds": dmax,
            "constitution_hash": charter["constitution_hash"],
            "precedent_root": charter["precedent_root"],
            "rubric_hash": rubric_hash,
            "offense_schedule_hash": charter["offense_schedule_hash"],
            "policy_hash": charter["policy_hash"],
        }, detail=self._detail(command_id, headers))
        return "POSTED", {"events": [ev["type"]]}

    def op_task_fund(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "expected_version"},
                     {"task_id", "expected_version"})
        task = self._get_task(args["task_id"])
        if task["poster"] != actor:
            raise forbidden("only the poster funds the task",
                            {"task_id": task["task_id"]})
        self._expect_task_version(task, int(args["expected_version"]))
        if task["state"] != "POSTED":
            raise conflict("INVALID_TRANSITION",
                           "task is not POSTED", {"state": task["state"]})
        if self.now_ms >= task["funding_deadline_ms"]:
            raise conflict("DEADLINE_CLOSED", "funding window expired")
        sch = schedule(task["value"])
        need = sch["poster_reserve"]
        avail = self.ledger.available(actor, self.asset)
        if avail < need:
            raise MintError(422, "INSUFFICIENT_FUNDS",
                            f"Poster requires {need} SIMUSD", False,
                            {"required": str(need), "available": str(avail)})
        # operator reserve earmark Rt from operator-funded pool
        reserve_free = self.ledger.balance(f"op:reserve:{self.asset}") \
            - self._reserve_earmarked()
        if reserve_free < sch["Rt"]:
            raise policy("RESERVE_EXHAUSTED",
                         "operator reserve cannot cover Rt earmark",
                         {"required": str(sch["Rt"]),
                          "reserve_free": str(reserve_free)})
        txn = self.ledger.txn_id(command_id, self._seq())
        res_ids = {}
        for kind, amt in (("V", sch["V"]), ("Bp", sch["Bp"]),
                          ("E", sch["E"]), ("F", sch["F"])):
            res_ids[kind] = self._new_reservation(
                txn, actor, kind, amt, task_id=task["task_id"])
        rt = "res-rt-" + task["task_id"]
        self.s.db.execute(
            "INSERT INTO reservations(reservation_id,owner,task_id,kind,"
            "asset,amount,state,created_seq,note) "
            "VALUES(?,?,?,?,?,?,'ACTIVE',?,?)",
            (rt, "operator-reserve", task["task_id"], "Rt", self.asset,
             sch["Rt"], self._seq(), "operator reserve earmark"))
        eligible = self.epoch_of(self.now_ms) + 1
        self.s.db.execute(
            "UPDATE tasks SET state='BONDED', funded_ms=?, "
            "eligible_epoch=?, auction_state='SCHEDULED', "
            "auction_epoch=?, terms_version=version WHERE task_id=?",
            (self.now_ms, eligible, eligible, task["task_id"]))
        self._bump_task_version(task["task_id"])
        ev1 = self._emit("TaskFunded", {
            "task_id": task["task_id"], "reserved": str(need),
            "reservations": res_ids, "rt_earmark": rt,
        }, detail=self._detail(command_id, headers))
        ev2 = self._emit("AuctionScheduled", {
            "task_id": task["task_id"], "epoch": eligible,
            "commit_close": fmt_ts(
                self.epoch_start(eligible) + POLICY["commit_seconds"] * 1000),
            "reveal_close": fmt_ts(
                self.epoch_start(eligible) + POLICY["epoch_seconds"] * 1000),
        })
        reveal_close = self.epoch_start(eligible) \
            + POLICY["epoch_seconds"] * 1000
        self.add_deadline("beacon_abort", task["task_id"], reveal_close,
                          POLICY["beacon_wait_seconds"], pausable=False)
        self.add_deadline(
            "longstop", task["task_id"], self.now_ms,
            POLICY["absolute_task_days"] * 86400, pausable=False)
        return "BONDED", {"events": [ev1["type"], ev2["type"]]}

    def op_task_cancel(self, actor, args, headers, command_id):
        check_fields(args, {"task_id", "expected_version", "reason"},
                     {"task_id", "expected_version"})
        task = self._get_task(args["task_id"])
        if task["poster"] != actor:
            raise forbidden("only the poster cancels",
                            {"task_id": task["task_id"]})
        self._expect_task_version(task, int(args["expected_version"]))
        if task["state"] == "POSTED":
            self.s.db.execute(
                "UPDATE tasks SET state='SETTLED', outcome='CANCELED', "
                "settled_ms=? WHERE task_id=?",
                (self.now_ms, task["task_id"]))
            self._bump_task_version(task["task_id"])
            e1 = self._emit("TaskClosedUnfunded", {
                "task_id": task["task_id"], "reason": "CANCELED"})
            e2 = self._emit("TaskSettled", {
                "task_id": task["task_id"], "outcome": "CANCELED",
                "outstanding_reservations": "0"})
            return "SETTLED", {"events": [e1["type"], e2["type"]]}
        if task["state"] == "BONDED" and task["cancellation_open"]:
            self._cancel_bonded(task, command_id, headers)
            return "EVALUATED", {"events": ["AuctionClosed",
                                           "EvaluationFinalized"]}
        raise conflict("INVALID_TRANSITION",
                       "unilateral cancellation closed after first "
                       "eligible commitment", {"task_id": task["task_id"]})

    def _cancel_bonded(self, task, command_id, headers):
        self.s.db.execute(
            "UPDATE tasks SET state='EVALUATED', outcome='CANCELED', "
            "auction_state='CLOSED', finality_ready=1 WHERE task_id=?",
            (task["task_id"],))
        self._bump_task_version(task["task_id"])
        self._emit("AuctionClosed", {"task_id": task["task_id"],
                                     "reason": "CANCELED"})
        self._emit("EvaluationFinalized", {
            "task_id": task["task_id"], "outcome": "CANCELED",
            "verdict": "NONE"})

    def _reserve_earmarked(self) -> int:
        row = self.s.one(
            "SELECT COALESCE(SUM(amount),0) AS t FROM reservations "
            "WHERE kind='Rt' AND state='ACTIVE'")
        return int(row["t"])


from .auction_ops import AuctionOps   # noqa: E402
from .eval_ops import EvalOps         # noqa: E402
from .case_ops import CaseOps         # noqa: E402
from .settle_ops import SettleOps     # noqa: E402
from .reads import ReadRoutes         # noqa: E402


class Engine(EngineBase, AuctionOps, EvalOps, CaseOps, SettleOps,
             ReadRoutes):
    """The complete single-market sequencer."""

