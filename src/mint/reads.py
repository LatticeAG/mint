"""Read routes (spec §8.5): deterministic projections at witnessed
checkpoints. These are not transport-signed; balance reads for private
accounts still require the account holder's signed scope."""

from __future__ import annotations

import base64

from .errors import malformed, not_found
from .events import merkle_path
from .store import jload, jload as _jl


class ReadRoutes:
    def get_task(self, task_id: str) -> dict:
        task = self._get_task(task_id)
        cp = self._latest_checkpoint()
        res = self.s.one(
            "SELECT COALESCE(SUM(amount),0) AS t FROM reservations WHERE "
            "task_id=? AND state='ACTIVE'", (task_id,))
        return {
            "task_id": task_id, "version": task["version"],
            "state": task["state"], "outcome": task["outcome"],
            "value": str(task["value"]),
            "price": str(task["price"]) if task["price"] is not None
            else None,
            "score": task["aggregate_q"], "asset": self.asset,
            "checkpoint_id": cp["checkpoint_id"] if cp else None,
            "outstanding_reservations": str(res["t"]),
        }

    def get_account(self, actor: str, asset: str) -> dict:
        if asset != self.asset:
            raise malformed("unknown asset")
        if not self.s.one("SELECT 1 FROM actors WHERE actor=?", (actor,)):
            raise not_found("account not found")
        cp = self._latest_checkpoint()
        avail = self.ledger.acct(actor, asset, "available")
        pend = self.ledger.acct(actor, asset, "withdrawal_pending")
        hold = self.ledger.acct(actor, asset, "legal_hold")
        return {
            "actor": actor, "asset": asset,
            "available": str(self.ledger.balance(avail)),
            "reserved": str(self.ledger.total_reserved(actor, asset)),
            "payable": "0",
            "withdrawal_pending": str(self.ledger.balance(pend)),
            "legal_hold": str(self.ledger.balance(hold)),
            "checkpoint_id": cp["checkpoint_id"] if cp else None,
        }

    def get_clearing(self, market_id: str, epoch: int) -> dict:
        if market_id != self.market_id:
            raise malformed("unknown market_id")
        offers = []
        excluded = 0
        artifact_id = None
        for r in self.s.all(
                "SELECT * FROM events WHERE type='ClearingPublished' AND "
                "json_extract(data,'$.epoch')=?", (epoch,)):
            d = jload(r["data"])
            artifact_id = d["artifact_id"]
            for i, g in enumerate(d["ladder"]):
                offers.append({
                    "task_id": d["task_id"], "principal_group": g,
                    "price": self._bid_price(d["task_id"], g),
                    "score": d["scores"].get(g), "round": i + 1,
                    "reason": d["reasons"].get(g)})
            excluded += len(d["excluded"])
        if not offers and artifact_id is None:
            raise not_found("no clearing for that epoch")
        return {"market_id": market_id, "epoch": epoch,
                "artifact_id": artifact_id, "offers": offers,
                "excluded_count": excluded}

    def _bid_price(self, task_id: str, group: str) -> str:
        row = self.s.one(
            "SELECT price FROM bids WHERE task_id=? AND principal_group=?",
            (task_id, group))
        return str(row["price"]) if row and row["price"] is not None \
            else None

    def get_case(self, case_id: str) -> dict:
        case = self.s.one("SELECT * FROM cases WHERE case_id=?",
                          (case_id,))
        if not case:
            raise not_found("case not found")
        pen = None
        alg = self.s.one(
            "SELECT penalty FROM allegations WHERE case_id=? AND "
            "penalty IS NOT NULL", (case_id,))
        if alg:
            pen = _jl(alg["penalty"]).get("total")
        return {
            "case_id": case_id,
            "state": "FINAL" if case["state"] in ("DECIDED", "CLOSED")
            else case["state"],
            "offense": case["offense"], "claimant": case["claimant"],
            "slash": pen, "verdict": case["verdict"],
            "precedent_ids": _jl(case["precedent_ids"]),
            "evidence_access": "AUTHORIZED_REVIEWERS",
        }

    def get_artifact(self, artifact_id: str) -> dict:
        row = self.s.one("SELECT * FROM artifacts WHERE artifact_id=?",
                         (artifact_id,))
        if not row:
            # uniform denial: does not reveal private artifact metadata
            raise not_found("artifact not found")
        return {
            "artifact_id": artifact_id, "media_type": row["media_type"],
            "visibility": row["visibility"],
            "content_base64": base64.b64encode(row["content"]).decode(),
            "sha256": row["sha256"],
        }

    def get_log(self, after: int = 0, limit: int = 1000,
                checkpoint_id: str | None = None) -> dict:
        if not (1 <= limit <= 1000):
            raise malformed("limit must be 1..1000")
        max_seq = None
        if checkpoint_id:
            cp = self.s.one("SELECT * FROM checkpoints WHERE "
                            "checkpoint_id=?", (checkpoint_id,))
            if not cp:
                raise not_found("checkpoint not found")
            max_seq = cp["size"]
        q = "SELECT * FROM events WHERE seq>?"
        args: list = [after]
        if max_seq is not None:
            q += " AND seq<=?"
            args.append(max_seq)
        q += " ORDER BY seq LIMIT ?"
        args.append(limit)
        rows = self.s.all(q, tuple(args))
        events = [{
            "seq": r["seq"], "prev": r["prev"], "time": r["time"],
            "type": r["type"], "data": jload(r["data"]),
            "hash": r["hash"],
        } for r in rows]
        cp = self._latest_checkpoint()
        return {"events": events,
                "next_after": events[-1]["seq"] if events else after,
                "checkpoint_id": cp["checkpoint_id"] if cp else None}

    def get_checkpoint(self, checkpoint_id: str) -> dict:
        if checkpoint_id == "latest":
            cp = self._latest_checkpoint()
        else:
            cp = self.s.one(
                "SELECT * FROM checkpoints WHERE checkpoint_id=?",
                (checkpoint_id,))
        if not cp:
            raise not_found("checkpoint not found")
        return {
            "checkpoint_id": cp["checkpoint_id"], "market_id":
            self.market_id, "size": cp["size"],
            "chain_head": cp["chain_head"],
            "merkle_root": cp["merkle_root"], "time": cp["time"],
            "witness_key_epoch": cp["witness_key_epoch"],
            "signatures": jload(cp["signatures"]),
        }

    def get_proof(self, checkpoint_id: str, seq: int) -> dict:
        cp = self.s.one("SELECT * FROM checkpoints WHERE checkpoint_id=?",
                        (checkpoint_id,))
        if not cp:
            raise not_found("checkpoint not found")
        if not (1 <= seq <= cp["size"]):
            raise not_found("seq outside checkpoint")
        hashes = self.event_hashes(cp["size"])
        return {"checkpoint_id": checkpoint_id, "seq": seq,
                "leaf_index": seq - 1, "tree_size": cp["size"],
                "path": merkle_path(hashes, seq - 1)}

    def get_health(self) -> dict:
        fresh = len(self.trust["witnesses"]) if self.checkpoint_fresh() \
            else 0
        reserve = self.ledger.balance(f"op:reserve:{self.asset}")
        earmarked = self._reserve_earmarked()
        cov = 10000 * reserve // max(1, reserve + earmarked)
        return {
            "status": "READY", "mode": self.cfg.mode,
            "covenant_gate": "UNMET", "admissions": "SIMULATION_ONLY",
            "witnesses_fresh": fresh,
            "witnesses_total": len(self.trust["witnesses"]),
            "reserve_coverage_bps": min(10000, cov),
            "log_lag_seconds": 1,
        }

    def _latest_checkpoint(self):
        return self.s.one(
            "SELECT * FROM checkpoints ORDER BY rowid DESC LIMIT 1")
