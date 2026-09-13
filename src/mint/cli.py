"""`mint` command-line interface (spec §8.6).

Every mutation produces the same signed command body, detached
signature, receipt, and verification behavior as the HTTP transport.
`--key-id` resolves a local keystore entry; private keys never appear as
literal command-line arguments.

Exit codes: 0 ok, 2 invalid input/config, 3 auth/role, 4 conflict/
deadline, 5 insufficient funds, 6 unavailable, 7 verification failure,
8 private evidence unavailable.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

from .config import load_config
from .engine import Engine
from .errors import MintError
from .jsonutil import jcs, jcs_text, parse_strict
from .sim import Keystore, Sim, export_fixture, make_trust
from .store import Store
from .timeutil import fmt_ts, parse_ts
from .transport import sign_request
from .trust import load_trust


def _emit_out(obj: dict, out: str | None, json_mode: bool) -> None:
    text = jcs_text(obj) if json_mode else json.dumps(obj, indent=2)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text + "\n")
    print(text)


def _load_engine(config_path: str) -> Engine:
    cfg = load_config(config_path)
    trust = load_trust(cfg.base_dir / cfg.trust_file)
    store = Store(cfg.base_dir / "mint.sqlite")
    return Engine(store, cfg, trust)


def _load_sim(config_path: str) -> Sim:
    cfg = load_config(config_path)
    trust = load_trust(cfg.base_dir / cfg.trust_file)
    store = Store(cfg.base_dir / "mint.sqlite")
    eng = Engine(store, cfg, trust)
    ks_path = cfg.base_dir / "keys.json"
    return Sim(eng, Keystore(ks_path))


def _key_id(args) -> str:
    if not getattr(args, "key_id", None):
        raise MintError(2, "MISSING_KEY", "--key-id is required")
    return args.key_id


def _send(sim: Sim, args, op: str, op_args: dict) -> tuple[int, dict]:
    sim.e.create_checkpoint()  # keep admission freshness in simulation
    return sim.send(_key_id(args), op, op_args)


def _finish(sim: Sim, args, code: int, resp: dict) -> int:
    if code == 200:
        _emit_out(resp, getattr(args, "out", None), True)
        return 0
    err = resp.get("error", {})
    print(jcs_text(resp), file=sys.stderr)
    return MintError(code, err.get("code", "ERROR"),
                     err.get("message", ""), err.get("retryable", False),
                     err.get("details", {})).exit_code


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mint", description=__doc__)
    ap.add_argument("--json", action="store_true",
                    help="canonical JSON output")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, **kw):
        p = sub.add_parser(name, **kw)
        return p

    p = add("fixture")
    fsub = p.add_subparsers(dest="sub", required=True)
    fe = fsub.add_parser("export")
    fe.add_argument("--name", default="clean-100")
    fe.add_argument("--directory", required=True)

    p = add("config")
    csub = p.add_subparsers(dest="sub", required=True)
    cv = csub.add_parser("validate")
    cv.add_argument("--file", required=True)

    p = add("market")
    msub = p.add_subparsers(dest="sub", required=True)
    mi = msub.add_parser("init")
    mi.add_argument("--config", required=True)
    mi.add_argument("--seed-reserve", type=int, default=None)

    def cmd_parser(name):
        p = add(name)
        p.add_argument("--config", required=True)
        p.add_argument("--key-id")
        p.add_argument("--out")
        return p

    # task subcommands
    p = add("task"); tsub = p.add_subparsers(dest="sub", required=True)
    tp = tsub.add_parser("post")
    tp.add_argument("--file", required=True); tp.add_argument("--key-id")
    tp.add_argument("--out"); tp.add_argument("--config", required=True)
    tp = tsub.add_parser("fund")
    tp.add_argument("--task", required=True)
    tp.add_argument("--expected-version", type=int, required=True)
    tp.add_argument("--key-id"); tp.add_argument("--out")
    tp.add_argument("--config", required=True)
    tp = tsub.add_parser("cancel")
    tp.add_argument("--task", required=True)
    tp.add_argument("--expected-version", type=int, required=True)
    tp.add_argument("--key-id"); tp.add_argument("--config", required=True)
    tp = tsub.add_parser("claim")
    tp.add_argument("--task", required=True)
    tp.add_argument("--offer", required=True)
    tp.add_argument("--expected-version", type=int, required=True)
    tp.add_argument("--key-id"); tp.add_argument("--config", required=True)
    tp = tsub.add_parser("submit")
    tp.add_argument("--task", required=True)
    tp.add_argument("--expected-version", type=int, required=True)
    tp.add_argument("--manifest", required=True)
    tp.add_argument("--execution-receipt", required=True)
    tp.add_argument("--key-id"); tp.add_argument("--config", required=True)
    tp = tsub.add_parser("get")
    tp.add_argument("--task", required=True)
    tp.add_argument("--config", required=True)

    p = add("bid"); bsub = p.add_subparsers(dest="sub", required=True)
    bp = bsub.add_parser("commit")
    bp.add_argument("--task", required=True)
    bp.add_argument("--epoch", type=int, required=True)
    bp.add_argument("--bid", required=True)
    bp.add_argument("--key-id"); bp.add_argument("--out")
    bp.add_argument("--config", required=True)
    bp = bsub.add_parser("reveal")
    bp.add_argument("--task", required=True)
    bp.add_argument("--epoch", type=int, required=True)
    bp.add_argument("--bid", required=True)
    bp.add_argument("--key-id"); bp.add_argument("--out")
    bp.add_argument("--config", required=True)

    p = add("evaluation"); esub = p.add_subparsers(dest="sub",
                                                 required=True)
    for nm in ("commit", "reveal"):
        ep = esub.add_parser(nm)
        ep.add_argument("--task", required=True)
        ep.add_argument("--seat", required=True)
        ep.add_argument("--round", type=int, default=1)
        ep.add_argument("--judgment", required=True)
        ep.add_argument("--key-id"); ep.add_argument("--config",
                                                   required=True)

    p = add("test"); tesub = p.add_subparsers(dest="sub", required=True)
    tr = tesub.add_parser("reveal")
    tr.add_argument("--task", required=True)
    tr.add_argument("--expected-version", type=int, required=True)
    tr.add_argument("--test-commitment", required=True)
    tr.add_argument("--test-artifact", required=True)
    tr.add_argument("--key-id"); tr.add_argument("--config",
                                                required=True)

    p = add("evidence"); evsub = p.add_subparsers(dest="sub",
                                                required=True)
    ea = evsub.add_parser("attach")
    ea.add_argument("--task"); ea.add_argument("--case")
    ea.add_argument("--artifacts", required=True)
    ea.add_argument("--key-id"); ea.add_argument("--config",
                                                required=True)

    p = add("case"); casub = p.add_subparsers(dest="sub", required=True)
    for nm in ("open", "answer", "appeal"):
        cp_ = casub.add_parser(nm)
        cp_.add_argument("--file", required=True)
        cp_.add_argument("--key-id"); cp_.add_argument("--config",
                                                      required=True)

    p = add("command"); cmsub = p.add_subparsers(dest="sub",
                                               required=True)
    cs = cmsub.add_parser("send")
    cs.add_argument("--file", required=True); cs.add_argument("--key-id")
    cs.add_argument("--out"); cs.add_argument("--config", required=True)

    p = add("request"); rsub = p.add_subparsers(dest="sub", required=True)
    rs = rsub.add_parser("sign")
    rs.add_argument("--method", default="POST")
    rs.add_argument("--target", default="/v1/commands")
    rs.add_argument("--body", required=True)
    rs.add_argument("--key-id", required=True)
    rs.add_argument("--keystore")
    rs.add_argument("--network", default="mint-sim-1")
    rs.add_argument("--headers-out", required=True)

    p = add("clock"); clsub = p.add_subparsers(dest="sub", required=True)
    ca = clsub.add_parser("advance")
    ca.add_argument("--seconds", type=int, required=True)
    ca.add_argument("--config", required=True)

    p = add("account"); acsub = p.add_subparsers(dest="sub",
                                               required=True)
    ag = acsub.add_parser("get")
    ag.add_argument("--actor", required=True)
    ag.add_argument("--asset", default="SIMUSD")
    ag.add_argument("--config", required=True)

    p = add("log"); lsub = p.add_subparsers(dest="sub", required=True)
    le = lsub.add_parser("export")
    le.add_argument("--checkpoint")
    le.add_argument("--out", required=True)
    le.add_argument("--config", required=True)

    p = add("artifacts"); artsub = p.add_subparsers(dest="sub",
                                                  required=True)
    ax = artsub.add_parser("export")
    ax.add_argument("--dir", required=True)
    ax.add_argument("--config", required=True)

    p = add("verify")
    p.add_argument("--log", required=True)
    p.add_argument("--trust", required=True)
    p.add_argument("--artifacts", required=True)
    p.add_argument("--checkpoint")
    p.add_argument("--strict", action="store_true")

    p = add("simulate")
    p.add_argument("--config", required=True)
    p.add_argument("--seed", default="42")
    p.add_argument("--out", required=True)

    p = add("serve")
    p.add_argument("--config", required=True)

    args = ap.parse_args(argv)
    try:
        return _dispatch(args)
    except MintError as e:
        print(jcs_text(e.body()), file=sys.stderr)
        return e.exit_code
    except KeyError as e:
        print(jcs_text({"error": {"code": "MISSING_KEY", "message":
                                  str(e), "retryable": False,
                                  "details": {}}}), file=sys.stderr)
        return 3


def _dispatch(args) -> int:
    cmd, sub_ = args.cmd, getattr(args, "sub", None)

    if cmd == "fixture" and sub_ == "export":
        res = export_fixture(args.name, args.directory)
        _emit_out(res, None, args.json)
        return 0

    if cmd == "config" and sub_ == "validate":
        cfg = load_config(args.file)
        _emit_out({"valid": True, "network": cfg.network,
                   "market_id": cfg.market_id, "mode": cfg.mode},
                  None, args.json)
        return 0

    if cmd == "market" and sub_ == "init":
        cfg = load_config(args.config)
        trust = load_trust(cfg.base_dir / cfg.trust_file)
        store = Store(cfg.base_dir / "mint.sqlite")
        eng = Engine(store, cfg, trust)
        if args.seed_reserve:
            with eng.s.tx():
                eng.ledger.post("txn-init-reserve", eng.asset,
                                f"custody:cash:{eng.asset}",
                                f"op:reserve:{eng.asset}",
                                args.seed_reserve)
                eng._emit("OperatorReserveSeeded",
                          {"amount": str(args.seed_reserve)})
        eng.create_checkpoint()
        _emit_out({"market_id": cfg.market_id, "state": "OPEN",
                   "genesis": fmt_ts(eng.genesis_ms)}, None, args.json)
        return 0

    if cmd == "serve":
        from .server import serve
        eng = _load_engine(args.config)
        cfg = eng.cfg
        httpd = serve(eng, cfg.listen)
        print(f"mint sim server on {cfg.listen}", file=sys.stderr)
        httpd.serve_forever()
        return 0

    if cmd == "verify":
        from .verifier import verify_log
        res = verify_log(args.log, args.trust, args.artifacts,
                         strict=args.strict,
                         checkpoint_path=args.checkpoint)
        _emit_out(res, None, True)
        if not res["valid"]:
            return 7
        if res["unavailable_private_evidence"]:
            return 8
        return 0

    if cmd == "simulate":
        from .scenario import bootstrap, run_clean_100
        simcfg = parse_strict(Path(args.config).read_bytes())
        trust = make_trust(args.seed if args.seed != "42" else
                           simcfg.get("seed", "clean-100"))
        store = Store(":memory:")
        from .config import Config
        cfg = Config(network=trust["network"], market_id=trust[
            "market_id"], mode="simulation", asset="SIMUSD",
            listen="127.0.0.1:8787", policy_id="mint-policy-1",
            trust_file="", charter_bundle="", covenant_v1_attestation=
            "unmet")
        ks = Keystore()
        actors = [("poster-test", "poster-1"),
                  ("operator", "operator-1")]
        for i in range(3):
            actors.append((f"worker-{i + 1}", f"worker-{i + 1}"))
        for i in range(40):
            actors.append((f"evaluator-{i + 1}", f"evaluator-{i + 1}"))
        for i in range(10):
            actors.append((f"judge-{i + 1}", f"judge-{i + 1}"))
        from .sim import _derive_ed25519, _derive_x25519
        seed = simcfg.get("seed", "clean-100")
        for key_id, actor in actors:
            sk, pk = _derive_ed25519(seed, actor)
            ks.add(key_id, actor, sk, pk)
        xsk, xpk = _derive_x25519(seed, "poster-1-enc")
        ks.keys["poster-test-enc"] = {"actor": "poster-1",
                                      "secret_hex": xsk.hex(),
                                      "public_key_hex": xpk.hex(),
                                      "key_epoch": 0}
        eng = Engine(store, cfg, trust)
        sim = Sim(eng, ks, seed)
        bootstrap(sim)
        result = run_clean_100(sim)
        outdir = Path(args.out)
        outdir.mkdir(parents=True, exist_ok=True)
        _export_log(eng, outdir / "log.jsonl")
        _export_artifacts(eng, outdir / "artifacts")
        (outdir / "checkpoints.json").write_text(json.dumps(
            _all_checkpoints(eng), indent=2))
        (outdir / "report.json").write_text(json.dumps(
            {"scenario": result["scenario"], "seed": seed,
             "outcome": result["outcome"], "events": result["events"],
             "policy_hash": __import__("mint.policy", fromlist=[
                 "POLICY_HASH"]).POLICY_HASH}, indent=2))
        _emit_out({"scenario": result["scenario"], "seed": seed,
                   "outcome": result["outcome"],
                   "events": result["events"],
                   "out_dir": str(outdir)}, None, True)
        return 0

    # ---- engine-backed commands ------------------------------------------
    if cmd in ("task", "bid", "evaluation", "test", "evidence", "case",
               "command", "clock", "account", "log", "artifacts"):
        if cmd == "account" and sub_ == "get":
            eng = _load_engine(args.config)
            _emit_out(eng.get_account(args.actor, args.asset), None,
                      args.json)
            return 0
        if cmd == "task" and sub_ == "get":
            eng = _load_engine(args.config)
            _emit_out(eng.get_task(args.task), None, args.json)
            return 0
        if cmd == "log" and sub_ == "export":
            eng = _load_engine(args.config)
            n = _export_log(eng, Path(args.out), args.checkpoint)
            _emit_out({"exported": n, "out": args.out}, None, args.json)
            return 0
        if cmd == "artifacts" and sub_ == "export":
            eng = _load_engine(args.config)
            n = _export_artifacts(eng, Path(args.dir))
            _emit_out({"exported": n, "dir": args.dir}, None, args.json)
            return 0
        if cmd == "clock" and sub_ == "advance":
            eng = _load_engine(args.config)
            eng._advance_clock(eng.now_ms + args.seconds * 1000)
            _emit_out({"now": fmt_ts(eng.now_ms)}, None, args.json)
            return 0

        sim = _load_sim(args.config)
        if cmd == "task" and sub_ == "post":
            body = parse_strict(Path(args.file).read_bytes())
            op_args = body["args"] if "op" in body else body
            return _finish(sim, args, *_send(sim, args, "task.post",
                                             op_args))
        if cmd == "task" and sub_ == "fund":
            return _finish(sim, args, *_send(sim, args, "task.fund", {
                "task_id": args.task,
                "expected_version": args.expected_version}))
        if cmd == "task" and sub_ == "cancel":
            return _finish(sim, args, *_send(sim, args, "task.cancel", {
                "task_id": args.task,
                "expected_version": args.expected_version}))
        if cmd == "task" and sub_ == "claim":
            return _finish(sim, args, *_send(sim, args, "task.claim", {
                "task_id": args.task, "offer_id": args.offer,
                "expected_version": args.expected_version}))
        if cmd == "task" and sub_ == "submit":
            return _finish(sim, args, *_send(sim, args, "task.submit", {
                "task_id": args.task,
                "expected_version": args.expected_version,
                "manifest_id": args.manifest,
                "execution_receipt_id": args.execution_receipt}))
        if cmd == "bid":
            bid = parse_strict(Path(args.bid).read_bytes())
            k = sim.ks.get(_key_id(args))
            eng = sim.e
            if sub_ == "commit":
                from .clearing import bid_commitment
                from .crypto import random_hex
                salt = bid.get("salt") or random_hex(32)
                commit = bid_commitment(
                    eng.network, eng.market_id, args.epoch, args.task,
                    k["actor"] and _group_of(eng, k["actor"]),
                    k["key_epoch"], int(bid["price"]),
                    int(bid["latency_seconds"]), bid["slot"], salt)
                # publish commitment artifact then commit
                code, resp = sim.send(_key_id(args), "artifact.publish", {
                    "artifact_id": f"art:commit-{args.task}-"
                                   f"{k['actor']}",
                    "media_type": "application/json",
                    "visibility": "public",
                    "content_base64": __import__("base64").b64encode(
                        jcs({"commitment": commit})).decode(),
                    "sha256": sha256_hex(jcs({"commitment": commit}))})
                if code != 200:
                    return _finish(sim, args, code, resp)
                task = eng._get_task(args.task)
                return _finish(sim, args, *_send(sim, args, "bid.commit", {
                    "task_id": args.task, "epoch": args.epoch,
                    "expected_version": task["terms_version"],
                    "slot": bid["slot"],
                    "commitment_id": f"art:commit-{args.task}-"
                                     f"{k['actor']}"}))
            if sub_ == "reveal":
                return _finish(sim, args, *_send(sim, args, "bid.reveal", {
                    "task_id": args.task, "epoch": args.epoch,
                    "price": str(bid["price"]),
                    "latency_seconds": int(bid["latency_seconds"]),
                    "slot": bid["slot"], "salt": bid["salt"]}))
        if cmd == "evaluation":
            from .crypto import random_hex
            from .jsonutil import domain_hash, sha256_hex
            judgment = parse_strict(Path(args.judgment).read_bytes())
            eng = sim.e
            k = sim.ks.get(_key_id(args))
            if sub_ == "commit":
                salt = random_hex(32)
                commit = domain_hash("mint.eval.commit.v1", {
                    "network": eng.network, "market_id": eng.market_id,
                    "task_id": args.task, "round": args.round,
                    "seat_id": args.seat, "key_epoch": k["key_epoch"],
                    "judgment": judgment, "salt": salt})
                code, resp = sim.send(_key_id(args), "artifact.publish", {
                    "artifact_id": f"art:evalcommit-{args.seat}",
                    "media_type": "application/json",
                    "visibility": "public",
                    "content_base64": __import__("base64").b64encode(
                        jcs({"commitment": commit,
                             "salt": salt})).decode(),
                    "sha256": sha256_hex(jcs({"commitment": commit,
                                              "salt": salt}))})
                if code != 200:
                    return _finish(sim, args, code, resp)
                return _finish(sim, args, *_send(
                    sim, args, "evaluation.commit", {
                        "task_id": args.task, "seat_id": args.seat,
                        "round": args.round,
                        "commitment_id": f"art:evalcommit-{args.seat}"}))
            if sub_ == "reveal":
                meta = eng.artifact_json(f"art:evalcommit-{args.seat}")
                salt = meta["salt"]
                return _finish(sim, args, *_send(
                    sim, args, "evaluation.reveal", {
                        "task_id": args.task, "seat_id": args.seat,
                        "round": args.round, "judgment": judgment,
                        "salt": salt}))
        if cmd == "test" and sub_ == "reveal":
            return _finish(sim, args, *_send(sim, args, "test.reveal", {
                "task_id": args.task,
                "expected_version": args.expected_version,
                "test_commitment_id": args.test_commitment,
                "test_artifact_id": args.test_artifact}))
        if cmd == "evidence" and sub_ == "attach":
            ids = [s.strip() for s in args.artifacts.split(",")]
            op_args = {"artifact_ids": ids}
            if args.task:
                op_args["task_id"] = args.task
            if args.case:
                op_args["case_id"] = args.case
            return _finish(sim, args, *_send(sim, args,
                                             "evidence.attach", op_args))
        if cmd == "case":
            body = parse_strict(Path(args.file).read_bytes())
            op_args = body["args"] if "op" in body else body
            return _finish(sim, args, *_send(
                sim, args, f"case.{sub_}", op_args))
        if cmd == "command" and sub_ == "send":
            body = parse_strict(Path(args.file).read_bytes())
            return _finish(sim, args, *_send(sim, args, body["op"],
                                             body["args"]))
        raise MintError(2, "USAGE", f"unhandled {cmd} {sub_}")

    if cmd == "request" and sub_ == "sign":
        ks = Keystore(args.keystore or "./keys.json")
        k = ks.get(args.key_id)
        body = Path(args.body).read_bytes()
        import time
        now = int(time.time() * 1000)
        headers = sign_request(
            bytes.fromhex(k["secret_hex"]), args.network, args.method,
            args.target, k["actor"], k["key_epoch"],
            secrets.token_hex(16), fmt_ts(now),
            fmt_ts(now + 300_000), body,
            f"idem-{secrets.token_hex(12)}")
        Path(args.headers_out).write_text(
            "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n")
        _emit_out({"headers_out": args.headers_out}, None, args.json)
        return 0

    raise MintError(2, "USAGE", f"unhandled command {cmd}")


def _group_of(eng, actor: str) -> str:
    row = eng.s.one("SELECT principal_group FROM actors WHERE actor=?",
                    (actor,))
    if not row:
        raise MintError(2, "UNKNOWN_ACTOR", actor)
    return row["principal_group"]


def sha256_hex(b: bytes) -> str:
    from .jsonutil import sha256_hex as f
    return f(b)


def _export_log(eng: Engine, out: Path, checkpoint: str | None = None) -> int:
    from .store import jload
    out.parent.mkdir(parents=True, exist_ok=True)
    max_seq = None
    if checkpoint:
        cp = eng.s.one("SELECT * FROM checkpoints WHERE checkpoint_id=?",
                       (checkpoint,))
        if cp:
            max_seq = cp["size"]
    n = 0
    with out.open("w") as f:
        for r in eng.s.all("SELECT * FROM events ORDER BY seq"):
            if max_seq and r["seq"] > max_seq:
                break
            ev = {"seq": r["seq"], "prev": r["prev"], "time": r["time"],
                  "type": r["type"], "data": jload(r["data"]),
                  "hash": r["hash"],
                  "detail_artifact_id": r["detail_artifact_id"]}
            f.write(jcs_text(ev) + "\n")
            n += 1
    return n


def _export_artifacts(eng: Engine, outdir: Path) -> int:
    import base64
    outdir.mkdir(parents=True, exist_ok=True)
    n = 0
    for r in eng.s.all("SELECT * FROM artifacts ORDER BY artifact_id"):
        obj = {"artifact_id": r["artifact_id"], "sha256": r["sha256"],
               "media_type": r["media_type"],
               "visibility": r["visibility"],
               "content_base64": base64.b64encode(r["content"]).decode()}
        (outdir / (r["artifact_id"].replace(":", "_").replace("/", "_")
                   + ".json")).write_text(json.dumps(obj, indent=2))
        n += 1
    return n


def _all_checkpoints(eng: Engine) -> list:
    from .store import jload
    return [{
        "checkpoint_id": r["checkpoint_id"], "market_id": eng.market_id,
        "size": r["size"], "chain_head": r["chain_head"],
        "merkle_root": r["merkle_root"], "time": r["time"],
        "witness_key_epoch": r["witness_key_epoch"],
        "signatures": jload(r["signatures"]),
    } for r in eng.s.all("SELECT * FROM checkpoints ORDER BY rowid")]
