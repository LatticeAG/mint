"""Simulation harness and fixture exporter (spec §10).

Deterministic discrete-event simulator driving the real Engine through
the clean-100 scenario. The simulator holds the local witness quorum,
pinned authority keys, and per-actor signing keys — these are fixture
credentials only, never usable as real-money credentials.

Determinism: every keypair derives from SHA-256 domain expansion of the
fixture seed, so exported fixtures and run outputs are reproducible.
"""

from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path

from .crypto import (
    b64u, deliverable_commitment, ed25519_sign, seal_chunk,
    tk_commitment, unwrap_key, wrap_key, x25519_keypair,
)
from .engine import Engine
from .jsonutil import domain_hash, jcs, jcs_text, sha256_hex
from .policy import POLICY, schedule, OFFENSE_SCHEDULE_HASH, POLICY_HASH
from .store import Store, jdump
from .timeutil import fmt_ts, parse_ts
from .transport import sign_request
from .trust import beacon_value

GENESIS = "2026-09-12T00:00:00.000Z"


def _derive_secret(seed: str, name: str) -> bytes:
    import hashlib
    return hashlib.sha256(
        b"mint.sim.key.v1\x00" + seed.encode() + b"\x00"
        + name.encode()).digest()


def _derive_x25519(seed: str, name: str) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey)
    sk = X25519PrivateKey.from_private_bytes(_derive_secret(seed, name))
    pk = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _derive_secret(seed, name), pk


def _derive_ed25519(seed: str, name: str) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    sk = Ed25519PrivateKey.from_private_bytes(_derive_secret(seed, name))
    pk = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    raw = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    return raw, pk


class Keystore:
    """Local fixture keystore (an OS keystore/signer boundary in prod)."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.keys: dict[str, dict] = {}
        if self.path and self.path.exists():
            self.keys = json.loads(self.path.read_text())

    def add(self, key_id: str, actor: str, secret: bytes, public: bytes,
            epoch: int = 1):
        self.keys[key_id] = {
            "actor": actor, "secret_hex": secret.hex(),
            "public_key_hex": public.hex(), "key_epoch": epoch}

    def get(self, key_id: str) -> dict:
        if key_id not in self.keys:
            raise KeyError(f"unknown key-id {key_id}")
        return self.keys[key_id]

    def save(self, path: str | Path | None = None):
        p = Path(path) if path else self.path
        p.write_text(json.dumps(self.keys, indent=2))


class Sim:
    """Deterministic engine driver with a local signer."""

    def __init__(self, engine: Engine, keystore: Keystore,
                 seed: str = "sim-seed-1"):
        self.e = engine
        self.ks = keystore
        self.seed = seed

    # -- signing ---------------------------------------------------------
    def sign_headers(self, key_id: str, body: bytes,
                     expires_in_s: int = 300) -> dict:
        k = self.ks.get(key_id)
        now = self.e.now_ms
        return sign_request(
            bytes.fromhex(k["secret_hex"]), self.e.network, "POST",
            "/v1/commands", k["actor"], k["key_epoch"],
            secrets.token_hex(16), fmt_ts(now), fmt_ts(now +
                                                     expires_in_s * 1000),
            body, f"idem-{secrets.token_hex(12)}")

    def send(self, key_id: str, op: str, args: dict,
             idem_key: str | None = None,
             nonce: str | None = None) -> tuple[int, dict]:
        # commands are witnessed: a fresh local checkpoint stands in for
        # the quorum's admission freshness (production gates this on the
        # real witness network)
        self.e.create_checkpoint()
        body = jcs({"op": op, "args": args})
        k = self.ks.get(key_id)
        now = self.e.now_ms
        headers = sign_request(
            bytes.fromhex(k["secret_hex"]), self.e.network, "POST",
            "/v1/commands", k["actor"], k["key_epoch"],
            nonce or secrets.token_hex(16), fmt_ts(now),
            fmt_ts(now + 300_000), body,
            idem_key or f"idem-{secrets.token_hex(12)}")
        return self.e.execute(headers, body)

    def send_raw(self, headers: dict, body: bytes) -> tuple[int, dict]:
        return self.e.execute(headers, body)

    # -- control ---------------------------------------------------------
    def checkpoint(self) -> dict:
        return self.e.create_checkpoint()

    def advance(self, seconds: int) -> None:
        self.e._advance_clock(self.e.now_ms + seconds * 1000)

    def advance_to(self, ms: int) -> None:
        self.e._advance_clock(ms)

    # -- fixture helpers ---------------------------------------------------
    def publish(self, key_id: str, artifact_id: str, obj: dict | bytes,
                media_type: str = "application/json",
                visibility: str = "public") -> tuple[int, dict]:
        raw = obj if isinstance(obj, bytes) else jcs(obj)
        return self.send(key_id, "artifact.publish", {
            "artifact_id": artifact_id, "media_type": media_type,
            "visibility": visibility,
            "content_base64": base64.b64encode(raw).decode(),
            "sha256": sha256_hex(raw)})

    def registrar_cert(self, key_id: str, args: dict) -> dict:
        """Sign an enrollment certificate over the full enroll args."""
        signer = self.e.trust["authority_keys"]
        reg = next(k for k in signer if k["role"] == "registrar")
        msg = b"mint.enroll.v1\x00" + jcs(args)
        return {"domain": "mint.enroll.v1", "signer": reg["key_id"],
                "signature": b64u(ed25519_sign(
                    bytes.fromhex(reg["secret_hex"]), msg))}

    def custody_cert(self, subject: dict, domain: str) -> dict:
        iss = next(k for k in self.e.trust["authority_keys"]
                   if k["role"] == "custody_issuer")
        msg = domain.encode() + b"\x00" + jcs(subject)
        return {"domain": domain, "signer": iss["key_id"],
                "signature": b64u(ed25519_sign(
                    bytes.fromhex(iss["secret_hex"]), msg))}

    def settlement_cert(self, instruction: dict) -> dict:
        sigs = []
        msg = b"mint.settlement.cert.v1\x00" + jcs(instruction)
        for s in self.e.trust["settlement_signers"][:3]:
            sigs.append({"key_id": s["key_id"], "signature": b64u(
                ed25519_sign(bytes.fromhex(s["secret_hex"]), msg))})
        return {"domain": "mint.settlement.cert.v1",
                "signatures": sigs}

    def recovery_cert(self, order: dict, action: str) -> dict:
        sigs = []
        msg = b"mint.control.cert.v1\x00" + jcs(order)
        for s in self.e.trust["recovery_authority"][:4]:
            sigs.append({"key_id": s["key_id"], "signature": b64u(
                ed25519_sign(bytes.fromhex(s["secret_hex"]), msg))})
        return {"domain": "mint.control.cert.v1", "action": action,
                "signatures": sigs}

    def court_cert(self, case_id: str, stage: str, order: dict,
                   seats: list) -> dict:
        sigs = []
        msg = b"mint.court.cert.v1\x00" + jcs(order)
        for seat in seats:
            actor = seat["actor"]
            kid = self._key_for_actor(actor)
            k = self.ks.get(kid)
            sigs.append({"seat_actor": actor, "signature": b64u(
                ed25519_sign(bytes.fromhex(k["secret_hex"]), msg))})
        return {"domain": "mint.court.cert.v1", "stage": stage,
                "signatures": sigs}

    def _key_for_actor(self, actor: str) -> str:
        for kid, k in self.keys_iter():
            if k["actor"] == actor:
                return kid
        raise KeyError(actor)

    def keys_iter(self):
        return iter(self.ks.keys.items())

    def enroll_actor(self, key_id: str, actor: str, group: str,
                     roles: list[str], **extra) -> tuple[int, dict]:
        k = self.ks.get(key_id)
        args = {"actor": actor, "principal_group": group, "roles": roles,
                "key_epoch": k["key_epoch"],
                "public_key_hex": k["public_key_hex"],
                "identity_attestation": f"att:{actor}",
                "registrar_certificate": "",  # replaced below
                **extra}
        # the certificate signs the args WITH the registrar_certificate
        # field empty? No: cert binds the public enrollment statement;
        # put the cert id placeholder then sign args minus it.
        cert_args = {kk: vv for kk, vv in args.items()
                     if kk != "registrar_certificate"}
        cert = self.registrar_cert(key_id, cert_args)
        # store cert as artifact first
        code, _ = self.publish("operator", f"cert:{actor}-enroll", cert)
        if code != 200:
            return code, _
        args["registrar_certificate"] = f"cert:{actor}-enroll"
        return self.send(key_id, "actor.enroll", args)


# ======================================================================
# Fixture export
# ======================================================================

def make_trust(seed: str, network: str = "mint-sim-1",
               market_id: str = "m1") -> dict:
    witnesses = []
    for i in range(5):
        sk, pk = _derive_ed25519(seed, f"witness-{i}")
        witnesses.append({"key_id": f"wit-{i}", "entity": f"w-ent-{i}",
                          "public_key_hex": pk.hex(), "secret": sk.hex()})
    settlers = []
    for i in range(5):
        sk, pk = _derive_ed25519(seed, f"settler-{i}")
        settlers.append({"key_id": f"set-{i}", "entity": f"s-ent-{i}",
                         "public_key_hex": pk.hex(), "secret_hex": sk.hex()})
    recovery = []
    for i in range(7):
        sk, pk = _derive_ed25519(seed, f"recovery-{i}")
        recovery.append({"key_id": f"rec-{i}", "entity": f"r-ent-{i}",
                         "public_key_hex": pk.hex(), "secret_hex": sk.hex()})
    reg_sk, reg_pk = _derive_ed25519(seed, "registrar")
    iss_sk, iss_pk = _derive_ed25519(seed, "custody-issuer")
    ct_sk, ct_pk = _derive_ed25519(seed, "court-authority")
    pe_sk, pe_pk = _derive_x25519(seed, "panel-escrow")
    at_sk, at_pk = _derive_ed25519(seed, "escrow-attest")
    return {
        "schema_version": 1,
        "network": network, "market_id": market_id,
        "policy_id": "mint-policy-1",
        "genesis_time": GENESIS,
        "genesis_seed": sha256_hex(b"mint.genesis\x00" + seed.encode()),
        "witnesses": witnesses,
        "settlement_signers": settlers,
        "recovery_authority": recovery,
        "authority_keys": [
            {"role": "registrar", "key_id": "registrar-1",
             "public_key_hex": reg_pk.hex(), "secret_hex": reg_sk.hex()},
            {"role": "custody_issuer", "key_id": "custody-issuer-1",
             "public_key_hex": iss_pk.hex(), "secret_hex": iss_sk.hex()},
            {"role": "court_authority", "key_id": "court-authority-1",
             "public_key_hex": ct_pk.hex(), "secret_hex": ct_sk.hex()},
        ],
        "beacon": {"profile": "deterministic-simulation-v1"},
        "panel_escrow": {
            "holder": "witness_quorum", "key_id": "panel-escrow-1",
            "public_key_hex": pe_pk.hex(), "secret_key_hex": pe_sk.hex(),
            "attestation_key": {"key_id": "escrow-attest-1",
                                "public_key_hex": at_pk.hex(),
                                "secret_hex": at_sk.hex()}},
    }


MINT_TOML = """schema_version = 1
network = "mint-sim-1"
market_id = "m1"
mode = "simulation"
asset = "SIMUSD"
listen = "127.0.0.1:8787"
policy_id = "mint-policy-1"
trust_file = "./trust.json"
charter_bundle = "./artifacts/charter-r1.json"
covenant_v1_attestation = "unmet"

[limits]
minimum_value = 1000
maximum_value = 100000
max_active_claims_per_principal = 3
max_commits_per_epoch = 20
max_artifact_bytes = 268435456
absolute_task_days = 45
max_acceptance_score = 9500

[execution]
dmax_min_seconds = 3600
dmax_max_seconds = 259200
evaluator_commit_seconds = 7200
evaluator_reveal_seconds = 3600
seat_acceptance_seconds = 300
evidence_access_seconds = 300
review_hours = 24
court_decision_seconds = 259200
supervisory_seconds = 259200

[auction]
commit_seconds = 900
reveal_seconds = 300
claim_offer_seconds = 300
maximum_offers = 3
quality_weight_bps = 5000
price_weight_bps = 3000
latency_weight_bps = 2000
fairness_band_points = 200
beacon_profile = "deterministic-simulation-v1"

[judgment]
primary_seats = 5
primary_quorum = 4
trial_seats = 7
trial_quorum = 5
appeal_seats = 9
appeal_quorum = 7
supervisory_seats = 9
supervisory_quorum = 7
challenge_seconds = 172800
appeal_filing_seconds = 172800

[ledger]
backend = "sqlite-wal"
synchronous = "FULL"
checkpoint_seconds = 1
witness_seats = 5
witness_quorum = 4
max_checkpoint_age_seconds = 30

[custody]
adapter = "sim-fixture"
reserve_initial = 10000000
withdrawal_cooldown_seconds = 86400

[settlement]
signer_seats = 5
signer_quorum = 3
signers_source = "trust"

[recovery]
authority_seats = 7
authority_quorum = 4
recovery_challenge_seconds = 172800

[escrow]
panel_key_holder = "witness_quorum"
panel_key_quorum = 4
"""

RUBRIC_R1 = {
    "rubric_id": "R1", "version": 1,
    "components": {
        "correctness": {"weight_bps": 4000, "units": 20,
                        "floor": 15},
        "completeness": {"weight_bps": 3000, "units": 4, "floor": 3},
        "reproducibility": {"weight_bps": 2000, "units": 5, "floor": 3},
        "safety": {"weight_bps": 1000, "units": 2, "floor": 2},
    },
    "mandatory_gates": ["content", "license", "integrity"],
    "expected_observations": {
        "tests_passed": 19, "tests_determinate": 20,
        "clauses_satisfied": 3, "clauses_determinate": 4,
        "reruns_matched": 5, "reruns_determinate": 5,
        "controls_passed": 2, "controls_determinate": 2,
    },
}


def export_fixture(name: str, directory: str, seed: str = "clean-100") \
        -> dict:
    """Materialize the complete synthetic fixture set (§8.6)."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    (out / "artifacts").mkdir(exist_ok=True)
    trust = make_trust(seed)
    (out / "trust.json").write_text(
        json.dumps(trust, indent=2))
    (out / "mint.toml").write_text(MINT_TOML)

    ks = Keystore()
    actors = [("poster-test", "poster-1", "pg-poster-1", ["poster"])]
    for i in range(3):
        actors.append((f"worker-{i + 1}", f"worker-{i + 1}",
                       f"pg-worker-{i + 1}", ["worker"]))
    for i in range(40):
        actors.append((f"evaluator-{i + 1}", f"evaluator-{i + 1}",
                       f"pg-eval-{i + 1}", ["evaluator"]))
    for i in range(10):
        actors.append((f"judge-{i + 1}", f"judge-{i + 1}",
                       f"pg-judge-{i + 1}", ["judge"]))
    actors.append(("operator", "operator-1", "pg-operator", ["operator"]))
    enc_keys: dict[str, str] = {}
    for key_id, actor, group, roles in actors:
        sk, pk = _derive_ed25519(seed, actor)
        ks.add(key_id, actor, sk, pk)
        if "poster" in roles:
            xsk, xpk = _derive_x25519(seed, f"{actor}-enc")
            enc_keys[actor] = xpk.hex()
            ks.keys[f"{key_id}-enc"] = {
                "actor": actor, "secret_hex": xsk.hex(),
                "public_key_hex": xpk.hex(), "key_epoch": 0}
    ks.save(out / "keys.json")

    # ---- artifacts ------------------------------------------------------
    def art(aid: str, obj: dict, media: str = "application/json"):
        raw = jcs(obj)
        (out / "artifacts" / f"{aid.replace(':', '_')}.json").write_text(
            json.dumps({"artifact_id": aid, "sha256": sha256_hex(raw),
                        "media_type": media, "visibility": "public",
                        "content_base64":
                            base64.b64encode(raw).decode()}, indent=2))
        return sha256_hex(raw)

    charter = {
        "charter_id": "charter-r1", "constitution_hash": domain_hash(
            "mint.constitution.v1", {"text": "sim constitution"}),
        "precedent_root": domain_hash(
            "mint.precedent.v1", {"empty": True}),
        "offense_schedule_hash": OFFENSE_SCHEDULE_HASH,
        "policy_hash": POLICY_HASH,
    }
    art("art:charter-r1", charter)
    art("art:rubric-r1", RUBRIC_R1)
    manifest = {
        "manifest_id": "art:manifest-t1", "task_class": "code",
        "deliverable_spec": {"format": "tar.gz",
                             "tests": "rubric-hidden"},
        "requirements": ["build a thing"],
        "hidden_test_commitments": ["art:hidden-tests-commit-t1"],
    }
    art("art:manifest-t1", manifest)
    hidden = {"tests": ["t-check-1", "t-check-2"],
              "sha256_of_pack": sha256_hex(b"hidden-test-pack")}
    hraw = jcs(hidden)
    art("art:hidden-tests-t1", hidden)
    art("art:hidden-tests-commit-t1", {"sha256": sha256_hex(hraw)})

    # task-post command args file
    task_post = {
        "op": "task.post",
        "args": {
            "task_id": "t1", "market_id": "m1", "asset": "SIMUSD",
            "value": "10000", "execution_cap_seconds": 3600,
            "forecast_floor": 7000, "acceptance_score": 8500,
            "manifest_id": "art:manifest-t1",
            "rubric_id": "art:rubric-r1",
            "charter_bundle_id": "art:charter-r1",
            "policy_id": "mint-policy-1",
        },
    }
    (out / "task-post.json").write_text(json.dumps(task_post, indent=2))

    bid = {"price": "9000", "latency_seconds": 1800,
           "slot": "slot-worker-1", "epoch": 42}
    (out / "bid.json").write_text(json.dumps(bid, indent=2))
    judgment = {
        "observations": dict(RUBRIC_R1["expected_observations"]),
        "mandatory_gates": {"content": True, "license": True,
                            "integrity": True},
        "evidence_ids": ["art:tests-t1", "art:run-t1"],
        "conflict": False, "reason": "RUBRIC_PASS",
    }
    (out / "judgment.json").write_text(json.dumps(judgment, indent=2))
    (out / "case-open.json").write_text(json.dumps({
        "op": "case.open", "args": {
            "task_id": "t1", "offense": "W1", "claimed_loss": "2000",
            "evidence_ids": ["art:run-t1"],
            "incident_id": "inc-fixture-1"}}, indent=2))
    (out / "case-appeal.json").write_text(json.dumps({
        "op": "case.appeal", "args": {
            "case_id": "case-t1-e2", "expected_version": 3,
            "grounds_id": "art:grounds-1"}}, indent=2))
    (out / "simulation.json").write_text(json.dumps({
        "scenario": "clean-100", "seed": seed, "network": "mint-sim-1",
        "market_id": "m1", "trust_file": "./trust.json",
        "mint_toml": "./mint.toml", "keys": "./keys.json"}, indent=2))
    return {"directory": str(out), "seed": seed,
            "files": sorted(p.name for p in out.iterdir())}
