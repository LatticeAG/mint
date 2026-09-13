"""Shared fixtures: a bootstrapped deterministic simulation engine."""

from __future__ import annotations

import pytest

from mint.config import Config
from mint.engine import Engine
from mint.scenario import bootstrap
from mint.sim import (
    Keystore, Sim, _derive_ed25519, _derive_x25519, make_trust)
from mint.store import Store

SEED = "clean-100"


def build_keystore(seed: str = SEED) -> Keystore:
    ks = Keystore()
    actors = [("poster-test", "poster-1"), ("operator", "operator-1")]
    for i in range(3):
        actors.append((f"worker-{i + 1}", f"worker-{i + 1}"))
    for i in range(40):
        actors.append((f"evaluator-{i + 1}", f"evaluator-{i + 1}"))
    for i in range(10):
        actors.append((f"judge-{i + 1}", f"judge-{i + 1}"))
    for key_id, actor in actors:
        sk, pk = _derive_ed25519(seed, actor)
        ks.add(key_id, actor, sk, pk)
    xsk, xpk = _derive_x25519(seed, "poster-1-enc")
    ks.keys["poster-test-enc"] = {
        "actor": "poster-1", "secret_hex": xsk.hex(),
        "public_key_hex": xpk.hex(), "key_epoch": 0}
    return ks


def build_sim(seed: str = SEED) -> Sim:
    trust = make_trust(seed)
    cfg = Config(
        network="mint-sim-1", market_id="m1", mode="simulation",
        asset="SIMUSD", listen="127.0.0.1:8787", policy_id="mint-policy-1",
        trust_file="", charter_bundle="", covenant_v1_attestation="unmet")
    eng = Engine(Store(":memory:"), cfg, trust)
    sim = Sim(eng, build_keystore(seed), seed)
    return sim


@pytest.fixture()
def sim() -> Sim:
    """Bootstrapped engine: actors enrolled, accounts credited, artifacts
    published, operator reserve seeded."""
    s = build_sim()
    bootstrap(s)
    return s


def send(sim: Sim, key_id: str, op: str, args: dict, **kw):
    return sim.send(key_id, op, args, **kw)


def must(sim: Sim, key_id: str, op: str, args: dict, **kw) -> dict:
    code, resp = sim.send(key_id, op, args, **kw)
    assert code == 200, f"{op} failed: {resp}"
    return resp


def post_task(sim: Sim, task_id: str = "t1", value: str = "10000",
              **over) -> dict:
    args = {
        "task_id": task_id, "market_id": sim.e.market_id,
        "asset": sim.e.asset, "value": value,
        "execution_cap_seconds": 3600, "forecast_floor": 7000,
        "acceptance_score": 8500, "manifest_id": "art:manifest-t1",
        "rubric_id": "art:rubric-r1",
        "charter_bundle_id": "art:charter-r1", "policy_id": "mint-policy-1",
    }
    args.update(over)
    return must(sim, "poster-test", "task.post", args)


def fund_task(sim: Sim, task_id: str = "t1", **kw) -> dict:
    return must(sim, "poster-test", "task.fund",
                {"task_id": task_id, "expected_version": 1}, **kw)
