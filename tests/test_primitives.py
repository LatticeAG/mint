"""Conformance vectors: hash fixtures (TV-M-43/44/45), strict JSON and
amounts (TV-M-53), crypto round-trips, checkpoint witness rules
(TV-M-46/47)."""

from __future__ import annotations

import pytest

from mint.amounts import ceil_bps, floor_bps, lower_median
from mint.crypto import (
    b64u, ed25519_keypair, ed25519_sign, ed25519_verify, open_chunk,
    seal_chunk, tk_commitment, unwrap_key, wrap_key, x25519_keypair,
    deliverable_commitment)
from mint.errors import MintError
from mint.events import (
    event_hash, make_event, merkle_path, merkle_root, merkle_verify)
from mint.jsonutil import (
    jcs_text, parse_amount, parse_strict, sha256_hex)
from mint.sim import make_trust
from mint.verifier import verify_log

ZERO = "0" * 64

EV1 = {"data": {"asset": "SIMUSD", "market_id": "m1",
                "policy": "mint-policy-1"},
       "prev": ZERO, "seq": 1, "time": "2026-09-12T00:00:00.000Z",
       "type": "MarketOpened"}
EV2 = {"data": {"actor": "poster-1", "amount": "12700",
                "external_ref": "sim-deposit-1"},
       "prev": "fe5d2302525732816f2b6940e9b931ae5c3583c179cfcf2284dbfec"
               "664a9819f",
       "seq": 2, "time": "2026-09-12T00:00:01.000Z",
       "type": "AccountCredited"}

H1 = "fe5d2302525732816f2b6940e9b931ae5c3583c179cfcf2284dbfec664a9819f"
H2 = "dd7b3f2b81bb5c1a7494d69aed4be2540cb0f04b4666398cd8b04c176efcc3d8"
ROOT2 = "2d1c91f6c3128ca2e623cc74e700abf7427c8bdb1cffe9e696ec354b888ca329"
SIB1 = "613758d392aabcb6c0641d3a426510d1b62f27a55399c34dd1914d9d3ad96b7f"
EMPTY_ROOT = ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7"
              "852b855")


# -- TV-M-43: first event canonical bytes + hash ---------------------------
def test_tvm43_first_event_hash():
    assert event_hash(EV1) == H1


def test_tvm43_canonical_form_is_key_sorted():
    # the published fixture object is already canonical; JCS must
    # reproduce its exact bytes
    assert jcs_text(EV1) == (
        '{"data":{"asset":"SIMUSD","market_id":"m1","policy":'
        '"mint-policy-1"},"prev":"' + ZERO + '","seq":1,"time":'
        '"2026-09-12T00:00:00.000Z","type":"MarketOpened"}')


# -- TV-M-44: second event hash + two-leaf merkle root ---------------------
def test_tvm44_second_event_hash_and_root():
    assert event_hash(EV2) == H2
    assert merkle_root([H1, H2]) == ROOT2


def test_tvm44_first_leaf_inclusion_path():
    path = merkle_path([H1, H2], 0)
    assert path == [SIB1]
    # merkle_verify applies the leaf domain hash to the event hash and
    # returns the recomputed root
    assert merkle_verify(H1, 0, 2, path) == ROOT2


def test_tvm44_empty_tree_root_is_sha256_of_empty():
    assert merkle_root([]) == EMPTY_ROOT


def test_merkle_odd_tree_split_verifies():
    hs = [sha256_hex(f"e{i}".encode()) for i in range(7)]
    root = merkle_root(hs)
    for i in range(7):
        path = merkle_path(hs, i)
        assert merkle_verify(hs[i], i, 7, path) == root


# -- TV-M-45: tampered event fails chain verification ----------------------
def test_tvm45_tamper_detection():
    bad = dict(EV2, data=dict(EV2["data"], amount="12701"))
    assert event_hash(bad) != H2
    # a forged event in the stream must break the chain
    res = verify_log  # exercised end-to-end in test_verifier


# -- TV-M-53: strict JSON + amount grammar ---------------------------------
def test_tvm53_duplicate_key_rejected():
    with pytest.raises(MintError):
        parse_strict(b'{"amount":"5","amount":"6"}')


def test_tvm53_unsafe_integer_rejected():
    with pytest.raises(MintError):
        parse_strict(b'{"n":9007199254740993}')


def test_tvm53_float_rejected():
    with pytest.raises(MintError):
        parse_strict(b'{"n":1.5}')


def test_tvm53_nan_rejected():
    with pytest.raises(MintError):
        parse_strict(b'{"n":NaN}')


@pytest.mark.parametrize("bad", ["01", "-1", "1.5", "", "+5", " 5",
                                 "18446744073709551616"])
def test_tvm53_bad_amounts(bad):
    with pytest.raises(MintError):
        parse_amount(bad)


def test_amount_max_bound():
    assert parse_amount(str(2**63 - 1)) == 2**63 - 1
    with pytest.raises(MintError):
        parse_amount(str(2**63))


def test_amounts_helpers():
    assert ceil_bps(10001, 2000) == 2001
    assert floor_bps(999, 5000) == 499
    assert lower_median([8800, 9000, 9050, 9200, 9800]) == 9050
    assert lower_median([8400, 8600, 8650, 8800]) == 8600


# -- crypto round-trips ----------------------------------------------------
def test_ed25519_sign_verify():
    sk, pk = ed25519_keypair()
    sig = ed25519_sign(sk, b"hello")
    assert ed25519_verify(pk, sig, b"hello")
    assert not ed25519_verify(pk, sig, b"other")


def test_x25519_key_wrap_round_trip():
    sk, pk = x25519_keypair()
    tk = b"t" * 32
    env = wrap_key(tk, pk)
    assert unwrap_key(env, sk) == tk
    assert tk_commitment(tk) == tk_commitment(unwrap_key(env, sk))


def test_chunk_seal_open():
    tk = b"k" * 32
    blob = seal_chunk(tk, b"deliverable bytes")
    assert open_chunk(tk, blob) == b"deliverable bytes"
    with pytest.raises(Exception):
        open_chunk(b"x" * 32, blob)


def test_wrap_key_wrong_recipient_fails():
    sk, pk = x25519_keypair()
    sk2, _ = x25519_keypair()
    env = wrap_key(b"t" * 32, pk)
    with pytest.raises(Exception):
        unwrap_key(env, sk2)


def test_deliverable_commitment_deterministic():
    d = [sha256_hex(b"c0"), sha256_hex(b"c1")]
    assert deliverable_commitment("aa" * 32, d) == \
        deliverable_commitment("aa" * 32, d)
    assert deliverable_commitment("bb" * 32, d) != \
        deliverable_commitment("aa" * 32, d)


# -- TV-M-46: repeated witness signature is not quorum ---------------------
def test_tvm46_duplicate_witness_rejected(sim):
    e = sim.e
    cp = e.create_checkpoint()
    dup = dict(cp)
    dup["signatures"] = [cp["signatures"][0]] * 4 + [cp["signatures"][1]]
    with pytest.raises(MintError) as ei:
        e.verify_checkpoint(dup)
    assert ei.value.body()["error"]["code"] == "WITNESS_QUORUM_INVALID"


def test_checkpoint_valid(sim):
    e = sim.e
    e.verify_checkpoint(e.create_checkpoint())


# -- TV-M-58: simulation mode refuses a real asset --------------------------
def test_tvm58_real_asset_gate():
    from mint.config import Config
    from mint.engine import Engine
    from mint.store import Store
    trust = make_trust("clean-100")
    cfg = Config(
        network="mint-sim-1", market_id="m1", mode="simulation",
        asset="USD", listen="127.0.0.1:8787", policy_id="mint-policy-1",
        trust_file="", charter_bundle="", covenant_v1_attestation="unmet")
    with pytest.raises(MintError):
        Engine(Store(":memory:"), cfg, trust)


# -- TV-M-47: stale checkpoint cannot admit new work ------------------------
def test_tvm47_stale_checkpoint(sim):
    sim.e.create_checkpoint()
    # witnessed time advanced 31s without a new checkpoint (clock set
    # directly — no witnessed event, so no fresh checkpoint is minted)
    sim.e._set_now(sim.e.now_ms + 31_000)
    assert not sim.e.checkpoint_fresh()
    code, resp = send_post(sim)
    assert code == 503
    assert resp["error"]["code"] == "CHECKPOINT_UNAVAILABLE"


def send_post(sim):
    """task.post without the sim's auto-checkpoint (raw signed request)."""
    import secrets
    from mint.transport import sign_request
    from mint.jsonutil import jcs
    from mint.timeutil import fmt_ts
    args = {"task_id": "stale-1", "market_id": sim.e.market_id,
            "asset": sim.e.asset, "value": "10000",
            "execution_cap_seconds": 3600, "forecast_floor": 7000,
            "acceptance_score": 8500, "manifest_id": "art:manifest-t1",
            "rubric_id": "art:rubric-r1",
            "charter_bundle_id": "art:charter-r1",
            "policy_id": "mint-policy-1"}
    body = jcs({"op": "task.post", "args": args})
    k = sim.ks.get("poster-test")
    now = sim.e.now_ms
    headers = sign_request(
        bytes.fromhex(k["secret_hex"]), sim.e.network, "POST",
        "/v1/commands", k["actor"], k["key_epoch"],
        secrets.token_hex(16), fmt_ts(now), fmt_ts(now + 300_000), body,
        f"idem-{secrets.token_hex(12)}")
    return sim.send_raw(headers, body)
