"""Trust package: pinned keys and authority structure for the market.

The simulation trust file pins:
  - 5 witness keys (checkpoint signing + panel-escrow share holders)
  - 5 settlement custodian keys (3-of-5 execution)
  - 7 recovery-authority keys (4-of-7 control/recovery)
  - registrar key (enrollment certificates)
  - custody issuer key (deposit attestations)
  - deterministic simulation beacon key
  - panel-escrow X25519 public key (witness-held share set in production;
    local simulation holds the pinned keypair for the escrow fixture)
"""

from __future__ import annotations

import json
from pathlib import Path

from .errors import MintError
from .jsonutil import jcs
from .timeutil import parse_ts


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise MintError(2, "TRUST_INVALID", msg, False, {})


def load_trust(path: str | Path) -> dict:
    p = Path(path)
    try:
        raw = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise MintError(2, "TRUST_INVALID", f"cannot parse {p}: {e}")
    return parse_trust(raw)


def parse_trust(raw: dict) -> dict:
    for f in ("network", "market_id", "policy_id", "genesis_time",
              "genesis_seed", "witnesses", "settlement_signers",
              "recovery_authority", "authority_keys", "beacon",
              "panel_escrow"):
        _need(f in raw, f"trust file missing {f}")
    _need(len(raw["witnesses"]) == 5, "need exactly 5 pinned witnesses")
    entities = {w["entity"] for w in raw["witnesses"]}
    _need(len(entities) == 5, "witnesses must be 5 distinct entities")
    _need(len(raw["settlement_signers"]) == 5,
          "need exactly 5 settlement custodians")
    _need(len({s["entity"] for s in raw["settlement_signers"]}) == 5,
          "settlement custodians must be distinct entities")
    _need(len(raw["recovery_authority"]) == 7,
          "need exactly 7 recovery-authority signers")
    _need(len({s["entity"] for s in raw["recovery_authority"]}) == 7,
          "recovery authority must be distinct entities")
    _need(raw["beacon"].get("profile") == "deterministic-simulation-v1",
          "only the deterministic simulation beacon profile is supported")
    _need(raw["panel_escrow"].get("holder") == "witness_quorum",
          "panel escrow key must be held by the witness quorum")
    genesis_ms = parse_ts(raw["genesis_time"], "genesis_time")
    return {
        "canonical": raw,
        "network": raw["network"],
        "market_id": raw["market_id"],
        "policy_id": raw["policy_id"],
        "genesis_ms": genesis_ms,
        "genesis_seed": raw["genesis_seed"],
        "witnesses": raw["witnesses"],
        "settlement_signers": raw["settlement_signers"],
        "recovery_authority": raw["recovery_authority"],
        "authority_keys": raw["authority_keys"],
        "beacon": raw["beacon"],
        "panel_escrow": raw["panel_escrow"],
    }


def beacon_value(trust: dict, round_no: int) -> str:
    """Deterministic simulation beacon: proofs tagged `simulation`, never
    accepted by a real-money verifier."""
    from .jsonutil import domain_hash
    return domain_hash("mint.beacon.sim.v1", {
        "network": trust["network"], "market_id": trust["market_id"],
        "round": round_no, "genesis_seed": trust["genesis_seed"],
        "profile": "deterministic-simulation-v1",
    })
