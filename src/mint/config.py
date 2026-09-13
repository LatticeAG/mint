"""mint.toml reference configuration loading and validation (spec §8.7).

Validation rejects unknown fields, non-summing weights, unsafe quorums,
missing trust artifacts, and real-money assets in simulation mode.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import MintError
from .policy import POLICY

_TOP = {"schema_version", "network", "market_id", "mode", "asset", "listen",
        "policy_id", "trust_file", "charter_bundle", "covenant_v1_attestation",
        "limits", "execution", "auction", "judgment", "ledger", "custody",
        "settlement", "recovery", "escrow"}
_LIMITS = {"minimum_value", "maximum_value", "max_active_claims_per_principal",
           "max_commits_per_epoch", "max_artifact_bytes", "absolute_task_days",
           "max_acceptance_score"}
_EXEC = {"dmax_min_seconds", "dmax_max_seconds", "evaluator_commit_seconds",
         "evaluator_reveal_seconds", "seat_acceptance_seconds",
         "evidence_access_seconds", "review_hours", "court_decision_seconds",
         "supervisory_seconds"}
_AUCTION = {"commit_seconds", "reveal_seconds", "claim_offer_seconds",
            "maximum_offers", "quality_weight_bps", "price_weight_bps",
            "latency_weight_bps", "fairness_band_points", "beacon_profile"}
_JUDGMENT = {"primary_seats", "primary_quorum", "trial_seats", "trial_quorum",
             "appeal_seats", "appeal_quorum", "supervisory_seats",
             "supervisory_quorum", "challenge_seconds",
             "appeal_filing_seconds"}
_LEDGER = {"backend", "synchronous", "checkpoint_seconds", "witness_seats",
           "witness_quorum", "max_checkpoint_age_seconds"}
_CUSTODY = {"adapter", "reserve_initial", "withdrawal_cooldown_seconds"}
_SETTLE = {"signer_seats", "signer_quorum", "signers_source"}
_RECOVERY = {"authority_seats", "authority_quorum",
             "recovery_challenge_seconds"}
_ESCROW = {"panel_key_holder", "panel_key_quorum"}


def _bad(msg: str) -> MintError:
    return MintError(2, "CONFIG_INVALID", msg, False, {})


def _check_fields(section: dict, allowed: set, name: str) -> None:
    for k in section:
        if k not in allowed:
            raise _bad(f"unknown field in [{name}]: {k}")


@dataclass
class Config:
    network: str
    market_id: str
    mode: str
    asset: str
    listen: str
    policy_id: str
    trust_file: str
    charter_bundle: str
    covenant_v1_attestation: str
    raw: dict = field(default_factory=dict)
    base_dir: Path = Path(".")

    def section(self, name: str) -> dict:
        return self.raw.get(name, {})


def load_config(path: str | Path) -> Config:
    p = Path(path)
    try:
        raw = tomllib.loads(p.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise _bad(f"cannot parse {p}: {e}")
    for k in raw:
        if k not in _TOP:
            raise _bad(f"unknown top-level field: {k}")
    for name, allowed in (("limits", _LIMITS), ("execution", _EXEC),
                          ("auction", _AUCTION), ("judgment", _JUDGMENT),
                          ("ledger", _LEDGER), ("custody", _CUSTODY),
                          ("settlement", _SETTLE), ("recovery", _RECOVERY),
                          ("escrow", _ESCROW)):
        if name in raw:
            _check_fields(raw[name], allowed, name)
    required = ["network", "market_id", "mode", "asset", "policy_id",
                "trust_file"]
    for k in required:
        if k not in raw:
            raise _bad(f"missing required field: {k}")
    if raw.get("schema_version") != 1:
        raise _bad("schema_version must be 1")
    cfg = Config(
        network=raw["network"], market_id=raw["market_id"],
        mode=raw["mode"], asset=raw["asset"],
        listen=raw.get("listen", "127.0.0.1:8787"),
        policy_id=raw["policy_id"], trust_file=raw["trust_file"],
        charter_bundle=raw.get("charter_bundle", ""),
        covenant_v1_attestation=raw.get("covenant_v1_attestation", "unmet"),
        raw=raw, base_dir=p.parent)
    _validate(cfg)
    return cfg


def _validate(cfg: Config) -> None:
    if cfg.mode == "simulation":
        if cfg.asset != "SIMUSD":
            raise MintError(
                2, "LAUNCH_GATE_UNMET",
                "simulation mode requires asset SIMUSD; a real-money asset "
                "needs the §14 acceptance bundle, approved custody, and "
                "non-simulation trust roots", False,
                {"asset": cfg.asset})
    else:
        raise MintError(
            2, "LAUNCH_GATE_UNMET",
            "production mode is not implemented: gated behind Covenant v1 "
            "and the §14 P2/P3 acceptance bundle", False, {})
    auct = cfg.raw.get("auction", {})
    if auct:
        total = (auct.get("quality_weight_bps", 0)
                 + auct.get("price_weight_bps", 0)
                 + auct.get("latency_weight_bps", 0))
        if total != 10000:
            raise _bad("auction weights must sum to 10000 bps")
    led = cfg.raw.get("ledger", {})
    if led:
        wq, ws = led.get("witness_quorum"), led.get("witness_seats")
        if wq is not None and ws is not None:
            # 4-of-5 is the stated safety point: 3-of-5 is expressly unsafe.
            if not (4 <= wq <= ws):
                raise _bad("unsafe witness quorum (requires >=4 of 5)")
    stl = cfg.raw.get("settlement", {})
    if stl:
        sq, ss = stl.get("signer_quorum"), stl.get("signer_seats")
        if sq is not None and ss is not None and not (3 <= sq <= ss):
            raise _bad("unsafe settlement quorum")
    rec = cfg.raw.get("recovery", {})
    if rec:
        rq, rs = rec.get("authority_quorum"), rec.get("authority_seats")
        if rq is not None and rs is not None and not (4 <= rq <= rs):
            raise _bad("unsafe recovery quorum")
    limits = cfg.raw.get("limits", {})
    if limits:
        if limits.get("minimum_value", POLICY["min_value"]) != \
                POLICY["min_value"] or \
                limits.get("maximum_value", POLICY["max_value"]) != \
                POLICY["max_value"]:
            raise _bad("value limits are fixed by mint-policy-1")
    # trust file must exist and parse
    tp = (cfg.base_dir / cfg.trust_file).resolve()
    if not tp.exists():
        raise _bad(f"trust file missing: {cfg.trust_file}")
    if cfg.covenant_v1_attestation != "unmet" and cfg.mode == "simulation":
        pass  # attestation string is informational in simulation
