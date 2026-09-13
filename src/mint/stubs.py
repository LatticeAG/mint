"""Hosted / paid / cloud / zone-gated surfaces (spec §11, §14).

Mint's open-source core ships the bond/escrow state machine, ledger,
clearing, courts, and the offline verifier. The following surfaces are
explicitly out of OSS scope: each is a documented interface that raises
NotImplementedSurface with the spec-grounded reason — never a fake
implementation.

These stubs exist so the boundary is visible and typed; calling any of
them is a hard error.
"""

from __future__ import annotations

from .errors import NotImplementedSurface


def _ni(surface: str, reason: str) -> NotImplementedSurface:
    return NotImplementedSurface(surface, reason)


class HostedMarketSurface:
    """Multi-market hosted control plane (zone-gated SaaS surface)."""

    def create_market(self, *a, **k):
        raise _ni(
            "hosted.market.create",
            "hosted market provisioning is a paid zone surface; the OSS "
            "core runs a single pinned market per §8.7 mint.toml")

    def list_markets(self, *a, **k):
        raise _ni("hosted.market.list",
                  "multi-tenant market enumeration is hosted-only")


class CustodyAdapter:
    """Real-money custody integration (segregated custodian adapter).

    §14: production custody requires the P2/P3 acceptance bundle —
    audited custodian, reserve attestation, and Covenant v1 gate. The OSS
    simulator uses only the SIMUSD fixture adapter in sim.py.
    """

    def deposit(self, *a, **k):
        raise _ni(
            "custody.deposit",
            "real-money custody is not implemented; gated behind the §14 "
            "launch acceptance bundle and an approved custodian adapter")

    def payout(self, *a, **k):
        raise _ni("custody.payout", "real-money payouts are hosted/gated")

    def attest_reserve(self, *a, **k):
        raise _ni(
            "custody.reserve_attestation",
            "independent reserve attestation requires the production "
            "custody adapter")


class WitnessNetwork:
    """Multi-operator witness network transport (production only).

    The simulation engine signs checkpoints with the five pinned
    simulation witness keys locally (trust.py). Inter-operator witnessed
    consensus transport is a deployment concern outside the OSS core.
    """

    def broadcast_checkpoint(self, *a, **k):
        raise _ni(
            "witness.broadcast",
            "inter-operator witness transport is deployment-gated; the "
            "OSS core produces pinned-key simulation checkpoints only")

    def fork_proof_exchange(self, *a, **k):
        raise _ni("witness.fork_exchange",
                  "cross-witness fork exchange is deployment-gated")


class BeaconNetwork:
    """Production randomness beacon client (e.g. drand-style).

    Simulation uses the deterministic test beacon (§5.5), whose proofs
    are tagged `simulation` and never accepted for real-money operation.
    """

    def fetch(self, *a, **k):
        raise _ni(
            "beacon.fetch",
            "a production beacon is not pinned in OSS scope; only the "
            "deterministic simulation beacon profile is supported")


class PaidDisputeSurface:
    """Human adjudication network / paid dispute resolution."""

    def open_human_case(self, *a, **k):
        raise _ni(
            "dispute.human_panel",
            "paid human adjudication panels are a hosted zone surface; "
            "the OSS courts cover the deterministic offense schedule")


class TelemetrySink:
    """Hosted metrics/observability sink (§12 counters live locally)."""

    def emit(self, *a, **k):
        raise _ni("telemetry.hosted_sink",
                  "hosted telemetry export is out of OSS scope; local "
                  "Prometheus-style counters are emitted by the engine")


class CovenantBridge:
    """Covenant v1 integration surface.

    Mint is gated behind Covenant v1 (spec status: unwritten until that
    gate is met). Attestation ingestion is deliberately not implemented.
    """

    def attest(self, *a, **k):
        raise _ni(
            "covenant.attest",
            "Covenant v1 attestation is a launch gate, not an OSS code "
            "path; covenant_v1_attestation remains 'unmet'")
