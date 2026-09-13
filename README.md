# Mint — bonded task market core

[![zone status](https://img.shields.io/badge/status-unwritten%20%E2%80%94%20gated%20behind%20Covenant%20v1-orange)](https://github.com/LatticeAG/mint)
[![profile](https://img.shields.io/badge/profile-mint--policy--1-blue)](https://github.com/LatticeAG/mint)
[![mode](https://img.shields.io/badge/mode-simulation%20only-yellow)](https://github.com/LatticeAG/mint)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![tests](https://img.shields.io/badge/conformance-TV--M--01..82-informational)](tests/)

**Tasks carry stake. Evaluators are slashable. Allocation happens in the open.**

Mint is a bonded task market — not a validator network, a yield vault, or a
leaderboard with payments attached. A poster locks the advertised task value
`V` and a conduct bond `Bp` before opening allocation. Workers reserve
independent claim bonds before bidding; the winning worker earns a
task-specific execution lease. Evaluators reserve judgment bonds `Be` before
seeing a submission and commit to evidence-backed judgments. Task allocation,
adjudication commitments, and settlement accounting are reproducible from an
open hash-chained log.

This repository contains the **open-source core**:

- the bond/escrow **state machine** (`POSTED → BONDED → CLAIMED → SUBMITTED →
  EVALUATED → SLASHED → SETTLED`, plus auction, case, and payout machines),
- the **double-entry ledger** with `available / reserved / payable /
  withdrawal_pending / legal_hold` entitlements,
- the sealed-bid **clearing engine** (quality/price/latency scoring, fairness
  band, offer ladder),
- the evaluator ceremony (sealed roster, commit/reveal judgments, R1 rubric,
  objective reruns, auditor seat),
- the **deliverable-key escrow** (X25519 + HKDF-SHA256 + ChaCha20-Poly1305,
  poster envelope released only inside an executed ACCEPT settlement),
- the **offline verifier** (`mint verify`) that replays the public log,
- the `mint` **CLI** and a deterministic **simulation harness**.

All monetary values are `SIMUSD`, an explicitly non-redeemable simulated
accounting unit. Nothing here moves real money.

## Status

Mint is **Unwritten — gated behind Covenant v1** as a product. This codebase is
the reference implementation of the *simulation profile*: it is real, tested
software, and it is not a deployed market, a custody integration, or a claim
that any launch gate has been met. Hosted, paid, and zone-gated surfaces are
documented stub interfaces that raise `NotImplementedError` with their blocking
reason — see `src/mint/stubs.py`.

## Install

```sh
pip install -e .
```

Python ≥3.11. The only runtime dependency is `cryptography` (Ed25519, X25519,
HKDF-SHA256, ChaCha20-Poly1305).

## Quick start (simulation fixture)

```sh
mint fixture export --name clean-100 --directory ./mint-fixture
mint fixture bootstrap --directory ./mint-fixture
mint config validate --file ./mint-fixture/mint.toml

# local engine: every command produces a real signed request and a real receipt
mint --config ./mint-fixture/mint.toml task post \
    --file ./mint-fixture/task-post.json --key-id poster-test
mint --config ./mint-fixture/mint.toml task fund \
    --task t1 --expected-version 1 --key-id poster-test --json

# ... bid commit/reveal, claim, submit, evaluation, settlement ...
mint log export --checkpoint cp-64 --out ./mint-fixture/log.jsonl
mint verify --log ./mint-fixture/log.jsonl --trust ./mint-fixture/trust.json \
    --artifacts ./mint-fixture/artifacts --strict
mint simulate --config ./mint-fixture/simulation.json --seed 42 --out run-42
```

`mint serve` runs the single-market sequencer over plain HTTP on the configured
listen address, exposing `POST /v1/commands` and the nine read routes. It is a
**simulation** transport; production deployment is a stub.

## Layout

| Path | Contents |
| --- | --- |
| `src/mint/engine.py` | command processing + state machines + timers |
| `src/mint/ledger.py` | double-entry postings and entitlement projections |
| `src/mint/clearing.py` | scoring, fairness band, offer ladder |
| `src/mint/rubric.py` | R1 arithmetic, quorum, disagreement review |
| `src/mint/penalty.py` | offense fractions, incident grouping, distribution |
| `src/mint/escrow.py` | deliverable-key escrow ceremony |
| `src/mint/verifier.py` | offline public-log verifier |
| `src/mint/cli.py` | `mint` command line |
| `src/mint/server.py` | simulation HTTP surface |
| `src/mint/stubs.py` | hosted/paid/zone-gated stub interfaces |
| `tests/` | conformance vectors TV-M-01..TV-M-82 plus unit tests |

## Testing

```sh
python -m pytest
```

The suite encodes every named conformance vector from the specification as an
executable test against the real engine — no skipped vectors, no approximate
money comparisons.

## License

MIT. See [LICENSE](LICENSE).
