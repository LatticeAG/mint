"""SQLite storage (ledger backend `sqlite-wal`, synchronous FULL).

All mutations run inside BEGIN IMMEDIATE transactions; a crash inside an
uncommitted transaction rolls the whole thing back, so a retried command
can only commit once.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;

CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY,
  prev TEXT NOT NULL,
  time TEXT NOT NULL,
  type TEXT NOT NULL,
  data TEXT NOT NULL,
  hash TEXT NOT NULL,
  detail_artifact_id TEXT
);

CREATE TABLE IF NOT EXISTS checkpoints (
  checkpoint_id TEXT PRIMARY KEY,
  market_id TEXT NOT NULL,
  size INTEGER NOT NULL,
  chain_head TEXT NOT NULL,
  merkle_root TEXT NOT NULL,
  time TEXT NOT NULL,
  witness_key_epoch INTEGER NOT NULL,
  signatures TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actors (
  actor TEXT PRIMARY KEY,
  principal_group TEXT NOT NULL,
  roles TEXT NOT NULL,
  encryption_key_hex TEXT,
  attestation TEXT,
  qualifications TEXT NOT NULL DEFAULT '[]',
  model_family TEXT,
  regions TEXT NOT NULL DEFAULT '[]',
  conflicts TEXT NOT NULL DEFAULT '[]',
  affiliates TEXT NOT NULL DEFAULT '[]',
  sponsors TEXT NOT NULL DEFAULT '[]',
  state TEXT NOT NULL DEFAULT 'ACTIVE',
  enrolled_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS actor_keys (
  actor TEXT NOT NULL,
  key_epoch INTEGER NOT NULL,
  public_key_hex TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'ACTIVE',
  activates_ms INTEGER,
  revoked_ms INTEGER,
  PRIMARY KEY (actor, key_epoch)
);

CREATE TABLE IF NOT EXISTS principal_groups (
  principal_group TEXT PRIMARY KEY,
  created_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
  actor TEXT NOT NULL,
  asset TEXT NOT NULL,
  available INTEGER NOT NULL DEFAULT 0,
  payable INTEGER NOT NULL DEFAULT 0,
  withdrawal_pending INTEGER NOT NULL DEFAULT 0,
  legal_hold INTEGER NOT NULL DEFAULT 0,
  version INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (actor, asset)
);

CREATE TABLE IF NOT EXISTS balances (
  account TEXT PRIMARY KEY,
  balance INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS postings (
  entry_seq INTEGER PRIMARY KEY AUTOINCREMENT,
  transaction_id TEXT NOT NULL,
  asset TEXT NOT NULL,
  debit_account TEXT NOT NULL,
  credit_account TEXT NOT NULL,
  amount INTEGER NOT NULL,
  reservation_id TEXT
);

CREATE TABLE IF NOT EXISTS reservations (
  reservation_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  task_id TEXT,
  case_id TEXT,
  kind TEXT NOT NULL,
  asset TEXT NOT NULL,
  amount INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'ACTIVE',
  created_seq INTEGER NOT NULL,
  note TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY,
  sha256 TEXT NOT NULL,
  media_type TEXT NOT NULL,
  visibility TEXT NOT NULL,
  content BLOB NOT NULL,
  owner TEXT,
  created_seq INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
  actor TEXT NOT NULL,
  key_epoch INTEGER NOT NULL,
  nonce TEXT NOT NULL,
  command_hash TEXT NOT NULL,
  PRIMARY KEY (actor, key_epoch, nonce)
);

CREATE TABLE IF NOT EXISTS idempotency (
  actor TEXT NOT NULL,
  op TEXT NOT NULL,
  idem_key TEXT NOT NULL,
  body_sha256 TEXT NOT NULL,
  response TEXT NOT NULL,
  receipt_seq INTEGER,
  PRIMARY KEY (actor, op, idem_key)
);

CREATE TABLE IF NOT EXISTS commands (
  command_id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  op TEXT NOT NULL,
  body_sha256 TEXT NOT NULL,
  receipt_seq INTEGER,
  created_seq INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL DEFAULT 1,
  terms_version INTEGER NOT NULL DEFAULT 1,
  state TEXT NOT NULL,
  outcome TEXT,
  poster TEXT NOT NULL,
  poster_group TEXT NOT NULL,
  poster_enc_key TEXT NOT NULL,
  market_id TEXT NOT NULL,
  asset TEXT NOT NULL,
  value INTEGER NOT NULL,
  execution_cap_seconds INTEGER NOT NULL,
  forecast_floor INTEGER NOT NULL,
  acceptance_score INTEGER NOT NULL,
  manifest_id TEXT NOT NULL,
  rubric_id TEXT NOT NULL,
  charter_bundle_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  qualification TEXT,
  constitution_hash TEXT NOT NULL,
  precedent_root TEXT NOT NULL,
  rubric_hash TEXT NOT NULL,
  offense_schedule_hash TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  posted_ms INTEGER NOT NULL,
  funding_deadline_ms INTEGER NOT NULL,
  funded_ms INTEGER,
  eligible_epoch INTEGER,
  auction_state TEXT,
  auction_epoch INTEGER,
  consecutive_aborts INTEGER NOT NULL DEFAULT 0,
  cancellation_open INTEGER NOT NULL DEFAULT 1,
  offer_round INTEGER NOT NULL DEFAULT 0,
  offer_id TEXT,
  offer_group TEXT,
  offer_deadline_ms INTEGER,
  claim_group TEXT,
  claim_actor TEXT,
  claimed_ms INTEGER,
  claim_pause_ms INTEGER NOT NULL DEFAULT 0,
  slot TEXT,
  price INTEGER,
  promised_latency INTEGER,
  submission_manifest_id TEXT,
  submission_hash TEXT,
  submitted_ms INTEGER,
  envelope_artifact_id TEXT,
  escrow_status TEXT,
  roster TEXT,
  roster_revealed INTEGER NOT NULL DEFAULT 0,
  access_close_ms INTEGER,
  commit_close_ms INTEGER,
  reveal_close_ms INTEGER,
  replacement_done INTEGER NOT NULL DEFAULT 0,
  evaluation TEXT,
  verdict TEXT,
  aggregate_q INTEGER,
  challenge_close_ms INTEGER,
  finality_ready INTEGER NOT NULL DEFAULT 0,
  settled_ms INTEGER,
  history_recorded INTEGER NOT NULL DEFAULT 0,
  beacon_failure INTEGER NOT NULL DEFAULT 0,
  draw_beacon_round INTEGER,
  pause_evidence TEXT
);

CREATE TABLE IF NOT EXISTS bids (
  task_id TEXT NOT NULL,
  principal_group TEXT NOT NULL,
  actor TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  slot TEXT NOT NULL,
  commitment_digest TEXT NOT NULL,
  commitment_id TEXT NOT NULL,
  revealed INTEGER NOT NULL DEFAULT 0,
  price INTEGER,
  latency INTEGER,
  salt TEXT,
  state TEXT NOT NULL DEFAULT 'COMMITTED',
  exclusion TEXT,
  score INTEGER,
  offer_round INTEGER,
  bw_reservation TEXT NOT NULL,
  c_reservation TEXT NOT NULL,
  committed_ms INTEGER NOT NULL,
  PRIMARY KEY (task_id, principal_group)
);

CREATE TABLE IF NOT EXISTS seats (
  seat_id TEXT PRIMARY KEY,
  task_id TEXT,
  case_id TEXT,
  stage TEXT NOT NULL,
  principal_group TEXT NOT NULL,
  actor TEXT NOT NULL,
  idx INTEGER NOT NULL,
  role TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'DRAWN',
  bond_reservation TEXT,
  accept_deadline_ms INTEGER,
  access_deadline_ms INTEGER,
  commit_deadline_ms INTEGER,
  committed INTEGER NOT NULL DEFAULT 0,
  commitment_digest TEXT,
  revealed INTEGER NOT NULL DEFAULT 0,
  judgment TEXT,
  fee_eligible INTEGER NOT NULL DEFAULT 0,
  replaced_by TEXT,
  assignment_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  state TEXT NOT NULL,
  offense TEXT NOT NULL,
  respondent TEXT NOT NULL,
  respondent_group TEXT,
  reservation_id TEXT NOT NULL,
  incident_id TEXT,
  claimant TEXT NOT NULL,
  claimant_group TEXT,
  claimed_loss INTEGER NOT NULL DEFAULT 0,
  evidence_ids TEXT NOT NULL,
  precedent_ids TEXT NOT NULL,
  automatic INTEGER NOT NULL DEFAULT 0,
  opened_ms INTEGER NOT NULL,
  answer_deadline_ms INTEGER,
  trial_deadline_ms INTEGER,
  appeal_close_ms INTEGER,
  supervisory_close_ms INTEGER,
  recovery_close_ms INTEGER,
  decided_order_id TEXT,
  decided_ms INTEGER,
  verdict TEXT,
  panel_stage TEXT,
  appeal_filed INTEGER NOT NULL DEFAULT 0,
  appeals_used INTEGER NOT NULL DEFAULT 0,
  selected_bps INTEGER,
  materiality INTEGER NOT NULL DEFAULT 0,
  panel TEXT,
  challenge_filed INTEGER NOT NULL DEFAULT 0,
  d_reservation TEXT,
  a_reservation TEXT
);

CREATE TABLE IF NOT EXISTS orders (
  order_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  certificate_id TEXT NOT NULL,
  outcome TEXT NOT NULL,
  decided_ms INTEGER NOT NULL,
  slash_ids TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS allegations (
  allegation_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  case_id TEXT,
  offender TEXT NOT NULL,
  offender_group TEXT,
  role TEXT NOT NULL,
  offense TEXT NOT NULL,
  reservation_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  evidence TEXT NOT NULL,
  auto INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'PROPOSED',
  penalty TEXT,
  created_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS withdrawals (
  withdrawal_id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  asset TEXT NOT NULL,
  amount INTEGER NOT NULL,
  address TEXT NOT NULL,
  instruction_id TEXT NOT NULL,
  requested_ms INTEGER NOT NULL,
  release_ms INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'PENDING',
  receipt_id TEXT
);

CREATE TABLE IF NOT EXISTS destinations (
  destination_id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'VERIFIED',
  changed_ms INTEGER,
  cooldown_until_ms INTEGER
);

CREATE TABLE IF NOT EXISTS deadlines (
  deadline_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  anchor_ms INTEGER NOT NULL,
  nominal_seconds INTEGER NOT NULL,
  pausable INTEGER NOT NULL DEFAULT 0,
  scope TEXT NOT NULL DEFAULT 'task',
  payload TEXT,
  done INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pauses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL,
  object_id TEXT,
  start_ms INTEGER NOT NULL,
  end_ms INTEGER,
  reason TEXT
);

CREATE TABLE IF NOT EXISTS outbox (
  outbox_id TEXT PRIMARY KEY,
  withdrawal_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'PENDING',
  provider_reference TEXT,
  dispatched INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rosters (
  commitment TEXT PRIMARY KEY,
  task_id TEXT,
  case_id TEXT,
  stage TEXT NOT NULL,
  mapping TEXT NOT NULL,
  revealed INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS escrow_keys (
  task_id TEXT PRIMARY KEY,
  tk_hex TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'RETAINED',
  poster_envelope TEXT,
  attestation TEXT
);

CREATE TABLE IF NOT EXISTS history (
  principal_group TEXT NOT NULL,
  task_id TEXT NOT NULL,
  observation INTEGER NOT NULL,
  settled_seq INTEGER NOT NULL,
  PRIMARY KEY (principal_group, task_id)
);

CREATE TABLE IF NOT EXISTS incidents_seen (
  task_id TEXT NOT NULL,
  reservation_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  selected_bps INTEGER NOT NULL,
  PRIMARY KEY (task_id, reservation_id, incident_id)
);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the threaded sim server shares one
        # connection across handler threads; tx() serializes writes
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.isolation_level = None  # autocommit; tx() is explicit
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def tx(self):
        """Serializable transaction; rolls back entirely on error."""
        cur = self.db.cursor()
        cur.execute("BEGIN IMMEDIATE")
        try:
            yield cur
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        finally:
            cur.close()

    # -- tiny helpers --------------------------------------------------------
    def one(self, sql: str, args: tuple = ()) -> sqlite3.Row | None:
        return self.db.execute(sql, args).fetchone()

    def all(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        return self.db.execute(sql, args).fetchall()

    def kv_get(self, key: str, default: str | None = None) -> str | None:
        row = self.one("SELECT value FROM kv WHERE key=?", (key,))
        return row["value"] if row else default

    def kv_set(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO kv(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def jdump(x) -> str:
    return json.dumps(x, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True)


def jload(text):
    return json.loads(text)
