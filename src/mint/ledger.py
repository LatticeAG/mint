"""Double-entry ledger (spec §9.1).

Asset accounts increase on debit; liability/entitlement accounts increase on
credit. Every transaction posts balanced entries; balances are projections
of posted entries and may never go negative.

Account naming:
  custody:cash:{asset}          backing asset held by the custodian (asset)
  acct:{actor}:{asset}:available|payable|withdrawal_pending|legal_hold
  res:{reservation_id}          task/case reservation liability
  op:revenue:{asset}            platform revenue (operator-owned)
  op:reserve:{asset}            operator reserve pool (operator-owned)
  op:receivable:{asset}         custodian credit-risk receivable (asset)
  trust:redress:{asset}         segregated redress reserve (trust-owned)
"""

from __future__ import annotations

from .errors import MintError
from .jsonutil import sha256_hex
from .store import Store, jload, jdump

ASSET_ACCTS = ("custody:cash:", "op:receivable:")


def is_asset(account: str) -> bool:
    return any(account.startswith(p) for p in ASSET_ACCTS)


class Ledger:
    def __init__(self, store: Store):
        self.s = store

    # -- account helpers ------------------------------------------------------
    def balance(self, account: str) -> int:
        row = self.s.one("SELECT balance FROM balances WHERE account=?",
                         (account,))
        return row["balance"] if row else 0

    def _add(self, account: str, delta: int) -> None:
        bal = self.balance(account) + delta
        if bal < 0:
            raise MintError(422, "LEDGER_UNDERFLOW",
                            f"account {account} would go negative",
                            details={"account": account})
        self.s.db.execute(
            "INSERT INTO balances(account,balance) VALUES(?,?) "
            "ON CONFLICT(account) DO UPDATE SET balance=excluded.balance",
            (account, bal),
        )

    def post(self, txn: str, asset: str, debit: str, credit: str,
             amount: int, reservation_id: str | None = None) -> None:
        """Post one balanced entry: debit `debit`, credit `credit`."""
        if amount < 0:
            raise MintError(400, "MALFORMED", "negative posting")
        if amount == 0:
            return
        self.s.db.execute(
            "INSERT INTO postings(transaction_id,asset,debit_account,"
            "credit_account,amount,reservation_id) VALUES(?,?,?,?,?,?)",
            (txn, asset, debit, credit, amount, reservation_id),
        )
        # debit increases assets, decreases liabilities; credit the reverse.
        self._add(debit, amount if is_asset(debit) else -amount)
        self._add(credit, -amount if is_asset(credit) else amount)

    # -- actor-facing helpers -------------------------------------------------
    @staticmethod
    def acct(actor: str, asset: str, bucket: str = "available") -> str:
        return f"acct:{actor}:{asset}:{bucket}"

    @staticmethod
    def res(reservation_id: str) -> str:
        return f"res:{reservation_id}"

    def available(self, actor: str, asset: str) -> int:
        return self.balance(self.acct(actor, asset, "available"))

    def credit_deposit(self, txn: str, actor: str, asset: str,
                       amount: int) -> None:
        self.post(txn, asset, f"custody:cash:{asset}",
                  self.acct(actor, asset, "available"), amount)

    def reserve(self, txn: str, actor: str, asset: str, amount: int,
                reservation_id: str) -> None:
        if self.available(actor, asset) < amount:
            from .errors import insufficient
            raise insufficient(amount, self.available(actor, asset))
        self.post(txn, asset, self.acct(actor, asset, "available"),
                  self.res(reservation_id), amount, reservation_id)

    def release(self, txn: str, actor: str, asset: str, amount: int,
                reservation_id: str) -> None:
        self.post(txn, asset, self.res(reservation_id),
                  self.acct(actor, asset, "available"), amount,
                  reservation_id)

    def transfer_res(self, txn: str, reservation_id: str, to_account: str,
                     asset: str, amount: int) -> None:
        self.post(txn, asset, self.res(reservation_id), to_account, amount,
                  reservation_id)

    def move(self, txn: str, asset: str, src: str, dst: str, amount: int,
             reservation_id: str | None = None) -> None:
        """Debit src, credit dst — a value move between named accounts."""
        self.post(txn, asset, src, dst, amount, reservation_id)

    def slash_to_burned(self, txn: str, owner: str, asset: str,
                        amount: int, reservation_id: str) -> None:
        """Forfeit a reservation into the burn/distribution account."""
        self.post(txn, asset, self.res(reservation_id),
                  f"sys:burned:{asset}", amount, reservation_id)

    def pay_out(self, txn: str, poster: str, worker: str, asset: str,
                amount: int, task_id: str) -> None:
        """Pay the worker price out of the poster's available balance."""
        self.post(txn, asset, self.acct(poster, asset, "available"),
                  self.acct(worker, asset, "available"), amount)

    def pending_bucket(self, actor: str, asset: str) -> str:
        return self.acct(actor, asset, "withdrawal_pending")

    # -- conservation ---------------------------------------------------------
    def conservation(self, asset: str) -> dict:
        """custody assets == user entitlements + operator + trust (§9.1)."""
        assets = 0
        liabilities = 0
        for row in self.s.all("SELECT account,balance FROM balances"):
            acct, bal = row["account"], row["balance"]
            if not acct.endswith(f":{asset}") and ":" not in acct.split(":")[-1]:
                pass
            if is_asset(acct):
                assets += bal
            else:
                liabilities += bal
        return {"assets": assets, "liabilities": liabilities,
                "balanced": assets == liabilities}

    def total_reserved(self, actor: str, asset: str) -> int:
        row = self.s.one(
            "SELECT COALESCE(SUM(amount),0) AS t FROM reservations "
            "WHERE owner=? AND asset=? AND state='ACTIVE'",
            (actor, asset),
        )
        return int(row["t"])

    def txn_id(self, command_id: str, seq: int) -> str:
        return sha256_hex(
            f"mint.txn.v1\0{command_id}:{seq}".encode())[:32]
