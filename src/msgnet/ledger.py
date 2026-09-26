"""Append-only balanced USD transfers; no balance writes outside this module."""

from dataclasses import dataclass

from msgnet.database import Database, Transaction
from msgnet.model import Conflict, Denied, identifier, integer


@dataclass(frozen=True, slots=True)
class Ledger:
    database: Database

    def balance(self, account: str) -> int:
        account = identifier(account)
        with self.database.transaction(write=False) as tx:
            result = tx.all("SELECT balance FROM accounts WHERE id=?", (account,))
            return integer(result[0][0], minimum=-(10**12)) if result else 0

    @staticmethod
    def transfer(tx: Transaction, key: str, debit: str, credit: str, cents: int) -> bool:
        """Internal use case boundary; only authenticated/authorized callers may invoke.

        False means an exact retry, not a second movement. External deposit settlement
        must verify its provider receipt before using the system clearing account.
        """
        key, debit, credit = identifier(key), identifier(debit), identifier(credit)
        cents = integer(cents, minimum=1)
        if debit == credit:
            raise Conflict("transfer endpoints must differ")
        previous = tx.all("SELECT debit,credit,amount FROM transfers WHERE id=?", (key,))
        if previous:
            if previous[0] != (debit, credit, cents):
                raise Conflict("idempotency key reused with different transfer")
            return False
        for account in (debit, credit):
            tx.execute("INSERT INTO accounts(id) VALUES(?) ON CONFLICT DO NOTHING", (account,))
        balance = integer(
            tx.one("SELECT balance FROM accounts WHERE id=?", (debit,))[0], minimum=-(10**12)
        )
        if debit != "system.clearing" and balance < cents:
            raise Denied("insufficient USD balance")
        changes = ((debit, -cents), (credit, cents))
        # Validate both sides before making either balance change.
        for account, delta in changes:
            old = integer(
                tx.one("SELECT balance FROM accounts WHERE id=?", (account,))[0], minimum=-(10**12)
            )
            integer(old + delta, minimum=-(10**12) if account == "system.clearing" else 0)
        for account, delta in changes:
            tx.execute("UPDATE accounts SET balance=balance+? WHERE id=?", (delta, account))
        tx.execute("INSERT INTO transfers VALUES(?,?,?,?)", (key, debit, credit, cents))
        return True
