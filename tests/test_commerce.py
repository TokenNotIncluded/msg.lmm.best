import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from msgnet.commerce import Commerce
from msgnet.content import Content
from msgnet.ledger import Ledger
from msgnet.model import Conflict, Denied, Record
from msgnet.policy import Principal
from msgnet.templates import Field, Template


def test_ledger_zero_balance_idempotency_and_overdraft(content: Content) -> None:
    ledger = Ledger(content.database)
    assert ledger.balance("alice") == 0
    with content.database.transaction() as tx:
        assert ledger.transfer(tx, "provider-payment-1", "system.clearing", "alice", 100)
    with content.database.transaction() as tx:
        assert not ledger.transfer(tx, "provider-payment-1", "system.clearing", "alice", 100)
    with pytest.raises(Conflict), content.database.transaction() as tx:
        ledger.transfer(tx, "provider-payment-1", "system.clearing", "alice", 200)
    with pytest.raises(Denied), content.database.transaction() as tx:
        ledger.transfer(tx, "overspend", "alice", "bob", 101)
    assert ledger.balance("alice") == 100
    assert ledger.balance("bob") == 0
    assert ledger.balance("system.clearing") == -100
    with content.database.transaction() as tx:
        assert tx.one("SELECT sum(balance) FROM accounts")[0] == 0
        with pytest.raises(sqlite3.IntegrityError):
            tx.execute("DELETE FROM transfers")


def test_concurrent_debits_are_serialized(content: Content) -> None:
    ledger = Ledger(content.database)
    with content.database.transaction() as tx:
        ledger.transfer(tx, "fund", "system.clearing", "alice", 10)

    def spend(number: int) -> bool:
        try:
            with content.database.transaction() as tx:
                return ledger.transfer(tx, f"spend-{number}", "alice", "bob", 1)
        except Denied:
            return False

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(spend, range(20)))
    assert sum(results) == 10
    assert ledger.balance("alice") == 0
    assert ledger.balance("bob") == 10


def test_catalog_checkout_is_immutable(content: Content, root: Principal) -> None:
    template = Template(
        1,
        (
            Field("title", "string"),
            Field("price_cents", "integer"),
            Field("currency", "string", choices=("USD",)),
            Field("enabled", "boolean"),
        ),
    )
    content.topic(root, "store", template)
    fields: Record = {"title": "Membership", "price_cents": 100, "currency": "USD", "enabled": True}
    product = content.create(root, "store", b"normal catalog post", fields)
    commerce = Commerce(content.database)
    first = commerce.checkout(Principal("buyer"), product, "request-1", now=1000)
    content.edit(root, product, 1, b"changed price", {**fields, "price_cents": 200})
    retry = commerce.checkout(Principal("buyer"), product, "request-1", now=1100)
    second = commerce.checkout(Principal("buyer"), product, "request-2", now=1100)
    assert retry == first
    assert first.snapshot["fields"] == fields
    assert first.expires == 1900
    assert first.revision == 1 and second.revision == 2
    with pytest.raises(Conflict):
        commerce.checkout(Principal("buyer"), product + 1, "request-1", now=1100)
