"""Immutable checkout snapshots and durable verified payment inbox.

No provider event can grant arbitrary authority. Receipt processing/CA fulfillment
is a separate, explicitly unfinished release gate, not a fake success callback.
"""

import hashlib
import secrets
from dataclasses import dataclass

from msgnet.database import Database
from msgnet.model import Conflict, Invalid, Record, decode, encode, identifier, integer, text
from msgnet.policy import Principal


@dataclass(frozen=True, slots=True)
class Checkout:
    id: str
    buyer: str
    product: int
    revision: int
    snapshot: Record
    expires: int

    def record(self) -> Record:
        return {
            "id": self.id,
            "buyer": self.buyer,
            "product": self.product,
            "revision": self.revision,
            "snapshot": self.snapshot,
            "expires": self.expires,
        }


@dataclass(frozen=True, slots=True)
class Commerce:
    database: Database
    checkout_ttl: int = 900

    def checkout(self, actor: Principal, product: int, key: str, *, now: int) -> Checkout:
        integer(product, minimum=1)
        integer(now)
        integer(self.checkout_ttl, minimum=60, maximum=3600)
        key = identifier(key)
        with self.database.transaction() as tx:
            previous = tx.all(
                "SELECT id,product,revision,snapshot,expires FROM orders "
                "WHERE buyer=? AND request_key=?",
                (actor.subject, key),
            )
            if previous:
                row = previous[0]
                if row[1] != product:
                    raise Conflict("idempotency key reused with another product")
                return Checkout(
                    text(row[0]),
                    actor.subject,
                    product,
                    integer(row[2]),
                    decode(text(row[3], maximum=65536).encode()),
                    integer(row[4]),
                )
            row = tx.one(
                "SELECT p.version,r.fields,p.author FROM posts p JOIN revisions r "
                "ON r.post=p.id AND r.version=p.version "
                "WHERE p.id=? AND p.topic='store' AND p.archived=0",
                (product,),
            )
            fields = decode(text(row[1], maximum=65536).encode())
            integer(fields.get("price_cents"), minimum=1)
            if fields.get("currency") != "USD" or fields.get("enabled") is not True:
                raise Invalid("product is not purchasable")
            # Data is snapshotted, not treated as executable fulfillment instructions.
            snapshot: Record = {"fields": fields, "seller": text(row[2])}
            order = Checkout(
                secrets.token_hex(16),
                actor.subject,
                product,
                integer(row[0]),
                snapshot,
                now + self.checkout_ttl,
            )
            tx.execute(
                "INSERT INTO orders VALUES(?,?,?,?,?,?,?)",
                (
                    order.id,
                    actor.subject,
                    product,
                    order.revision,
                    encode(snapshot).decode(),
                    order.expires,
                    key,
                ),
            )
            return order

    def accept_receipt(self, event: Record, raw: bytes, *, now: int) -> bool:
        """Only called AFTER provider signature/store/environment validation.

        Receipt and work item commit together. This method deliberately does not
        report a paid order or issue a certificate based solely on event arrival.
        """
        integer(now)
        key = ":".join(
            identifier(event.get(field)) for field in ("mode", "storeId", "eventType", "eventId")
        )
        digest = hashlib.sha256(raw).hexdigest()
        with self.database.transaction() as tx:
            previous = tx.all("SELECT digest FROM receipts WHERE id=?", (key,))
            if previous:
                if previous[0][0] != digest:
                    raise Conflict("provider event ID reused with different content; reconcile")
                return False
            tx.execute("INSERT INTO receipts VALUES(?,?,?,?)", (key, digest, raw, now))
            tx.execute("INSERT INTO outbox(id,available) VALUES(?,?)", (key, now))
            return True
