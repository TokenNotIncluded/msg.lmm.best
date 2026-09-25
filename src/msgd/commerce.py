"""Data-driven paid products, balances, Waffo checkout, and certificate fulfillment."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from msgd.config import Config
from msgd.crypto import (
    canonical_json,
    certificate_payload,
    make_certificate,
    parse_certificate,
    public_identity,
)
from msgd.store import Post, Store, StoreError
from msgd.templates import TopicTemplateService

WAFFO_CHECKOUT_PATH = "/v1/actions/checkout/create-session"
WAFFO_WEBHOOK_PAST_TOLERANCE_MS = 45 * 60 * 1000
WAFFO_WEBHOOK_FUTURE_TOLERANCE_MS = 60 * 1000

WAFFO_TEST_WEBHOOK_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnmRY6yMMA3lVqmAU6ZG
b1sjL/+r/z6E+ZjkXaDAKiqOhk9rpazni0bNsGXwmftTPk9jy2wn+j6JHODD/WH/
SCnSfvKkLIjy4Hk7BuCgB174C0ydan7J+KgXLkOwgCAxxB68t2tezldwo74ZpXgn
F49opzMvQ9prEwIAWOE+kV9iK6gx/AckSMtHIHpUesoPDkldpmFHlB2qpf1vsFTZ
5kD6DmGl+2GIVK01aChy2lk8pLv0yUMu18v44sLkO5M44TkGPJD9qG09wrvVG2wp
OTVCn1n5pP8P+HRLcgzbUB3OlZVfdFurn6EZwtyL4ZD9kdkQ4EZE/9inKcp3c1h4
xwIDAQAB
-----END PUBLIC KEY-----
"""

WAFFO_PROD_WEBHOOK_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz+xApdTIb4ua+DgZKQ54
iBsD82ybyhGCLRETONW4Jgbb3A8DUM1LqBk6r/CmTOCHqLalTQHNigvP3R5zkDNX
iRJz6gA4MJ/+8K0+mnEE2RISQzN+Qu65TNd6svb+INm/kMaftY4uIXr6y6kchtTJ
dwnQhcKdAL2v7h7IFnkVelQsKxDdb2PqX8xX/qwd01iXvMcpCCaXovUwZsxH2QN5
ZKBTseJivbhUeyJCco4fdUyxOMHe2ybCVhyvim2uxAl1nkvL5L8RCWMCAV55LLo0
9OhmLahz/DYNu13YLVP6dvIT09ZFBYU6Owj1NxdinTynlJCFS9VYwBgmftosSE1U
dwIDAQAB
-----END PUBLIC KEY-----
"""


def _money_cents(value: object) -> int:
    if isinstance(value, bool):
        raise StoreError("price_usd must be numeric", 400)
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError) as exc:
        raise StoreError("price_usd must be a valid decimal amount", 400) from exc
    if amount < Decimal("0.01"):
        raise StoreError("price_usd must be at least 0.01", 400)
    cents = int(amount * 100)
    if cents > 100_000_000_00:
        raise StoreError("price_usd is too large", 400)
    return cents


def _money_text(cents: int) -> str:
    return f"{Decimal(cents) / Decimal(100):.2f}"


def _pem_or_file(value: str) -> bytes:
    text = value.strip()
    if "-----BEGIN" in text:
        return text.encode()
    if not text:
        raise StoreError("missing configured key", 503)
    path = Path(text)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise StoreError(f"unable to read configured key: {path}", 503) from exc


class CommerceService:
    """Commerce state is local; /store posts are the product catalog.

    Waffo is only the payment rail. Product price, billing alias and fulfillment
    are read from the signed /store post snapshot and persisted with the purchase.
    """

    def __init__(self, cfg: Config, store: Store, templates: TopicTemplateService) -> None:
        self.cfg = cfg
        self.store = store
        self.templates = templates
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            cfg.database,
            check_same_thread=False,
            isolation_level=None,
            timeout=15.0,
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS commerce_balances (
                    author_id TEXT PRIMARY KEY,
                    cents     INTEGER NOT NULL DEFAULT 0,
                    updated   REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS commerce_ledger (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    author_id TEXT NOT NULL,
                    delta     INTEGER NOT NULL,
                    reason    TEXT NOT NULL,
                    ref       TEXT NOT NULL DEFAULT '',
                    created   REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS commerce_ledger_author
                    ON commerce_ledger(author_id, id DESC);

                CREATE TABLE IF NOT EXISTS commerce_purchases (
                    id                  TEXT PRIMARY KEY,
                    product_post_id     INTEGER NOT NULL,
                    product_snapshot    TEXT NOT NULL,
                    buyer_id            TEXT NOT NULL,
                    buyer_key           TEXT NOT NULL,
                    amount_cents        INTEGER NOT NULL,
                    currency            TEXT NOT NULL,
                    billing             TEXT NOT NULL,
                    provider_product_id TEXT NOT NULL,
                    provider_session_id TEXT NOT NULL DEFAULT '',
                    provider_order_id   TEXT NOT NULL DEFAULT '',
                    checkout_url        TEXT NOT NULL DEFAULT '',
                    status              TEXT NOT NULL,
                    expires_at          REAL NOT NULL,
                    period_end          REAL,
                    created             REAL NOT NULL,
                    updated             REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS commerce_purchase_buyer
                    ON commerce_purchases(buyer_id, created DESC);
                CREATE INDEX IF NOT EXISTS commerce_purchase_session
                    ON commerce_purchases(provider_session_id);
                CREATE INDEX IF NOT EXISTS commerce_purchase_order
                    ON commerce_purchases(provider_order_id);

                CREATE TABLE IF NOT EXISTS commerce_events (
                    event_id   TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    purchase_id TEXT NOT NULL DEFAULT '',
                    payload    TEXT NOT NULL,
                    created    REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS commerce_fulfillments (
                    purchase_id TEXT NOT NULL,
                    period_key  TEXT NOT NULL,
                    action_index INTEGER NOT NULL,
                    action_type TEXT NOT NULL,
                    result      TEXT NOT NULL,
                    created     REAL NOT NULL,
                    PRIMARY KEY(purchase_id, period_key, action_index)
                );
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.commerce_enabled)

    def balance(self, author_id: str) -> dict[str, object]:
        with self._lock:
            row = self._conn.execute(
                "SELECT cents, updated FROM commerce_balances WHERE author_id = ?",
                (author_id,),
            ).fetchone()
        cents = int(row["cents"]) if row is not None else 0
        return {
            "author_id": author_id,
            "currency": "USD",
            "cents": cents,
            "balance": _money_text(cents),
            "updated": round(float(row["updated"]), 3) if row is not None else None,
        }

    def credit_balance(self, author_id: str, cents: int, *, reason: str, ref: str = "") -> int:
        if cents == 0:
            return int(self.balance(author_id)["cents"])
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO commerce_balances(author_id, cents, updated)
                VALUES (?, ?, ?)
                ON CONFLICT(author_id) DO UPDATE SET
                    cents = commerce_balances.cents + excluded.cents,
                    updated = excluded.updated
                """,
                (author_id, cents, now),
            )
            self._conn.execute(
                """
                INSERT INTO commerce_ledger(author_id, delta, reason, ref, created)
                VALUES (?, ?, ?, ?, ?)
                """,
                (author_id, cents, reason[:120], ref[:200], now),
            )
            row = self._conn.execute(
                "SELECT cents FROM commerce_balances WHERE author_id = ?",
                (author_id,),
            ).fetchone()
        assert row is not None
        return int(row["cents"])

    def product(self, post_id: int) -> dict[str, Any]:
        post = self.store.get_post(post_id)
        if post is None or post.board != "store" or post.reply_to is not None:
            raise StoreError("store product not found", 404)
        values = self.templates.decode_body("store", post.body)
        if values is None:
            raise StoreError("store product does not match the current /store template", 409)
        if not bool(values.get("active", True)):
            raise StoreError("store product is inactive", 409)
        cents = _money_cents(values.get("price_usd"))
        billing = str(values.get("billing") or "one_time").strip().lower()
        if not billing:
            raise StoreError("store product billing alias is empty", 400)
        fulfillment = values.get("fulfillment")
        self._normalize_fulfillment(fulfillment)
        provider_product_id = self._provider_product_id(billing)
        ttl = values.get("checkout_ttl_seconds", self.cfg.commerce_checkout_ttl_seconds)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not (60 <= ttl <= 86_400):
            raise StoreError("checkout_ttl_seconds must be 60..86400", 400)
        return {
            "post": post,
            "fields": values,
            "amount_cents": cents,
            "amount": _money_text(cents),
            "currency": "USD",
            "billing": billing,
            "provider_product_id": provider_product_id,
            "checkout_ttl_seconds": ttl,
        }

    def _provider_product_id(self, billing: str) -> str:
        if billing == "one_time":
            product_id = self.cfg.waffo_onetime_product_id
        else:
            product_id = self.cfg.waffo_subscription_product_map.get(billing, "")
        if not product_id:
            raise StoreError(
                f"no Waffo product configured for billing alias {billing!r}",
                503,
            )
        return product_id

    def _normalize_fulfillment(self, raw: object) -> list[dict[str, Any]]:
        if not isinstance(raw, list) or not raw:
            raise StoreError("fulfillment must be a non-empty JSON array", 400)
        if len(raw) > 32:
            raise StoreError("fulfillment has too many actions", 400)
        result: list[dict[str, Any]] = []
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                raise StoreError(f"fulfillment[{index}] must be an object", 400)
            kind = item.get("type")
            if kind == "certificate":
                grants = item.get("grants")
                if not isinstance(grants, list) or not grants:
                    raise StoreError(f"fulfillment[{index}].grants is required", 400)
                compact: list[dict[str, Any]] = []
                for grant in grants:
                    if not isinstance(grant, dict):
                        raise StoreError("certificate grant must be an object", 400)
                    scope = grant.get("scope")
                    actions = grant.get("actions")
                    if not isinstance(scope, str) or not scope:
                        raise StoreError("certificate grant scope is required", 400)
                    if (
                        not isinstance(actions, list)
                        or not actions
                        or not all(isinstance(action, str) for action in actions)
                    ):
                        raise StoreError("certificate grant actions are required", 400)
                    denied = set(actions) - self.cfg.commerce_allowed_grant_action_set
                    if denied:
                        raise StoreError(
                            f"commerce fulfillment action is not allowed: {sorted(denied)}",
                            403,
                        )
                    compact.append({"scope": scope, "actions": sorted(set(actions))})
                duration = item.get("duration", "period")
                if duration != "period" and (
                    isinstance(duration, bool)
                    or not isinstance(duration, int)
                    or not (60 <= duration <= 366 * 86_400)
                ):
                    raise StoreError(
                        "certificate duration must be 'period' or 60..31622400 seconds",
                        400,
                    )
                result.append(
                    {
                        "type": "certificate",
                        "grants": compact,
                        "duration": duration,
                    }
                )
            elif kind == "balance":
                cents = _money_cents(item.get("amount_usd"))
                result.append({"type": "balance", "amount_cents": cents})
            else:
                raise StoreError(f"unsupported fulfillment type: {kind!r}", 400)
        return result

    def create_checkout(self, *, buyer_key: str, buyer_id: str, product_id: int) -> dict[str, Any]:
        if not self.enabled:
            raise StoreError("commerce is disabled", 503)
        canonical_key, expected_id = public_identity(buyer_key)
        if expected_id != buyer_id:
            raise StoreError("buyer identity mismatch", 400)
        product = self.product(product_id)
        post = product["post"]
        assert isinstance(post, Post)
        fields = product["fields"]
        assert isinstance(fields, dict)
        purchase_id = secrets.token_hex(16)
        now = time.time()
        ttl = int(product["checkout_ttl_seconds"])
        expires_at = now + ttl
        snapshot = {
            "post_id": post.id,
            "post_updated": round(post.updated, 3),
            "seller_id": post.author_id,
            "fields": fields,
            "amount_cents": product["amount_cents"],
            "currency": "USD",
            "billing": product["billing"],
        }
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO commerce_purchases(
                    id, product_post_id, product_snapshot, buyer_id, buyer_key,
                    amount_cents, currency, billing, provider_product_id,
                    status, expires_at, created, updated
                ) VALUES (?, ?, ?, ?, ?, ?, 'USD', ?, ?, 'creating', ?, ?, ?)
                """,
                (
                    purchase_id,
                    post.id,
                    canonical_json(snapshot),
                    buyer_id,
                    canonical_key,
                    int(product["amount_cents"]),
                    str(product["billing"]),
                    str(product["provider_product_id"]),
                    expires_at,
                    now,
                    now,
                ),
            )
        try:
            checkout = self._waffo_checkout(
                purchase_id=purchase_id,
                buyer_id=buyer_id,
                product=product,
            )
        except Exception:
            with self._lock, self._conn:
                self._conn.execute(
                    "UPDATE commerce_purchases SET status='failed', updated=? WHERE id=?",
                    (time.time(), purchase_id),
                )
            raise
        session_id = str(checkout.get("sessionId") or "")
        checkout_url = str(checkout.get("checkoutUrl") or checkout.get("checkoutURL") or "")
        provider_expires = checkout.get("expiresAt")
        if not session_id or not checkout_url:
            raise StoreError("Waffo checkout response is missing sessionId/checkoutUrl", 502)
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE commerce_purchases
                   SET provider_session_id=?, checkout_url=?, status='pending', updated=?
                 WHERE id=?
                """,
                (session_id, checkout_url, time.time(), purchase_id),
            )
        return {
            "purchase_id": purchase_id,
            "product": post.id,
            "amount": product["amount"],
            "currency": "USD",
            "billing": product["billing"],
            "checkout_url": checkout_url,
            "expires_at": provider_expires or round(expires_at, 3),
        }

    def _waffo_checkout(
        self,
        *,
        purchase_id: str,
        buyer_id: str,
        product: dict[str, Any],
    ) -> dict[str, Any]:
        private_key = serialization.load_pem_private_key(
            _pem_or_file(self.cfg.waffo_private_key),
            password=None,
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise StoreError("Waffo merchant key must be RSA", 503)
        payload = {
            "productId": str(product["provider_product_id"]),
            "currency": "USD",
            "priceSnapshot": {
                "amount": str(product["amount"]),
                "taxCategory": self.cfg.waffo_tax_category,
            },
            "expiresInSeconds": int(product["checkout_ttl_seconds"]),
            "metadata": {
                "msgPurchaseId": purchase_id,
                "msgBuyerId": buyer_id,
                "msgProductPostId": str(product["post"].id),
            },
            "orderMerchantExternalId": f"msg:{purchase_id}",
        }
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode()
        timestamp = str(int(time.time()))
        digest = base64.b64encode(hashlib.sha256(body).digest()).decode()
        canonical = f"POST\n{WAFFO_CHECKOUT_PATH}\n{timestamp}\n{digest}".encode()
        signature = base64.b64encode(
            private_key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
        ).decode()
        request = urllib.request.Request(
            self.cfg.waffo_base_url.rstrip("/") + WAFFO_CHECKOUT_PATH,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Merchant-Id": self.cfg.waffo_merchant_id,
                "X-Timestamp": timestamp,
                "X-Signature": signature,
                "X-Idempotency-Key": purchase_id,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", "replace")[:1000]
            finally:
                exc.close()
            raise StoreError(f"Waffo checkout rejected request: {detail}", 502) from exc
        except OSError as exc:
            raise StoreError("Waffo checkout is unavailable", 502) from exc
        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StoreError("Waffo returned invalid JSON", 502) from exc
        if not isinstance(envelope, dict):
            raise StoreError("Waffo returned an invalid response", 502)
        errors = envelope.get("errors")
        if errors:
            raise StoreError(f"Waffo checkout error: {errors}", 502)
        data = envelope.get("data")
        if not isinstance(data, dict):
            raise StoreError("Waffo checkout response is missing data", 502)
        return data

    def verify_waffo_webhook(self, payload: bytes, signature_header: str) -> dict[str, Any]:
        if not signature_header:
            raise StoreError("missing X-Waffo-Signature", 401)
        timestamp = ""
        signature_b64 = ""
        for part in signature_header.split(","):
            key, sep, value = part.strip().partition("=")
            if not sep:
                continue
            if key == "t":
                timestamp = value
            elif key == "v1":
                signature_b64 = value
        if not timestamp or not signature_b64:
            raise StoreError("malformed X-Waffo-Signature", 401)
        try:
            ts = int(timestamp)
        except ValueError as exc:
            raise StoreError("invalid Waffo webhook timestamp", 401) from exc
        age = int(time.time() * 1000) - ts
        if age > WAFFO_WEBHOOK_PAST_TOLERANCE_MS or age < -WAFFO_WEBHOOK_FUTURE_TOLERANCE_MS:
            raise StoreError("Waffo webhook timestamp outside tolerance", 401)
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except ValueError as exc:
            raise StoreError("invalid Waffo webhook signature encoding", 401) from exc
        signed = timestamp.encode() + b"." + payload
        configured = self.cfg.waffo_webhook_public_key.strip()
        candidates = (
            [_pem_or_file(configured)]
            if configured
            else [WAFFO_PROD_WEBHOOK_KEY.encode(), WAFFO_TEST_WEBHOOK_KEY.encode()]
        )
        verified = False
        for pem in candidates:
            try:
                key = serialization.load_pem_public_key(pem)
                if not isinstance(key, rsa.RSAPublicKey):
                    continue
                key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
                verified = True
                break
            except (ValueError, TypeError, InvalidSignature):
                continue
        if not verified:
            raise StoreError("invalid Waffo webhook signature", 401)
        try:
            event = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise StoreError("invalid Waffo webhook JSON", 400) from exc
        if not isinstance(event, dict):
            raise StoreError("invalid Waffo webhook payload", 400)
        return event

    def handle_waffo_webhook(self, payload: bytes, signature_header: str) -> dict[str, Any]:
        event = self.verify_waffo_webhook(payload, signature_header)
        event_id = str(event.get("id") or event.get("eventId") or "")
        event_type = str(event.get("eventType") or "")
        if not event_id or not event_type:
            raise StoreError("Waffo webhook is missing id/eventType", 400)
        data = event.get("data")
        if not isinstance(data, dict):
            data = {}
        external_id = data.get("orderMerchantExternalId")
        if not isinstance(external_id, str) or not external_id.startswith("msg:"):
            purchase_id = ""
        else:
            purchase_id = external_id[4:]
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT 1 FROM commerce_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if existing is not None:
                return {"ok": 1, "duplicate": True, "event_id": event_id}
            self._conn.execute(
                """
                INSERT INTO commerce_events(event_id, event_type, purchase_id, payload, created)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_id, event_type, purchase_id, payload.decode("utf-8"), time.time()),
            )
        if not purchase_id:
            return {"ok": 1, "ignored": True, "event_id": event_id}

        row = self._purchase(purchase_id)
        if row is None:
            raise StoreError("unknown commerce purchase", 404)

        order_id = str(data.get("orderId") or "")
        period_end = self._period_end(data.get("currentPeriodEnd"))
        success_events = {
            "order.completed",
            "subscription.activated",
            "subscription.renewed",
            "subscription.recovered",
        }
        if event_type in success_events:
            with self._lock, self._conn:
                self._conn.execute(
                    """
                    UPDATE commerce_purchases
                       SET status='paid', provider_order_id=?,
                           period_end=COALESCE(?, period_end), updated=?
                     WHERE id=?
                    """,
                    (order_id, period_end, time.time(), purchase_id),
                )
            self._fulfill(purchase_id, period_end=period_end, event_type=event_type)
        elif event_type == "subscription.canceled":
            with self._lock, self._conn:
                self._conn.execute(
                    "UPDATE commerce_purchases SET status='ended', updated=? WHERE id=?",
                    (time.time(), purchase_id),
                )
        elif event_type == "subscription.past_due":
            with self._lock, self._conn:
                self._conn.execute(
                    "UPDATE commerce_purchases SET status='past_due', updated=? WHERE id=?",
                    (time.time(), purchase_id),
                )
        return {"ok": 1, "event_id": event_id, "purchase_id": purchase_id}

    @staticmethod
    def _period_end(value: object) -> float | None:
        if not isinstance(value, str) or not value:
            return None
        # Waffo documents subscription period fields as ISO-8601 dates.
        try:
            parsed = time.strptime(value[:10], "%Y-%m-%d")
        except ValueError:
            return None
        return float(time.mktime(parsed) + 86_400)

    def _purchase(self, purchase_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM commerce_purchases WHERE id=?",
                (purchase_id,),
            ).fetchone()

    def _fulfill(
        self,
        purchase_id: str,
        *,
        period_end: float | None,
        event_type: str,
    ) -> None:
        row = self._purchase(purchase_id)
        if row is None:
            raise StoreError("purchase not found", 404)
        snapshot = json.loads(str(row["product_snapshot"]))
        fields = snapshot.get("fields")
        if not isinstance(fields, dict):
            raise StoreError("invalid product snapshot", 500)
        actions = self._normalize_fulfillment(fields.get("fulfillment"))
        period_key = (
            str(int(period_end))
            if period_end is not None
            else ("once" if str(row["billing"]) == "one_time" else event_type)
        )
        for index, action in enumerate(actions):
            with self._lock:
                done = self._conn.execute(
                    """
                    SELECT result FROM commerce_fulfillments
                     WHERE purchase_id=? AND period_key=? AND action_index=?
                    """,
                    (purchase_id, period_key, index),
                ).fetchone()
            if done is not None:
                continue
            if action["type"] == "certificate":
                result = self._fulfill_certificate(
                    buyer_key=str(row["buyer_key"]),
                    grants=action["grants"],
                    duration=action["duration"],
                    period_end=period_end,
                )
            else:
                balance = self.credit_balance(
                    str(row["buyer_id"]),
                    int(action["amount_cents"]),
                    reason="store purchase",
                    ref=f"purchase:{purchase_id}",
                )
                result = {"balance_cents": balance}
            with self._lock, self._conn:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO commerce_fulfillments(
                        purchase_id, period_key, action_index, action_type, result, created
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        purchase_id,
                        period_key,
                        index,
                        str(action["type"]),
                        canonical_json(result),
                        time.time(),
                    ),
                )

    def _fulfill_certificate(
        self,
        *,
        buyer_key: str,
        grants: list[dict[str, Any]],
        duration: object,
        period_end: float | None,
    ) -> dict[str, Any]:
        issuer_key = serialization.load_pem_private_key(
            _pem_or_file(self.cfg.commerce_issuer_private_key),
            password=None,
        )
        if not isinstance(issuer_key, ed25519.Ed25519PrivateKey):
            raise StoreError("commerce issuer key must be Ed25519", 503)
        issuer_public = base64.b64encode(
            issuer_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).decode()
        _canonical, issuer_id = public_identity(issuer_public)
        issuer_serial = self.cfg.commerce_issuer_serial.strip()
        if not issuer_serial:
            raise StoreError("commerce issuer serial is not configured", 503)
        parent_info = self.store.certificate(issuer_serial)
        if parent_info is None or not self.store.certificate_active(issuer_serial):
            raise StoreError("commerce issuer certificate is not active", 503)
        parent = parse_certificate(str(parent_info["body"]))
        if parent.subject_id != issuer_id or not parent.delegate:
            raise StoreError("commerce issuer key/certificate mismatch", 503)

        grant_map: dict[str, set[str]] = {}
        for grant in grants:
            scope = str(grant["scope"])
            grant_map.setdefault(scope, set()).update(str(x) for x in grant["actions"])
        now = int(time.time())
        if duration == "period":
            if period_end is None:
                if "one_time" in str(duration):
                    not_after = now + 30 * 86_400
                else:
                    raise StoreError("subscription period end is unavailable", 503)
            else:
                not_after = max(now + 60, int(period_end))
        else:
            not_after = now + int(duration)
        cert = make_certificate(
            serial=secrets.token_hex(16),
            issuer_serial=issuer_serial,
            issuer_id=issuer_id,
            subject_key=buyer_key,
            not_before=now - 60,
            not_after=not_after,
            delegate=False,
            grants=grant_map,
        )
        signature = base64.b64encode(issuer_key.sign(certificate_payload(cert.body))).decode()
        registered = self.store.register_certificate(cert.body, signature)
        return {
            "certificate_serial": registered.serial,
            "not_after": registered.not_after,
        }
