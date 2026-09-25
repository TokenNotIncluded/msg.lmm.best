"""Commerce and data-driven /store behavior."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from msgd.commerce import CommerceService
from msgd.config import Config
from msgd.store import Store, StoreError
from msgd.templates import TopicTemplateService


STORE_TEMPLATE = {
    "v": 1,
    "scope": "root",
    "allow_extra": False,
    "title_field": "name",
    "fields": [
        {"name": "name", "type": "string", "required": True, "max_bytes": 160},
        {"name": "description", "type": "text", "required": True, "max_bytes": 4096},
        {"name": "price_usd", "type": "number", "required": True, "min": 0.01},
        {"name": "billing", "type": "string", "required": True, "max_bytes": 32},
        {"name": "checkout_ttl_seconds", "type": "integer", "default": 900, "min": 60},
        {"name": "fulfillment", "type": "json", "required": True, "max_bytes": 16384},
        {"name": "active", "type": "boolean", "default": True},
    ],
}


class CommerceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        templates_dir = root / "templates"
        templates_dir.mkdir()
        (templates_dir / "store.json").write_text(
            json.dumps(STORE_TEMPLATE),
            encoding="utf-8",
        )
        self.cfg = Config(
            database=str(root / "msg.db"),
            root_public_key=str(root / "root.pub"),
            topic_template_dir=str(templates_dir),
            certificate_only_topics="store,ads",
            waffo_subscription_products="month=PROD_test_month",
        )
        self.store = Store(self.cfg)
        self.templates = TopicTemplateService(self.cfg)
        self.commerce = CommerceService(self.cfg, self.store, self.templates)

    def tearDown(self) -> None:
        self.commerce.close()
        self.templates.close()
        self.store.close()
        self.tmp.cleanup()

    def test_balance_defaults_to_zero_usd(self) -> None:
        balance = self.commerce.balance("a" * 64)
        self.assertEqual(balance["currency"], "USD")
        self.assertEqual(balance["cents"], 0)
        self.assertEqual(balance["balance"], "0.00")

        cents = self.commerce.credit_balance(
            "a" * 64,
            125,
            reason="test",
            ref="test:1",
        )
        self.assertEqual(cents, 125)
        self.assertEqual(self.commerce.balance("a" * 64)["balance"], "1.25")

    def test_store_and_ads_are_certificate_only_by_default(self) -> None:
        for board in ("store", "ads"):
            policy = self.store.policy(board)
            self.assertEqual(policy["anonymous"], [])
            self.assertEqual(policy["signed"], [])

    def test_product_price_and_fulfillment_are_read_from_store_post(self) -> None:
        normalized = self.templates.normalize_fields(
            "store",
            {
                "name": "Membership",
                "description": "Data-defined membership",
                "price_usd": 1,
                "billing": "month",
                "fulfillment": [
                    {
                        "type": "certificate",
                        "grants": [
                            {"scope": "web:self", "actions": ["web.write", "web.delete"]},
                            {"scope": "account:self", "actions": ["badge.blue"]},
                        ],
                        "duration": "period",
                    }
                ],
            },
            reply_to=None,
        )
        assert normalized is not None
        body, _values, _version, title = normalized
        post, _ = self.store.create_post(
            board="store",
            body=body,
            name="seed",
            title=title,
        )

        product = self.commerce.product(post.id)
        self.assertEqual(product["amount_cents"], 100)
        self.assertEqual(product["amount"], "1.00")
        self.assertEqual(product["currency"], "USD")
        self.assertEqual(product["billing"], "month")
        self.assertEqual(product["provider_product_id"], "PROD_test_month")

    def test_fulfillment_rejects_unlisted_capabilities(self) -> None:
        with self.assertRaises(StoreError):
            self.commerce._normalize_fulfillment(
                [
                    {
                        "type": "certificate",
                        "grants": [{"scope": "topic:*", "actions": ["cert.issue"]}],
                        "duration": 3600,
                    }
                ]
            )


if __name__ == "__main__":
    unittest.main()
