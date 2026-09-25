"""WebSub discovery, verification, subscriptions, and feed delivery."""

from __future__ import annotations

import hashlib
import hmac
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from msgd.config import Config
from msgd.server import build_server


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    import base64

    return base64.b64encode(raw).decode("ascii")


class Client:
    def __init__(self, base: str) -> None:
        self.base = base

    def request(
        self,
        path: str,
        params: dict[str, str] | None = None,
        *,
        post: bool = False,
    ) -> tuple[int, str]:
        params = params or {}
        data = urllib.parse.urlencode(params).encode() if post else None
        url = self.base + path
        if not post and params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"} if post else {},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read().decode()
            finally:
                exc.close()

    def get(self, path: str, **params: str) -> tuple[int, str]:
        return self.request(path, params)

    def post(self, path: str, **params: str) -> tuple[int, str]:
        return self.request(path, params, post=True)


class WebSubCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root_key = Ed25519PrivateKey.generate()
        root_public = Path(self.tmp.name) / "root.pub"
        root_public.write_text(public_b64(self.root_key) + "\n", encoding="utf-8")
        cfg = Config(
            host="127.0.0.1",
            port=0,
            database=str(Path(self.tmp.name) / "msg.db"),
            root_public_key=str(root_public),
            webhook_secret_key=str(Path(self.tmp.name) / "webhook.key"),
            webhook_delivery_enabled=False,
            websub_delivery_enabled=False,
            websub_external_hubs="https://hub.example/hub",
            write_burst=200,
            write_per_minute=3000,
            read_per_minute=3000,
        )
        self.server = build_server(cfg)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.c = Client(f"http://{host}:{port}")
        self.topic = "https://msg.lmm.best/rss.xml"
        self.callback = "https://subscriber.example/websub"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server.board.store.close()
        self.tmp.cleanup()

    def test_rss_discovers_hub_and_canonical_topic(self) -> None:
        status, body = self.c.get("/rss.xml")
        self.assertEqual(status, 200, body)
        self.assertIn(
            '<atom:link href="https://msg.lmm.best/rss.xml" rel="self" '
            'type="application/rss+xml"/>',
            body,
        )
        self.assertIn(
            '<atom:link href="https://msg.lmm.best/hub" rel="hub"/>',
            body,
        )
        self.assertIn(
            '<atom:link href="https://hub.example/hub" rel="hub"/>',
            body,
        )

        status, body = self.c.get("/main/rss.xml")
        self.assertEqual(status, 200, body)
        self.assertIn(
            '<atom:link href="https://msg.lmm.best/main/rss.xml" rel="self" '
            'type="application/rss+xml"/>',
            body,
        )
        self.assertIn(
            '<atom:link href="https://msg.lmm.best/hub" rel="hub"/>',
            body,
        )
        self.assertIn(
            '<atom:link href="https://hub.example/hub" rel="hub"/>',
            body,
        )

    def test_config_accepts_multiple_external_hubs(self) -> None:
        hubs = Config(
            websub_external_hubs=(
                "https://websubhub.com/hub,"
                "https://pubsubhubbub.appspot.com/"
            )
        ).websub_hubs
        self.assertEqual(hubs[0], "https://msg.lmm.best/hub")
        self.assertIn("https://websubhub.com/hub", hubs)
        self.assertIn("https://pubsubhubbub.appspot.com/", hubs)

    def subscribe(self, *, secret: str = "shared-secret", lease: str = "600") -> None:
        status, body = self.c.post(
            "/hub",
            **{
                "hub.mode": "subscribe",
                "hub.topic": self.topic,
                "hub.callback": self.callback,
                "hub.lease_seconds": lease,
                "hub.secret": secret,
            },
        )
        self.assertEqual(status, 202, body)
        with patch("msgd.websub._verify_callback", return_value=True) as verify:
            self.server.board.websub._run_once()
        verify.assert_called_once()
        self.assertIsNotNone(self.server.board.store.websub_subscription(self.topic, self.callback))

    def test_subscribe_publish_signed_delivery_and_unsubscribe(self) -> None:
        secret = "shared-secret"
        self.subscribe(secret=secret)

        status, body = self.c.post("/publish", board="main", text="websub hello")
        self.assertEqual(status, 201, body)

        captured: dict[str, object] = {}

        def deliver(callback: str, payload: bytes, headers: dict[str, str]) -> int:
            captured["callback"] = callback
            captured["body"] = payload
            captured["headers"] = headers
            return 204

        public_pings: list[tuple[str, str]] = []

        def ping(hub: str, topic: str) -> int:
            public_pings.append((hub, topic))
            return 204

        with (
            patch("msgd.websub._post_feed", side_effect=deliver),
            patch("msgd.websub._post_publish_ping", side_effect=ping),
        ):
            self.server.board.websub._run_once()

        payload = captured["body"]
        headers = captured["headers"]
        assert isinstance(payload, bytes)
        assert isinstance(headers, dict)
        self.assertEqual(captured["callback"], self.callback)
        self.assertIn(b"websub hello", payload)
        expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-Hub-Signature"], f"sha256={expected}")
        self.assertEqual(self.server.board.store.due_websub_deliveries(), [])
        self.assertEqual(self.server.board.store.due_websub_hub_pings(), [])
        self.assertEqual(
            set(public_pings),
            {
                ("https://hub.example/hub", "https://msg.lmm.best/rss.xml"),
                ("https://hub.example/hub", "https://msg.lmm.best/feed.xml"),
                ("https://hub.example/hub", "https://msg.lmm.best/main/rss.xml"),
                ("https://hub.example/hub", "https://msg.lmm.best/main/feed.xml"),
            },
        )

        status, body = self.c.post(
            "/hub",
            **{
                "hub.mode": "unsubscribe",
                "hub.topic": self.topic,
                "hub.callback": self.callback,
            },
        )
        self.assertEqual(status, 202, body)
        with patch("msgd.websub._verify_callback", return_value=True) as verify:
            self.server.board.websub._run_once()
        verify.assert_called_once()
        self.assertIsNone(self.server.board.store.websub_subscription(self.topic, self.callback))

    def test_failed_renewal_does_not_replace_active_subscription(self) -> None:
        self.subscribe(secret="old-secret", lease="600")
        before = self.server.board.store.websub_subscription(self.topic, self.callback)
        assert before is not None

        status, body = self.c.post(
            "/hub",
            **{
                "hub.mode": "subscribe",
                "hub.topic": self.topic,
                "hub.callback": self.callback,
                "hub.lease_seconds": "1200",
                "hub.secret": "new-secret",
            },
        )
        self.assertEqual(status, 202, body)
        with patch("msgd.websub._verify_callback", return_value=False):
            self.server.board.websub._run_once()

        after = self.server.board.store.websub_subscription(self.topic, self.callback)
        assert after is not None
        self.assertEqual(before["updated"], after["updated"])
        self.assertEqual(before["expires"], after["expires"])

    def test_external_hub_pings_coalesce_per_topic(self) -> None:
        status, body = self.c.post("/publish", board="main", text="first")
        self.assertEqual(status, 201, body)
        first = self.server.board.store.due_websub_hub_pings()
        self.assertEqual(len(first), 4)
        self.assertTrue(all(int(row["generation"]) == 1 for row in first))

        status, body = self.c.post("/publish", board="main", text="second")
        self.assertEqual(status, 201, body)
        second = self.server.board.store.due_websub_hub_pings()
        self.assertEqual(len(second), 4)
        self.assertTrue(all(int(row["generation"]) == 2 for row in second))

    def test_rejects_non_feed_topic_and_oversized_secret(self) -> None:
        status, _ = self.c.post(
            "/hub",
            **{
                "hub.mode": "subscribe",
                "hub.topic": "https://msg.lmm.best/main",
                "hub.callback": self.callback,
            },
        )
        self.assertEqual(status, 400)

        status, _ = self.c.post(
            "/hub",
            **{
                "hub.mode": "subscribe",
                "hub.topic": self.topic,
                "hub.callback": self.callback,
                "hub.secret": "x" * 200,
            },
        )
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
