"""Signed webhook management and event routing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
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
from msgd.crypto import certificate_payload, make_certificate
from msgd.server import build_server
from msgd.webhooks import _public_addresses, delivery_signature, validate_webhook_url


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def author_id(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def sign_b64(key: Ed25519PrivateKey, payload_b64: str) -> str:
    return base64.b64encode(key.sign(base64.b64decode(payload_b64))).decode("ascii")


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


class WebhookCase(unittest.TestCase):
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
            write_burst=200,
            write_per_minute=3000,
            read_per_minute=3000,
        )
        self.server = build_server(cfg)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.c = Client(f"http://{host}:{port}")

        self.member = Ed25519PrivateKey.generate()
        self.member_id = author_id(self.member)
        cert = make_certificate(
            serial="1" * 32,
            issuer_serial="root",
            issuer_id=author_id(self.root_key),
            subject_key=public_b64(self.member),
            not_before=1,
            not_after=4_102_444_800,
            delegate=False,
            grants={
                "*": {
                    "post.create",
                    "post.edit.self",
                    "post.delete.self",
                }
            },
        )
        signature = base64.b64encode(
            self.root_key.sign(certificate_payload(cert.body))
        ).decode("ascii")
        self.server.board.store.register_certificate(cert.body, signature)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server.board.store.close()
        self.tmp.cleanup()

    def signing(self, key: Ed25519PrivateKey, action: str, **fields: str) -> dict:
        status, body = self.c.get(
            "/_signing",
            action=action,
            key=public_b64(key),
            **fields,
        )
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def signed_webhook(
        self,
        key: Ed25519PrivateKey,
        action: str,
        **fields: str,
    ) -> tuple[int, dict | str]:
        info = self.signing(key, action, **fields)
        submit = {
            "action": action,
            "key": public_b64(key),
            "sig": sign_b64(key, info["payload_b64"]),
            "nonce": info["nonce"],
            "issued": str(info["issued"]),
            **fields,
        }
        status, body = self.c.post("/_webhook", **submit)
        if body.lstrip().startswith(("{", "[")):
            return status, json.loads(body)
        return status, body

    def signed_post(self, text: str, *, name: str = "Alice") -> int:
        info = self.signing(
            self.member,
            "post.create",
            board="main",
            name=name,
            text=text,
        )
        status, body = self.c.post(
            "/publish",
            board="main",
            name=name,
            text=text,
            key=public_b64(self.member),
            sig=sign_b64(self.member, info["payload_b64"]),
            nonce=info["nonce"],
            issued=str(info["issued"]),
        )
        self.assertEqual(status, 201, body)
        return int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])

    def events(self) -> list[str]:
        return [str(row["event"]) for row in self.server.board.store.due_webhook_deliveries(100)]

    def test_signed_configuration_and_event_catalog(self) -> None:
        events = ",".join(
            [
                "post.created",
                "post.updated",
                "post.deleted",
                "reply.created",
                "mention.created",
                "certificate.issued",
                "certificate.revoked",
            ]
        )
        status, created = self.signed_webhook(
            self.member,
            "webhook.create",
            url="https://hooks.example.com/msg",
            events=events,
        )
        self.assertEqual(status, 201)
        assert isinstance(created, dict)
        webhook_id = created["id"]
        secret = created["secret"]
        self.assertTrue(secret)
        self.assertEqual(set(created["events"]), set(events.split(",")))

        status, listed = self.signed_webhook(self.member, "webhook.list")
        self.assertEqual(status, 200)
        assert isinstance(listed, list)
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["id"], webhook_id)
        self.assertNotIn("secret", listed[0])

        other = Ed25519PrivateKey.generate()
        status, _ = self.signed_webhook(
            other,
            "webhook.delete",
            id=webhook_id,
        )
        self.assertEqual(status, 404)

        post_id = self.signed_post("my post")
        self.assertIn("post.created", self.events())

        status, body = self.c.get(
            "/publish",
            reply_to=str(post_id),
            text=f"reply and mention @{self.member_id}",
        )
        self.assertEqual(status, 201, body)
        current = self.events()
        self.assertIn("reply.created", current)
        self.assertIn("mention.created", current)

        info = self.signing(
            self.member,
            "post.edit",
            id=str(post_id),
            text="edited",
        )
        status, body = self.c.post(
            "/publish",
            edit=str(post_id),
            text="edited",
            key=public_b64(self.member),
            sig=sign_b64(self.member, info["payload_b64"]),
        )
        self.assertEqual(status, 200, body)
        self.assertIn("post.updated", self.events())

        second = make_certificate(
            serial="2" * 32,
            issuer_serial="root",
            issuer_id=author_id(self.root_key),
            subject_key=public_b64(self.member),
            not_before=1,
            not_after=4_102_444_800,
            delegate=False,
            grants={"*": {"post.create"}},
        )
        second_sig = base64.b64encode(
            self.root_key.sign(certificate_payload(second.body))
        ).decode("ascii")
        status, body = self.c.post("/_cert", cert=second.body, sig=second_sig)
        self.assertEqual(status, 201, body)
        self.assertIn("certificate.issued", self.events())

        revoke = self.signing(
            self.root_key,
            "cert.revoke",
            serial=second.serial,
        )
        status, body = self.c.post(
            "/_revoke",
            serial=second.serial,
            key=public_b64(self.root_key),
            sig=sign_b64(self.root_key, revoke["payload_b64"]),
        )
        self.assertEqual(status, 200, body)
        self.assertIn("certificate.revoked", self.events())

        info = self.signing(
            self.member,
            "post.delete",
            id=str(post_id),
        )
        status, body = self.c.post(
            "/publish",
            delete=str(post_id),
            key=public_b64(self.member),
            sig=sign_b64(self.member, info["payload_b64"]),
        )
        self.assertEqual(status, 200, body)
        self.assertIn("post.deleted", self.events())

        status, tested = self.signed_webhook(
            self.member,
            "webhook.test",
            id=webhook_id,
        )
        self.assertEqual(status, 202)
        assert isinstance(tested, dict)
        self.assertEqual(tested["event"], "webhook.test")
        self.assertIn("webhook.test", self.events())

        status, rotated = self.signed_webhook(
            self.member,
            "webhook.rotate",
            id=webhook_id,
        )
        self.assertEqual(status, 200)
        assert isinstance(rotated, dict)
        self.assertNotEqual(rotated["secret"], secret)

    def test_url_security_and_signature(self) -> None:
        for value in (
            "http://example.com/hook",
            "https://127.0.0.1/hook",
            "https://localhost/hook",
            "https://example.com:8443/hook",
        ):
            with self.assertRaises(Exception):
                validate_webhook_url(value)

        with patch(
            "msgd.webhooks.socket.getaddrinfo",
            return_value=[
                (
                    2,
                    1,
                    6,
                    "",
                    ("127.0.0.1", 443),
                )
            ],
        ):
            with self.assertRaises(OSError):
                _public_addresses("hooks.example.com")

        secret = "secret"
        timestamp = 123
        body = b'{"event":"test"}'
        expected = "sha256=" + hmac.new(
            secret.encode(),
            b"123." + body,
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(delivery_signature(secret, timestamp, body), expected)


if __name__ == "__main__":
    unittest.main()
