"""Valkey-backed engagement ranking integration tests."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import valkey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from msgd.config import Config
from msgd.server import build_server


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


class Client:
    def __init__(self, base: str) -> None:
        self.base = base

    def get(self, path: str, **params: str) -> tuple[int, str]:
        query = urllib.parse.urlencode(params)
        request = urllib.request.Request(self.base + path + (("?" + query) if query else ""))
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read().decode()
            finally:
                exc.close()

    def post(self, path: str, **params: str) -> tuple[int, str]:
        data = urllib.parse.urlencode(params).encode()
        request = urllib.request.Request(
            self.base + path,
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read().decode()
            finally:
                exc.close()


@unittest.skipUnless(os.environ.get("VALKEY_TEST_URL"), "VALKEY_TEST_URL is not configured")
class EngagementCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root_key = Ed25519PrivateKey.generate()
        root_public = Path(self.tmp.name) / "root.pub"
        root_public.write_text(public_b64(root_key) + "\n", encoding="utf-8")
        self.prefix = "msgd-test-" + uuid.uuid4().hex
        self.valkey_url = os.environ["VALKEY_TEST_URL"]
        self.like_key = root_key

        cfg = Config(
            host="127.0.0.1",
            port=0,
            database=str(Path(self.tmp.name) / "msg.db"),
            root_public_key=str(root_public),
            max_storage_bytes=2_000_000,
            write_burst=200,
            write_per_minute=3000,
            read_per_minute=3000,
            valkey_url=self.valkey_url,
            valkey_prefix=self.prefix,
            valkey_required=True,
        )
        self.server = build_server(cfg)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.c = Client(f"http://{host}:{port}")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server.board.store.close()
        client = valkey.from_url(self.valkey_url, decode_responses=True)
        keys = list(client.scan_iter(match=self.prefix + ":*"))
        if keys:
            client.delete(*keys)
        client.close()
        self.tmp.cleanup()

    def publish(self, text: str, *, board: str = "main", reply_to: int | None = None) -> int:
        params = {"board": board, "text": text}
        if reply_to is not None:
            params["reply_to"] = str(reply_to)
        status, body = self.c.get("/publish", **params)
        self.assertEqual(status, 201, body)
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        return int(fields["id"])

    def meta(self, post_id: int) -> dict:
        status, body = self.c.get(f"/main/{post_id}/meta")
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def set_like(self, post_id: int, liked: bool) -> dict[str, str]:
        public = public_b64(self.like_key)
        signed_action = "post.like" if liked else "post.unlike"
        status, body = self.c.get(
            "/_signing",
            action=signed_action,
            key=public,
            id=str(post_id),
        )
        self.assertEqual(status, 200, body)
        challenge = json.loads(body)
        signature = base64.b64encode(
            self.like_key.sign(base64.b64decode(challenge["payload_b64"]))
        ).decode("ascii")
        status, body = self.c.post(
            "/like",
            id=str(post_id),
            action="like" if liked else "unlike",
            key=public,
            sig=signature,
            nonce=str(challenge["nonce"]),
            issued=str(challenge["issued"]),
        )
        self.assertEqual(status, 200, body)
        return dict(line.split("=", 1) for line in body.splitlines() if "=" in line)

    def test_views_comments_likes_and_rankings(self) -> None:
        parent = self.publish("parent")
        first_reply = self.publish("first reply", reply_to=parent)
        self.publish("second reply", reply_to=parent)
        other = self.publish("other")

        initial = self.meta(parent)
        self.assertEqual(initial["engagement"]["views"], 0)
        self.assertEqual(initial["engagement"]["comments"], 2)
        self.assertEqual(initial["engagement"]["likes"], 0)

        first_like = self.set_like(parent, True)
        self.assertEqual(first_like["likes"], "1")
        duplicate_like = self.set_like(parent, True)
        self.assertEqual(duplicate_like["changed"], "0")
        self.assertEqual(duplicate_like["likes"], "1")

        self.assertEqual(self.c.get(f"/main/{parent}")[0], 200)
        self.assertEqual(self.c.get(f"/main/{parent}")[0], 200)
        self.assertEqual(self.c.get(f"/main/{parent}/raw")[0], 200)
        self.assertEqual(self.c.get(f"/main/{other}")[0], 200)

        parent_meta = self.meta(parent)
        self.assertEqual(parent_meta["engagement"]["views"], 3)
        self.assertEqual(parent_meta["engagement"]["comments"], 2)
        self.assertEqual(parent_meta["engagement"]["likes"], 1)
        self.assertGreater(parent_meta["engagement"]["hot"], 12)

        status, views = self.c.get("/hot", sort="views")
        self.assertEqual(status, 200, views)
        self.assertLess(views.index(f"#{parent} "), views.index(f"#{other} "))
        self.assertIn("3 views", views)
        self.assertIn("2 comments", views)

        status, likes = self.c.get("/hot", sort="likes")
        self.assertEqual(status, 200, likes)
        self.assertLess(likes.index(f"#{parent} "), likes.index(f"#{other} "))
        self.assertIn("1 likes", likes)

        status, comments = self.c.get("/hot", sort="comments")
        self.assertEqual(status, 200, comments)
        self.assertIn(f"#{parent} ", comments)

        status, board = self.c.get("/main", sort="views")
        self.assertEqual(status, 200, board)
        self.assertLess(board.index(f"#{parent} "), board.index(f"#{other} "))

        # Rankings/listings are not views.
        self.assertEqual(self.meta(parent)["engagement"]["views"], 3)

        self.server.board.store.set_policy(
            "main",
            ("post.create", "post.edit.any", "post.delete.any"),
            None,
            1,
        )
        status, _ = self.c.get("/publish", delete=str(first_reply))
        self.assertEqual(status, 200)
        self.assertEqual(self.meta(parent)["engagement"]["comments"], 1)

        unlike = self.set_like(parent, False)
        self.assertEqual(unlike["likes"], "0")
        self.assertEqual(self.meta(parent)["engagement"]["likes"], 0)

        schema = json.loads(self.c.get("/_schema")[1])
        self.assertTrue(schema["engagement"]["likes"]["supported"])
        self.assertEqual(schema["engagement"]["backend"], "valkey")


if __name__ == "__main__":
    unittest.main()
