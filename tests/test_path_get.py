"""Query-free base64url path GET protocol."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from msgd.config import Config
from msgd.ratelimit import Limiter
from msgd.server import build_server


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def raw_payload(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def encode_bytes(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def encode_payload(value: dict[str, object]) -> str:
    return encode_bytes(raw_payload(value))


class Client:
    def __init__(self, base: str) -> None:
        self.base = base

    def raw(self, path: str) -> tuple[int, str, dict[str, str]]:
        request = urllib.request.Request(self.base + path)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read().decode(), dict(response.headers)
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read().decode(), dict(exc.headers)
            finally:
                exc.close()


class PathGetCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Ed25519PrivateKey.generate()
        root_public = Path(self.tmp.name) / "root.pub"
        root_public.write_text(public_b64(root) + "\n", encoding="utf-8")
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

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server.board.store.close()
        self.tmp.cleanup()

    def path(self, payload: dict[str, object]) -> str:
        return "/g/v1/" + encode_payload(payload)

    def test_guest_post_is_path_only_and_persistently_idempotent(self) -> None:
        status, help_body, _ = self.c.raw("/g")
        self.assertEqual(status, 200, help_body)
        self.assertIn("/g/v1/BASE64URL_PAYLOAD", help_body)
        self.assertIn("guest.post", help_body)

        payload = {
            "op": "guest.post",
            "rid": "agentreq000001",
            "name": "PathAgent",
            "title": "Path only",
            "text": "hello from one GET #pathget",
        }
        path = self.path(payload)
        self.assertNotIn("?", path)
        self.assertNotIn("=", path)

        status, first, first_headers = self.c.raw(path)
        self.assertEqual(status, 201, first)
        self.assertIn("client=raw-http", first)
        self.assertIn("hint=prefer msg CLI", first)
        self.assertEqual(first_headers["X-Path-GET-Request-ID"], "agentreq000001")
        self.assertEqual(first_headers["X-Path-GET-Replay"], "0")
        post_id = int(dict(line.split("=", 1) for line in first.splitlines() if "=" in line)["id"])

        posts = self.server.board.store.list_posts(board="guest", limit=20)
        self.assertEqual([post.id for post in posts], [post_id])
        self.assertEqual(posts[0].name, "[anon] anonymous")

        status, replay, replay_headers = self.c.raw(path)
        self.assertEqual(status, 201, replay)
        self.assertEqual(replay, first)
        self.assertEqual(replay_headers["X-Path-GET-Replay"], "1")
        self.assertEqual(
            len(self.server.board.store.list_posts(board="guest", limit=20)),
            1,
        )

        conflicting = dict(payload)
        conflicting["text"] = "different text"
        status, body, _ = self.c.raw(self.path(conflicting))
        self.assertEqual(status, 409, body)
        self.assertIn("reused with different payload", body)
        self.assertEqual(
            len(self.server.board.store.list_posts(board="guest", limit=20)),
            1,
        )

        status, body, _ = self.c.raw(path + "?x=1")
        self.assertEqual(status, 400, body)
        self.assertIn("does not accept query parameters", body)

    def test_edit_and_delete_are_idempotent(self) -> None:
        create = {
            "op": "guest.post",
            "rid": "agentreq000010",
            "name": "Editor",
            "text": "before",
        }
        status, body, _ = self.c.raw(self.path(create))
        self.assertEqual(status, 201, body)
        post_id = int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])

        edit = {
            "op": "guest.edit",
            "rid": "agentreq000011",
            "id": post_id,
            "text": "after #edited",
        }
        edit_path = self.path(edit)
        status, edited, headers = self.c.raw(edit_path)
        self.assertEqual(status, 200, edited)
        self.assertEqual(headers["X-Path-GET-Replay"], "0")
        self.assertEqual(self.server.board.store.get_post(post_id).body, "after #edited")

        status, replayed, headers = self.c.raw(edit_path)
        self.assertEqual(status, 200, replayed)
        self.assertEqual(replayed, edited)
        self.assertEqual(headers["X-Path-GET-Replay"], "1")
        self.assertEqual(self.server.board.store.get_post(post_id).body, "after #edited")

        delete = {
            "op": "guest.delete",
            "rid": "agentreq000012",
            "id": post_id,
        }
        delete_path = self.path(delete)
        status, deleted, headers = self.c.raw(delete_path)
        self.assertEqual(status, 200, deleted)
        self.assertEqual(headers["X-Path-GET-Replay"], "0")
        self.assertIsNone(self.server.board.store.get_post(post_id))

        status, replayed_delete, headers = self.c.raw(delete_path)
        self.assertEqual(status, 200, replayed_delete)
        self.assertEqual(replayed_delete, deleted)
        self.assertEqual(headers["X-Path-GET-Replay"], "1")
        self.assertIsNone(self.server.board.store.get_post(post_id))

    def test_chunked_large_post_is_resumable_and_idempotent(self) -> None:
        request_id = "chunkreq00000000000000001"
        text = ("0123456789abcdef" * 3000) + " #chunked"
        payload = {
            "op": "guest.post",
            "rid": request_id,
            "title": "large path transfer",
            "text": text,
        }
        raw = raw_payload(payload)
        self.assertGreater(len(raw), self.server.board.cfg.max_post_bytes)

        chunk_size = 4096
        chunks = [raw[index : index + chunk_size] for index in range(0, len(raw), chunk_size)]
        total = len(chunks)

        first_path = f"/g/v1/chunk/{request_id}/0/{total}/{encode_bytes(chunks[0])}"
        self.assertLess(len(first_path), 6000)
        status, body, headers = self.c.raw(first_path)
        self.assertEqual(status, 201, body)
        self.assertEqual(headers["X-Path-GET-Chunk-Replay"], "0")

        status, body, headers = self.c.raw(first_path)
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["X-Path-GET-Chunk-Replay"], "1")

        status, body, _ = self.c.raw(f"/g/v1/status/{request_id}")
        self.assertEqual(status, 200, body)
        self.assertIn("state=receiving", body)
        self.assertIn("missing=", body)

        digest = hashlib.sha256(raw).hexdigest()
        status, body, _ = self.c.raw(f"/g/v1/commit/{request_id}/{digest}")
        self.assertEqual(status, 409, body)
        self.assertIn("transfer is incomplete", body)

        for index in range(total - 1, 0, -1):
            path = f"/g/v1/chunk/{request_id}/{index}/{total}/{encode_bytes(chunks[index])}"
            self.assertLess(len(path), 6000)
            status, body, _ = self.c.raw(path)
            self.assertEqual(status, 201, body)

        status, body, _ = self.c.raw(f"/g/v1/status/{request_id}")
        self.assertEqual(status, 200, body)
        self.assertIn("state=ready", body)

        status, created, headers = self.c.raw(f"/g/v1/commit/{request_id}/{digest}")
        self.assertEqual(status, 201, created)
        self.assertEqual(headers["X-Path-GET-Replay"], "0")
        self.assertEqual(headers["X-Path-GET-Transfer"], "chunked")
        post_id = int(
            dict(line.split("=", 1) for line in created.splitlines() if "=" in line)["id"]
        )
        self.assertEqual(self.server.board.store.get_post(post_id).body, text)

        status, replayed, headers = self.c.raw(f"/g/v1/commit/{request_id}/{digest}")
        self.assertEqual(status, 201, replayed)
        self.assertEqual(replayed, created)
        self.assertEqual(headers["X-Path-GET-Replay"], "1")
        self.assertEqual(
            len(self.server.board.store.list_posts(board="guest", limit=20)),
            1,
        )

        status, body, _ = self.c.raw(f"/g/v1/status/{request_id}")
        self.assertEqual(status, 200, body)
        self.assertIn("state=complete", body)

    def test_chunk_conflict_and_commit_hash_validation(self) -> None:
        request_id = "chunkreq00000000000000002"
        payload = {
            "op": "post.create",
            "rid": request_id,
            "board": "main",
            "text": "generic path operation",
        }
        raw = raw_payload(payload)
        midpoint = len(raw) // 2
        chunks = [raw[:midpoint], raw[midpoint:]]

        path = f"/g/v1/chunk/{request_id}/0/2/{encode_bytes(chunks[0])}"
        status, body, _ = self.c.raw(path)
        self.assertEqual(status, 201, body)

        conflicting = f"/g/v1/chunk/{request_id}/0/2/{encode_bytes(b'different')}"
        status, body, _ = self.c.raw(conflicting)
        self.assertEqual(status, 409, body)
        self.assertIn("different data", body)

        status, body, _ = self.c.raw(f"/g/v1/chunk/{request_id}/1/2/{encode_bytes(chunks[1])}")
        self.assertEqual(status, 201, body)

        wrong_digest = "0" * 64
        status, body, _ = self.c.raw(f"/g/v1/commit/{request_id}/{wrong_digest}")
        self.assertEqual(status, 409, body)
        self.assertIn("SHA256", body)

        digest = hashlib.sha256(raw).hexdigest()
        status, body, _ = self.c.raw(f"/g/v1/commit/{request_id}/{digest}")
        self.assertEqual(status, 201, body)
        post_id = int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])
        post = self.server.board.store.get_post(post_id)
        self.assertEqual(post.board, "main")
        self.assertEqual(post.body, "generic path operation")

    def test_generic_post_operations_keep_single_request_compatibility(self) -> None:
        self.server.board.store.set_policy(
            "main",
            ("post.create", "post.edit.any", "post.delete.any"),
            None,
            1,
        )
        create = {
            "op": "post.create",
            "rid": "genericreq000001",
            "board": "main",
            "title": "generic",
            "text": "before",
        }
        status, body, _ = self.c.raw(self.path(create))
        self.assertEqual(status, 201, body)
        post_id = int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])

        edit = {
            "op": "post.edit",
            "rid": "genericreq000002",
            "id": post_id,
            "text": "after",
        }
        status, body, _ = self.c.raw(self.path(edit))
        self.assertEqual(status, 200, body)
        self.assertEqual(self.server.board.store.get_post(post_id).body, "after")

        delete = {
            "op": "post.delete",
            "rid": "genericreq000003",
            "id": post_id,
        }
        status, body, _ = self.c.raw(self.path(delete))
        self.assertEqual(status, 200, body)
        self.assertIsNone(self.server.board.store.get_post(post_id))

    def test_chunk_transport_has_separate_rate_limit_from_commit(self) -> None:
        self.server.board.writes = Limiter(burst=1, per_minute=1)
        request_id = "chunkreq00000000000000003"
        payload = {
            "op": "guest.post",
            "rid": request_id,
            "text": "rate limit separation",
        }
        raw = raw_payload(payload)
        midpoint = len(raw) // 2
        chunks = [raw[:midpoint], raw[midpoint:]]

        for index, chunk in enumerate(chunks):
            status, body, _ = self.c.raw(
                f"/g/v1/chunk/{request_id}/{index}/2/{encode_bytes(chunk)}"
            )
            self.assertEqual(status, 201, body)

        digest = hashlib.sha256(raw).hexdigest()
        status, body, _ = self.c.raw(f"/g/v1/commit/{request_id}/{digest}")
        self.assertEqual(status, 201, body)

        next_payload = {
            "op": "guest.post",
            "rid": "aftercommit000001",
            "text": "should be write-rate-limited",
        }
        status, body, _ = self.c.raw(self.path(next_payload))
        self.assertEqual(status, 429, body)

    def test_payload_validation_and_robots(self) -> None:
        status, body, _ = self.c.raw("/g/v1/not+base64")
        self.assertEqual(status, 400, body)
        self.assertIn("unpadded base64url", body)

        missing_rid = encode_payload({"op": "guest.post", "text": "hello"})
        status, body, _ = self.c.raw("/g/v1/" + missing_rid)
        self.assertEqual(status, 400, body)
        self.assertIn("rid", body)

        secret_op = encode_payload(
            {
                "op": "custody.post",
                "rid": "agentreq000020",
                "token": "secret",
                "text": "no",
            }
        )
        status, body, _ = self.c.raw("/g/v1/" + secret_op)
        self.assertEqual(status, 400, body)
        self.assertIn("guest.post", body)

        status, robots, _ = self.c.raw("/robots.txt")
        self.assertEqual(status, 200, robots)
        self.assertIn("Disallow: /g/", robots)


if __name__ == "__main__":
    unittest.main()
