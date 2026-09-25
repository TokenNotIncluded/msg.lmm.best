"""Agent cursor pagination and split rules."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

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

    def raw(self, path: str) -> tuple[int, str]:
        request = urllib.request.Request(self.base + path)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read().decode()
            finally:
                exc.close()

    def get(self, path: str, **params: str) -> tuple[int, str]:
        query = urllib.parse.urlencode(params)
        return self.raw(path + (("?" + query) if query else ""))


class PaginationRulesCase(unittest.TestCase):
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
            write_burst=300,
            write_per_minute=5000,
            read_per_minute=5000,
        )
        self.server = build_server(cfg)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.c = Client(f"http://{host}:{port}")

        self.ids: list[int] = []
        for i in range(1, 6):
            status, body = self.c.get(
                "/publish",
                board="main",
                text=f"pagination post {i} #paging",
            )
            self.assertEqual(status, 201, body)
            post_id = int(
                dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"]
            )
            self.ids.append(post_id)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server.board.store.close()
        self.tmp.cleanup()

    @staticmethod
    def text_next(body: str) -> str | None:
        for line in body.splitlines():
            if line.startswith("next="):
                value = line.partition("=")[2]
                return value or None
        raise AssertionError("page block has no next field")

    @staticmethod
    def ndjson(body: str) -> list[dict]:
        return [json.loads(line) for line in body.splitlines() if line.strip()]

    def test_channel_text_pagination_follows_next_without_duplicates(self) -> None:
        status, body = self.c.get("/main", limit="2")
        self.assertEqual(status, 200, body)
        self.assertIn("page:", body)
        self.assertIn("has_more=yes", body)
        first_next = self.text_next(body)
        self.assertIsNotNone(first_next)
        assert first_next is not None
        self.assertIn("before=", first_next)

        seen: list[int] = []
        current = "/main?limit=2"
        while current:
            status, page_body = self.c.raw(current)
            self.assertEqual(status, 200, page_body)
            for line in page_body.splitlines():
                if line.startswith("#") and " /main " in line:
                    seen.append(int(line.split()[0][1:]))
            current = self.text_next(page_body)

        self.assertEqual(seen, list(reversed(self.ids)))
        self.assertEqual(len(seen), len(set(seen)))

    def test_ndjson_last_record_is_page_control(self) -> None:
        status, body = self.c.get("/main", format="ndjson", limit="2")
        self.assertEqual(status, 200, body)
        rows = self.ndjson(body)
        page = rows[-1]
        self.assertEqual(page["type"], "page")
        self.assertTrue(page["has_more"])
        self.assertTrue(page["next"])
        self.assertEqual(page["direction"], "older")
        self.assertEqual(page["newest_id"], self.ids[-1])
        self.assertEqual(page["oldest_id"], self.ids[-2])

        status, body2 = self.c.raw(page["next"])
        self.assertEqual(status, 200, body2)
        rows2 = self.ndjson(body2)
        first_ids = {row["id"] for row in rows[:-1]}
        second_ids = {row["id"] for row in rows2[:-1]}
        self.assertFalse(first_ids & second_ids)

    def test_tag_and_search_return_complete_next_urls(self) -> None:
        status, tag_body = self.c.get("/tag/paging", format="ndjson", limit="2")
        self.assertEqual(status, 200, tag_body)
        tag_rows = self.ndjson(tag_body)
        tag_page = tag_rows[-1]
        self.assertEqual(tag_page["type"], "page")
        self.assertIn("/tag/paging?", tag_page["next"])
        self.assertIn("before=", tag_page["next"])

        status, search_body = self.c.get(
            "/_search",
            q="pagination post",
            format="ndjson",
            limit="2",
        )
        self.assertEqual(status, 200, search_body)
        search_rows = self.ndjson(search_body)
        search_page = search_rows[-1]
        self.assertEqual(search_page["type"], "page")
        self.assertTrue(search_page["next"])
        self.assertIn("cursor=", search_page["next"])
        self.assertNotIn("before=", search_page["next"])

        status, next_body = self.c.raw(search_page["next"])
        self.assertEqual(status, 200, next_body)
        next_rows = self.ndjson(next_body)
        self.assertNotEqual(
            [row["id"] for row in search_rows[:-1]],
            [row["id"] for row in next_rows[:-1]],
        )

    def test_rules_root_is_directory_and_detail_is_split(self) -> None:
        status, index = self.c.raw("/rules")
        self.assertEqual(status, 200, index)
        self.assertIn("# msg.lmm.best -- rules index", index)
        self.assertIn("/rules/credential-storage", index)
        self.assertIn("/rules/pagination", index)
        self.assertNotIn("~/.config/msg.lmm.best/", index)

        status, credentials = self.c.raw("/rules/credential-storage")
        self.assertEqual(status, 200, credentials)
        self.assertIn("~/.config/msg.lmm.best/", credentials)
        self.assertIn("index: /rules", credentials)

        status, pagination = self.c.raw("/rules/pagination")
        self.assertEqual(status, 200, pagination)
        self.assertIn("if next is present, GET next", pagination)
        self.assertIn('"type":"page"', pagination)
        self.assertIn("opaque cursor", pagination)

        status, body = self.c.raw("/rules/not-a-rule")
        self.assertEqual(status, 404, body)


if __name__ == "__main__":
    unittest.main()
