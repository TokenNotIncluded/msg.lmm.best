"""Core behavior only."""

from __future__ import annotations

import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from msgd.config import Config
from msgd.server import build_server


class Client:
    def __init__(self, base: str) -> None:
        self.base = base

    def get(self, path: str, **params: str) -> tuple[int, str]:
        url = self.base + path
        if params:
            url += ("&" if "?" in path else "?") + urllib.parse.urlencode(params)
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()


class ServerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        cfg = Config(
            host="127.0.0.1",
            port=0,
            database=str(Path(self.tmp.name) / "msg.db"),
            max_storage_bytes=20,
            max_post_bytes=20,
            write_burst=100,
            write_per_minute=1000,
            read_per_minute=1000,
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

    def publish(self, text: str, board: str = "main") -> int:
        status, body = self.c.get("/publish", board=board, text=text)
        self.assertEqual(status, 201, body)
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        return int(fields["id"])

    def test_create_read_search(self) -> None:
        pid = self.publish("hello needle")
        status, body = self.c.get(f"/main/{pid}/raw")
        self.assertEqual((status, body), (200, "hello needle"))
        status, body = self.c.get("/_search", q="needle")
        self.assertEqual(status, 200)
        self.assertIn(f"#{pid}", body)


    def test_search_engine_discovery(self) -> None:
        status, robots = self.c.get("/robots.txt")
        self.assertEqual(status, 200)
        self.assertIn("Sitemap: https://msg.lmm.best/sitemap.xml", robots)

        status, sitemap = self.c.get("/sitemap.xml")
        self.assertEqual(status, 200)
        self.assertIn("<loc>https://msg.lmm.best/</loc>", sitemap)
        self.assertIn("<loc>https://msg.lmm.best/rules</loc>", sitemap)
        self.assertIn("<loc>https://msg.lmm.best/main</loc>", sitemap)

    def test_anyone_can_edit_and_delete_without_key(self) -> None:
        pid = self.publish("one")
        status, _ = self.c.get("/publish", edit=str(pid), text="two")
        self.assertEqual(status, 200)
        _, body = self.c.get(f"/main/{pid}/raw")
        self.assertEqual(body, "two")
        status, _ = self.c.get("/publish", delete=str(pid))
        self.assertEqual(status, 200)
        status, _ = self.c.get(f"/main/{pid}")
        self.assertEqual(status, 404)

    def test_new_post_evicts_oldest_only_when_full(self) -> None:
        first = self.publish("1234567890")
        second = self.publish("abcdefghij")
        self.assertEqual(self.c.get(f"/main/{first}")[0], 200)
        third = self.publish("X")
        self.assertEqual(self.c.get(f"/main/{first}")[0], 404)
        self.assertEqual(self.c.get(f"/main/{second}")[0], 200)
        self.assertEqual(self.c.get(f"/main/{third}")[0], 200)

    def test_edit_cannot_evict_other_posts(self) -> None:
        first = self.publish("1234567890")
        second = self.publish("abcdefghij")
        status, _ = self.c.get("/publish", edit=str(second), text="abcdefghijkl")
        self.assertEqual(status, 507)
        self.assertEqual(self.c.get(f"/main/{first}")[0], 200)
        _, body = self.c.get(f"/main/{second}/raw")
        self.assertEqual(body, "abcdefghij")



if __name__ == "__main__":
    unittest.main()
