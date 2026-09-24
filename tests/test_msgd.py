"""End-to-end tests for msgd: a real server on an ephemeral port, driven over HTTP.

Run:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from msgconf import Config, parse_config_text  # noqa: E402
import msgsrv  # noqa: E402
from msgsrv import build_server  # noqa: E402

msgsrv.log = lambda *a, **k: None


def kv(text: str) -> dict[str, str]:
    """Parse a key=value reply the way an agent would."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key] = value
    return out


class Client:
    def __init__(self, base: str) -> None:
        self.base = base

    def get(self, path: str, **params: str) -> tuple[int, str, dict[str, str]]:
        url = self.base + path
        if params:
            url += ("&" if "?" in path else "?") + urllib.parse.urlencode(params)
        return self._open(urllib.request.Request(url))

    def post(self, path: str, data: bytes, ctype: str) -> tuple[int, str, dict[str, str]]:
        req = urllib.request.Request(
            self.base + path, data=data, method="POST", headers={"Content-Type": ctype}
        )
        return self._open(req)

    def _open(self, req: urllib.request.Request) -> tuple[int, str, dict[str, str]]:
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.read().decode("utf-8"), dict(exc.headers)


class ServerCase(unittest.TestCase):
    overrides: dict = {}
    house_rules = "Be kind to other agents."

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        rules = root / "rules.md"
        rules.write_text(self.house_rules, encoding="utf-8")
        cfg = Config(
            host="127.0.0.1",
            port=0,
            database=str(root / "msg.db"),
            files_dir=str(root / "files"),
            rules_file=str(rules),
            write_per_minute=6000,
            write_burst=1000,
            read_per_minute=60000,
            max_post_bytes=1024,
            max_posts_per_board=5,
            files_enabled=True,
            max_file_bytes=2048,
        )
        cfg = replace(cfg, **self.overrides)
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

    def publish(self, **params: str) -> dict[str, str]:
        status, body, _ = self.c.get("/publish", **params)
        self.assertEqual(status, 201, body)
        return kv(body)


class RulesTests(ServerCase):
    def test_rules_is_served_at_every_alias(self) -> None:
        bodies = set()
        for path in ("/rules", "/_rules", "/_help", "/llms.txt"):
            status, body, _ = self.c.get(path)
            self.assertEqual(status, 200, path)
            bodies.add(body)
        self.assertEqual(len(bodies), 1, "aliases must serve the same document")

    def test_rules_quote_the_live_limits_and_house_rules(self) -> None:
        _, body, _ = self.c.get("/rules")
        self.assertIn("max 1024 bytes", body)
        self.assertIn("house rules", body)
        self.assertIn("Be kind to other agents.", body)

    def test_rules_cannot_be_written_or_used_as_a_board(self) -> None:
        status, body, _ = self.c.get("/publish", board="rules", text="overwrite")
        self.assertEqual(status, 400, body)
        status, _, _ = self.c.post("/rules", b"text=x", "application/x-www-form-urlencoded")
        _, after, _ = self.c.get("/rules")
        self.assertNotIn("overwrite", after)

    def test_every_response_links_to_rules(self) -> None:
        for path in ("/", "/main", "/nope-board/99", "/_health"):
            _, _, headers = self.c.get(path)
            self.assertEqual(headers.get("Link"), '</rules>; rel="help"', path)

    def test_index_points_agents_at_rules(self) -> None:
        _, body, _ = self.c.get("/")
        self.assertIn("read /rules first", body)

    def test_schema_is_json(self) -> None:
        status, body, _ = self.c.get("/_schema")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["limits"]["max_post_bytes"], 1024)


class LifecycleTests(ServerCase):
    def test_create_read_edit_append_delete(self) -> None:
        r = self.publish(board="main", name="agent-a", title="hi", text="first **md**")
        self.assertEqual(r["ok"], "1")
        pid, key = r["id"], r["key"]
        self.assertTrue(r["url"].endswith(f"/main/{pid}"))

        _, raw, _ = self.c.get(f"/main/{pid}/raw")
        self.assertEqual(raw, "first **md**")

        status, body, _ = self.c.get("/publish", edit=pid, key=key, text="second")
        self.assertEqual((status, kv(body)["rev"]), (200, "1"))

        status, body, _ = self.c.get("/publish", append=pid, key=key, text="third")
        self.assertEqual((status, kv(body)["rev"]), (200, "2"))
        _, raw, _ = self.c.get(f"/main/{pid}/raw")
        self.assertEqual(raw, "second\n\nthird")

        _, hist, _ = self.c.get(f"/main/{pid}/history")
        self.assertIn("rev 0  create", hist)
        self.assertIn("rev 1  edit", hist)
        self.assertIn("rev 2  append", hist)
        self.assertIn("first **md**", hist)

        status, body, _ = self.c.get("/publish", delete=pid, key=key)
        self.assertEqual(status, 200, body)
        _, listing, _ = self.c.get("/main")
        self.assertNotIn("third", listing)
        _, listing, _ = self.c.get("/main", deleted="1")
        self.assertIn("deleted", listing)

    def test_deleted_entries_are_final(self) -> None:
        r = self.publish(board="main", text="bye")
        self.c.get("/publish", delete=r["id"], key=r["key"])
        for verb in ("edit", "append"):
            status, _, _ = self.c.get("/publish", **{verb: r["id"], "key": r["key"], "text": "back"})
            self.assertEqual(status, 410, verb)

    def test_wrong_key_is_refused(self) -> None:
        r = self.publish(board="main", text="mine")
        status, body, _ = self.c.get("/publish", edit=r["id"], key="guess", text="theirs")
        self.assertEqual(status, 403)
        self.assertEqual(kv(body)["see"], "/rules")
        _, raw, _ = self.c.get(f"/main/{r['id']}/raw")
        self.assertEqual(raw, "mine")

    def test_caller_may_choose_its_own_key(self) -> None:
        r = self.publish(board="main", text="x", key="my-own-key")
        self.assertEqual(r["key"], "my-own-key")
        status, _, _ = self.c.get("/publish", edit=r["id"], key="my-own-key", text="y")
        self.assertEqual(status, 200)

    def test_ndjson_since_polls_incrementally(self) -> None:
        a = self.publish(board="main", text="one")
        b = self.publish(board="main", text="two")
        _, body, headers = self.c.get("/main", format="ndjson", since=a["id"])
        self.assertIn("ndjson", headers["Content-Type"])
        rows = [json.loads(line) for line in body.splitlines() if line]
        self.assertEqual([r["id"] for r in rows], [int(b["id"])])
        self.assertEqual(rows[0]["body"], "two")

    def test_post_with_form_body(self) -> None:
        big = "x" * 900
        data = urllib.parse.urlencode({"board": "main", "text": big}).encode()
        status, body, _ = self.c.post("/publish", data, "application/x-www-form-urlencoded")
        self.assertEqual(status, 201, body)
        _, raw, _ = self.c.get(f"/main/{kv(body)['id']}/raw")
        self.assertEqual(raw, big)

    def test_post_with_plain_text_body(self) -> None:
        status, body, _ = self.c.post("/publish?board=main&name=p", b"line1\nline2", "text/plain")
        self.assertEqual(status, 201, body)
        _, raw, _ = self.c.get(f"/main/{kv(body)['id']}/raw")
        self.assertEqual(raw, "line1\nline2")

    def test_search(self) -> None:
        self.publish(board="main", text="needle in main")
        self.publish(board="other", text="needle in other")
        self.publish(board="main", text="hay")
        _, body, _ = self.c.get("/_search", q="needle")
        self.assertIn("needle in main", body)
        self.assertIn("needle in other", body)
        self.assertNotIn("hay", body)

    def test_seq_and_global_id_both_resolve(self) -> None:
        self.publish(board="a", text="a1")
        r = self.publish(board="b", text="b1")
        self.assertEqual(r["seq"], "1")
        _, by_seq, _ = self.c.get("/b/1/raw")
        _, by_id, _ = self.c.get(f"/b/{r['id']}/raw")
        self.assertEqual(by_seq, "b1")
        self.assertEqual(by_id, "b1")


class LimitTests(ServerCase):
    def test_oversized_post_is_413(self) -> None:
        status, body, _ = self.c.get("/publish", board="main", text="x" * 1025)
        self.assertEqual(status, 413)
        self.assertIn("max_post_bytes=1024", body)

    def test_full_board_is_507_and_nothing_is_evicted(self) -> None:
        for i in range(5):
            self.publish(board="cap", text=f"n{i}")
        status, _, _ = self.c.get("/publish", board="cap", text="overflow")
        self.assertEqual(status, 507)
        _, body, _ = self.c.get("/cap", format="ndjson")
        self.assertEqual(len(body.splitlines()), 5)

    def test_bad_board_name(self) -> None:
        status, _, _ = self.c.get("/publish", board="Bad Name!", text="x")
        self.assertEqual(status, 400)

    def test_reserved_author_name(self) -> None:
        status, _, _ = self.c.get("/publish", board="main", name="admin", text="x")
        self.assertEqual(status, 403)

    def test_missing_text(self) -> None:
        status, body, _ = self.c.get("/publish", board="main")
        self.assertEqual(status, 400)
        self.assertIn("hint=", body)


class RateLimitTests(ServerCase):
    overrides = {"write_burst": 2, "write_per_minute": 1}

    def test_write_burst_then_429_with_retry_after(self) -> None:
        self.publish(board="main", text="1")
        self.publish(board="main", text="2")
        status, body, headers = self.c.get("/publish", board="main", text="3")
        self.assertEqual(status, 429)
        self.assertIn("retry_after", kv(body))
        self.assertIn("Retry-After", headers)

    def test_rules_are_never_rate_limited(self) -> None:
        for _ in range(3):
            self.c.get("/publish", board="main", text="spam")
        status, _, _ = self.c.get("/rules")
        self.assertEqual(status, 200)


class GatedTests(ServerCase):
    overrides = {"write_token": "board-secret"}

    def test_write_needs_token(self) -> None:
        status, _, _ = self.c.get("/publish", board="main", text="x")
        self.assertEqual(status, 403)
        self.publish(board="main", text="x", token="board-secret")

    def test_board_token_is_never_echoed_as_edit_key(self) -> None:
        r = self.publish(board="main", text="x", token="board-secret")
        self.assertNotEqual(r["key"], "board-secret")
        self.assertNotIn("board-secret", "\n".join(r.values()))

    def test_board_token_does_not_grant_edit_rights(self) -> None:
        r = self.publish(board="main", text="x", token="board-secret")
        status, _, _ = self.c.get(
            "/publish", edit=r["id"], key="board-secret", token="board-secret", text="hijack"
        )
        self.assertEqual(status, 403)

    def test_rules_say_board_is_gated(self) -> None:
        _, body, _ = self.c.get("/rules")
        self.assertIn("gated", body)


class FileTests(ServerCase):
    def test_upload_fetch_delete(self) -> None:
        status, body, _ = self.c.post("/_files/notes.md", b"# hi\n", "text/markdown")
        self.assertEqual(status, 201, body)
        key = kv(body)["key"]
        status, data, headers = self.c.get("/_files/notes.md")
        self.assertEqual((status, data), (200, "# hi\n"))
        self.assertTrue(headers["Content-Type"].startswith("text/markdown"))
        status, _, _ = self.c.get("/_files/notes.md/delete", key=key)
        self.assertEqual(status, 200)
        status, _, _ = self.c.get("/_files/notes.md")
        self.assertEqual(status, 404)

    def test_cannot_overwrite_someone_elses_file(self) -> None:
        self.c.post("/_files/a.txt", b"original", "text/plain")
        status, _, _ = self.c.post("/_files/a.txt", b"clobbered", "text/plain")
        self.assertEqual(status, 403)
        _, data, _ = self.c.get("/_files/a.txt")
        self.assertEqual(data, "original")

    def test_disallowed_type_and_size(self) -> None:
        status, _, _ = self.c.post("/_files/x.html", b"<b>", "text/html")
        self.assertEqual(status, 415)
        status, _, _ = self.c.post("/_files/big.txt", b"x" * 4096, "text/plain")
        self.assertEqual(status, 413)

    def test_path_traversal_rejected(self) -> None:
        status, _, _ = self.c.post("/_files/..%2Fescape.txt", b"x", "text/plain")
        self.assertIn(status, {400, 404})


class ConfigTests(unittest.TestCase):
    def test_parse_and_coerce(self) -> None:
        cfg = Config.from_sections(parse_config_text(
            "[limits]\nmax_post_bytes = 99\n[files]\nfiles_enabled = yes\n"
            "allowed_file_types = text/plain, application/json\n"
        ))
        self.assertEqual(cfg.max_post_bytes, 99)
        self.assertTrue(cfg.files_enabled)
        self.assertEqual(cfg.allowed_file_types, ("text/plain", "application/json"))

    def test_shipped_config_is_valid(self) -> None:
        path = Path(__file__).resolve().parent.parent / "deploy/etc/msg-lmm-best/msg.conf"
        cfg = Config.load(path)
        cfg.validate()
        self.assertEqual(cfg.site_name, "msg.lmm.best")
        self.assertEqual(cfg.write_token, "")


if __name__ == "__main__":
    unittest.main()
