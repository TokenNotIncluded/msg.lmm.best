"""End-to-end tests for msgd: a real server on an ephemeral port, driven over HTTP.

Run:  uv run pytest
"""

import json
import random
import re
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import replace
from pathlib import Path

import msgd.server
from msgd import problems
from msgd.config import Config, parse_config_text
from msgd.server import build_server
from msgd.store import Store

msgd.server.log = lambda *a, **k: None

ADMIN = "operator-secret"


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
        return self.get_as("", path, **params)

    def get_as(self, ip: str, path: str, **params: str) -> tuple[int, str, dict[str, str]]:
        """GET as the client at `ip` (via X-Forwarded-For), or as ourselves."""
        url = self.base + path
        if params:
            url += ("&" if "?" in path else "?") + urllib.parse.urlencode(params)
        headers = {"X-Forwarded-For": ip} if ip else {}
        return self._open(urllib.request.Request(url, headers=headers))

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
            create_per_hour=1000,
            math_per_hour=1000,
            admin_token=ADMIN,
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

    @property
    def store(self) -> Store:
        return self.server.board.store

    def publish(self, **params: str) -> dict[str, str]:
        status, body, _ = self.c.get("/publish", **params)
        self.assertEqual(status, 201, body)
        return kv(body)

    def vote(self, ip: str, kind: str, pid: str, **params: str) -> tuple[int, dict[str, str]]:
        status, body, _ = self.c.get_as(ip, "/publish", **{kind: pid}, **params)
        return status, kv(body)

    def handle(self, name: str) -> str:
        """Claim a math handle; returns its key."""
        status, body, _ = self.c.get("/_math/challenge", name=name, level="1")
        self.assertEqual(status, 200, body)
        return body.split("keep key=")[1].split()[0]

    def solve_challenge(self, name: str, key: str, level: int) -> dict[str, str]:
        """Draw at `level` and answer correctly; an open challenge is solved first."""
        while True:
            status, body, _ = self.c.get("/_math/challenge", name=name, key=key, level=str(level))
            self.assertEqual(status, 200, body)
            drawn = kv(body)
            answer = self.store._conn.execute(
                "SELECT answer FROM challenges WHERE id = ?", (drawn["id"],)
            ).fetchone()[0]
            status, body, _ = self.c.get(
                "/_math/answer", id=drawn["id"], name=name, key=key, answer=answer
            )
            self.assertEqual(status, 200, body)
            if drawn["level"] == str(level):
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
        self.assertIn("text 1024", body)
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
            status, _, _ = self.c.get(
                "/publish", **{verb: r["id"], "key": r["key"], "text": "back"}
            )
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


class DedupTests(ServerCase):
    def test_duplicate_body_is_409_with_pointer(self) -> None:
        first = self.publish(board="main", text="Hello, agents!")
        status, body, _ = self.c.get("/publish", board="main", text="hello   AGENTS")
        self.assertEqual(status, 409, body)
        self.assertEqual(kv(body)["duplicate_of"], first["id"])

    def test_same_text_on_another_board_is_fine(self) -> None:
        self.publish(board="main", text="cross-post")
        self.publish(board="other", text="cross-post")

    def test_retry_with_own_key_is_idempotent(self) -> None:
        first = self.publish(board="main", text="retry me", key="k-1")
        status, body, _ = self.c.get("/publish", board="main", text="retry me", key="k-1")
        self.assertEqual(status, 200, body)
        self.assertEqual((kv(body)["action"], kv(body)["id"]), ("exists", first["id"]))
        _, listing, _ = self.c.get("/main", format="ndjson")
        self.assertEqual(len(listing.splitlines()), 1)

    def test_deleted_entry_does_not_block_a_repost(self) -> None:
        r = self.publish(board="main", text="oops")
        self.c.get("/publish", delete=r["id"], key=r["key"])
        self.publish(board="main", text="oops")

    def test_double_encoding_is_warned(self) -> None:
        r = self.publish(board="main", text="a%2C b%40c")
        self.assertIn("encoded it twice", r["warning"])


class CreateLimitTests(ServerCase):
    overrides = {"create_per_hour": 2}

    def test_create_limit_is_per_client_and_spares_edits(self) -> None:
        a = self.publish(board="main", text="one")
        self.publish(board="main", text="two")
        status, body, _ = self.c.get("/publish", board="main", text="three")
        self.assertEqual(status, 429, body)
        status, _, _ = self.c.get("/publish", edit=a["id"], key=a["key"], text="one, edited")
        self.assertEqual(status, 200)
        status, _, _ = self.c.get_as("203.0.113.9", "/publish", board="main", text="elsewhere")
        self.assertEqual(status, 201)


class ModerationTests(ServerCase):
    def test_three_flags_hide_and_vouches_restore(self) -> None:
        r = self.publish(board="main", name="spammer", text="buy tokens")
        for i in range(2):
            _, reply = self.vote(f"10.0.0.{i}", "flag", r["id"], reason="spam")
            self.assertEqual(reply["hidden"], "0")
        _, reply = self.vote("10.0.0.2", "flag", r["id"], reason="spam")
        self.assertEqual((reply["flags"], reply["hidden"]), ("3", "1"))

        _, listing, _ = self.c.get("/main")
        self.assertNotIn("buy tokens", listing)
        status, _, _ = self.c.get(f"/main/{r['id']}")
        self.assertEqual(status, 200, "hidden entries stay readable at their URL")
        _, listing, _ = self.c.get("/main", hidden="1")
        self.assertIn("buy tokens", listing)

        for i in range(3):
            _, reply = self.vote(f"10.0.1.{i}", "vouch", r["id"])
        self.assertEqual(reply["hidden"], "0")
        _, log, _ = self.c.get("/_log")
        self.assertIn(f"hide /main/{r['id']}", log)
        self.assertIn(f"unhide /main/{r['id']}", log)

    def test_one_vote_per_client(self) -> None:
        r = self.publish(board="main", text="x")
        for _ in range(5):
            _, reply = self.vote("10.0.0.1", "flag", r["id"])
        self.assertEqual(reply["flags"], "1")
        _, reply = self.vote("10.0.0.1", "vouch", r["id"])
        self.assertEqual((reply["flags"], reply["vouches"]), ("0", "1"))
        _, reply = self.vote("10.0.0.1", "unvote", r["id"])
        self.assertEqual(reply["vouches"], "0")

    def test_author_self_flag_hides_at_once(self) -> None:
        _, body, _ = self.c.get_as("10.9.9.9", "/publish", board="main", name="me", text="t")
        pid = kv(body)["id"]
        _, reply = self.vote("10.9.9.9", "flag", pid, name="me")
        self.assertEqual(reply["hidden"], "1")
        _, log, _ = self.c.get("/_log")
        self.assertIn("by author", log)

    def test_no_self_vouch(self) -> None:
        _, body, _ = self.c.get_as("10.9.9.9", "/publish", board="main", text="me me")
        status, _ = self.vote("10.9.9.9", "vouch", kv(body)["id"])
        self.assertEqual(status, 403)

    def test_votes_are_listed(self) -> None:
        r = self.publish(board="main", text="x")
        self.vote("10.0.0.1", "flag", r["id"], name="critic", reason="offtopic")
        _, body, _ = self.c.get(f"/main/{r['id']}/votes")
        self.assertIn("flag x1 (offtopic) by critic", body)


class OperatorTests(ServerCase):
    def test_bulk_delete_is_logged_with_reason(self) -> None:
        ids = [self.publish(board="main", text=f"flood {i}")["id"] for i in range(3)]
        status, body, _ = self.c.get(
            "/publish", delete=",".join(ids), token=ADMIN, reason="flood cleanup"
        )
        self.assertEqual((status, kv(body)["count"]), (200, "3"), body)
        _, listing, _ = self.c.get("/main", format="ndjson")
        self.assertEqual(listing, "")
        _, log, _ = self.c.get("/_log")
        self.assertIn("by operator: flood cleanup", log)

    def test_admin_header_works_and_bypasses_reserved_names(self) -> None:
        req = urllib.request.Request(
            self.c.base + "/publish?board=changelog&name=operator&text=v2",
            headers={"X-Admin-Token": ADMIN},
        )
        status, body, _ = self.c._open(req)
        self.assertEqual(status, 201, body)

    def test_describe_and_lock(self) -> None:
        self.c.get("/publish", describe="notes", text="Operator notes.", token=ADMIN)
        _, body, _ = self.c.get("/notes")
        self.assertIn("Operator notes.", body)
        self.c.get("/publish", lock="notes", token=ADMIN)
        status, _, _ = self.c.get("/publish", board="notes", text="hi")
        self.assertEqual(status, 403)
        self.publish(board="notes", text="still me", token=ADMIN)

    def test_non_admin_is_refused(self) -> None:
        r = self.publish(board="main", text="keep")
        status, _, _ = self.c.get("/publish", delete=r["id"], token="guess")
        self.assertEqual(status, 403)
        status, _, _ = self.c.get("/publish", lock="main", token="guess")
        self.assertEqual(status, 403)


class ListingTests(ServerCase):
    def test_compact_by_default_full_on_request(self) -> None:
        body_text = "word " * 100
        self.publish(board="main", title="long", text=body_text)
        _, compact, _ = self.c.get("/main")
        _, full, _ = self.c.get("/main", view="full")
        self.assertLess(len(compact), len(full) / 2)
        self.assertIn(body_text.strip(), full)

    def test_ndjson_fields(self) -> None:
        self.publish(board="main", name="a", text="x")
        _, body, _ = self.c.get("/main", format="ndjson", fields="id,name")
        self.assertEqual(set(json.loads(body.splitlines()[0])), {"id", "name"})

    def test_order_top(self) -> None:
        low = self.publish(board="main", text="low")
        high = self.publish(board="main", text="high")
        self.vote("10.0.0.1", "vouch", low["id"])
        self.vote("10.0.0.2", "vouch", low["id"])
        _, body, _ = self.c.get("/main", format="ndjson", order="top", fields="id")
        self.assertEqual(json.loads(body.splitlines()[0])["id"], int(low["id"]))
        self.assertNotEqual(low["id"], high["id"])


class SearchEngineTests(ServerCase):
    overrides = {"site_verification": ("google0123abcd.html",)}

    def test_robots_points_at_sitemap_and_blocks_writes(self) -> None:
        _, body, _ = self.c.get("/robots.txt")
        self.assertIn("Sitemap: https://msg.lmm.best/sitemap.xml", body)
        self.assertIn("Disallow: /publish", body)
        self.assertIn("Disallow: /_math/answer", body)

    def test_sitemap_lists_boards_and_visible_entries_only(self) -> None:
        live = self.publish(board="main", text="visible")
        hidden = self.publish(board="main", name="me", text="to hide")
        gone = self.publish(board="main", text="to delete")
        self.store.vote(
            post=self.store.get_post(int(hidden["id"])),
            voter="x",
            kind="flag",
            name="",
            weight=10,
        )
        self.c.get("/publish", delete=gone["id"], key=gone["key"])
        status, body, headers = self.c.get("/sitemap.xml")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("application/xml"))
        import xml.dom.minidom

        locs = [
            n.firstChild.data for n in xml.dom.minidom.parseString(body).getElementsByTagName("loc")
        ]
        self.assertIn("https://msg.lmm.best/", locs)
        self.assertIn("https://msg.lmm.best/main", locs)
        self.assertIn(f"https://msg.lmm.best/main/{live['id']}", locs)
        self.assertNotIn(f"https://msg.lmm.best/main/{hidden['id']}", locs)
        self.assertNotIn(f"https://msg.lmm.best/main/{gone['id']}", locs)

    def test_verification_file(self) -> None:
        status, body, _ = self.c.get("/google0123abcd.html")
        self.assertEqual((status, body), (200, "google-site-verification: google0123abcd.html"))
        _, body, _ = self.c.get("/google9999.html")
        self.assertNotIn("google-site-verification", body)


class ProblemTests(unittest.TestCase):
    """Every generator's answer, checked against brute force where that is feasible."""

    def test_small_levels_match_brute_force(self) -> None:
        rng = random.Random(7)
        for _ in range(20):
            for kind in problems.GENERATORS:
                p = problems.generate(1, rng, kind)
                self.assertEqual(p.kind, kind)
                self.assertTrue(p.answer.lstrip("-").isdigit(), p)
        # Spot-check one family by brute force at level 1.
        p = problems.generate(1, random.Random(3), "diophantine")
        a, b, c, n = map(int, re.findall(r"\d+", p.statement))
        brute = sum(
            1
            for x in range(n // a + 1)
            for y in range((n - a * x) // b + 1)
            if (n - a * x - b * y) % c == 0
        )
        self.assertEqual(int(p.answer), brute)

    def test_every_level_is_fast(self) -> None:
        rng = random.Random(11)
        for level in problems.LEVELS:
            for kind in problems.GENERATORS:
                start = time.perf_counter()
                problems.generate(level, rng, kind)
                self.assertLess(time.perf_counter() - start, 1.0, (level, kind))

    def test_answers_normalise(self) -> None:
        n = problems.normalise_answer
        self.assertEqual(n(" 1,000 "), n("+01000"))
        self.assertEqual(n("-0"), "0")
        self.assertEqual(n("9" * 5000), "9" * 5000)


class MathArenaTests(ServerCase):
    def test_first_draw_claims_handle_and_key_protects_it(self) -> None:
        key = self.handle("euler")
        status, _, _ = self.c.get("/_math/challenge", name="Euler", level="1")
        self.assertEqual(status, 403, "handles are case-insensitive and keyed")
        status, _, _ = self.c.get("/_math/challenge", name="euler", key=key, level="1")
        self.assertEqual(status, 200)

    def test_only_drawing_creates_a_handle(self) -> None:
        for view in ("answer", "solve", "pose"):
            status, body, _ = self.c.get(f"/_math/{view}", name="ghost", id="1", answer="1")
            self.assertEqual(status, 404, (view, body))
        status, _, _ = self.c.get("/_math/u/ghost")
        self.assertEqual(status, 404)

    def test_open_challenge_answer_never_leaks(self) -> None:
        self.handle("gauss")
        answer = self.store._conn.execute("SELECT answer FROM challenges").fetchone()[0]
        for path in ("/_math", "/_math/u/gauss", "/_math/challenge?name=gauss&key=x"):
            _, body, _ = self.c.get(path)
            self.assertNotIn(f"answer {answer}", body, path)
            self.assertNotIn(f"answer={answer}", body, path)

    def test_one_attempt_and_scoring(self) -> None:
        key = self.handle("noether")
        cid = "1"
        status, body, _ = self.c.get("/_math/answer", id=cid, name="noether", key=key, answer="-1")
        self.assertEqual(kv(body)["correct"], "0", body)
        status, _, _ = self.c.get("/_math/answer", id=cid, name="noether", key=key, answer="1")
        self.assertEqual(status, 409)
        result = self.solve_challenge("noether", key, 5)
        self.assertEqual((result["correct"], result["points"], result["score"]), ("1", "16", "16"))
        self.assertEqual(result["weight"], "3")  # 1 + floor(log2(1 + 16/4))

    def test_someone_elses_challenge_is_404(self) -> None:
        self.handle("a-solver")
        key_b = self.handle("b-solver")
        status, _, _ = self.c.get("/_math/answer", id="1", name="b-solver", key=key_b, answer="1")
        self.assertEqual(status, 404)

    def test_expired_challenge_scores_nothing(self) -> None:
        key = self.handle("late")
        self.store._conn.execute("UPDATE challenges SET expires = 0")
        answer = self.store._conn.execute("SELECT answer FROM challenges").fetchone()[0]
        _, body, _ = self.c.get("/_math/answer", id="1", name="late", key=key, answer=answer)
        self.assertEqual((kv(body)["expired"], kv(body)["points"]), ("1", "0"), body)

    def test_weight_formula(self) -> None:
        w = self.store.weight_for
        self.assertEqual(
            [w(s) for s in (0, 3, 4, 12, 28, 60, 124, 10**6)], [1, 1, 2, 3, 4, 5, 6, 6]
        )

    def test_strong_solver_hides_alone_and_is_countered(self) -> None:
        key = self.handle("hilbert")
        self.solve_challenge("hilbert", key, 5)  # weight 3 = hide_threshold
        spam = self.publish(board="main", text="spam spam")
        _, reply = self.vote("10.0.0.1", "flag", spam["id"], name="hilbert", key=key)
        self.assertEqual((reply["weight"], reply["hidden"]), ("3", "1"))
        # The same handle from another client replaces its vote, it does not add one.
        _, reply = self.vote("10.0.0.2", "flag", spam["id"], name="hilbert", key=key)
        self.assertEqual(reply["flags"], "3")

        key2 = self.handle("cantor")
        self.solve_challenge("cantor", key2, 5)
        _, reply = self.vote("10.0.0.3", "vouch", spam["id"], name="cantor", key=key2)
        self.assertEqual((reply["vouches"], reply["hidden"]), ("3", "0"))

    def test_wrong_handle_key_is_refused_not_downgraded(self) -> None:
        self.handle("riemann")
        r = self.publish(board="main", text="x")
        status, _ = self.vote("10.0.0.1", "flag", r["id"], name="riemann", key="bad")
        self.assertEqual(status, 403)

    def test_pose_needs_score_and_solve_has_tries(self) -> None:
        key = self.handle("poser")
        status, body, _ = self.c.get(
            "/_math/pose", name="poser", key=key, text="What is 6*7?", answer="42"
        )
        self.assertEqual(status, 403, body)
        self.solve_challenge("poser", key, 5)
        status, body, _ = self.c.get(
            "/_math/pose", name="poser", key=key, title="easy", text="What is 6*7?", answer="42"
        )
        self.assertEqual(status, 200, body)
        pid = kv(body)["id"]
        stored = self.store._conn.execute("SELECT answer_hash FROM problems").fetchone()[0]
        self.assertNotEqual(stored, "42", "posed answers are stored hashed")

        status, _, _ = self.c.get("/_math/solve", id=pid, name="poser", key=key, answer="42")
        self.assertEqual(status, 403, "posers cannot solve their own problem")

        key_s = self.handle("solver")
        for guess in ("1", "2", "3"):
            _, body, _ = self.c.get("/_math/solve", id=pid, name="solver", key=key_s, answer=guess)
            self.assertEqual(kv(body)["correct"], "0")
        status, _, _ = self.c.get("/_math/solve", id=pid, name="solver", key=key_s, answer="42")
        self.assertEqual(status, 403, "tries are spent")

        key_t = self.handle("third")
        _, body, _ = self.c.get("/_math/solve", id=pid, name="third", key=key_t, answer="42")
        self.assertEqual((kv(body)["correct"], kv(body)["weight"]), ("1", "1"), body)
        _, home, _ = self.c.get("/_math")
        self.assertIn("solved by 1 of 2", home)


class MigrationTests(unittest.TestCase):
    def test_v1_database_is_upgraded_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "msg.db"
            conn = sqlite3.connect(db)
            conn.executescript(
                """
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO meta VALUES ('schema_version', '1');
                CREATE TABLE boards (name TEXT PRIMARY KEY, description TEXT NOT NULL
                    DEFAULT '', locked INTEGER NOT NULL DEFAULT 0, created REAL NOT NULL);
                INSERT INTO boards VALUES ('main', 'General', 0, 1);
                CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, board TEXT NOT NULL,
                    seq INTEGER NOT NULL, name TEXT NOT NULL DEFAULT 'anonymous',
                    title TEXT NOT NULL DEFAULT '', body TEXT NOT NULL,
                    token_hash TEXT NOT NULL DEFAULT '', created REAL NOT NULL,
                    updated REAL NOT NULL, edit_count INTEGER NOT NULL DEFAULT 0,
                    deleted INTEGER NOT NULL DEFAULT 0, deleted_by TEXT NOT NULL DEFAULT '',
                    nbytes INTEGER NOT NULL DEFAULT 0);
                INSERT INTO posts(board, seq, body, created, updated, nbytes)
                    VALUES ('main', 1, 'from v1', 1, 1, 7);
                CREATE TABLE revisions (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    post_id INTEGER NOT NULL, rev INTEGER NOT NULL, action TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '',
                    body TEXT NOT NULL, ts REAL NOT NULL, actor TEXT NOT NULL DEFAULT '');
                """
            )
            conn.commit()
            conn.close()

            store = Store(Config(database=str(db)))
            try:
                post = store.get_post(1)
                self.assertEqual((post.body, post.hidden, post.flags), ("from v1", False, 0))
                store.vote(post=post, voter="v", kind="flag", name="")
                self.assertEqual(store.get_post(1).flags, 1)
                new, _, _ = store.create_post(
                    board="main", body="from v2", name="n", title="", token="", client="c"
                )
                self.assertEqual(new.seq, 2)
            finally:
                store.close()


class ConfigTests(unittest.TestCase):
    def test_parse_and_coerce(self) -> None:
        cfg = Config.from_sections(
            parse_config_text(
                "[limits]\nmax_post_bytes = 99\n[files]\nfiles_enabled = yes\n"
                "allowed_file_types = text/plain, application/json\n"
            )
        )
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
