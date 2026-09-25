"""GET-only bridge and search-engine syntax behavior."""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from msgd.config import Config
from msgd.search import parse_search_query
from msgd.server import build_server


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def sign_b64(key: Ed25519PrivateKey, payload_b64: str) -> str:
    return base64.b64encode(key.sign(base64.b64decode(payload_b64))).decode("ascii")


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

    def get(self, path: str, **params: str) -> tuple[int, str]:
        query = urllib.parse.urlencode(params)
        status, body, _ = self.raw(path + (("?" + query) if query else ""))
        return status, body

    def post(self, path: str, **params: str) -> tuple[int, str]:
        data = urllib.parse.urlencode(params).encode()
        request = urllib.request.Request(
            self.base + path,
            data=data,
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

    def multipart(
        self,
        path: str,
        fields: dict[str, str],
        filename: str,
        data: bytes,
    ) -> tuple[int, str]:
        boundary = "----msgd-bridge-test"
        chunks: list[bytes] = []
        for name, value in fields.items():
            chunks += [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            ]
        chunks += [
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(),
            b"Content-Type: text/plain\r\n\r\n",
            data,
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
        request = urllib.request.Request(
            self.base + path,
            data=b"".join(chunks),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read().decode()
            finally:
                exc.close()


class BridgeSearchCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root_key = Ed25519PrivateKey.generate()
        root_public = Path(self.tmp.name) / "root.pub"
        root_public.write_text(public_b64(self.root_key) + "\n")

        cfg = Config(
            host="127.0.0.1",
            port=0,
            database=str(Path(self.tmp.name) / "msg.db"),
            root_public_key=str(root_public),
            max_storage_bytes=2_000_000,
            max_post_bytes=16_384,
            max_post_bytes_post=100_000,
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

    def signing(self, **params: str) -> dict:
        status, body = self.c.get("/_signing", **params)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def issue(self, subject: Ed25519PrivateKey) -> str:
        grants = json.dumps(
            [
                {
                    "topic": "*",
                    "actions": ["post.create", "post.edit.self", "post.delete.self"],
                }
            ],
            separators=(",", ":"),
        )
        info = self.signing(
            action="cert.issue",
            key=public_b64(self.root_key),
            issuer_serial="root",
            subject_key=public_b64(subject),
            grants=grants,
        )
        status, body = self.c.post(
            "/_cert",
            cert=info["certificate"],
            sig=sign_b64(self.root_key, info["payload_b64"]),
        )
        self.assertEqual(status, 201, body)
        return json.loads(body)["serial"]

    def signed_post(self, key: Ed25519PrivateKey, text: str, *, name: str = "agent") -> int:
        info = self.signing(
            action="post.create",
            key=public_b64(key),
            board="main",
            name=name,
            text=text,
        )
        status, body = self.c.post(
            "/publish",
            board="main",
            name=name,
            text=text,
            key=public_b64(key),
            sig=sign_b64(key, info["payload_b64"]),
            nonce=info["nonce"],
            issued=str(info["issued"]),
        )
        self.assertEqual(status, 201, body)
        return int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])

    def test_guest_get_only_bridge(self) -> None:
        policy = json.loads(self.c.get("/_policy", board="guest")[1])
        self.assertEqual(policy["permissions"], 7)
        self.assertTrue(policy["locked"])

        status, body = self.c.get("/guest/post", name="Tiny", text="hello")
        self.assertEqual(status, 201, body)
        post_id = int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])
        self.assertIn("[auth:unsigned] Tiny", self.c.get("/guest")[1])

        status, _ = self.c.get("/guest/edit", id=str(post_id), text="updated")
        self.assertEqual(status, 200)
        self.assertEqual(self.c.get(f"/guest/{post_id}/raw")[1], "updated")

        status, _ = self.c.get("/guest/delete", id=str(post_id))
        self.assertEqual(status, 200)
        self.assertEqual(self.c.get(f"/guest/{post_id}")[0], 404)

    def test_custody_identity_is_capability_controlled_and_low_assurance(self) -> None:
        status, body, headers = self.c.raw(
            "/custody/new?" + urllib.parse.urlencode({"name": "TinyAgent"})
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        identity = json.loads(body)
        token = identity["token"]
        self.assertEqual(identity["auth"], "custodial")

        status, body = self.c.get("/custody/me", token=token)
        self.assertEqual(status, 200, body)
        self.assertNotIn(token, body)

        status, rotated_body = self.c.get("/custody/rotate", token=token)
        self.assertEqual(status, 200, rotated_body)
        rotated = json.loads(rotated_body)
        self.assertEqual(rotated["author_id"], identity["author_id"])
        self.assertNotEqual(rotated["token"], token)
        self.assertEqual(self.c.get("/custody/me", token=token)[0], 403)
        token = rotated["token"]

        status, body = self.c.get("/custody/post", token=token, text="custody hello")
        self.assertEqual(status, 201, body)
        post_id = int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])
        self.assertNotIn(token, body)

        listing = self.c.get("/custody")[1]
        self.assertIn(f"#{post_id} /custody [auth:custodial] TinyAgent", listing)
        self.assertNotIn(token, listing)

        meta = json.loads(self.c.get(f"/custody/{post_id}/meta")[1])
        self.assertEqual(meta["authentication"]["status"], "custodial")
        self.assertTrue(meta["custodial"])
        self.assertNotIn("custody_id", meta)

        key_info = json.loads(self.c.get(f"/key/{identity['author_id']}")[1])
        self.assertTrue(key_info["custodial"])
        self.assertFalse(key_info["certification"]["certified"])

        wrong = json.loads(self.c.get("/custody/new", name="Other")[1])["token"]
        self.assertEqual(
            self.c.get("/custody/edit", token=wrong, id=str(post_id), text="attack")[0],
            403,
        )

        status, _ = self.c.get("/custody/edit", token=token, id=str(post_id), text="updated")
        self.assertEqual(status, 200)
        self.assertEqual(self.c.get(f"/custody/{post_id}/raw")[1], "updated")

        self.assertEqual(
            self.c.get("/publish", board="custody", text="bypass")[0],
            403,
        )

        status, _ = self.c.get("/custody/delete", token=token, id=str(post_id))
        self.assertEqual(status, 200)
        self.assertEqual(self.c.get(f"/custody/{post_id}")[0], 404)

    def test_search_engine_syntax(self) -> None:
        self.assertEqual(self.c.get("/_search")[0], 200)
        help_text = self.c.get("/_search")[1]
        self.assertIn("board:meta", help_text)
        self.assertIn("auth:certified", help_text)

        first = self.c.get(
            "/publish",
            board="main",
            name="Alice",
            title="Network incident",
            text="network error spam",
        )[1]
        first_id = int(dict(line.split("=", 1) for line in first.splitlines() if "=" in line)["id"])

        second = self.c.get(
            "/publish",
            board="meta",
            name="Bob",
            title="Network incident",
            text="network error clean",
        )[1]
        second_id = int(
            dict(line.split("=", 1) for line in second.splitlines() if "=" in line)["id"]
        )

        reply = self.c.get(
            "/publish",
            reply_to=str(second_id),
            name="Bob",
            text="follow up",
        )[1]
        reply_id = int(dict(line.split("=", 1) for line in reply.splitlines() if "=" in line)["id"])

        member = Ed25519PrivateKey.generate()
        self.issue(member)
        trusted_id = self.signed_post(member, "trusted search note", name="Trusted")

        custody = json.loads(self.c.get("/custody/new", name="CustodySearch")[1])
        custody_post = self.c.get(
            "/custody/post",
            token=custody["token"],
            text="custody search note",
        )[1]
        custody_id = int(
            dict(line.split("=", 1) for line in custody_post.splitlines() if "=" in line)["id"]
        )

        status, upload = self.c.multipart(
            "/publish",
            {"board": "meta", "name": "FileAgent", "text": "attachment search"},
            "note.txt",
            b"hello",
        )
        self.assertEqual(status, 201, upload)
        file_id = int(dict(line.split("=", 1) for line in upload.splitlines() if "=" in line)["id"])

        status, body = self.c.get(
            "/_search",
            q="network -spam board:meta from:Bob",
        )
        self.assertEqual(status, 200, body)
        self.assertIn(f"#{second_id}", body)
        self.assertNotIn(f"#{first_id}", body)

        status, body = self.c.get(
            "/_search",
            q='title:"Network incident" board:meta',
        )
        self.assertEqual(status, 200, body)
        self.assertIn(f"#{second_id}", body)

        self.assertIn(
            f"#{reply_id}",
            self.c.get("/_search", q="reply:any from:Bob")[1],
        )
        self.assertIn(
            f"#{trusted_id}",
            self.c.get("/_search", q="trusted auth:certified")[1],
        )
        self.assertIn(
            f"#{custody_id}",
            self.c.get("/_search", q="custody auth:custodial")[1],
        )
        self.assertIn(
            f"#{file_id}",
            self.c.get("/_search", q="has:file board:meta")[1],
        )

        status, ndjson = self.c.get(
            "/_search",
            q="trusted auth:certified",
            format="ndjson",
        )
        self.assertEqual(status, 200)
        row = json.loads(ndjson.splitlines()[0])
        self.assertEqual(row["id"], trusted_id)
        self.assertEqual(row["authentication"]["status"], "certified")

        self.assertEqual(self.c.get("/_search", q="auth:nope")[0], 400)

    def test_homepage_is_layered_but_index_remains_machine_oriented(self) -> None:
        self.c.get("/guest/post", name="Tiny", text="recent hello")
        home = self.c.get("/")[1]
        self.assertIn("## active", home)
        self.assertIn("## recent", home)
        self.assertIn("## topics", home)
        self.assertIn("## identity", home)
        self.assertIn("## get-only", home)
        self.assertIn("/guest", home)
        self.assertIn("/custody", home)

        robots = self.c.get("/robots.txt")[1]
        self.assertIn("Disallow: /custody/new", robots)
        self.assertIn("Disallow: /custody/rotate", robots)
        self.assertIn("Disallow: /guest/post", robots)

    def test_search_parser_quotes_dates_and_sort(self) -> None:
        spec = parse_search_query(
            '"alpha beta" -spam board:meta from:"Agent X" '
            "after:2026-09-20 before:2026-09-26 reply:any has:file sort:old"
        )
        self.assertEqual(spec.terms, ("alpha beta",))
        self.assertEqual(spec.excluded_terms, ("spam",))
        self.assertEqual(spec.board, "meta")
        self.assertEqual(spec.author_name, "Agent X")
        self.assertTrue(spec.replies_only)
        self.assertTrue(spec.has_files)
        self.assertEqual(spec.order, "asc")
        self.assertLess(spec.after or 0, spec.before or 0)


if __name__ == "__main__":
    unittest.main()
