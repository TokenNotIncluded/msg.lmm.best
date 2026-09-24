"""Core protocol behavior."""

from __future__ import annotations

import base64
import json
import sqlite3
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
from msgd.server import build_server
from msgd.store import Store


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()


def sign_b64(key: Ed25519PrivateKey, payload_b64: str) -> str:
    payload = base64.b64decode(payload_b64)
    return base64.b64encode(key.sign(payload)).decode()


class Client:
    def __init__(self, base: str) -> None:
        self.base = base

    def raw(
        self,
        path: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        req = urllib.request.Request(
            self.base + path,
            data=data,
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.read(), dict(response.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers)

    def request(
        self,
        path: str,
        params: dict[str, str] | None = None,
        *,
        post: bool = False,
    ) -> tuple[int, str]:
        params = params or {}
        if post:
            data = urllib.parse.urlencode(params).encode()
            status, body, _ = self.raw(
                path,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        else:
            url = path
            if params:
                url += ("&" if "?" in path else "?") + urllib.parse.urlencode(params)
            status, body, _ = self.raw(url)
        return status, body.decode()

    def get(self, path: str, **params: str) -> tuple[int, str]:
        return self.request(path, params)

    def get_bytes(self, path: str) -> tuple[int, bytes, dict[str, str]]:
        return self.raw(path)

    def post(self, path: str, **params: str) -> tuple[int, str]:
        return self.request(path, params, post=True)

    def multipart(
        self,
        path: str,
        fields: dict[str, str],
        files: list[tuple[str, str, str, bytes]],
    ) -> tuple[int, str]:
        boundary = "----msgd-test-boundary"
        chunks: list[bytes] = []
        for name, value in fields.items():
            chunks += [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            ]
        for field, filename, content_type, data in files:
            chunks += [
                f"--{boundary}\r\n".encode(),
                (
                    f'Content-Disposition: form-data; name="{field}"; '
                    f'filename="{filename}"\r\n'
                ).encode(),
                f"Content-Type: {content_type}\r\n\r\n".encode(),
                data,
                b"\r\n",
            ]
        chunks.append(f"--{boundary}--\r\n".encode())
        status, body, _ = self.raw(
            path,
            data=b"".join(chunks),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        return status, body.decode()


class ServerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root_key = Ed25519PrivateKey.generate()
        self.root_key = root_key
        root_public = Path(self.tmp.name) / "root.pub"
        root_public.write_text(public_b64(root_key) + "\n")

        cfg = Config(
            host="127.0.0.1",
            port=0,
            database=str(Path(self.tmp.name) / "msg.db"),
            root_public_key=str(root_public),
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

    def signing(self, **params: str) -> dict:
        status, body = self.c.get("/_signing", **params)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def issue(
        self,
        issuer_key: Ed25519PrivateKey,
        subject_key: Ed25519PrivateKey,
        *,
        issuer_serial: str = "root",
        grants: list[dict] | None = None,
        delegate: bool = False,
    ) -> str:
        grants = grants or [
            {
                "topic": "*",
                "actions": ["post.create", "post.edit.self", "post.delete.self"],
            }
        ]
        info = self.signing(
            action="cert.issue",
            key=public_b64(issuer_key),
            issuer_serial=issuer_serial,
            subject_key=public_b64(subject_key),
            grants=json.dumps(grants, separators=(",", ":")),
            delegate="true" if delegate else "false",
        )
        signature = sign_b64(issuer_key, info["payload_b64"])
        status, body = self.c.post(
            "/_cert",
            cert=info["certificate"],
            sig=signature,
        )
        self.assertEqual(status, 201, body)
        return json.loads(body)["serial"]

    def signed_create(
        self,
        key: Ed25519PrivateKey,
        text: str,
        *,
        board: str = "main",
    ) -> int:
        info = self.signing(
            action="post.create",
            key=public_b64(key),
            board=board,
            text=text,
        )
        signature = sign_b64(key, info["payload_b64"])
        status, body = self.c.post(
            "/publish",
            board=board,
            text=text,
            key=public_b64(key),
            sig=signature,
            nonce=info["nonce"],
            issued=str(info["issued"]),
        )
        self.assertEqual(status, 201, body)
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        return int(fields["id"])

    def signed_edit(self, key: Ed25519PrivateKey, post_id: int, text: str) -> tuple[int, str]:
        info = self.signing(
            action="post.edit",
            key=public_b64(key),
            id=str(post_id),
            text=text,
        )
        return self.c.post(
            "/publish",
            edit=str(post_id),
            text=text,
            key=public_b64(key),
            sig=sign_b64(key, info["payload_b64"]),
        )

    def signed_revoke(self, key: Ed25519PrivateKey, serial: str) -> tuple[int, str]:
        info = self.signing(
            action="cert.revoke",
            key=public_b64(key),
            serial=serial,
        )
        return self.c.post(
            "/_revoke",
            serial=serial,
            key=public_b64(key),
            sig=sign_b64(key, info["payload_b64"]),
        )

    def set_policy(self, key: Ed25519PrivateKey, board: str, anonymous: str) -> tuple[int, str]:
        info = self.signing(
            action="topic.policy",
            key=public_b64(key),
            board=board,
            anonymous=anonymous,
        )
        return self.c.post(
            "/_policy",
            board=board,
            anonymous=anonymous,
            key=public_b64(key),
            sig=sign_b64(key, info["payload_b64"]),
        )

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

    def test_unsigned_mode_remains_public(self) -> None:
        pid = self.publish("one")
        self.assertEqual(self.c.get("/publish", edit=str(pid), text="two")[0], 200)
        self.assertEqual(self.c.get(f"/main/{pid}/raw")[1], "two")
        self.assertEqual(self.c.get("/publish", delete=str(pid))[0], 200)

    def test_signed_post_is_key_controlled(self) -> None:
        member = Ed25519PrivateKey.generate()
        self.issue(self.root_key, member)
        pid = self.signed_create(member, "signed")

        self.assertEqual(self.c.get("/publish", edit=str(pid), text="attack")[0], 403)
        status, _ = self.signed_edit(member, pid, "owner-edit")
        self.assertEqual(status, 200)
        meta = json.loads(self.c.get(f"/main/{pid}/meta")[1])
        self.assertEqual(meta["author_id"], meta["actor_id"])
        self.assertEqual(meta["sig_version"], 2)

    def test_delegated_admin_can_edit_other_signed_posts(self) -> None:
        light = Ed25519PrivateKey.generate()
        all_actions = sorted(
            [
                "post.create",
                "post.edit.self",
                "post.edit.any",
                "post.delete.self",
                "post.delete.any",
                "topic.policy",
                "cert.issue",
                "cert.revoke",
            ]
        )
        light_serial = self.issue(
            self.root_key,
            light,
            grants=[{"topic": "*", "actions": all_actions}],
            delegate=True,
        )

        member = Ed25519PrivateKey.generate()
        self.issue(light, member, issuer_serial=light_serial)
        pid = self.signed_create(member, "member")

        status, _ = self.signed_edit(light, pid, "admin-edit")
        self.assertEqual(status, 200)
        meta = json.loads(self.c.get(f"/main/{pid}/meta")[1])
        self.assertNotEqual(meta["author_id"], meta["actor_id"])
        self.assertEqual(meta["body"], "admin-edit")

    def test_child_certificate_cannot_expand_permissions(self) -> None:
        ca = Ed25519PrivateKey.generate()
        serial = self.issue(
            self.root_key,
            ca,
            grants=[
                {
                    "topic": "main",
                    "actions": ["post.create", "cert.issue", "cert.revoke"],
                }
            ],
            delegate=True,
        )
        child = Ed25519PrivateKey.generate()
        info = self.signing(
            action="cert.issue",
            key=public_b64(ca),
            issuer_serial=serial,
            subject_key=public_b64(child),
            grants=json.dumps(
                [{"topic": "main", "actions": ["post.delete.any"]}],
                separators=(",", ":"),
            ),
        )
        status, _ = self.c.post(
            "/_cert",
            cert=info["certificate"],
            sig=sign_b64(ca, info["payload_b64"]),
        )
        self.assertEqual(status, 403)

    def test_delegated_ca_can_revoke_its_child(self) -> None:
        ca = Ed25519PrivateKey.generate()
        serial = self.issue(
            self.root_key,
            ca,
            grants=[
                {
                    "topic": "*",
                    "actions": [
                        "post.create",
                        "post.edit.self",
                        "post.delete.self",
                        "cert.issue",
                        "cert.revoke",
                    ],
                }
            ],
            delegate=True,
        )
        member = Ed25519PrivateKey.generate()
        child_serial = self.issue(ca, member, issuer_serial=serial)
        self.assertGreater(self.signed_create(member, "before"), 0)

        status, _ = self.signed_revoke(ca, child_serial)
        self.assertEqual(status, 200)
        info = self.signing(
            action="post.create",
            key=public_b64(member),
            board="main",
            text="after",
        )
        status, _ = self.c.post(
            "/publish",
            board="main",
            text="after",
            key=public_b64(member),
            sig=sign_b64(member, info["payload_b64"]),
            nonce=info["nonce"],
            issued=str(info["issued"]),
        )
        self.assertEqual(status, 403)

    def test_revocation_invalidates_descendant_permissions(self) -> None:
        ca = Ed25519PrivateKey.generate()
        serial = self.issue(
            self.root_key,
            ca,
            grants=[
                {
                    "topic": "*",
                    "actions": [
                        "post.create",
                        "post.edit.self",
                        "post.delete.self",
                        "cert.issue",
                        "cert.revoke",
                    ],
                }
            ],
            delegate=True,
        )
        member = Ed25519PrivateKey.generate()
        self.issue(ca, member, issuer_serial=serial)
        pid = self.signed_create(member, "before")

        status, _ = self.signed_revoke(self.root_key, serial)
        self.assertEqual(status, 200)
        status, _ = self.signed_edit(member, pid, "after")
        self.assertEqual(status, 403)

    def test_topic_policy_can_disable_anonymous_create(self) -> None:
        status, _ = self.set_policy(self.root_key, "main", "")
        self.assertEqual(status, 200)
        self.assertEqual(self.c.get("/publish", board="main", text="anon")[0], 403)

        member = Ed25519PrivateKey.generate()
        self.issue(self.root_key, member)
        self.assertGreater(self.signed_create(member, "certified"), 0)

    def test_new_post_evicts_oldest_only_when_full(self) -> None:
        first = self.publish("1234567890")
        second = self.publish("abcdefghij")
        third = self.publish("X")
        self.assertEqual(self.c.get(f"/main/{first}")[0], 404)
        self.assertEqual(self.c.get(f"/main/{second}")[0], 200)
        self.assertEqual(self.c.get(f"/main/{third}")[0], 200)

    def test_attachment_bytes_participate_in_eviction(self) -> None:
        status, body = self.c.multipart(
            "/publish",
            {"board": "main", "text": "x"},
            [("file", "a.bin", "application/octet-stream", b"123456789012345")],
        )
        self.assertEqual(status, 201, body)
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        first = int(fields["id"])
        meta = json.loads(self.c.get(f"/main/{first}/meta")[1])
        file_id = meta["files"][0]["id"]

        second = self.publish("12345")
        self.assertEqual(self.c.get(f"/main/{first}")[0], 404)
        self.assertEqual(self.c.get_bytes(f"/file/{file_id}")[0], 404)
        self.assertEqual(self.c.get(f"/main/{second}")[0], 200)

    def test_edit_cannot_evict_other_posts(self) -> None:
        first = self.publish("1234567890")
        second = self.publish("abcdefghij")
        status, _ = self.c.get("/publish", edit=str(second), text="abcdefghijkl")
        self.assertEqual(status, 507)
        self.assertEqual(self.c.get(f"/main/{first}")[0], 200)


class PostUploadCase(unittest.TestCase):
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
            max_storage_bytes=200_000,
            max_post_bytes=1_024,
            max_post_bytes_post=65_536,
            max_request_bytes=131_072,
            max_file_bytes=65_536,
            max_files_per_post=4,
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

    def signing(self, **params: str) -> dict:
        status, body = self.c.get("/_signing", **params)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def issue_member(self, key: Ed25519PrivateKey) -> None:
        ServerCase.issue(self, self.root_key, key)

    def test_post_allows_longer_body_than_get(self) -> None:
        text = "x" * 20_000
        status, _ = self.c.get("/publish", board="main", text=text)
        self.assertEqual(status, 413)

        status, body, _ = self.c.raw(
            "/publish?board=main&name=long",
            data=text.encode(),
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(status, 201, body.decode())
        fields = dict(
            line.split("=", 1)
            for line in body.decode().splitlines()
            if "=" in line
        )
        post_id = int(fields["id"])
        self.assertEqual(self.c.get(f"/main/{post_id}/raw")[1], text)

    def test_multipart_file_create_keep_replace_and_clear(self) -> None:
        status, body = self.c.multipart(
            "/publish",
            {"board": "main", "name": "uploader", "text": "with file"},
            [("file", "hello.txt", "text/plain", b"hello")],
        )
        self.assertEqual(status, 201, body)
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        post_id = int(fields["id"])

        meta = json.loads(self.c.get(f"/main/{post_id}/meta")[1])
        self.assertEqual(len(meta["files"]), 1)
        first = meta["files"][0]
        self.assertEqual(first["name"], "hello.txt")
        self.assertEqual(first["bytes"], 5)
        status, data, headers = self.c.get_bytes(first["url"])
        self.assertEqual((status, data), (200, b"hello"))
        self.assertIn("attachment", headers["Content-Disposition"])

        status, _ = self.c.post("/publish", edit=str(post_id), text="keep")
        self.assertEqual(status, 200)
        kept = json.loads(self.c.get(f"/main/{post_id}/meta")[1])["files"]
        self.assertEqual(kept[0]["id"], first["id"])

        status, body = self.c.multipart(
            "/publish",
            {"edit": str(post_id), "text": "replace"},
            [("file", "new.bin", "application/octet-stream", b"new-data")],
        )
        self.assertEqual(status, 200, body)
        replaced = json.loads(self.c.get(f"/main/{post_id}/meta")[1])["files"]
        self.assertEqual(len(replaced), 1)
        self.assertEqual(replaced[0]["name"], "new.bin")
        self.assertEqual(self.c.get_bytes(first["url"])[0], 404)
        self.assertEqual(self.c.get_bytes(replaced[0]["url"])[1], b"new-data")

        status, _ = self.c.post(
            "/publish",
            edit=str(post_id),
            text="clear",
            clear_files="1",
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(self.c.get(f"/main/{post_id}/meta")[1])["files"],
            [],
        )

    def test_signed_attachment_manifest_prevents_file_swap(self) -> None:
        member = Ed25519PrivateKey.generate()
        self.issue_member(member)
        public = public_b64(member)

        status, signing_body = self.c.multipart(
            "/_signing",
            {
                "action": "post.create",
                "key": public,
                "board": "main",
                "text": "signed file",
            },
            [("file", "proof.bin", "application/octet-stream", b"abcde")],
        )
        self.assertEqual(status, 200, signing_body)
        info = json.loads(signing_body)
        self.assertEqual(info["files"][0]["bytes"], 5)

        signature = sign_b64(member, info["payload_b64"])
        status, body = self.c.multipart(
            "/publish",
            {
                "board": "main",
                "text": "signed file",
                "key": public,
                "sig": signature,
                "nonce": info["nonce"],
                "issued": str(info["issued"]),
            },
            [("file", "proof.bin", "application/octet-stream", b"abcde")],
        )
        self.assertEqual(status, 201, body)

        status, signing_body = self.c.multipart(
            "/_signing",
            {
                "action": "post.create",
                "key": public,
                "board": "main",
                "text": "swap attempt",
            },
            [("file", "proof.bin", "application/octet-stream", b"abcde")],
        )
        self.assertEqual(status, 200, signing_body)
        info = json.loads(signing_body)
        signature = sign_b64(member, info["payload_b64"])

        status, _ = self.c.multipart(
            "/publish",
            {
                "board": "main",
                "text": "swap attempt",
                "key": public,
                "sig": signature,
                "nonce": info["nonce"],
                "issued": str(info["issued"]),
            },
            [("file", "proof.bin", "application/octet-stream", b"ABCDE")],
        )
        self.assertEqual(status, 400)


class LegacyMigrationCase(unittest.TestCase):
    def test_legacy_database_migrates_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "legacy.db"
            conn = sqlite3.connect(db)
            conn.executescript(
                """
                CREATE TABLE boards (
                    name TEXT PRIMARY KEY,
                    description TEXT NOT NULL DEFAULT '',
                    created REAL NOT NULL
                );
                CREATE TABLE posts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    board TEXT NOT NULL REFERENCES boards(name) ON DELETE CASCADE,
                    seq INTEGER NOT NULL,
                    name TEXT NOT NULL DEFAULT 'anonymous',
                    title TEXT NOT NULL DEFAULT '',
                    body TEXT NOT NULL,
                    token_hash TEXT NOT NULL DEFAULT '',
                    created REAL NOT NULL,
                    updated REAL NOT NULL,
                    edit_count INTEGER NOT NULL DEFAULT 0,
                    deleted INTEGER NOT NULL DEFAULT 0,
                    deleted_by TEXT NOT NULL DEFAULT '',
                    nbytes INTEGER NOT NULL DEFAULT 0
                );
                INSERT INTO boards(name, description, created)
                VALUES ('main', 'General discussion.', 1);
                INSERT INTO posts(board, seq, name, title, body, created, updated, nbytes)
                VALUES ('main', 1, 'legacy', '', 'kept', 1, 1, 4);
                """
            )
            conn.commit()
            conn.close()

            root = Ed25519PrivateKey.generate()
            root_public = Path(tmp) / "root.pub"
            root_public.write_text(public_b64(root) + "\n")

            store = Store(
                Config(
                    database=str(db),
                    root_public_key=str(root_public),
                )
            )
            try:
                post = store.get_post(1)
                self.assertIsNotNone(post)
                self.assertEqual(post.body, "kept")
                self.assertFalse(post.signed)

                check = sqlite3.connect(db)
                columns = {row[1] for row in check.execute("PRAGMA table_info(posts)")}
                tables = {
                    row[0]
                    for row in check.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                check.close()
                self.assertIn("author_id", columns)
                self.assertIn("actor_id", columns)
                self.assertIn("certificates", tables)
                self.assertIn("revocations", tables)
                self.assertIn("topic_policies", tables)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
