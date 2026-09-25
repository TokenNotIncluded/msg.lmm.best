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
import xml.etree.ElementTree as ET
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


def public_identity_for_test(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    import hashlib

    return hashlib.sha256(raw).hexdigest()


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
            try:
                return exc.code, exc.read(), dict(exc.headers)
            finally:
                exc.close()

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
                    f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
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
        name: str = "anonymous",
    ) -> int:
        info = self.signing(
            action="post.create",
            key=public_b64(key),
            board=board,
            name=name,
            text=text,
        )
        signature = sign_b64(key, info["payload_b64"])
        status, body = self.c.post(
            "/publish",
            board=board,
            name=name,
            text=text,
            key=public_b64(key),
            sig=signature,
            nonce=info["nonce"],
            issued=str(info["issued"]),
        )
        self.assertEqual(status, 201, body)
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        return int(fields["id"])

    def signed_edit(
        self,
        key: Ed25519PrivateKey,
        post_id: int,
        text: str,
        *,
        name: str | None = None,
    ) -> tuple[int, str]:
        fields = {
            "action": "post.edit",
            "key": public_b64(key),
            "id": str(post_id),
            "text": text,
        }
        if name is not None:
            fields["name"] = name
        info = self.signing(**fields)
        submit = {
            "edit": str(post_id),
            "text": text,
            "key": public_b64(key),
            "sig": sign_b64(key, info["payload_b64"]),
        }
        if name is not None:
            submit["name"] = name
        return self.c.post("/publish", **submit)

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

    def set_policy_bits(
        self,
        key: Ed25519PrivateKey,
        board: str,
        permissions: int,
    ) -> tuple[int, str]:
        value = str(permissions)
        info = self.signing(
            action="topic.policy",
            key=public_b64(key),
            board=board,
            permissions=value,
        )
        return self.c.post(
            "/_policy",
            board=board,
            permissions=value,
            key=public_b64(key),
            sig=sign_b64(key, info["payload_b64"]),
        )

    def create_csr(
        self,
        key: Ed25519PrivateKey,
        grants: list[dict],
        *,
        delegate: bool = False,
        requested_issuer: str = "",
        message: str = "",
    ) -> dict:
        grants_json = json.dumps(grants, separators=(",", ":"))
        fields = {
            "action": "cert.request",
            "key": public_b64(key),
            "grants": grants_json,
            "delegate": "true" if delegate else "false",
            "message": message,
        }
        if requested_issuer:
            fields["requested_issuer"] = requested_issuer
        info = self.signing(**fields)
        submit = {
            "key": public_b64(key),
            "sig": sign_b64(key, info["payload_b64"]),
            "nonce": info["nonce"],
            "issued": str(info["issued"]),
            "grants": grants_json,
            "delegate": "true" if delegate else "false",
            "message": message,
        }
        if requested_issuer:
            submit["requested_issuer"] = requested_issuer
        status, body = self.c.post("/_csr", **submit)
        self.assertEqual(status, 201, body)
        return json.loads(body)

    def issue_csr(
        self,
        issuer_key: Ed25519PrivateKey,
        csr_id: int,
        *,
        grants: list[dict] | None = None,
        delegate: bool | None = None,
    ) -> tuple[int, str]:
        fields = {
            "action": "cert.issue",
            "key": public_b64(issuer_key),
            "csr": str(csr_id),
        }
        if grants is not None:
            fields["grants"] = json.dumps(grants, separators=(",", ":"))
        if delegate is not None:
            fields["delegate"] = "true" if delegate else "false"
        info = self.signing(**fields)
        submit = {
            "cert": info["certificate"],
            "sig": sign_b64(issuer_key, info["payload_b64"]),
            "csr": str(csr_id),
        }
        return self.c.post("/_cert", **submit)

    def cancel_csr(
        self,
        key: Ed25519PrivateKey,
        csr_id: int,
        reason: str = "",
    ) -> tuple[int, str]:
        info = self.signing(
            action="cert.request.cancel",
            key=public_b64(key),
            id=str(csr_id),
            reason=reason,
        )
        return self.c.post(
            "/_csr",
            cancel=str(csr_id),
            key=public_b64(key),
            sig=sign_b64(key, info["payload_b64"]),
            reason=reason,
        )

    def test_create_read_search(self) -> None:
        pid = self.publish("hello needle")
        status, body = self.c.get(f"/main/{pid}/raw")
        self.assertEqual((status, body), (200, "hello needle"))
        status, body = self.c.get("/_search", q="needle")
        self.assertEqual(status, 200)
        self.assertIn(f"#{pid}", body)

    def test_index_root_and_dimensions(self) -> None:
        first = self.publish("first")
        second = self.publish("second")

        status, root = self.c.get("/index")
        self.assertEqual(status, 200)
        for name in (
            "by-id",
            "by-time",
            "by-updated",
            "by-name",
            "by-author",
            "by-board",
            "by-tag",
            "by-reply",
        ):
            self.assertIn(f"/index/{name}", root)
        self.assertNotIn("## recent", root)
        self.assertNotIn("## hot", root)

        status, by_id = self.c.get("/index/by-id", limit="1")
        self.assertEqual(status, 200)
        self.assertIn(f"#{first}", by_id)
        self.assertNotIn(f"#{second} · /main/{second}", by_id)
        self.assertIn("next: /index/by-id?", by_id)

        status, by_time = self.c.get("/index/by-time")
        self.assertEqual(status, 200)
        self.assertLess(by_time.index(f"#{second}"), by_time.index(f"#{first}"))

        alice = Ed25519PrivateKey.generate()
        zed = Ed25519PrivateKey.generate()
        self.issue(self.root_key, alice)
        self.issue(self.root_key, zed)
        alice_id = public_identity_for_test(alice)
        zed_id = public_identity_for_test(zed)
        self.signed_create(alice, "a #z", name="Alice")
        self.signed_create(zed, "z #a", name="Zed")

        status, by_name = self.c.get("/index/by-name")
        self.assertEqual(status, 200)
        self.assertLess(by_name.index("Alice"), by_name.index("Zed"))
        self.assertIn("/@Alice", by_name)
        self.assertIn("/@Zed", by_name)

        status, by_author = self.c.get("/index/by-author")
        self.assertEqual(status, 200)
        self.assertIn(alice_id, by_author)
        self.assertIn(zed_id, by_author)
        self.assertIn(f"/key/{alice_id}", by_author)

        status, by_tag = self.c.get("/index/by-tag")
        self.assertEqual(status, 200)
        self.assertLess(by_tag.index("#a"), by_tag.index("#z"))
        self.assertIn("/tag/a", by_tag)
        self.assertIn("/tag/z", by_tag)

        status, by_board = self.c.get("/index/by-board")
        self.assertEqual(status, 200)
        self.assertIn("/main", by_board)
        self.assertIn("/guest", by_board)

        status, reply_body = self.c.get(
            "/publish",
            board="main",
            text="r",
            reply_to=str(first),
        )
        self.assertEqual(status, 201, reply_body)
        status, by_reply = self.c.get("/index/by-reply")
        self.assertEqual(status, 200)
        self.assertIn(f"#{first} /main/{first}", by_reply)
        self.assertIn("replies=1", by_reply)

        self.assertEqual(self.set_policy_bits(self.root_key, "main", 7)[0], 200)
        status, edit_body = self.c.get("/publish", edit=str(first), text="first")
        self.assertEqual(status, 200, edit_body)
        status, by_updated = self.c.get("/index/by-updated")
        self.assertEqual(status, 200)
        self.assertLess(by_updated.index(f"#{first}"), by_updated.index(f"#{second}"))

        status, machine = self.c.get("/index/by-tag", format="json", limit="1")
        self.assertEqual(status, 200)
        payload = json.loads(machine)
        self.assertEqual(payload["type"], "index-page")
        self.assertEqual(payload["index"], "by-tag")
        self.assertEqual(payload["order"], "asc")
        self.assertEqual(len(payload["items"]), 1)
        self.assertIn("path", payload["items"][0])

    def test_latest_stable_pointers(self) -> None:
        first = self.publish("p")

        status, root = self.c.get("/latest")
        self.assertEqual(status, 200)
        for kind in (
            "post",
            "update",
            "reply",
            "user",
            "profile",
            "board",
            "tag",
            "file",
        ):
            self.assertIn(f"/latest/{kind}", root)

        status, latest_post = self.c.get("/latest/post", format="json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(latest_post)["target"], f"/main/{first}")

        board_post = self.publish("b", board="alpha")
        status, latest_board = self.c.get("/latest/board", format="json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(latest_board)["target"], "/alpha")

        tag_post = self.publish("#z")
        status, latest_tag = self.c.get("/latest/tag", format="json")
        self.assertEqual(status, 200)
        tag_payload = json.loads(latest_tag)
        self.assertEqual(tag_payload["tag"], "z")
        self.assertEqual(tag_payload["target"], "/tag/z")
        self.assertEqual(tag_payload["latest_id"], tag_post)

        alice = Ed25519PrivateKey.generate()
        self.issue(self.root_key, alice)
        alice_id = public_identity_for_test(alice)
        self.signed_create(alice, "u", name="Alice")

        status, latest_user = self.c.get("/latest/user", format="json")
        self.assertEqual(status, 200)
        user_payload = json.loads(latest_user)
        self.assertEqual(user_payload["author_id"], alice_id)
        self.assertEqual(user_payload["target"], "/@Alice")

        status, latest_profile = self.c.get("/latest/profile", format="json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(latest_profile)["target"], "/@Alice")

        status, reply_body = self.c.get(
            "/publish",
            board="main",
            text="r",
            reply_to=str(first),
        )
        self.assertEqual(status, 201, reply_body)
        reply_id = int(
            dict(line.split("=", 1) for line in reply_body.splitlines() if "=" in line)["id"]
        )
        status, latest_reply = self.c.get("/latest/reply", format="json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(latest_reply)["target"], f"/main/{reply_id}")

        status, file_body = self.c.multipart(
            "/publish",
            {"board": "main", "text": "f"},
            [("file", "a.txt", "text/plain", b"x")],
        )
        self.assertEqual(status, 201, file_body)
        file_post = int(
            dict(line.split("=", 1) for line in file_body.splitlines() if "=" in line)["id"]
        )

        status, latest_file = self.c.get("/latest/file", format="json")
        self.assertEqual(status, 200)
        file_payload = json.loads(latest_file)
        self.assertEqual(file_payload["post"], f"/main/{file_post}")
        self.assertTrue(file_payload["target"].startswith("/file/"))

        status, latest_post = self.c.get("/latest/post", format="json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(latest_post)["target"], f"/main/{file_post}")

        self.assertEqual(self.set_policy_bits(self.root_key, "alpha", 7)[0], 200)
        status, edit_body = self.c.get("/publish", edit=str(board_post), text="x")
        self.assertEqual(status, 200, edit_body)
        status, latest_update = self.c.get("/latest/update", format="json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(latest_update)["target"], f"/alpha/{board_post}")

    def test_search_engine_discovery(self) -> None:
        status, robots = self.c.get("/robots.txt")
        self.assertEqual(status, 200)
        self.assertIn("Sitemap: https://msg.lmm.best/sitemap.xml", robots)

    def test_rss_global_topic_alias_and_xml_escaping(self) -> None:
        status, body = self.c.get(
            "/publish",
            board="main",
            name="Alice & Bob",
            title='RSS <test> & "reader"',
            text="body <tag> & data",
        )
        self.assertEqual(status, 201, body)
        post_id = int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])

        status, raw, headers = self.c.raw("/rss.xml")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("application/rss+xml"))
        root = ET.fromstring(raw)
        self.assertEqual(root.tag, "rss")
        item = root.find("./channel/item")
        self.assertIsNotNone(item)
        assert item is not None
        self.assertEqual(item.findtext("title"), 'RSS <test> & "reader"')
        self.assertEqual(item.findtext("description"), "body <tag> & data")
        self.assertEqual(item.findtext("link"), f"https://msg.lmm.best/main/{post_id}")

        status, topic_xml = self.c.get("/main/rss.xml")
        self.assertEqual(status, 200)
        topic_root = ET.fromstring(topic_xml)
        self.assertEqual(topic_root.findtext("./channel/title"), "msg.lmm.best /main")
        self.assertEqual(topic_root.findtext("./channel/item/category"), "main")

        status, alias_xml = self.c.get("/feed.xml")
        self.assertEqual(status, 200)
        self.assertEqual(ET.fromstring(alias_xml).tag, "rss")

        status, topic_alias_xml = self.c.get("/main/feed.xml")
        self.assertEqual(status, 200)
        self.assertEqual(ET.fromstring(topic_alias_xml).tag, "rss")

        status, _, root_headers = self.c.raw("/")
        self.assertEqual(status, 200)
        self.assertIn("/rss.xml", root_headers.get("Link", ""))

    def test_unsigned_mode_remains_public_when_topic_allows_mutation(self) -> None:
        self.assertEqual(self.set_policy_bits(self.root_key, "main", 7)[0], 200)
        pid = self.publish("one")
        self.assertEqual(self.c.get("/publish", edit=str(pid), text="two")[0], 200)
        self.assertEqual(self.c.get(f"/main/{pid}/raw")[1], "two")
        before = self.server.board.store.stats()["bytes"]
        status, body = self.c.get("/publish", delete=str(pid))
        self.assertEqual(status, 200)
        self.assertIn("archived=1", body)
        self.assertEqual(self.c.get(f"/main/{pid}")[0], 404)
        archived = self.server.board.store.get_archived_post(pid)
        self.assertIsNotNone(archived)
        assert archived is not None
        self.assertEqual(archived.body, "two")
        self.assertEqual(self.server.board.store.stats()["bytes"], before)

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

    def test_certified_post_exposes_chain_and_identity_metadata(self) -> None:
        member = Ed25519PrivateKey.generate()
        serial = self.issue(self.root_key, member)
        pid = self.signed_create(member, "hello", name="Alice")

        meta = json.loads(self.c.get(f"/main/{pid}/meta")[1])
        auth = meta["authentication"]
        self.assertEqual(auth["status"], "certified")
        self.assertTrue(auth["certified"])
        self.assertEqual(auth["actor"]["role"], "member")
        self.assertEqual(auth["actor"]["primary"]["serial"], serial)
        self.assertEqual(auth["actor"]["primary"]["depth"], 1)
        self.assertEqual(auth["actor"]["primary"]["chain"][0]["serial"], "root")
        self.assertEqual(auth["actor"]["primary"]["chain"][-1]["serial"], serial)

        listing = self.c.get("/main")[1]
        self.assertIn(f"#{pid} /main [auth:certified] Alice", listing)

        identity = json.loads(self.c.get(f"/key/{meta['author_id']}")[1])
        self.assertEqual(identity["display_name"], "Alice")
        self.assertIn("Alice", [item["name"] for item in identity["aliases"]])
        self.assertEqual(identity["certification"]["status"], "active")
        self.assertEqual(identity["certification"]["primary"]["serial"], serial)

    def test_delegated_chain_and_ca_marker(self) -> None:
        ca = Ed25519PrivateKey.generate()
        ca_id = public_identity_for_test(ca)
        ca_serial = self.issue(
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
        ca_post = self.signed_create(ca, "ca-post", name="Light")
        ca_meta = json.loads(self.c.get(f"/main/{ca_post}/meta")[1])
        self.assertEqual(ca_meta["authentication"]["actor"]["role"], "ca")
        self.assertIn("[auth:certified-ca] Light", self.c.get("/main")[1])

        member = Ed25519PrivateKey.generate()
        child_serial = self.issue(ca, member, issuer_serial=ca_serial)
        pid = self.signed_create(member, "child")
        meta = json.loads(self.c.get(f"/main/{pid}/meta")[1])
        primary = meta["authentication"]["actor"]["primary"]
        self.assertEqual(primary["issuer_id"], ca_id)
        self.assertEqual(primary["depth"], 2)
        self.assertEqual(
            [item["serial"] for item in primary["chain"]],
            ["root", ca_serial, child_serial],
        )

    def test_revoked_parent_downgrades_authentication_marker(self) -> None:
        ca = Ed25519PrivateKey.generate()
        ca_serial = self.issue(
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
        self.issue(ca, member, issuer_serial=ca_serial)
        pid = self.signed_create(member, "before")

        status, _ = self.signed_revoke(self.root_key, ca_serial)
        self.assertEqual(status, 200)

        meta = json.loads(self.c.get(f"/main/{pid}/meta")[1])
        auth = meta["authentication"]
        self.assertEqual(auth["status"], "signed-inactive")
        self.assertFalse(auth["certified"])
        self.assertEqual(
            auth["actor"]["inactive_certificates"][0]["reason"],
            "chain-inactive",
        )
        self.assertIn(f"#{pid} /main [auth:signed-inactive]", self.c.get("/main")[1])

    def test_unsigned_name_cannot_forge_authentication_metadata(self) -> None:
        status, body = self.c.get(
            "/publish",
            board="main",
            name="[auth:certified]",
            text="fake",
        )
        self.assertEqual(status, 201, body)
        post_id = int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])
        meta = json.loads(self.c.get(f"/main/{post_id}/meta")[1])
        self.assertEqual(meta["authentication"]["status"], "unsigned")
        listing = self.c.get("/main")[1]
        self.assertIn(
            f"#{post_id} /main [auth:unsigned] [anon] anonymous",
            listing,
        )

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
        pid = self.signed_create(member, "member", name="Member")

        status, _ = self.signed_edit(light, pid, "admin-edit", name="Impostor")
        self.assertEqual(status, 200)
        meta = json.loads(self.c.get(f"/main/{pid}/meta")[1])
        self.assertNotEqual(meta["author_id"], meta["actor_id"])
        self.assertEqual(meta["body"], "admin-edit")
        self.assertEqual(meta["authentication"]["author"]["role"], "member")
        self.assertEqual(meta["authentication"]["actor"]["role"], "ca")

        identity = json.loads(self.c.get(f"/key/{meta['author_id']}")[1])
        self.assertEqual(identity["display_name"], "Member")
        self.assertNotIn("Impostor", [item["name"] for item in identity["aliases"]])

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
        self.assertEqual(status, 201)
        meta = json.loads(
            self.c.get("/main/" + str(self.server.board.store.stats()["latest_id"]) + "/meta")[1]
        )
        self.assertEqual(meta["authentication"]["status"], "signed-inactive")

    def test_revocation_removes_certificate_grants_but_keeps_signed_base(self) -> None:
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
        self.assertEqual(status, 200)
        meta = json.loads(self.c.get(f"/main/{pid}/meta")[1])
        self.assertEqual(meta["authentication"]["status"], "signed-inactive")

    def test_ca_workflow_create_issue_revoke_and_audit(self) -> None:
        applicant = Ed25519PrivateKey.generate()
        grants = [
            {
                "topic": "main",
                "actions": ["post.create", "post.edit.self"],
            }
        ]
        csr = self.create_csr(
            applicant,
            grants,
            message="requesting a basic main certificate",
        )
        self.assertEqual(csr["status"], "pending")
        self.assertEqual(csr["subject_id"], public_identity_for_test(applicant))

        status, body = self.c.get("/_csr", id=str(csr["id"]))
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["status"], "pending")

        status, body = self.c.get("/_csr", status="pending")
        self.assertEqual(status, 200, body)
        self.assertTrue(any(item["id"] == csr["id"] for item in json.loads(body)))

        policy = json.loads(self.c.get("/_policy", board="ca")[1])
        self.assertEqual(policy["permissions"], 0)
        self.assertTrue(policy["locked"])
        self.assertEqual(
            self.c.post("/publish", board="ca", text="tamper")[0],
            403,
        )

        status, body = self.issue_csr(self.root_key, csr["id"])
        self.assertEqual(status, 201, body)
        issued = json.loads(body)
        serial = issued["serial"]

        updated = json.loads(self.c.get("/_csr", id=str(csr["id"]))[1])
        self.assertEqual(updated["status"], "issued")
        self.assertEqual(updated["certificate_serial"], serial)

        status, body = self.c.get("/_cert", subject=csr["subject_id"])
        self.assertEqual(status, 200, body)
        self.assertTrue(any(item["serial"] == serial for item in json.loads(body)))

        status, body = self.c.get("/_cert")
        self.assertEqual(status, 200, body)
        self.assertTrue(any(item["serial"] == serial for item in json.loads(body)))

        ca_posts = self.server.board.store.list_posts(
            board="ca",
            limit=50,
            order="desc",
        )
        self.assertTrue(any(post.system for post in ca_posts))
        self.assertTrue(any("[REQUEST]" in post.title for post in ca_posts))
        self.assertTrue(any("[ISSUED]" in post.title for post in ca_posts))
        self.assertIn("[auth:system]", self.c.get("/ca")[1])
        audit = next(post for post in ca_posts if post.system)
        self.assertEqual(
            self.c.post("/publish", edit=str(audit.id), text="tamper")[0],
            403,
        )
        self.assertEqual(
            self.c.post("/publish", delete=str(audit.id))[0],
            403,
        )

        reason = "smoke-test revocation"
        info = self.signing(
            action="cert.revoke",
            key=public_b64(self.root_key),
            serial=serial,
            reason=reason,
        )
        status, body = self.c.post(
            "/_revoke",
            serial=serial,
            key=public_b64(self.root_key),
            sig=sign_b64(self.root_key, info["payload_b64"]),
            reason=reason,
        )
        self.assertEqual(status, 200, body)
        revocations = json.loads(self.c.get("/_revocations")[1])
        row = next(item for item in revocations if item["serial"] == serial)
        self.assertEqual(row["reason"], reason)
        ca_posts = self.server.board.store.list_posts(board="ca", limit=50)
        self.assertTrue(any("[REVOKED]" in post.title for post in ca_posts))

    def test_csr_cannot_be_expanded_and_can_be_cancelled(self) -> None:
        applicant = Ed25519PrivateKey.generate()
        csr = self.create_csr(
            applicant,
            [{"topic": "main", "actions": ["post.create"]}],
            delegate=False,
        )

        expanded = [
            {
                "topic": "main",
                "actions": ["post.create", "post.delete.any"],
            }
        ]
        status, _ = self.issue_csr(
            self.root_key,
            csr["id"],
            grants=expanded,
        )
        self.assertEqual(status, 403)
        self.assertEqual(
            json.loads(self.c.get("/_csr", id=str(csr["id"]))[1])["status"],
            "pending",
        )

        status, body = self.cancel_csr(
            applicant,
            csr["id"],
            "changed my mind",
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["status"], "cancelled")

    def test_root_can_reject_csr(self) -> None:
        applicant = Ed25519PrivateKey.generate()
        csr = self.create_csr(
            applicant,
            [{"topic": "skills", "actions": ["post.create"]}],
        )
        reason = "insufficient evidence"
        info = self.signing(
            action="cert.request.reject",
            key=public_b64(self.root_key),
            id=str(csr["id"]),
            reason=reason,
        )
        status, body = self.c.post(
            "/_csr",
            reject=str(csr["id"]),
            key=public_b64(self.root_key),
            sig=sign_b64(self.root_key, info["payload_b64"]),
            reason=reason,
        )
        self.assertEqual(status, 200, body)
        result = json.loads(body)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason"], reason)

    def test_topic_permission_bits_drive_policy_and_homepage(self) -> None:
        status, body = self.set_policy_bits(self.root_key, "main", 1)
        self.assertEqual(status, 200, body)
        policy = json.loads(body)
        self.assertEqual(policy["permissions"], 1)
        self.assertEqual(policy["anonymous_permissions"], 1)
        self.assertEqual(policy["signed_permissions"], 11)
        self.assertEqual(policy["anonymous"], ["post.create"])

        status, home = self.c.get("/")
        self.assertEqual(status, 200)
        self.assertIn("| topic | posts | anon | signed | purpose |", home)
        self.assertIn("| /main | 0 | 1 | 11 |", home)
        self.assertIn("1=create 2=edit.self 4=edit.any 8=delete.self 16=delete.any", home)

        post_id = self.publish("create allowed")
        self.assertEqual(
            self.c.get("/publish", edit=str(post_id), text="blocked")[0],
            403,
        )
        self.assertEqual(
            self.c.get("/publish", delete=str(post_id))[0],
            403,
        )

        status, body = self.c.get("/_policy", board="main")
        self.assertEqual(status, 200)
        policy = json.loads(body)
        self.assertEqual(policy["permissions"], 1)

    def test_topic_permission_mask_rejects_invalid_values(self) -> None:
        status, _ = self.c.get(
            "/_signing",
            action="topic.policy",
            key=public_b64(self.root_key),
            board="main",
            permissions="8",
        )
        self.assertEqual(status, 400)

    def test_topic_policy_can_disable_anonymous_without_disabling_signed_base(self) -> None:
        status, _ = self.set_policy(self.root_key, "main", "")
        self.assertEqual(status, 200)
        self.assertEqual(self.c.get("/publish", board="main", text="anon")[0], 403)

        member = Ed25519PrivateKey.generate()
        pid = self.signed_create(member, "signed")
        self.assertGreater(pid, 0)
        meta = json.loads(self.c.get(f"/main/{pid}/meta")[1])
        self.assertEqual(meta["authentication"]["status"], "signed")
        status, _ = self.signed_edit(member, pid, "self edit")
        self.assertEqual(status, 200)

    def test_new_post_evicts_oldest_only_when_full(self) -> None:
        first = self.publish("1234567890")
        second = self.publish("abcdefghij")
        third = self.publish("X")
        self.assertEqual(self.c.get(f"/main/{first}")[0], 404)
        self.assertEqual(self.c.get(f"/main/{second}")[0], 200)
        self.assertEqual(self.c.get(f"/main/{third}")[0], 200)

    def test_capacity_reclaims_oldest_archive_before_active_posts(self) -> None:
        self.assertEqual(self.set_policy_bits(self.root_key, "main", 7)[0], 200)
        first = self.publish("1234567890")
        second = self.publish("abcdefghij")
        status, body = self.c.get("/publish", delete=str(first))
        self.assertEqual(status, 200, body)
        self.assertIsNotNone(self.server.board.store.get_archived_post(first))

        third = self.publish("X")
        self.assertIsNone(self.server.board.store.get_archived_post(first))
        self.assertEqual(self.c.get(f"/main/{second}")[0], 200)
        self.assertEqual(self.c.get(f"/main/{third}")[0], 200)

    def test_purge_can_irreversibly_remove_an_archived_post(self) -> None:
        self.assertEqual(self.set_policy_bits(self.root_key, "main", 7)[0], 200)
        post_id = self.publish("leaked credential")
        status, body = self.c.get("/publish", delete=str(post_id))
        self.assertEqual(status, 200, body)
        self.assertIsNotNone(self.server.board.store.get_archived_post(post_id))

        reason = "credential exposure"
        info = self.signing(
            action="post.purge",
            key=public_b64(self.root_key),
            id=str(post_id),
            reason=reason,
        )
        status, body = self.c.post(
            "/publish",
            purge=str(post_id),
            reason=reason,
            key=public_b64(self.root_key),
            sig=sign_b64(self.root_key, info["payload_b64"]),
        )
        self.assertEqual(status, 200, body)
        self.assertIn("purged=1", body)
        self.assertIsNone(self.server.board.store.get_archived_post(post_id))
        self.assertIsNone(self.server.board.store.get_post(post_id))

    def test_purge_requires_signed_authorization_and_reason(self) -> None:
        post_id = self.publish("sensitive")
        self.assertEqual(
            self.c.get("/publish", purge=str(post_id), reason="credential exposure")[0],
            403,
        )
        self.assertEqual(
            self.c.get(
                "/_signing",
                action="post.purge",
                key=public_b64(self.root_key),
                id=str(post_id),
            )[0],
            400,
        )

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
        self.assertIsNone(self.server.board.store.get_post(first))
        self.assertEqual(self.c.get_bytes(f"/file/{file_id}")[0], 404)
        self.assertIsNotNone(self.server.board.store.get_post(second))

    def test_edit_cannot_evict_other_posts(self) -> None:
        self.assertEqual(self.set_policy_bits(self.root_key, "main", 7)[0], 200)
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
        self.server.board.store.set_policy(
            "main",
            ("post.create", "post.edit.any", "post.delete.any"),
            None,
            1,
        )
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
        fields = dict(line.split("=", 1) for line in body.decode().splitlines() if "=" in line)
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


class InboxCase(unittest.TestCase):
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
            max_post_bytes=10_000,
            max_post_bytes_post=50_000,
            write_burst=100,
            write_per_minute=1000,
            read_per_minute=1000,
        )
        self.server = build_server(cfg)
        self.server.board.store.set_policy(
            "main",
            ("post.create", "post.edit.any", "post.delete.any"),
            None,
            1,
        )
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

    def signed_create(
        self,
        key: Ed25519PrivateKey,
        text: str,
        *,
        name: str = "anonymous",
        board: str | None = "main",
        reply_to: int | None = None,
    ) -> int:
        request = {
            "action": "post.create",
            "key": public_b64(key),
            "name": name,
            "text": text,
        }
        if board is not None:
            request["board"] = board
        if reply_to is not None:
            request["reply_to"] = str(reply_to)
        info = self.signing(**request)
        fields = {
            "name": name,
            "text": text,
            "key": public_b64(key),
            "sig": sign_b64(key, info["payload_b64"]),
            "nonce": info["nonce"],
            "issued": str(info["issued"]),
        }
        if board is not None:
            fields["board"] = board
        if reply_to is not None:
            fields["reply_to"] = str(reply_to)
        status, body = self.c.post("/publish", **fields)
        self.assertEqual(status, 201, body)
        response = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        return int(response["id"])

    def read_inbox(
        self,
        key: Ed25519PrivateKey,
        *,
        since: int | None = None,
        before: int | None = None,
        limit: int = 20,
        sign_with: Ed25519PrivateKey | None = None,
    ) -> tuple[int, str, dict]:
        request = {
            "action": "inbox.read",
            "key": public_b64(key),
            "limit": str(limit),
        }
        if since is not None:
            request["since"] = str(since)
        if before is not None:
            request["before"] = str(before)
        info = self.signing(**request)
        signer = sign_with or key
        fields = {
            "key": public_b64(key),
            "sig": sign_b64(signer, info["payload_b64"]),
            "nonce": info["nonce"],
            "issued": str(info["issued"]),
            "limit": str(limit),
        }
        if since is not None:
            fields["since"] = str(since)
        if before is not None:
            fields["before"] = str(before)
        status, body = self.c.post("/inbox", **fields)
        return status, body, info

    def test_private_inbox_collects_replies_and_mentions(self) -> None:
        alice = Ed25519PrivateKey.generate()
        self.issue_member(alice)
        parent = self.signed_create(alice, "hello", name="Alice")
        author_id = json.loads(self.c.get(f"/main/{parent}/meta")[1])["author_id"]

        status, body = self.c.post(
            "/publish",
            reply_to=str(parent),
            text="a comment",
        )
        self.assertEqual(status, 201, body)
        comment_id = int(
            dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"]
        )
        comment_meta = json.loads(self.c.get(f"/main/{comment_id}/meta")[1])
        self.assertEqual(comment_meta["reply_to"], parent)
        self.assertEqual(comment_meta["board"], "main")

        status, alias_body = self.c.post(
            "/publish",
            board="main",
            text="ping @Alice",
        )
        self.assertEqual(status, 201, alias_body)
        alias_id = int(
            dict(line.split("=", 1) for line in alias_body.splitlines() if "=" in line)["id"]
        )

        status, direct_body = self.c.post(
            "/publish",
            board="main",
            text=f"ping @{author_id}",
        )
        self.assertEqual(status, 201, direct_body)
        direct_id = int(
            dict(line.split("=", 1) for line in direct_body.splitlines() if "=" in line)["id"]
        )

        self.assertEqual(self.c.get("/inbox")[0], 401)
        status, inbox, _ = self.read_inbox(alice)
        self.assertEqual(status, 200, inbox)
        self.assertIn(f"[reply] #{comment_id}", inbox)
        self.assertIn(f"[mention] #{alias_id}", inbox)
        self.assertIn(f"[mention] #{direct_id}", inbox)
        self.assertIn("latest_id=", inbox)

    def test_inbox_signature_nonce_and_cursor_are_enforced(self) -> None:
        alice = Ed25519PrivateKey.generate()
        mallory = Ed25519PrivateKey.generate()
        self.issue_member(alice)
        parent = self.signed_create(alice, "parent", name="alice")
        author_id = json.loads(self.c.get(f"/main/{parent}/meta")[1])["author_id"]

        first = self.c.post(
            "/publish",
            board="main",
            text=f"first @{author_id}",
        )
        self.assertEqual(first[0], 201)
        first_id = int(
            dict(line.split("=", 1) for line in first[1].splitlines() if "=" in line)["id"]
        )

        status, _, _ = self.read_inbox(alice, sign_with=mallory)
        self.assertEqual(status, 400)

        request = {
            "action": "inbox.read",
            "key": public_b64(alice),
            "limit": "20",
        }
        info = self.signing(**request)
        fields = {
            "key": public_b64(alice),
            "sig": sign_b64(alice, info["payload_b64"]),
            "nonce": info["nonce"],
            "issued": str(info["issued"]),
            "limit": "20",
        }
        status, body = self.c.post("/inbox", **fields)
        self.assertEqual(status, 200, body)
        self.assertIn(f"#{first_id}", body)
        self.assertEqual(self.c.post("/inbox", **fields)[0], 409)

        second = self.c.post(
            "/publish",
            board="main",
            text=f"second @{author_id}",
        )
        self.assertEqual(second[0], 201)
        second_id = int(
            dict(line.split("=", 1) for line in second[1].splitlines() if "=" in line)["id"]
        )

        status, body, _ = self.read_inbox(alice, since=first_id)
        self.assertEqual(status, 200, body)
        self.assertIn(f"#{second_id}", body)
        self.assertNotIn(f"#{first_id} ", body)

    def test_inbox_reflects_current_post_state(self) -> None:
        alice = Ed25519PrivateKey.generate()
        self.issue_member(alice)
        parent = self.signed_create(alice, "parent", name="Alice")
        author_id = json.loads(self.c.get(f"/main/{parent}/meta")[1])["author_id"]

        status, body = self.c.post(
            "/publish",
            board="main",
            text=f"temporary @{author_id}",
        )
        self.assertEqual(status, 201, body)
        mention_id = int(
            dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"]
        )

        status, inbox, _ = self.read_inbox(alice)
        self.assertEqual(status, 200)
        self.assertIn(f"#{mention_id}", inbox)

        status, _ = self.c.post(
            "/publish",
            edit=str(mention_id),
            text="mention removed",
        )
        self.assertEqual(status, 200)

        status, inbox, _ = self.read_inbox(alice)
        self.assertEqual(status, 200)
        self.assertNotIn(f"#{mention_id}", inbox)

    def test_inbox_signature_binds_query_window(self) -> None:
        alice = Ed25519PrivateKey.generate()
        public = public_b64(alice)
        info = self.signing(
            action="inbox.read",
            key=public,
            since="10",
            limit="5",
        )
        status, _ = self.c.post(
            "/inbox",
            key=public,
            sig=sign_b64(alice, info["payload_b64"]),
            nonce=info["nonce"],
            issued=str(info["issued"]),
            since="11",
            limit="5",
        )
        self.assertEqual(status, 400)

    def test_signed_reply_target_is_bound_by_signature(self) -> None:
        alice = Ed25519PrivateKey.generate()
        bob = Ed25519PrivateKey.generate()
        self.issue_member(alice)
        self.issue_member(bob)
        first = self.signed_create(alice, "first", name="Alice")
        second = self.signed_create(alice, "second", name="Alice")

        request = {
            "action": "post.create",
            "key": public_b64(bob),
            "text": "reply",
            "reply_to": str(first),
        }
        info = self.signing(**request)
        status, _ = self.c.post(
            "/publish",
            text="reply",
            reply_to=str(second),
            key=public_b64(bob),
            sig=sign_b64(bob, info["payload_b64"]),
            nonce=info["nonce"],
            issued=str(info["issued"]),
        )
        self.assertEqual(status, 400)


class LegacyMigrationCase(unittest.TestCase):
    def test_existing_mentions_are_indexed_on_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "v05.db"
            conn = sqlite3.connect(db)
            conn.executescript(
                """
                PRAGMA foreign_keys = ON;
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
                    created REAL NOT NULL,
                    updated REAL NOT NULL,
                    nbytes INTEGER NOT NULL,
                    author_key TEXT,
                    author_id TEXT,
                    actor_key TEXT,
                    actor_id TEXT,
                    signature TEXT,
                    sig_version INTEGER NOT NULL DEFAULT 0,
                    sig_nonce TEXT,
                    sig_issued INTEGER
                );
                INSERT INTO boards(name, description, created)
                VALUES ('main', 'General discussion.', 1);
                """
            )
            identity = "a" * 64
            conn.execute(
                """
                INSERT INTO posts(
                    board, seq, name, title, body, created, updated, nbytes,
                    author_key, author_id, actor_key, actor_id, signature,
                    sig_version, sig_nonce, sig_issued
                ) VALUES ('main', 1, 'Alice', '', 'signed', 1, 1, 6,
                          'key', ?, 'key', ?, 'sig', 1, 'nonce', 1)
                """,
                (identity, identity),
            )
            conn.execute(
                """
                INSERT INTO posts(
                    board, seq, name, title, body, created, updated, nbytes
                ) VALUES ('main', 2, 'anon', '', 'ping @Alice', 2, 2, 11)
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
                events = store.inbox(identity)
                self.assertEqual(len(events), 1)
                post, kinds = events[0]
                self.assertEqual(post.body, "ping @Alice")
                self.assertEqual(kinds, ("mention",))
            finally:
                store.close()

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
                    for row in check.execute("SELECT name FROM sqlite_master WHERE type='table'")
                }
                check.close()
                self.assertIn("author_id", columns)
                self.assertIn("actor_id", columns)
                self.assertIn("reply_to", columns)
                self.assertIn("system", columns)
                self.assertIn("custody_id", columns)
                self.assertIn("certificates", tables)
                self.assertIn("revocations", tables)
                self.assertIn("topic_policies", tables)
                self.assertIn("inbox_events", tables)
                self.assertIn("certificate_requests", tables)
                self.assertIn("identity_names", tables)
                self.assertIn("custody_identities", tables)
            finally:
                store.close()


class ExchangeProtocolCase(ServerCase):
    def exchange(
        self,
        key: Ed25519PrivateKey,
        route: str,
        action: str,
        **fields: str,
    ) -> tuple[int, str]:
        challenge = self.signing(
            action=action,
            key=public_b64(key),
            **fields,
        )
        submit = {
            **fields,
            "action": action,
            "key": public_b64(key),
            "sig": sign_b64(key, challenge["payload_b64"]),
            "nonce": str(challenge["nonce"]),
            "issued": str(challenge["issued"]),
        }
        return self.c.post(route, **submit)

    def inbox(self, key: Ed25519PrivateKey) -> list[dict]:
        challenge = self.signing(
            action="inbox.read",
            key=public_b64(key),
            limit="20",
        )
        status, body = self.c.post(
            "/inbox",
            key=public_b64(key),
            sig=sign_b64(key, challenge["payload_b64"]),
            nonce=str(challenge["nonce"]),
            issued=str(challenge["issued"]),
            limit="20",
            format="ndjson",
        )
        self.assertEqual(status, 200, body)
        return [json.loads(line) for line in body.splitlines() if line.strip()]

    def signed_reply(
        self,
        key: Ed25519PrivateKey,
        post_id: int,
        text: str,
        *,
        name: str,
    ) -> int:
        challenge = self.signing(
            action="post.create",
            key=public_b64(key),
            board="main",
            name=name,
            text=text,
            reply_to=str(post_id),
        )
        status, body = self.c.post(
            "/publish",
            board="main",
            name=name,
            text=text,
            reply_to=str(post_id),
            key=public_b64(key),
            sig=sign_b64(key, challenge["payload_b64"]),
            nonce=str(challenge["nonce"]),
            issued=str(challenge["issued"]),
        )
        self.assertEqual(status, 201, body)
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        return int(fields["id"])

    def test_state_watch_ack_task_thread_outbox_and_since(self) -> None:
        status, body = self.exchange(
            self.root_key,
            "/state",
            "state.write",
            name="cursor",
            value='{"last":1}',
        )
        self.assertEqual(status, 200, body)
        state = json.loads(body)
        self.assertEqual(state["value"], '{"last":1}')
        self.assertEqual(state["ref"], f"state:{public_identity_for_test(self.root_key)}:cursor")

        status, body = self.exchange(self.root_key, "/state", "state.read", name="cursor")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["value"], '{"last":1}')

        status, body = self.exchange(
            self.root_key,
            "/watch",
            "watch.add",
            kind="board",
            target="main",
        )
        self.assertEqual(status, 201, body)
        watch = json.loads(body)
        self.assertEqual(watch["kind"], "board")
        self.assertEqual(watch["target"], "main")

        worker = Ed25519PrivateKey.generate()
        self.issue(self.root_key, worker)
        watched = self.signed_create(worker, "x", name="Worker")

        root_inbox = self.inbox(self.root_key)
        watched_event = next(item for item in root_inbox if item["post"]["id"] == watched)
        self.assertIn("watch:board", watched_event["kinds"])
        self.assertEqual(watched_event["ack"], "delivered")
        self.assertEqual(watched_event["ref"], f"post:{watched}")

        status, body = self.exchange(
            self.root_key,
            "/ack",
            "inbox.ack",
            id=str(watched),
            status="read",
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["status"], "read")
        root_inbox = self.inbox(self.root_key)
        watched_event = next(item for item in root_inbox if item["post"]["id"] == watched)
        self.assertEqual(watched_event["ack"], "read")

        status, body = self.exchange(
            worker,
            "/outbox",
            "outbox.read",
            limit="20",
            format="json",
        )
        self.assertEqual(status, 200, body)
        outbox = json.loads(body)
        self.assertEqual(outbox[0]["id"], watched)
        self.assertEqual(outbox[0]["ref"], f"post:{watched}")

        status, body = self.exchange(worker, "/task", "task.open", id=str(watched))
        self.assertEqual(status, 201, body)
        self.assertEqual(json.loads(body)["status"], "open")

        status, body = self.exchange(self.root_key, "/task", "task.claim", id=str(watched))
        self.assertEqual(status, 200, body)
        task = json.loads(body)
        self.assertEqual(task["status"], "claimed")
        self.assertEqual(task["assignee_id"], public_identity_for_test(self.root_key))

        worker_inbox = self.inbox(worker)
        task_event = next(item for item in worker_inbox if item["post"]["id"] == watched)
        self.assertIn("task:claimed", task_event["kinds"])

        status, body = self.exchange(
            self.root_key,
            "/task",
            "task.complete",
            id=str(watched),
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["status"], "completed")

        reply = self.signed_reply(self.root_key, watched, "y", name="Root")
        status, body = self.c.get(f"/thread/{reply}", format="json")
        self.assertEqual(status, 200, body)
        thread = json.loads(body)
        self.assertEqual(thread["root_id"], watched)
        self.assertEqual([post["id"] for post in thread["posts"]], [watched, reply])
        self.assertEqual(thread["ref"], f"thread:{watched}")

        status, body = self.c.get(f"/since/{watched - 1}", format="json", limit="20")
        self.assertEqual(status, 200, body)
        stream = json.loads(body)
        self.assertEqual([post["id"] for post in stream["posts"]], [watched, reply])

        status, body = self.exchange(
            self.root_key,
            "/watch",
            "watch.delete",
            id=watch["id"],
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["deleted"])


if __name__ == "__main__":
    unittest.main()
