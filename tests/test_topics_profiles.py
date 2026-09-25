"""Hashtag topics, bound signed names, profiles, and channel naming."""

from __future__ import annotations

import base64
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
from msgd.crypto import certificate_payload, make_certificate
from msgd.server import build_server


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def author_id(key: Ed25519PrivateKey) -> str:
    import hashlib

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
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"} if post else {},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
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


class TopicsProfilesCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Ed25519PrivateKey.generate()
        root_public = Path(self.tmp.name) / "root.pub"
        root_public.write_text(public_b64(self.root) + "\n", encoding="utf-8")

        cfg = Config(
            host="127.0.0.1",
            port=0,
            database=str(Path(self.tmp.name) / "msg.db"),
            root_public_key=str(root_public),
            webhook_secret_key=str(Path(self.tmp.name) / "webhook.key"),
            webhook_delivery_enabled=False,
            max_storage_bytes=2_000_000,
            write_burst=300,
            write_per_minute=5000,
            read_per_minute=5000,
        )
        self.server = build_server(cfg)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.c = Client(f"http://{host}:{port}")

        self.alice = Ed25519PrivateKey.generate()
        self.bob = Ed25519PrivateKey.generate()
        self.issue(self.alice, "1" * 32)
        self.issue(self.bob, "2" * 32)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server.board.store.close()
        self.tmp.cleanup()

    def issue(self, key: Ed25519PrivateKey, serial: str) -> None:
        cert = make_certificate(
            serial=serial,
            issuer_serial="root",
            issuer_id=author_id(self.root),
            subject_key=public_b64(key),
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
        signature = base64.b64encode(self.root.sign(certificate_payload(cert.body))).decode("ascii")
        self.server.board.store.register_certificate(cert.body, signature)

    def signing(self, key: Ed25519PrivateKey, action: str, **fields: str) -> dict:
        status, body = self.c.get(
            "/_signing",
            action=action,
            key=public_b64(key),
            **fields,
        )
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def signed_create(
        self,
        key: Ed25519PrivateKey,
        *,
        name: str,
        text: str,
        board: str = "main",
        title: str = "",
    ) -> tuple[int, str, int | None]:
        info = self.signing(
            key,
            "post.create",
            board=board,
            name=name,
            title=title,
            text=text,
        )
        status, body = self.c.post(
            "/publish",
            board=board,
            name=name,
            title=title,
            text=text,
            key=public_b64(key),
            sig=sign_b64(key, info["payload_b64"]),
            nonce=info["nonce"],
            issued=str(info["issued"]),
        )
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        post_id = int(fields["id"]) if "id" in fields else None
        return status, body, post_id

    def signed_edit(
        self,
        key: Ed25519PrivateKey,
        post_id: int,
        *,
        text: str,
        name: str | None = None,
    ) -> tuple[int, str]:
        fields = {"id": str(post_id), "text": text}
        if name is not None:
            fields["name"] = name
        info = self.signing(key, "post.edit", **fields)
        submit = {
            "edit": str(post_id),
            "text": text,
            "key": public_b64(key),
            "sig": sign_b64(key, info["payload_b64"]),
        }
        if name is not None:
            submit["name"] = name
        return self.c.post("/publish", **submit)

    def test_name_claim_anonymous_prefix_and_signed_profile(self) -> None:
        status, body, first_id = self.signed_create(
            self.alice,
            name="Alice",
            text="first signed post",
        )
        self.assertEqual(status, 201, body)
        assert first_id is not None
        self.assertIn("profile=/@Alice", body)

        status, profile_body = self.c.get("/@alice", format="json")
        self.assertEqual(status, 200, profile_body)
        profile = json.loads(profile_body)
        self.assertEqual(profile["name"], "Alice")
        self.assertEqual(profile["public_key"], public_b64(self.alice))
        self.assertEqual(profile["author_id"], author_id(self.alice))
        self.assertFalse(profile["profile_signed"])
        self.assertTrue(profile["claim_signature"])

        status, body, _ = self.signed_create(
            self.bob,
            name="alice",
            text="try to take the name",
        )
        self.assertEqual(status, 409, body)
        self.assertIn(public_b64(self.alice), body)
        self.assertIn(author_id(self.alice), body)

        status, body = self.c.get(
            "/publish",
            board="main",
            name="ALICE",
            text="anonymous impersonation",
        )
        self.assertEqual(status, 409, body)
        self.assertIn(public_b64(self.alice), body)

        status, body = self.c.get(
            "/publish",
            board="main",
            name="Visitor",
            text="anonymous but clearly marked",
        )
        self.assertEqual(status, 201, body)
        anon_id = int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])
        status, meta_body = self.c.get(f"/main/{anon_id}/meta")
        self.assertEqual(status, 200, meta_body)
        self.assertEqual(json.loads(meta_body)["name"], "[anon] Visitor")

        status, body, _ = self.signed_create(
            self.alice,
            name="Alicia",
            text="claim an alias",
        )
        self.assertEqual(status, 201, body)
        status, alias_body = self.c.get("/@Alicia", format="json")
        self.assertEqual(status, 200, alias_body)
        self.assertEqual(json.loads(alias_body)["author_id"], author_id(self.alice))

        signed = self.signing(
            self.alice,
            "profile.update",
            name="ALICE",
            bio="Agent profile\nsecond line",
        )
        self.assertEqual(signed["name"], "Alice")
        status, updated_body = self.c.post(
            "/_profile",
            key=public_b64(self.alice),
            sig=sign_b64(self.alice, signed["payload_b64"]),
            nonce=signed["nonce"],
            issued=str(signed["issued"]),
            name="ALICE",
            bio="Agent profile\nsecond line",
        )
        self.assertEqual(status, 200, updated_body)
        updated = json.loads(updated_body)
        self.assertTrue(updated["profile_signed"])
        self.assertEqual(updated["bio"], "Agent profile\nsecond line")
        self.assertEqual(updated["name"], "Alice")

        payload = base64.b64decode(updated["profile_payload_b64"])
        signature = base64.b64decode(updated["profile_signature"])
        self.alice.public_key().verify(signature, payload)

        status, text_profile = self.c.get("/@Alice")
        self.assertEqual(status, 200, text_profile)
        self.assertIn("Agent profile", text_profile)
        self.assertIn("profile_signature:", text_profile)
        self.assertIn(public_b64(self.alice), text_profile)

        status, denied = self.c.get(
            "/_signing",
            action="profile.update",
            key=public_b64(self.bob),
            name="Alice",
            bio="not mine",
        )
        self.assertEqual(status, 403, denied)

    def test_hashtag_topics_reindex_search_and_delete(self) -> None:
        status, body = self.c.get(
            "/publish",
            board="main",
            name="Tagger",
            title="#AI release",
            text=(
                "hello #安全 #rust-lang #AI "
                "https://example.com/#section\n# heading\n"
                "#this-tag-is-way-too-long-because-it-exceeds-thirty-two-characters"
            ),
        )
        self.assertEqual(status, 201, body)
        post_id = int(dict(line.split("=", 1) for line in body.splitlines() if "=" in line)["id"])

        status, meta_body = self.c.get(f"/main/{post_id}/meta")
        self.assertEqual(status, 200, meta_body)
        meta = json.loads(meta_body)
        self.assertEqual(set(meta["tags"]), {"ai", "安全", "rust-lang"})
        self.assertNotIn("section", meta["tags"])

        status, tags_body = self.c.get("/tags", format="json")
        self.assertEqual(status, 200, tags_body)
        tag_names = {item["tag"] for item in json.loads(tags_body)}
        self.assertTrue({"ai", "安全", "rust-lang"}.issubset(tag_names))

        status, topic_body = self.c.get("/tag/AI", format="ndjson")
        self.assertEqual(status, 200, topic_body)
        item = json.loads(topic_body.splitlines()[0])
        self.assertEqual(item["id"], post_id)
        self.assertIn("ai", item["tags"])

        status, search_body = self.c.get("/_search", q="#AI")
        self.assertEqual(status, 200, search_body)
        self.assertIn(f"#{post_id} ", search_body)

        status, edit_body = self.c.get(
            "/publish",
            edit=str(post_id),
            name="Tagger",
            text="replacement #newtopic",
        )
        self.assertEqual(status, 200, edit_body)

        status, meta_body = self.c.get(f"/main/{post_id}/meta")
        self.assertEqual(status, 200, meta_body)
        self.assertEqual(json.loads(meta_body)["tags"], ["newtopic"])
        self.assertEqual(self.c.get("/tag/ai")[0], 404)

        status, _ = self.c.get("/publish", delete=str(post_id))
        self.assertEqual(status, 200)
        self.assertEqual(self.c.get("/tag/newtopic")[0], 404)

    def test_channel_naming_reserved_words_and_legacy_read_only(self) -> None:
        status, body = self.c.get(
            "/publish",
            board="news2",
            name="reader",
            text="valid channel",
        )
        self.assertEqual(status, 201, body)

        invalid = [
            ("News", "lowercase"),
            ("a", "2..24"),
            ("news-room", "only lowercase ASCII letters and digits"),
            ("news_room", "only lowercase ASCII letters and digits"),
            ("news.room", "only lowercase ASCII letters and digits"),
            ("安全", "start with a lowercase ASCII letter"),
            ("admin", "reserved"),
            ("abcdefghijklmnopqrstuvwxy", "2..24"),
        ]
        for channel, expected in invalid:
            with self.subTest(channel=channel):
                status, body = self.c.get(
                    "/publish",
                    board=channel,
                    name="reader",
                    text="should fail",
                )
                self.assertEqual(status, 400, body)
                self.assertIn(expected, body)

        store = self.server.board.store
        with store._lock, store._conn:
            store._ensure_board("old-name")
        status, body = self.c.get("/old-name")
        self.assertEqual(status, 200, body)
        status, body = self.c.get(
            "/publish",
            board="old-name",
            name="reader",
            text="legacy write",
        )
        self.assertEqual(status, 400, body)

        rules = self.c.get("/rules")[1]
        self.assertIn("## channel naming", rules)
        self.assertIn("admin", rules)
        self.assertIn("[anon] NAME", rules)
        schema = json.loads(self.c.get("/_schema")[1])
        self.assertEqual(schema["channels"]["pattern"], "^[a-z][a-z0-9]{1,23}$")
        self.assertEqual(schema["profiles"]["route"], "/@{name}")


if __name__ == "__main__":
    unittest.main()
