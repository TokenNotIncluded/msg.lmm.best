"""Certificate-gated per-identity static web hosting."""

from __future__ import annotations

import base64
import hashlib
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
from msgd.crypto import SignatureError, certificate_payload, make_certificate
from msgd.server import build_server


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def author_id(key: Ed25519PrivateKey) -> str:
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
    ) -> tuple[int, bytes, dict[str, str]]:
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
                return response.status, response.read(), dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read(), dict(exc.headers.items())
            finally:
                exc.close()

    def get(self, path: str, **params: str) -> tuple[int, bytes, dict[str, str]]:
        return self.request(path, params)

    def post(self, path: str, **params: str) -> tuple[int, bytes, dict[str, str]]:
        return self.request(path, params, post=True)


class WebSiteCase(unittest.TestCase):
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
            web_root=str(Path(self.tmp.name) / "web"),
            web_max_site_bytes=64,
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
        self.issue(
            self.alice,
            "1" * 32,
            {"post.create", "post.edit.self", "web.write", "web.delete"},
        )
        self.issue(self.bob, "2" * 32, {"post.create", "post.edit.self"})
        self.claim(self.alice, "AliceWeb")
        self.claim(self.bob, "BobWeb")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server.board.store.close()
        self.tmp.cleanup()

    def issue(self, key: Ed25519PrivateKey, serial: str, actions: set[str]) -> None:
        cert = make_certificate(
            serial=serial,
            issuer_serial="root",
            issuer_id=author_id(self.root),
            subject_key=public_b64(key),
            not_before=1,
            not_after=4_102_444_800,
            delegate=False,
            grants={"*": actions},
        )
        signature = base64.b64encode(self.root.sign(certificate_payload(cert.body))).decode("ascii")
        self.server.board.store.register_certificate(cert.body, signature)

    def signing(self, key: Ed25519PrivateKey, action: str, **fields: str) -> tuple[int, dict]:
        status, body, _headers = self.c.get(
            "/_signing",
            action=action,
            key=public_b64(key),
            **fields,
        )
        try:
            parsed = json.loads(body.decode())
        except json.JSONDecodeError:
            parsed = {"error": body.decode()}
        return status, parsed

    def claim(self, key: Ed25519PrivateKey, name: str) -> None:
        status, signing = self.signing(
            key,
            "post.create",
            board="main",
            name=name,
            text="claim",
        )
        self.assertEqual(status, 200, signing)
        status, body, _headers = self.c.post(
            "/publish",
            board="main",
            name=name,
            text="claim",
            key=public_b64(key),
            sig=sign_b64(key, signing["payload_b64"]),
            nonce=str(signing["nonce"]),
            issued=str(signing["issued"]),
        )
        self.assertEqual(status, 201, body.decode())

    def put(
        self,
        key: Ed25519PrivateKey,
        path: str,
        data: bytes,
        content_type: str = "text/html",
    ) -> tuple[int, dict]:
        digest = hashlib.sha256(data).hexdigest()
        status, signing = self.signing(
            key,
            "web.write",
            path=path,
            sha256=digest,
            bytes=str(len(data)),
            content_type=content_type,
        )
        if status != 200:
            return status, signing
        status, body, _headers = self.c.post(
            "/_web",
            action="web.write",
            version=str(signing["version"]),
            path=path,
            content_type=content_type,
            content_b64=base64.b64encode(data).decode("ascii"),
            key=public_b64(key),
            sig=sign_b64(key, signing["payload_b64"]),
            nonce=str(signing["nonce"]),
            issued=str(signing["issued"]),
        )
        return status, json.loads(body.decode())

    def delete(self, key: Ed25519PrivateKey, path: str) -> tuple[int, dict]:
        status, signing = self.signing(key, "web.delete", path=path)
        if status != 200:
            return status, signing
        status, body, _headers = self.c.post(
            "/_web",
            action="web.delete",
            version=str(signing["version"]),
            path=path,
            key=public_b64(key),
            sig=sign_b64(key, signing["payload_b64"]),
            nonce=str(signing["nonce"]),
            issued=str(signing["issued"]),
        )
        return status, json.loads(body.decode())

    def test_index_resolution_nested_paths_and_delete(self) -> None:
        html = b"<h1>agent site</h1>"
        status, result = self.put(self.alice, "index.html", html)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["quota_bytes"], 64)
        self.assertEqual(result["url"], "/@AliceWeb/w/index.html")

        status, empty = self.put(self.alice, "empty.txt", b"", "text/plain")
        self.assertEqual(status, 200, empty)

        status, body, headers = self.c.get("/@AliceWeb/w/")
        self.assertEqual(status, 200)
        self.assertEqual(body, html)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn("sandbox", headers["Content-Security-Policy"])

        nested = b"<p>docs</p>"
        status, result = self.put(self.alice, "docs/index.html", nested)
        self.assertEqual(status, 200, result)
        status, body, _headers = self.c.get("/@AliceWeb/w/docs/")
        self.assertEqual(status, 200)
        self.assertEqual(body, nested)

        status, result = self.delete(self.alice, "docs/index.html")
        self.assertEqual(status, 200, result)
        self.assertTrue(result["deleted"])
        self.assertEqual(self.c.get("/@AliceWeb/w/docs/")[0], 404)

    def test_certificate_permission_and_quota_are_enforced(self) -> None:
        status, error = self.put(self.bob, "index.html", b"denied")
        self.assertEqual(status, 403, error)

        first = b"a" * 40
        second = b"b" * 30
        self.assertEqual(
            self.put(self.alice, "first.bin", first, "application/octet-stream")[0], 200
        )
        status, error = self.put(
            self.alice,
            "second.bin",
            second,
            "application/octet-stream",
        )
        self.assertEqual(status, 413, error)

    def test_web_grants_are_global_only(self) -> None:
        with self.assertRaisesRegex(SignatureError, "web grants require topic"):
            make_certificate(
                serial="3" * 32,
                issuer_serial="root",
                issuer_id=author_id(self.root),
                subject_key=public_b64(Ed25519PrivateKey.generate()),
                not_before=1,
                not_after=4_102_444_800,
                delegate=False,
                grants={"main": {"web.write"}},
            )


if __name__ == "__main__":
    unittest.main()
