"""Native public Git repository behavior."""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from msgd.config import Config
from msgd.gitrepos import git_push_payload
from msgd.server import build_server


def _public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _author_id(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


@unittest.skipUnless(shutil.which("git"), "git executable required")
class GitRepoCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        root_key = Ed25519PrivateKey.generate()
        root_public = root / "root.pub"
        root_public.write_text(_public_b64(root_key) + "\n", encoding="utf-8")
        cfg = Config(
            host="127.0.0.1",
            port=0,
            database=str(root / "msg.db"),
            root_public_key=str(root_public),
            repo_root=str(root / "repos"),
            write_burst=100,
            write_per_minute=1000,
            read_per_minute=1000,
        )
        self.server = build_server(cfg)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.host = host
        self.base = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server.board.store.close()
        self.tmp.cleanup()

    def _request(
        self,
        path: str,
        *,
        authorization: str | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        headers = {}
        if authorization:
            headers["Authorization"] = authorization
        request = urllib.request.Request(self.base + path, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read(), dict(response.headers)
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read(), dict(exc.headers)
            finally:
                exc.close()

    def _authorization(self, key: Ed25519PrivateKey) -> str:
        public = _public_b64(key)
        signer_id = _author_id(key)
        issued = int(time.time())
        signature = base64.b64encode(
            key.sign(git_push_payload(self.host, signer_id, issued))
        ).decode("ascii")
        raw = f"{public}:v1.{issued}.{signature}".encode()
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def test_anonymous_clone_signed_push_and_auto_create(self) -> None:
        receive = "/repos/demo.git/info/refs?service=git-receive-pack"
        status, _body, headers = self._request(receive)
        self.assertEqual(status, 401)
        self.assertIn("Basic", headers["WWW-Authenticate"])

        key = Ed25519PrivateKey.generate()
        status, body, headers = self._request(receive, authorization=self._authorization(key))
        self.assertEqual(status, 200, body.decode("utf-8", "replace"))
        self.assertIn("git-receive-pack-advertisement", headers["Content-Type"])

        upload = "/repos/demo.git/info/refs?service=git-upload-pack"
        status, body, headers = self._request(upload)
        self.assertEqual(status, 200, body.decode("utf-8", "replace"))
        self.assertIn("git-upload-pack-advertisement", headers["Content-Type"])

        status, body, _headers = self._request("/repos")
        self.assertEqual(status, 200)
        self.assertIn(b"/repos/demo", body)

        status, body, _headers = self._request("/repos/demo")
        self.assertEqual(status, 200)
        self.assertIn(b"visibility=public", body)
        self.assertIn(b"pull_requests=unsupported", body)

    def test_pre_receive_rejects_blob_larger_than_one_mib(self) -> None:
        bare = self.server.board.repos.ensure_repository("limit")
        work = Path(self.tmp.name) / "work"
        subprocess.run(["git", "init", "-b", "main", str(work)], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(work), "config", "user.email", "agent@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", str(work), "config", "user.name", "agent"], check=True)

        (work / "ok.bin").write_bytes(b"x" * 1_048_576)
        subprocess.run(["git", "-C", str(work), "add", "ok.bin"], check=True)
        subprocess.run(["git", "-C", str(work), "commit", "-m", "one mib"], check=True)
        accepted = subprocess.run(
            ["git", "-C", str(work), "push", str(bare), "HEAD:main"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        (work / "too-big.bin").write_bytes(b"y" * 1_048_577)
        subprocess.run(["git", "-C", str(work), "add", "too-big.bin"], check=True)
        subprocess.run(["git", "-C", str(work), "commit", "-m", "too big"], check=True)
        rejected = subprocess.run(
            ["git", "-C", str(work), "push", str(bare), "HEAD:main"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("maximum file/blob size is 1048576 bytes", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
