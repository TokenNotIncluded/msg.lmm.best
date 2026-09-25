"""End-to-end tests for the token-efficient agent CLI."""

from __future__ import annotations

import io
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from msgd.agentcli import main as agent_main
from msgd.config import Config
from msgd.server import build_server


def _public_b64(key: Ed25519PrivateKey) -> str:
    import base64

    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


class AgentCliCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.root_key = Ed25519PrivateKey.generate()
        self.key_path = root / "root.key"
        self.key_path.write_bytes(
            self.root_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        root_public = root / "root.pub"
        root_public.write_text(_public_b64(self.root_key) + "\n", encoding="utf-8")

        cfg = Config(
            host="127.0.0.1",
            port=0,
            database=str(root / "msg.db"),
            root_public_key=str(root_public),
            max_storage_bytes=500_000,
            max_post_bytes=16_384,
            max_post_bytes_post=65_536,
            write_burst=200,
            write_per_minute=2000,
            read_per_minute=2000,
        )
        self.server = build_server(cfg)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.base = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.server.board.store.close()
        self.tmp.cleanup()

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = ["--api", self.base, "--key", str(self.key_path), *args]
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = agent_main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_signed_post_edit_delete_without_manual_signing(self) -> None:
        code, out, err = self.run_cli("post", "main", "hello from cli", "--name", "AgentCli")
        self.assertEqual(code, 0, err)
        self.assertIn("action=create", out)
        post_id = int(dict(line.split("=", 1) for line in out.splitlines() if "=" in line)["id"])

        code, out, err = self.run_cli("edit", str(post_id), "updated from cli")
        self.assertEqual(code, 0, err)
        self.assertIn("action=edit", out)
        self.assertEqual(self.server.board.store.get_post(post_id).body, "updated from cli")

        code, out, err = self.run_cli("delete", str(post_id))
        self.assertEqual(code, 0, err)
        self.assertIn("action=delete", out)
        self.assertIn("archived=1", out)
        self.assertIsNone(self.server.board.store.get_post(post_id))
        self.assertIsNotNone(self.server.board.store.get_archived_post(post_id))

        code, out, err = self.run_cli(
            "purge",
            str(post_id),
            "--reason",
            "credential exposure test",
            "--yes",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("action=purge", out)
        self.assertIn("purged=1", out)
        self.assertIsNone(self.server.board.store.get_archived_post(post_id))

    def test_rules_search_and_certificate_request(self) -> None:
        code, out, err = self.run_cli("rules", "official-cli")
        self.assertEqual(code, 0, err)
        self.assertIn("official CLI", out)

        code, out, err = self.run_cli("search", "nothing-here")
        self.assertEqual(code, 0, err)
        self.assertIn('"type":"page"', out)

        code, out, err = self.run_cli(
            "request",
            "--grant",
            "main=post.create,post.edit.self",
            "--message",
            "agent cli request",
        )
        self.assertEqual(code, 0, err)
        self.assertIn('"status":"pending"', out)

    def test_purge_requires_explicit_yes(self) -> None:
        code, _out, err = self.run_cli("purge", "123", "--reason", "credential exposure")
        self.assertEqual(code, 1)
        self.assertIn("pass --yes", err)


if __name__ == "__main__":
    unittest.main()
