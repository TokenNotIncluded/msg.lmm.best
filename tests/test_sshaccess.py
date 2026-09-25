from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from msgd.config import Config
from msgd.gitrepos import RepoService
from msgd.sshaccess import (
    SSH_PRESETS,
    SSHKeyStore,
    _authorized_line,
    _repo_name_from_ssh_path,
    auth_main,
    has_scope,
    normalize_scopes,
    normalize_ssh_public_key,
    ssh_access_payload,
)
from msgd.store import StoreError


def public_key() -> str:
    key = Ed25519PrivateKey.generate().public_key()
    return key.public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")


class SSHAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.cfg = Config(
            database=str(root / "msg.db"),
            repo_root=str(root / "repos"),
            site_name="example.test",
            ssh_shell_command="/usr/local/bin/msg-ssh-shell",
            ssh_max_keys_per_identity=3,
        )
        self.store = SSHKeyStore(self.cfg)
        self.owner = "a" * 64

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_public_key_normalizes_comment_and_trailing_newline(self) -> None:
        key = public_key()
        canonical, key_type, fingerprint = normalize_ssh_public_key(key + " laptop\n")
        self.assertEqual(canonical, key)
        self.assertEqual(key_type, "ssh-ed25519")
        self.assertTrue(fingerprint.startswith("SHA256:"))

    def test_scopes_and_presets(self) -> None:
        self.assertEqual(normalize_scopes("repo-write,read,read"), ("read", "repo-write"))
        self.assertIn("keys", SSH_PRESETS["owner"])
        with self.assertRaises(StoreError):
            normalize_scopes("root-shell")

    def test_add_lookup_scope_and_revoke(self) -> None:
        key = public_key()
        item = self.store.add(
            owner_id=self.owner,
            public_key=key,
            name="human laptop",
            scopes=("read", "repo-write"),
        )
        key_type, key_data = key.split()
        found = self.store.lookup(key_type, key_data)
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found["owner_id"], self.owner)
        self.assertTrue(has_scope(found, "repo-write"))
        self.assertFalse(has_scope(found, "keys"))

        updated = self.store.set_scopes(self.owner, str(item["id"]), SSH_PRESETS["owner"])
        self.assertTrue(has_scope(updated, "admin"))
        revoked = self.store.revoke(self.owner, str(item["id"]))
        self.assertIsNotNone(revoked["revoked"])
        self.assertIsNone(self.store.lookup(key_type, key_data))

    def test_same_key_cannot_ambiguously_map_to_two_accounts(self) -> None:
        key = public_key()
        self.store.add(owner_id=self.owner, public_key=key, name="one")
        with self.assertRaises(StoreError) as ctx:
            self.store.add(owner_id="b" * 64, public_key=key, name="two")
        self.assertEqual(ctx.exception.status, 409)

    def test_authorized_keys_forces_restricted_shell(self) -> None:
        item = self.store.add(owner_id=self.owner, public_key=public_key(), name="agent")
        line = _authorized_line(self.cfg, item)
        self.assertIn('command="/usr/local/bin/msg-ssh-shell --key-id ', line)
        self.assertIn(",restrict ssh-ed25519 ", line)

    def test_git_ssh_path_is_strict(self) -> None:
        self.assertEqual(_repo_name_from_ssh_path("/repos/demo.git"), "demo")
        self.assertEqual(_repo_name_from_ssh_path("demo.git"), "demo")
        with self.assertRaises(StoreError):
            _repo_name_from_ssh_path("../../etc")

    def test_repo_metadata_advertises_ssh(self) -> None:
        if not RepoService(self.cfg).available:
            self.skipTest("git executable unavailable")
        service = RepoService(self.cfg)
        service.ensure_repository("demo")
        info = service.repository_info("demo")
        self.assertEqual(info["ssh_clone_url"], "ssh://msg@example.test/demo.git")

    def test_access_payload_is_deterministic(self) -> None:
        kwargs = {
            "action": "ssh.add",
            "signer_id": self.owner,
            "nonce": "1" * 32,
            "issued": 123,
            "ssh_public_key": public_key(),
            "name": "human",
            "scopes": ("read", "repo-read"),
        }
        self.assertEqual(ssh_access_payload(**kwargs), ssh_access_payload(**kwargs))

    def test_authorized_keys_command_looks_up_database_key(self) -> None:
        key = public_key()
        self.store.add(owner_id=self.owner, public_key=key, name="human", scopes=("read",))
        config = Path(self.temp.name) / "msg.conf"
        config.write_text(
            "[storage]\n"
            f"database = {self.cfg.database}\n"
            "[ssh]\n"
            "shell_command = /usr/local/bin/msg-ssh-shell\n"
            "max_keys_per_identity = 3\n",
            encoding="utf-8",
        )
        key_type, key_data = key.split()
        output = io.StringIO()
        with patch.dict(os.environ, {"MSGD_CONFIG": str(config)}), contextlib.redirect_stdout(output):
            self.assertEqual(auth_main([key_type, key_data]), 0)
        self.assertIn(",restrict ssh-ed25519 ", output.getvalue())


if __name__ == "__main__":
    unittest.main()
