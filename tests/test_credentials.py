"""Credential storage policy tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from msgd.cli.cert import main as cert_main
from msgd.credentials import credential_dir_candidates, credential_path, find_credential_dir


class CredentialStorageTest(unittest.TestCase):
    def test_candidate_order_prefers_home_then_local_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            cwd = root / "work"
            home.mkdir()
            cwd.mkdir()
            candidates = credential_dir_candidates(
                home=home,
                cwd=cwd,
                env={"XDG_CONFIG_HOME": str(root / "xdg"), "TMPDIR": str(root / "tmp")},
            )
            self.assertEqual(candidates[0], home / ".config" / "msg.lmm.best")
            self.assertEqual(candidates[1], cwd / ".config" / "msg.lmm.best")
            self.assertIn(root / "xdg" / "msg.lmm.best", candidates)
            self.assertEqual(candidates[-1], root / "tmp" / "msg.lmm.best")

    def test_falls_back_when_home_config_is_unusable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            blocked_home = root / "blocked-home"
            blocked_home.write_text("not a directory", encoding="utf-8")
            cwd = root / "work"
            cwd.mkdir()

            directory = find_credential_dir(home=blocked_home, cwd=cwd, env={})
            self.assertEqual(directory, cwd / ".config" / "msg.lmm.best")
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

            path = credential_path("custody.token", home=blocked_home, cwd=cwd, env={})
            self.assertEqual(path, directory / "custody.token")

    def test_keygen_defaults_to_private_config_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            work = Path(tmp) / "work"
            home.mkdir()
            work.mkdir()
            old_cwd = Path.cwd()
            try:
                os.chdir(work)
                with patch.dict(os.environ, {"HOME": str(home)}, clear=False):
                    self.assertEqual(cert_main(["keygen"]), 0)
            finally:
                os.chdir(old_cwd)

            key = home / ".config" / "msg.lmm.best" / "identity.key"
            self.assertTrue(key.is_file())
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(key.parent.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
