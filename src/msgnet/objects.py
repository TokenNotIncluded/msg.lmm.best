"""Private, pinned Git blobs; callers hold Database.lock during every operation."""

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from msgnet.model import Invalid


@dataclass(frozen=True, slots=True)
class Objects:
    path: Path
    limit: int = 1_048_576

    def _run(self, *arguments: str, data: bytes | None = None) -> bytes:
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith("GIT_")
        }
        environment.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        })
        command = [
            "git",
            "--git-dir",
            str(self.path),
            "-c",
            "core.fsync=all",
            "-c",
            "gc.auto=0",
            *arguments,
        ]
        result = subprocess.run(
            command,
            input=data,
            capture_output=True,
            env=environment,
            check=False,
            timeout=30,
        )
        if result.returncode:
            raise Invalid(
                f"Git object operation failed: {result.stderr.decode(errors='replace')[:200]}"
            )
        return result.stdout

    def initialize(self) -> None:
        if self.path.exists():
            if self._run("rev-parse", "--is-bare-repository").strip() != b"true":
                raise Invalid("content storage must be a bare repository")
            if self._run("rev-parse", "--show-object-format").strip() != b"sha256":
                raise Invalid("object format differs; explicit migration required")
            return
        self.path.mkdir(mode=0o700, parents=True)
        self._run("init", "--bare", "--object-format=sha256", str(self.path))
        self._run("config", "gc.auto", "0")
        self._run("config", "core.logAllRefUpdates", "false")

    @staticmethod
    def oid(value: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise Invalid("invalid SHA-256 object ID")
        return value

    def put(self, body: bytes) -> str:
        if len(body) > self.limit:
            raise Invalid("content exceeds object limit")
        oid = self.oid(self._run("hash-object", "-w", "--stdin", data=body).decode().strip())
        self._run("update-ref", f"refs/msg/objects/{oid}", oid)
        return oid

    def get(self, oid: str) -> bytes:
        oid = self.oid(oid)
        size = int(self._run("cat-file", "-s", oid))
        if size > self.limit:
            raise Invalid("stored object exceeds configured limit")
        return self._run("cat-file", "blob", oid)

    def collect(self, reachable: frozenset[str]) -> int:
        """Offline/exclusively locked maintenance, never an HTTP request operation."""
        for oid in reachable:
            self.get(oid)  # Fail closed before deleting any pin if SQL is inconsistent.
            self._run("update-ref", f"refs/msg/objects/{oid}", oid)
        pins = self._run("for-each-ref", "--format=%(refname)", "refs/msg/objects/")
        removed = 0
        for ref in pins.decode().splitlines():
            oid = self.oid(ref.rsplit("/", 1)[1])
            if oid not in reachable:
                self._run("update-ref", "-d", ref)
                removed += 1
        self._run("gc")  # Normal grace period remains in force, even under exclusive lock.
        return removed
