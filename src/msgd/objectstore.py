"""Git object database used as the durable content layer.

SQLite remains the transactional metadata/index store.  This module stores post
bodies and attachment bytes in a private bare Git repository so repeated and
versioned content can benefit from Git object deduplication and pack deltas.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

OID_RE = re.compile(r"^[0-9a-f]{40,64}$")


class ObjectStoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class ContentRevision:
    commit_oid: str
    body_oid: str
    attachment_oids: tuple[str, ...]


class GitObjectStore:
    """Private Git ODB with one live ref per post.

    The ref `refs/msg/posts/<id>` points at the latest revision commit.  Each
    revision tree contains `body` plus generated `file-NNNN` entries.  SQLite
    owns names, MIME types and all other metadata; the Git tree exists only to
    make current and historical bytes reachable to Git's pack/gc machinery.
    """

    def __init__(self, root: str | Path, *, enabled: bool = True) -> None:
        self.root = Path(root).expanduser().resolve()
        self.git = shutil.which("git") if enabled else None
        self._lock = threading.RLock()
        if self.git:
            self._ensure_repository()

    @property
    def available(self) -> bool:
        return self.git is not None

    def _ensure_repository(self) -> None:
        assert self.git is not None
        with self._lock:
            if self.root.exists():
                probe = subprocess.run(
                    [self.git, "--git-dir", str(self.root), "rev-parse", "--is-bare-repository"],
                    capture_output=True,
                    text=True,
                )
                if probe.returncode != 0 or probe.stdout.strip() != "true":
                    raise ObjectStoreError(
                        f"object store path is not a bare Git repository: {self.root}"
                    )
                return

            self.root.parent.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    [self.git, "init", "--bare", "--initial-branch=main", str(self.root)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                # Ref logs are unnecessary here and complicate emergency purge semantics.
                subprocess.run(
                    [
                        self.git,
                        "--git-dir",
                        str(self.root),
                        "config",
                        "core.logAllRefUpdates",
                        "false",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except (OSError, subprocess.CalledProcessError) as exc:
                shutil.rmtree(self.root, ignore_errors=True)
                raise ObjectStoreError("failed to initialize Git object store") from exc

    def _run(
        self,
        args: list[str],
        *,
        data: bytes | None = None,
        env: dict[str, str] | None = None,
    ) -> bytes:
        if not self.git:
            raise ObjectStoreError("Git object store is unavailable")
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        try:
            result = subprocess.run(
                [self.git, "--git-dir", str(self.root), *args],
                input=data,
                check=True,
                capture_output=True,
                env=process_env,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            detail = ""
            if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
                detail = exc.stderr.decode("utf-8", "replace").strip()
            message = "Git object store command failed"
            if detail:
                message += f": {detail}"
            raise ObjectStoreError(message) from exc
        return result.stdout

    @staticmethod
    def _oid(value: str) -> str:
        value = value.strip().lower()
        if not OID_RE.fullmatch(value):
            raise ObjectStoreError("invalid Git object id")
        return value

    def put_blob(self, data: bytes) -> str:
        with self._lock:
            oid = self._run(["hash-object", "-w", "--stdin"], data=data).decode().strip()
        return self._oid(oid)

    def get_blob(self, oid: str) -> bytes:
        oid = self._oid(oid)
        with self._lock:
            return self._run(["cat-file", "blob", oid])

    def write_revision(
        self,
        post_id: int,
        *,
        body: bytes,
        attachments: Iterable[bytes] = (),
        parent: str | None = None,
        timestamp: float | None = None,
        message: str = "store post revision",
        activate: bool = True,
    ) -> ContentRevision:
        if post_id < 1:
            raise ObjectStoreError("post id must be positive")
        parent_oid = self._oid(parent) if parent else None
        with self._lock:
            body_oid = self.put_blob(body)
            attachment_oids = tuple(self.put_blob(data) for data in attachments)

            entries = [f"100644 blob {body_oid}\tbody\n"]
            entries.extend(
                f"100644 blob {oid}\tfile-{slot:04d}\n" for slot, oid in enumerate(attachment_oids)
            )
            tree_oid = self._oid(
                self._run(["mktree"], data="".join(entries).encode()).decode().strip()
            )

            stamp = int(time.time() if timestamp is None else timestamp)
            commit_args = ["commit-tree", tree_oid]
            if parent_oid:
                commit_args.extend(["-p", parent_oid])
            identity_env = {
                "GIT_AUTHOR_NAME": "msgd object store",
                "GIT_AUTHOR_EMAIL": "object-store@localhost",
                "GIT_COMMITTER_NAME": "msgd object store",
                "GIT_COMMITTER_EMAIL": "object-store@localhost",
                "GIT_AUTHOR_DATE": f"{stamp} +0000",
                "GIT_COMMITTER_DATE": f"{stamp} +0000",
            }
            commit_oid = self._oid(
                self._run(
                    commit_args,
                    data=(message.rstrip() + "\n").encode(),
                    env=identity_env,
                )
                .decode()
                .strip()
            )
            if activate:
                self.set_post_ref(post_id, commit_oid)
            return ContentRevision(commit_oid, body_oid, attachment_oids)

    def set_post_ref(self, post_id: int, commit_oid: str) -> None:
        if post_id < 1:
            raise ObjectStoreError("post id must be positive")
        commit_oid = self._oid(commit_oid)
        with self._lock:
            self._run(["cat-file", "-e", f"{commit_oid}^{{commit}}"])
            self._run(["update-ref", f"refs/msg/posts/{post_id}", commit_oid])

    def delete_post_ref(self, post_id: int) -> None:
        if post_id < 1 or not self.available:
            return
        ref = f"refs/msg/posts/{post_id}"
        with self._lock:
            probe = subprocess.run(
                [
                    self.git,
                    "--git-dir",
                    str(self.root),
                    "show-ref",
                    "--verify",
                    "--quiet",
                    ref,
                ],
                check=False,
            )
            if probe.returncode == 0:
                self._run(["update-ref", "-d", ref])

    def prune(self) -> None:
        """Immediately discard objects that became unreachable after a hard purge."""
        if not self.available:
            return
        with self._lock:
            self._run(["reflog", "expire", "--expire=now", "--all"])
            self._run(["gc", "--prune=now"])

    def purge_post(self, post_id: int) -> None:
        self.delete_post_ref(post_id)
        self.prune()
