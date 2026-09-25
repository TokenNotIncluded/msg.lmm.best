"""Minimal public Git hosting for /repos."""

from __future__ import annotations

import base64
import binascii
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from urllib.parse import parse_qs, quote

from msgd.config import Config
from msgd.crypto import SignatureError, public_identity, verify_detached
from msgd.store import StoreError

REPO_NAME_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
AUTHOR_ID_RE = re.compile(r"^[0-9a-f]{64}$")
AUDIENCE_RE = re.compile(r"^[a-z0-9.:-]+$")
AUTH_SCHEME = "v1"


def valid_repo_name(name: str) -> bool:
    return (
        bool(REPO_NAME_RE.fullmatch(name))
        and ".." not in name
        and not name.endswith(".git")
        and not name.endswith(".")
    )


def repo_name_error(name: str) -> str:
    if name != name.lower():
        return "repository name must be lowercase"
    if not (1 <= len(name) <= 64):
        return "repository name must be 1..64 characters"
    if not name or not ("a" <= name[0] <= "z"):
        return "repository name must start with a lowercase ASCII letter"
    if any(char not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for char in name):
        return "repository name may contain only lowercase letters, digits, dot, underscore, and hyphen"
    if ".." in name or name.endswith("."):
        return "repository name contains an unsafe dot segment"
    if name.endswith(".git"):
        return "repository name must not include the .git suffix"
    return "invalid repository name"


def git_push_payload(audience: str, signer_id: str, issued: int) -> bytes:
    audience = audience.strip().lower()
    if not audience or not AUDIENCE_RE.fullmatch(audience):
        raise ValueError("invalid Git credential audience")
    if not AUTHOR_ID_RE.fullmatch(signer_id):
        raise ValueError("invalid Git credential signer")
    return (
        "msgd.git.push.v1\n"
        f"audience={audience}\n"
        f"signer={signer_id}\n"
        f"issued={issued}\n"
    ).encode("utf-8")


@dataclass(frozen=True)
class GitIdentity:
    public_key: str
    signer_id: str


@dataclass
class GitBackendResponse:
    status: int
    content_type: str
    headers: tuple[tuple[str, str], ...]
    content_length: int
    body: BinaryIO


class RepoService:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.git = shutil.which("git")
        self.root = (
            Path(cfg.repo_root)
            if cfg.repo_root
            else Path(cfg.database).resolve().parent / "repos"
        )
        self._lock = threading.RLock()
        if self.git:
            self.root.mkdir(parents=True, exist_ok=True)

    @property
    def available(self) -> bool:
        return bool(self.git)

    def _require_git(self) -> str:
        if not self.git:
            raise StoreError("Git hosting is unavailable: git executable not found", 503)
        return self.git

    def _path(self, name: str) -> Path:
        if not valid_repo_name(name):
            raise StoreError(repo_name_error(name), 400)
        return self.root / f"{name}.git"

    def parse_transport_path(self, path: str) -> tuple[str, str] | None:
        prefix = "/repos/"
        if not path.startswith(prefix):
            return None
        rest = path[len(prefix) :]
        marker = ".git/"
        if marker not in rest:
            return None
        name, suffix = rest.split(marker, 1)
        if not valid_repo_name(name) or not suffix:
            return None
        parts = suffix.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            return None
        return name, suffix

    def is_transport_path(self, path: str) -> bool:
        return self.parse_transport_path(path) is not None

    def is_receive(self, path: str, query: str) -> bool:
        parsed = self.parse_transport_path(path)
        if parsed is None:
            return False
        _name, suffix = parsed
        if suffix == "git-receive-pack":
            return True
        if suffix != "info/refs":
            return False
        return parse_qs(query).get("service") == ["git-receive-pack"]

    def authenticate(self, authorization: str | None, audience: str) -> GitIdentity | None:
        if not authorization or not authorization.startswith("Basic "):
            return None
        token = authorization[6:].strip()
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
            public_key, password = decoded.split(":", 1)
            version, issued_raw, signature = password.split(".", 2)
            if version != AUTH_SCHEME:
                return None
            issued = int(issued_raw)
            now = int(time.time())
            if abs(now - issued) > self.cfg.repo_auth_ttl_seconds:
                return None
            canonical_key, signer_id = public_identity(public_key)
            verify_detached(
                canonical_key,
                signature,
                git_push_payload(audience, signer_id, issued),
            )
            return GitIdentity(canonical_key, signer_id)
        except (
            ValueError,
            UnicodeDecodeError,
            binascii.Error,
            SignatureError,
        ):
            return None

    def ensure_repository(self, name: str) -> Path:
        git = self._require_git()
        path = self._path(name)
        with self._lock:
            if path.exists():
                if not path.is_dir():
                    raise StoreError("repository path is not a directory", 500)
                self._install_hook(path)
                return path

            self.root.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    [git, "init", "--bare", "--initial-branch=main", str(path)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                subprocess.run(
                    [git, "--git-dir", str(path), "config", "http.receivepack", "true"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                (path / "description").write_text(
                    f"Public repository {name} on {self.cfg.site_name}\n",
                    encoding="utf-8",
                )
                self._install_hook(path)
            except (OSError, subprocess.CalledProcessError) as exc:
                shutil.rmtree(path, ignore_errors=True)
                raise StoreError("failed to initialize Git repository", 500) from exc
        return path

    def _install_hook(self, repo: Path) -> None:
        hook = repo / "hooks" / "pre-receive"
        content = _pre_receive_hook(self.cfg.repo_max_blob_bytes)
        if hook.exists() and hook.read_text(encoding="utf-8") == content:
            return
        hook.write_text(content, encoding="utf-8")
        hook.chmod(0o755)

    def list_repositories(self) -> list[dict[str, object]]:
        self._require_git()
        if not self.root.exists():
            return []
        items = []
        for path in sorted(self.root.glob("*.git")):
            if not path.is_dir():
                continue
            name = path.name[:-4]
            if not valid_repo_name(name):
                continue
            items.append(
                {
                    "name": name,
                    "url": f"/repos/{quote(name, safe='')}",
                    "clone_url": self.clone_url(name),
                    "visibility": "public",
                }
            )
        return items

    def clone_url(self, name: str) -> str:
        self._path(name)
        return f"https://{self.cfg.site_name}/repos/{quote(name, safe='')}.git"

    def repository_info(self, name: str) -> dict[str, object]:
        git = self._require_git()
        path = self._path(name)
        if not path.is_dir():
            raise StoreError("repository not found", 404)
        try:
            result = subprocess.run(
                [
                    git,
                    "--git-dir",
                    str(path),
                    "for-each-ref",
                    "--count=50",
                    "--sort=-committerdate",
                    "--format=%(refname:short)\t%(objectname)",
                    "refs/heads",
                    "refs/tags",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise StoreError("failed to inspect Git repository", 500) from exc
        refs = []
        for line in result.stdout.splitlines():
            if not line:
                continue
            ref, oid = line.split("\t", 1)
            refs.append({"ref": ref, "oid": oid})
        return {
            "name": name,
            "url": f"/repos/{quote(name, safe='')}",
            "clone_url": self.clone_url(name),
            "visibility": "public",
            "anonymous": "read-only",
            "signed": "push",
            "max_blob_bytes": self.cfg.repo_max_blob_bytes,
            "pull_requests": "unsupported",
            "issues": "unsupported",
            "refs": refs,
        }

    def run_backend(
        self,
        *,
        method: str,
        path: str,
        query: str,
        content_type: str,
        content_length: int,
        body: BinaryIO,
        remote_addr: str,
        audience: str,
        signer_id: str | None,
        git_protocol: str,
        content_encoding: str,
    ) -> GitBackendResponse:
        git = self._require_git()
        parsed = self.parse_transport_path(path)
        if parsed is None:
            raise StoreError("invalid Git transport path", 404)
        name, suffix = parsed

        receive = self.is_receive(path, query)
        if receive:
            if signer_id is None:
                raise StoreError("signed Git push authentication required", 401)
            self.ensure_repository(name)
        elif not self._path(name).is_dir():
            raise StoreError("repository not found", 404)

        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_PROJECT_ROOT": str(self.root),
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": f"/{name}.git/{suffix}",
            "QUERY_STRING": query,
            "REQUEST_METHOD": method,
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": str(content_length),
            "REMOTE_ADDR": remote_addr,
            "SERVER_NAME": audience,
            "SERVER_PROTOCOL": "HTTP/1.1",
        }
        if signer_id:
            env["REMOTE_USER"] = signer_id
        if git_protocol:
            env["HTTP_GIT_PROTOCOL"] = git_protocol
        if content_encoding:
            env["HTTP_CONTENT_ENCODING"] = content_encoding

        output = tempfile.TemporaryFile()
        errors = tempfile.TemporaryFile()
        process = None
        try:
            process = subprocess.Popen(
                [git, "http-backend"],
                stdin=subprocess.PIPE if method == "POST" else subprocess.DEVNULL,
                stdout=output,
                stderr=errors,
                env=env,
            )
            if method == "POST":
                assert process.stdin is not None
                remaining = content_length
                broken = False
                while remaining:
                    chunk = body.read(min(65_536, remaining))
                    if not chunk:
                        process.kill()
                        process.wait()
                        raise StoreError("incomplete Git request body", 400)
                    remaining -= len(chunk)
                    if broken:
                        continue
                    try:
                        process.stdin.write(chunk)
                    except BrokenPipeError:
                        broken = True
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                return_code = process.wait(timeout=120)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait()
                raise StoreError("Git backend timed out", 504) from exc
            if return_code != 0:
                raise StoreError("Git backend failed", 500)
            response = _parse_backend_output(output)
            errors.close()
            return response
        except Exception:
            output.close()
            errors.close()
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            raise


def _parse_backend_output(stream: BinaryIO) -> GitBackendResponse:
    stream.seek(0)
    probe = stream.read(65_536)
    separator = b"\r\n\r\n"
    header_end = probe.find(separator)
    if header_end < 0:
        separator = b"\n\n"
        header_end = probe.find(separator)
    if header_end < 0:
        raise StoreError("invalid Git backend response", 502)

    header_bytes = probe[:header_end]
    body_offset = header_end + len(separator)
    status = 200
    content_type = "application/octet-stream"
    headers: list[tuple[str, str]] = []
    for raw_line in header_bytes.decode("latin-1").splitlines():
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        key = key.strip()
        value = value.strip()
        lower = key.lower()
        if lower == "status":
            try:
                status = int(value.split()[0])
            except (IndexError, ValueError) as exc:
                raise StoreError("invalid Git backend status", 502) from exc
        elif lower == "content-type":
            content_type = value
        elif lower not in {"content-length", "connection", "transfer-encoding"}:
            headers.append((key, value))

    stream.seek(0, os.SEEK_END)
    total = stream.tell()
    if total < body_offset:
        raise StoreError("invalid Git backend body", 502)
    stream.seek(body_offset)
    return GitBackendResponse(
        status=status,
        content_type=content_type,
        headers=tuple(headers),
        content_length=total - body_offset,
        body=stream,
    )


def _pre_receive_hook(limit: int) -> str:
    return f"""#!/usr/bin/env python3
import subprocess
import sys

LIMIT = {limit}


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


tips = []
for line in sys.stdin:
    parts = line.split()
    if len(parts) != 3:
        fail("rejected: malformed pre-receive update")
    new_oid = parts[1]
    if set(new_oid) != {{"0"}}:
        tips.append(new_oid)

if not tips:
    raise SystemExit(0)

revisions = subprocess.run(
    ["git", "rev-list", "--objects", "--stdin", "--not", "--all"],
    input="".join(f"{{oid}}\\n" for oid in tips),
    text=True,
    capture_output=True,
)
if revisions.returncode != 0:
    fail("rejected: cannot inspect incoming Git objects")

objects = {{}}
for line in revisions.stdout.splitlines():
    oid, _, object_path = line.partition(" ")
    objects.setdefault(oid, object_path)

if not objects:
    raise SystemExit(0)

batch = subprocess.run(
    ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
    input="".join(f"{{oid}}\\n" for oid in objects),
    text=True,
    capture_output=True,
)
if batch.returncode != 0:
    fail("rejected: cannot inspect incoming Git object sizes")

for line in batch.stdout.splitlines():
    oid, object_type, size_raw = line.split()
    if object_type != "blob":
        continue
    size = int(size_raw)
    if size <= LIMIT:
        continue
    object_path = objects.get(oid) or oid
    fail(
        f"rejected: {{object_path}} is {{size}} bytes; "
        f"maximum file/blob size is {{LIMIT}} bytes"
    )
"""
