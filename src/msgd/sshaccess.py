"""Delegated SSH access for msg.lmm.best accounts."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
import unicodedata
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from msgd.config import Config
from msgd.crypto import canonical_json
from msgd.gitrepos import RepoService, valid_repo_name
from msgd.store import StoreError

SSH_ACCESS_MAGIC = b"msg.lmm.best/ssh-access/v1\n"
SSH_KEY_ID_RE = re.compile(r"^[0-9a-f]{32}$")
AUTHOR_ID_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_KEY_TYPES = frozenset(
    {
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }
)
SSH_SCOPES = frozenset(
    {
        "read",
        "repo-read",
        "repo-write",
        "keys",
        "admin",
    }
)
SSH_PRESETS: dict[str, tuple[str, ...]] = {
    "viewer": ("read", "repo-read"),
    "contributor": ("read", "repo-read", "repo-write"),
    "owner": tuple(sorted(SSH_SCOPES)),
}


def normalize_scopes(values: str | list[str] | tuple[str, ...] | set[str]) -> tuple[str, ...]:
    raw = values.replace(" ", ",").split(",") if isinstance(values, str) else list(values)
    scopes = tuple(sorted({str(item).strip().lower() for item in raw if str(item).strip()}))
    if not scopes:
        raise StoreError("at least one SSH scope is required", 400)
    unknown = sorted(set(scopes) - SSH_SCOPES)
    if unknown:
        raise StoreError(f"unknown SSH scope: {', '.join(unknown)}", 400)
    return scopes


def scopes_from_preset(value: str) -> tuple[str, ...]:
    preset = value.strip().lower()
    try:
        return SSH_PRESETS[preset]
    except KeyError as exc:
        raise StoreError(f"unknown SSH preset: {value}", 400) from exc


def normalize_ssh_key_name(value: str, *, fallback: str = "") -> str:
    label = " ".join(value.split())
    if not label:
        label = fallback
    if not label:
        raise StoreError("SSH key name is required", 400)
    if len(label) > 80:
        raise StoreError("SSH key name exceeds 80 characters", 400)
    if any(unicodedata.category(char).startswith("C") for char in label):
        raise StoreError("SSH key name may not contain control/format characters", 400)
    return label


def normalize_ssh_public_key(value: str) -> tuple[str, str, str]:
    value = value.strip()
    if "\n" in value or "\r" in value or len(value.encode("utf-8")) > 16_384:
        raise StoreError("invalid SSH public key", 400)
    parts = value.split()
    if len(parts) < 2:
        raise StoreError("SSH public key must contain key type and base64 data", 400)
    key_type, encoded = parts[0], parts[1]
    if key_type not in ALLOWED_KEY_TYPES:
        raise StoreError(f"unsupported SSH key type: {key_type}", 400)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded):
        raise StoreError("invalid SSH public key base64", 400)
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise StoreError("invalid SSH public key base64", 400) from exc
    if not blob or len(blob) > 8192:
        raise StoreError("invalid SSH public key data", 400)
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    canonical = f"{key_type} {encoded}"
    return canonical, key_type, f"SHA256:{fingerprint}"


def ssh_access_payload(
    *,
    action: str,
    signer_id: str,
    nonce: str,
    issued: int,
    key_id: str = "",
    ssh_public_key: str = "",
    name: str = "",
    scopes: tuple[str, ...] | list[str] | str = (),
    expires: int | None = None,
    owner_id: str | None = None,
) -> bytes:
    if action not in {
        "ssh.list",
        "ssh.add",
        "ssh.scopes",
        "ssh.rename",
        "ssh.expiry",
        "ssh.revoke",
    }:
        raise StoreError("unsupported SSH key action", 400)
    if not AUTHOR_ID_RE.fullmatch(signer_id):
        raise StoreError("invalid SSH key signer id", 400)
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise StoreError("SSH key nonce must be 32 lowercase hex characters", 400)
    normalized_scopes: tuple[str, ...] = ()
    if scopes:
        normalized_scopes = normalize_scopes(scopes)
    value = {
        "v": 1,
        "action": action,
        "signer_id": signer_id,
        "nonce": nonce,
        "issued": int(issued),
        "key_id": key_id,
        "ssh_public_key": ssh_public_key,
        "name": " ".join(name.split()),
        "scopes": list(normalized_scopes),
        "expires": int(expires or 0),
    }
    if owner_id is not None:
        if not AUTHOR_ID_RE.fullmatch(owner_id):
            raise StoreError("invalid SSH key owner id", 400)
        value["owner_id"] = owner_id
    return SSH_ACCESS_MAGIC + canonical_json(value).encode("utf-8")


class SSHKeyStore:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._lock = threading.RLock()
        path = Path(cfg.database)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, timeout=5, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout = 5000")
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ssh_authorized_keys (
                    id          TEXT PRIMARY KEY,
                    owner_id    TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    public_key  TEXT NOT NULL,
                    key_type    TEXT NOT NULL,
                    fingerprint TEXT NOT NULL UNIQUE,
                    scopes      TEXT NOT NULL,
                    created     REAL NOT NULL,
                    updated     REAL NOT NULL,
                    last_used   REAL,
                    expires     REAL,
                    revoked     REAL,
                    created_by  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ssh_keys_owner
                    ON ssh_authorized_keys(owner_id, created DESC);
                CREATE INDEX IF NOT EXISTS ssh_keys_public
                    ON ssh_authorized_keys(public_key);
                """
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _item(self, row: sqlite3.Row | None) -> dict[str, object] | None:
        if row is None:
            return None
        return {
            "id": str(row["id"]),
            "owner_id": str(row["owner_id"]),
            "name": str(row["name"]),
            "public_key": str(row["public_key"]),
            "key_type": str(row["key_type"]),
            "fingerprint": str(row["fingerprint"]),
            "scopes": tuple(json.loads(str(row["scopes"]))),
            "created": round(float(row["created"]), 3),
            "updated": round(float(row["updated"]), 3),
            "last_used": round(float(row["last_used"]), 3) if row["last_used"] else None,
            "expires": round(float(row["expires"]), 3) if row["expires"] else None,
            "revoked": round(float(row["revoked"]), 3) if row["revoked"] else None,
            "created_by": str(row["created_by"]),
        }

    @staticmethod
    def active(item: dict[str, object], *, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        return item["revoked"] is None and (
            item["expires"] is None or float(item["expires"]) > current
        )

    def add(
        self,
        *,
        owner_id: str,
        public_key: str,
        name: str,
        scopes: tuple[str, ...] | list[str] | str = ("read",),
        expires: int | None = None,
        created_by: str | None = None,
    ) -> dict[str, object]:
        if not AUTHOR_ID_RE.fullmatch(owner_id):
            raise StoreError("invalid SSH key owner id", 400)
        canonical, key_type, fingerprint = normalize_ssh_public_key(public_key)
        label = normalize_ssh_key_name(name, fallback=fingerprint)
        normalized_scopes = normalize_scopes(scopes)
        now = time.time()
        if expires is not None and expires <= now:
            raise StoreError("SSH key expiry must be in the future", 400)
        with self._lock, self._conn:
            count = self._conn.execute(
                """
                SELECT COUNT(*) AS n FROM ssh_authorized_keys
                 WHERE owner_id = ? AND revoked IS NULL
                   AND (expires IS NULL OR expires > ?)
                """,
                (owner_id, now),
            ).fetchone()
            if int(count["n"]) >= self.cfg.ssh_max_keys_per_identity:
                raise StoreError("SSH key limit reached", 409)
            key_id = os.urandom(16).hex()
            try:
                self._conn.execute(
                    """
                    INSERT INTO ssh_authorized_keys(
                        id, owner_id, name, public_key, key_type, fingerprint,
                        scopes, created, updated, expires, created_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key_id,
                        owner_id,
                        label,
                        canonical,
                        key_type,
                        fingerprint,
                        json.dumps(normalized_scopes, separators=(",", ":")),
                        now,
                        now,
                        expires,
                        created_by or owner_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreError("SSH public key is already registered", 409) from exc
        item = self.get(owner_id, key_id)
        assert item is not None
        return item

    def list(self, owner_id: str) -> list[dict[str, object]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM ssh_authorized_keys
                 WHERE owner_id = ?
                 ORDER BY revoked IS NOT NULL, created DESC
                """,
                (owner_id,),
            ).fetchall()
        return [item for row in rows if (item := self._item(row)) is not None]

    def get(self, owner_id: str, key_id: str) -> dict[str, object] | None:
        if not SSH_KEY_ID_RE.fullmatch(key_id):
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM ssh_authorized_keys WHERE owner_id = ? AND id = ?",
                (owner_id, key_id),
            ).fetchone()
        return self._item(row)

    def lookup(self, key_type: str, key_data: str) -> dict[str, object] | None:
        try:
            canonical, _type, _fingerprint = normalize_ssh_public_key(f"{key_type} {key_data}")
        except StoreError:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM ssh_authorized_keys WHERE public_key = ?",
                (canonical,),
            ).fetchone()
        item = self._item(row)
        return item if item is not None and self.active(item) else None

    def lookup_id(self, key_id: str) -> dict[str, object] | None:
        if not SSH_KEY_ID_RE.fullmatch(key_id):
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM ssh_authorized_keys WHERE id = ?",
                (key_id,),
            ).fetchone()
        item = self._item(row)
        return item if item is not None and self.active(item) else None

    def touch(self, key_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE ssh_authorized_keys SET last_used = ? WHERE id = ?",
                (time.time(), key_id),
            )

    def set_scopes(
        self, owner_id: str, key_id: str, scopes: tuple[str, ...] | list[str] | str
    ) -> dict[str, object]:
        normalized = normalize_scopes(scopes)
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                UPDATE ssh_authorized_keys
                   SET scopes = ?, updated = ?
                 WHERE owner_id = ? AND id = ? AND revoked IS NULL
                """,
                (json.dumps(normalized, separators=(",", ":")), time.time(), owner_id, key_id),
            )
            if cur.rowcount != 1:
                raise StoreError("SSH key not found or revoked", 404)
        item = self.get(owner_id, key_id)
        assert item is not None
        return item

    def rename(self, owner_id: str, key_id: str, name: str) -> dict[str, object]:
        label = normalize_ssh_key_name(name)
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                UPDATE ssh_authorized_keys SET name = ?, updated = ?
                 WHERE owner_id = ? AND id = ? AND revoked IS NULL
                """,
                (label, time.time(), owner_id, key_id),
            )
            if cur.rowcount != 1:
                raise StoreError("SSH key not found or revoked", 404)
        item = self.get(owner_id, key_id)
        assert item is not None
        return item

    def set_expiry(self, owner_id: str, key_id: str, expires: int | None) -> dict[str, object]:
        if expires is not None and expires <= time.time():
            raise StoreError("SSH key expiry must be in the future", 400)
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                UPDATE ssh_authorized_keys SET expires = ?, updated = ?
                 WHERE owner_id = ? AND id = ? AND revoked IS NULL
                """,
                (expires, time.time(), owner_id, key_id),
            )
            if cur.rowcount != 1:
                raise StoreError("SSH key not found or revoked", 404)
        item = self.get(owner_id, key_id)
        assert item is not None
        return item

    def revoke(self, owner_id: str, key_id: str) -> dict[str, object]:
        now = time.time()
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                UPDATE ssh_authorized_keys SET revoked = ?, updated = ?
                 WHERE owner_id = ? AND id = ? AND revoked IS NULL
                """,
                (now, now, owner_id, key_id),
            )
            if cur.rowcount != 1:
                raise StoreError("SSH key not found or already revoked", 404)
        item = self.get(owner_id, key_id)
        assert item is not None
        return item

    def owner_name(self, owner_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT nc.display_name AS name
                  FROM profiles p
                  JOIN name_claims nc
                    ON nc.author_id = p.author_id
                   AND nc.name_key = p.primary_name_key
                 WHERE p.author_id = ?
                """,
                (owner_id,),
            ).fetchone()
        return str(row["name"]) if row is not None else None


def has_scope(item: dict[str, object], scope: str) -> bool:
    scopes = set(item.get("scopes") or ())
    return "admin" in scopes or scope in scopes


def _authorized_line(cfg: Config, item: dict[str, object]) -> str:
    command = cfg.ssh_shell_command.strip()
    if not command or any(char in command for char in '"\r\n'):
        raise StoreError("invalid ssh shell command configuration", 500)
    key_id = str(item["id"])
    return f'command="{command} --key-id {key_id}",restrict {item["public_key"]}'


def auth_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("key_type")
    parser.add_argument("key_data")
    args = parser.parse_args(argv)
    cfg = Config.load()
    store = SSHKeyStore(cfg)
    try:
        item = store.lookup(args.key_type, args.key_data)
        if item is None:
            return 1
        print(_authorized_line(cfg, item))
        return 0
    finally:
        store.close()


def _require_scope(item: dict[str, object], scope: str) -> None:
    if not has_scope(item, scope):
        raise StoreError(f"SSH key requires `{scope}` scope", 403)


def _repo_name_from_ssh_path(value: str) -> str:
    name = value.strip()
    while name.startswith("/"):
        name = name[1:]
    if name.startswith("repos/"):
        name = name[6:]
    if name.endswith(".git"):
        name = name[:-4]
    if not valid_repo_name(name):
        raise StoreError("invalid repository name", 400)
    return name


def _run_git_command(cfg: Config, item: dict[str, object], argv: list[str]) -> int | None:
    if len(argv) != 2 or argv[0] not in {"git-upload-pack", "git-receive-pack"}:
        return None
    service = RepoService(cfg)
    name = _repo_name_from_ssh_path(argv[1])
    receive = argv[0] == "git-receive-pack"
    _require_scope(item, "repo-write" if receive else "repo-read")
    if receive:
        path = service.ensure_repository(name)
    else:
        path = service._path(name)
        if not path.is_dir():
            raise StoreError("repository not found", 404)
    git = service._require_git()
    env = os.environ.copy()
    env["REMOTE_USER"] = str(item["owner_id"])
    result = subprocess.run(
        [git, "receive-pack" if receive else "upload-pack", str(path)],
        env=env,
        check=False,
    )
    return int(result.returncode)


def _local_get(cfg: Config, path: str) -> int:
    if not path.startswith("/") or path.startswith("//"):
        raise StoreError("path must be site-relative and begin with /", 400)
    url = f"{cfg.local_api_url}{path}"
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=cfg.internal_http_timeout_seconds) as response:
            sys.stdout.buffer.write(response.read())
        return 0
    except HTTPError as exc:
        sys.stdout.buffer.write(exc.read())
        return 1
    except URLError as exc:
        raise StoreError(f"local msgd request failed: {exc.reason}", 503) from exc


def _print_shell_help() -> None:
    print(
        "msg.lmm.best restricted SSH interface\n"
        "\n"
        "help\n"
        "whoami\n"
        "get PATH\n"
        "repos\n"
        "repo NAME\n"
        "keys\n"
        "keys add NAME SCOPES KEY_TYPE KEY_DATA\n"
        "keys scopes KEY_ID SCOPES\n"
        "keys revoke KEY_ID\n"
        "\n"
        "Git clients use git-upload-pack/git-receive-pack automatically.\n"
        "No operating-system shell or arbitrary command execution is provided."
    )


def _shell_keys(store: SSHKeyStore, item: dict[str, object], argv: list[str]) -> int:
    _require_scope(item, "keys")
    owner_id = str(item["owner_id"])
    if len(argv) == 1:
        print(json.dumps(store.list(owner_id), ensure_ascii=False, separators=(",", ":")))
        return 0
    if argv[1] == "add" and len(argv) == 6:
        scopes = (
            scopes_from_preset(argv[3]) if argv[3] in SSH_PRESETS else normalize_scopes(argv[3])
        )
        added = store.add(
            owner_id=owner_id,
            name=argv[2],
            scopes=scopes,
            public_key=f"{argv[4]} {argv[5]}",
            created_by=f"ssh:{item['id']}",
        )
        print(json.dumps(added, ensure_ascii=False, separators=(",", ":")))
        return 0
    if argv[1] == "scopes" and len(argv) == 4:
        scopes = (
            scopes_from_preset(argv[3]) if argv[3] in SSH_PRESETS else normalize_scopes(argv[3])
        )
        updated = store.set_scopes(owner_id, argv[2], scopes)
        print(json.dumps(updated, ensure_ascii=False, separators=(",", ":")))
        return 0
    if argv[1] == "revoke" and len(argv) == 3:
        revoked = store.revoke(owner_id, argv[2])
        print(json.dumps(revoked, ensure_ascii=False, separators=(",", ":")))
        return 0
    raise StoreError("invalid keys command; run `help`", 400)


def shell_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--key-id", required=True)
    args = parser.parse_args(argv)
    cfg = Config.load()
    store = SSHKeyStore(cfg)
    try:
        item = store.lookup_id(args.key_id)
        if item is None:
            print("SSH credential is revoked, expired, or unknown", file=sys.stderr)
            return 1
        store.touch(args.key_id)
        original = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
        if not original:
            _print_shell_help()
            return 0
        try:
            command = shlex.split(original, posix=True)
        except ValueError as exc:
            raise StoreError("invalid SSH command syntax", 400) from exc
        if not command:
            _print_shell_help()
            return 0

        git_status = _run_git_command(cfg, item, command)
        if git_status is not None:
            return git_status

        verb = command[0]
        if verb == "help" and len(command) == 1:
            _print_shell_help()
            return 0
        if verb == "whoami" and len(command) == 1:
            name = store.owner_name(str(item["owner_id"]))
            print(f"account=@{name}" if name else f"account_id={item['owner_id']}")
            print(f"credential={item['name']}")
            print(f"fingerprint={item['fingerprint']}")
            print("scopes=" + ",".join(item["scopes"]))
            return 0
        if verb in {"get", "cat"} and len(command) == 2:
            _require_scope(item, "read")
            return _local_get(cfg, command[1])
        if verb == "repos" and len(command) == 1:
            _require_scope(item, "repo-read")
            print(
                json.dumps(
                    RepoService(cfg).list_repositories(),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
            return 0
        if verb == "repo" and len(command) == 2:
            _require_scope(item, "repo-read")
            print(
                json.dumps(
                    RepoService(cfg).repository_info(command[1]),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
            return 0
        if verb == "keys":
            return _shell_keys(store, item, command)
        raise StoreError("command is not available in the restricted SSH interface", 403)
    except StoreError as exc:
        print(f"msg-ssh: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(shell_main())
