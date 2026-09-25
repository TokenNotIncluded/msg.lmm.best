"""SQLite current-state store with optional certificate-controlled identities."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from msgd.config import Config
from msgd.crypto import (
    ACTIONS,
    Certificate,
    SignatureError,
    SignedRequest,
    canonical_json,
    certificate_payload,
    parse_certificate,
    public_identity,
    verify_detached,
)
from msgd.search import SearchSpec

BOARD_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
AUTHOR_ID_RE = re.compile(r"^[0-9a-f]{64}$")
MENTION_RE = re.compile(r"(?<![A-Za-z0-9._-])@([A-Za-z0-9][A-Za-z0-9._-]{0,63})(?![A-Za-z0-9._-])")

ANONYMOUS_PERMISSION_BITS = {
    "post.create": 1,
    "post.edit.any": 2,
    "post.delete.any": 4,
}
ANONYMOUS_PERMISSION_MASK = sum(ANONYMOUS_PERMISSION_BITS.values())
DEFAULT_ANONYMOUS = frozenset(ANONYMOUS_PERMISSION_BITS)


def anonymous_permission_mask(actions: Iterable[str]) -> int:
    current = set(actions)
    return sum(bit for action, bit in ANONYMOUS_PERMISSION_BITS.items() if action in current)


def anonymous_actions(mask: int) -> tuple[str, ...]:
    if mask < 0 or mask & ~ANONYMOUS_PERMISSION_MASK:
        raise ValueError(f"anonymous permission mask must be 0..{ANONYMOUS_PERMISSION_MASK}")
    return tuple(action for action, bit in ANONYMOUS_PERMISSION_BITS.items() if mask & bit)


RESERVED_BOARDS = {
    "rules",
    "_rules",
    "_help",
    "_schema",
    "_health",
    "_search",
    "_signing",
    "_ca",
    "_cert",
    "_csr",
    "_revoke",
    "_policy",
    "_revocations",
    "publish",
    "inbox",
    "file",
    "key",
    "llms.txt",
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
}
DEFAULT_BOARDS = {
    "main": "General discussion.",
    "meta": "Talk about this board.",
    "guest": "GET-only escape hatch. Anonymous and intentionally low-trust.",
    "custody": "GET-only custodial identities. Server holds signing keys; low assurance.",
    "ca": "Public CA audit log. Authority: /_csr, /_cert, /_revocations.",
}

TABLES = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS boards (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    board       TEXT NOT NULL REFERENCES boards(name) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    name        TEXT NOT NULL DEFAULT 'anonymous',
    title       TEXT NOT NULL DEFAULT '',
    body        TEXT NOT NULL,
    created     REAL NOT NULL,
    updated     REAL NOT NULL,
    nbytes      INTEGER NOT NULL,
    author_key  TEXT,
    author_id   TEXT,
    actor_key   TEXT,
    actor_id    TEXT,
    signature   TEXT,
    sig_version INTEGER NOT NULL DEFAULT 0,
    sig_nonce   TEXT,
    sig_issued  INTEGER,
    reply_to    INTEGER,
    system      INTEGER NOT NULL DEFAULT 0,
    custody_id  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS posts_board_seq ON posts(board, seq);
CREATE INDEX IF NOT EXISTS posts_board_id ON posts(board, id);
CREATE INDEX IF NOT EXISTS posts_created ON posts(id);

CREATE TABLE IF NOT EXISTS attachments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id      INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    slot         INTEGER NOT NULL,
    name         TEXT NOT NULL,
    content_type TEXT NOT NULL,
    data         BLOB NOT NULL,
    nbytes       INTEGER NOT NULL,
    sha256       TEXT NOT NULL,
    UNIQUE(post_id, slot)
);
CREATE INDEX IF NOT EXISTS attachments_post ON attachments(post_id);

CREATE TABLE IF NOT EXISTS signature_nonces (
    signer_id TEXT NOT NULL,
    nonce     TEXT NOT NULL,
    issued    INTEGER NOT NULL,
    PRIMARY KEY(signer_id, nonce)
);

CREATE TABLE IF NOT EXISTS custody_identities (
    id          TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    author_id   TEXT NOT NULL UNIQUE,
    key_nonce      BLOB NOT NULL,
    key_ciphertext BLOB NOT NULL,
    created         REAL NOT NULL,
    last_used   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS custody_author_id ON custody_identities(author_id);

CREATE TABLE IF NOT EXISTS certificates (
    serial        TEXT PRIMARY KEY,
    issuer_serial TEXT NOT NULL,
    issuer_id     TEXT NOT NULL,
    subject_id    TEXT NOT NULL,
    subject_key   TEXT NOT NULL,
    body          TEXT NOT NULL,
    signature     TEXT NOT NULL,
    created       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS certificates_subject ON certificates(subject_id);

CREATE TABLE IF NOT EXISTS identity_names (
    author_id  TEXT NOT NULL,
    name       TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL,
    PRIMARY KEY(author_id, name)
);
CREATE INDEX IF NOT EXISTS identity_names_author_last
    ON identity_names(author_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS revocations (
    serial     TEXT PRIMARY KEY REFERENCES certificates(serial) ON DELETE CASCADE,
    revoked_at REAL NOT NULL,
    revoked_by TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS certificate_requests (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_key      TEXT NOT NULL,
    subject_id       TEXT NOT NULL,
    requested_issuer TEXT NOT NULL DEFAULT '',
    grants           TEXT NOT NULL,
    delegate         INTEGER NOT NULL DEFAULT 0,
    message          TEXT NOT NULL DEFAULT '',
    created          REAL NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    decided          REAL,
    decision_by      TEXT NOT NULL DEFAULT '',
    reason           TEXT NOT NULL DEFAULT '',
    certificate_serial TEXT
);
CREATE INDEX IF NOT EXISTS csr_status_id
    ON certificate_requests(status, id);
CREATE INDEX IF NOT EXISTS csr_subject_id
    ON certificate_requests(subject_id, id);

CREATE TABLE IF NOT EXISTS topic_policies (
    board     TEXT PRIMARY KEY,
    anonymous TEXT NOT NULL,
    version   INTEGER NOT NULL,
    updated   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS inbox_events (
    post_id    INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    subject_id TEXT NOT NULL,
    kind       TEXT NOT NULL,
    PRIMARY KEY(post_id, subject_id, kind)
);
CREATE INDEX IF NOT EXISTS inbox_subject_post
    ON inbox_events(subject_id, post_id);
"""


class StoreError(Exception):
    def __init__(self, message: str, status: int = 400, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.hint = hint


@dataclass(frozen=True)
class FileInput:
    name: str
    content_type: str
    data: bytes
    sha256: str

    @property
    def nbytes(self) -> int:
        return len(self.data)

    def manifest(self) -> dict[str, object]:
        return {
            "name": self.name,
            "type": self.content_type,
            "bytes": self.nbytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class Attachment:
    id: int
    post_id: int
    slot: int
    name: str
    content_type: str
    data: bytes
    nbytes: int
    sha256: str

    def manifest(self) -> dict[str, object]:
        return {
            "name": self.name,
            "type": self.content_type,
            "bytes": self.nbytes,
            "sha256": self.sha256,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "slot": self.slot,
            **self.manifest(),
            "url": f"/file/{self.id}",
        }


@dataclass
class Post:
    id: int
    board: str
    seq: int
    name: str
    title: str
    body: str
    created: float
    updated: float
    nbytes: int
    author_key: str | None = None
    author_id: str | None = None
    actor_key: str | None = None
    actor_id: str | None = None
    signature: str | None = None
    sig_version: int = 0
    sig_nonce: str | None = None
    sig_issued: int | None = None
    reply_to: int | None = None
    system: bool = False
    custody_id: str | None = None

    @property
    def signed(self) -> bool:
        return self.author_id is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "board": self.board,
            "seq": self.seq,
            "name": self.name,
            "title": self.title,
            "body": self.body,
            "created": round(self.created, 3),
            "updated": round(self.updated, 3),
            "bytes": self.nbytes,
            "auth": "signed" if self.signed else "unsigned",
            "author_id": self.author_id,
            "author_key": self.author_key,
            "actor_id": self.actor_id,
            "actor_key": self.actor_key,
            "signature": self.signature,
            "sig_version": self.sig_version if self.signed else None,
            "sig_action": (
                "post.create"
                if self.signed and self.sig_version == 1
                else "post.edit"
                if self.signed
                else None
            ),
            "sig_nonce": self.sig_nonce if self.signed and self.sig_version == 1 else None,
            "sig_issued": self.sig_issued if self.signed and self.sig_version == 1 else None,
            "reply_to": self.reply_to,
            "system": self.system,
            "custodial": self.custody_id is not None,
        }


def valid_board_name(name: str) -> bool:
    return bool(BOARD_RE.fullmatch(name)) and name not in RESERVED_BOARDS


def valid_author_id(value: str) -> bool:
    return bool(AUTHOR_ID_RE.fullmatch(value))


def _normalise(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


class Store:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._lock = threading.RLock()
        path = Path(cfg.database)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(path), check_same_thread=False, isolation_level=None, timeout=15.0
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            had_inbox = (
                self._conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='inbox_events'"
                ).fetchone()
                is not None
            )
            self._conn.executescript(TABLES)
            self._ensure_schema()
            for name, description in DEFAULT_BOARDS.items():
                self._ensure_board(name, description)
            for name in ("guest", "custody", "ca"):
                self._conn.execute(
                    "UPDATE boards SET description = ? WHERE name = ?",
                    (DEFAULT_BOARDS[name], name),
                )
            if not had_inbox:
                self._rebuild_inbox()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _ensure_schema(self) -> None:
        columns = {
            str(row["name"]) for row in self._conn.execute("PRAGMA table_info(posts)").fetchall()
        }
        additions = {
            "author_key": "TEXT",
            "author_id": "TEXT",
            "actor_key": "TEXT",
            "actor_id": "TEXT",
            "signature": "TEXT",
            "sig_version": "INTEGER NOT NULL DEFAULT 0",
            "sig_nonce": "TEXT",
            "sig_issued": "INTEGER",
            "reply_to": "INTEGER",
            "system": "INTEGER NOT NULL DEFAULT 0",
            "custody_id": "TEXT",
        }
        for name, definition in additions.items():
            if name not in columns:
                self._conn.execute(f"ALTER TABLE posts ADD COLUMN {name} {definition}")

        revocation_columns = {
            str(row["name"])
            for row in self._conn.execute("PRAGMA table_info(revocations)").fetchall()
        }
        if revocation_columns and "reason" not in revocation_columns:
            self._conn.execute("ALTER TABLE revocations ADD COLUMN reason TEXT NOT NULL DEFAULT ''")

        self._conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS posts_author_id ON posts(author_id);
            CREATE INDEX IF NOT EXISTS posts_reply_to ON posts(reply_to);
            CREATE TABLE IF NOT EXISTS signature_nonces (
                signer_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                issued INTEGER NOT NULL,
                PRIMARY KEY(signer_id, nonce)
            );
            CREATE TABLE IF NOT EXISTS custody_identities (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                author_id TEXT NOT NULL UNIQUE,
                key_nonce BLOB NOT NULL,
                key_ciphertext BLOB NOT NULL,
                created REAL NOT NULL,
                last_used REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS custody_author_id
                ON custody_identities(author_id);
            CREATE TABLE IF NOT EXISTS certificates (
                serial TEXT PRIMARY KEY,
                issuer_serial TEXT NOT NULL,
                issuer_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                body TEXT NOT NULL,
                signature TEXT NOT NULL,
                created REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS certificates_subject ON certificates(subject_id);
            CREATE TABLE IF NOT EXISTS identity_names (
                author_id TEXT NOT NULL,
                name TEXT NOT NULL,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                PRIMARY KEY(author_id, name)
            );
            CREATE INDEX IF NOT EXISTS identity_names_author_last
                ON identity_names(author_id, last_seen DESC);
            CREATE TABLE IF NOT EXISTS revocations (
                serial TEXT PRIMARY KEY REFERENCES certificates(serial) ON DELETE CASCADE,
                revoked_at REAL NOT NULL,
                revoked_by TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS certificate_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_key TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                requested_issuer TEXT NOT NULL DEFAULT '',
                grants TEXT NOT NULL,
                delegate INTEGER NOT NULL DEFAULT 0,
                message TEXT NOT NULL DEFAULT '',
                created REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                decided REAL,
                decision_by TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                certificate_serial TEXT
            );
            CREATE INDEX IF NOT EXISTS csr_status_id
                ON certificate_requests(status, id);
            CREATE INDEX IF NOT EXISTS csr_subject_id
                ON certificate_requests(subject_id, id);
            CREATE TABLE IF NOT EXISTS topic_policies (
                board TEXT PRIMARY KEY,
                anonymous TEXT NOT NULL,
                version INTEGER NOT NULL,
                updated REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS inbox_events (
                post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                subject_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                PRIMARY KEY(post_id, subject_id, kind)
            );
            CREATE INDEX IF NOT EXISTS inbox_subject_post
                ON inbox_events(subject_id, post_id);
            """
        )
        self._conn.execute(
            """
            INSERT INTO identity_names(author_id, name, first_seen, last_seen)
            SELECT author_id, name, MIN(created), MAX(updated)
              FROM posts
             WHERE author_id IS NOT NULL AND actor_id = author_id
             GROUP BY author_id, name
            ON CONFLICT(author_id, name) DO UPDATE SET
                first_seen = MIN(identity_names.first_seen, excluded.first_seen),
                last_seen = MAX(identity_names.last_seen, excluded.last_seen)
            """
        )

    def _rebuild_inbox(self) -> None:
        self._conn.execute("DELETE FROM inbox_events")
        rows = self._conn.execute("SELECT id FROM posts ORDER BY id").fetchall()
        for row in rows:
            self._reindex_inbox(int(row["id"]))

    def root_info(self) -> dict[str, str] | None:
        try:
            key = Path(self.cfg.root_public_key).read_text(encoding="utf-8").strip()
            canonical, root_id = public_identity(key)
        except OSError, SignatureError:
            return None
        return {
            "algorithm": "ed25519",
            "public_key": canonical,
            "root_id": root_id,
        }

    def prepare_post(
        self,
        *,
        body: str,
        title: str,
        name: str,
        max_body_bytes: int | None = None,
    ) -> tuple[str, str, str, int]:
        body = _normalise(body)
        title = " ".join(title.split())
        name = " ".join(name.split()) or "anonymous"
        if not body.strip():
            raise StoreError("text is empty", 400)
        nbytes = len(body.encode("utf-8"))
        limit = self.cfg.max_post_bytes if max_body_bytes is None else max_body_bytes
        if nbytes > limit:
            raise StoreError(f"text exceeds max_post_bytes={limit}", 413)
        if len(title.encode("utf-8")) > self.cfg.max_title_bytes:
            raise StoreError(f"title exceeds max_title_bytes={self.cfg.max_title_bytes}", 413)
        if len(name.encode("utf-8")) > self.cfg.max_name_bytes:
            raise StoreError(f"name exceeds max_name_bytes={self.cfg.max_name_bytes}", 413)
        if nbytes > self.cfg.max_storage_bytes:
            raise StoreError("post is larger than the whole storage capacity", 507)
        return body, title, name, nbytes

    def prepare_files(self, files: tuple[FileInput, ...]) -> tuple[FileInput, ...]:
        if len(files) > self.cfg.max_files_per_post:
            raise StoreError(
                f"too many files; max_files_per_post={self.cfg.max_files_per_post}",
                413,
            )
        total = 0
        for file in files:
            if not file.name or len(file.name.encode("utf-8")) > self.cfg.max_filename_bytes:
                raise StoreError("invalid or too-long file name", 413)
            if len(file.content_type.encode("utf-8")) > 200:
                raise StoreError("file content type is too long", 413)
            if file.nbytes > self.cfg.max_file_bytes:
                raise StoreError(
                    f"file exceeds max_file_bytes={self.cfg.max_file_bytes}",
                    413,
                )
            if hashlib.sha256(file.data).hexdigest() != file.sha256:
                raise StoreError("file sha256 mismatch", 400)
            total += file.nbytes
        if total > self.cfg.max_storage_bytes:
            raise StoreError("attachments exceed the whole storage capacity", 507)
        return files

    def attachments(self, post_id: int) -> list[Attachment]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, post_id, slot, name, content_type, data, nbytes, sha256
                  FROM attachments
                 WHERE post_id = ?
                 ORDER BY slot
                """,
                (post_id,),
            ).fetchall()
        return [self._attachment(row) for row in rows]

    def attachment(self, file_id: int) -> Attachment | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, post_id, slot, name, content_type, data, nbytes, sha256
                  FROM attachments
                 WHERE id = ?
                """,
                (file_id,),
            ).fetchone()
        return self._attachment(row) if row else None

    def attachment_manifest(self, post_id: int) -> tuple[dict[str, object], ...]:
        return tuple(file.manifest() for file in self.attachments(post_id))

    def _storage_bytes(self) -> int:
        row = self._conn.execute(
            """
            SELECT
                COALESCE((SELECT SUM(nbytes) FROM posts WHERE system = 0), 0)
              + COALESCE((SELECT SUM(nbytes) FROM attachments), 0) AS n
            """
        ).fetchone()
        return int(row["n"])

    def _post_storage_bytes(self, post_id: int) -> int:
        row = self._conn.execute(
            """
            SELECT p.nbytes + COALESCE(SUM(a.nbytes), 0) AS n
              FROM posts p
              LEFT JOIN attachments a ON a.post_id = p.id
             WHERE p.id = ?
             GROUP BY p.id
            """,
            (post_id,),
        ).fetchone()
        return int(row["n"]) if row else 0

    def _insert_attachments(self, post_id: int, files: tuple[FileInput, ...]) -> None:
        for slot, file in enumerate(files):
            self._conn.execute(
                """
                INSERT INTO attachments(
                    post_id, slot, name, content_type, data, nbytes, sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    post_id,
                    slot,
                    file.name,
                    file.content_type,
                    file.data,
                    file.nbytes,
                    file.sha256,
                ),
            )

    def _ensure_board(self, name: str, description: str = "") -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO boards(name, description, created) VALUES (?, ?, ?)",
            (name, description, time.time()),
        )

    def ensure_board(self, name: str) -> None:
        if not valid_board_name(name):
            raise StoreError(f"invalid board name: {name!r}", 400)
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM boards WHERE name = ?", (name,)).fetchone()
            if row is None:
                count = self._conn.execute("SELECT COUNT(*) AS n FROM boards").fetchone()["n"]
                if count >= self.cfg.max_boards:
                    raise StoreError("board limit reached", 507)
                self._ensure_board(name)

    def list_boards(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT b.name, b.description, COUNT(p.id) AS posts,
                       COALESCE(MAX(p.updated), 0) AS last_ts
                  FROM boards b
                  LEFT JOIN posts p ON p.board = b.name
                 GROUP BY b.name
                 ORDER BY b.name
                """
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["permissions"] = self.policy(str(row["name"]))["permissions"]
            result.append(item)
        return result

    def board_info(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT name, description, created FROM boards WHERE name = ?", (name,)
            ).fetchone()
        return dict(row) if row else None

    def policy(self, board: str) -> dict[str, Any]:
        if board in {"ca", "custody"}:
            return {
                "board": board,
                "permissions": 0,
                "anonymous": [],
                "version": 0,
                "updated": None,
                "locked": True,
            }
        if board == "guest":
            actions = sorted(DEFAULT_ANONYMOUS)
            return {
                "board": "guest",
                "permissions": anonymous_permission_mask(actions),
                "anonymous": actions,
                "version": 0,
                "updated": None,
                "locked": True,
            }
        with self._lock:
            row = self._conn.execute(
                "SELECT anonymous, version, updated FROM topic_policies WHERE board = ?",
                (board,),
            ).fetchone()
        if row is None:
            actions = [] if board == "ca" else sorted(DEFAULT_ANONYMOUS)
            return {
                "board": board,
                "permissions": anonymous_permission_mask(actions),
                "anonymous": actions,
                "version": 0,
                "updated": None,
                "locked": False,
            }
        actions = json.loads(str(row["anonymous"]))
        return {
            "board": board,
            "permissions": anonymous_permission_mask(actions),
            "anonymous": actions,
            "version": int(row["version"]),
            "updated": float(row["updated"]),
            "locked": False,
        }

    def set_policy(self, board: str, anonymous: tuple[str, ...], version: int) -> dict[str, Any]:
        if board in {"ca", "custody", "guest"}:
            raise StoreError(f"/{board} policy is system-managed", 403)
        if not valid_board_name(board):
            raise StoreError(f"invalid board name: {board!r}", 400)
        invalid = set(anonymous) - DEFAULT_ANONYMOUS
        if invalid:
            raise StoreError(f"invalid anonymous actions: {sorted(invalid)}", 400)
        current = self.policy(board)
        if version != int(current["version"]) + 1:
            raise StoreError("stale policy version", 409)
        self.ensure_board(board)
        values = sorted(set(anonymous))
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO topic_policies(board, anonymous, version, updated)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(board) DO UPDATE SET
                    anonymous = excluded.anonymous,
                    version = excluded.version,
                    updated = excluded.updated
                """,
                (board, json.dumps(values, separators=(",", ":")), version, now),
            )
        return self.policy(board)

    def anonymous_allowed(self, board: str, action: str, *, signed_target: bool = False) -> bool:
        if signed_target:
            return False
        return action in set(self.policy(board)["anonymous"])

    @staticmethod
    def _grant_list(
        grants: dict[str, tuple[str, ...] | list[str] | set[str]],
    ) -> list[dict[str, object]]:
        if not grants:
            raise StoreError("certificate grants are required", 400)
        result: list[dict[str, object]] = []
        for topic, actions in sorted(grants.items()):
            if topic != "*" and not BOARD_RE.fullmatch(topic):
                raise StoreError(f"invalid grant topic: {topic!r}", 400)
            normalized = sorted(set(actions))
            if not normalized:
                raise StoreError("grant actions are required", 400)
            invalid = set(normalized) - ACTIONS
            if invalid:
                raise StoreError(f"invalid grant actions: {sorted(invalid)}", 400)
            result.append({"topic": topic, "actions": normalized})
        return result

    @staticmethod
    def _grant_map(value: object) -> dict[str, set[str]]:
        if not isinstance(value, list):
            raise StoreError("invalid stored grants", 500)
        result: dict[str, set[str]] = {}
        for item in value:
            if not isinstance(item, dict):
                raise StoreError("invalid stored grant", 500)
            topic = item.get("topic")
            actions = item.get("actions")
            if not isinstance(topic, str) or not isinstance(actions, list):
                raise StoreError("invalid stored grant", 500)
            result[topic] = {str(action) for action in actions}
        return result

    def _create_system_post(self, title: str, body: str) -> Post:
        board = "ca"
        body = _normalise(body)
        title = " ".join(title.split())
        name = "ca-audit"
        if not body.strip():
            raise StoreError("system audit body is empty", 500)
        nbytes = len(body.encode("utf-8"))
        if nbytes > self.cfg.max_post_bytes_post:
            raise StoreError("system audit body is too large", 500)
        if len(title.encode("utf-8")) > self.cfg.max_title_bytes:
            raise StoreError("system audit title is too large", 500)
        self.ensure_board(board)
        now = time.time()
        with self._lock, self._conn:
            seq = int(
                self._conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM posts WHERE board = ?",
                    (board,),
                ).fetchone()["n"]
            )
            cur = self._conn.execute(
                """
                INSERT INTO posts(
                    board, seq, name, title, body, created, updated, nbytes,
                    system
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (board, seq, name, title, body, now, now, nbytes),
            )
            post_id = int(cur.lastrowid or 0)
        post = self.get_post(post_id)
        if post is None:
            raise StoreError("failed to create CA audit post", 500)
        return post

    def _audit_ca(self, kind: str, title: str, lines: list[str]) -> None:
        body = "\n".join([f"type={kind}", *lines, "authority=/_csr /_cert /_revocations"])
        self._create_system_post(title, body)

    def create_csr(
        self,
        *,
        auth: SignedRequest,
        grants: dict[str, tuple[str, ...]],
        delegate: bool,
        requested_issuer: str,
        message: str,
    ) -> dict[str, Any]:
        if requested_issuer and not valid_author_id(requested_issuer):
            raise StoreError("requested_issuer must be an author id", 400)
        if len(message.encode("utf-8")) > 4096:
            raise StoreError("CSR message exceeds 4096 bytes", 413)
        grant_list = self._grant_list(grants)
        self.consume_nonce(auth)
        now = time.time()
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO certificate_requests(
                    subject_key, subject_id, requested_issuer, grants,
                    delegate, message, created, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
                """,
                (
                    auth.public_key,
                    auth.signer_id,
                    requested_issuer,
                    canonical_json(grant_list),
                    1 if delegate else 0,
                    message,
                    now,
                ),
            )
            csr_id = int(cur.lastrowid or 0)
        csr = self.csr(csr_id)
        if csr is None:
            raise StoreError("failed to create CSR", 500)
        self._audit_ca(
            "request",
            f"[REQUEST] CSR #{csr_id}",
            [
                f"csr=/_csr?id={csr_id}",
                f"subject={auth.signer_id}",
                f"requested_issuer={requested_issuer or 'any'}",
                f"delegate={str(delegate).lower()}",
                f"grants={canonical_json(grant_list)}",
                *([f"message={message[:300]}"] if message else []),
            ],
        )
        return csr

    def csr(self, csr_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, subject_key, subject_id, requested_issuer, grants,
                       delegate, message, created, status, decided, decision_by,
                       reason, certificate_serial
                  FROM certificate_requests
                 WHERE id = ?
                """,
                (csr_id,),
            ).fetchone()
        return self._csr_row(row)

    def list_csrs(
        self,
        *,
        status: str | None = None,
        subject_id: str | None = None,
        requested_issuer: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if status:
            if status not in {"pending", "issued", "rejected", "cancelled"}:
                raise StoreError("invalid CSR status", 400)
            where.append("status = ?")
            params.append(status)
        if subject_id:
            if not valid_author_id(subject_id):
                raise StoreError("invalid subject id", 400)
            where.append("subject_id = ?")
            params.append(subject_id)
        if requested_issuer:
            if not valid_author_id(requested_issuer):
                raise StoreError("invalid requested issuer", 400)
            where.append("requested_issuer = ?")
            params.append(requested_issuer)
        sql = (
            "SELECT id, subject_key, subject_id, requested_issuer, grants, delegate,"
            " message, created, status, decided, decision_by, reason,"
            " certificate_serial FROM certificate_requests"
        )
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, self.cfg.max_limit)))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._csr_row(row) for row in rows if row is not None]

    def can_issue_csr(self, signer_id: str, csr: dict[str, Any]) -> bool:
        root = self.root_info()
        if root is not None and signer_id == root["root_id"]:
            return True
        if csr["requested_issuer"] and csr["requested_issuer"] != signer_id:
            return False
        grants = self._grant_map(csr["grants"])
        return all("cert.issue" in self.permissions_for(signer_id, topic) for topic in grants)

    def cancel_csr(self, csr_id: int, signer_id: str, reason: str = "") -> dict[str, Any]:
        csr = self.csr(csr_id)
        if csr is None:
            raise StoreError("CSR not found", 404)
        if csr["status"] != "pending":
            raise StoreError("CSR is not pending", 409)
        if csr["subject_id"] != signer_id:
            raise StoreError("only the CSR subject may cancel it", 403)
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE certificate_requests
                   SET status='cancelled', decided=?, decision_by=?, reason=?
                 WHERE id=? AND status='pending'
                """,
                (now, signer_id, reason[:500], csr_id),
            )
        result = self.csr(csr_id)
        assert result is not None
        self._audit_ca(
            "cancelled",
            f"[CANCELLED] CSR #{csr_id}",
            [f"csr=/_csr?id={csr_id}", f"subject={csr['subject_id']}", f"reason={reason[:300]}"],
        )
        return result

    def reject_csr(self, csr_id: int, signer_id: str, reason: str = "") -> dict[str, Any]:
        csr = self.csr(csr_id)
        if csr is None:
            raise StoreError("CSR not found", 404)
        if csr["status"] != "pending":
            raise StoreError("CSR is not pending", 409)
        if not self.can_issue_csr(signer_id, csr):
            raise StoreError("not allowed to decide this CSR", 403)
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE certificate_requests
                   SET status='rejected', decided=?, decision_by=?, reason=?
                 WHERE id=? AND status='pending'
                """,
                (now, signer_id, reason[:500], csr_id),
            )
        result = self.csr(csr_id)
        assert result is not None
        self._audit_ca(
            "rejected",
            f"[REJECTED] CSR #{csr_id}",
            [
                f"csr=/_csr?id={csr_id}",
                f"subject={csr['subject_id']}",
                f"by={signer_id}",
                f"reason={reason[:300]}",
            ],
        )
        return result

    def _validate_csr_certificate(self, csr: dict[str, Any], cert: Certificate) -> None:
        if csr["status"] != "pending":
            raise StoreError("CSR is not pending", 409)
        if cert.subject_id != csr["subject_id"] or cert.subject_key != csr["subject_key"]:
            raise StoreError("certificate subject does not match CSR", 403)
        if csr["requested_issuer"] and cert.issuer_id != csr["requested_issuer"]:
            raise StoreError("certificate issuer does not match requested issuer", 403)
        if cert.delegate and not csr["delegate"]:
            raise StoreError("certificate delegation exceeds CSR", 403)
        requested = self._grant_map(csr["grants"])
        for topic, actions in cert.grants.items():
            allowed = set(requested.get("*", set()))
            if topic != "*":
                allowed.update(requested.get(topic, set()))
            if not set(actions).issubset(allowed):
                raise StoreError(f"certificate grants exceed CSR for topic {topic}", 403)

    @staticmethod
    def _csr_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return {
            "id": int(row["id"]),
            "subject_key": str(row["subject_key"]),
            "subject_id": str(row["subject_id"]),
            "requested_issuer": str(row["requested_issuer"] or ""),
            "grants": json.loads(str(row["grants"])),
            "delegate": bool(row["delegate"]),
            "message": str(row["message"]),
            "created": round(float(row["created"]), 3),
            "status": str(row["status"]),
            "decided": round(float(row["decided"]), 3) if row["decided"] is not None else None,
            "decision_by": str(row["decision_by"] or ""),
            "reason": str(row["reason"] or ""),
            "certificate_serial": (
                str(row["certificate_serial"]) if row["certificate_serial"] is not None else None
            ),
        }

    def register_certificate(
        self,
        body: str,
        signature: str,
        *,
        csr_id: int | None = None,
    ) -> Certificate:
        try:
            cert = parse_certificate(body)
        except SignatureError as exc:
            raise StoreError(str(exc), 400) from exc

        existing = self.certificate(cert.serial)
        if existing is not None:
            if existing["body"] == cert.body and existing["signature"] == signature:
                return cert
            raise StoreError("certificate serial already exists", 409)

        csr = None
        if csr_id is not None:
            csr = self.csr(csr_id)
            if csr is None:
                raise StoreError("CSR not found", 404)
            self._validate_csr_certificate(csr, cert)

        root = self.root_info()
        if root is None:
            raise StoreError("root CA is not initialized", 503)

        if cert.issuer_serial == "root":
            if cert.issuer_id != root["root_id"]:
                raise StoreError("certificate issuer is not the root CA", 403)
            issuer_key = root["public_key"]
        else:
            parent_info = self.certificate(cert.issuer_serial)
            if parent_info is None:
                raise StoreError("issuer certificate not found", 404)
            if not self.certificate_active(cert.issuer_serial):
                raise StoreError("issuer certificate is not active", 403)
            parent = parse_certificate(str(parent_info["body"]))
            if cert.issuer_id != parent.subject_id:
                raise StoreError("issuer id does not match issuer certificate", 403)
            if not parent.delegate:
                raise StoreError("issuer certificate cannot delegate", 403)
            self._check_delegation(parent, cert)
            issuer_key = parent.subject_key

        try:
            _, _, canonical_sig = verify_detached(
                issuer_key,
                signature,
                certificate_payload(cert.body),
            )
        except SignatureError as exc:
            raise StoreError(str(exc), 403) from exc

        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO certificates(
                    serial, issuer_serial, issuer_id, subject_id, subject_key,
                    body, signature, created
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cert.serial,
                    cert.issuer_serial,
                    cert.issuer_id,
                    cert.subject_id,
                    cert.subject_key,
                    cert.body,
                    canonical_sig,
                    now,
                ),
            )
            if csr is not None:
                cur = self._conn.execute(
                    """
                    UPDATE certificate_requests
                       SET status='issued', decided=?, decision_by=?,
                           certificate_serial=?
                     WHERE id=? AND status='pending'
                    """,
                    (now, cert.issuer_id, cert.serial, csr_id),
                )
                if cur.rowcount != 1:
                    raise StoreError("CSR changed while issuing", 409)

        self._audit_ca(
            "issued",
            f"[ISSUED] {cert.serial[:12]}",
            [
                *([f"csr=/_csr?id={csr_id}"] if csr_id is not None else []),
                f"certificate=/_cert?serial={cert.serial}",
                f"subject={cert.subject_id}",
                f"issuer={cert.issuer_id}",
                f"delegate={str(cert.delegate).lower()}",
                f"grants={canonical_json(self._grant_list(cert.grants))}",
            ],
        )
        return cert

    def certificate(self, serial: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT serial, issuer_serial, issuer_id, subject_id, subject_key,
                       body, signature, created
                  FROM certificates WHERE serial = ?
                """,
                (serial,),
            ).fetchone()
        return dict(row) if row else None

    def certificates_for(self, subject_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT serial, issuer_serial, issuer_id, subject_id, subject_key,
                       body, signature, created
                  FROM certificates
                 WHERE subject_id = ?
                 ORDER BY created ASC
                """,
                (subject_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_certificates(
        self,
        *,
        issuer_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        where = ""
        params: list[Any] = []
        if issuer_id:
            if not valid_author_id(issuer_id):
                raise StoreError("invalid issuer id", 400)
            where = " WHERE issuer_id = ?"
            params.append(issuer_id)
        params.append(max(1, min(limit, self.cfg.max_limit)))
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT serial, issuer_serial, issuer_id, subject_id, subject_key,
                       body, signature, created
                  FROM certificates
                """
                + where
                + " ORDER BY created DESC LIMIT ?",
                params,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["active"] = self.certificate_active(str(row["serial"]))
            result.append(item)
        return result

    def certificate_active(self, serial: str, *, now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        try:
            return self._validate_chain(serial, now=now, seen=set(), depth=0)
        except StoreError, SignatureError:
            return False

    def certificate_chain(self, serial: str) -> list[dict[str, Any]]:
        """Return the currently valid chain from Root to *serial*."""
        if not self.certificate_active(serial):
            return []
        root = self.root_info()
        if root is None:
            return []

        chain: list[dict[str, Any]] = []
        current = serial
        seen: set[str] = set()
        while current != "root":
            if current in seen or len(seen) >= 8:
                return []
            seen.add(current)
            row = self.certificate(current)
            if row is None:
                return []
            try:
                cert = parse_certificate(str(row["body"]))
            except SignatureError:
                return []
            chain.append(
                {
                    "serial": cert.serial,
                    "subject_id": cert.subject_id,
                    "issuer_id": cert.issuer_id,
                    "delegate": cert.delegate,
                    "not_before": cert.not_before,
                    "not_after": cert.not_after,
                }
            )
            current = cert.issuer_serial

        chain.append(
            {
                "serial": "root",
                "subject_id": root["root_id"],
                "issuer_id": None,
                "delegate": True,
                "not_before": None,
                "not_after": None,
            }
        )
        chain.reverse()
        return chain

    def certification(self, subject_id: str) -> dict[str, Any]:
        """Return server-derived certificate state for an identity."""
        root = self.root_info()
        if root is not None and subject_id == root["root_id"]:
            return {
                "status": "root",
                "certified": True,
                "role": "root",
                "active_certificates": 0,
                "certificate_count": 0,
                "primary": {
                    "serial": "root",
                    "issuer_id": None,
                    "delegate": True,
                    "depth": 0,
                    "chain": [
                        {
                            "serial": "root",
                            "subject_id": root["root_id"],
                            "issuer_id": None,
                            "delegate": True,
                            "not_before": None,
                            "not_after": None,
                        }
                    ],
                },
            }

        rows = self.certificates_for(subject_id)
        if not rows:
            return {
                "status": "none",
                "certified": False,
                "role": None,
                "active_certificates": 0,
                "certificate_count": 0,
                "primary": None,
                "certificates": [],
                "inactive_certificates": [],
            }

        active: list[dict[str, Any]] = []
        inactive: list[dict[str, Any]] = []
        now = int(time.time())
        for row in rows:
            serial = str(row["serial"])
            try:
                cert = parse_certificate(str(row["body"]))
            except SignatureError:
                inactive.append({"serial": serial, "reason": "invalid"})
                continue
            if not self.certificate_active(serial):
                if self.is_revoked(serial):
                    reason = "revoked"
                elif now < cert.not_before:
                    reason = "not-yet-valid"
                elif now > cert.not_after:
                    reason = "expired"
                else:
                    reason = "chain-inactive"
                inactive.append(
                    {
                        "serial": serial,
                        "issuer_id": cert.issuer_id,
                        "reason": reason,
                    }
                )
                continue
            chain = self.certificate_chain(serial)
            if not chain:
                inactive.append(
                    {
                        "serial": serial,
                        "issuer_id": cert.issuer_id,
                        "reason": "chain-inactive",
                    }
                )
                continue
            can_issue = cert.delegate and any(
                "cert.issue" in actions for actions in cert.grants.values()
            )
            active.append(
                {
                    "serial": serial,
                    "url": f"/_cert?serial={serial}",
                    "issuer_id": cert.issuer_id,
                    "delegate": cert.delegate,
                    "ca": can_issue,
                    "not_before": cert.not_before,
                    "not_after": cert.not_after,
                    "depth": len(chain) - 1,
                    "chain": chain,
                }
            )

        if not active:
            return {
                "status": "inactive",
                "certified": False,
                "role": None,
                "active_certificates": 0,
                "certificate_count": len(rows),
                "primary": None,
                "certificates": [],
                "inactive_certificates": inactive[:8],
            }

        active.sort(
            key=lambda item: (
                int(item["depth"]),
                -int(item["not_after"]),
                str(item["serial"]),
            )
        )
        ca_certificates = [item for item in active if bool(item["ca"])]
        role = "ca" if ca_certificates else "member"
        primary = ca_certificates[0] if ca_certificates else active[0]
        return {
            "status": "active",
            "certified": True,
            "role": role,
            "active_certificates": len(active),
            "certificate_count": len(rows),
            "primary": primary,
            "certificates": active[:8],
            "inactive_certificates": inactive[:8],
        }

    def post_authentication(self, post: Post) -> dict[str, Any]:
        if post.custody_id:
            identity = self.custody_by_author(post.actor_id or post.author_id or "")
            return {
                "type": "custodial",
                "signed": True,
                "certified": False,
                "status": "custodial",
                "server_accepted_signature": True,
                "basis": "server-custodied-ed25519-key",
                "author": identity,
                "actor": identity,
                "actor_is_author": post.actor_id == post.author_id,
            }
        if post.system:
            return {
                "type": "system",
                "signed": False,
                "certified": False,
                "status": "system",
                "server_accepted_signature": False,
                "basis": "server-managed-system-state",
                "author": None,
                "actor": None,
            }
        if not post.signed:
            return {
                "type": "unsigned",
                "signed": False,
                "certified": False,
                "status": "unsigned",
                "server_accepted_signature": False,
                "basis": "anonymous-policy",
                "author": None,
                "actor": None,
            }

        author = self.certification(post.author_id or "")
        actor = self.certification(post.actor_id or "")
        certified = bool(actor["certified"])
        return {
            "type": "certificate-signed",
            "signed": True,
            "certified": certified,
            "status": "certified" if certified else "signed-inactive",
            "server_accepted_signature": True,
            "basis": (
                "current-active-certificate-chain"
                if certified
                else "stored-signature-current-chain-inactive"
            ),
            "author": author,
            "actor": actor,
            "actor_is_author": post.actor_id == post.author_id,
        }

    def create_custody_identity(self, name: str) -> dict[str, Any]:
        name = " ".join(name.split()) or "guest"
        if len(name.encode("utf-8")) > self.cfg.max_name_bytes:
            raise StoreError(f"name exceeds max_name_bytes={self.cfg.max_name_bytes}", 413)

        key = Ed25519PrivateKey.generate()
        private = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_raw = key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        public_key = base64.b64encode(public_raw).decode("ascii")
        _, author_id = public_identity(public_key)
        token = secrets.token_urlsafe(32)
        token_bytes = token.encode("utf-8")
        token_hash = hashlib.sha256(b"custody-auth\0" + token_bytes).hexdigest()
        custody_id = secrets.token_hex(12)
        nonce = secrets.token_bytes(12)
        key_key = hashlib.sha256(b"custody-key\0" + token_bytes).digest()
        ciphertext = AESGCM(key_key).encrypt(nonce, private, custody_id.encode("ascii"))
        now = time.time()

        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO custody_identities(
                    id, token_hash, name, public_key, author_id, key_nonce,
                    key_ciphertext, created, last_used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    custody_id,
                    token_hash,
                    name,
                    public_key,
                    author_id,
                    nonce,
                    ciphertext,
                    now,
                    now,
                ),
            )

        return {
            "id": custody_id,
            "token": token,
            "name": name,
            "author_id": author_id,
            "public_key": public_key,
            "created": round(now, 3),
            "auth": "custodial",
            "warning": "server holds the signing key; this is not self-custody",
        }

    def _custody_row(self, token: str) -> sqlite3.Row:
        if len(token) < 32 or len(token) > 128:
            raise StoreError("invalid custody token", 403)
        token_hash = hashlib.sha256(
            b"custody-auth\0" + token.encode("utf-8")
        ).hexdigest()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, name, public_key, author_id, key_nonce, key_ciphertext,
                       created, last_used
                  FROM custody_identities
                 WHERE token_hash = ?
                """,
                (token_hash,),
            ).fetchone()
        if row is None:
            raise StoreError("invalid custody token", 403)
        return row

    def custody_info(self, token: str) -> dict[str, Any]:
        row = self._custody_row(token)
        with self._lock:
            posts = self._conn.execute(
                "SELECT COUNT(*) AS n FROM posts WHERE custody_id = ?",
                (str(row["id"]),),
            ).fetchone()["n"]
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "author_id": str(row["author_id"]),
            "public_key": str(row["public_key"]),
            "created": round(float(row["created"]), 3),
            "last_used": round(float(row["last_used"]), 3),
            "posts": int(posts),
            "auth": "custodial",
            "warning": "server holds the signing key; capability token controls this identity",
        }

    def custody_auth(
        self,
        token: str,
        payload: bytes,
        *,
        version: int,
        nonce: str | None = None,
        issued: int | None = None,
    ) -> tuple[SignedRequest, str]:
        row = self._custody_row(token)
        token_bytes = token.encode("utf-8")
        key_key = hashlib.sha256(b"custody-key\0" + token_bytes).digest()
        try:
            private = AESGCM(key_key).decrypt(
                bytes(row["key_nonce"]),
                bytes(row["key_ciphertext"]),
                str(row["id"]).encode("ascii"),
            )
        except ValueError as exc:
            raise StoreError("invalid custody token", 403) from exc
        key = Ed25519PrivateKey.from_private_bytes(private)
        signature = base64.b64encode(key.sign(payload)).decode("ascii")
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE custody_identities SET last_used = ? WHERE id = ?",
                (time.time(), str(row["id"])),
            )
        return (
            SignedRequest(
                public_key=str(row["public_key"]),
                signer_id=str(row["author_id"]),
                signature=signature,
                version=version,
                nonce=nonce,
                issued=issued,
            ),
            str(row["id"]),
        )

    def custody_owns(self, token: str, post: Post) -> bool:
        row = self._custody_row(token)
        return post.custody_id == str(row["id"])

    def custody_by_author(self, author_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, name, public_key, author_id, created, last_used
                  FROM custody_identities
                 WHERE author_id = ?
                """,
                (author_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "public_key": str(row["public_key"]),
            "author_id": str(row["author_id"]),
            "created": round(float(row["created"]), 3),
            "last_used": round(float(row["last_used"]), 3),
        }

    def permissions_for(self, subject_id: str, board: str) -> set[str]:
        permissions: set[str] = set()
        for row in self.certificates_for(subject_id):
            if not self.certificate_active(str(row["serial"])):
                continue
            cert = parse_certificate(str(row["body"]))
            permissions.update(cert.grants.get("*", ()))
            permissions.update(cert.grants.get(board, ()))
        return permissions

    def signed_allowed(
        self,
        signer_id: str,
        board: str,
        action: str,
        *,
        owner_id: str | None = None,
    ) -> bool:
        root = self.root_info()
        if root is not None and signer_id == root["root_id"]:
            return True
        permissions = self.permissions_for(signer_id, board)
        if action == "post.edit":
            return "post.edit.any" in permissions or (
                owner_id == signer_id and "post.edit.self" in permissions
            )
        if action == "post.delete":
            return "post.delete.any" in permissions or (
                owner_id == signer_id and "post.delete.self" in permissions
            )
        return action in permissions

    def revoke_certificate(
        self,
        serial: str,
        signer_id: str,
        reason: str = "",
    ) -> None:
        row = self.certificate(serial)
        if row is None:
            raise StoreError("certificate not found", 404)
        if self.is_revoked(serial):
            return

        root = self.root_info()
        if root is None:
            raise StoreError("root CA is not initialized", 503)
        cert = parse_certificate(str(row["body"]))
        allowed = signer_id == root["root_id"]
        if not allowed and signer_id == cert.issuer_id:
            topics = tuple(cert.grants)
            allowed = all(
                "cert.revoke" in self.permissions_for(signer_id, topic) for topic in topics
            )
        if not allowed:
            raise StoreError("not allowed to revoke this certificate", 403)

        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO revocations(serial, revoked_at, revoked_by, reason)
                VALUES (?, ?, ?, ?)
                """,
                (serial, now, signer_id, reason[:500]),
            )
        self._audit_ca(
            "revoked",
            f"[REVOKED] {serial[:12]}",
            [
                f"certificate=/_cert?serial={serial}",
                f"subject={cert.subject_id}",
                f"by={signer_id}",
                f"reason={reason[:300]}",
            ],
        )

    def is_revoked(self, serial: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM revocations WHERE serial = ?",
                (serial,),
            ).fetchone()
        return row is not None

    def revocations(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT serial, revoked_at, revoked_by, reason FROM revocations ORDER BY revoked_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def consume_nonce(self, auth: SignedRequest) -> None:
        if auth.nonce is None or auth.issued is None:
            raise StoreError("signed request requires nonce and issued", 400)
        now = int(time.time())
        if abs(now - auth.issued) > 300:
            raise StoreError("signed request timestamp is outside the 5 minute window", 400)
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM signature_nonces WHERE issued < ?",
                (now - 600,),
            )
            try:
                self._conn.execute(
                    "INSERT INTO signature_nonces(signer_id, nonce, issued) VALUES (?, ?, ?)",
                    (auth.signer_id, auth.nonce, auth.issued),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreError("signed request nonce already used", 409) from exc

    def _remember_identity_name(self, author_id: str, name: str, seen: float) -> None:
        self._conn.execute(
            """
            INSERT INTO identity_names(author_id, name, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(author_id, name) DO UPDATE SET
                first_seen = MIN(identity_names.first_seen, excluded.first_seen),
                last_seen = MAX(identity_names.last_seen, excluded.last_seen)
            """,
            (author_id, name, seen, seen),
        )

    def create_post(
        self,
        *,
        board: str,
        body: str,
        name: str,
        title: str,
        auth: SignedRequest | None = None,
        files: tuple[FileInput, ...] = (),
        max_body_bytes: int | None = None,
        reply_to: int | None = None,
        custody_id: str | None = None,
    ) -> tuple[Post, int]:
        body, title, name, nbytes = self.prepare_post(
            body=body,
            title=title,
            name=name,
            max_body_bytes=max_body_bytes,
        )
        files = self.prepare_files(files)
        self.ensure_board(board)
        if reply_to is not None:
            parent = self.get_post(reply_to)
            if parent is None:
                raise StoreError(f"reply target {reply_to} not found", 404)
            if parent.board != board:
                raise StoreError("reply must stay in the parent topic", 400)
        now = time.time()
        evicted = 0

        if auth is not None:
            if auth.version != 1:
                raise StoreError("signed create version must be 1", 400)
            self.consume_nonce(auth)

        with self._lock, self._conn:
            file_bytes = sum(file.nbytes for file in files)
            new_bytes = nbytes + file_bytes
            if new_bytes > self.cfg.max_storage_bytes:
                raise StoreError("post plus attachments exceed storage capacity", 507)
            used = self._storage_bytes()
            need = max(0, used + new_bytes - self.cfg.max_storage_bytes)
            if need:
                freed = 0
                rows = self._conn.execute(
                    """
                    SELECT p.id, p.nbytes + COALESCE(SUM(a.nbytes), 0) AS nbytes
                      FROM posts p
                      LEFT JOIN attachments a ON a.post_id = p.id
                     WHERE p.system = 0
                     GROUP BY p.id
                     ORDER BY p.id ASC
                    """
                ).fetchall()
                ids: list[int] = []
                for row in rows:
                    ids.append(int(row["id"]))
                    freed += int(row["nbytes"])
                    if freed >= need:
                        break
                if ids:
                    marks = ",".join("?" for _ in ids)
                    self._conn.execute(f"DELETE FROM posts WHERE id IN ({marks})", ids)
                    self._prune_empty_boards()
                    evicted = len(ids)

            seq = int(
                self._conn.execute(
                    "SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM posts WHERE board = ?",
                    (board,),
                ).fetchone()["n"]
            )
            cur = self._conn.execute(
                """
                INSERT INTO posts(
                    board, seq, name, title, body, created, updated, nbytes,
                    author_key, author_id, actor_key, actor_id, signature,
                    sig_version, sig_nonce, sig_issued, reply_to, custody_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    board,
                    seq,
                    name,
                    title,
                    body,
                    now,
                    now,
                    nbytes,
                    auth.public_key if auth else None,
                    auth.signer_id if auth else None,
                    auth.public_key if auth else None,
                    auth.signer_id if auth else None,
                    auth.signature if auth else None,
                    auth.version if auth else 0,
                    auth.nonce if auth else None,
                    auth.issued if auth else None,
                    reply_to,
                    custody_id,
                ),
            )
            post_id = int(cur.lastrowid or 0)
            if auth is not None:
                self._remember_identity_name(auth.signer_id, name, now)
            self._insert_attachments(post_id, files)
            self._reindex_inbox(post_id)

        post = self.get_post(post_id)
        assert post is not None
        return post, evicted

    def get_post(self, post_id: int) -> Post | None:
        with self._lock:
            row = self._conn.execute(self._select_posts() + " WHERE id = ?", (post_id,)).fetchone()
        return self._row(row)

    def find_in_board(self, board: str, ident: str | int) -> Post | None:
        try:
            value = int(ident)
        except TypeError, ValueError:
            return None
        with self._lock:
            row = self._conn.execute(
                self._select_posts()
                + " WHERE board = ? AND (id = ? OR seq = ?) ORDER BY id ASC LIMIT 1",
                (board, value, value),
            ).fetchone()
        return self._row(row)

    def edit_post(
        self,
        *,
        post: Post,
        body: str,
        name: str | None = None,
        title: str | None = None,
        auth: SignedRequest | None = None,
        files: tuple[FileInput, ...] | None = None,
        max_body_bytes: int | None = None,
    ) -> Post:
        body, new_title, new_name, nbytes = self.prepare_post(
            body=body,
            title=post.title if title is None else title,
            name=post.name if name is None else name,
            max_body_bytes=max_body_bytes,
        )
        if files is not None:
            files = self.prepare_files(files)
        if post.system:
            raise StoreError("system post is immutable", 403)
        if post.signed:
            if auth is None:
                raise StoreError("signed post requires a signed request", 403)
            if auth.version != post.sig_version + 1:
                raise StoreError("stale signature version", 409)

        with self._lock, self._conn:
            used = self._storage_bytes()
            old_bytes = self._post_storage_bytes(post.id)
            file_bytes = (
                sum(file.nbytes for file in files) if files is not None else old_bytes - post.nbytes
            )
            new_bytes = nbytes + file_bytes
            if new_bytes > old_bytes and used - old_bytes + new_bytes > self.cfg.max_storage_bytes:
                raise StoreError(
                    "edit would exceed max_storage_bytes; only new posts may evict old posts",
                    507,
                )
            now = time.time()
            if post.signed:
                cur = self._conn.execute(
                    """
                    UPDATE posts
                       SET body = ?, title = ?, name = ?, updated = ?, nbytes = ?,
                           actor_key = ?, actor_id = ?, signature = ?, sig_version = ?
                     WHERE id = ? AND sig_version = ?
                    """,
                    (
                        body,
                        new_title,
                        new_name,
                        now,
                        nbytes,
                        auth.public_key,
                        auth.signer_id,
                        auth.signature,
                        auth.version,
                        post.id,
                        post.sig_version,
                    ),
                )
                if cur.rowcount != 1:
                    raise StoreError("signed post changed; request a new signing payload", 409)
            else:
                self._conn.execute(
                    "UPDATE posts SET body=?, title=?, name=?, updated=?, nbytes=? WHERE id=?",
                    (body, new_title, new_name, now, nbytes, post.id),
                )

            if files is not None:
                self._conn.execute("DELETE FROM attachments WHERE post_id = ?", (post.id,))
                self._insert_attachments(post.id, files)
            if auth is not None and auth.signer_id == post.author_id:
                self._remember_identity_name(auth.signer_id, new_name, now)
            self._reindex_inbox(post.id)

        updated = self.get_post(post.id)
        assert updated is not None
        return updated

    def delete_post(self, post: Post) -> bool:
        if post.system:
            raise StoreError("system post is immutable", 403)
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM posts WHERE id = ?", (post.id,))
            if cur.rowcount:
                self._prune_empty_boards()
        return cur.rowcount > 0

    def _prune_empty_boards(self) -> None:
        self._conn.execute(
            "DELETE FROM boards WHERE name NOT IN ('main', 'meta', 'guest', 'custody', 'ca')"
            " AND NOT EXISTS (SELECT 1 FROM posts WHERE posts.board = boards.name)"
        )

    def list_posts(
        self,
        *,
        board: str | None = None,
        since: int | None = None,
        before: int | None = None,
        limit: int = 20,
        order: str = "desc",
        author: str | None = None,
        author_id: str | None = None,
        search: str | None = None,
    ) -> list[Post]:
        where: list[str] = []
        params: list[Any] = []
        if board:
            where.append("board = ?")
            params.append(board)
        if since is not None:
            where.append("id > ?")
            params.append(since)
        if before is not None:
            where.append("id < ?")
            params.append(before)
        if author:
            where.append("name = ?")
            params.append(author)
        if author_id:
            where.append("author_id = ?")
            params.append(author_id)
        if search:
            where.append("(title LIKE ? OR body LIKE ?)")
            params.extend((f"%{search}%", f"%{search}%"))

        sql = self._select_posts()
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id " + ("ASC" if order == "asc" else "DESC") + " LIMIT ?"
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [post for row in rows if (post := self._row(row)) is not None]

    @staticmethod
    def _like_pattern(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return f"%{escaped}%"

    def search_posts(
        self,
        spec: SearchSpec,
        *,
        limit: int,
    ) -> tuple[list[Post], bool]:
        where: list[str] = []
        params: list[Any] = []

        if spec.board:
            where.append("p.board = ?")
            params.append(spec.board)
        if spec.author_name:
            where.append("p.name = ?")
            params.append(spec.author_name)
        if spec.author_id:
            if not valid_author_id(spec.author_id):
                raise StoreError("author: must be a 64-character author id", 400)
            where.append("p.author_id = ?")
            params.append(spec.author_id)
        if spec.after is not None:
            where.append("p.created >= ?")
            params.append(spec.after)
        if spec.before is not None:
            where.append("p.created < ?")
            params.append(spec.before)
        if spec.reply_to is not None:
            where.append("p.reply_to = ?")
            params.append(spec.reply_to)
        elif spec.replies_only:
            where.append("p.reply_to IS NOT NULL")
        if spec.has_files is True:
            where.append("EXISTS (SELECT 1 FROM attachments a WHERE a.post_id = p.id)")
        elif spec.has_files is False:
            where.append("NOT EXISTS (SELECT 1 FROM attachments a WHERE a.post_id = p.id)")

        for term in spec.terms:
            where.append("(p.title LIKE ? ESCAPE '\\' OR p.body LIKE ? ESCAPE '\\')")
            needle = self._like_pattern(term)
            params.extend((needle, needle))
        for term in spec.excluded_terms:
            where.append(
                "NOT (p.title LIKE ? ESCAPE '\\' OR p.body LIKE ? ESCAPE '\\')"
            )
            needle = self._like_pattern(term)
            params.extend((needle, needle))
        for term in spec.title_terms:
            where.append("p.title LIKE ? ESCAPE '\\'")
            params.append(self._like_pattern(term))

        dynamic_auth = spec.auth in {"certified", "certified-ca", "signed-inactive"}
        if spec.auth == "unsigned":
            where.append("p.author_id IS NULL AND p.system = 0 AND p.custody_id IS NULL")
        elif spec.auth == "system":
            where.append("p.system = 1")
        elif spec.auth == "custodial":
            where.append("p.custody_id IS NOT NULL")
        elif spec.auth == "signed":
            where.append("p.author_id IS NOT NULL")
        elif spec.auth == "root":
            root = self.root_info()
            if root is None:
                return [], False
            where.append("p.actor_id = ?")
            params.append(root["root_id"])

        base = (
            "SELECT p.id, p.board, p.seq, p.name, p.title, p.body, p.created, p.updated, "
            "p.nbytes, p.author_key, p.author_id, p.actor_key, p.actor_id, p.signature, "
            "p.sig_version, p.sig_nonce, p.sig_issued, p.reply_to, p.system, p.custody_id "
            "FROM posts p"
        )
        if where:
            base += " WHERE " + " AND ".join(where)
        base += " ORDER BY p.id " + ("ASC" if spec.order == "asc" else "DESC")

        if not dynamic_auth:
            with self._lock:
                rows = self._conn.execute(base + " LIMIT ?", [*params, limit + 1]).fetchall()
            posts = [post for row in rows if (post := self._row(row)) is not None]
            return posts[: limit + 1], False

        collected: list[Post] = []
        offset = 0
        scan_cap = 5000
        chunk = 200
        capped = False

        while len(collected) <= limit and offset < scan_cap:
            with self._lock:
                rows = self._conn.execute(
                    base + " LIMIT ? OFFSET ?",
                    [*params, chunk, offset],
                ).fetchall()
            if not rows:
                break
            offset += len(rows)
            for row in rows:
                post = self._row(row)
                if post is None:
                    continue
                status = self.post_authentication(post)["status"]
                if spec.auth == "certified" and status == "certified":
                    collected.append(post)
                elif spec.auth == "certified-ca":
                    auth = self.post_authentication(post)
                    actor = auth.get("actor")
                    if (
                        status == "certified"
                        and isinstance(actor, dict)
                        and actor.get("role") == "ca"
                    ):
                        collected.append(post)
                elif spec.auth == "signed-inactive" and status == "signed-inactive":
                    collected.append(post)
                if len(collected) > limit:
                    break
            if len(rows) < chunk:
                break

        if offset >= scan_cap and len(collected) <= limit:
            capped = True
        return collected[: limit + 1], capped

    def inbox(
        self,
        subject_id: str,
        *,
        since: int | None = None,
        before: int | None = None,
        limit: int = 20,
    ) -> list[tuple[Post, tuple[str, ...]]]:
        if not valid_author_id(subject_id):
            raise StoreError("invalid inbox identity", 400)

        where = ["e.subject_id = ?"]
        params: list[Any] = [subject_id]
        if since is not None:
            where.append("e.post_id > ?")
            params.append(since)
        if before is not None:
            where.append("e.post_id < ?")
            params.append(before)

        sql = (
            "SELECT e.post_id, GROUP_CONCAT(e.kind) AS kinds "
            "FROM inbox_events e WHERE "
            + " AND ".join(where)
            + " GROUP BY e.post_id ORDER BY e.post_id DESC LIMIT ?"
        )
        params.append(max(1, min(limit, self.cfg.max_limit)))

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            result: list[tuple[Post, tuple[str, ...]]] = []
            for row in rows:
                post_row = self._conn.execute(
                    self._select_posts() + " WHERE id = ?",
                    (int(row["post_id"]),),
                ).fetchone()
                post = self._row(post_row)
                if post is None:
                    continue
                kinds = tuple(sorted({item for item in str(row["kinds"] or "").split(",") if item}))
                result.append((post, kinds))
        return result

    def _reindex_inbox(self, post_id: int) -> None:
        self._conn.execute("DELETE FROM inbox_events WHERE post_id = ?", (post_id,))
        row = self._conn.execute(
            self._select_posts() + " WHERE id = ?",
            (post_id,),
        ).fetchone()
        post = self._row(row)
        if post is None:
            return

        actor_id = post.actor_id
        events: set[tuple[str, str]] = set()

        if post.reply_to is not None:
            parent = self._conn.execute(
                "SELECT author_id FROM posts WHERE id = ?",
                (post.reply_to,),
            ).fetchone()
            if parent is not None and parent["author_id"] is not None:
                target = str(parent["author_id"])
                if target != actor_id:
                    events.add((target, "reply"))

        text = post.title + "\n" + post.body
        for token in set(MENTION_RE.findall(text)):
            lowered = token.lower()
            targets: set[str] = set()
            if AUTHOR_ID_RE.fullmatch(lowered):
                targets.add(lowered)
            else:
                rows = self._conn.execute(
                    """
                    SELECT DISTINCT author_id
                      FROM posts
                     WHERE author_id IS NOT NULL
                       AND name = ? COLLATE NOCASE
                    """,
                    (token,),
                ).fetchall()
                targets.update(str(item["author_id"]) for item in rows)

            for target in targets:
                if target != actor_id:
                    events.add((target, "mention"))

        if events:
            self._conn.executemany(
                """
                INSERT OR IGNORE INTO inbox_events(post_id, subject_id, kind)
                VALUES (?, ?, ?)
                """,
                [(post_id, subject_id, kind) for subject_id, kind in events],
            )

    def key_info(self, author_id: str) -> dict[str, Any] | None:
        if not valid_author_id(author_id):
            return None
        certs = self.certificates_for(author_id)
        custody = self.custody_by_author(author_id)
        with self._lock:
            stats = self._conn.execute(
                """
                SELECT COUNT(*) AS posts, MIN(created) AS first_seen,
                       MAX(updated) AS last_seen
                  FROM posts
                 WHERE author_id = ?
                """,
                (author_id,),
            ).fetchone()
            aliases = self._conn.execute(
                """
                SELECT name, first_seen, last_seen
                  FROM identity_names
                 WHERE author_id = ?
                 ORDER BY last_seen DESC
                 LIMIT 8
                """,
                (author_id,),
            ).fetchall()
            latest = self._conn.execute(
                self._select_posts() + " WHERE author_id = ? ORDER BY id DESC LIMIT 1",
                (author_id,),
            ).fetchone()
        latest_post = self._row(latest)
        public_key = (
            certs[0]["subject_key"]
            if certs
            else custody["public_key"]
            if custody
            else (latest_post.author_key if latest_post else None)
        )
        if public_key is None:
            root = self.root_info()
            if root is not None and author_id == root["root_id"]:
                public_key = root["public_key"]
            else:
                return None
        return {
            "author_id": author_id,
            "algorithm": "ed25519",
            "public_key": public_key,
            "display_name": str(aliases[0]["name"]) if aliases else None,
            "aliases": [
                {
                    "name": str(row["name"]),
                    "first_seen": round(float(row["first_seen"]), 3),
                    "last_seen": round(float(row["last_seen"]), 3),
                }
                for row in aliases
            ],
            "posts": int(stats["posts"] or 0),
            "first_seen": (
                round(float(stats["first_seen"]), 3) if stats["first_seen"] is not None else None
            ),
            "last_seen": (
                round(float(stats["last_seen"]), 3) if stats["last_seen"] is not None else None
            ),
            "certification": self.certification(author_id),
            "custodial": custody is not None,
        }

    def stats(self) -> dict[str, int]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS posts,
                       SUM(CASE WHEN system = 1 THEN 1 ELSE 0 END) AS system_posts,
                       COALESCE(SUM(CASE WHEN system = 0 THEN nbytes ELSE 0 END), 0) AS post_bytes,
                       COALESCE(MAX(id),0) AS latest_id
                  FROM posts
                """
            ).fetchone()
            files = self._conn.execute(
                "SELECT COUNT(*) AS files, COALESCE(SUM(nbytes),0) AS file_bytes FROM attachments"
            ).fetchone()
            boards = self._conn.execute("SELECT COUNT(*) AS n FROM boards").fetchone()["n"]
        post_bytes = int(row["post_bytes"])
        file_bytes = int(files["file_bytes"])
        return {
            "boards": int(boards),
            "posts": int(row["posts"]),
            "system_posts": int(row["system_posts"] or 0),
            "files": int(files["files"]),
            "post_bytes": post_bytes,
            "file_bytes": file_bytes,
            "bytes": post_bytes + file_bytes,
            "capacity": self.cfg.max_storage_bytes,
            "latest_id": int(row["latest_id"]),
        }

    def _validate_chain(self, serial: str, *, now: int, seen: set[str], depth: int) -> bool:
        if depth >= 8 or serial in seen or self.is_revoked(serial):
            return False
        row = self.certificate(serial)
        if row is None:
            return False
        cert = parse_certificate(str(row["body"]))
        if not (cert.not_before <= now <= cert.not_after):
            return False

        seen = set(seen)
        seen.add(serial)
        root = self.root_info()
        if root is None:
            return False

        if cert.issuer_serial == "root":
            if cert.issuer_id != root["root_id"]:
                return False
            issuer_key = root["public_key"]
        else:
            if not self._validate_chain(
                cert.issuer_serial,
                now=now,
                seen=seen,
                depth=depth + 1,
            ):
                return False
            parent_row = self.certificate(cert.issuer_serial)
            if parent_row is None:
                return False
            parent = parse_certificate(str(parent_row["body"]))
            if cert.issuer_id != parent.subject_id:
                return False
            self._check_delegation(parent, cert)
            issuer_key = parent.subject_key

        verify_detached(
            issuer_key,
            str(row["signature"]),
            certificate_payload(cert.body),
        )
        return True

    @staticmethod
    def _check_delegation(parent: Certificate, child: Certificate) -> None:
        if not parent.delegate:
            raise StoreError("issuer certificate cannot delegate", 403)
        for topic, child_actions in child.grants.items():
            parent_actions = set(parent.grants.get("*", ()))
            if topic != "*":
                parent_actions.update(parent.grants.get(topic, ()))
            if "cert.issue" not in parent_actions:
                raise StoreError(f"issuer cannot issue for topic {topic}", 403)
            if not set(child_actions).issubset(parent_actions):
                raise StoreError(f"child grant exceeds issuer grant for topic {topic}", 403)

    @staticmethod
    def _select_posts() -> str:
        return (
            "SELECT id, board, seq, name, title, body, created, updated, nbytes,"
            " author_key, author_id, actor_key, actor_id, signature,"
            " sig_version, sig_nonce, sig_issued, reply_to, system, custody_id FROM posts"
        )

    @staticmethod
    def _attachment(row: sqlite3.Row) -> Attachment:
        return Attachment(
            id=int(row["id"]),
            post_id=int(row["post_id"]),
            slot=int(row["slot"]),
            name=str(row["name"]),
            content_type=str(row["content_type"]),
            data=bytes(row["data"]),
            nbytes=int(row["nbytes"]),
            sha256=str(row["sha256"]),
        )

    @staticmethod
    def _row(row: sqlite3.Row | None) -> Post | None:
        if row is None:
            return None
        return Post(
            id=int(row["id"]),
            board=str(row["board"]),
            seq=int(row["seq"]),
            name=str(row["name"]),
            title=str(row["title"]),
            body=str(row["body"]),
            created=float(row["created"]),
            updated=float(row["updated"]),
            nbytes=int(row["nbytes"]),
            author_key=str(row["author_key"]) if row["author_key"] is not None else None,
            author_id=str(row["author_id"]) if row["author_id"] is not None else None,
            actor_key=str(row["actor_key"]) if row["actor_key"] is not None else None,
            actor_id=str(row["actor_id"]) if row["actor_id"] is not None else None,
            signature=str(row["signature"]) if row["signature"] is not None else None,
            sig_version=int(row["sig_version"] or 0),
            sig_nonce=str(row["sig_nonce"]) if row["sig_nonce"] is not None else None,
            sig_issued=int(row["sig_issued"]) if row["sig_issued"] is not None else None,
            reply_to=int(row["reply_to"]) if row["reply_to"] is not None else None,
            system=bool(row["system"]),
            custody_id=str(row["custody_id"]) if row["custody_id"] is not None else None,
        )
