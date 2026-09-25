"""SQLite current-state store with optional certificate-controlled identities."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from msgd.config import Config
from msgd.crypto import (
    ACTIONS,
    Certificate,
    SignatureError,
    SignedRequest,
    certificate_payload,
    parse_certificate,
    public_identity,
    verify_detached,
)

BOARD_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
AUTHOR_ID_RE = re.compile(r"^[0-9a-f]{64}$")
MENTION_RE = re.compile(
    r"(?<![A-Za-z0-9._-])@([A-Za-z0-9][A-Za-z0-9._-]{0,63})(?![A-Za-z0-9._-])"
)

ANONYMOUS_PERMISSION_BITS = {
    "post.create": 1,
    "post.edit.any": 2,
    "post.delete.any": 4,
}
ANONYMOUS_PERMISSION_MASK = sum(ANONYMOUS_PERMISSION_BITS.values())
DEFAULT_ANONYMOUS = frozenset(ANONYMOUS_PERMISSION_BITS)


def anonymous_permission_mask(actions: Iterable[str]) -> int:
    current = set(actions)
    return sum(
        bit
        for action, bit in ANONYMOUS_PERMISSION_BITS.items()
        if action in current
    )


def anonymous_actions(mask: int) -> tuple[str, ...]:
    if mask < 0 or mask & ~ANONYMOUS_PERMISSION_MASK:
        raise ValueError(f"anonymous permission mask must be 0..{ANONYMOUS_PERMISSION_MASK}")
    return tuple(
        action
        for action, bit in ANONYMOUS_PERMISSION_BITS.items()
        if mask & bit
    )

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
    reply_to    INTEGER
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

CREATE TABLE IF NOT EXISTS certificate_requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id    TEXT NOT NULL,
    subject_key   TEXT NOT NULL,
    issuer_serial TEXT NOT NULL,
    delegate      INTEGER NOT NULL,
    grants        TEXT NOT NULL,
    message       TEXT NOT NULL DEFAULT '',
    signature     TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    issued        INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    certificate   TEXT,
    decided_by    TEXT,
    created       REAL NOT NULL,
    updated       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS csr_status_id
    ON certificate_requests(status, id);
CREATE INDEX IF NOT EXISTS csr_subject_id
    ON certificate_requests(subject_id, id);

CREATE TABLE IF NOT EXISTS revocations (
    serial     TEXT PRIMARY KEY REFERENCES certificates(serial) ON DELETE CASCADE,
    revoked_at REAL NOT NULL,
    revoked_by TEXT NOT NULL
);

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
                "post.create" if self.signed and self.sig_version == 1 else
                "post.edit" if self.signed else None
            ),
            "sig_nonce": self.sig_nonce if self.signed and self.sig_version == 1 else None,
            "sig_issued": self.sig_issued if self.signed and self.sig_version == 1 else None,
            "reply_to": self.reply_to,
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
            had_inbox = self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='inbox_events'"
            ).fetchone() is not None
            self._conn.executescript(TABLES)
            self._ensure_schema()
            for name, description in DEFAULT_BOARDS.items():
                self._ensure_board(name, description)
            if not had_inbox:
                self._rebuild_inbox()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _ensure_schema(self) -> None:
        columns = {
            str(row["name"])
            for row in self._conn.execute("PRAGMA table_info(posts)").fetchall()
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
        }
        for name, definition in additions.items():
            if name not in columns:
                self._conn.execute(f"ALTER TABLE posts ADD COLUMN {name} {definition}")
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
            CREATE TABLE IF NOT EXISTS certificate_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_id TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                issuer_serial TEXT NOT NULL,
                delegate INTEGER NOT NULL,
                grants TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                signature TEXT NOT NULL,
                nonce TEXT NOT NULL,
                issued INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                certificate TEXT,
                decided_by TEXT,
                created REAL NOT NULL,
                updated REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS csr_status_id
                ON certificate_requests(status, id);
            CREATE INDEX IF NOT EXISTS csr_subject_id
                ON certificate_requests(subject_id, id);
            CREATE TABLE IF NOT EXISTS revocations (
                serial TEXT PRIMARY KEY REFERENCES certificates(serial) ON DELETE CASCADE,
                revoked_at REAL NOT NULL,
                revoked_by TEXT NOT NULL
            );
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

    def _rebuild_inbox(self) -> None:
        self._conn.execute("DELETE FROM inbox_events")
        rows = self._conn.execute("SELECT id FROM posts ORDER BY id").fetchall()
        for row in rows:
            self._reindex_inbox(int(row["id"]))

    def root_info(self) -> dict[str, str] | None:
        try:
            key = Path(self.cfg.root_public_key).read_text(encoding="utf-8").strip()
            canonical, root_id = public_identity(key)
        except (OSError, SignatureError):
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
                COALESCE((SELECT SUM(nbytes) FROM posts), 0)
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
        with self._lock:
            row = self._conn.execute(
                "SELECT anonymous, version, updated FROM topic_policies WHERE board = ?",
                (board,),
            ).fetchone()
        if row is None:
            actions = sorted(DEFAULT_ANONYMOUS)
            return {
                "board": board,
                "permissions": anonymous_permission_mask(actions),
                "anonymous": actions,
                "version": 0,
                "updated": None,
            }
        actions = json.loads(str(row["anonymous"]))
        return {
            "board": board,
            "permissions": anonymous_permission_mask(actions),
            "anonymous": actions,
            "version": int(row["version"]),
            "updated": float(row["updated"]),
        }

    def set_policy(self, board: str, anonymous: tuple[str, ...], version: int) -> dict[str, Any]:
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

    def create_certificate_request(
        self,
        *,
        subject_key: str,
        issuer_serial: str,
        delegate: bool,
        grants: str,
        message: str,
        signature: str,
        nonce: str,
        issued: int,
    ) -> dict[str, Any]:
        canonical_key, subject_id = public_identity(subject_key)
        now = int(time.time())
        if abs(now - issued) > 300:
            raise StoreError("certificate request timestamp is outside the 5 minute window", 400)
        if len(message.encode("utf-8")) > 4096:
            raise StoreError("certificate request message is too long", 413)

        auth = SignedRequest(
            public_key=canonical_key,
            signer_id=subject_id,
            signature=signature,
            version=1,
            nonce=nonce,
            issued=issued,
        )
        self.consume_nonce(auth)
        created = time.time()
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO certificate_requests(
                    subject_id, subject_key, issuer_serial, delegate, grants,
                    message, signature, nonce, issued, status, created, updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    subject_id,
                    canonical_key,
                    issuer_serial,
                    1 if delegate else 0,
                    grants,
                    message,
                    signature,
                    nonce,
                    issued,
                    created,
                    created,
                ),
            )
            csr_id = int(cur.lastrowid or 0)
            self._append_ca_event(
                "REQUEST",
                {
                    "csr_id": csr_id,
                    "subject_id": subject_id,
                    "issuer_serial": issuer_serial,
                    "delegate": delegate,
                    "grants": json.loads(grants),
                },
            )
        row = self.certificate_request(csr_id)
        assert row is not None
        return row

    def certificate_request(self, csr_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, subject_id, subject_key, issuer_serial, delegate,
                       grants, message, signature, nonce, issued, status,
                       certificate, decided_by, created, updated
                  FROM certificate_requests
                 WHERE id = ?
                """,
                (csr_id,),
            ).fetchone()
        return self._csr_row(row) if row else None

    def certificate_requests(
        self,
        *,
        status: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        where = ""
        params: list[Any] = []
        if status:
            if status not in {"pending", "issued", "rejected"}:
                raise StoreError("invalid certificate request status", 400)
            where = " WHERE status = ?"
            params.append(status)
        params.append(max(1, min(limit, self.cfg.max_limit)))
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, subject_id, subject_key, issuer_serial, delegate,
                       grants, message, signature, nonce, issued, status,
                       certificate, decided_by, created, updated
                  FROM certificate_requests
                """
                + where
                + " ORDER BY id DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._csr_row(row) for row in rows]

    def decide_certificate_request(
        self,
        csr_id: int,
        *,
        signer_id: str,
        decision: str,
        certificate_serial: str | None = None,
    ) -> dict[str, Any]:
        if decision not in {"approve", "reject"}:
            raise StoreError("decision must be approve or reject", 400)
        current = self.certificate_request(csr_id)
        if current is None:
            raise StoreError("certificate request not found", 404)
        if current["status"] != "pending":
            raise StoreError("certificate request is already decided", 409)

        status = "issued" if decision == "approve" else "rejected"
        now = time.time()
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                UPDATE certificate_requests
                   SET status = ?, certificate = ?, decided_by = ?, updated = ?
                 WHERE id = ? AND status = 'pending'
                """,
                (status, certificate_serial, signer_id, now, csr_id),
            )
            if cur.rowcount != 1:
                raise StoreError("certificate request changed", 409)
            self._append_ca_event(
                "CSR-ISSUED" if decision == "approve" else "REJECTED",
                {
                    "csr_id": csr_id,
                    "subject_id": current["subject_id"],
                    "certificate": certificate_serial,
                    "decided_by": signer_id,
                },
            )
        row = self.certificate_request(csr_id)
        assert row is not None
        return row

    def register_certificate(self, body: str, signature: str) -> Certificate:
        try:
            cert = parse_certificate(body)
        except SignatureError as exc:
            raise StoreError(str(exc), 400) from exc

        existing = self.certificate(cert.serial)
        if existing is not None:
            if existing["body"] == cert.body and existing["signature"] == signature:
                return cert
            raise StoreError("certificate serial already exists", 409)

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
                    time.time(),
                ),
            )
            self._append_ca_event(
                "ISSUED",
                {
                    "serial": cert.serial,
                    "subject_id": cert.subject_id,
                    "issuer_id": cert.issuer_id,
                    "issuer_serial": cert.issuer_serial,
                    "delegate": cert.delegate,
                    "grants": cert.grants,
                },
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

    def certificate_active(self, serial: str, *, now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        try:
            return self._validate_chain(serial, now=now, seen=set(), depth=0)
        except (StoreError, SignatureError):
            return False

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
            return (
                "post.edit.any" in permissions
                or (owner_id == signer_id and "post.edit.self" in permissions)
            )
        if action == "post.delete":
            return (
                "post.delete.any" in permissions
                or (owner_id == signer_id and "post.delete.self" in permissions)
            )
        return action in permissions

    def revoke_certificate(self, serial: str, signer_id: str) -> None:
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
                "cert.revoke" in self.permissions_for(signer_id, topic)
                for topic in topics
            )
        if not allowed:
            raise StoreError("not allowed to revoke this certificate", 403)

        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO revocations(serial, revoked_at, revoked_by) VALUES (?, ?, ?)",
                (serial, time.time(), signer_id),
            )
            self._append_ca_event(
                "REVOKED",
                {
                    "serial": serial,
                    "subject_id": cert.subject_id,
                    "revoked_by": signer_id,
                },
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
                "SELECT serial, revoked_at, revoked_by FROM revocations ORDER BY revoked_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def consume_nonce(self, auth: SignedRequest) -> None:
        if auth.nonce is None or auth.issued is None:
            raise StoreError("signed request requires nonce and issued", 400)
        now = int(time.time())
        if abs(now - auth.issued) > 300:
            raise StoreError("signed create timestamp is outside the 5 minute window", 400)
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
                raise StoreError("signed create nonce already used", 409) from exc

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
                    sig_version, sig_nonce, sig_issued, reply_to
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            post_id = int(cur.lastrowid or 0)
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
        except (TypeError, ValueError):
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
        if post.signed:
            if auth is None:
                raise StoreError("signed post requires a signed request", 403)
            if auth.version != post.sig_version + 1:
                raise StoreError("stale signature version", 409)

        with self._lock, self._conn:
            used = self._storage_bytes()
            old_bytes = self._post_storage_bytes(post.id)
            file_bytes = (
                sum(file.nbytes for file in files)
                if files is not None
                else old_bytes - post.nbytes
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
            self._reindex_inbox(post.id)

        updated = self.get_post(post.id)
        assert updated is not None
        return updated

    def delete_post(self, post: Post) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM posts WHERE id = ?", (post.id,))
            if cur.rowcount:
                self._prune_empty_boards()
        return cur.rowcount > 0

    def _append_ca_event(self, kind: str, data: dict[str, Any]) -> None:
        self._ensure_board("ca", "Certificate authority public audit log.")
        now = time.time()
        seq = int(
            self._conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM posts WHERE board = 'ca'"
            ).fetchone()["n"]
        )
        body = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        title = f"[{kind}]"
        cur = self._conn.execute(
            """
            INSERT INTO posts(
                board, seq, name, title, body, created, updated, nbytes
            ) VALUES ('ca', ?, 'ca-audit', ?, ?, ?, ?, ?)
            """,
            (
                seq,
                title,
                body,
                now,
                now,
                len(body.encode("utf-8")),
            ),
        )
        post_id = int(cur.lastrowid or 0)
        self._reindex_inbox(post_id)

    def _prune_empty_boards(self) -> None:
        self._conn.execute(
            "DELETE FROM boards WHERE name NOT IN ('main', 'meta')"
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
                kinds = tuple(
                    sorted(
                        {
                            item
                            for item in str(row["kinds"] or "").split(",")
                            if item
                        }
                    )
                )
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
        posts = self.list_posts(author_id=author_id, limit=self.cfg.max_limit)
        public_key = certs[0]["subject_key"] if certs else (posts[0].author_key if posts else None)
        if public_key is None:
            return None
        return {
            "author_id": author_id,
            "algorithm": "ed25519",
            "public_key": public_key,
            "posts": len(posts),
            "active_certificates": sum(
                1 for cert in certs if self.certificate_active(str(cert["serial"]))
            ),
        }

    def stats(self) -> dict[str, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS posts, COALESCE(SUM(nbytes),0) AS post_bytes,"
                " COALESCE(MAX(id),0) AS latest_id FROM posts"
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
    def _csr_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "subject_id": str(row["subject_id"]),
            "subject_key": str(row["subject_key"]),
            "issuer_serial": str(row["issuer_serial"]),
            "delegate": bool(row["delegate"]),
            "grants": json.loads(str(row["grants"])),
            "message": str(row["message"]),
            "signature": str(row["signature"]),
            "nonce": str(row["nonce"]),
            "issued": int(row["issued"]),
            "status": str(row["status"]),
            "certificate": (
                str(row["certificate"]) if row["certificate"] is not None else None
            ),
            "decided_by": (
                str(row["decided_by"]) if row["decided_by"] is not None else None
            ),
            "created": float(row["created"]),
            "updated": float(row["updated"]),
        }

    @staticmethod
    def _select_posts() -> str:
        return (
            "SELECT id, board, seq, name, title, body, created, updated, nbytes,"
            " author_key, author_id, actor_key, actor_id, signature,"
            " sig_version, sig_nonce, sig_issued, reply_to FROM posts"
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
        )
