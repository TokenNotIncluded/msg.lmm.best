"""SQLite current-state store with optional certificate-controlled identities."""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

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
    curve25519_public_key,
    parse_certificate,
    public_identity,
    verify_detached,
)
from msgd.search import SearchSpec

BOARD_RE = re.compile(r"^[a-z][a-z0-9]{1,23}$")
AUTHOR_ID_RE = re.compile(r"^[0-9a-f]{64}$")
MENTION_RE = re.compile(r"(?<![A-Za-z0-9._-])@([A-Za-z0-9][A-Za-z0-9._-]{0,63})(?![A-Za-z0-9._-])")
HASHTAG_RE = re.compile(r"(?<![\w/#])#([\w][\w-]{0,31})(?![\w-])", re.UNICODE)
MAX_TAGS_PER_POST = 16
KEYSTORE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
KEYSTORE_FORMAT = "libsodium-sealed-box-v1"
KEYSTORE_MAX_ENTRY_BYTES = 64 * 1024
KEYSTORE_MAX_TOTAL_BYTES = 1024 * 1024

LEGACY_ANONYMOUS_PERMISSION_BITS = {
    "post.create": 1,
    "post.edit.any": 2,
    "post.delete.any": 4,
}
LEGACY_ANONYMOUS_PERMISSION_MASK = sum(LEGACY_ANONYMOUS_PERMISSION_BITS.values())

BASE_PERMISSION_BITS = {
    "post.create": 1,
    "post.edit.self": 2,
    "post.edit.any": 4,
    "post.delete.self": 8,
    "post.delete.any": 16,
}
BASE_PERMISSION_MASK = sum(BASE_PERMISSION_BITS.values())
ANONYMOUS_BASE_ACTIONS = frozenset({"post.create", "post.edit.any", "post.delete.any"})
SIGNED_BASE_ACTIONS = frozenset({"post.create", "post.edit.self", "post.delete.self"})
ANONYMOUS_BASE_PERMISSION_MASK = sum(
    BASE_PERMISSION_BITS[action] for action in ANONYMOUS_BASE_ACTIONS
)
SIGNED_BASE_PERMISSION_MASK = sum(BASE_PERMISSION_BITS[action] for action in SIGNED_BASE_ACTIONS)

DEFAULT_ANONYMOUS = frozenset({"post.create"})
DEFAULT_SIGNED = SIGNED_BASE_ACTIONS
GUEST_ANONYMOUS = ANONYMOUS_BASE_ACTIONS


def anonymous_permission_mask(actions: Iterable[str]) -> int:
    """Legacy 3-bit anonymous mask kept for API compatibility."""
    current = set(actions)
    return sum(bit for action, bit in LEGACY_ANONYMOUS_PERMISSION_BITS.items() if action in current)


def anonymous_actions(mask: int) -> tuple[str, ...]:
    """Decode the legacy 3-bit anonymous mask."""
    if mask < 0 or mask & ~LEGACY_ANONYMOUS_PERMISSION_MASK:
        raise ValueError(f"anonymous permission mask must be 0..{LEGACY_ANONYMOUS_PERMISSION_MASK}")
    return tuple(action for action, bit in LEGACY_ANONYMOUS_PERMISSION_BITS.items() if mask & bit)


def base_permission_mask(actions: Iterable[str]) -> int:
    current = set(actions)
    return sum(bit for action, bit in BASE_PERMISSION_BITS.items() if action in current)


def _base_actions(mask: int, allowed: frozenset[str], label: str) -> tuple[str, ...]:
    allowed_mask = sum(BASE_PERMISSION_BITS[action] for action in allowed)
    if mask < 0 or mask & ~allowed_mask:
        raise ValueError(f"{label} permission mask contains unsupported bits")
    return tuple(
        action for action, bit in BASE_PERMISSION_BITS.items() if action in allowed and mask & bit
    )


def anonymous_base_actions(mask: int) -> tuple[str, ...]:
    return _base_actions(mask, ANONYMOUS_BASE_ACTIONS, "anonymous")


def signed_base_actions(mask: int) -> tuple[str, ...]:
    return _base_actions(mask, SIGNED_BASE_ACTIONS, "signed")


RESERVED_BOARDS = {
    "admin",
    "api",
    "assets",
    "auth",
    "create",
    "delete",
    "edit",
    "feed",
    "health",
    "help",
    "new",
    "null",
    "profile",
    "repos",
    "root",
    "search",
    "settings",
    "static",
    "system",
    "undefined",
    "webhook",
    "users",
    "rules",
    "_rules",
    "_help",
    "_schema",
    "_health",
    "_search",
    "hot",
    "tags",
    "tag",
    "_signing",
    "_ca",
    "_cert",
    "_csr",
    "_revoke",
    "_policy",
    "_revocations",
    "publish",
    "inbox",
    "outbox",
    "state",
    "watch",
    "ack",
    "task",
    "thread",
    "since",
    "ref",
    "index",
    "file",
    "files",
    "key",
    "keystore",
    "_keystore",
    "_profile",
    "latest",
    "like",
    "llms.txt",
    "robots.txt",
    "sitemap.xml",
    "rss.xml",
    "feed.xml",
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
PRAGMA secure_delete = ON;

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
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id       INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    slot          INTEGER NOT NULL,
    name          TEXT NOT NULL,
    content_type  TEXT NOT NULL,
    data          BLOB NOT NULL,
    nbytes        INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    created       REAL NOT NULL,
    uploader_name TEXT NOT NULL DEFAULT 'anonymous',
    uploader_id   TEXT,
    downloads     INTEGER NOT NULL DEFAULT 0,
    UNIQUE(post_id, slot)
);
CREATE INDEX IF NOT EXISTS attachments_post ON attachments(post_id);

CREATE TABLE IF NOT EXISTS archived_posts (
    id          INTEGER PRIMARY KEY,
    board       TEXT NOT NULL,
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
    custody_id  TEXT,
    archived_at REAL NOT NULL,
    archived_by TEXT
);
CREATE INDEX IF NOT EXISTS archived_posts_time ON archived_posts(archived_at, id);
CREATE INDEX IF NOT EXISTS archived_posts_board ON archived_posts(board, id);

CREATE TABLE IF NOT EXISTS archived_attachments (
    id            INTEGER PRIMARY KEY,
    post_id       INTEGER NOT NULL REFERENCES archived_posts(id) ON DELETE CASCADE,
    slot          INTEGER NOT NULL,
    name          TEXT NOT NULL,
    content_type  TEXT NOT NULL,
    data          BLOB NOT NULL,
    nbytes        INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    created       REAL NOT NULL,
    uploader_name TEXT NOT NULL DEFAULT 'anonymous',
    uploader_id   TEXT,
    downloads     INTEGER NOT NULL DEFAULT 0,
    UNIQUE(post_id, slot)
);
CREATE INDEX IF NOT EXISTS archived_attachments_post ON archived_attachments(post_id);

CREATE TABLE IF NOT EXISTS purge_tombstones (
    post_id   INTEGER PRIMARY KEY,
    board     TEXT NOT NULL,
    purged_at REAL NOT NULL,
    purged_by TEXT,
    reason    TEXT NOT NULL DEFAULT ''
);

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

CREATE TABLE IF NOT EXISTS name_claims (
    name_key        TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    author_id       TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    claim_post_id   INTEGER REFERENCES posts(id) ON DELETE SET NULL,
    claim_signature TEXT NOT NULL DEFAULT '',
    claimed         REAL NOT NULL,
    last_used       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS name_claims_author ON name_claims(author_id, claimed);

CREATE TABLE IF NOT EXISTS profiles (
    author_id         TEXT PRIMARY KEY,
    primary_name_key  TEXT NOT NULL,
    bio               TEXT NOT NULL DEFAULT '',
    version           INTEGER NOT NULL DEFAULT 0,
    payload_b64       TEXT NOT NULL DEFAULT '',
    signature         TEXT NOT NULL DEFAULT '',
    updated           REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS profiles_name ON profiles(primary_name_key);

CREATE TABLE IF NOT EXISTS keystore_entries (
    owner_id    TEXT NOT NULL,
    name        TEXT NOT NULL,
    ciphertext  BLOB NOT NULL,
    sha256      TEXT NOT NULL,
    version     INTEGER NOT NULL,
    created     REAL NOT NULL,
    updated     REAL NOT NULL,
    PRIMARY KEY(owner_id, name)
);
CREATE INDEX IF NOT EXISTS keystore_owner_updated
    ON keystore_entries(owner_id, updated DESC, name);

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
    signed    TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS post_tags (
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    tag     TEXT NOT NULL,
    PRIMARY KEY(post_id, tag)
);
CREATE INDEX IF NOT EXISTS post_tags_tag_post ON post_tags(tag, post_id DESC);

CREATE TABLE IF NOT EXISTS post_likes (
    post_id   INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    author_id TEXT NOT NULL,
    created   REAL NOT NULL,
    PRIMARY KEY(post_id, author_id)
);
CREATE INDEX IF NOT EXISTS post_likes_author_post ON post_likes(author_id, post_id DESC);

CREATE TABLE IF NOT EXISTS webhooks (
    id                TEXT PRIMARY KEY,
    owner_id          TEXT NOT NULL,
    url               TEXT NOT NULL,
    events            TEXT NOT NULL,
    secret_nonce      BLOB NOT NULL,
    secret_ciphertext BLOB NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    created           REAL NOT NULL,
    updated           REAL NOT NULL,
    last_error        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS webhooks_owner ON webhooks(owner_id, created);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id           TEXT PRIMARY KEY,
    webhook_id   TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    subject_id   TEXT NOT NULL,
    event        TEXT NOT NULL,
    data         TEXT NOT NULL,
    created      REAL NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    next_attempt REAL NOT NULL,
    delivered    REAL,
    last_error   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS webhook_due
    ON webhook_deliveries(delivered, next_attempt, created);


CREATE TABLE IF NOT EXISTS websub_subscriptions (
    id                TEXT PRIMARY KEY,
    topic             TEXT NOT NULL,
    callback          TEXT NOT NULL,
    secret_nonce      BLOB NOT NULL DEFAULT X'',
    secret_ciphertext BLOB NOT NULL DEFAULT X'',
    created           REAL NOT NULL,
    updated           REAL NOT NULL,
    expires           REAL NOT NULL,
    UNIQUE(topic, callback)
);
CREATE INDEX IF NOT EXISTS websub_subscriptions_topic
    ON websub_subscriptions(topic, expires);

CREATE TABLE IF NOT EXISTS websub_verifications (
    id                TEXT PRIMARY KEY,
    mode              TEXT NOT NULL,
    topic             TEXT NOT NULL,
    callback          TEXT NOT NULL,
    lease_seconds     INTEGER NOT NULL,
    challenge         TEXT NOT NULL,
    secret_nonce      BLOB NOT NULL DEFAULT X'',
    secret_ciphertext BLOB NOT NULL DEFAULT X'',
    created           REAL NOT NULL,
    attempts          INTEGER NOT NULL DEFAULT 0,
    next_attempt      REAL NOT NULL,
    last_error        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS websub_verifications_due
    ON websub_verifications(next_attempt, created);

CREATE TABLE IF NOT EXISTS websub_deliveries (
    id              TEXT PRIMARY KEY,
    subscription_id TEXT NOT NULL REFERENCES websub_subscriptions(id) ON DELETE CASCADE,
    topic           TEXT NOT NULL,
    created         REAL NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt    REAL NOT NULL,
    delivered       REAL,
    last_error      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS websub_deliveries_due
    ON websub_deliveries(delivered, next_attempt, created);

CREATE TABLE IF NOT EXISTS websub_hub_pings (
    id           TEXT PRIMARY KEY,
    hub          TEXT NOT NULL,
    topic        TEXT NOT NULL,
    generation   INTEGER NOT NULL DEFAULT 1,
    created      REAL NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    next_attempt REAL NOT NULL,
    delivered    REAL,
    last_error   TEXT NOT NULL DEFAULT '',
    UNIQUE(hub, topic)
);
CREATE INDEX IF NOT EXISTS websub_hub_pings_due
    ON websub_hub_pings(delivered, next_attempt, created);


CREATE TABLE IF NOT EXISTS path_get_receipts (
    request_id     TEXT PRIMARY KEY,
    payload_sha256 TEXT NOT NULL,
    operation      TEXT NOT NULL,
    status         INTEGER,
    content_type   TEXT,
    body           BLOB,
    headers        TEXT NOT NULL DEFAULT '{}',
    created        REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS path_get_chunks (
    request_id  TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    chunk_count INTEGER NOT NULL,
    data        BLOB NOT NULL,
    created     REAL NOT NULL,
    PRIMARY KEY (request_id, chunk_index)
);
CREATE INDEX IF NOT EXISTS path_get_chunks_created
    ON path_get_chunks(created);
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
    created: float
    uploader_name: str
    uploader_id: str | None
    downloads: int

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
            "post_id": self.post_id,
            "slot": self.slot,
            **self.manifest(),
            "uploaded_at": round(self.created, 3),
            "downloads": self.downloads,
            "uploader": {
                "name": self.uploader_name,
                "author_id": self.uploader_id,
                "signed": self.uploader_id is not None,
            },
            "url": f"/file/{self.id}",
            "meta": f"/file/{self.id}/meta",
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
            "ref": f"post:{self.id}",
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


def board_name_error(name: str) -> str:
    if name != name.lower():
        return "channel name must be lowercase"
    if len(name) < 2 or len(name) > 24:
        return "channel name must be 2..24 characters"
    if not name or not ("a" <= name[0] <= "z"):
        return "channel name must start with a lowercase ASCII letter"
    if any(char not in "abcdefghijklmnopqrstuvwxyz0123456789" for char in name):
        return "channel name may contain only lowercase ASCII letters and digits"
    if name in RESERVED_BOARDS:
        return "channel name is reserved"
    return "invalid channel name"


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
            had_tags = (
                self._conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='post_tags'"
                ).fetchone()
                is not None
            )
            had_claims = (
                self._conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='name_claims'"
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
            self._migrate_identity_names()
            if not had_inbox or not had_claims:
                self._rebuild_inbox()
            if not had_tags:
                self._rebuild_tags()

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

        attachment_additions = {
            "created": "REAL NOT NULL DEFAULT 0",
            "uploader_name": "TEXT NOT NULL DEFAULT 'anonymous'",
            "uploader_id": "TEXT",
            "downloads": "INTEGER NOT NULL DEFAULT 0",
        }
        for table, post_table in (
            ("attachments", "posts"),
            ("archived_attachments", "archived_posts"),
        ):
            attachment_columns = {
                str(row["name"])
                for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for name, definition in attachment_additions.items():
                if name not in attachment_columns:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
            self._conn.execute(
                f"""
                UPDATE {table}
                   SET created = COALESCE(
                       (SELECT updated FROM {post_table} p WHERE p.id = {table}.post_id),
                       0
                   )
                 WHERE created = 0
                """
            )
            self._conn.execute(
                f"""
                UPDATE {table}
                   SET uploader_name = COALESCE(
                       NULLIF(uploader_name, ''),
                       (SELECT name FROM {post_table} p WHERE p.id = {table}.post_id),
                       'anonymous'
                   )
                 WHERE uploader_name IN ('', 'anonymous') OR uploader_name IS NULL
                """
            )
            self._conn.execute(
                f"""
                UPDATE {table}
                   SET uploader_id = (
                       SELECT author_id FROM {post_table} p WHERE p.id = {table}.post_id
                   )
                 WHERE uploader_id IS NULL
                """
            )

        self._conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS attachments_created ON attachments(created, id);
            CREATE INDEX IF NOT EXISTS attachments_name ON attachments(name, id);
            CREATE INDEX IF NOT EXISTS attachments_uploader ON attachments(uploader_id, id);
            CREATE INDEX IF NOT EXISTS attachments_downloads ON attachments(downloads, id);
            """
        )

        revocation_columns = {
            str(row["name"])
            for row in self._conn.execute("PRAGMA table_info(revocations)").fetchall()
        }
        if revocation_columns and "reason" not in revocation_columns:
            self._conn.execute("ALTER TABLE revocations ADD COLUMN reason TEXT NOT NULL DEFAULT ''")

        policy_columns = {
            str(row["name"])
            for row in self._conn.execute("PRAGMA table_info(topic_policies)").fetchall()
        }
        if policy_columns and "signed" not in policy_columns:
            default_signed = json.dumps(sorted(DEFAULT_SIGNED), separators=(",", ":"))
            self._conn.execute(
                "ALTER TABLE topic_policies ADD COLUMN signed TEXT NOT NULL DEFAULT "
                + repr(default_signed)
            )

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
            CREATE TABLE IF NOT EXISTS name_claims (
                name_key TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                author_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                claim_post_id INTEGER REFERENCES posts(id) ON DELETE SET NULL,
                claim_signature TEXT NOT NULL DEFAULT '',
                claimed REAL NOT NULL,
                last_used REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS name_claims_author
                ON name_claims(author_id, claimed);
            CREATE TABLE IF NOT EXISTS profiles (
                author_id TEXT PRIMARY KEY,
                primary_name_key TEXT NOT NULL,
                bio TEXT NOT NULL DEFAULT '',
                version INTEGER NOT NULL DEFAULT 0,
                payload_b64 TEXT NOT NULL DEFAULT '',
                signature TEXT NOT NULL DEFAULT '',
                updated REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS profiles_name
                ON profiles(primary_name_key);
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

            CREATE TABLE IF NOT EXISTS post_tags (
                post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                tag TEXT NOT NULL,
                PRIMARY KEY(post_id, tag)
            );
            CREATE INDEX IF NOT EXISTS post_tags_tag_post
                ON post_tags(tag, post_id DESC);

            CREATE TABLE IF NOT EXISTS post_likes (
                post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
                author_id TEXT NOT NULL,
                created REAL NOT NULL,
                PRIMARY KEY(post_id, author_id)
            );
            CREATE INDEX IF NOT EXISTS post_likes_author_post
                ON post_likes(author_id, post_id DESC);

            CREATE TABLE IF NOT EXISTS webhooks (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                url TEXT NOT NULL,
                events TEXT NOT NULL,
                secret_nonce BLOB NOT NULL,
                secret_ciphertext BLOB NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created REAL NOT NULL,
                updated REAL NOT NULL,
                last_error TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS webhooks_owner
                ON webhooks(owner_id, created);
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                id TEXT PRIMARY KEY,
                webhook_id TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
                subject_id TEXT NOT NULL,
                event TEXT NOT NULL,
                data TEXT NOT NULL,
                created REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt REAL NOT NULL,
                delivered REAL,
                last_error TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS webhook_due
                ON webhook_deliveries(delivered, next_attempt, created);

            CREATE TABLE IF NOT EXISTS path_get_receipts (
                request_id TEXT PRIMARY KEY,
                payload_sha256 TEXT NOT NULL,
                operation TEXT NOT NULL,
                status INTEGER,
                content_type TEXT,
                body BLOB,
                headers TEXT NOT NULL DEFAULT '{}',
                created REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS path_get_chunks (
                request_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_count INTEGER NOT NULL,
                data BLOB NOT NULL,
                created REAL NOT NULL,
                PRIMARY KEY (request_id, chunk_index)
            );
            CREATE INDEX IF NOT EXISTS path_get_chunks_created
                ON path_get_chunks(created);
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

    @staticmethod
    def normalize_tag(value: str) -> str:
        tag = unicodedata.normalize("NFC", value.strip()).casefold()
        if not tag or len(tag) > 32 or len(tag.encode("utf-8")) > 96:
            raise StoreError("tag must be 1..32 characters and at most 96 UTF-8 bytes", 400)
        if not all(char.isalnum() or char in {"_", "-"} for char in tag):
            raise StoreError("tag may contain letters, numbers, underscore, or hyphen", 400)
        if not tag[0].isalnum() and tag[0] != "_":
            raise StoreError("tag must start with a letter, number, or underscore", 400)
        return tag

    @classmethod
    def extract_tags(cls, title: str, body: str) -> tuple[str, ...]:
        found: list[str] = []
        seen: set[str] = set()
        for match in HASHTAG_RE.finditer(title + "\n" + body):
            try:
                tag = cls.normalize_tag(match.group(1))
            except StoreError:
                continue
            if tag in seen:
                continue
            seen.add(tag)
            found.append(tag)
            if len(found) >= MAX_TAGS_PER_POST:
                break
        return tuple(found)

    def _reindex_tags(self, post_id: int) -> None:
        self._conn.execute("DELETE FROM post_tags WHERE post_id = ?", (post_id,))
        row = self._conn.execute(
            "SELECT title, body FROM posts WHERE id = ?",
            (post_id,),
        ).fetchone()
        if row is None:
            return
        tags = self.extract_tags(str(row["title"]), str(row["body"]))
        if tags:
            self._conn.executemany(
                "INSERT INTO post_tags(post_id, tag) VALUES (?, ?)",
                [(post_id, tag) for tag in tags],
            )

    def _rebuild_tags(self) -> None:
        self._conn.execute("DELETE FROM post_tags")
        rows = self._conn.execute("SELECT id FROM posts ORDER BY id").fetchall()
        for row in rows:
            self._reindex_tags(int(row["id"]))

    def post_tags(self, post_id: int) -> tuple[str, ...]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT tag FROM post_tags WHERE post_id = ? ORDER BY tag",
                (post_id,),
            ).fetchall()
        return tuple(str(row["tag"]) for row in rows)

    def tags_for_posts(
        self,
        post_ids: list[int] | tuple[int, ...],
    ) -> dict[int, tuple[str, ...]]:
        ids = list(dict.fromkeys(int(post_id) for post_id in post_ids if post_id > 0))
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT post_id, tag
                  FROM post_tags
                 WHERE post_id IN ({placeholders})
                 ORDER BY post_id, tag
                """,
                ids,
            ).fetchall()
        result: dict[int, list[str]] = {post_id: [] for post_id in ids}
        for row in rows:
            result.setdefault(int(row["post_id"]), []).append(str(row["tag"]))
        return {post_id: tuple(tags) for post_id, tags in result.items()}

    def list_tags(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT t.tag, COUNT(*) AS posts,
                       COUNT(DISTINCT p.board) AS boards,
                       MAX(p.updated) AS last_ts,
                       MAX(p.id) AS latest_id
                  FROM post_tags t
                  JOIN posts p ON p.id = t.post_id
                 GROUP BY t.tag
                 ORDER BY posts DESC, last_ts DESC, t.tag
                 LIMIT ?
                """,
                (max(1, min(limit, self.cfg.max_limit)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def tag_info(self, tag: str) -> dict[str, Any] | None:
        normalized = self.normalize_tag(tag)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT t.tag, COUNT(*) AS posts,
                       COUNT(DISTINCT p.board) AS boards,
                       MAX(p.updated) AS last_ts,
                       MAX(p.id) AS latest_id
                  FROM post_tags t
                  JOIN posts p ON p.id = t.post_id
                 WHERE t.tag = ?
                 GROUP BY t.tag
                """,
                (normalized,),
            ).fetchone()
        return dict(row) if row is not None else None

    def posts_by_tag(
        self,
        tag: str,
        *,
        since: int | None = None,
        before: int | None = None,
        limit: int = 20,
        order: str = "desc",
    ) -> list[Post]:
        normalized = self.normalize_tag(tag)
        where = ["t.tag = ?"]
        params: list[Any] = [normalized]
        if since is not None:
            where.append("p.id > ?")
            params.append(since)
        if before is not None:
            where.append("p.id < ?")
            params.append(before)
        sql = (
            self._select_posts().replace(" FROM posts", " FROM posts p")
            + " JOIN post_tags t ON t.post_id = p.id"
            + " WHERE "
            + " AND ".join(where)
            + " ORDER BY p.id "
            + ("ASC" if order == "asc" else "DESC")
            + " LIMIT ?"
        )
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [post for row in rows if (post := self._row(row)) is not None]

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

    def root_profile(self) -> dict[str, Any] | None:
        """Return the server-managed profile for the configured Root CA."""
        root = self.root_info()
        if root is None:
            return None
        root_id = root["root_id"]
        return {
            "name": "root",
            "name_key": "root",
            "bio": f"Root CA trust anchor for {self.cfg.site_name}.",
            "public_key": root["public_key"],
            "keystore_public_key": curve25519_public_key(root["public_key"]),
            "author_id": root_id,
            "profile_url": "/@root",
            "aliases": ["root"],
            "claim_post_id": None,
            "claim_signature": "",
            "profile_version": 0,
            "profile_payload_b64": "",
            "profile_signature": "",
            "profile_signed": False,
            "updated": None,
            "system": True,
            "root_ca": {
                **root,
                "trust_anchor": True,
                "ca_url": "/_ca",
                "audit_url": "/ca",
            },
            "certification": self.certification(root_id),
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
                SELECT id, post_id, slot, name, content_type, data, nbytes, sha256,
                       created, uploader_name, uploader_id, downloads
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
                SELECT id, post_id, slot, name, content_type, data, nbytes, sha256,
                       created, uploader_name, uploader_id, downloads
                  FROM attachments
                 WHERE id = ?
                """,
                (file_id,),
            ).fetchone()
        return self._attachment(row) if row else None

    def attachment_manifest(self, post_id: int) -> tuple[dict[str, object], ...]:
        return tuple(file.manifest() for file in self.attachments(post_id))

    @staticmethod
    def _attachment_metadata_row(row: sqlite3.Row) -> dict[str, Any]:
        uploader_id = str(row["uploader_id"]) if row["uploader_id"] is not None else None
        uploader_name = str(row["uploader_name"] or "anonymous")
        file_id = int(row["id"])
        post_id = int(row["post_id"])
        board = str(row["board"])
        return {
            "id": file_id,
            "post_id": post_id,
            "slot": int(row["slot"]),
            "name": str(row["name"]),
            "type": str(row["content_type"]),
            "bytes": int(row["nbytes"]),
            "sha256": str(row["sha256"]),
            "uploaded_at": round(float(row["created"]), 6),
            "downloads": int(row["downloads"]),
            "uploader": {
                "name": uploader_name,
                "author_id": uploader_id,
                "signed": uploader_id is not None,
            },
            "board": board,
            "url": f"/file/{file_id}",
            "meta": f"/file/{file_id}/meta",
            "post": f"/{board}/{post_id}",
        }

    def attachment_metadata(self, file_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT a.id, a.post_id, a.slot, a.name, a.content_type, a.nbytes,
                       a.sha256, a.created, a.uploader_name, a.uploader_id,
                       a.downloads, p.board
                  FROM attachments a
                  JOIN posts p ON p.id = a.post_id
                 WHERE a.id = ? AND p.system = 0
                """,
                (file_id,),
            ).fetchone()
        return self._attachment_metadata_row(row) if row is not None else None

    def list_attachment_metadata(
        self,
        *,
        sort: str = "time",
        cursor: tuple[object, int] | None = None,
        limit: int = 20,
        order: str = "desc",
        uploader_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if sort not in {"id", "time", "name", "uploader", "downloads"}:
            raise StoreError("unsupported file index", 500)
        if order not in {"asc", "desc"}:
            raise StoreError("order must be asc or desc", 400)

        expressions = {
            "id": "a.id",
            "time": "a.created",
            "name": "a.name",
            "uploader": "a.uploader_name",
            "downloads": "a.downloads",
        }
        expression = expressions[sort]
        where = ["p.system = 0"]
        params: list[Any] = []
        if uploader_id is not None:
            where.append("a.uploader_id = ?")
            params.append(uploader_id)
        if cursor is not None:
            value, file_id = cursor
            operator = ">" if order == "asc" else "<"
            where.append(
                f"({expression} {operator} ? OR "
                f"({expression} = ? AND a.id {operator} ?))"
            )
            params.extend((value, value, file_id))

        direction = "ASC" if order == "asc" else "DESC"
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT a.id, a.post_id, a.slot, a.name, a.content_type, a.nbytes,
                       a.sha256, a.created, a.uploader_name, a.uploader_id,
                       a.downloads, p.board
                  FROM attachments a
                  JOIN posts p ON p.id = a.post_id
                 WHERE {" AND ".join(where)}
                 ORDER BY {expression} {direction}, a.id {direction}
                 LIMIT ?
                """,
                params,
            ).fetchall()
        return [self._attachment_metadata_row(row) for row in rows]

    def record_attachment_download(self, file_id: int) -> int | None:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE attachments SET downloads = downloads + 1 WHERE id = ?",
                (file_id,),
            )
            if cur.rowcount != 1:
                return None
            row = self._conn.execute(
                "SELECT downloads FROM attachments WHERE id = ?",
                (file_id,),
            ).fetchone()
        return int(row["downloads"]) if row is not None else None

    def _storage_bytes(self) -> int:
        row = self._conn.execute(
            """
            SELECT
                COALESCE((SELECT SUM(nbytes) FROM posts WHERE system = 0), 0)
              + COALESCE((SELECT SUM(nbytes) FROM attachments), 0)
              + COALESCE((SELECT SUM(nbytes) FROM archived_posts WHERE system = 0), 0)
              + COALESCE((SELECT SUM(nbytes) FROM archived_attachments), 0) AS n
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

    def _insert_attachments(
        self,
        post_id: int,
        files: tuple[FileInput, ...],
        *,
        uploaded_at: float,
        uploader_name: str,
        uploader_id: str | None,
    ) -> None:
        for slot, file in enumerate(files):
            self._conn.execute(
                """
                INSERT INTO attachments(
                    post_id, slot, name, content_type, data, nbytes, sha256,
                    created, uploader_name, uploader_id, downloads
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    post_id,
                    slot,
                    file.name,
                    file.content_type,
                    file.data,
                    file.nbytes,
                    file.sha256,
                    uploaded_at,
                    uploader_name,
                    uploader_id,
                ),
            )

    def _ensure_board(self, name: str, description: str = "") -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO boards(name, description, created) VALUES (?, ?, ?)",
            (name, description, time.time()),
        )

    def ensure_board(self, name: str) -> None:
        if not valid_board_name(name):
            raise StoreError(board_name_error(name), 400)
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
                       COALESCE(MAX(p.updated), 0) AS last_ts,
                       COALESCE(MAX(p.id), 0) AS latest_id
                  FROM boards b
                  LEFT JOIN posts p ON p.board = b.name
                 GROUP BY b.name
                 ORDER BY b.name
                """
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            policy = self.policy(str(row["name"]))
            item["permissions"] = policy["permissions"]
            item["anonymous_permissions"] = policy["anonymous_permissions"]
            item["signed_permissions"] = policy["signed_permissions"]
            result.append(item)
        return result

    def board_info(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT name, description, created FROM boards WHERE name = ?", (name,)
            ).fetchone()
        return dict(row) if row else None

    def policy(self, board: str) -> dict[str, Any]:
        def result(
            anonymous: Iterable[str],
            signed: Iterable[str],
            *,
            version: int,
            updated: float | None,
            locked: bool,
        ) -> dict[str, Any]:
            anonymous_values = sorted(set(anonymous))
            signed_values = sorted(set(signed))
            return {
                "board": board,
                "permissions": anonymous_permission_mask(anonymous_values),
                "anonymous_permissions": base_permission_mask(anonymous_values),
                "signed_permissions": base_permission_mask(signed_values),
                "anonymous": anonymous_values,
                "signed": signed_values,
                "version": version,
                "updated": updated,
                "locked": locked,
            }

        if board in {"ca", "custody"}:
            return result((), (), version=0, updated=None, locked=True)
        if board == "guest":
            return result(GUEST_ANONYMOUS, (), version=0, updated=None, locked=True)
        with self._lock:
            row = self._conn.execute(
                "SELECT anonymous, signed, version, updated FROM topic_policies WHERE board = ?",
                (board,),
            ).fetchone()
        if row is None:
            return result(DEFAULT_ANONYMOUS, DEFAULT_SIGNED, version=0, updated=None, locked=False)
        return result(
            json.loads(str(row["anonymous"])),
            json.loads(str(row["signed"])),
            version=int(row["version"]),
            updated=float(row["updated"]),
            locked=False,
        )

    def set_policy(
        self,
        board: str,
        anonymous: tuple[str, ...] | None,
        signed: tuple[str, ...] | None,
        version: int,
    ) -> dict[str, Any]:
        if board in {"ca", "custody", "guest"}:
            raise StoreError(f"/{board} policy is system-managed", 403)
        if not valid_board_name(board):
            raise StoreError(f"invalid board name: {board!r}", 400)
        current = self.policy(board)
        anonymous_values = set(current["anonymous"]) if anonymous is None else set(anonymous)
        signed_values = set(current["signed"]) if signed is None else set(signed)
        invalid_anonymous = anonymous_values - ANONYMOUS_BASE_ACTIONS
        if invalid_anonymous:
            raise StoreError(f"invalid anonymous actions: {sorted(invalid_anonymous)}", 400)
        invalid_signed = signed_values - SIGNED_BASE_ACTIONS
        if invalid_signed:
            raise StoreError(f"invalid signed base actions: {sorted(invalid_signed)}", 400)
        if version != int(current["version"]) + 1:
            raise StoreError("stale policy version", 409)
        self.ensure_board(board)
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO topic_policies(board, anonymous, signed, version, updated)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(board) DO UPDATE SET
                    anonymous = excluded.anonymous,
                    signed = excluded.signed,
                    version = excluded.version,
                    updated = excluded.updated
                """,
                (
                    board,
                    json.dumps(sorted(anonymous_values), separators=(",", ":")),
                    json.dumps(sorted(signed_values), separators=(",", ":")),
                    version,
                    now,
                ),
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
            if topic != "*" and not valid_board_name(topic):
                raise StoreError(f"invalid/reserved channel grant: {topic!r}", 400)
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
            self._reindex_tags(post_id)
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
        never_certified = actor.get("status") == "none"
        return {
            "type": "certificate-signed" if certified else "signed",
            "signed": True,
            "certified": certified,
            "status": "certified"
            if certified
            else ("signed" if never_certified else "signed-inactive"),
            "server_accepted_signature": True,
            "basis": (
                "current-active-certificate-chain"
                if certified
                else (
                    "self-custodied-ed25519-signature"
                    if never_certified
                    else "stored-signature-current-chain-inactive"
                )
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
            "credential": "login",
            "save_as": "~/.config/msg.lmm.best/custody.token",
            "fallback_save_as": "./.config/msg.lmm.best/custody.token",
            "warning": (
                "capability token is a login credential; save it before use. "
                "server holds the signing key; this is not self-custody"
            ),
        }

    def _custody_row(self, token: str) -> sqlite3.Row:
        if len(token) < 32 or len(token) > 128:
            raise StoreError("invalid custody token", 403)
        token_hash = hashlib.sha256(b"custody-auth\0" + token.encode("utf-8")).hexdigest()
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

    def _custody_private(self, row: sqlite3.Row, token: str) -> bytes:
        token_bytes = token.encode("utf-8")
        key_key = hashlib.sha256(b"custody-key\0" + token_bytes).digest()
        try:
            return AESGCM(key_key).decrypt(
                bytes(row["key_nonce"]),
                bytes(row["key_ciphertext"]),
                str(row["id"]).encode("ascii"),
            )
        except ValueError as exc:
            raise StoreError("invalid custody token", 403) from exc

    def rotate_custody_token(self, token: str) -> dict[str, Any]:
        row = self._custody_row(token)
        private = self._custody_private(row, token)

        new_token = secrets.token_urlsafe(32)
        new_bytes = new_token.encode("utf-8")
        new_hash = hashlib.sha256(b"custody-auth\0" + new_bytes).hexdigest()
        new_key = hashlib.sha256(b"custody-key\0" + new_bytes).digest()
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(new_key).encrypt(
            nonce,
            private,
            str(row["id"]).encode("ascii"),
        )
        old_hash = hashlib.sha256(b"custody-auth\0" + token.encode("utf-8")).hexdigest()
        now = time.time()

        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                UPDATE custody_identities
                   SET token_hash = ?, key_nonce = ?, key_ciphertext = ?, last_used = ?
                 WHERE id = ? AND token_hash = ?
                """,
                (new_hash, nonce, ciphertext, now, str(row["id"]), old_hash),
            )
        if cur.rowcount != 1:
            raise StoreError("custody token was already rotated", 409)

        return {
            "id": str(row["id"]),
            "token": new_token,
            "author_id": str(row["author_id"]),
            "rotated": round(now, 3),
            "auth": "custodial",
            "credential": "login",
            "save_as": "~/.config/msg.lmm.best/custody.token",
            "fallback_save_as": "./.config/msg.lmm.best/custody.token",
            "warning": "old login credential is invalid now; save this new token before use",
        }

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
        private = self._custody_private(row, token)
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
        permissions = set(self.policy(board)["signed"])
        permissions.update(self.permissions_for(signer_id, board))
        if action == "post.edit":
            return "post.edit.any" in permissions or (
                owner_id == signer_id and "post.edit.self" in permissions
            )
        if action in {"post.delete", "post.purge"}:
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

    @staticmethod
    def normalize_identity_name(value: str) -> str:
        display = " ".join(unicodedata.normalize("NFKC", value).split())
        if not display:
            raise StoreError("name is required", 400)
        if display.casefold().startswith("[anon]"):
            raise StoreError("signed names may not use the reserved [anon] prefix", 400)
        if any(char in display for char in "/?#@"):
            raise StoreError("name may not contain / ? # or @", 400)
        if any(unicodedata.category(char).startswith("C") for char in display):
            raise StoreError("name may not contain control/format characters", 400)
        return display.casefold()

    @staticmethod
    def anonymous_base_name(value: str) -> str:
        display = " ".join(value.split()) or "anonymous"
        while display.casefold().startswith("[anon]"):
            display = display[6:].strip()
        while display.casefold().startswith("[custody]"):
            display = display[9:].strip()
        return display or "anonymous"

    def anonymous_display_name(self, value: str, *, check_claim: bool = True) -> str:
        del value, check_claim
        return "[anon] anonymous"

    def name_claim(self, name_or_key: str) -> dict[str, Any] | None:
        try:
            name_key = self.normalize_identity_name(name_or_key)
        except StoreError:
            name_key = name_or_key.casefold()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT name_key, display_name, author_id, public_key, claim_post_id,
                       claim_signature, claimed, last_used
                  FROM name_claims
                 WHERE name_key = ?
                """,
                (name_key,),
            ).fetchone()
        return dict(row) if row is not None else None

    def _claim_identity_name(
        self,
        *,
        author_id: str,
        public_key: str,
        name: str,
        signature: str,
        seen: float,
        post_id: int | None = None,
    ) -> str:
        name_key = self.normalize_identity_name(name)
        if name_key == "anonymous":
            return name_key
        if name_key == "root":
            root = self.root_info()
            if root is None or author_id != root["root_id"]:
                raise StoreError("name 'root' is reserved for the Root CA", 409)
            # Root is a server-managed trust anchor, not a normal claimed profile.
            return name_key
        row = self._conn.execute(
            """
            SELECT display_name, author_id, public_key
              FROM name_claims
             WHERE name_key = ?
            """,
            (name_key,),
        ).fetchone()
        if row is not None and str(row["author_id"]) != author_id:
            raise StoreError(
                f"name {name!r} is already bound to public key {row['public_key']} "
                f"(author_id {row['author_id']})",
                409,
            )
        if row is None:
            self._conn.execute(
                """
                INSERT INTO name_claims(
                    name_key, display_name, author_id, public_key, claim_post_id,
                    claim_signature, claimed, last_used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name_key,
                    name,
                    author_id,
                    public_key,
                    post_id,
                    signature,
                    seen,
                    seen,
                ),
            )
            self._conn.execute(
                """
                INSERT OR IGNORE INTO profiles(
                    author_id, primary_name_key, bio, version, payload_b64,
                    signature, updated
                ) VALUES (?, ?, '', 0, '', '', ?)
                """,
                (author_id, name_key, seen),
            )
        else:
            self._conn.execute(
                """
                UPDATE name_claims
                   SET last_used = ?,
                       claim_post_id = COALESCE(claim_post_id, ?),
                       claim_signature = CASE
                           WHEN claim_signature = '' THEN ?
                           ELSE claim_signature
                       END
                 WHERE name_key = ? AND author_id = ?
                """,
                (seen, post_id, signature, name_key, author_id),
            )
        return name_key

    def _migrate_identity_names(self) -> None:
        # Every unsigned author is intentionally one indistinguishable identity.
        self._conn.execute(
            """
            UPDATE posts
               SET name = '[anon] anonymous'
             WHERE author_id IS NULL AND system = 0 AND custody_id IS NULL
            """
        )

        # Historical self-signed names are claimed oldest-first; earliest proof wins.
        signed = self._conn.execute(
            """
            SELECT id, name, author_id, author_key, signature, created
              FROM posts
             WHERE author_id IS NOT NULL
               AND author_key IS NOT NULL
               AND actor_id = author_id
               AND signature IS NOT NULL
             ORDER BY id
            """
        ).fetchall()
        for row in signed:
            name = str(row["name"])
            if self.anonymous_base_name(name).casefold() == "anonymous":
                continue
            try:
                self._claim_identity_name(
                    author_id=str(row["author_id"]),
                    public_key=str(row["author_key"]),
                    name=name,
                    signature=str(row["signature"]),
                    seen=float(row["created"]),
                    post_id=int(row["id"]),
                )
            except StoreError as exc:
                if exc.status not in {400, 409}:
                    raise

    def list_users(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT p.author_id,
                       pr.primary_name_key,
                       nc.display_name AS name,
                       nc.public_key,
                       pr.bio,
                       COUNT(p.id) AS posts,
                       MIN(p.created) AS first_post,
                       MAX(p.updated) AS last_post
                  FROM posts p
                  JOIN profiles pr ON pr.author_id = p.author_id
                  JOIN name_claims nc
                    ON nc.author_id = pr.author_id
                   AND nc.name_key = pr.primary_name_key
                 WHERE p.author_id IS NOT NULL
                   AND p.system = 0
                   AND p.custody_id IS NULL
                 GROUP BY p.author_id, pr.primary_name_key, nc.display_name,
                          nc.public_key, pr.bio
                 ORDER BY last_post DESC, nc.display_name COLLATE NOCASE
                 LIMIT ?
                """,
                (max(1, min(limit, self.cfg.max_limit)),),
            ).fetchall()
        return [
            {
                "name": str(row["name"]),
                "author_id": str(row["author_id"]),
                "public_key": str(row["public_key"]),
                "bio": str(row["bio"]),
                "posts": int(row["posts"]),
                "first_post": round(float(row["first_post"]), 3),
                "last_post": round(float(row["last_post"]), 3),
                "profile": f"/@{quote(str(row['name']), safe='')}",
                "posts_url": f"/users/{quote(str(row['name']), safe='')}",
            }
            for row in rows
        ]

    def posts_by_username(
        self,
        name: str,
        *,
        since: int | None = None,
        before: int | None = None,
        limit: int = 20,
        order: str = "desc",
    ) -> tuple[dict[str, Any], list[Post]]:
        profile = self.profile_by_name(name)
        if profile is None:
            raise StoreError(f"unknown signed username: {name}", 404)
        author_id = str(profile["author_id"])
        posts = self.list_posts(
            author_id=author_id,
            since=since,
            before=before,
            limit=limit,
            order=order,
        )
        posts = [post for post in posts if post.custody_id is None and post.system is False]
        return profile, posts

    def profile_by_name(self, name: str) -> dict[str, Any] | None:
        try:
            name_key = self.normalize_identity_name(name)
        except StoreError:
            return None
        if name_key == "root":
            return self.root_profile()
        claim = self.name_claim(name_key)
        if claim is None:
            return None
        return self.profile_by_author(str(claim["author_id"]))

    def profile_by_author(self, author_id: str) -> dict[str, Any] | None:
        if not valid_author_id(author_id):
            return None
        root = self.root_info()
        if root is not None and author_id == root["root_id"]:
            return self.root_profile()
        with self._lock:
            profile = self._conn.execute(
                """
                SELECT author_id, primary_name_key, bio, version, payload_b64,
                       signature, updated
                  FROM profiles
                 WHERE author_id = ?
                """,
                (author_id,),
            ).fetchone()
            claims = self._conn.execute(
                """
                SELECT name_key, display_name, public_key, claim_post_id,
                       claim_signature, claimed, last_used
                  FROM name_claims
                 WHERE author_id = ?
                 ORDER BY claimed, name_key
                """,
                (author_id,),
            ).fetchall()
        if profile is None or not claims:
            return None
        claim_items = [dict(row) for row in claims]
        primary_key = str(profile["primary_name_key"])
        primary = next(
            (item for item in claim_items if str(item["name_key"]) == primary_key),
            claim_items[0],
        )
        return {
            "name": str(primary["display_name"]),
            "name_key": str(primary["name_key"]),
            "bio": str(profile["bio"]),
            "public_key": str(primary["public_key"]),
            "keystore_public_key": curve25519_public_key(str(primary["public_key"])),
            "author_id": author_id,
            "profile_url": f"/@{quote(str(primary['display_name']), safe='')}",
            "aliases": [str(item["display_name"]) for item in claim_items],
            "claim_post_id": primary["claim_post_id"],
            "claim_signature": str(primary["claim_signature"]),
            "profile_version": int(profile["version"]),
            "profile_payload_b64": str(profile["payload_b64"]),
            "profile_signature": str(profile["signature"]),
            "profile_signed": bool(profile["signature"]),
            "updated": round(float(profile["updated"]), 3),
            "certification": self.certification(author_id),
        }

    @staticmethod
    def normalize_keystore_name(value: str) -> str:
        name = value.strip().casefold()
        if name == "pubkey":
            raise StoreError("keystore name 'pubkey' is reserved", 400)
        if not KEYSTORE_NAME_RE.fullmatch(name):
            raise StoreError(
                "keystore name must be 1..64 lowercase letters, digits, dot, underscore, or hyphen",
                400,
            )
        return name

    @staticmethod
    def prepare_keystore_ciphertext(
        value: str,
        expected_sha256: str = "",
    ) -> tuple[bytes, str, str]:
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise StoreError("keystore ciphertext must be valid base64", 400) from exc
        if len(raw) < 48:
            raise StoreError("keystore ciphertext is too short for a sealed box", 400)
        if len(raw) > KEYSTORE_MAX_ENTRY_BYTES:
            raise StoreError(
                f"keystore ciphertext exceeds {KEYSTORE_MAX_ENTRY_BYTES} bytes",
                413,
            )
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 and expected_sha256.casefold() != digest:
            raise StoreError("keystore ciphertext sha256 mismatch", 400)
        return raw, base64.b64encode(raw).decode("ascii"), digest

    def keystore_version(self, owner_id: str, name: str) -> int:
        name = self.normalize_keystore_name(name)
        with self._lock:
            row = self._conn.execute(
                "SELECT version FROM keystore_entries WHERE owner_id = ? AND name = ?",
                (owner_id, name),
            ).fetchone()
        return int(row["version"]) if row is not None else 0

    def keystore_list(self, owner_id: str) -> list[dict[str, Any]]:
        if not valid_author_id(owner_id):
            return []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT name, sha256, version, length(ciphertext) AS nbytes, created, updated
                  FROM keystore_entries
                 WHERE owner_id = ?
                 ORDER BY name
                """,
                (owner_id,),
            ).fetchall()
        return [
            {
                "name": str(row["name"]),
                "format": KEYSTORE_FORMAT,
                "bytes": int(row["nbytes"]),
                "sha256": str(row["sha256"]),
                "version": int(row["version"]),
                "created": round(float(row["created"]), 3),
                "updated": round(float(row["updated"]), 3),
            }
            for row in rows
        ]

    def keystore_entry(self, owner_id: str, name: str) -> dict[str, Any] | None:
        name = self.normalize_keystore_name(name)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT name, ciphertext, sha256, version, created, updated
                  FROM keystore_entries
                 WHERE owner_id = ? AND name = ?
                """,
                (owner_id, name),
            ).fetchone()
        if row is None:
            return None
        ciphertext = bytes(row["ciphertext"])
        return {
            "name": str(row["name"]),
            "format": KEYSTORE_FORMAT,
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "bytes": len(ciphertext),
            "sha256": str(row["sha256"]),
            "version": int(row["version"]),
            "created": round(float(row["created"]), 3),
            "updated": round(float(row["updated"]), 3),
        }

    def keystore_put(
        self,
        *,
        auth: SignedRequest,
        name: str,
        ciphertext_b64: str,
        expected_sha256: str,
    ) -> dict[str, Any]:
        if self.profile_by_author(auth.signer_id) is None:
            raise StoreError("keystore requires an established signed profile", 403)
        name = self.normalize_keystore_name(name)
        ciphertext, _canonical, digest = self.prepare_keystore_ciphertext(
            ciphertext_b64,
            expected_sha256,
        )
        self.consume_nonce(auth)
        now = time.time()
        with self._lock, self._conn:
            current = self._conn.execute(
                "SELECT version, created FROM keystore_entries WHERE owner_id = ? AND name = ?",
                (auth.signer_id, name),
            ).fetchone()
            expected_version = int(current["version"] if current is not None else 0) + 1
            if auth.version != expected_version:
                raise StoreError("stale keystore version", 409)
            used = int(
                self._conn.execute(
                    """
                    SELECT COALESCE(SUM(length(ciphertext)), 0) AS n
                      FROM keystore_entries
                     WHERE owner_id = ? AND name <> ?
                    """,
                    (auth.signer_id, name),
                ).fetchone()["n"]
            )
            if used + len(ciphertext) > KEYSTORE_MAX_TOTAL_BYTES:
                raise StoreError(
                    f"keystore exceeds per-identity limit {KEYSTORE_MAX_TOTAL_BYTES} bytes",
                    413,
                )
            created = float(current["created"]) if current is not None else now
            self._conn.execute(
                """
                INSERT INTO keystore_entries(
                    owner_id, name, ciphertext, sha256, version, created, updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(owner_id, name) DO UPDATE SET
                    ciphertext = excluded.ciphertext,
                    sha256 = excluded.sha256,
                    version = excluded.version,
                    updated = excluded.updated
                """,
                (
                    auth.signer_id,
                    name,
                    ciphertext,
                    digest,
                    auth.version,
                    created,
                    now,
                ),
            )
        result = self.keystore_entry(auth.signer_id, name)
        assert result is not None
        return result

    def keystore_delete(self, *, auth: SignedRequest, name: str) -> dict[str, Any]:
        name = self.normalize_keystore_name(name)
        self.consume_nonce(auth)
        with self._lock, self._conn:
            current = self._conn.execute(
                "SELECT version FROM keystore_entries WHERE owner_id = ? AND name = ?",
                (auth.signer_id, name),
            ).fetchone()
            if current is None:
                raise StoreError("keystore entry not found", 404)
            if auth.version != int(current["version"]) + 1:
                raise StoreError("stale keystore version", 409)
            self._conn.execute(
                "DELETE FROM keystore_entries WHERE owner_id = ? AND name = ?",
                (auth.signer_id, name),
            )
        return {"ok": 1, "deleted": True, "name": name}

    def profile_version(self, author_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT version FROM profiles WHERE author_id = ?",
                (author_id,),
            ).fetchone()
        return int(row["version"]) if row is not None else 0

    def update_profile(
        self,
        *,
        auth: SignedRequest,
        name: str,
        bio: str,
        payload_b64: str,
    ) -> dict[str, Any]:
        if len(bio.encode("utf-8")) > 4096:
            raise StoreError("profile bio exceeds 4096 UTF-8 bytes", 413)
        name_key = self.normalize_identity_name(name)
        self.consume_nonce(auth)
        with self._lock, self._conn:
            claim = self._conn.execute(
                "SELECT author_id FROM name_claims WHERE name_key = ?",
                (name_key,),
            ).fetchone()
            if claim is None or str(claim["author_id"]) != auth.signer_id:
                raise StoreError("profile name must already be claimed by this public key", 403)
            current = self._conn.execute(
                "SELECT version FROM profiles WHERE author_id = ?",
                (auth.signer_id,),
            ).fetchone()
            expected = int(current["version"] if current is not None else 0) + 1
            if auth.version != expected:
                raise StoreError("stale profile version", 409)
            self._conn.execute(
                """
                INSERT INTO profiles(
                    author_id, primary_name_key, bio, version, payload_b64,
                    signature, updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(author_id) DO UPDATE SET
                    primary_name_key = excluded.primary_name_key,
                    bio = excluded.bio,
                    version = excluded.version,
                    payload_b64 = excluded.payload_b64,
                    signature = excluded.signature,
                    updated = excluded.updated
                """,
                (
                    auth.signer_id,
                    name_key,
                    bio,
                    auth.version,
                    payload_b64,
                    auth.signature,
                    time.time(),
                ),
            )
        profile = self.profile_by_author(auth.signer_id)
        assert profile is not None
        return profile

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
        if auth is None:
            name = self.anonymous_display_name(name, check_claim=False)
        elif custody_id is not None:
            base = self.anonymous_base_name(name)
            name = f"[custody] {base}"
        else:
            self.normalize_identity_name(name)
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
            if auth is None:
                base_name = self.anonymous_base_name(name)
                name_key = self.normalize_identity_name(base_name)
                claim = self._conn.execute(
                    "SELECT author_id, public_key FROM name_claims WHERE name_key = ?",
                    (name_key,),
                ).fetchone()
                if claim is not None:
                    raise StoreError(
                        f"name {base_name!r} is already bound to public key {claim['public_key']} "
                        f"(author_id {claim['author_id']})",
                        409,
                    )
            elif custody_id is None:
                self._claim_identity_name(
                    author_id=auth.signer_id,
                    public_key=auth.public_key,
                    name=name,
                    signature=auth.signature,
                    seen=now,
                )

            file_bytes = sum(file.nbytes for file in files)
            new_bytes = nbytes + file_bytes
            if new_bytes > self.cfg.max_storage_bytes:
                raise StoreError("post plus attachments exceed storage capacity", 507)
            used = self._storage_bytes()
            need = max(0, used + new_bytes - self.cfg.max_storage_bytes)
            if need:
                freed = 0
                archived_ids: list[int] = []
                archived_rows = self._conn.execute(
                    """
                    SELECT p.id, p.nbytes + COALESCE(SUM(a.nbytes), 0) AS nbytes
                      FROM archived_posts p
                      LEFT JOIN archived_attachments a ON a.post_id = p.id
                     WHERE p.system = 0
                     GROUP BY p.id
                     ORDER BY p.archived_at ASC, p.id ASC
                    """
                ).fetchall()
                for row in archived_rows:
                    archived_ids.append(int(row["id"]))
                    freed += int(row["nbytes"])
                    if freed >= need:
                        break
                if archived_ids:
                    marks = ",".join("?" for _ in archived_ids)
                    self._conn.execute(
                        f"DELETE FROM archived_posts WHERE id IN ({marks})",
                        archived_ids,
                    )

                active_ids: list[int] = []
                if freed < need:
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
                    for row in rows:
                        active_ids.append(int(row["id"]))
                        freed += int(row["nbytes"])
                        if freed >= need:
                            break
                    if active_ids:
                        marks = ",".join("?" for _ in active_ids)
                        self._conn.execute(f"DELETE FROM posts WHERE id IN ({marks})", active_ids)
                        self._prune_empty_boards()
                evicted = len(archived_ids) + len(active_ids)

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
            if auth is not None and custody_id is None:
                self._conn.execute(
                    """
                    UPDATE name_claims
                       SET claim_post_id = COALESCE(claim_post_id, ?),
                           last_used = ?
                     WHERE name_key = ? AND author_id = ?
                    """,
                    (
                        post_id,
                        now,
                        self.normalize_identity_name(name),
                        auth.signer_id,
                    ),
                )
                self._remember_identity_name(auth.signer_id, name, now)
            self._insert_attachments(
                post_id,
                files,
                uploaded_at=now,
                uploader_name=name,
                uploader_id=auth.signer_id if auth is not None else None,
            )
            self._reindex_inbox(post_id)
            self._reindex_tags(post_id)

        post = self.get_post(post_id)
        assert post is not None
        return post, evicted

    def get_post(self, post_id: int) -> Post | None:
        with self._lock:
            row = self._conn.execute(self._select_posts() + " WHERE id = ?", (post_id,)).fetchone()
        return self._row(row)

    def get_archived_post(self, post_id: int) -> Post | None:
        with self._lock:
            row = self._conn.execute(
                self._select_archived_posts() + " WHERE id = ?",
                (post_id,),
            ).fetchone()
        return self._row(row)

    def get_post_or_archived(self, post_id: int) -> Post | None:
        post = self.get_post(post_id)
        return post if post is not None else self.get_archived_post(post_id)

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
            if post.custody_id is not None:
                base = new_name
                while base.casefold().startswith("[custody]"):
                    base = base[9:].strip()
                new_name = f"[custody] {base or 'guest'}"
            if auth.version != post.sig_version + 1:
                raise StoreError("stale signature version", 409)
            if auth.signer_id != post.author_id and new_name != post.name:
                raise StoreError("only the post owner may change its bound display name", 403)
            self.normalize_identity_name(new_name)
        elif new_name != post.name:
            new_name = self.anonymous_display_name(new_name, check_claim=False)

        file_uploader_name = new_name
        if files is not None and auth is not None:
            uploader_profile = self.profile_by_author(auth.signer_id)
            file_uploader_name = (
                str(uploader_profile["name"])
                if uploader_profile is not None
                else auth.signer_id
            )

        with self._lock, self._conn:
            if (
                post.signed
                and post.custody_id is None
                and auth is not None
                and auth.signer_id == post.author_id
            ):
                self._claim_identity_name(
                    author_id=auth.signer_id,
                    public_key=post.author_key or auth.public_key,
                    name=new_name,
                    signature=auth.signature,
                    seen=time.time(),
                    post_id=post.id,
                )
            elif not post.signed and new_name != post.name:
                base_name = self.anonymous_base_name(new_name)
                name_key = self.normalize_identity_name(base_name)
                claim = self._conn.execute(
                    "SELECT author_id, public_key FROM name_claims WHERE name_key = ?",
                    (name_key,),
                ).fetchone()
                if claim is not None:
                    raise StoreError(
                        f"name {base_name!r} is already bound to public key {claim['public_key']} "
                        f"(author_id {claim['author_id']})",
                        409,
                    )
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
                self._insert_attachments(
                    post.id,
                    files,
                    uploaded_at=now,
                    uploader_name=file_uploader_name,
                    uploader_id=auth.signer_id if auth is not None else None,
                )
            if auth is not None and auth.signer_id == post.author_id:
                self._remember_identity_name(auth.signer_id, new_name, now)
            self._reindex_inbox(post.id)
            self._reindex_tags(post.id)

        updated = self.get_post(post.id)
        assert updated is not None
        return updated

    def archive_post(self, post: Post, *, actor_id: str | None = None) -> bool:
        if post.system:
            raise StoreError("system post is immutable", 403)
        with self._lock, self._conn:
            row = self._conn.execute("SELECT 1 FROM posts WHERE id = ?", (post.id,)).fetchone()
            if row is None:
                return False
            now = time.time()
            self._conn.execute(
                """
                INSERT INTO archived_posts(
                    id, board, seq, name, title, body, created, updated, nbytes,
                    author_key, author_id, actor_key, actor_id, signature,
                    sig_version, sig_nonce, sig_issued, reply_to, system, custody_id,
                    archived_at, archived_by
                )
                SELECT
                    id, board, seq, name, title, body, created, updated, nbytes,
                    author_key, author_id, actor_key, actor_id, signature,
                    sig_version, sig_nonce, sig_issued, reply_to, system, custody_id,
                    ?, ?
                  FROM posts
                 WHERE id = ?
                """,
                (now, actor_id, post.id),
            )
            self._conn.execute(
                """
                INSERT INTO archived_attachments(
                    id, post_id, slot, name, content_type, data, nbytes, sha256,
                    created, uploader_name, uploader_id, downloads
                )
                SELECT id, post_id, slot, name, content_type, data, nbytes, sha256,
                       created, uploader_name, uploader_id, downloads
                  FROM attachments
                 WHERE post_id = ?
                """,
                (post.id,),
            )
            cur = self._conn.execute("DELETE FROM posts WHERE id = ?", (post.id,))
            if cur.rowcount:
                self._prune_empty_boards()
        return cur.rowcount > 0

    def delete_post(self, post: Post) -> bool:
        """Backward-compatible alias: normal delete now archives."""
        return self.archive_post(post)

    def purge_post(
        self,
        post_id: int,
        *,
        actor_id: str | None = None,
        reason: str = "",
    ) -> Post | None:
        reason = " ".join(reason.split())[:500]
        with self._lock, self._conn:
            row = self._conn.execute(
                self._select_posts() + " WHERE id = ?",
                (post_id,),
            ).fetchone()
            source = "posts"
            if row is None:
                row = self._conn.execute(
                    self._select_archived_posts() + " WHERE id = ?",
                    (post_id,),
                ).fetchone()
                source = "archived_posts"
            post = self._row(row)
            if post is None:
                return None
            if post.system:
                raise StoreError("system post is immutable", 403)

            delivery_rows = self._conn.execute("SELECT id, data FROM webhook_deliveries").fetchall()
            delivery_ids: list[str] = []
            for delivery in delivery_rows:
                try:
                    data = json.loads(str(delivery["data"]))
                except json.JSONDecodeError:
                    continue
                webhook_post = data.get("post")
                if isinstance(webhook_post, dict) and webhook_post.get("id") == post.id:
                    delivery_ids.append(str(delivery["id"]))
            if delivery_ids:
                marks = ",".join("?" for _ in delivery_ids)
                self._conn.execute(
                    f"DELETE FROM webhook_deliveries WHERE id IN ({marks})",
                    delivery_ids,
                )

            self._conn.execute(
                """
                INSERT INTO purge_tombstones(post_id, board, purged_at, purged_by, reason)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(post_id) DO UPDATE SET
                    board = excluded.board,
                    purged_at = excluded.purged_at,
                    purged_by = excluded.purged_by,
                    reason = excluded.reason
                """,
                (post.id, post.board, time.time(), actor_id, reason),
            )
            self._conn.execute(f"DELETE FROM {source} WHERE id = ?", (post.id,))
            if source == "posts":
                self._prune_empty_boards()

        # secure_delete overwrites deleted SQLite cells/pages. Truncate the WAL so
        # an emergency purge does not leave the just-removed content in old frames.
        with self._lock, contextlib.suppress(sqlite3.OperationalError):
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        return post

    def _prune_empty_boards(self) -> None:
        self._conn.execute(
            "DELETE FROM boards WHERE name NOT IN ('main', 'meta', 'guest', 'custody', 'ca')"
            " AND NOT EXISTS (SELECT 1 FROM posts WHERE posts.board = boards.name)"
        )

    def comment_count(self, post_id: int) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM posts WHERE reply_to = ?",
                (post_id,),
            ).fetchone()
        return int(row["n"] if row is not None else 0)

    def comment_counts(self) -> list[tuple[int, str, int]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT p.id, p.board, COUNT(r.id) AS comments
                  FROM posts p
                  LEFT JOIN posts r ON r.reply_to = p.id
                 GROUP BY p.id, p.board
                 ORDER BY p.id
                """
            ).fetchall()
        return [(int(row["id"]), str(row["board"]), int(row["comments"])) for row in rows]

    def like_count(self, post_id: int) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM post_likes WHERE post_id = ?",
                (post_id,),
            ).fetchone()
        return int(row["n"] if row is not None else 0)

    def like_counts(self) -> list[tuple[int, str, int]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT p.id, p.board, COUNT(l.author_id) AS likes
                  FROM posts p
                  LEFT JOIN post_likes l ON l.post_id = p.id
                 GROUP BY p.id, p.board
                 ORDER BY p.id
                """
            ).fetchall()
        return [(int(row["id"]), str(row["board"]), int(row["likes"])) for row in rows]

    def set_post_like(self, post_id: int, author_id: str, liked: bool) -> tuple[bool, int]:
        if not valid_author_id(author_id):
            raise StoreError("invalid author id", 400)
        with self._lock, self._conn:
            exists = self._conn.execute(
                "SELECT 1 FROM posts WHERE id = ?",
                (post_id,),
            ).fetchone()
            if exists is None:
                raise StoreError("post not found", 404)
            if liked:
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO post_likes(post_id, author_id, created) VALUES (?, ?, ?)",
                    (post_id, author_id, time.time()),
                )
            else:
                cur = self._conn.execute(
                    "DELETE FROM post_likes WHERE post_id = ? AND author_id = ?",
                    (post_id, author_id),
                )
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM post_likes WHERE post_id = ?",
                (post_id,),
            ).fetchone()
        return cur.rowcount > 0, int(row["n"] if row is not None else 0)

    def posts_by_ids(self, post_ids: list[int] | tuple[int, ...]) -> list[Post]:
        if not post_ids:
            return []
        unique = list(dict.fromkeys(int(post_id) for post_id in post_ids if post_id > 0))
        if not unique:
            return []
        placeholders = ",".join("?" for _ in unique)
        with self._lock:
            rows = self._conn.execute(
                f"{self._select_posts()} WHERE id IN ({placeholders})",
                unique,
            ).fetchall()
        posts = {post.id: post for row in rows if (post := self._row(row)) is not None}
        return [posts[post_id] for post_id in unique if post_id in posts]

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

    def _list_posts_by_timestamp(
        self,
        column: str,
        *,
        cursor: tuple[float, int] | None = None,
        limit: int = 20,
        order: str = "desc",
    ) -> list[Post]:
        if column not in {"created", "updated"}:
            raise StoreError("unsupported timestamp index", 500)
        if order not in {"asc", "desc"}:
            raise StoreError("order must be asc or desc", 400)

        where: list[str] = []
        params: list[Any] = []
        if cursor is not None:
            value, post_id = cursor
            operator = ">" if order == "asc" else "<"
            where.append(f"({column} {operator} ? OR ({column} = ? AND id {operator} ?))")
            params.extend((value, value, post_id))

        sql = self._select_posts()
        if where:
            sql += " WHERE " + " AND ".join(where)
        direction = "ASC" if order == "asc" else "DESC"
        sql += f" ORDER BY {column} {direction}, id {direction} LIMIT ?"
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [post for row in rows if (post := self._row(row)) is not None]

    def list_posts_by_time(
        self,
        *,
        cursor: tuple[float, int] | None = None,
        limit: int = 20,
        order: str = "desc",
    ) -> list[Post]:
        """List posts by creation time with a stable (created, id) cursor."""
        return self._list_posts_by_timestamp(
            "created",
            cursor=cursor,
            limit=limit,
            order=order,
        )

    def list_posts_by_updated(
        self,
        *,
        cursor: tuple[float, int] | None = None,
        limit: int = 20,
        order: str = "desc",
    ) -> list[Post]:
        """List posts by update time with a stable (updated, id) cursor."""
        return self._list_posts_by_timestamp(
            "updated",
            cursor=cursor,
            limit=limit,
            order=order,
        )

    def list_bound_names(
        self,
        *,
        cursor_key: str | None = None,
        limit: int = 20,
        order: str = "asc",
    ) -> list[dict[str, Any]]:
        """List claimed signed names alphabetically for the canonical name index."""
        if order not in {"asc", "desc"}:
            raise StoreError("order must be asc or desc", 400)

        params: list[Any] = []
        where = ""
        if cursor_key is not None:
            operator = ">" if order == "asc" else "<"
            where = f" WHERE nc.name_key {operator} ?"
            params.append(cursor_key)

        direction = "ASC" if order == "asc" else "DESC"
        sql = f"""
            SELECT nc.name_key, nc.display_name, nc.author_id, nc.public_key,
                   nc.claimed, nc.last_used, COUNT(p.id) AS posts
              FROM name_claims nc
              LEFT JOIN posts p
                ON p.author_id = nc.author_id
               AND p.system = 0
               AND p.custody_id IS NULL
              {where}
             GROUP BY nc.name_key, nc.display_name, nc.author_id, nc.public_key,
                      nc.claimed, nc.last_used
             ORDER BY nc.name_key {direction}
             LIMIT ?
        """
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()

        return [
            {
                "name_key": str(row["name_key"]),
                "name": str(row["display_name"]),
                "author_id": str(row["author_id"]),
                "public_key": str(row["public_key"]),
                "claimed": round(float(row["claimed"]), 3),
                "last_used": round(float(row["last_used"]), 3),
                "posts": int(row["posts"]),
                "profile": f"/@{quote(str(row['display_name']), safe='')}",
            }
            for row in rows
        ]

    def list_tags_by_name(
        self,
        *,
        cursor_key: str | None = None,
        limit: int = 20,
        order: str = "asc",
    ) -> list[dict[str, Any]]:
        if order not in {"asc", "desc"}:
            raise StoreError("order must be asc or desc", 400)
        params: list[Any] = []
        where = ""
        if cursor_key is not None:
            operator = ">" if order == "asc" else "<"
            where = f" WHERE t.tag {operator} ?"
            params.append(cursor_key)
        direction = "ASC" if order == "asc" else "DESC"
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT t.tag, COUNT(*) AS posts,
                       COUNT(DISTINCT p.board) AS boards,
                       MAX(p.updated) AS last_ts,
                       MAX(p.id) AS latest_id
                  FROM post_tags t
                  JOIN posts p ON p.id = t.post_id
                  {where}
                 GROUP BY t.tag
                 ORDER BY t.tag {direction}
                 LIMIT ?
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def list_boards_by_name(
        self,
        *,
        cursor_key: str | None = None,
        limit: int = 20,
        order: str = "asc",
    ) -> list[dict[str, Any]]:
        if order not in {"asc", "desc"}:
            raise StoreError("order must be asc or desc", 400)
        params: list[Any] = []
        where = ""
        if cursor_key is not None:
            operator = ">" if order == "asc" else "<"
            where = f" WHERE b.name {operator} ?"
            params.append(cursor_key)
        direction = "ASC" if order == "asc" else "DESC"
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT b.name, b.description, COUNT(p.id) AS posts,
                       COALESCE(MAX(p.updated), 0) AS last_ts,
                       COALESCE(MAX(p.id), 0) AS latest_id
                  FROM boards b
                  LEFT JOIN posts p ON p.board = b.name
                  {where}
                 GROUP BY b.name, b.description
                 ORDER BY b.name {direction}
                 LIMIT ?
                """,
                params,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            policy = self.policy(str(row["name"]))
            item["permissions"] = policy["permissions"]
            item["anonymous_permissions"] = policy["anonymous_permissions"]
            item["signed_permissions"] = policy["signed_permissions"]
            result.append(item)
        return result

    def list_authors(
        self,
        *,
        cursor_key: str | None = None,
        limit: int = 20,
        order: str = "asc",
    ) -> list[dict[str, Any]]:
        if order not in {"asc", "desc"}:
            raise StoreError("order must be asc or desc", 400)
        params: list[Any] = []
        where = ["p.author_id IS NOT NULL", "p.system = 0"]
        if cursor_key is not None:
            if not valid_author_id(cursor_key):
                raise StoreError("invalid author cursor", 400)
            operator = ">" if order == "asc" else "<"
            where.append(f"p.author_id {operator} ?")
            params.append(cursor_key)
        direction = "ASC" if order == "asc" else "DESC"
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT p.author_id, MAX(p.author_key) AS public_key,
                       COUNT(*) AS posts, MIN(p.created) AS first_seen,
                       MAX(p.updated) AS last_seen
                  FROM posts p
                 WHERE {" AND ".join(where)}
                 GROUP BY p.author_id
                 ORDER BY p.author_id {direction}
                 LIMIT ?
                """,
                params,
            ).fetchall()
        return [
            {
                "author_id": str(row["author_id"]),
                "public_key": str(row["public_key"] or ""),
                "posts": int(row["posts"]),
                "first_seen": round(float(row["first_seen"]), 3),
                "last_seen": round(float(row["last_seen"]), 3),
                "key_url": f"/key/{row['author_id']}",
            }
            for row in rows
        ]

    def list_reply_groups(
        self,
        *,
        cursor_id: int | None = None,
        limit: int = 20,
        order: str = "asc",
    ) -> list[dict[str, Any]]:
        if order not in {"asc", "desc"}:
            raise StoreError("order must be asc or desc", 400)
        params: list[Any] = []
        where = ["r.reply_to IS NOT NULL"]
        if cursor_id is not None:
            operator = ">" if order == "asc" else "<"
            where.append(f"r.reply_to {operator} ?")
            params.append(cursor_id)
        direction = "ASC" if order == "asc" else "DESC"
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT r.reply_to AS parent_id, parent.board AS parent_board,
                       COUNT(*) AS replies, MIN(r.id) AS first_reply_id,
                       MAX(r.id) AS latest_reply_id,
                       MAX(r.updated) AS last_ts
                  FROM posts r
                  LEFT JOIN posts parent ON parent.id = r.reply_to
                 WHERE {" AND ".join(where)}
                 GROUP BY r.reply_to, parent.board
                 ORDER BY r.reply_to {direction}
                 LIMIT ?
                """,
                params,
            ).fetchall()
        return [
            {
                "parent_id": int(row["parent_id"]),
                "parent_board": (
                    str(row["parent_board"]) if row["parent_board"] is not None else None
                ),
                "replies": int(row["replies"]),
                "first_reply_id": int(row["first_reply_id"]),
                "latest_reply_id": int(row["latest_reply_id"]),
                "last_ts": round(float(row["last_ts"]), 3),
            }
            for row in rows
        ]

    def latest_pointer(self, kind: str) -> dict[str, Any] | None:
        """Resolve one stable /latest pointer from current active state."""
        if kind in {"post", "update", "reply"}:
            where = "system = 0"
            order_by = "created DESC, id DESC"
            if kind == "update":
                order_by = "updated DESC, id DESC"
            elif kind == "reply":
                where += " AND reply_to IS NOT NULL"
            with self._lock:
                row = self._conn.execute(
                    f"{self._select_posts()} WHERE {where} ORDER BY {order_by} LIMIT 1"
                ).fetchone()
            post = self._row(row)
            if post is None:
                return None
            return {
                "type": kind,
                "id": post.id,
                "target": f"/{post.board}/{post.id}",
                "board": post.board,
                "name": post.name,
                "title": post.title,
                "created": round(post.created, 3),
                "updated": round(post.updated, 3),
                "reply_to": post.reply_to,
            }

        if kind == "user":
            with self._lock:
                row = self._conn.execute(
                    """
                    WITH joined AS (
                        SELECT author_id, MIN(claimed) AS joined_at
                          FROM name_claims
                         GROUP BY author_id
                    )
                    SELECT j.author_id, j.joined_at, nc.display_name AS name,
                           nc.public_key
                      FROM joined j
                      JOIN profiles pr ON pr.author_id = j.author_id
                      JOIN name_claims nc
                        ON nc.author_id = pr.author_id
                       AND nc.name_key = pr.primary_name_key
                     ORDER BY j.joined_at DESC, j.author_id DESC
                     LIMIT 1
                    """
                ).fetchone()
            if row is None:
                return None
            name = str(row["name"])
            return {
                "type": "user",
                "author_id": str(row["author_id"]),
                "name": name,
                "public_key": str(row["public_key"]),
                "joined_at": round(float(row["joined_at"]), 3),
                "target": f"/@{quote(name, safe='')}",
            }

        if kind == "profile":
            with self._lock:
                row = self._conn.execute(
                    """
                    SELECT pr.author_id, pr.updated, nc.display_name AS name,
                           nc.public_key
                      FROM profiles pr
                      JOIN name_claims nc
                        ON nc.author_id = pr.author_id
                       AND nc.name_key = pr.primary_name_key
                     ORDER BY pr.updated DESC, pr.author_id DESC
                     LIMIT 1
                    """
                ).fetchone()
            if row is None:
                return None
            name = str(row["name"])
            return {
                "type": "profile",
                "author_id": str(row["author_id"]),
                "name": name,
                "public_key": str(row["public_key"]),
                "updated": round(float(row["updated"]), 3),
                "target": f"/@{quote(name, safe='')}",
            }

        if kind == "board":
            defaults = tuple(sorted(DEFAULT_BOARDS))
            placeholders = ",".join("?" for _ in defaults)
            with self._lock:
                row = self._conn.execute(
                    f"""
                    SELECT name, description, created
                      FROM boards
                     WHERE name NOT IN ({placeholders})
                     ORDER BY created DESC, name DESC
                     LIMIT 1
                    """,
                    defaults,
                ).fetchone()
            if row is None:
                return None
            name = str(row["name"])
            return {
                "type": "board",
                "name": name,
                "description": str(row["description"]),
                "created": round(float(row["created"]), 3),
                "target": f"/{name}",
            }

        if kind == "tag":
            with self._lock:
                row = self._conn.execute(
                    """
                    SELECT t.tag, COUNT(*) AS posts,
                           COUNT(DISTINCT p.board) AS boards,
                           MAX(p.updated) AS last_used,
                           MAX(p.id) AS latest_id
                      FROM post_tags t
                      JOIN posts p ON p.id = t.post_id
                     GROUP BY t.tag
                     ORDER BY last_used DESC, latest_id DESC, t.tag ASC
                     LIMIT 1
                    """
                ).fetchone()
            if row is None:
                return None
            tag = str(row["tag"])
            return {
                "type": "tag",
                "tag": tag,
                "posts": int(row["posts"]),
                "boards": int(row["boards"]),
                "last_used": round(float(row["last_used"]), 3),
                "latest_id": int(row["latest_id"]),
                "target": f"/tag/{quote(tag, safe='')}",
            }

        if kind == "file":
            rows = self.list_attachment_metadata(sort="id", limit=1, order="desc")
            if not rows:
                return None
            item = rows[0]
            return {
                "type": "file",
                "id": item["id"],
                "post_id": item["post_id"],
                "board": item["board"],
                "name": item["name"],
                "content_type": item["type"],
                "bytes": item["bytes"],
                "sha256": item["sha256"],
                "uploaded_at": item["uploaded_at"],
                "downloads": item["downloads"],
                "uploader": item["uploader"],
                "post": item["post"],
                "meta": item["meta"],
                "target": item["url"],
            }

        raise StoreError(f"unknown latest kind: {kind}", 404)

    @staticmethod
    def _like_pattern(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return f"%{escaped}%"

    def search_posts(
        self,
        spec: SearchSpec,
        *,
        limit: int,
        cursor_id: int | None = None,
    ) -> tuple[list[Post], bool]:
        where: list[str] = []
        params: list[Any] = []

        if spec.board:
            where.append("p.board = ?")
            params.append(spec.board)
        if cursor_id is not None:
            where.append("p.id < ?" if spec.order != "asc" else "p.id > ?")
            params.append(cursor_id)
        if spec.author_name:
            where.append("p.name = ?")
            params.append(spec.author_name)
        for tag in spec.tags:
            where.append("EXISTS (SELECT 1 FROM post_tags t WHERE t.post_id = p.id AND t.tag = ?)")
            params.append(self.normalize_tag(tag))
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
            where.append("NOT (p.title LIKE ? ESCAPE '\\' OR p.body LIKE ? ESCAPE '\\')")
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
                    SELECT author_id
                      FROM name_claims
                     WHERE name_key = ?
                    """,
                    (self.normalize_identity_name(token),),
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

    def inbox_targets(self, post_id: int) -> list[tuple[str, str]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT subject_id, kind
                  FROM inbox_events
                 WHERE post_id = ?
                 ORDER BY subject_id, kind
                """,
                (post_id,),
            ).fetchall()
        return [(str(row["subject_id"]), str(row["kind"])) for row in rows]

    def webhook_count(self, owner_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM webhooks WHERE owner_id = ?",
                (owner_id,),
            ).fetchone()
        return int(row["n"] if row is not None else 0)

    def create_webhook(
        self,
        *,
        webhook_id: str,
        owner_id: str,
        url: str,
        events: tuple[str, ...],
        secret_nonce: bytes,
        secret_ciphertext: bytes,
    ) -> dict[str, Any]:
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO webhooks(
                    id, owner_id, url, events, secret_nonce, secret_ciphertext,
                    enabled, created, updated
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    webhook_id,
                    owner_id,
                    url,
                    json.dumps(list(events), separators=(",", ":")),
                    secret_nonce,
                    secret_ciphertext,
                    now,
                    now,
                ),
            )
        row = self.webhook(webhook_id)
        assert row is not None
        return row

    def webhook(self, webhook_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, owner_id, url, events, secret_nonce, secret_ciphertext,
                       enabled, created, updated, last_error
                  FROM webhooks
                 WHERE id = ?
                """,
                (webhook_id,),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["events"] = tuple(json.loads(str(row["events"])))
        item["enabled"] = bool(row["enabled"])
        return item

    def list_webhooks(self, owner_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT w.id, w.owner_id, w.url, w.events, w.enabled,
                       w.created, w.updated, w.last_error,
                       SUM(CASE WHEN d.id IS NOT NULL AND d.delivered IS NULL
                                      AND d.attempts < 6 THEN 1 ELSE 0 END) AS pending,
                       SUM(CASE WHEN d.id IS NOT NULL AND d.delivered IS NULL
                                      AND d.attempts >= 6 THEN 1 ELSE 0 END)
                           AS failed
                  FROM webhooks w
                  LEFT JOIN webhook_deliveries d ON d.webhook_id = w.id
                 WHERE w.owner_id = ?
                 GROUP BY w.id
                 ORDER BY w.created
                """,
                (owner_id,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["events"] = tuple(json.loads(str(row["events"])))
            item["enabled"] = bool(row["enabled"])
            item["pending"] = int(row["pending"] or 0)
            item["failed"] = int(row["failed"] or 0)
            result.append(item)
        return result

    def update_webhook(
        self,
        webhook_id: str,
        owner_id: str,
        *,
        url: str,
        events: tuple[str, ...],
        enabled: bool,
    ) -> dict[str, Any]:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                UPDATE webhooks
                   SET url = ?, events = ?, enabled = ?, updated = ?, last_error = ''
                 WHERE id = ? AND owner_id = ?
                """,
                (
                    url,
                    json.dumps(list(events), separators=(",", ":")),
                    1 if enabled else 0,
                    time.time(),
                    webhook_id,
                    owner_id,
                ),
            )
            if cur.rowcount != 1:
                raise StoreError("webhook not found", 404)
        row = self.webhook(webhook_id)
        assert row is not None
        return row

    def rotate_webhook_secret(
        self,
        webhook_id: str,
        owner_id: str,
        *,
        secret_nonce: bytes,
        secret_ciphertext: bytes,
    ) -> None:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                UPDATE webhooks
                   SET secret_nonce = ?, secret_ciphertext = ?, updated = ?
                 WHERE id = ? AND owner_id = ?
                """,
                (secret_nonce, secret_ciphertext, time.time(), webhook_id, owner_id),
            )
            if cur.rowcount != 1:
                raise StoreError("webhook not found", 404)

    def delete_webhook(self, webhook_id: str, owner_id: str) -> None:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM webhooks WHERE id = ? AND owner_id = ?",
                (webhook_id, owner_id),
            )
            if cur.rowcount != 1:
                raise StoreError("webhook not found", 404)

    def queue_webhook_event(
        self,
        subject_id: str,
        event: str,
        data: dict[str, Any],
        *,
        only_webhook_id: str | None = None,
    ) -> list[str]:
        with self._lock:
            if only_webhook_id is None:
                rows = self._conn.execute(
                    """
                    SELECT id, events
                      FROM webhooks
                     WHERE owner_id = ? AND enabled = 1
                    """,
                    (subject_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT id, events
                      FROM webhooks
                     WHERE id = ? AND owner_id = ? AND enabled = 1
                    """,
                    (only_webhook_id, subject_id),
                ).fetchall()

        now = time.time()
        queued: list[str] = []
        with self._lock, self._conn:
            for row in rows:
                subscribed = set(json.loads(str(row["events"])))
                if event != "webhook.test" and event not in subscribed:
                    continue
                delivery_id = secrets.token_hex(16)
                self._conn.execute(
                    """
                    INSERT INTO webhook_deliveries(
                        id, webhook_id, subject_id, event, data, created, next_attempt
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        delivery_id,
                        str(row["id"]),
                        subject_id,
                        event,
                        json.dumps(data, ensure_ascii=False, separators=(",", ":")),
                        now,
                        now,
                    ),
                )
                queued.append(delivery_id)
        return queued

    def due_webhook_deliveries(self, limit: int = 20) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT d.id, d.webhook_id, d.subject_id, d.event, d.data,
                       d.created, d.attempts, d.next_attempt,
                       w.url, w.secret_nonce, w.secret_ciphertext
                  FROM webhook_deliveries d
                  JOIN webhooks w ON w.id = d.webhook_id
                 WHERE d.delivered IS NULL
                   AND d.attempts < 6
                   AND d.next_attempt <= ?
                   AND w.enabled = 1
                 ORDER BY d.next_attempt, d.created
                 LIMIT ?
                """,
                (now, max(1, min(limit, 100))),
            ).fetchall()
        return [dict(row) for row in rows]

    def prune_webhook_deliveries(self) -> None:
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                DELETE FROM webhook_deliveries
                 WHERE (delivered IS NOT NULL AND delivered < ?)
                    OR (delivered IS NULL AND attempts >= 6 AND created < ?)
                """,
                (now - 7 * 86400, now - 30 * 86400),
            )

    def finish_webhook_delivery(
        self,
        delivery_id: str,
        *,
        success: bool,
        error: str = "",
        retry_after: float = 0,
    ) -> None:
        now = time.time()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT webhook_id, attempts FROM webhook_deliveries WHERE id = ?",
                (delivery_id,),
            ).fetchone()
            if row is None:
                return
            attempts = int(row["attempts"]) + 1
            if success:
                self._conn.execute(
                    """
                    UPDATE webhook_deliveries
                       SET attempts = ?, delivered = ?, last_error = ''
                     WHERE id = ?
                    """,
                    (attempts, now, delivery_id),
                )
                self._conn.execute(
                    "UPDATE webhooks SET last_error = '' WHERE id = ?",
                    (str(row["webhook_id"]),),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE webhook_deliveries
                       SET attempts = ?, next_attempt = ?, last_error = ?
                     WHERE id = ?
                    """,
                    (attempts, now + retry_after, error[:500], delivery_id),
                )
                self._conn.execute(
                    "UPDATE webhooks SET last_error = ? WHERE id = ?",
                    (error[:500], str(row["webhook_id"])),
                )

    def upsert_websub_verification(
        self,
        *,
        verification_id: str,
        mode: str,
        topic: str,
        callback: str,
        lease_seconds: int,
        challenge: str,
        secret_nonce: bytes,
        secret_ciphertext: bytes,
    ) -> None:
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO websub_verifications(
                    id, mode, topic, callback, lease_seconds, challenge,
                    secret_nonce, secret_ciphertext, created, attempts, next_attempt, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, '')
                ON CONFLICT(id) DO UPDATE SET
                    mode = excluded.mode,
                    topic = excluded.topic,
                    callback = excluded.callback,
                    lease_seconds = excluded.lease_seconds,
                    challenge = excluded.challenge,
                    secret_nonce = excluded.secret_nonce,
                    secret_ciphertext = excluded.secret_ciphertext,
                    created = excluded.created,
                    attempts = 0,
                    next_attempt = excluded.next_attempt,
                    last_error = ''
                """,
                (
                    verification_id,
                    mode,
                    topic,
                    callback,
                    lease_seconds,
                    challenge,
                    secret_nonce,
                    secret_ciphertext,
                    now,
                    now,
                ),
            )

    def due_websub_verifications(self, limit: int = 20) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, mode, topic, callback, lease_seconds, challenge,
                       secret_nonce, secret_ciphertext, created, attempts,
                       next_attempt, last_error
                  FROM websub_verifications
                 WHERE attempts < 3 AND next_attempt <= ?
                 ORDER BY next_attempt, created
                 LIMIT ?
                """,
                (now, max(1, min(limit, 100))),
            ).fetchall()
        return [dict(row) for row in rows]

    def finish_websub_verification(
        self,
        verification_id: str,
        *,
        success: bool,
        error: str = "",
        retry_after: float = 0,
    ) -> None:
        with self._lock, self._conn:
            if success:
                self._conn.execute(
                    "DELETE FROM websub_verifications WHERE id = ?",
                    (verification_id,),
                )
                return
            row = self._conn.execute(
                "SELECT attempts FROM websub_verifications WHERE id = ?",
                (verification_id,),
            ).fetchone()
            if row is None:
                return
            self._conn.execute(
                """
                UPDATE websub_verifications
                   SET attempts = ?, next_attempt = ?, last_error = ?
                 WHERE id = ?
                """,
                (
                    int(row["attempts"]) + 1,
                    time.time() + retry_after,
                    error[:500],
                    verification_id,
                ),
            )

    def delete_websub_verification(self, verification_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM websub_verifications WHERE id = ?",
                (verification_id,),
            )

    def activate_websub_subscription(
        self,
        *,
        subscription_id: str,
        topic: str,
        callback: str,
        lease_seconds: int,
        secret_nonce: bytes,
        secret_ciphertext: bytes,
    ) -> None:
        now = time.time()
        expires = now + lease_seconds
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO websub_subscriptions(
                    id, topic, callback, secret_nonce, secret_ciphertext,
                    created, updated, expires
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    topic = excluded.topic,
                    callback = excluded.callback,
                    secret_nonce = excluded.secret_nonce,
                    secret_ciphertext = excluded.secret_ciphertext,
                    updated = excluded.updated,
                    expires = excluded.expires
                """,
                (
                    subscription_id,
                    topic,
                    callback,
                    secret_nonce,
                    secret_ciphertext,
                    now,
                    now,
                    expires,
                ),
            )

    def websub_subscription(self, topic: str, callback: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, topic, callback, secret_nonce, secret_ciphertext,
                       created, updated, expires
                  FROM websub_subscriptions
                 WHERE topic = ? AND callback = ?
                """,
                (topic, callback),
            ).fetchone()
        return dict(row) if row is not None else None

    def delete_websub_subscription(self, topic: str, callback: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM websub_subscriptions WHERE topic = ? AND callback = ?",
                (topic, callback),
            )

    def queue_websub_topic(self, topic: str) -> list[str]:
        now = time.time()
        queued: list[str] = []
        with self._lock, self._conn:
            rows = self._conn.execute(
                """
                SELECT id
                  FROM websub_subscriptions
                 WHERE topic = ? AND expires > ?
                """,
                (topic, now),
            ).fetchall()
            for row in rows:
                subscription_id = str(row["id"])
                pending = self._conn.execute(
                    """
                    SELECT 1
                      FROM websub_deliveries
                     WHERE subscription_id = ?
                       AND delivered IS NULL
                       AND attempts < 6
                     LIMIT 1
                    """,
                    (subscription_id,),
                ).fetchone()
                if pending is not None:
                    continue
                delivery_id = secrets.token_hex(16)
                self._conn.execute(
                    """
                    INSERT INTO websub_deliveries(
                        id, subscription_id, topic, created, next_attempt
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (delivery_id, subscription_id, topic, now, now),
                )
                queued.append(delivery_id)
        return queued

    def due_websub_deliveries(self, limit: int = 20) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT d.id, d.subscription_id, d.topic, d.created, d.attempts,
                       d.next_attempt, s.callback, s.secret_nonce,
                       s.secret_ciphertext, s.expires
                  FROM websub_deliveries d
                  JOIN websub_subscriptions s ON s.id = d.subscription_id
                 WHERE d.delivered IS NULL
                   AND d.attempts < 6
                   AND d.next_attempt <= ?
                   AND s.expires > ?
                 ORDER BY d.next_attempt, d.created
                 LIMIT ?
                """,
                (now, now, max(1, min(limit, 100))),
            ).fetchall()
        return [dict(row) for row in rows]

    def finish_websub_delivery(
        self,
        delivery_id: str,
        *,
        success: bool,
        error: str = "",
        retry_after: float = 0,
    ) -> None:
        now = time.time()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT attempts FROM websub_deliveries WHERE id = ?",
                (delivery_id,),
            ).fetchone()
            if row is None:
                return
            attempts = int(row["attempts"]) + 1
            if success:
                self._conn.execute(
                    """
                    UPDATE websub_deliveries
                       SET attempts = ?, delivered = ?, last_error = ''
                     WHERE id = ?
                    """,
                    (attempts, now, delivery_id),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE websub_deliveries
                       SET attempts = ?, next_attempt = ?, last_error = ?
                     WHERE id = ?
                    """,
                    (attempts, now + retry_after, error[:500], delivery_id),
                )

    def queue_websub_hub_ping(self, hub: str, topic: str) -> str:
        now = time.time()
        ping_id = hashlib.sha256(f"{hub}\n{topic}".encode()).hexdigest()
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO websub_hub_pings(
                    id, hub, topic, generation, created, next_attempt
                ) VALUES (?, ?, ?, 1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    generation = websub_hub_pings.generation + 1,
                    created = excluded.created,
                    attempts = 0,
                    next_attempt = excluded.next_attempt,
                    delivered = NULL,
                    last_error = ''
                """,
                (ping_id, hub, topic, now, now),
            )
        return ping_id

    def due_websub_hub_pings(self, limit: int = 20) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, hub, topic, generation, created, attempts, next_attempt
                  FROM websub_hub_pings
                 WHERE delivered IS NULL
                   AND attempts < 6
                   AND next_attempt <= ?
                 ORDER BY next_attempt, created
                 LIMIT ?
                """,
                (now, max(1, min(limit, 100))),
            ).fetchall()
        return [dict(row) for row in rows]

    def finish_websub_hub_ping(
        self,
        ping_id: str,
        generation: int,
        *,
        success: bool,
        error: str = "",
        retry_after: float = 0,
    ) -> None:
        now = time.time()
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT attempts, generation FROM websub_hub_pings WHERE id = ?",
                (ping_id,),
            ).fetchone()
            if row is None or int(row["generation"]) != generation:
                return
            attempts = int(row["attempts"]) + 1
            if success:
                self._conn.execute(
                    """
                    UPDATE websub_hub_pings
                       SET attempts = ?, delivered = ?, last_error = ''
                     WHERE id = ? AND generation = ?
                    """,
                    (attempts, now, ping_id, generation),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE websub_hub_pings
                       SET attempts = ?, next_attempt = ?, last_error = ?
                     WHERE id = ? AND generation = ?
                    """,
                    (attempts, now + retry_after, error[:500], ping_id, generation),
                )

    def prune_websub(self) -> None:
        now = time.time()
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM websub_subscriptions WHERE expires <= ?",
                (now,),
            )
            self._conn.execute(
                """
                DELETE FROM websub_verifications
                 WHERE (attempts >= 3 AND created < ?)
                    OR created < ?
                """,
                (now - 86400, now - 7 * 86400),
            )
            self._conn.execute(
                """
                DELETE FROM websub_deliveries
                 WHERE (delivered IS NOT NULL AND delivered < ?)
                    OR (delivered IS NULL AND attempts >= 6 AND created < ?)
                """,
                (now - 7 * 86400, now - 30 * 86400),
            )
            self._conn.execute(
                """
                DELETE FROM websub_hub_pings
                 WHERE (delivered IS NOT NULL AND delivered < ?)
                    OR (delivered IS NULL AND attempts >= 6 AND created < ?)
                """,
                (now - 86400, now - 7 * 86400),
            )

    def path_get_receipt(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT request_id, payload_sha256, operation, status,
                       content_type, body, headers, created
                  FROM path_get_receipts
                 WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["completed"] = row["status"] is not None
        item["body"] = bytes(row["body"]) if row["body"] is not None else b""
        item["headers"] = json.loads(str(row["headers"]))
        return item

    def claim_path_get(
        self,
        *,
        request_id: str,
        payload_sha256: str,
        operation: str,
    ) -> tuple[bool, dict[str, Any] | None]:
        with self._lock, self._conn:
            try:
                self._conn.execute(
                    """
                    INSERT INTO path_get_receipts(
                        request_id, payload_sha256, operation, created
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (request_id, payload_sha256, operation, time.time()),
                )
                return True, None
            except sqlite3.IntegrityError as exc:
                existing = self.path_get_receipt(request_id)
                if existing is None:
                    raise StoreError("path GET receipt conflict", 409) from exc
                if existing["payload_sha256"] != payload_sha256:
                    raise StoreError(
                        "path GET request id was reused with different payload",
                        409,
                    ) from exc
                return False, existing

    def complete_path_get(
        self,
        *,
        request_id: str,
        payload_sha256: str,
        status: int,
        content_type: str,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        if len(body) > 4096:
            raise StoreError("path GET response is too large to cache safely", 500)
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                UPDATE path_get_receipts
                   SET status = ?, content_type = ?, body = ?, headers = ?
                 WHERE request_id = ? AND payload_sha256 = ? AND status IS NULL
                """,
                (
                    status,
                    content_type,
                    body,
                    json.dumps(headers, separators=(",", ":")),
                    request_id,
                    payload_sha256,
                ),
            )
            if cur.rowcount != 1:
                raise StoreError("path GET receipt could not be completed", 409)

    def abort_path_get(self, request_id: str, payload_sha256: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                DELETE FROM path_get_receipts
                 WHERE request_id = ? AND payload_sha256 = ? AND status IS NULL
                """,
                (request_id, payload_sha256),
            )

    def put_path_get_chunk(
        self,
        *,
        request_id: str,
        chunk_index: int,
        chunk_count: int,
        data: bytes,
        max_total_bytes: int,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        now = time.time()
        cutoff = now - ttl_seconds
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM path_get_chunks WHERE created < ?", (cutoff,))
            receipt = self._conn.execute(
                "SELECT 1 FROM path_get_receipts WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if receipt is not None:
                raise StoreError("path GET request id already has an execution receipt", 409)

            rows = self._conn.execute(
                """
                SELECT chunk_index, chunk_count, data
                  FROM path_get_chunks
                 WHERE request_id = ?
                 ORDER BY chunk_index
                """,
                (request_id,),
            ).fetchall()
            if rows and any(int(row["chunk_count"]) != chunk_count for row in rows):
                raise StoreError("path GET chunk count conflicts with existing transfer", 409)

            existing = next(
                (row for row in rows if int(row["chunk_index"]) == chunk_index),
                None,
            )
            replay = existing is not None
            if existing is not None:
                if bytes(existing["data"]) != data:
                    raise StoreError("path GET chunk index was reused with different data", 409)
            else:
                self._conn.execute(
                    """
                    INSERT INTO path_get_chunks(
                        request_id, chunk_index, chunk_count, data, created
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (request_id, chunk_index, chunk_count, data, now),
                )

            self._conn.execute(
                "UPDATE path_get_chunks SET created = ? WHERE request_id = ?",
                (now, request_id),
            )
            stats = self._conn.execute(
                """
                SELECT COUNT(*) AS received,
                       COALESCE(SUM(LENGTH(data)), 0) AS bytes
                  FROM path_get_chunks
                 WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            total_bytes = int(stats["bytes"])
            if total_bytes > max_total_bytes:
                raise StoreError(
                    f"path GET transfer exceeds max_path_transfer_bytes={max_total_bytes}",
                    413,
                )
            return {
                "request_id": request_id,
                "index": chunk_index,
                "total": chunk_count,
                "received": int(stats["received"]),
                "bytes": total_bytes,
                "replay": replay,
            }

    def path_get_chunk_state(
        self,
        request_id: str,
        *,
        ttl_seconds: int,
        max_total_bytes: int,
    ) -> tuple[dict[str, Any] | None, bytes | None]:
        cutoff = time.time() - ttl_seconds
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM path_get_chunks WHERE created < ?", (cutoff,))
            rows = self._conn.execute(
                """
                SELECT chunk_index, chunk_count, data, created
                  FROM path_get_chunks
                 WHERE request_id = ?
                 ORDER BY chunk_index
                """,
                (request_id,),
            ).fetchall()
        if not rows:
            return None, None

        chunk_count = int(rows[0]["chunk_count"])
        if any(int(row["chunk_count"]) != chunk_count for row in rows):
            raise StoreError("path GET transfer has inconsistent chunk counts", 409)
        indices = [int(row["chunk_index"]) for row in rows]
        if any(index < 0 or index >= chunk_count for index in indices):
            raise StoreError("path GET transfer has invalid chunk indexes", 409)
        total_bytes = sum(len(bytes(row["data"])) for row in rows)
        if total_bytes > max_total_bytes:
            raise StoreError(
                f"path GET transfer exceeds max_path_transfer_bytes={max_total_bytes}",
                413,
            )
        present = set(indices)
        missing = [index for index in range(chunk_count) if index not in present]
        state = {
            "request_id": request_id,
            "total": chunk_count,
            "received": len(rows),
            "bytes": total_bytes,
            "missing": missing,
        }
        if missing:
            return state, None
        raw = b"".join(bytes(row["data"]) for row in rows)
        if len(raw) > max_total_bytes:
            raise StoreError(
                f"path GET transfer exceeds max_path_transfer_bytes={max_total_bytes}",
                413,
            )
        return state, raw

    def delete_path_get_chunks(self, request_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM path_get_chunks WHERE request_id = ?",
                (request_id,),
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
            "profile": self.profile_by_author(author_id),
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
            archived = self._conn.execute(
                """
                SELECT COUNT(*) AS posts,
                       COALESCE(SUM(CASE WHEN system = 0 THEN nbytes ELSE 0 END), 0) AS post_bytes
                  FROM archived_posts
                """
            ).fetchone()
            archived_files = self._conn.execute(
                """
                SELECT COUNT(*) AS files, COALESCE(SUM(nbytes),0) AS file_bytes
                  FROM archived_attachments
                """
            ).fetchone()
            boards = self._conn.execute("SELECT COUNT(*) AS n FROM boards").fetchone()["n"]
            hashtags = self._conn.execute(
                "SELECT COUNT(DISTINCT tag) AS n FROM post_tags"
            ).fetchone()["n"]
        post_bytes = int(row["post_bytes"])
        file_bytes = int(files["file_bytes"])
        archived_post_bytes = int(archived["post_bytes"])
        archived_file_bytes = int(archived_files["file_bytes"])
        archived_bytes = archived_post_bytes + archived_file_bytes
        return {
            "boards": int(boards),
            "hashtags": int(hashtags),
            "posts": int(row["posts"]),
            "system_posts": int(row["system_posts"] or 0),
            "files": int(files["files"]),
            "archived_posts": int(archived["posts"]),
            "archived_files": int(archived_files["files"]),
            "post_bytes": post_bytes,
            "file_bytes": file_bytes,
            "archived_bytes": archived_bytes,
            "bytes": post_bytes + file_bytes + archived_bytes,
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
    def _select_archived_posts() -> str:
        return (
            "SELECT id, board, seq, name, title, body, created, updated, nbytes,"
            " author_key, author_id, actor_key, actor_id, signature,"
            " sig_version, sig_nonce, sig_issued, reply_to, system, custody_id"
            " FROM archived_posts"
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
            created=float(row["created"]),
            uploader_name=str(row["uploader_name"] or "anonymous"),
            uploader_id=str(row["uploader_id"]) if row["uploader_id"] is not None else None,
            downloads=int(row["downloads"]),
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
