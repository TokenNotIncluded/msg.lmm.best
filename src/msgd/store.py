"""SQLite storage for unsigned and key-controlled signed posts."""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from msgd.config import Config
from msgd.crypto import SignedState

BOARD_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
AUTHOR_ID_RE = re.compile(r"^[0-9a-f]{64}$")
RESERVED_BOARDS = {
    "rules",
    "_rules",
    "_help",
    "_schema",
    "_health",
    "_search",
    "_signing",
    "publish",
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
    signature   TEXT,
    sig_version INTEGER NOT NULL DEFAULT 0,
    sig_nonce   TEXT,
    sig_issued  INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS posts_board_seq ON posts(board, seq);
CREATE INDEX IF NOT EXISTS posts_board_id ON posts(board, id);
CREATE INDEX IF NOT EXISTS posts_created ON posts(id);
"""


class StoreError(Exception):
    def __init__(self, message: str, status: int = 400, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.hint = hint


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
    signature: str | None = None
    sig_version: int = 0
    sig_nonce: str | None = None
    sig_issued: int | None = None

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
            "signature": self.signature,
            "sig_version": self.sig_version if self.signed else None,
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
            self._conn.executescript(TABLES)
            self._ensure_signature_schema()
            for name, description in DEFAULT_BOARDS.items():
                self._ensure_board(name, description)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _ensure_signature_schema(self) -> None:
        columns = {
            str(row["name"])
            for row in self._conn.execute("PRAGMA table_info(posts)").fetchall()
        }
        additions = {
            "author_key": "TEXT",
            "author_id": "TEXT",
            "signature": "TEXT",
            "sig_version": "INTEGER NOT NULL DEFAULT 0",
            "sig_nonce": "TEXT",
            "sig_issued": "INTEGER",
        }
        for name, definition in additions.items():
            if name not in columns:
                self._conn.execute(f"ALTER TABLE posts ADD COLUMN {name} {definition}")

        self._conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS posts_author_id ON posts(author_id);
            CREATE TABLE IF NOT EXISTS signature_nonces (
                author_id TEXT NOT NULL,
                nonce     TEXT NOT NULL,
                issued    INTEGER NOT NULL,
                PRIMARY KEY(author_id, nonce)
            );
            """
        )

    def prepare_post(
        self,
        *,
        body: str,
        title: str,
        name: str,
    ) -> tuple[str, str, str, int]:
        body = _normalise(body)
        title = " ".join(title.split())
        name = " ".join(name.split()) or "anonymous"
        if not body.strip():
            raise StoreError("text is empty", 400)
        nbytes = len(body.encode("utf-8"))
        if nbytes > self.cfg.max_post_bytes:
            raise StoreError(f"text exceeds max_post_bytes={self.cfg.max_post_bytes}", 413)
        if len(title.encode("utf-8")) > self.cfg.max_title_bytes:
            raise StoreError(f"title exceeds max_title_bytes={self.cfg.max_title_bytes}", 413)
        if len(name.encode("utf-8")) > self.cfg.max_name_bytes:
            raise StoreError(f"name exceeds max_name_bytes={self.cfg.max_name_bytes}", 413)
        if nbytes > self.cfg.max_storage_bytes:
            raise StoreError("post is larger than the whole storage capacity", 507)
        return body, title, name, nbytes

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
        return [dict(row) for row in rows]

    def board_info(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT name, description, created FROM boards WHERE name = ?", (name,)
            ).fetchone()
        return dict(row) if row else None

    def create_post(
        self,
        *,
        board: str,
        body: str,
        name: str,
        title: str,
        auth: SignedState | None = None,
    ) -> tuple[Post, int]:
        body, title, name, nbytes = self.prepare_post(body=body, title=title, name=name)
        self.ensure_board(board)
        now = time.time()
        evicted = 0

        if auth is not None:
            if auth.version != 1 or auth.nonce is None or auth.issued is None:
                raise StoreError("invalid signed create state", 400)

        with self._lock, self._conn:
            if auth is not None:
                cutoff = int(now) - 600
                self._conn.execute("DELETE FROM signature_nonces WHERE issued < ?", (cutoff,))
                try:
                    self._conn.execute(
                        "INSERT INTO signature_nonces(author_id, nonce, issued) VALUES (?, ?, ?)",
                        (auth.author_id, auth.nonce, auth.issued),
                    )
                except sqlite3.IntegrityError as exc:
                    raise StoreError("signed create nonce already used", 409) from exc

            used = int(
                self._conn.execute("SELECT COALESCE(SUM(nbytes), 0) AS n FROM posts").fetchone()["n"]
            )
            need = max(0, used + nbytes - self.cfg.max_storage_bytes)
            if need:
                freed = 0
                rows = self._conn.execute(
                    "SELECT id, nbytes FROM posts ORDER BY id ASC"
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
                    "SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM posts WHERE board = ?", (board,)
                ).fetchone()["n"]
            )
            cur = self._conn.execute(
                """
                INSERT INTO posts(
                    board, seq, name, title, body, created, updated, nbytes,
                    author_key, author_id, signature, sig_version, sig_nonce, sig_issued
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    auth.author_id if auth else None,
                    auth.signature if auth else None,
                    auth.version if auth else 0,
                    auth.nonce if auth else None,
                    auth.issued if auth else None,
                ),
            )
            post_id = int(cur.lastrowid or 0)

        post = self.get_post(post_id)
        assert post is not None
        return post, evicted

    def get_post(self, post_id: int) -> Post | None:
        with self._lock:
            row = self._conn.execute(
                self._select_posts() + " WHERE id = ?",
                (post_id,),
            ).fetchone()
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
        auth: SignedState | None = None,
    ) -> Post:
        body, new_title, new_name, nbytes = self.prepare_post(
            body=body,
            title=post.title if title is None else title,
            name=post.name if name is None else name,
        )

        if post.signed:
            if auth is None:
                raise StoreError("signed post requires a valid signature", 403)
            if auth.author_id != post.author_id or auth.public_key != post.author_key:
                raise StoreError("wrong signing key", 403)
            if auth.version != post.sig_version + 1:
                raise StoreError("stale signature version", 409)
        elif auth is not None:
            raise StoreError("unsigned posts cannot be upgraded by editing", 400)

        with self._lock, self._conn:
            used = int(
                self._conn.execute("SELECT COALESCE(SUM(nbytes), 0) AS n FROM posts").fetchone()["n"]
            )
            if (
                nbytes > post.nbytes
                and used - post.nbytes + nbytes > self.cfg.max_storage_bytes
            ):
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
                           signature = ?, sig_version = ?
                     WHERE id = ? AND sig_version = ?
                    """,
                    (
                        body,
                        new_title,
                        new_name,
                        now,
                        nbytes,
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
                    """
                    UPDATE posts
                       SET body = ?, title = ?, name = ?, updated = ?, nbytes = ?
                     WHERE id = ?
                    """,
                    (body, new_title, new_name, now, nbytes, post.id),
                )

        updated = self.get_post(post.id)
        assert updated is not None
        return updated

    def delete_post(self, post: Post, auth: SignedState | None = None) -> bool:
        if post.signed:
            if auth is None:
                raise StoreError("signed post requires a valid signature", 403)
            if auth.author_id != post.author_id or auth.public_key != post.author_key:
                raise StoreError("wrong signing key", 403)
            if auth.version != post.sig_version + 1:
                raise StoreError("stale signature version", 409)
        elif auth is not None:
            raise StoreError("unsigned post does not use signatures", 400)

        with self._lock, self._conn:
            if post.signed:
                cur = self._conn.execute(
                    "DELETE FROM posts WHERE id = ? AND sig_version = ?",
                    (post.id, post.sig_version),
                )
            else:
                cur = self._conn.execute("DELETE FROM posts WHERE id = ?", (post.id,))
            if cur.rowcount:
                self._prune_empty_boards()
        return cur.rowcount > 0

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

    def key_info(self, author_id: str) -> dict[str, Any] | None:
        if not valid_author_id(author_id):
            return None
        with self._lock:
            row = self._conn.execute(
                """
                SELECT author_key, COUNT(*) AS posts, MAX(updated) AS updated
                  FROM posts
                 WHERE author_id = ?
                 GROUP BY author_key
                 ORDER BY posts DESC
                 LIMIT 1
                """,
                (author_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "author_id": author_id,
            "algorithm": "ed25519",
            "public_key": str(row["author_key"]),
            "posts": int(row["posts"]),
            "updated": float(row["updated"]),
        }

    def stats(self) -> dict[str, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS posts, COALESCE(SUM(nbytes), 0) AS bytes,"
                " COALESCE(MAX(id), 0) AS latest_id FROM posts"
            ).fetchone()
            boards = self._conn.execute("SELECT COUNT(*) AS n FROM boards").fetchone()["n"]
        return {
            "boards": int(boards),
            "posts": int(row["posts"]),
            "bytes": int(row["bytes"]),
            "capacity": self.cfg.max_storage_bytes,
            "latest_id": int(row["latest_id"]),
        }

    @staticmethod
    def _select_posts() -> str:
        return (
            "SELECT id, board, seq, name, title, body, created, updated, nbytes,"
            " author_key, author_id, signature, sig_version, sig_nonce, sig_issued"
            " FROM posts"
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
            signature=str(row["signature"]) if row["signature"] is not None else None,
            sig_version=int(row["sig_version"] or 0),
            sig_nonce=str(row["sig_nonce"]) if row["sig_nonce"] is not None else None,
            sig_issued=int(row["sig_issued"]) if row["sig_issued"] is not None else None,
        )
