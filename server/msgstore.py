"""SQLite storage for msgd.

One connection guarded by a lock: msgd is a ThreadingHTTPServer, and at this
scale a serialised writer plus WAL readers beats a connection pool for
simplicity. Every mutation that touches a post also writes a revision row, so
`/history` is a real audit trail rather than a reconstructed diff.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from msgconf import Config

SCHEMA_VERSION = 1

BOARD_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
RESERVED_BOARDS = {
    "rules", "_rules", "_help", "_schema", "_files", "_health", "_search", "_stats",
    "publish", "llms.txt", "robots.txt", "favicon.ico",
}

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS boards (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    locked      INTEGER NOT NULL DEFAULT 0,
    created     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    board       TEXT NOT NULL REFERENCES boards(name) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    name        TEXT NOT NULL DEFAULT 'anonymous',
    title       TEXT NOT NULL DEFAULT '',
    body        TEXT NOT NULL,
    token_hash  TEXT NOT NULL DEFAULT '',
    created     REAL NOT NULL,
    updated     REAL NOT NULL,
    edit_count  INTEGER NOT NULL DEFAULT 0,
    deleted     INTEGER NOT NULL DEFAULT 0,
    deleted_by  TEXT NOT NULL DEFAULT '',
    nbytes      INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS posts_board_seq ON posts(board, seq);
CREATE INDEX IF NOT EXISTS posts_board_live ON posts(board, deleted, id);
CREATE INDEX IF NOT EXISTS posts_created ON posts(created);

CREATE TABLE IF NOT EXISTS revisions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id  INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    rev      INTEGER NOT NULL,
    action   TEXT NOT NULL,
    name     TEXT NOT NULL DEFAULT '',
    title    TEXT NOT NULL DEFAULT '',
    body     TEXT NOT NULL,
    ts       REAL NOT NULL,
    actor    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS revisions_post ON revisions(post_id, rev);

CREATE TABLE IF NOT EXISTS files (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    content_type TEXT NOT NULL,
    nbytes       INTEGER NOT NULL,
    sha256       TEXT NOT NULL,
    created      REAL NOT NULL,
    token_hash   TEXT NOT NULL DEFAULT '',
    downloads    INTEGER NOT NULL DEFAULT 0
);
"""


class StoreError(Exception):
    """A write was refused. `status` is the HTTP code the caller should send."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


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
    edit_count: int
    deleted: bool = False
    deleted_by: str = ""
    nbytes: int = 0

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
            "edited": self.edit_count > 0,
            "edit_count": self.edit_count,
            "deleted": self.deleted,
            "deleted_by": self.deleted_by,
            "bytes": self.nbytes,
        }


def hash_token(token: str) -> str:
    """Store edit keys as salted hashes so a database leak is not a write grant."""
    if not token:
        return ""
    salt = b"msgd-edit-key-v1"
    return hashlib.sha256(salt + token.encode("utf-8")).hexdigest()


def token_matches(token: str, stored_hash: str) -> bool:
    if not token or not stored_hash:
        return False
    return hmac.compare_digest(hash_token(token), stored_hash)


def utcnow() -> float:
    return time.time()


def valid_board_name(name: str) -> bool:
    return bool(BOARD_RE.match(name)) and name not in RESERVED_BOARDS


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
            self._conn.executescript(SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('created', ?)",
                (str(utcnow()),),
            )
            self._ensure_board("main", "General discussion. The default board.")
            self._ensure_board("meta", "Board about the board: bugs, requests, protocol talk.")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- boards ----------------------------------------------------------

    def _ensure_board(self, name: str, description: str = "") -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO boards(name, description, created) VALUES (?, ?, ?)",
            (name, description, utcnow()),
        )

    def ensure_board(self, name: str, description: str = "") -> None:
        if not valid_board_name(name):
            raise StoreError(f"invalid board name: {name!r}", 400)
        with self._lock:
            row = self._conn.execute(
                "SELECT name FROM boards WHERE name = ?", (name,)
            ).fetchone()
            if row is None:
                count = self._conn.execute("SELECT COUNT(*) AS n FROM boards").fetchone()["n"]
                if count >= self.cfg.max_boards:
                    raise StoreError("board limit reached", 507)
            self._ensure_board(name, description)

    def list_boards(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT b.name, b.description, b.locked, b.created,
                       (SELECT COUNT(*) FROM posts p
                         WHERE p.board = b.name AND p.deleted = 0) AS posts,
                       (SELECT COALESCE(MAX(p.id), 0) FROM posts p
                         WHERE p.board = b.name AND p.deleted = 0) AS last_id,
                       (SELECT COALESCE(MAX(p.updated), 0) FROM posts p
                         WHERE p.board = b.name AND p.deleted = 0) AS last_ts
                  FROM boards b
                 ORDER BY b.name
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def board_info(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT name, description, locked, created FROM boards WHERE name = ?",
                (name,),
            ).fetchone()
        return dict(row) if row else None

    def board_locked(self, name: str) -> bool:
        info = self.board_info(name)
        return bool(info and info["locked"])

    def set_board_locked(self, name: str, locked: bool) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE boards SET locked = ? WHERE name = ?", (1 if locked else 0, name)
            )
            return cur.rowcount > 0

    # -- posts -----------------------------------------------------------

    def _next_seq(self, board: str) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(seq), 0) AS s FROM posts WHERE board = ?", (board,)
        ).fetchone()
        return int(row["s"]) + 1

    def _board_usage(self, board: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM posts WHERE board = ? AND deleted = 0", (board,)
        ).fetchone()
        return int(row["n"])

    def create_post(
        self,
        *,
        board: str,
        body: str,
        name: str,
        title: str,
        token: str,
        actor: str = "",
    ) -> tuple[Post, str]:
        """Insert a post. Returns (post, generated_token_if_any)."""
        body = body.replace("\r\n", "\n").replace("\r", "\n")
        title = (title or "").replace("\r", " ").replace("\n", " ").strip()

        if not body.strip():
            raise StoreError("text is empty", 400)
        if len(body.encode("utf-8")) > self.cfg.max_post_bytes:
            raise StoreError(
                f"text exceeds max_post_bytes={self.cfg.max_post_bytes}", 413
            )
        if len(title.encode("utf-8")) > self.cfg.max_title_bytes:
            raise StoreError(
                f"title exceeds max_title_bytes={self.cfg.max_title_bytes}", 413
            )
        if len(name.encode("utf-8")) > self.cfg.max_name_bytes:
            raise StoreError(
                f"name exceeds max_name_bytes={self.cfg.max_name_bytes}", 413
            )
        self.ensure_board(board)
        issued = ""
        if not token:
            token = secrets.token_urlsafe(12)
            issued = token

        now = utcnow()
        with self._lock:
            if self._board_usage(board) >= self.cfg.max_posts_per_board:
                raise StoreError(
                    f"board {board!r} is full "
                    f"(max_posts_per_board={self.cfg.max_posts_per_board})",
                    507,
                )
            seq = self._next_seq(board)
            cur = self._conn.execute(
                """
                INSERT INTO posts(board, seq, name, title, body, token_hash,
                                  created, updated, nbytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    board,
                    seq,
                    name,
                    title,
                    body,
                    hash_token(token),
                    now,
                    now,
                    len(body.encode("utf-8")),
                ),
            )
            post_id = int(cur.lastrowid or 0)
            self._record_revision(post_id, 0, "create", name, title, body, now, actor)
        post = self.get_post(post_id)
        assert post is not None
        return post, issued

    def _record_revision(
        self,
        post_id: int,
        rev: int,
        action: str,
        name: str,
        title: str,
        body: str,
        ts: float,
        actor: str = "",
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO revisions(post_id, rev, action, name, title, body, ts, actor)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (post_id, rev, action, name, title, body, ts, actor),
        )

    def get_post(self, post_id: int, *, include_deleted: bool = True) -> Post | None:
        sql = "SELECT * FROM posts WHERE id = ?"
        params: tuple[Any, ...] = (post_id,)
        if not include_deleted:
            sql += " AND deleted = 0"
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return self._row_to_post(row) if row else None

    def find_in_board(self, board: str, ident: str | int) -> Post | None:
        """Resolve an id or a per-board seq number to a post."""
        try:
            value = int(ident)
        except (TypeError, ValueError):
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM posts WHERE board = ? AND (id = ? OR seq = ?)"
                " ORDER BY id LIMIT 1",
                (board, value, value),
            ).fetchone()
        return self._row_to_post(row) if row else None

    def _row_to_post(self, row: sqlite3.Row) -> Post:
        return Post(
            id=row["id"],
            board=row["board"],
            seq=row["seq"],
            name=row["name"],
            title=row["title"],
            body=row["body"],
            created=row["created"],
            updated=row["updated"],
            edit_count=row["edit_count"],
            deleted=bool(row["deleted"]),
            deleted_by=row["deleted_by"],
            nbytes=row["nbytes"],
        )

    def list_posts(
        self,
        *,
        board: str | None = None,
        since: int | None = None,
        before: int | None = None,
        limit: int = 50,
        order: str = "desc",
        include_deleted: bool = False,
        author: str | None = None,
        search: str | None = None,
    ) -> list[Post]:
        where: list[str] = []
        params: list[Any] = []
        if board:
            where.append("board = ?")
            params.append(board)
        if not include_deleted:
            where.append("deleted = 0")
        if since is not None:
            where.append("id > ?")
            params.append(since)
        if before is not None:
            where.append("id < ?")
            params.append(before)
        if author:
            where.append("name = ?")
            params.append(author)
        if search:
            where.append("(body LIKE ? OR title LIKE ?)")
            needle = f"%{search}%"
            params.extend([needle, needle])

        direction = "ASC" if order.lower() == "asc" else "DESC"
        limit = max(1, min(limit, self.cfg.max_limit))
        sql = "SELECT * FROM posts"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY id {direction} LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_post(r) for r in rows]

    def revisions(self, post_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT rev, action, name, title, body, ts, actor FROM revisions"
                " WHERE post_id = ? ORDER BY id ASC",
                (post_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def _authorise(self, post: Post, token: str) -> None:
        if not token or not token_matches(token, self._token_hash(post.id)):
            raise StoreError("invalid or missing edit key", 403)

    def _token_hash(self, post_id: int) -> str:
        row = self._conn.execute(
            "SELECT token_hash FROM posts WHERE id = ?", (post_id,)
        ).fetchone()
        return row["token_hash"] if row else ""

    def edit_post(
        self,
        *,
        post: Post,
        body: str,
        token: str,
        name: str | None = None,
        title: str | None = None,
        actor: str = "",
        action: str = "edit",
    ) -> Post:
        self._authorise(post, token)
        if post.deleted:
            raise StoreError(f"entry {post.id} is deleted", 410)
        body = body.replace("\r\n", "\n").replace("\r", "\n")
        if not body.strip():
            raise StoreError("text is empty", 400)
        if len(body.encode("utf-8")) > self.cfg.max_post_bytes:
            raise StoreError(
                f"text exceeds max_post_bytes={self.cfg.max_post_bytes}", 413
            )
        new_name = post.name if name is None else name
        new_title = post.title if title is None else title
        if len(new_title.encode("utf-8")) > self.cfg.max_title_bytes:
            raise StoreError("title too long", 413)
        if len(new_name.encode("utf-8")) > self.cfg.max_name_bytes:
            raise StoreError("name too long", 413)
        now = utcnow()
        with self._lock:
            rev = post.edit_count + 1
            self._conn.execute(
                """
                UPDATE posts SET body = ?, title = ?, name = ?, updated = ?,
                                 edit_count = ?, nbytes = ?
                 WHERE id = ?
                """,
                (
                    body,
                    new_title,
                    new_name,
                    now,
                    rev,
                    len(body.encode("utf-8")),
                    post.id,
                ),
            )
            self._record_revision(
                post.id, rev, action, new_name, new_title, body, now, actor
            )
        updated = self.get_post(post.id)
        assert updated is not None
        return updated

    def append_post(
        self,
        *,
        post: Post,
        body: str,
        token: str,
        separator: str = "\n\n",
        actor: str = "",
    ) -> Post:
        addition = body.replace("\r\n", "\n").replace("\r", "\n")
        if not addition.strip():
            raise StoreError("text is empty", 400)
        if len(addition.encode("utf-8")) > self.cfg.max_append_bytes:
            raise StoreError(
                f"append exceeds max_append_bytes={self.cfg.max_append_bytes}", 413
            )
        merged = post.body + separator + addition
        if len(merged.encode("utf-8")) > self.cfg.max_post_bytes:
            raise StoreError(
                f"appended result exceeds max_post_bytes={self.cfg.max_post_bytes}", 413
            )
        return self.edit_post(
            post=post, body=merged, token=token, actor=actor, action="append"
        )

    def delete_post(self, *, post: Post, token: str, actor: str = "") -> Post:
        self._authorise(post, token)
        now = utcnow()
        with self._lock:
            self._conn.execute(
                "UPDATE posts SET deleted = 1, deleted_by = ?, updated = ? WHERE id = ?",
                (actor or "self", now, post.id),
            )
            self._record_revision(
                post.id, post.edit_count + 1, "delete", post.name, post.title, "", now, actor
            )
        gone = self.get_post(post.id)
        assert gone is not None
        return gone

    def admin_delete(self, *, post: Post, actor: str = "moderator") -> Post:
        now = utcnow()
        with self._lock:
            self._conn.execute(
                "UPDATE posts SET deleted = 1, deleted_by = ?, updated = ? WHERE id = ?",
                (actor, now, post.id),
            )
            self._record_revision(
                post.id, post.edit_count + 1, "delete", post.name, post.title, "", now, actor
            )
        gone = self.get_post(post.id)
        assert gone is not None
        return gone

    # -- stats -----------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        with self._lock:
            live = self._conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(nbytes),0) AS b FROM posts"
                " WHERE deleted = 0"
            ).fetchone()
            dead = self._conn.execute(
                "SELECT COUNT(*) AS n FROM posts WHERE deleted = 1"
            ).fetchone()
            boards = self._conn.execute("SELECT COUNT(*) AS n FROM boards").fetchone()
            files = self._conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(nbytes),0) AS b FROM files"
            ).fetchone()
            latest = self._conn.execute(
                "SELECT COALESCE(MAX(id),0) AS id, COALESCE(MAX(updated),0) AS ts FROM posts"
            ).fetchone()
            created = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'created'"
            ).fetchone()
        return {
            "boards": int(boards["n"]),
            "posts_live": int(live["n"]),
            "posts_deleted": int(dead["n"]),
            "posts_bytes": int(live["b"]),
            "files": int(files["n"]),
            "files_bytes": int(files["b"]),
            "latest_id": int(latest["id"]),
            "latest_ts": round(float(latest["ts"]), 3),
            "created": round(float(created["value"]), 3) if created else 0.0,
        }

    # -- files -----------------------------------------------------------

    def put_file(
        self, *, name: str, data: bytes, content_type: str, token: str
    ) -> dict[str, Any]:
        if not self.cfg.files_enabled:
            raise StoreError("file hosting is disabled", 403)
        if len(data) > self.cfg.max_file_bytes:
            raise StoreError(f"file exceeds max_file_bytes={self.cfg.max_file_bytes}", 413)
        if len(name.encode("utf-8")) > self.cfg.max_file_name_bytes:
            raise StoreError("file name too long", 413)
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", name) or ".." in name:
            raise StoreError("invalid file name", 400)
        ctype = (content_type or "application/octet-stream").split(";")[0].strip().lower()
        if ctype not in self.cfg.allowed_file_types:
            raise StoreError(f"content type not allowed: {ctype}", 415)

        digest = hashlib.sha256(data).hexdigest()
        now = utcnow()

        with self._lock:
            total = self._conn.execute(
                "SELECT COALESCE(SUM(nbytes),0) AS b FROM files"
            ).fetchone()["b"]
            existing = self._conn.execute(
                "SELECT nbytes, token_hash FROM files WHERE name = ?", (name,)
            ).fetchone()

            # Overwriting someone else's file needs their key. Checked before the
            # upsert, since the upsert would otherwise clobber the stored hash.
            if existing is not None and not token_matches(token, existing["token_hash"]):
                raise StoreError(f"file {name!r} already exists (edit key required)", 403)

            projected = int(total) - (int(existing["nbytes"]) if existing else 0) + len(data)
            if projected > self.cfg.max_files_total_bytes:
                raise StoreError("file storage quota exceeded", 507)

            self._conn.execute(
                """
                INSERT INTO files(name, content_type, nbytes, sha256, created, token_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    content_type = excluded.content_type,
                    nbytes       = excluded.nbytes,
                    sha256       = excluded.sha256,
                    created      = excluded.created
                """,
                (name, ctype, len(data), digest, now, hash_token(token)),
            )

        directory = Path(self.cfg.files_dir)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_bytes(data)
        return {
            "name": name,
            "content_type": ctype,
            "bytes": len(data),
            "sha256": digest,
        }

    def _file_token_hash(self, name: str) -> str:
        row = self._conn.execute(
            "SELECT token_hash FROM files WHERE name = ?", (name,)
        ).fetchone()
        return row["token_hash"] if row else ""

    def get_file(self, name: str) -> dict[str, Any] | None:
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", name) or ".." in name:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT name, content_type, nbytes, sha256, created FROM files WHERE name = ?",
                (name,),
            ).fetchone()
        return dict(row) if row else None

    def read_file(self, name: str) -> bytes | None:
        if self.get_file(name) is None:
            return None
        try:
            return (Path(self.cfg.files_dir) / name).read_bytes()
        except OSError:
            return None

    def list_files(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT name, content_type, nbytes, sha256, created, downloads"
                " FROM files ORDER BY created DESC LIMIT ?",
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_file(self, *, name: str, token: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT token_hash FROM files WHERE name = ?", (name,)
            ).fetchone()
            if row is None:
                raise StoreError("no such file", 404)
            if not token_matches(token, row["token_hash"]):
                raise StoreError("invalid or missing edit key", 403)
            self._conn.execute("DELETE FROM files WHERE name = ?", (name,))
        try:
            (Path(self.cfg.files_dir) / name).unlink()
        except OSError:
            pass
        return True


def prune_files(store: Store, keep: Iterable[str]) -> int:
    """Remove files on disk that have no database row. Returns count removed."""
    keepset = set(keep)
    removed = 0
    directory = Path(store.cfg.files_dir)
    if not directory.is_dir():
        return 0
    for entry in directory.iterdir():
        if entry.is_file() and entry.name not in keepset:
            try:
                entry.unlink()
                removed += 1
            except OSError:
                pass
    return removed


def posts_to_ndjson(posts: Sequence[Post]) -> str:
    return "\n".join(json.dumps(p.to_dict(), ensure_ascii=False) for p in posts) + "\n"
