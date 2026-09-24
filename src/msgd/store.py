"""SQLite storage for the current state only.

There is no ownership, revision history, moderation state, or soft delete.
Anyone may edit or delete any post. Creating a new post evicts the oldest posts
only when necessary to keep current post-body bytes within max_storage_bytes.
"""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from msgd.config import Config

BOARD_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
RESERVED_BOARDS = {
    "rules",
    "_rules",
    "_help",
    "_schema",
    "_health",
    "_search",
    "publish",
    "llms.txt",
    "robots.txt",
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
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    board   TEXT NOT NULL REFERENCES boards(name) ON DELETE CASCADE,
    seq     INTEGER NOT NULL,
    name    TEXT NOT NULL DEFAULT 'anonymous',
    title   TEXT NOT NULL DEFAULT '',
    body    TEXT NOT NULL,
    created REAL NOT NULL,
    updated REAL NOT NULL,
    nbytes  INTEGER NOT NULL
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
        }


def valid_board_name(name: str) -> bool:
    return bool(BOARD_RE.fullmatch(name)) and name not in RESERVED_BOARDS


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
            for name, description in DEFAULT_BOARDS.items():
                self._ensure_board(name, description)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _check(self, *, body: str, title: str, name: str) -> tuple[str, str, str, int]:
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

    def create_post(self, *, board: str, body: str, name: str, title: str) -> tuple[Post, int]:
        body, title, name, nbytes = self._check(body=body, title=title, name=name)
        self.ensure_board(board)
        now = time.time()
        evicted = 0

        with self._lock, self._conn:
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
                INSERT INTO posts(board, seq, name, title, body, created, updated, nbytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (board, seq, name, title, body, now, now, nbytes),
            )
            post_id = int(cur.lastrowid or 0)

        post = self.get_post(post_id)
        assert post is not None
        return post, evicted

    def get_post(self, post_id: int) -> Post | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, board, seq, name, title, body, created, updated, nbytes"
                " FROM posts WHERE id = ?",
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
                """
                SELECT id, board, seq, name, title, body, created, updated, nbytes
                  FROM posts
                 WHERE board = ? AND (id = ? OR seq = ?)
                 ORDER BY id ASC LIMIT 1
                """,
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
    ) -> Post:
        body, new_title, new_name, nbytes = self._check(
            body=body,
            title=post.title if title is None else title,
            name=post.name if name is None else name,
        )
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

    def delete_post(self, post_id: int) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
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
        if search:
            where.append("(title LIKE ? OR body LIKE ?)")
            params.extend((f"%{search}%", f"%{search}%"))

        sql = (
            "SELECT id, board, seq, name, title, body, created, updated, nbytes FROM posts"
        )
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id " + ("ASC" if order == "asc" else "DESC") + " LIMIT ?"
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))

        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [post for row in rows if (post := self._row(row)) is not None]

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
        )
