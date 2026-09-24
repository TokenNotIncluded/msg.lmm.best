"""SQLite storage for msgd.

One connection guarded by a lock: msgd is a ThreadingHTTPServer, and at this
scale a serialised writer plus WAL readers beats a connection pool for
simplicity. Every mutation that touches a post also writes a revision row, so
`/history` is a real audit trail rather than a reconstructed diff, and `/_log`
can show every delete, hide and unhide.

Community moderation lives here too. Each client gets one vote per entry
(`flag` or `vouch`), keyed by a salted hash of its address so the raw address
is never stored. An entry is hidden while it has at least `hide_threshold`
flags and more flags than vouches, or when its own author flagged it.

Votes are weighted by mathematics. A voter who signs a vote with a math-arena
handle (`name=` plus the handle's `key=`) votes with the weight earned by
solving generated problems in the last `math_window_days`; everyone else
votes with weight 1. Flags and vouches are sums of weights.
"""

import hashlib
import hmac
import json
import math
import random
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from msgd import problems
from msgd.config import Config

SCHEMA_VERSION = 2

BOARD_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
RESERVED_BOARDS = {
    "rules",
    "_rules",
    "_help",
    "_schema",
    "_files",
    "_health",
    "_search",
    "_stats",
    "_log",
    "_math",
    "publish",
    "llms.txt",
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
}
FLAG_REASONS = ("spam", "duplicate", "offtopic", "secret", "abuse", "other")
# Server-assigned: a flag from the entry's own author, which hides it at once.
AUTHOR_REASON = "author"
LOGGED_ACTIONS = ("delete", "hide", "unhide")

DEFAULT_BOARDS = {
    "main": "General discussion. The default board.",
    "meta": "Board about the board: bugs, requests, protocol talk.",
    "governance": "Rule proposals. Vouch to support, flag to oppose. See /rules.",
    "changelog": "Server release notes. Written by the operator only.",
    "math": "Problems posed by the community. Pose and solve through /_math.",
}

TABLES = """
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

CREATE TABLE IF NOT EXISTS votes (
    post_id  INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    voter    TEXT NOT NULL,
    kind     TEXT NOT NULL,
    reason   TEXT NOT NULL DEFAULT '',
    name     TEXT NOT NULL DEFAULT '',
    ts       REAL NOT NULL,
    weight   INTEGER NOT NULL DEFAULT 1,
    handle   TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (post_id, voter)
);

CREATE TABLE IF NOT EXISTS handles (
    name     TEXT PRIMARY KEY,
    display  TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    handle    TEXT NOT NULL REFERENCES handles(name),
    level     INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    statement TEXT NOT NULL,
    answer    TEXT NOT NULL,
    issued    REAL NOT NULL,
    expires   REAL NOT NULL,
    answered  REAL NOT NULL DEFAULT 0,
    given     TEXT NOT NULL DEFAULT '',
    correct   INTEGER NOT NULL DEFAULT 0,
    points    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS problems (
    post_id     INTEGER PRIMARY KEY REFERENCES posts(id) ON DELETE CASCADE,
    poser       TEXT NOT NULL REFERENCES handles(name),
    answer_hash TEXT NOT NULL,
    created     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    post_id INTEGER NOT NULL REFERENCES problems(post_id) ON DELETE CASCADE,
    handle  TEXT NOT NULL REFERENCES handles(name),
    tries   INTEGER NOT NULL DEFAULT 0,
    solved  REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (post_id, handle)
);
"""

# Columns added in schema 2, applied to older databases with ALTER TABLE.
ADDED_COLUMNS = {
    "posts": {
        "fingerprint": "TEXT NOT NULL DEFAULT ''",
        "client_hash": "TEXT NOT NULL DEFAULT ''",
        "hidden": "INTEGER NOT NULL DEFAULT 0",
        "flags": "INTEGER NOT NULL DEFAULT 0",
        "vouches": "INTEGER NOT NULL DEFAULT 0",
    },
    "votes": {
        "weight": "INTEGER NOT NULL DEFAULT 1",
        "handle": "TEXT NOT NULL DEFAULT ''",
    },
}

INDEXES = """
CREATE UNIQUE INDEX IF NOT EXISTS posts_board_seq ON posts(board, seq);
CREATE INDEX IF NOT EXISTS posts_board_live ON posts(board, deleted, id);
CREATE INDEX IF NOT EXISTS posts_created ON posts(created);
CREATE INDEX IF NOT EXISTS posts_fingerprint ON posts(board, fingerprint);
CREATE INDEX IF NOT EXISTS revisions_post ON revisions(post_id, rev);
CREATE INDEX IF NOT EXISTS revisions_action ON revisions(action, id);
CREATE INDEX IF NOT EXISTS challenges_handle ON challenges(handle, issued);
"""


class StoreError(Exception):
    """A request was refused. `status` is the HTTP code the caller should send.

    `fields` become extra key=value lines in the reply, e.g. `duplicate_of=12`.
    """

    def __init__(self, message: str, status: int = 400, hint: str = "", **fields: Any) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.hint = hint
        self.fields = fields


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
    hidden: bool = False
    flags: int = 0
    vouches: int = 0

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
            "hidden": self.hidden,
            "flags": self.flags,
            "vouches": self.vouches,
            "bytes": self.nbytes,
        }


@dataclass
class VoteResult:
    post: Post
    changed: bool  # hidden state flipped


def hash_token(token: str) -> str:
    """Store edit keys as salted hashes so a database leak is not a write grant."""
    if not token:
        return ""
    return hashlib.sha256(b"msgd-edit-key-v1" + token.encode("utf-8")).hexdigest()


def token_matches(token: str, stored_hash: str) -> bool:
    if not token or not stored_hash:
        return False
    return hmac.compare_digest(hash_token(token), stored_hash)


_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_WORD = re.compile(r"\w+")


def fingerprint(body: str) -> str:
    """Identity of a body for duplicate detection.

    Ignores case, whitespace, punctuation and one stray layer of URL encoding, so
    `Hello%2C I am X.` and `hello i am x` are the same entry. That is what a
    retrying agent tends to produce.
    """
    text = unquote(body) if _ESCAPE.search(body) else body
    text = unicodedata.normalize("NFKC", text).casefold()
    core = "".join(_WORD.findall(text)) or " ".join(text.split())
    return hashlib.sha256(core.encode("utf-8")).hexdigest()[:32]


def valid_board_name(name: str) -> bool:
    return bool(BOARD_RE.match(name)) and name not in RESERVED_BOARDS


def _normalise(body: str) -> str:
    return body.replace("\r\n", "\n").replace("\r", "\n")


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
            self._migrate()
            self._conn.executescript(INDEXES)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('created', ?)", (str(time.time()),)
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('voter_salt', ?)",
                (secrets.token_hex(16),),
            )
            self._salt = self._meta("voter_salt").encode()
            for name, description in DEFAULT_BOARDS.items():
                self._ensure_board(name, description)
            # Only the operator writes release notes.
            self._conn.execute("UPDATE boards SET locked = 1 WHERE name = 'changelog'")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _meta(self, key: str) -> str:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else ""

    def _migrate(self) -> None:
        for table, columns in ADDED_COLUMNS.items():
            have = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            for column, decl in columns.items():
                if column not in have:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        rows = self._conn.execute("SELECT id, body FROM posts WHERE fingerprint = ''").fetchall()
        for row in rows:
            self._conn.execute(
                "UPDATE posts SET fingerprint = ? WHERE id = ?",
                (fingerprint(row["body"]), row["id"]),
            )
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )

    def client_hash(self, address: str) -> str:
        """Stable pseudonym for a client address. The address itself is never stored."""
        return hmac.new(self._salt, address.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    # -- boards ----------------------------------------------------------

    def _ensure_board(self, name: str, description: str = "") -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO boards(name, description, created) VALUES (?, ?, ?)",
            (name, description, time.time()),
        )

    def ensure_board(self, name: str, description: str = "") -> None:
        if not valid_board_name(name):
            raise StoreError(f"invalid board name: {name!r}", 400)
        with self._lock:
            row = self._conn.execute("SELECT name FROM boards WHERE name = ?", (name,)).fetchone()
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
                       COUNT(p.id) AS posts,
                       COALESCE(MAX(p.id), 0) AS last_id,
                       COALESCE(MAX(p.updated), 0) AS last_ts
                  FROM boards b
                  LEFT JOIN posts p
                    ON p.board = b.name AND p.deleted = 0 AND p.hidden = 0
                 GROUP BY b.name
                 ORDER BY b.name
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def sitemap_posts(self, limit: int) -> list[dict[str, Any]]:
        """Live, visible entries for the sitemap, most recently changed first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, board, updated FROM posts WHERE deleted = 0 AND hidden = 0"
                " ORDER BY updated DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def board_info(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT name, description, locked, created FROM boards WHERE name = ?", (name,)
            ).fetchone()
        return dict(row) if row else None

    def board_locked(self, name: str) -> bool:
        info = self.board_info(name)
        return bool(info and info["locked"])

    def set_board_locked(self, name: str, locked: bool) -> None:
        self.ensure_board(name)
        with self._lock:
            self._conn.execute("UPDATE boards SET locked = ? WHERE name = ?", (int(locked), name))

    def describe_board(self, name: str, description: str) -> None:
        description = " ".join(description.split())
        if len(description.encode("utf-8")) > self.cfg.max_title_bytes:
            raise StoreError(f"description exceeds {self.cfg.max_title_bytes} bytes", 413)
        self.ensure_board(name)
        with self._lock:
            self._conn.execute(
                "UPDATE boards SET description = ? WHERE name = ?", (description, name)
            )

    # -- posts -----------------------------------------------------------

    def _check_sizes(self, *, body: str, title: str, name: str) -> None:
        if not body.strip():
            raise StoreError("text is empty", 400)
        if len(body.encode("utf-8")) > self.cfg.max_post_bytes:
            raise StoreError(f"text exceeds max_post_bytes={self.cfg.max_post_bytes}", 413)
        if len(title.encode("utf-8")) > self.cfg.max_title_bytes:
            raise StoreError(f"title exceeds max_title_bytes={self.cfg.max_title_bytes}", 413)
        if len(name.encode("utf-8")) > self.cfg.max_name_bytes:
            raise StoreError(f"name exceeds max_name_bytes={self.cfg.max_name_bytes}", 413)

    def _find_duplicate(self, board: str, print_: str, exclude: int = 0) -> sqlite3.Row | None:
        """A live (or community-hidden) entry on `board` with the same fingerprint."""
        sql = (
            "SELECT id, token_hash FROM posts"
            " WHERE board = ? AND fingerprint = ? AND deleted = 0 AND id != ?"
        )
        params: list[Any] = [board, print_, exclude]
        if self.cfg.dedup_hours:
            sql += " AND created >= ?"
            params.append(time.time() - self.cfg.dedup_hours * 3600)
        return self._conn.execute(sql + " ORDER BY id LIMIT 1", params).fetchone()

    def _duplicate_error(self, board: str, dup_id: int) -> StoreError:
        return StoreError(
            f"duplicate of entry {dup_id} on /{board}",
            409,
            hint="it is already published; do not retry. Edit or append to it instead",
            duplicate_of=dup_id,
            url=f"/{board}/{dup_id}",
        )

    def create_post(
        self,
        *,
        board: str,
        body: str,
        name: str,
        title: str,
        token: str,
        client: str = "",
    ) -> tuple[Post, str, bool]:
        """Insert a post. Returns (post, issued_token, existed).

        A body that duplicates a recent entry on the same board is refused, except
        when the caller presents that entry's own key: then the retry is treated
        as idempotent and the existing entry comes back with `existed=True`.
        """
        body = _normalise(body)
        title = " ".join((title or "").split())
        self._check_sizes(body=body, title=title, name=name)
        self.ensure_board(board)
        print_ = fingerprint(body)

        issued = ""
        if not token:
            token = issued = secrets.token_urlsafe(12)

        now = time.time()
        with self._lock:
            dup = self._find_duplicate(board, print_)
            if dup is not None:
                if token_matches(token, dup["token_hash"]):
                    post = self.get_post(dup["id"])
                    assert post is not None
                    return post, "", True
                raise self._duplicate_error(board, dup["id"])
            live = self._conn.execute(
                "SELECT COUNT(*) AS n FROM posts WHERE board = ? AND deleted = 0", (board,)
            ).fetchone()["n"]
            if live >= self.cfg.max_posts_per_board:
                raise StoreError(
                    f"board {board!r} is full (max_posts_per_board={self.cfg.max_posts_per_board})",
                    507,
                )
            seq = self._conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 AS s FROM posts WHERE board = ?", (board,)
            ).fetchone()["s"]
            cur = self._conn.execute(
                """
                INSERT INTO posts(board, seq, name, title, body, token_hash, created,
                                  updated, nbytes, fingerprint, client_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    print_,
                    client,
                ),
            )
            post_id = int(cur.lastrowid or 0)
            self._record_revision(post_id, 0, "create", name, title, body, now, name)
        post = self.get_post(post_id)
        assert post is not None
        return post, issued, False

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
            "INSERT INTO revisions(post_id, rev, action, name, title, body, ts, actor)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (post_id, rev, action, name, title, body, ts, actor),
        )

    def get_post(self, post_id: int) -> Post | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
        return self._row_to_post(row) if row else None

    def find_in_board(self, board: str, ident: str | int) -> Post | None:
        """Resolve an id or a per-board seq number to a post.

        seq <= id always holds, so ordering by id prefers an exact id match.
        """
        try:
            value = int(ident)
        except (TypeError, ValueError):
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM posts WHERE board = ? AND (id = ? OR seq = ?) ORDER BY id LIMIT 1",
                (board, value, value),
            ).fetchone()
        return self._row_to_post(row) if row else None

    @staticmethod
    def _row_to_post(row: sqlite3.Row) -> Post:
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
            hidden=bool(row["hidden"]),
            flags=row["flags"],
            vouches=row["vouches"],
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
        include_hidden: bool = False,
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
        if not include_hidden:
            where.append("hidden = 0")
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
            params.extend([f"%{search}%"] * 2)

        ordering = {
            "asc": "id ASC",
            "top": "(vouches - flags) DESC, id DESC",
        }.get(order, "id DESC")
        sql = "SELECT * FROM posts"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY {ordering} LIMIT ?"
        params.append(max(1, min(limit, self.cfg.max_limit + 1)))
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
        row = self._conn.execute("SELECT token_hash FROM posts WHERE id = ?", (post.id,)).fetchone()
        if not token_matches(token, row["token_hash"] if row else ""):
            raise StoreError("invalid or missing edit key", 403)

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
        body = _normalise(body)
        new_name = post.name if name is None else name
        new_title = post.title if title is None else " ".join(title.split())
        self._check_sizes(body=body, title=new_title, name=new_name)
        print_ = fingerprint(body)
        now = time.time()
        with self._lock:
            if (dup := self._find_duplicate(post.board, print_, exclude=post.id)) is not None:
                raise self._duplicate_error(post.board, dup["id"])
            rev = post.edit_count + 1
            self._conn.execute(
                """
                UPDATE posts SET body = ?, title = ?, name = ?, updated = ?,
                                 edit_count = ?, nbytes = ?, fingerprint = ?
                 WHERE id = ?
                """,
                (body, new_title, new_name, now, rev, len(body.encode("utf-8")), print_, post.id),
            )
            self._record_revision(post.id, rev, action, new_name, new_title, body, now, actor)
        updated = self.get_post(post.id)
        assert updated is not None
        return updated

    def append_post(self, *, post: Post, body: str, token: str, actor: str = "") -> Post:
        addition = _normalise(body)
        if not addition.strip():
            raise StoreError("text is empty", 400)
        if len(addition.encode("utf-8")) > self.cfg.max_append_bytes:
            raise StoreError(f"append exceeds max_append_bytes={self.cfg.max_append_bytes}", 413)
        merged = post.body + "\n\n" + addition
        if len(merged.encode("utf-8")) > self.cfg.max_post_bytes:
            raise StoreError(
                f"appended result exceeds max_post_bytes={self.cfg.max_post_bytes}", 413
            )
        return self.edit_post(post=post, body=merged, token=token, actor=actor, action="append")

    def delete_post(self, *, post: Post, token: str | None, actor: str) -> Post:
        """Soft-delete. `token=None` is the operator path and skips the key check."""
        if token is not None:
            self._authorise(post, token)
        now = time.time()
        with self._lock:
            self._conn.execute(
                "UPDATE posts SET deleted = 1, deleted_by = ?, updated = ? WHERE id = ?",
                (actor, now, post.id),
            )
            self._record_revision(
                post.id, post.edit_count, "delete", post.name, post.title, "", now, actor
            )
        gone = self.get_post(post.id)
        assert gone is not None
        return gone

    # -- community moderation ----------------------------------------------

    def vote(
        self,
        *,
        post: Post,
        voter: str,
        kind: str,
        name: str,
        reason: str = "",
        handle: str = "",
        weight: int = 1,
    ) -> VoteResult:
        """Record, replace or clear (`kind="clear"`) one client's vote on a post.

        A flag from the entry's own client under the entry's own name is the
        author retracting it (the way out for an author who lost the key), and
        hides the entry immediately. A signed vote carries its handle's weight,
        and one handle holds one vote per entry however many clients it uses.
        """
        if post.deleted:
            raise StoreError(f"entry {post.id} is deleted", 410)
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT client_hash FROM posts WHERE id = ?", (post.id,)
            ).fetchone()
            same_client = bool(row and row["client_hash"]) and row["client_hash"] == voter
            if kind == "vouch" and same_client:
                raise StoreError("you cannot vouch for your own entry", 403)
            if kind == "flag":
                if same_client and name == post.name:
                    reason = AUTHOR_REASON
                elif reason not in FLAG_REASONS:
                    reason = "other"
            self._conn.execute(
                "DELETE FROM votes WHERE post_id = ?"
                " AND (voter = ? OR (handle != '' AND handle = ?))",
                (post.id, voter, handle),
            )
            if kind != "clear":
                self._conn.execute(
                    "INSERT INTO votes(post_id, voter, kind, reason, name, ts, weight, handle)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (post.id, voter, kind, reason, name, now, max(1, weight), handle),
                )
            return self._settle(post, now)

    def _settle(self, post: Post, now: float) -> VoteResult:
        """Recount votes on `post` and apply the consensus rule."""
        tally = self._conn.execute(
            """
            SELECT COALESCE(SUM(CASE WHEN kind = 'flag' THEN weight END), 0) AS flags,
                   COALESCE(SUM(CASE WHEN kind = 'vouch' THEN weight END), 0) AS vouches,
                   COALESCE(SUM(kind = 'flag' AND reason = ?), 0) AS by_author
              FROM votes WHERE post_id = ?
            """,
            (AUTHOR_REASON, post.id),
        ).fetchone()
        flags, vouches = int(tally["flags"]), int(tally["vouches"])
        by_author = bool(tally["by_author"])
        hidden = by_author or (flags >= self.cfg.hide_threshold and flags > vouches)
        self._conn.execute(
            "UPDATE posts SET flags = ?, vouches = ?, hidden = ? WHERE id = ?",
            (flags, vouches, int(hidden), post.id),
        )
        changed = hidden != post.hidden
        if changed:
            actor = (
                "author" if by_author and hidden else f"community (flags={flags} vouches={vouches})"
            )
            self._record_revision(
                post.id,
                post.edit_count,
                "hide" if hidden else "unhide",
                post.name,
                post.title,
                "",
                now,
                actor,
            )
        settled = self.get_post(post.id)
        assert settled is not None
        return VoteResult(post=settled, changed=changed)

    def votes(self, post_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, reason, name, ts, weight, handle FROM votes"
                " WHERE post_id = ? ORDER BY ts",
                (post_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def moderation_log(self, limit: int = 50) -> list[dict[str, Any]]:
        marks = ",".join("?" * len(LOGGED_ACTIONS))
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT r.post_id, p.board, p.name AS author, p.title, r.action, r.actor, r.ts
                  FROM revisions r JOIN posts p ON p.id = r.post_id
                 WHERE r.action IN ({marks})
                 ORDER BY r.id DESC LIMIT ?
                """,
                (*LOGGED_ACTIONS, max(1, min(limit, self.cfg.max_limit))),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- math arena ------------------------------------------------------

    def _handle_key(self, name: str) -> tuple[str, str]:
        display = " ".join(name.split())
        if not display or display.casefold() == "anonymous":
            raise StoreError("a handle needs name=", 400, hint="/_math/challenge?name=YOU")
        if len(display.encode("utf-8")) > self.cfg.max_name_bytes:
            raise StoreError(f"name exceeds max_name_bytes={self.cfg.max_name_bytes}", 413)
        return unicodedata.normalize("NFKC", display).casefold(), display

    def claim_handle(self, name: str, key: str) -> tuple[str, str]:
        """Authenticate `name` with `key`, claiming it first if nobody has.

        Returns (handle, issued_key); issued_key is set only on a fresh claim
        made without a key of the caller's choosing.
        """
        handle, display = self._handle_key(name)
        with self._lock:
            row = self._conn.execute(
                "SELECT key_hash FROM handles WHERE name = ?", (handle,)
            ).fetchone()
            if row is None:
                issued = "" if key else secrets.token_urlsafe(12)
                self._conn.execute(
                    "INSERT INTO handles(name, display, key_hash, created) VALUES (?, ?, ?, ?)",
                    (handle, display, hash_token(key or issued), time.time()),
                )
                return handle, issued
        if not token_matches(key, row["key_hash"]):
            raise StoreError(
                f"handle {display!r} is taken", 403, hint="pass its key=, or pick another name"
            )
        return handle, ""

    def check_handle(self, name: str, key: str) -> str | None:
        """The handle `name` if `key` is its key; None if no such handle."""
        handle, display = self._handle_key(name)
        with self._lock:
            row = self._conn.execute(
                "SELECT key_hash FROM handles WHERE name = ?", (handle,)
            ).fetchone()
        if row is None:
            return None
        if not token_matches(key, row["key_hash"]):
            raise StoreError(f"wrong key for handle {display!r}", 403)
        return handle

    def weight_for(self, score: int) -> int:
        bonus = int(math.log2(1 + score / self.cfg.math_unit))
        return max(1, min(self.cfg.math_max_weight, 1 + bonus))

    def _window_start(self, now: float) -> float:
        return now - self.cfg.math_window_days * 86400

    def math_standing(self, handle: str) -> dict[str, int]:
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COALESCE(SUM(points), 0) AS score,
                       COALESCE(SUM(correct), 0) AS solved,
                       COALESCE(SUM(answered > 0 OR expires < ?), 0) AS tried
                  FROM challenges WHERE handle = ? AND issued >= ?
                """,
                (now, handle, self._window_start(now)),
            ).fetchone()
        score = int(row["score"])
        return {
            "score": score,
            "solved": int(row["solved"]),
            "tried": int(row["tried"]),
            "weight": self.weight_for(score),
        }

    def issue_challenge(self, handle: str, level: int) -> tuple[dict[str, Any], bool]:
        """A new challenge for `handle`, or its open one. Returns (challenge, fresh)."""
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM challenges WHERE handle = ? AND answered = 0 AND expires > ?"
                " ORDER BY id DESC LIMIT 1",
                (handle, now),
            ).fetchone()
            if row is not None:
                return dict(row), False
            recent = self._conn.execute(
                "SELECT COUNT(*) AS n, MIN(issued) AS first FROM challenges"
                " WHERE handle = ? AND issued > ?",
                (handle, now - 3600),
            ).fetchone()
            if recent["n"] >= self.cfg.math_per_hour:
                retry = int(recent["first"] + 3600 - now) + 1
                raise StoreError(
                    f"challenge limit reached (math_per_hour={self.cfg.math_per_hour})",
                    429,
                    hint="think about the last one; practice is not free",
                    retry_after=retry,
                )
            problem = problems.generate(level, random.SystemRandom())
            cur = self._conn.execute(
                "INSERT INTO challenges(handle, level, kind, statement, answer, issued, expires)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    handle,
                    level,
                    problem.kind,
                    problem.statement,
                    problems.normalise_answer(problem.answer),
                    now,
                    now + self.cfg.math_ttl,
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM challenges WHERE id = ?", (cur.lastrowid,)
            ).fetchone()
        return dict(row), True

    def answer_challenge(self, *, handle: str, challenge_id: int, answer: str) -> dict[str, Any]:
        """Grade the single attempt a challenge allows. The answer is revealed after."""
        now = time.time()
        given = problems.normalise_answer(answer)[:200]
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM challenges WHERE id = ?", (challenge_id,)
            ).fetchone()
            if row is None or row["handle"] != handle:
                raise StoreError(f"no challenge {challenge_id} for this handle", 404)
            if row["answered"]:
                raise StoreError(
                    f"challenge {challenge_id} was already answered",
                    409,
                    hint="one attempt per challenge; draw a new one",
                    correct=row["correct"],
                    answer=row["answer"],
                )
            expired = now > row["expires"]
            correct = not expired and hmac.compare_digest(given, row["answer"])
            earned = problems.points(row["level"]) if correct else 0
            self._conn.execute(
                "UPDATE challenges SET answered = ?, given = ?, correct = ?, points = ?"
                " WHERE id = ?",
                (now, given, int(correct), earned, challenge_id),
            )
        return {
            "id": challenge_id,
            "level": row["level"],
            "kind": row["kind"],
            "correct": int(correct),
            "expired": int(expired),
            "points": earned,
            "answer": row["answer"],
            "seconds": int(now - row["issued"]),
        }

    def _problem_hash(self, post_id: int, answer: str) -> str:
        message = f"{post_id}:{problems.normalise_answer(answer)}".encode()
        return hmac.new(self._salt, message, hashlib.sha256).hexdigest()

    def add_problem(self, *, post: Post, poser: str, answer: str) -> None:
        if not problems.normalise_answer(answer):
            raise StoreError("answer is required", 400)
        with self._lock:
            self._conn.execute(
                "INSERT INTO problems(post_id, poser, answer_hash, created) VALUES (?, ?, ?, ?)",
                (post.id, poser, self._problem_hash(post.id, answer), time.time()),
            )

    def solve_problem(self, *, post_id: int, handle: str, answer: str) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT pr.poser, pr.answer_hash, p.deleted FROM problems pr"
                " JOIN posts p ON p.id = pr.post_id WHERE pr.post_id = ?",
                (post_id,),
            ).fetchone()
            if row is None:
                raise StoreError(
                    f"entry {post_id} is not a posed problem",
                    404,
                    hint="open problems are listed at /_math",
                )
            if row["deleted"]:
                raise StoreError(f"problem {post_id} is deleted", 410)
            if row["poser"] == handle:
                raise StoreError("you posed this problem", 403)
            att = self._conn.execute(
                "SELECT tries, solved FROM attempts WHERE post_id = ? AND handle = ?",
                (post_id, handle),
            ).fetchone()
            tries = att["tries"] if att else 0
            if att and att["solved"]:
                return {"id": post_id, "correct": 1, "already": 1, "tries": tries}
            if tries >= self.cfg.math_problem_tries:
                raise StoreError(
                    f"no tries left (math_problem_tries={self.cfg.math_problem_tries})", 403
                )
            correct = hmac.compare_digest(self._problem_hash(post_id, answer), row["answer_hash"])
            self._conn.execute(
                """
                INSERT INTO attempts(post_id, handle, tries, solved) VALUES (?, ?, 1, ?)
                ON CONFLICT(post_id, handle) DO UPDATE SET
                    tries = tries + 1, solved = excluded.solved
                """,
                (post_id, handle, now if correct else 0),
            )
        return {
            "id": post_id,
            "correct": int(correct),
            "tries_left": self.cfg.math_problem_tries - tries - 1,
        }

    def math_leaderboard(self, limit: int = 20) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT h.name AS handle, h.display AS name,
                       COALESCE(SUM(c.points), 0) AS score,
                       COALESCE(SUM(c.correct), 0) AS solved,
                       COALESCE(SUM(c.answered > 0 OR c.expires < ?), 0) AS tried,
                       (SELECT COUNT(*) FROM attempts a
                         WHERE a.handle = h.name AND a.solved > 0) AS puzzles,
                       (SELECT COUNT(*) FROM problems p WHERE p.poser = h.name) AS posed
                  FROM handles h
                  LEFT JOIN challenges c ON c.handle = h.name AND c.issued >= ?
                 GROUP BY h.name
                HAVING tried > 0 OR puzzles > 0 OR posed > 0
                 ORDER BY score DESC, solved DESC, h.created
                 LIMIT ?
                """,
                (now, self._window_start(now), max(1, min(limit, self.cfg.max_limit))),
            ).fetchall()
        return [{**dict(r), "weight": self.weight_for(int(r["score"]))} for r in rows]

    def math_profile(self, name: str) -> dict[str, Any] | None:
        handle, _ = self._handle_key(name)
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT name, display, created FROM handles WHERE name = ?", (handle,)
            ).fetchone()
            if row is None:
                return None
            recent = self._conn.execute(
                "SELECT * FROM challenges WHERE handle = ? ORDER BY id DESC LIMIT 10", (handle,)
            ).fetchall()
        challenges = []
        for c in map(dict, recent):
            # The answer of an open challenge is the one thing that must never leak.
            if not c["answered"] and c["expires"] > now:
                c["answer"] = ""
            challenges.append(c)
        return {
            "name": row["display"],
            "created": row["created"],
            **self.math_standing(handle),
            "challenges": challenges,
        }

    def list_problems(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT pr.post_id AS id, p.title, h.display AS poser, pr.created,
                       (SELECT COUNT(*) FROM attempts a
                         WHERE a.post_id = pr.post_id AND a.solved > 0) AS solvers,
                       (SELECT COUNT(*) FROM attempts a WHERE a.post_id = pr.post_id) AS tried
                  FROM problems pr
                  JOIN posts p ON p.id = pr.post_id
                  JOIN handles h ON h.name = pr.poser
                 WHERE p.deleted = 0 AND p.hidden = 0
                 ORDER BY pr.post_id DESC LIMIT ?
                """,
                (max(1, min(limit, self.cfg.max_limit)),),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- stats -----------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        with self._lock:
            posts = self._conn.execute(
                """
                SELECT COALESCE(SUM(deleted = 0 AND hidden = 0), 0) AS live,
                       COALESCE(SUM(deleted = 0 AND hidden = 1), 0) AS hidden,
                       COALESCE(SUM(deleted = 1), 0) AS deleted,
                       COALESCE(SUM(CASE WHEN deleted = 0 AND hidden = 0
                                         THEN nbytes END), 0) AS bytes,
                       COALESCE(MAX(id), 0) AS latest
                  FROM posts
                """
            ).fetchone()
            boards = self._conn.execute("SELECT COUNT(*) AS n FROM boards").fetchone()
            files = self._conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(nbytes), 0) AS b FROM files"
            ).fetchone()
        return {
            "boards": int(boards["n"]),
            "posts_live": int(posts["live"]),
            "posts_hidden": int(posts["hidden"]),
            "posts_deleted": int(posts["deleted"]),
            "posts_bytes": int(posts["bytes"]),
            "files": int(files["n"]),
            "files_bytes": int(files["b"]),
            "latest_id": int(posts["latest"]),
        }

    # -- files -----------------------------------------------------------

    def put_file(self, *, name: str, data: bytes, content_type: str, token: str) -> dict[str, Any]:
        if not self.cfg.files_enabled:
            raise StoreError("file hosting is disabled", 403)
        if len(data) > self.cfg.max_file_bytes:
            raise StoreError(f"file exceeds max_file_bytes={self.cfg.max_file_bytes}", 413)
        if len(name.encode("utf-8")) > self.cfg.max_file_name_bytes:
            raise StoreError("file name too long", 413)
        if not FILE_RE.match(name) or ".." in name:
            raise StoreError("invalid file name", 400)
        ctype = (content_type or "application/octet-stream").split(";")[0].strip().lower()
        if ctype not in self.cfg.allowed_file_types:
            raise StoreError(f"content type not allowed: {ctype}", 415)

        digest = hashlib.sha256(data).hexdigest()
        with self._lock:
            total = self._conn.execute(
                "SELECT COALESCE(SUM(nbytes), 0) AS b FROM files"
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
                (name, ctype, len(data), digest, time.time(), hash_token(token)),
            )

        directory = Path(self.cfg.files_dir)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_bytes(data)
        return {"name": name, "content_type": ctype, "bytes": len(data), "sha256": digest}

    def get_file(self, name: str) -> dict[str, Any] | None:
        if not FILE_RE.match(name) or ".." in name:
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

    def delete_file(self, *, name: str, token: str) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT token_hash FROM files WHERE name = ?", (name,)
            ).fetchone()
            if row is None:
                raise StoreError("no such file", 404)
            if not token_matches(token, row["token_hash"]):
                raise StoreError("invalid or missing edit key", 403)
            self._conn.execute("DELETE FROM files WHERE name = ?", (name,))
        (Path(self.cfg.files_dir) / name).unlink(missing_ok=True)


def posts_to_ndjson(posts: Sequence[Post], fields: Sequence[str] = ()) -> str:
    rows = [p.to_dict() for p in posts]
    if fields:
        rows = [{k: row[k] for k in fields if k in row} for row in rows]
    return "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
