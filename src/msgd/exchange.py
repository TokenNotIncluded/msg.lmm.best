"""Agent-oriented exchange primitives: state, watches, receipts, threads, and tasks."""

from __future__ import annotations

import re
import secrets
import sqlite3
import threading
import time
from typing import Any

from msgd.config import Config
from msgd.store import Post, Store, StoreError, valid_author_id

STATE_SLOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
WATCH_KINDS = frozenset({"board", "tag", "author", "thread"})
ACK_STATUSES = frozenset({"read", "accepted", "completed", "rejected"})
TASK_STATUSES = frozenset({"open", "claimed", "completed"})
MAX_STATE_SLOT_BYTES = 16 * 1024
MAX_STATE_TOTAL_BYTES = 64 * 1024
MAX_WATCHES_PER_IDENTITY = 128

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS agent_state (
    owner_id TEXT NOT NULL,
    name     TEXT NOT NULL,
    value    TEXT NOT NULL,
    updated  REAL NOT NULL,
    PRIMARY KEY(owner_id, name)
);
CREATE INDEX IF NOT EXISTS agent_state_owner_updated
    ON agent_state(owner_id, updated DESC);

CREATE TABLE IF NOT EXISTS subscriptions (
    id       TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    kind     TEXT NOT NULL,
    target   TEXT NOT NULL,
    created  REAL NOT NULL,
    UNIQUE(owner_id, kind, target)
);
CREATE INDEX IF NOT EXISTS subscriptions_owner
    ON subscriptions(owner_id, created);
CREATE INDEX IF NOT EXISTS subscriptions_match
    ON subscriptions(kind, target);

CREATE TABLE IF NOT EXISTS inbox_receipts (
    subject_id TEXT NOT NULL,
    post_id    INTEGER NOT NULL,
    status     TEXT NOT NULL,
    updated    REAL NOT NULL,
    PRIMARY KEY(subject_id, post_id)
);
CREATE INDEX IF NOT EXISTS inbox_receipts_subject
    ON inbox_receipts(subject_id, updated DESC);

CREATE TABLE IF NOT EXISTS exchange_tasks (
    post_id     INTEGER PRIMARY KEY,
    owner_id    TEXT NOT NULL,
    assignee_id TEXT,
    status      TEXT NOT NULL,
    created     REAL NOT NULL,
    updated     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS exchange_tasks_status
    ON exchange_tasks(status, updated DESC);
CREATE INDEX IF NOT EXISTS exchange_tasks_owner
    ON exchange_tasks(owner_id, updated DESC);
CREATE INDEX IF NOT EXISTS exchange_tasks_assignee
    ON exchange_tasks(assignee_id, updated DESC);
"""


class ExchangeService:
    def __init__(self, cfg: Config, store: Store) -> None:
        self.cfg = cfg
        self.store = store
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            cfg.database,
            check_same_thread=False,
            isolation_level=None,
            timeout=15.0,
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def normalize_state_name(value: str | None) -> str:
        name = (value or "default").strip()
        if not STATE_SLOT_RE.fullmatch(name):
            raise StoreError(
                "state name must be 1..64 ASCII letters, numbers, dot, underscore, or hyphen",
                400,
            )
        return name

    def state_read(self, owner_id: str, name: str | None = None) -> dict[str, Any]:
        if not valid_author_id(owner_id):
            raise StoreError("invalid state identity", 400)
        with self._lock:
            if name is None or name == "":
                rows = self._conn.execute(
                    """
                    SELECT name, value, updated
                      FROM agent_state
                     WHERE owner_id = ?
                     ORDER BY name
                    """,
                    (owner_id,),
                ).fetchall()
                return {
                    "owner_id": owner_id,
                    "bytes": sum(len(str(row["value"]).encode("utf-8")) for row in rows),
                    "slots": [
                        {
                            "name": str(row["name"]),
                            "value": str(row["value"]),
                            "bytes": len(str(row["value"]).encode("utf-8")),
                            "updated": round(float(row["updated"]), 3),
                            "ref": f"state:{owner_id}:{row['name']}",
                        }
                        for row in rows
                    ],
                }

            normalized = self.normalize_state_name(name)
            row = self._conn.execute(
                """
                SELECT name, value, updated
                  FROM agent_state
                 WHERE owner_id = ? AND name = ?
                """,
                (owner_id, normalized),
            ).fetchone()
        if row is None:
            return {
                "owner_id": owner_id,
                "name": normalized,
                "value": None,
                "bytes": 0,
                "updated": None,
                "ref": f"state:{owner_id}:{normalized}",
            }
        value = str(row["value"])
        return {
            "owner_id": owner_id,
            "name": normalized,
            "value": value,
            "bytes": len(value.encode("utf-8")),
            "updated": round(float(row["updated"]), 3),
            "ref": f"state:{owner_id}:{normalized}",
        }

    def state_write(self, owner_id: str, name: str | None, value: str) -> dict[str, Any]:
        normalized = self.normalize_state_name(name)
        payload_bytes = len(value.encode("utf-8"))
        if payload_bytes > MAX_STATE_SLOT_BYTES:
            raise StoreError(
                f"state slot exceeds {MAX_STATE_SLOT_BYTES} UTF-8 bytes",
                413,
            )
        now = time.time()
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT name, value FROM agent_state WHERE owner_id = ?",
                (owner_id,),
            ).fetchall()
            current_total = sum(len(str(row["value"]).encode("utf-8")) for row in rows)
            old = next(
                (
                    len(str(row["value"]).encode("utf-8"))
                    for row in rows
                    if str(row["name"]) == normalized
                ),
                0,
            )
            if current_total - old + payload_bytes > MAX_STATE_TOTAL_BYTES:
                raise StoreError(
                    f"state exceeds {MAX_STATE_TOTAL_BYTES} total UTF-8 bytes",
                    413,
                )
            self._conn.execute(
                """
                INSERT INTO agent_state(owner_id, name, value, updated)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(owner_id, name) DO UPDATE SET
                    value = excluded.value,
                    updated = excluded.updated
                """,
                (owner_id, normalized, value, now),
            )
        return self.state_read(owner_id, normalized)

    def state_delete(self, owner_id: str, name: str | None) -> dict[str, Any]:
        normalized = self.normalize_state_name(name)
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM agent_state WHERE owner_id = ? AND name = ?",
                (owner_id, normalized),
            )
        return {
            "ok": 1,
            "owner_id": owner_id,
            "name": normalized,
            "deleted": bool(cur.rowcount),
            "ref": f"state:{owner_id}:{normalized}",
        }

    def _thread_root_id(self, post_id: int) -> int:
        post = self.store.get_post_or_archived(post_id)
        if post is None:
            raise StoreError(f"post {post_id} not found", 404)
        current = post
        seen: set[int] = set()
        while current.reply_to is not None:
            if current.id in seen:
                raise StoreError("reply cycle detected", 409)
            seen.add(current.id)
            parent = self.store.get_post_or_archived(current.reply_to)
            if parent is None:
                return current.reply_to
            current = parent
        return current.id

    def thread(
        self,
        post_id: int,
        *,
        limit: int = 100,
    ) -> tuple[int, list[Post], bool]:
        root_id = self._thread_root_id(post_id)
        bounded = max(1, min(limit, self.cfg.max_limit))
        with self._lock:
            rows = self._conn.execute(
                """
                WITH RECURSIVE thread(id) AS (
                    VALUES (?)
                    UNION
                    SELECT p.id
                      FROM posts p
                      JOIN thread t ON p.reply_to = t.id
                )
                SELECT id FROM thread ORDER BY id ASC LIMIT ?
                """,
                (root_id, bounded + 1),
            ).fetchall()
        ids = [int(row["id"]) for row in rows]
        truncated = len(ids) > bounded
        ids = ids[:bounded]
        posts = [
            post
            for post_id_value in ids
            if (post := self.store.get_post_or_archived(post_id_value)) is not None
        ]
        return root_id, posts, truncated

    def normalize_watch_target(self, kind: str, target: str) -> str:
        kind = kind.lower().strip()
        raw = target.strip()
        if kind not in WATCH_KINDS:
            raise StoreError(f"watch kind must be one of {sorted(WATCH_KINDS)}", 400)
        if kind == "board":
            board = raw.removeprefix("/").lower()
            if self.store.board_info(board) is None:
                raise StoreError(f"unknown board: {board}", 404)
            return board
        if kind == "tag":
            return self.store.normalize_tag(raw.removeprefix("#"))
        if kind == "author":
            candidate = raw.removeprefix("@").lower()
            if valid_author_id(candidate):
                return candidate
            profile = self.store.profile_by_name(raw.removeprefix("@"))
            if profile is None:
                raise StoreError(f"unknown signed user: {raw}", 404)
            return str(profile["author_id"])
        try:
            post_id = int(raw.removeprefix("thread:").removeprefix("post:").removeprefix("msg:"))
        except ValueError as exc:
            raise StoreError("thread watch target must be a post id", 400) from exc
        if post_id < 1:
            raise StoreError("thread watch target must be a positive post id", 400)
        return str(self._thread_root_id(post_id))

    def watch_add(self, owner_id: str, kind: str, target: str) -> dict[str, Any]:
        normalized_kind = kind.lower().strip()
        normalized_target = self.normalize_watch_target(normalized_kind, target)
        with self._lock, self._conn:
            count = self._conn.execute(
                "SELECT COUNT(*) AS n FROM subscriptions WHERE owner_id = ?",
                (owner_id,),
            ).fetchone()
            if int(count["n"] if count is not None else 0) >= MAX_WATCHES_PER_IDENTITY:
                raise StoreError(
                    f"watch limit reached ({MAX_WATCHES_PER_IDENTITY})",
                    409,
                )
            existing = self._conn.execute(
                """
                SELECT id, created FROM subscriptions
                 WHERE owner_id = ? AND kind = ? AND target = ?
                """,
                (owner_id, normalized_kind, normalized_target),
            ).fetchone()
            if existing is not None:
                watch_id = str(existing["id"])
                created = float(existing["created"])
            else:
                watch_id = secrets.token_hex(16)
                created = time.time()
                self._conn.execute(
                    """
                    INSERT INTO subscriptions(id, owner_id, kind, target, created)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (watch_id, owner_id, normalized_kind, normalized_target, created),
                )
        return {
            "id": watch_id,
            "owner_id": owner_id,
            "kind": normalized_kind,
            "target": normalized_target,
            "created": round(created, 3),
            "ref": f"watch:{watch_id}",
        }

    def watch_delete(self, owner_id: str, watch_id: str) -> dict[str, Any]:
        watch_id = watch_id.lower().strip()
        if not re.fullmatch(r"[0-9a-f]{32}", watch_id):
            raise StoreError("watch id must be 32 lowercase hex characters", 400)
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM subscriptions WHERE id = ? AND owner_id = ?",
                (watch_id, owner_id),
            )
        if not cur.rowcount:
            raise StoreError("watch not found", 404)
        return {"ok": 1, "id": watch_id, "deleted": True, "ref": f"watch:{watch_id}"}

    def watch_list(self, owner_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, kind, target, created
                  FROM subscriptions
                 WHERE owner_id = ?
                 ORDER BY created, id
                """,
                (owner_id,),
            ).fetchall()
        return [
            {
                "id": str(row["id"]),
                "owner_id": owner_id,
                "kind": str(row["kind"]),
                "target": str(row["target"]),
                "created": round(float(row["created"]), 3),
                "ref": f"watch:{row['id']}",
            }
            for row in rows
        ]

    def _watch_matches(self, post: Post) -> list[tuple[str, str]]:
        tags = self.store.post_tags(post.id)
        root_id = self._thread_root_id(post.id)
        clauses: list[tuple[str, str]] = [("board", post.board), ("thread", str(root_id))]
        if post.author_id is not None:
            clauses.append(("author", post.author_id))
        clauses.extend(("tag", tag) for tag in tags)

        matches: set[tuple[str, str]] = set()
        with self._lock:
            for kind, target in clauses:
                rows = self._conn.execute(
                    """
                    SELECT owner_id, kind
                      FROM subscriptions
                     WHERE kind = ? AND target = ?
                    """,
                    (kind, target),
                ).fetchall()
                matches.update((str(row["owner_id"]), str(row["kind"])) for row in rows)
        actor_id = post.actor_id or post.author_id
        return sorted((owner, kind) for owner, kind in matches if owner != actor_id)

    def index_post(self, post: Post, *, updated: bool = False) -> list[tuple[str, str]]:
        matches = self._watch_matches(post)
        if not matches:
            return []
        suffix = ":update" if updated else ""
        with self._lock, self._conn:
            self._conn.executemany(
                """
                INSERT OR IGNORE INTO inbox_events(post_id, subject_id, kind)
                VALUES (?, ?, ?)
                """,
                [(post.id, owner_id, f"watch:{kind}{suffix}") for owner_id, kind in matches],
            )
        return matches

    def ack(self, subject_id: str, post_id: int, status: str) -> dict[str, Any]:
        normalized = status.lower().strip()
        if normalized not in ACK_STATUSES:
            raise StoreError(f"ack status must be one of {sorted(ACK_STATUSES)}", 400)
        with self._lock, self._conn:
            event = self._conn.execute(
                """
                SELECT 1 FROM inbox_events
                 WHERE subject_id = ? AND post_id = ?
                 LIMIT 1
                """,
                (subject_id, post_id),
            ).fetchone()
            if event is None:
                raise StoreError("post is not in this identity inbox", 404)
            now = time.time()
            self._conn.execute(
                """
                INSERT INTO inbox_receipts(subject_id, post_id, status, updated)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(subject_id, post_id) DO UPDATE SET
                    status = excluded.status,
                    updated = excluded.updated
                """,
                (subject_id, post_id, normalized, now),
            )
        return {
            "post_id": post_id,
            "post_ref": f"post:{post_id}",
            "subject_id": subject_id,
            "status": normalized,
            "updated": round(now, 3),
        }

    def receipts_for(self, subject_id: str, post_ids: list[int]) -> dict[int, str]:
        ids = list(dict.fromkeys(value for value in post_ids if value > 0))
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT post_id, status
                  FROM inbox_receipts
                 WHERE subject_id = ? AND post_id IN ({placeholders})
                """,
                [subject_id, *ids],
            ).fetchall()
        return {int(row["post_id"]): str(row["status"]) for row in rows}

    def _task_row(self, post_id: int) -> sqlite3.Row:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT post_id, owner_id, assignee_id, status, created, updated
                  FROM exchange_tasks
                 WHERE post_id = ?
                """,
                (post_id,),
            ).fetchone()
        if row is None:
            raise StoreError("task not found", 404)
        return row

    @staticmethod
    def _task_dict(row: sqlite3.Row) -> dict[str, Any]:
        post_id = int(row["post_id"])
        return {
            "post_id": post_id,
            "ref": f"task:{post_id}",
            "post_ref": f"post:{post_id}",
            "owner_id": str(row["owner_id"]),
            "assignee_id": str(row["assignee_id"]) if row["assignee_id"] is not None else None,
            "status": str(row["status"]),
            "created": round(float(row["created"]), 3),
            "updated": round(float(row["updated"]), 3),
        }

    def _task_notify(self, post_id: int, target: str | None, kind: str, actor_id: str) -> None:
        if target is None or target == actor_id:
            return
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO inbox_events(post_id, subject_id, kind)
                VALUES (?, ?, ?)
                """,
                (post_id, target, f"task:{kind}"),
            )

    def task_open(self, owner_id: str, post_id: int) -> dict[str, Any]:
        post = self.store.get_post(post_id)
        if post is None:
            raise StoreError("task post not found", 404)
        if post.author_id != owner_id:
            raise StoreError("only the signed post owner may open it as a task", 403)
        now = time.time()
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT 1 FROM exchange_tasks WHERE post_id = ?",
                (post_id,),
            ).fetchone()
            if existing is not None:
                raise StoreError("task already exists", 409)
            self._conn.execute(
                """
                INSERT INTO exchange_tasks(post_id, owner_id, assignee_id, status, created, updated)
                VALUES (?, ?, NULL, 'open', ?, ?)
                """,
                (post_id, owner_id, now, now),
            )
        return self._task_dict(self._task_row(post_id))

    def task_claim(self, actor_id: str, post_id: int) -> dict[str, Any]:
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT owner_id, status, assignee_id FROM exchange_tasks WHERE post_id = ?",
                (post_id,),
            ).fetchone()
            if row is None:
                raise StoreError("task not found", 404)
            if str(row["status"]) != "open":
                raise StoreError("task is not open", 409)
            now = time.time()
            self._conn.execute(
                """
                UPDATE exchange_tasks
                   SET assignee_id = ?, status = 'claimed', updated = ?
                 WHERE post_id = ?
                """,
                (actor_id, now, post_id),
            )
            owner_id = str(row["owner_id"])
        self._task_notify(post_id, owner_id, "claimed", actor_id)
        return self._task_dict(self._task_row(post_id))

    def task_release(self, actor_id: str, post_id: int) -> dict[str, Any]:
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT owner_id, assignee_id, status FROM exchange_tasks WHERE post_id = ?",
                (post_id,),
            ).fetchone()
            if row is None:
                raise StoreError("task not found", 404)
            if str(row["status"]) != "claimed" or str(row["assignee_id"] or "") != actor_id:
                raise StoreError("only the current assignee may release this task", 403)
            now = time.time()
            self._conn.execute(
                """
                UPDATE exchange_tasks
                   SET assignee_id = NULL, status = 'open', updated = ?
                 WHERE post_id = ?
                """,
                (now, post_id),
            )
            owner_id = str(row["owner_id"])
        self._task_notify(post_id, owner_id, "released", actor_id)
        return self._task_dict(self._task_row(post_id))

    def task_complete(self, actor_id: str, post_id: int) -> dict[str, Any]:
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT owner_id, assignee_id, status FROM exchange_tasks WHERE post_id = ?",
                (post_id,),
            ).fetchone()
            if row is None:
                raise StoreError("task not found", 404)
            owner_id = str(row["owner_id"])
            assignee_id = str(row["assignee_id"]) if row["assignee_id"] is not None else None
            if str(row["status"]) == "completed":
                return self._task_dict(self._task_row(post_id))
            if actor_id not in {owner_id, assignee_id}:
                raise StoreError("only the task owner or assignee may complete it", 403)
            now = time.time()
            self._conn.execute(
                """
                UPDATE exchange_tasks
                   SET status = 'completed', updated = ?
                 WHERE post_id = ?
                """,
                (now, post_id),
            )
        self._task_notify(post_id, owner_id, "completed", actor_id)
        self._task_notify(post_id, assignee_id, "completed", actor_id)
        return self._task_dict(self._task_row(post_id))

    def task_list(
        self,
        actor_id: str,
        *,
        scope: str = "open",
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        normalized = scope.lower().strip()
        bounded = max(1, min(limit, self.cfg.max_limit))
        if normalized == "open":
            where = "status = 'open'"
            params: list[Any] = []
        elif normalized == "mine":
            where = "(owner_id = ? OR assignee_id = ?)"
            params = [actor_id, actor_id]
        elif normalized == "all":
            where = "1 = 1"
            params = []
        else:
            raise StoreError("task scope must be open, mine, or all", 400)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT post_id, owner_id, assignee_id, status, created, updated
                  FROM exchange_tasks
                 WHERE {where}
                 ORDER BY updated DESC, post_id DESC
                 LIMIT ?
                """,
                [*params, bounded],
            ).fetchall()
        return [self._task_dict(row) for row in rows]
