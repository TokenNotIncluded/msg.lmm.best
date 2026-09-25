"""Valkey-backed engagement counters and rankings."""

from __future__ import annotations

from dataclasses import dataclass

import valkey
from valkey.exceptions import ValkeyError


@dataclass(frozen=True)
class EngagementStats:
    views: int = 0
    comments: int = 0
    hot: float = 0.0

    def to_dict(self) -> dict[str, int | float]:
        return {
            "views": self.views,
            "comments": self.comments,
            "hot": round(self.hot, 3),
        }


class Engagement:
    """Derived engagement state.

    SQLite remains authoritative for posts/replies. Valkey stores fast counters
    and sorted-set rankings. Likes intentionally do not exist.
    """

    SORTS = frozenset({"views", "comments", "hot"})

    def __init__(self, url: str = "", *, prefix: str = "msgd") -> None:
        self.url = url.strip()
        self.prefix = prefix.strip().strip(":") or "msgd"
        self.client: valkey.Valkey | None = None
        self.error = ""

        if not self.url:
            return

        try:
            client = valkey.from_url(
                self.url,
                decode_responses=True,
                socket_connect_timeout=0.5,
                socket_timeout=0.5,
                health_check_interval=30,
            )
            client.ping()
            self.client = client
        except (ValkeyError, OSError) as exc:
            self.error = str(exc)

    @property
    def available(self) -> bool:
        return self.client is not None

    def close(self) -> None:
        if self.client is not None:
            self.client.close()

    def status(self) -> str:
        if self.available:
            return "ready"
        return "disabled" if not self.url else "down"

    def _key(self, metric: str, board: str | None = None) -> str:
        key = f"{self.prefix}:engagement:{metric}"
        return f"{key}:board:{board}" if board else key

    @staticmethod
    def _member(post_id: int) -> str:
        return str(post_id)

    @staticmethod
    def _hot_score(post_id: int, views: float, comments: float) -> float:
        # Comments signal more deliberate engagement than a read. The tiny id
        # component is only a deterministic newest-first tiebreaker.
        return views + comments * 4.0 + min(post_id, 999_999_999) * 1e-12

    def sync_comments(self, rows: list[tuple[int, str, int]]) -> None:
        """Rebuild comment/hot rankings and reconcile them with live SQLite posts."""
        client = self.client
        if client is None:
            return
        try:
            live = {self._member(post_id) for post_id, _, _ in rows}
            live_by_board: dict[str, set[str]] = {}
            for post_id, board, _ in rows:
                live_by_board.setdefault(board, set()).add(self._member(post_id))

            prune = client.pipeline(transaction=False)
            for metric in self.SORTS:
                existing = set(client.zrange(self._key(metric), 0, -1))
                stale = existing - live
                if stale:
                    prune.zrem(self._key(metric), *stale)
            for key in client.scan_iter(match=f"{self.prefix}:engagement:*:board:*"):
                board = key.rsplit(":board:", 1)[-1]
                existing = set(client.zrange(key, 0, -1))
                stale = existing - live_by_board.get(board, set())
                if stale:
                    prune.zrem(key, *stale)
            prune.execute()

            pipe = client.pipeline(transaction=False)
            for post_id, board, count in rows:
                member = self._member(post_id)
                pipe.zadd(self._key("views"), {member: 0}, nx=True)
                pipe.zadd(self._key("views", board), {member: 0}, nx=True)
                pipe.zadd(self._key("comments"), {member: count})
                pipe.zadd(self._key("comments", board), {member: count})
                pipe.zscore(self._key("views"), member)
            results = pipe.execute()

            hot_pipe = client.pipeline(transaction=False)
            for index, (post_id, board, count) in enumerate(rows):
                raw_views = results[index * 5 + 4]
                views = float(raw_views or 0)
                score = self._hot_score(post_id, views, float(count))
                member = self._member(post_id)
                hot_pipe.zadd(self._key("hot"), {member: score})
                hot_pipe.zadd(self._key("hot", board), {member: score})
            hot_pipe.execute()
        except (ValkeyError, OSError) as exc:
            self.error = str(exc)

    def record_view(self, post_id: int, board: str) -> EngagementStats:
        client = self.client
        if client is None:
            return EngagementStats()
        member = self._member(post_id)
        try:
            pipe = client.pipeline(transaction=False)
            pipe.zincrby(self._key("views"), 1, member)
            pipe.zincrby(self._key("views", board), 1, member)
            pipe.zscore(self._key("comments"), member)
            views, _, raw_comments = pipe.execute()
            comments = float(raw_comments or 0)
            hot = self._hot_score(post_id, float(views), comments)
            client.zadd(self._key("hot"), {member: hot})
            client.zadd(self._key("hot", board), {member: hot})
            return EngagementStats(int(float(views)), int(comments), hot)
        except (ValkeyError, OSError) as exc:
            self.error = str(exc)
            return EngagementStats()

    def set_comments(self, post_id: int, board: str, comments: int) -> None:
        client = self.client
        if client is None:
            return
        member = self._member(post_id)
        try:
            pipe = client.pipeline(transaction=False)
            pipe.zadd(self._key("views"), {member: 0}, nx=True)
            pipe.zadd(self._key("views", board), {member: 0}, nx=True)
            pipe.zadd(self._key("comments"), {member: comments})
            pipe.zadd(self._key("comments", board), {member: comments})
            pipe.zscore(self._key("views"), member)
            _, _, _, _, raw_views = pipe.execute()
            views = float(raw_views or 0)
            hot = self._hot_score(post_id, views, float(comments))
            client.zadd(self._key("hot"), {member: hot})
            client.zadd(self._key("hot", board), {member: hot})
        except (ValkeyError, OSError) as exc:
            self.error = str(exc)

    def remove_post(self, post_id: int, board: str) -> None:
        client = self.client
        if client is None:
            return
        member = self._member(post_id)
        try:
            pipe = client.pipeline(transaction=False)
            for metric in self.SORTS:
                pipe.zrem(self._key(metric), member)
                pipe.zrem(self._key(metric, board), member)
            pipe.execute()
        except (ValkeyError, OSError) as exc:
            self.error = str(exc)

    def remove_ids(self, post_ids: list[int] | tuple[int, ...]) -> None:
        client = self.client
        if client is None or not post_ids:
            return
        members = [self._member(post_id) for post_id in post_ids]
        try:
            pipe = client.pipeline(transaction=False)
            for metric in self.SORTS:
                pipe.zrem(self._key(metric), *members)
            for key in client.scan_iter(match=f"{self.prefix}:engagement:*:board:*"):
                pipe.zrem(key, *members)
            pipe.execute()
        except (ValkeyError, OSError) as exc:
            self.error = str(exc)

    def metrics(self, post_ids: list[int] | tuple[int, ...]) -> dict[int, EngagementStats]:
        client = self.client
        if client is None or not post_ids:
            return {post_id: EngagementStats() for post_id in post_ids}
        try:
            pipe = client.pipeline(transaction=False)
            for post_id in post_ids:
                member = self._member(post_id)
                pipe.zscore(self._key("views"), member)
                pipe.zscore(self._key("comments"), member)
                pipe.zscore(self._key("hot"), member)
            values = pipe.execute()
        except (ValkeyError, OSError) as exc:
            self.error = str(exc)
            return {post_id: EngagementStats() for post_id in post_ids}

        result: dict[int, EngagementStats] = {}
        for index, post_id in enumerate(post_ids):
            views, comments, hot = values[index * 3 : index * 3 + 3]
            result[post_id] = EngagementStats(
                views=int(float(views or 0)),
                comments=int(float(comments or 0)),
                hot=float(hot or 0),
            )
        return result

    def rank(
        self,
        metric: str,
        *,
        board: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[int]:
        if metric not in self.SORTS:
            raise ValueError(f"unsupported engagement sort: {metric}")
        client = self.client
        if client is None:
            return []
        start = max(0, offset)
        try:
            members = client.zrevrange(
                self._key(metric, board),
                start,
                start + max(0, limit - 1),
            )
            return [int(member) for member in members]
        except (ValkeyError, OSError, ValueError) as exc:
            self.error = str(exc)
            return []
