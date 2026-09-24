"""Per-client rate limiting for msgd.

A token bucket per (client, kind) pair, held in memory. Deliberately simple:
msgd is a small public board, and losing the buckets on restart is acceptable.
The bucket refills continuously, so a burst of `write_burst` is allowed and then
sustained traffic settles at `write_per_minute`.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class Bucket:
    capacity: float
    refill_per_second: float
    tokens: float = field(default=0.0)
    updated: float = field(default=0.0)
    hits: int = 0

    def take(self, now: float, cost: float = 1.0) -> tuple[bool, float]:
        """Consume `cost` tokens. Returns (allowed, seconds_until_next_token)."""
        if self.updated == 0.0:
            self.tokens = self.capacity
            self.updated = now
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.updated = now

        if self.tokens >= cost:
            self.tokens -= cost
            self.hits += 1
            return True, 0.0

        shortfall = cost - self.tokens
        wait = shortfall / self.refill_per_second if self.refill_per_second > 0 else 60.0
        return False, max(1.0, min(wait, 3600.0))


class Limiter:
    """Tracks buckets per client key. `kind` separates read from write budgets."""

    def __init__(self, *, burst: int, per_minute: int) -> None:
        self.capacity = float(max(1, burst))
        self.rate = max(1, per_minute) / 60.0
        self._buckets: dict[tuple[str, str], Bucket] = {}
        self._lock = threading.Lock()
        self._sweep_at = 0.0

    def check(self, client: str, kind: str, *, cost: float = 1.0) -> tuple[bool, float]:
        now = time.monotonic()
        key = (client, kind)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = Bucket(capacity=self.capacity, refill_per_second=self.rate)
                self._buckets[key] = bucket
            self._maybe_sweep(now)
            return bucket.take(now, cost)

    def _maybe_sweep(self, now: float) -> None:
        """Drop idle buckets so a long-running process does not grow unbounded."""
        if now < self._sweep_at:
            return
        self._sweep_at = now + 300.0
        stale = [
            key
            for key, bucket in self._buckets.items()
            if bucket.updated and now - bucket.updated > 900
        ]
        for key in stale:
            del self._buckets[key]

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "buckets": len(self._buckets),
                "tracked_clients": len({k[0] for k in self._buckets}),
            }
