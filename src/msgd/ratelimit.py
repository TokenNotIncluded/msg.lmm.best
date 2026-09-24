"""Per-client rate limiting for msgd.

A token bucket per (client, kind) pair, held in memory. Deliberately simple:
msgd is a small public board, and losing the buckets on restart is acceptable.
The bucket refills continuously, so a burst of `burst` is allowed and then
sustained traffic settles at `per_minute`.
"""

import threading
import time
from dataclasses import dataclass


@dataclass
class Bucket:
    capacity: float
    refill_per_second: float
    tokens: float = 0.0
    updated: float = 0.0

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
            return True, 0.0

        shortfall = cost - self.tokens
        wait = shortfall / self.refill_per_second if self.refill_per_second > 0 else 60.0
        return False, max(1.0, min(wait, 3600.0))


class Limiter:
    """Tracks buckets per client key. `kind` separates independent budgets."""

    def __init__(self, *, burst: int, per_minute: float) -> None:
        self.capacity = float(max(1, burst))
        self.rate = max(per_minute, 0.001) / 60.0
        # An idle bucket is dropped only once it would have refilled anyway.
        self.idle = max(900.0, self.capacity / self.rate)
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
            if bucket.updated and now - bucket.updated > self.idle
        ]
        for key in stale:
            del self._buckets[key]
