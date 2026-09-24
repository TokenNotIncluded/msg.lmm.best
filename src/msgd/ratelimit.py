"""Small in-memory per-client token bucket."""

import threading
import time
from dataclasses import dataclass


@dataclass
class Bucket:
    capacity: float
    refill_per_second: float
    tokens: float = 0.0
    updated: float = 0.0

    def take(self, now: float) -> tuple[bool, float]:
        if self.updated == 0.0:
            self.tokens = self.capacity
            self.updated = now
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True, 0.0
        wait = (1.0 - self.tokens) / self.refill_per_second
        return False, max(1.0, min(wait, 3600.0))


class Limiter:
    def __init__(self, *, burst: int, per_minute: int) -> None:
        self.capacity = float(max(1, burst))
        self.rate = max(per_minute, 1) / 60.0
        self._buckets: dict[str, Bucket] = {}
        self._lock = threading.Lock()

    def check(self, client: str) -> tuple[bool, float]:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(client)
            if bucket is None:
                bucket = Bucket(self.capacity, self.rate)
                self._buckets[client] = bucket
            return bucket.take(now)
