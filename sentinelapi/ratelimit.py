from __future__ import annotations
import asyncio, time


class RateLimiter:
    """Simple async limiter: at most `rps` requests per second (0 = unlimited)."""
    def __init__(self, rps: float = 0):
        self.interval = 1.0 / rps if rps > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        if not self.interval:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            await asyncio.sleep(delay)
