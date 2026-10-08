"""Small in-process sliding-window rate limiter.

State is per process. When running several workers or replicas, each one enforces its own
window, so effective limits scale with the number of processes. Put a shared limiter
(for example Redis, or the API gateway) in front for strict global limits.
"""

import threading
import time
from collections import deque

from fastapi import Request

from alzando_authorization.config import settings
from alzando_authorization.service import ServiceError

_MAX_TRACKED_KEYS = 50_000


class RateLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = {}
        self._windows: dict[str, float] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, window_seconds: float) -> int:
        """Record one event and return how many events fall inside the window."""
        now = time.monotonic()
        with self._lock:
            events = self._events.setdefault(key, deque())
            self._windows[key] = window_seconds
            cutoff = now - window_seconds
            while events and events[0] <= cutoff:
                events.popleft()
            events.append(now)
            if len(self._events) > _MAX_TRACKED_KEYS:
                self._prune(now)
            return len(events)

    def count(self, key: str, window_seconds: float) -> int:
        now = time.monotonic()
        with self._lock:
            events = self._events.get(key)
            if not events:
                return 0
            cutoff = now - window_seconds
            return sum(1 for moment in events if moment > cutoff)

    def retry_after(self, key: str, window_seconds: float) -> int:
        now = time.monotonic()
        with self._lock:
            events = self._events.get(key)
            if not events:
                return 1
            return max(1, int(events[0] + window_seconds - now) + 1)

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)
            self._windows.pop(key, None)

    def _prune(self, now: float) -> None:
        for key in list(self._events):
            events = self._events[key]
            window = self._windows.get(key, 0)
            while events and events[0] <= now - window:
                events.popleft()
            if not events:
                self._events.pop(key, None)
                self._windows.pop(key, None)

    def enforce(self, key: str, limit: int, window_seconds: float) -> None:
        """Count a hit for `key` and raise a 429 ServiceError when the limit is exceeded."""
        if not settings.rate_limit_enabled:
            return
        if self.hit(key, window_seconds) > limit:
            raise ServiceError(
                "RATE_LIMITED",
                "Too many requests. Try again later.",
                429,
                headers={"Retry-After": str(self.retry_after(key, window_seconds))},
            )


def client_ip(request: Request) -> str:
    """Best-effort client address.

    `X-Forwarded-For` is honoured only when TRUST_PROXY_HEADERS is enabled, and then the
    right-most entry (the one appended by the nearest trusted proxy) is used so clients
    cannot spoof their own address by sending the header themselves.
    """
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("X-Forwarded-For", "")
        parts = [part.strip() for part in forwarded.split(",") if part.strip()]
        if parts:
            return parts[-1]
    return request.client.host if request.client else "unknown"
