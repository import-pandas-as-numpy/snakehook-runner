from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _WindowState:
    window_start: float
    count: int


class FixedWindowRateLimiter:
    def __init__(self, limit: int, window_sec: int) -> None:
        self._limit = limit
        self._window_sec = window_sec
        self._state: dict[str, _WindowState] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        ts = time.monotonic() if now is None else now
        with self._lock:
            current = self._state.get(key)
            if current is None or ts - current.window_start >= self._window_sec:
                self._state[key] = _WindowState(window_start=ts, count=1)
                return True
            if current.count >= self._limit:
                return False
            current.count += 1
            return True
