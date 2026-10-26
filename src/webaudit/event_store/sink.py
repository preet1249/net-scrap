"""Bounded event queue between collectors (producers) and the persistence worker (consumer).

Backpressure policy
-------------------
* CDP/Playwright *callbacks* are synchronous and must not block: they call ``offer()`` which uses
  ``put_nowait``. When the queue is full the event is **dropped and counted** (``dropped``); the count is
  surfaced in diagnostics and the manifest so the loss is never silent.
* Async producers (e.g. Playwright handlers that already ``await``) call ``await put()`` which
  genuinely blocks until space is available (backpressure).
"""
from __future__ import annotations

import asyncio
import itertools
import time
from dataclasses import dataclass
from typing import Any, Optional

from ..logging_setup import get_logger

log = get_logger("sink")


@dataclass(frozen=True, slots=True)
class RawCapture:
    seq: int
    timestamp: float
    source: str
    event_type: str
    target_id: Optional[str]
    session_id: Optional[str]
    request_id: Optional[str]
    raw_event: Any


class EventSink:
    def __init__(self, maxsize: int = 10_000) -> None:
        self.queue: asyncio.Queue[RawCapture | None] = asyncio.Queue(maxsize=maxsize)
        self._seq = itertools.count(1)
        self.dropped = 0
        self.dropped_by_type: dict[str, int] = {}
        self.accepted = 0
        self.closed = False
        self.late_after_close = 0
        self.max_depth = 0

    def _make(self, source: str, event_type: str, raw: Any, target_id: Optional[str],
              session_id: Optional[str], request_id: Optional[str]) -> RawCapture:
        return RawCapture(next(self._seq), time.time(), source, event_type, target_id, session_id, request_id, raw)

    def offer(self, source: str, event_type: str, raw: Any, *, target_id: Optional[str] = None,
              session_id: Optional[str] = None, request_id: Optional[str] = None) -> bool:
        """Non-blocking enqueue for synchronous callbacks. Returns False (and counts) on overflow."""
        item = self._make(source, event_type, raw, target_id, session_id, request_id)
        if self.closed:
            self.late_after_close += 1  # shutdown race, accounted separately from overflow drops
            return False
        try:
            self.queue.put_nowait(item)
        except asyncio.QueueFull:
            self.dropped += 1
            self.dropped_by_type[event_type] = self.dropped_by_type.get(event_type, 0) + 1
            if self.dropped in (1, 100, 1000) or self.dropped % 10_000 == 0:
                log.warning("event queue full; dropping events", extra={"ctx": {"dropped": self.dropped}})
            return False
        self.accepted += 1
        self.max_depth = max(self.max_depth, self.queue.qsize())
        return True

    async def put(self, source: str, event_type: str, raw: Any, *, target_id: Optional[str] = None,
                  session_id: Optional[str] = None, request_id: Optional[str] = None) -> bool:
        """Blocking enqueue (true backpressure) for async producers."""
        if self.closed:
            self.late_after_close += 1
            return False
        await self.queue.put(self._make(source, event_type, raw, target_id, session_id, request_id))
        self.accepted += 1
        self.max_depth = max(self.max_depth, self.queue.qsize())
        return True

    async def close(self) -> None:
        """Stop accepting events and signal the worker to drain and exit."""
        if not self.closed:
            self.closed = True
            await self.queue.put(None)

    def stats(self) -> dict[str, Any]:
        return {"accepted": self.accepted, "dropped": self.dropped, "dropped_by_type": dict(self.dropped_by_type),
                "late_after_close": self.late_after_close, "max_queue_depth": self.max_depth, "queue_maxsize": self.queue.maxsize}
