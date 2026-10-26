"""Persistence worker: the only place that validates, redacts and writes events (never inside CDP callbacks)."""
from __future__ import annotations

import asyncio
from typing import Any, Protocol, Sequence

from ..logging_setup import get_logger
from ..models import NetworkEvent
from ..redaction import redact_event
from .sink import EventSink, RawCapture

log = get_logger("worker")


class EventStoreProtocol(Protocol):
    def append_events(self, events: Sequence[NetworkEvent]) -> None: ...
    def close(self) -> None: ...


class PersistenceWorker:
    def __init__(self, sink: EventSink, stores: Sequence[EventStoreProtocol], scan_id: str, *,
                 batch_size: int = 200, flush_interval: float = 0.25, redact: bool = True) -> None:
        self.sink = sink
        self.stores = list(stores)
        self.scan_id = scan_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.redact = redact
        self.written = 0
        self.errors: list[str] = []
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="persistence-worker")

    def _to_event(self, cap: RawCapture) -> NetworkEvent:
        raw = cap.raw_event if isinstance(cap.raw_event, dict) else {"value": cap.raw_event}
        return NetworkEvent(
            event_id=f"evt-{cap.seq}", scan_id=self.scan_id, seq=cap.seq, timestamp=cap.timestamp,
            source=cap.source, target_id=cap.target_id, session_id=cap.session_id, request_id=cap.request_id,
            event_type=cap.event_type, raw_event=redact_event(raw) if self.redact else raw,
        )

    async def _run(self) -> None:
        done = False
        while not done:
            batch: list[RawCapture] = []
            try:
                first = await self.sink.queue.get()
            except asyncio.CancelledError:
                raise
            if first is None:
                self.sink.queue.task_done()
                break
            batch.append(first)
            while len(batch) < self.batch_size:
                try:
                    nxt = await asyncio.wait_for(self.sink.queue.get(), timeout=self.flush_interval)
                except asyncio.TimeoutError:
                    break
                if nxt is None:
                    self.sink.queue.task_done()
                    done = True
                    break
                batch.append(nxt)
            try:
                await self._write(batch)
            finally:
                for _ in batch:
                    self.sink.queue.task_done()
        log.info("persistence worker drained", extra={"ctx": {"written": self.written}})

    async def _write(self, batch: list[RawCapture]) -> None:
        events: list[NetworkEvent] = []
        for cap in batch:
            try:
                events.append(self._to_event(cap))
            except Exception as exc:  # validation problem must not kill the scan
                self.errors.append(f"event {cap.seq} {cap.event_type}: {exc!r}")
                log.error("event rejected", extra={"ctx": {"seq": cap.seq, "type": cap.event_type}})
        if not events:
            return
        for store in self.stores:
            try:
                await asyncio.to_thread(store.append_events, events)
            except Exception as exc:
                self.errors.append(f"store {type(store).__name__}: {exc!r}")
                log.error("store write failed", extra={"ctx": {"store": type(store).__name__}})
        self.written += len(events)

    async def stop(self) -> None:
        """Graceful shutdown: close the sink, drain everything queued, then close stores."""
        await self.sink.close()
        if self._task:
            await self._task
        for s in self.stores:
            await asyncio.to_thread(s.close)

    def diagnostics(self) -> dict[str, Any]:
        return {"written": self.written, "errors": list(self.errors), **self.sink.stats()}
