"""CollectionSession: wires sink -> worker -> (JSONL + SQLite), CDP + Playwright collectors and optional body capture."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Optional

from playwright.async_api import BrowserContext, Page

from .config import ScanConfig
from .event_store import EventSink, JsonlEventStore, PersistenceWorker
from .event_store.sqlite import SqliteEventStore
from .instrumentation import CDPNetworkCollector, NetworkCollector
from .instrumentation.bodies import BodyCapturer
from .logging_setup import get_logger

log = get_logger("session")
DB_NAME = "scan.sqlite"


class CollectionSession:
    def __init__(self, config: ScanConfig, scan_dir: Path, scan_id: str) -> None:
        self.config, self.scan_dir, self.scan_id = config, Path(scan_dir), scan_id
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.db = SqliteEventStore(self.scan_dir / DB_NAME)
        self.live_jsonl = JsonlEventStore(self.scan_dir / "network_events.live.jsonl")  # crash-safe incremental stream
        self.sink = EventSink(config.queue_size)
        self.worker = PersistenceWorker(self.sink, [self.db, self.live_jsonl], scan_id)
        self.bodies = BodyCapturer(self.sink, self.scan_dir, config.body)
        self.cdp: Optional[CDPNetworkCollector] = None
        self.pw: Optional[NetworkCollector] = None
        self.context: Optional[BrowserContext] = None
        self._tasks: set[asyncio.Task[Any]] = set()
        self.closed = False

    async def open(self, context: BrowserContext) -> None:
        self.context = context
        mb = self.config.network_buffer_mb * 1_000_000
        self.cdp = CDPNetworkCollector(context, self.sink, max_total_buffer=mb, max_resource_buffer=min(mb, 20_000_000),
                                       on_event=self.bodies.observe if self.config.body.mode != "none" else None)
        self.pw = NetworkCollector(context, self.sink)
        self.pw.attach_context()
        self.worker.start()
        if self.config.body.mode != "none":
            self.bodies.start()
        # Tabs/popups opened later: attach as soon as they are announced (first requests may precede this: documented gap).
        context.on("page", lambda p: self._spawn(self.arm_page(p, late=True)))
        for p in context.pages:
            await self.arm_page(p)

    def _spawn(self, coro: Any) -> None:
        t = asyncio.ensure_future(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def arm_page(self, page: Page, *, late: bool = False) -> None:
        """Attach CDP + enable Network. Call BEFORE navigating for full coverage of that page."""
        assert self.cdp is not None
        att = await self.cdp.attach(page)
        if late:
            self.sink.offer("collector", "collector.late_attach", {
                "url": page.url, "note": "page announced by browser before attach; earliest requests may be missing from CDP source"},
                target_id=att.target_id if att else None, session_id=att.label if att else None)

    async def _quiesce(self, quiet: float = 0.5, max_wait: float = 4.0) -> None:
        """Wait until no new events have been accepted for `quiet` seconds (bounded) so trailing network events are not lost."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max_wait
        last, last_change = self.sink.accepted, loop.time()
        while loop.time() < deadline and loop.time() - last_change < quiet:
            await asyncio.sleep(0.1)
            if self.sink.accepted != last:
                last, last_change = self.sink.accepted, loop.time()

    async def close(self, *, status: str = "completed") -> dict[str, Any]:
        """Graceful shutdown: let tasks finish, drain body jobs, flush queue, finalize stores, detach sessions last."""
        if self.closed:
            return {}
        self.closed = True
        if self._tasks:
            await asyncio.wait(list(self._tasks), timeout=5)
        await self._quiesce()
        if self.pw:
            await self.pw.drain()
        if self.config.body.mode != "none":
            await self.bodies.stop()
        diag: dict[str, Any] = {
            "cdp": self.cdp.diagnostics() if self.cdp else {}, "playwright": self.pw.diagnostics() if self.pw else {},
            "bodies": self.bodies.diagnostics(),
        }
        await self.worker.stop()
        diag["queue"] = self.worker.diagnostics()
        if self.cdp:
            await self.cdp.detach_all()
        self.db_reopen_for_meta(diag, status)
        return diag

    def db_reopen_for_meta(self, diag: dict[str, Any], status: str) -> None:
        # the worker closed the stores; write final meta through a fresh connection
        db = SqliteEventStore(self.scan_dir / DB_NAME)
        db.set_meta("diagnostics", diag)
        db.set_meta("final_status", status)
        db.close()
