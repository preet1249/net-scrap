from __future__ import annotations

import json
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable

import pytest
import pytest_asyncio
from playwright.async_api import Browser, async_playwright

from tests.fixture_app import FixtureServer
from webaudit.event_store import EventSink, JsonlEventStore, PersistenceWorker
from webaudit.instrumentation import CDPNetworkCollector, NetworkCollector


@pytest_asyncio.fixture(scope="session")
async def server() -> AsyncIterator[FixtureServer]:
    s = await FixtureServer().start()
    yield s
    await s.stop()


@pytest_asyncio.fixture(scope="session")
async def browser() -> AsyncIterator[Browser]:
    async with async_playwright() as pw:
        b = await pw.chromium.launch(headless=True)
        yield b
        await b.close()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class Harness:
    """Minimal collection harness: sink -> worker -> JSONL, collectors armed BEFORE navigation."""

    def __init__(self, browser: Browser, out_dir: Path, *, queue_size: int = 10_000, redact: bool = True) -> None:
        self.browser, self.out_dir = browser, out_dir
        self.sink = EventSink(queue_size)
        self.jsonl = JsonlEventStore(out_dir / "network_events.jsonl")
        self.worker = PersistenceWorker(self.sink, [self.jsonl], "scan-test", redact=redact)
        self.context: Any = None
        self.cdp: CDPNetworkCollector | None = None
        self.pw: NetworkCollector | None = None

    async def __aenter__(self) -> "Harness":
        self.context = await self.browser.new_context()
        self.cdp = CDPNetworkCollector(self.context, self.sink)
        self.pw = NetworkCollector(self.context, self.sink)
        self.pw.attach_context()
        self.worker.start()
        return self

    async def new_page(self) -> Any:
        page = await self.context.new_page()
        assert self.cdp is not None
        await self.cdp.attach(page)  # Network.enable completes before any navigation
        return page

    async def finish(self) -> list[dict[str, Any]]:
        assert self.cdp and self.pw
        await self.pw.drain()
        await self.worker.stop()
        await self.cdp.detach_all()
        return read_jsonl(self.out_dir / "network_events.jsonl")

    async def __aexit__(self, *exc: Any) -> None:
        if self.context:
            await self.context.close()


@pytest.fixture
def harness_factory(browser: Browser, tmp_path: Path) -> Callable[..., Harness]:
    def make(**kw: Any) -> Harness:
        return Harness(browser, tmp_path, **kw)
    return make
