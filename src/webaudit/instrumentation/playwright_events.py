"""Playwright-level observation (``NetworkCollector``). Complementary to CDP; source-attributed, never merged blindly.

Handlers are coroutines (Playwright schedules them as tasks) so they can await header retrieval and use
``sink.put`` backpressure. Pending tasks are tracked and awaited by ``drain()`` before shutdown.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

from playwright.async_api import BrowserContext, Page, Request, Response, WebSocket

from ..event_store.sink import EventSink
from ..logging_setup import get_logger

log = get_logger("pw-collector")
COLLECTOR_VERSION = "playwright-collector/1"


def _page_label(page: Optional[Page], pages: dict[int, str]) -> Optional[str]:
    return pages.get(id(page)) if page is not None else None


class NetworkCollector:
    def __init__(self, context: BrowserContext, sink: EventSink) -> None:
        self.context = context
        self.sink = sink
        self._tasks: set[asyncio.Task[Any]] = set()
        self._page_labels: dict[int, str] = {}
        self._ws_ids: dict[int, str] = {}
        self._req_ids: dict[int, str] = {}
        self._n = 0
        self.errors: list[str] = []
        self._pages_hooked: set[int] = set()

    # ---- wiring -----------------------------------------------------------------------------
    def attach_context(self) -> None:
        c = self.context
        c.on("request", lambda r: self._spawn(self._on_request(r)))
        c.on("response", lambda r: self._spawn(self._on_response(r)))
        c.on("requestfinished", lambda r: self._spawn(self._on_finished(r)))
        c.on("requestfailed", lambda r: self._spawn(self._on_failed(r)))
        c.on("page", self._on_page)
        c.on("serviceworker", lambda w: self.sink.offer("playwright", "pw.serviceworker", {"url": w.url}))
        for p in c.pages:
            self._hook_page(p)

    def _spawn(self, coro: Any) -> None:
        t = asyncio.ensure_future(coro)
        self._tasks.add(t)
        t.add_done_callback(self._task_done)

    def _task_done(self, t: asyncio.Task[Any]) -> None:
        self._tasks.discard(t)
        if not t.cancelled() and t.exception() is not None:
            self.errors.append(repr(t.exception()))
            log.error("playwright handler failed", extra={"ctx": {"err": repr(t.exception())}})

    async def drain(self, timeout: float = 5.0) -> None:
        if self._tasks:
            await asyncio.wait(list(self._tasks), timeout=timeout)

    # ---- pages ------------------------------------------------------------------------------
    def _on_page(self, page: Page) -> None:
        self._hook_page(page)
        self.sink.offer("playwright", "pw.page", {"page": self._page_labels.get(id(page)), "url": page.url})

    def _hook_page(self, page: Page) -> None:
        if id(page) in self._pages_hooked:
            return
        self._pages_hooked.add(id(page))
        self._n += 1
        label = f"page-{self._n}"
        self._page_labels[id(page)] = label
        page.on("websocket", lambda ws: self._on_websocket(ws, label))
        page.on("popup", lambda p: self.sink.offer("playwright", "pw.popup", {"opener": label, "url": p.url}))
        page.on("close", lambda: self.sink.offer("playwright", "pw.page_closed", {"page": label}))

    # ---- websockets -------------------------------------------------------------------------
    def _on_websocket(self, ws: WebSocket, page_label: str) -> None:
        wid = f"pwws-{len(self._ws_ids) + 1}"
        self._ws_ids[id(ws)] = wid
        self.sink.offer("playwright", "pw.websocket_created", {"id": wid, "url": ws.url, "page": page_label}, request_id=wid)
        ws.on("framesent", lambda p: self.sink.offer("playwright", "pw.websocket_framesent", {"id": wid, "len": _plen(p)}, request_id=wid))
        ws.on("framereceived", lambda p: self.sink.offer("playwright", "pw.websocket_framereceived", {"id": wid, "len": _plen(p)}, request_id=wid))
        ws.on("socketerror", lambda e: self.sink.offer("playwright", "pw.websocket_error", {"id": wid, "error": str(e)}, request_id=wid))
        ws.on("close", lambda *_: self.sink.offer("playwright", "pw.websocket_closed", {"id": wid}, request_id=wid))

    # ---- requests ---------------------------------------------------------------------------
    def _rid(self, req: Request) -> str:
        rid = self._req_ids.get(id(req))
        if rid is None:
            rid = f"pwreq-{len(self._req_ids) + 1}"
            self._req_ids[id(req)] = rid
        return rid

    async def _headers(self, obj: Request | Response) -> list[list[str]]:
        try:
            arr = await obj.headers_array()
            return [[h["name"], h["value"]] for h in arr]
        except Exception:
            try:
                return [[k, v] for k, v in (await obj.all_headers()).items()]
            except Exception as exc:
                return [["x-webaudit-error", f"headers unavailable: {type(exc).__name__}"]]

    async def _on_request(self, req: Request) -> None:
        rid = self._rid(req)
        redirected_from = self._req_ids.get(id(req.redirected_from)) if req.redirected_from else None
        try:
            sw = req.service_worker is not None
        except Exception:
            sw = None
        frame_url = None
        try:
            frame_url = req.frame.url
        except Exception:
            pass
        await self.sink.put("playwright", "pw.request", {
            "url": req.url, "method": req.method, "resource_type": req.resource_type,
            "is_navigation": req.is_navigation_request(), "frame_url": frame_url, "headers": await self._headers(req),
            "has_post_data": req.post_data_buffer is not None, "redirected_from": redirected_from,
            "from_service_worker_context": sw,
        }, request_id=rid)

    async def _on_response(self, resp: Response) -> None:
        req = resp.request
        await self.sink.put("playwright", "pw.response", {
            "url": resp.url, "status": resp.status, "status_text": resp.status_text,
            "headers": await self._headers(resp), "from_service_worker": resp.from_service_worker,
        }, request_id=self._rid(req))

    async def _on_finished(self, req: Request) -> None:
        try:
            timing = req.timing
        except Exception:
            timing = None
        await self.sink.put("playwright", "pw.requestfinished", {"url": req.url, "timing": timing}, request_id=self._rid(req))

    async def _on_failed(self, req: Request) -> None:
        await self.sink.put("playwright", "pw.requestfailed", {"url": req.url, "failure": req.failure}, request_id=self._rid(req))

    def diagnostics(self) -> dict[str, Any]:
        return {"collector": COLLECTOR_VERSION, "errors": list(self.errors), "pages_seen": len(self._page_labels),
                "requests_seen": len(self._req_ids)}


def _plen(payload: Any) -> int:
    return len(payload) if isinstance(payload, (str, bytes)) else -1
