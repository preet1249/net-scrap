"""CDPNetworkCollector: per-page/frame CDP sessions via ``context.new_cdp_session``.

Coverage note: a page-level CDP session sees that page's renderer network stack. It does NOT cover other tabs
(attach each), dedicated/shared/service workers (Playwright cannot open CDP sessions for them), or
out-of-process iframes unless they are attached separately (we try per frame and record the outcome).
Network events that happen before ``Network.enable`` completes (e.g. a popup's very first request) are missed.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from playwright.async_api import BrowserContext, CDPSession, Frame, Page

from ..event_store.sink import EventSink
from ..logging_setup import get_logger

log = get_logger("cdp")

COLLECTOR_VERSION = "cdp-collector/1"

# Event name -> required? Unsupported ones are tolerated: a handler is simply never fired.
CDP_EVENTS: tuple[str, ...] = (
    "Network.requestWillBeSent",
    "Network.requestWillBeSentExtraInfo",
    "Network.responseReceived",
    "Network.responseReceivedExtraInfo",
    "Network.loadingFinished",
    "Network.loadingFailed",
    "Network.requestServedFromCache",
    "Network.webSocketCreated",
    "Network.webSocketWillSendHandshakeRequest",
    "Network.webSocketHandshakeResponseReceived",
    "Network.webSocketFrameSent",
    "Network.webSocketFrameReceived",
    "Network.webSocketFrameError",
    "Network.webSocketClosed",
    "Network.dataReceived",  # size only; used for diagnostics of chunked/streaming bodies
    "Network.resourceChangedPriority",
)
DEFAULT_SKIPPED = {"Network.dataReceived", "Network.resourceChangedPriority"}  # high-volume, low evidential value


@dataclass
class CDPAttachment:
    label: str  # our session id, e.g. "cdp-1"
    target_id: Optional[str]
    kind: str  # page | frame
    session: CDPSession
    page_url_at_attach: str = ""
    enabled: bool = False
    event_counts: dict[str, int] = field(default_factory=dict)
    handlers: dict[str, Callable[[dict[str, Any]], None]] = field(default_factory=dict)


class CDPNetworkCollector:
    def __init__(self, context: BrowserContext, sink: EventSink, *, max_total_buffer: int = 10_000_000,
                 max_resource_buffer: int = 5_000_000, include_noisy: bool = False,
                 on_event: Callable[[str, dict[str, Any], CDPAttachment], None] | None = None) -> None:
        self.context = context
        self.sink = sink
        self.max_total_buffer = max_total_buffer
        self.max_resource_buffer = max_resource_buffer
        self.events = tuple(e for e in CDP_EVENTS if include_noisy or e not in DEFAULT_SKIPPED)
        self.on_event = on_event  # synchronous, cheap observers (e.g. body-capture scheduler)
        self.attachments: list[CDPAttachment] = []
        self._by_obj: dict[int, CDPAttachment] = {}
        self._pending: dict[int, asyncio.Future[Optional[CDPAttachment]]] = {}
        self._counter = 0
        self.failures: list[str] = []
        self.browser_info: dict[str, Any] = {}

    # ---- attach -----------------------------------------------------------------------------
    async def attach(self, target: Page | Frame) -> Optional[CDPAttachment]:
        """Create a CDP session, register handlers, THEN enable the Network domain. Call before navigating."""
        pending = self._pending.get(id(target))
        if pending is not None:  # concurrent attach for the same page (explicit call + context "page" event)
            return await pending
        fut: asyncio.Future[Optional[CDPAttachment]] = asyncio.get_running_loop().create_future()
        self._pending[id(target)] = fut
        try:
            res = await self._attach(target)
            fut.set_result(res)
            return res
        except BaseException as exc:
            fut.set_exception(exc)
            fut.exception()  # mark retrieved
            raise

    async def _attach(self, target: Page | Frame) -> Optional[CDPAttachment]:
        kind = "page" if isinstance(target, Page) else "frame"
        try:
            session = await self.context.new_cdp_session(target)
        except Exception as exc:
            msg = f"new_cdp_session({kind}) failed: {exc}"
            self.failures.append(msg)
            log.warning(msg)
            return None
        self._counter += 1
        att = CDPAttachment(label=f"cdp-{self._counter}", target_id=None, kind=kind, session=session,
                            page_url_at_attach=getattr(target, "url", ""))
        try:
            info = await session.send("Target.getTargetInfo")
            att.target_id = info["targetInfo"]["targetId"]
        except Exception as exc:  # target id is best-effort metadata
            self.failures.append(f"Target.getTargetInfo failed for {att.label}: {exc}")
        for name in self.events:
            handler = self._make_handler(name, att)
            att.handlers[name] = handler
            session.on(name, handler)
        try:
            await session.send("Network.enable", {"maxTotalBufferSize": self.max_total_buffer,
                                                  "maxResourceBufferSize": self.max_resource_buffer})
            att.enabled = True
        except Exception as exc:
            self.failures.append(f"Network.enable failed for {att.label}: {exc}")
            log.error("Network.enable failed", extra={"ctx": {"session": att.label}})
        if not self.browser_info:
            try:
                self.browser_info = await session.send("Browser.getVersion")
            except Exception:
                pass
        self.attachments.append(att)
        self._by_obj[id(target)] = att
        self.sink.offer("collector", "collector.cdp_attached", {
            "label": att.label, "kind": kind, "enabled": att.enabled, "page_url_at_attach": att.page_url_at_attach,
        }, target_id=att.target_id, session_id=att.label)
        return att

    def _make_handler(self, name: str, att: CDPAttachment) -> Callable[[dict[str, Any]], None]:
        sink = self.sink

        def handler(params: dict[str, Any]) -> None:
            # Minimal work only: count, enqueue, notify cheap observers.
            att.event_counts[name] = att.event_counts.get(name, 0) + 1
            rid = params.get("requestId") if isinstance(params, dict) else None
            sink.offer("cdp", name, params, target_id=att.target_id, session_id=att.label, request_id=rid)
            if self.on_event is not None:
                try:
                    self.on_event(name, params, att)
                except Exception:
                    log.exception("on_event observer failed")

        return handler

    async def attach_frames_of(self, page: Page) -> None:
        """Try to give each child frame its own session. Same-process frames legitimately refuse; that's recorded."""
        for frame in page.frames:
            if frame == page.main_frame:
                continue
            try:
                await self.attach(frame)
            except Exception as exc:
                self.sink.offer("collector", "collector.frame_attach_skipped", {"url": frame.url, "reason": str(exc)[:200]})

    # ---- teardown ---------------------------------------------------------------------------
    async def detach_all(self) -> None:
        """Keep sessions alive until collection is finalized; call this last."""
        for att in self.attachments:
            try:
                await att.session.detach()
            except Exception:
                pass
        self.attachments.clear()
        self._by_obj.clear()
        self._pending.clear()

    def diagnostics(self) -> dict[str, Any]:
        return {
            "collector": COLLECTOR_VERSION,
            "protocol_version": self.browser_info.get("protocolVersion"),
            "product": self.browser_info.get("product"),
            "sessions": [{"label": a.label, "target_id": a.target_id, "kind": a.kind, "enabled": a.enabled,
                          "event_counts": dict(a.event_counts)} for a in self.attachments],
            "failures": list(self.failures),
            "coverage_note": "Page/frame sessions only; workers, other targets and pre-attach requests are not covered.",
        }
