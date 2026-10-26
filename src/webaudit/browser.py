"""Browser lifecycle: dedicated persistent Chromium profile, manual login, scope guard routing."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urljoin, urlsplit

from playwright.async_api import BrowserContext, Page, Playwright, Request, Route

from .config import ScanConfig
from .event_store.sink import EventSink
from .logging_setup import get_logger
from .scope import ScopePolicy
from .urlnorm import normalize_path
from .writeguard import write_denied

log = get_logger("browser")
MARKER = ".webaudit_profile"
ORDINARY_PROFILE_HINTS = (
    "google\\chrome\\user data", "google/chrome/user data", "chromium\\user data", "microsoft\\edge\\user data",
    "bravesoftware", "mozilla\\firefox", "library/application support/google/chrome", ".config/google-chrome",
    ".config/chromium", "appdata\\local\\google", "appdata\\local\\microsoft\\edge",
)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def prepare_profile_dir(path: str | Path) -> Path:
    """Create/validate a dedicated automation profile. Refuses ordinary browser profiles and unmarked non-empty dirs."""
    p = Path(path).expanduser().resolve()
    low = str(p).lower()
    if any(h in low for h in ORDINARY_PROFILE_HINTS):
        raise ValueError(f"refusing to use what looks like an ordinary browser profile: {p}")
    if p.exists() and any(p.iterdir()) and not (p / MARKER).exists():
        raise ValueError(f"{p} is a non-empty directory not created by webaudit (missing {MARKER}); choose another profile_dir")
    p.mkdir(parents=True, exist_ok=True)
    (p / MARKER).write_text("dedicated webaudit profile; contains authenticated session data - keep local\n", encoding="utf-8")
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return p


async def launch_context(pw: Playwright, config: ScanConfig) -> BrowserContext:
    profile = prepare_profile_dir(config.profile_dir)
    ctx = await pw.chromium.launch_persistent_context(
        str(profile), headless=config.headless, viewport={"width": 1366, "height": 850},
        accept_downloads=False, args=["--disable-features=Translate"])
    ctx.set_default_navigation_timeout(config.crawl.page_timeout_ms)
    ctx.set_default_timeout(min(config.crawl.page_timeout_ms, 10_000))
    return ctx


LoginPrompt = Callable[[str], Awaitable[None]]


async def console_login_prompt(url: str) -> None:
    import asyncio
    print(f"\nA dedicated browser window opened at {url}.\n"
          "Log in manually (including MFA). Do not paste credentials anywhere else.\n"
          "When you are logged in and the dashboard is visible, return here and press Enter to start the scan...")
    await asyncio.to_thread(input)


async def manual_login(context: BrowserContext, url: str, prompt: LoginPrompt) -> Page:
    """Phase before collectors are armed: login traffic is deliberately NOT captured."""
    page = context.pages[0] if context.pages else await context.new_page()
    await page.goto(url)
    await prompt(url)
    return page


class ScopeGuard:
    """Crawler safety net (separate from the passive collectors).

    Two layers, because Playwright's ``context.route`` is NOT invoked for redirect hops (verified empirically):
    1. ``context.route``: checks navigation targets, refuses metadata/internal subresource targets and (once
       ``enforce_methods`` is on) state-changing methods. Playwright documents that routing disables the HTTP cache.
    2. Per-page CDP ``Fetch`` interception at the *response* stage of Document requests: a 3xx whose Location is out of
       scope is failed before the browser follows it. Other responses are continued untouched.
    Use scope_enforcement='observe' to avoid all interception (then escapes can only be detected afterwards).
    Limitation: a popup's very first request is only covered by layer 1 until layer 2 attaches.
    """

    def __init__(self, policy: ScopePolicy, sink: EventSink, config: ScanConfig) -> None:
        self.policy, self.sink, self.config = policy, sink, config
        self.blocked: list[dict[str, Any]] = []
        self.enforce_methods = False  # enabled after manual login (login itself legitimately POSTs credentials)
        self._sessions: list[Any] = []
        self._context: BrowserContext | None = None

    async def install(self, context: BrowserContext) -> None:
        self._context = context
        await context.route("**/*", self._handle)
        context.on("page", lambda p: asyncio.ensure_future(self._attach_redirect_guard(p)))
        for p in context.pages:
            await self._attach_redirect_guard(p)

    async def uninstall(self, context: BrowserContext) -> None:
        try:
            await context.unroute("**/*", self._handle)
        except Exception:
            pass
        for s in self._sessions:
            try:
                await s.detach()
            except Exception:
                pass

    def _record(self, reason: str, url: str, method: str, navigation: bool, rtype: str) -> None:
        p = urlsplit(url)
        info = {"reason": reason, "method": method, "origin": f"{p.scheme}://{p.netloc}", "path": normalize_path(p.path)[:200],
                "navigation": navigation, "resource_type": rtype}
        self.blocked.append(info)
        self.sink.offer("crawler", "crawler.request_blocked", info)

    def _block(self, route: Route, request: Request, reason: str) -> Any:
        self._record(reason, request.url, request.method, request.is_navigation_request(), request.resource_type)
        return route.abort("blockedbyclient")

    async def _handle(self, route: Route, request: Request) -> None:
        try:
            url = request.url
            if request.is_navigation_request():
                d = self.policy.check(url, apply_excludes=False)
                if not d:
                    return await self._block(route, request, f"navigation:{d.reason}")
            else:
                d = self.policy.request_blocked(url)
                if not d:
                    return await self._block(route, request, f"request:{d.reason}")
            if self.enforce_methods and request.method not in SAFE_METHODS:
                u = urlsplit(url)
                if self.config.interaction_mode == "read_write":
                    why = write_denied(u.path, u.query, request.method, self.config.write_deny_patterns, self.config.write_uploads)
                    if why:
                        return await self._block(route, request, f"write_denied:{why}")
                elif self.config.block_unsafe_methods and not any(u.path.startswith(a) for a in self.config.allow_unsafe_method_paths):
                    return await self._block(route, request, "state_changing_method")
            await route.continue_()
        except Exception as exc:  # fail closed, never hang the page
            log.error("scope guard error", extra={"ctx": {"err": repr(exc)}})
            try:
                await route.abort("failed")
            except Exception:
                pass

    async def _attach_redirect_guard(self, page: Page) -> None:
        if self._context is None:
            return
        try:
            s = await self._context.new_cdp_session(page)
            self._sessions.append(s)
            s.on("Fetch.requestPaused", lambda ev, s=s: asyncio.ensure_future(self._on_paused(s, ev)))
            await s.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "resourceType": "Document", "requestStage": "Response"}]})
        except Exception as exc:
            self.sink.offer("collector", "collector.redirect_guard_unavailable", {"error": str(exc)[:200]})

    async def _on_paused(self, s: Any, ev: dict[str, Any]) -> None:
        rid = ev["requestId"]
        try:
            code = ev.get("responseStatusCode")
            if code and 300 <= code < 400:
                loc = next((h["value"] for h in ev.get("responseHeaders") or [] if h["name"].lower() == "location"), None)
                if loc:
                    target = urljoin(ev["request"]["url"], loc)
                    d = self.policy.check(target, apply_excludes=False)
                    if not d:
                        self._record(f"redirect:{d.reason}", target, "GET", True, "Document")
                        await s.send("Fetch.failRequest", {"requestId": rid, "errorReason": "BlockedByClient"})
                        return
            await s.send("Fetch.continueRequest", {"requestId": rid})
        except Exception:
            try:
                await s.send("Fetch.failRequest", {"requestId": rid, "errorReason": "Failed"})
            except Exception:
                pass
