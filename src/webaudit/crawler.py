"""Budgeted, scope-enforced, read-only crawler with explicit coverage accounting.

It never claims to have found every route: every skipped URL/action and every budget that was hit is recorded.
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlsplit

from playwright.async_api import Page, Response, TimeoutError as PWTimeout

from .config import ScanConfig
from .logging_setup import get_logger
from .models import PageRecord
from .scope import ScopePolicy
from .session import CollectionSession
from .urlnorm import normalize_url
from .samplefiles import SampleFiles, sample_text
from .writeguard import ALWAYS_UNSAFE_LABEL, HARD_DENY_LABEL, LOGIN_PATH, SENSITIVE_FIELD, UPLOAD_LABEL, label_allowed, write_denied

log = get_logger("crawler")

UNSAFE_WORDS = re.compile(
    r"\b(delete|remove|destroy|erase|drop|purge|revoke|deactivate|disable|terminate|cancel|unsubscribe|close account|"
    r"log ?out|sign ?out|pay|purchase|buy|order|checkout|subscribe|upgrade|invite|share|send|submit|save|update|apply|"
    r"confirm|approve|reject|publish|upload|import|reset|transfer|withdraw|grant|permission|role|password|create|add|new|"
    r"edit|rename|restore|clear|archive|run|execute|deploy|start|stop|restart|install|export|download)\b", re.I)
SAFE_WORDS = re.compile(
    r"^(show|view|details?|more|show more|load more|see more|expand|collapse|next|previous|prev|back|overview|summary|"
    r"general|settings overview|list|grid|table|activity|history|info|help|faq|menu|filter|sort|\w+ view|view \w+|all( \w+)?|show \w+|hide \w+|filter.*|sort.*|\d{1,3}|›|»|‹|«|>|<)$", re.I)
APPROVAL_DEFAULT = None


@dataclass
class Candidate:
    url: str
    depth: int
    discovered_from: Optional[str]
    source: str


@dataclass
class CrawlResult:
    pages: list[PageRecord] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


def classify_control(label: str, *, role: str = "", tag: str = "", in_form: bool = False, input_type: str = "",
                     has_expanded: bool = False) -> tuple[str, str]:
    """Return (decision, reason). decision in safe | unsafe | uncertain | skip."""
    text = (label or "").strip()
    if input_type in ("file", "submit", "password", "reset"):
        return "unsafe", f"input_type={input_type}"
    if in_form:
        return "skip", "inside_form"
    if UNSAFE_WORDS.search(text):
        return "unsafe", "unsafe_label"
    if role == "tab" or tag == "summary":
        return "safe", "tab_or_disclosure"
    if has_expanded and not UNSAFE_WORDS.search(text):
        return "safe", "disclosure_control"
    if SAFE_WORDS.match(text):
        return "safe", "read_only_label"
    return "uncertain", "unclassified_control"


LINK_JS = """() => {
  const out = [];
  document.querySelectorAll('a[href]').forEach(a => out.push({href: a.href, text: (a.innerText || a.getAttribute('aria-label') || '').trim().slice(0, 80),
      nav: !!a.closest('nav,[role=navigation],header'), download: a.hasAttribute('download'), target: a.target || ''}));
  document.querySelectorAll('link[rel=next],link[rel=prev]').forEach(l => out.push({href: l.href, text: l.rel, nav: true, download: false, target: ''}));
  return out;
}"""

CONTROL_JS = """el => ({tag: el.tagName.toLowerCase(), role: el.getAttribute('role') || '', type: (el.getAttribute('type') || '').toLowerCase(),
  text: (el.innerText || el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('alt') || el.value || '').trim().slice(0, 60),
  inForm: !!el.closest('form'), inDialog: !!el.closest('[role=dialog],[role=alertdialog],[aria-modal=true],dialog[open]'), expanded: el.hasAttribute('aria-expanded'), disabled: !!el.disabled,
  visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)})"""

FORMS_JS = """() => Array.from(document.forms).map((f, i) => ({
  i, action: f.getAttribute('action') || '', method: (f.getAttribute('method') || 'get').toLowerCase(),
  visible: !!(f.offsetWidth || f.offsetHeight || f.getClientRects().length),
  fields: Array.from(f.querySelectorAll('input,textarea,select')).map(e => ({tag: e.tagName.toLowerCase(), type: (e.getAttribute('type') || 'text').toLowerCase(),
      name: e.getAttribute('name') || e.id || '', accept: e.getAttribute('accept') || '', auto: e.getAttribute('autocomplete') || '', required: e.required, disabled: e.disabled,
      visible: !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length)})),
  buttons: Array.from(f.querySelectorAll('button,input[type=submit]')).map(b => ({text: (b.innerText || b.value || b.getAttribute('aria-label') || '').trim().slice(0, 40),
      type: (b.getAttribute('type') || 'submit').toLowerCase()}))}))"""


SEEN_JS = """() => document.querySelectorAll('input,textarea,select,button,[role=button]').forEach(e => {
  if (e.type === 'file' || e.offsetWidth || e.offsetHeight || e.getClientRects().length) e.setAttribute('data-wa-seen', '1'); })"""

OVERLAY_SELECTOR = "[role=dialog], [role=alertdialog], [aria-modal=true], dialog[open], [class*=modal i], [class*=overlay i], [class*=backdrop i], [class*=popup i]"
OVERLAY_JS = """(sel) => { const vw = innerWidth, vh = innerHeight;
  return Array.from(document.querySelectorAll(sel)).filter(e => {
    if (!(e.offsetWidth || e.offsetHeight || e.getClientRects().length)) return false;
    const cs = getComputedStyle(e);
    if (cs.pointerEvents === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) === 0) return false;
    const r = e.getBoundingClientRect();
    const aria = ['dialog', 'alertdialog'].includes(e.getAttribute('role')) || e.getAttribute('aria-modal') === 'true' || e.tagName === 'DIALOG';
    const floating = cs.position === 'fixed' || cs.position === 'absolute';
    const big = r.width * r.height >= 0.25 * vw * vh;
    return (aria && (big || floating)) || (floating && big);   // only something that can actually cover/block the page
  }).length; }"""
CLOSE_LABEL = re.compile(r"^(close|dismiss|cancel|not now|no,? thanks|maybe later|got it|ok|okay|skip|back|[x×✕✖])$", re.I)

CLICKABLE_JS = """() => { let n = 0;
  document.querySelectorAll('div,span,li,img,svg,p,td,h3,h4,label').forEach(e => {
    if (n >= 80 || e.hasAttribute('data-wa-clickable')) return;
    if (e.closest('a,button,[role=button],[role=tab],input,select,textarea,form,[data-wa-skip]')) return;
    if (!(e.offsetWidth || e.offsetHeight)) return;
    if (getComputedStyle(e).cursor !== 'pointer') return;
    if (Array.from(e.children).some(c => getComputedStyle(c).cursor === 'pointer')) return;   // click the innermost clickable
    const t = (e.innerText || e.getAttribute('aria-label') || e.getAttribute('title') || e.getAttribute('alt') || '').trim();
    if (!t || t.length > 40 || t.includes('\\n')) return;
    e.setAttribute('data-wa-clickable', '1'); n++; });
  return n; }"""

CONTROL_SELECTOR = "[data-wa-clickable], [role=tab], summary, button, [role=button], [aria-expanded], input[type=submit], input[type=button], input[type=file]"


ApproveFn = Callable[[dict[str, Any]], Awaitable[bool]]


class Crawler:
    def __init__(self, config: ScanConfig, session: CollectionSession, policy: ScopePolicy, *,
                 approve: ApproveFn | None = None, guard: Any = None) -> None:
        self.config, self.session, self.policy, self.approve = config, session, policy, approve
        self.guard = guard
        self.lim = config.crawl
        self.seen: set[str] = set()
        self.pattern_counts: Counter[str] = Counter()
        self.queue: deque[Candidate] = deque()
        self.visited = 0
        self.writes_done = 0
        self.write_actions: list[dict[str, Any]] = []
        self.marker_base = f"{config.write_test_prefix}-{uuid.uuid4().hex[:6]}"
        self._marker_n = 0
        self._done_forms: set[str] = set()
        self.session_lost = False
        self.samples: Optional[SampleFiles] = None
        self.readback_done = False
        self.click_errors: list[dict[str, str]] = []
        self.errors: list[dict[str, str]] = []
        self.page: Optional[Page] = None
        self._ctx: Any = None
        self._creating_page = False
        self.timeouts = 0
        self._clicked_on_pages: dict[str, int] = {}  # label -> number of pages where it was clicked (layout widgets repeat everywhere)
        self._pending: set[int] = set()  # in-flight state-changing requests
        self.nonget_count = 0
        self.readback_urls: list[str] = []
        self._extra_pages = 0
        self.result = CrawlResult()
        self.skipped: Counter[str] = Counter()
        self.budget_hit: list[str] = []
        self.started = 0.0
        self.interactions: Counter[str] = Counter()
        self.popups: list[str] = []
        self._popup_tasks: set[asyncio.Task[Any]] = set()
        self._dialogs = 0

    # ---- helpers ----------------------------------------------------------------------------
    def _request_count(self) -> int:
        cdp = self.session.cdp
        return sum(a.event_counts.get("Network.requestWillBeSent", 0) for a in cdp.attachments) if cdp else 0

    def _budget_ok(self) -> bool:
        if time.monotonic() - self.started > self.lim.max_seconds:
            self._hit("max_seconds")
            return False
        if self.visited >= self.lim.max_pages + self._extra_pages:
            self._hit("max_pages")
            return False
        if self._request_count() >= self.lim.max_requests:
            self._hit("max_requests")
            return False
        return True

    def _hit(self, name: str) -> None:
        if name not in self.budget_hit:
            self.budget_hit.append(name)

    def _record(self, rec: PageRecord) -> None:
        self.result.pages.append(rec)
        self.session.db.upsert_page(rec.page_id, rec.model_dump_json())

    def _skip(self, url: str, depth: int, frm: Optional[str], source: str, status: str, note: str) -> None:
        self.skipped[status + ":" + note] += 1
        self._record(PageRecord(page_id=f"pg-{uuid.uuid4().hex[:10]}", url=self._safe_url(url), discovered_from=frm,
                                discovery_source=source, navigation_status=status, depth=depth, note=note,
                                pattern=normalize_url(url)))

    @staticmethod
    def _safe_url(url: str) -> str:
        from .redaction import redact_url
        return redact_url(url)

    def _enqueue(self, url: str, depth: int, frm: Optional[str], source: str) -> None:
        url = self.policy.strip_fragment(url)
        if url in self.seen:
            return
        self.seen.add(url)
        d = self.policy.check(url)
        if not d:
            status = "skipped_policy" if d.reason == "excluded_pattern" else "skipped_scope"
            self._skip(url, depth, frm, source, status, d.reason)
            return
        if depth > self.lim.max_depth:
            self._skip(url, depth, frm, source, "skipped_budget", "max_depth")
            self._hit("max_depth")
            return
        pat = normalize_url(url)
        self.pattern_counts[pat] += 1
        if self.pattern_counts[pat] > self.lim.max_pages_per_pattern:
            self._skip(url, depth, frm, source, "skipped_budget", "pattern_repeat")
            return
        self.queue.append(Candidate(url, depth, frm, source))

    # ---- main loop --------------------------------------------------------------------------
    async def run(self, page: Page) -> CrawlResult:
        self.started = time.monotonic()
        self.page = page
        self._ctx = page.context
        ctx = page.context
        ctx.on("request", self._req_started)
        ctx.on("requestfinished", self._req_done)
        ctx.on("requestfailed", self._req_done)
        ctx.on("page", lambda p: self._on_new_page(p, page))
        page.on("dialog", lambda d: asyncio.ensure_future(self._dismiss(d)))
        self._enqueue(self.config.initial_url, 0, None, "seed")
        while True:
            while self.queue:
                if not self._budget_ok():
                    for c in self.queue:
                        self._skip(c.url, c.depth, c.discovered_from, c.source, "skipped_budget", "budget_exhausted")
                    self.queue.clear()
                    break
                cand = self.queue.popleft()
                await self._visit_safely(cand)
                page = self.page  # may have been replaced after a crash
                await asyncio.sleep(self.lim.request_delay_ms / 1000)
            if self.write_actions and not self.readback_done and not self.session_lost:
                # read-after-write: reload the seed and the pages where writes happened so the created data is read back
                self.readback_done = True
                self._extra_pages = 6
                urls = [self.config.initial_url] + [a["page"] for a in self.write_actions]
                for u in list(dict.fromkeys(urls))[:5]:
                    self.readback_urls.append(self._safe_url(u))
                    self.queue.append(Candidate(u, 1, None, "read_back"))
                continue
            break
        await self._wait_writes(page)
        if self._popup_tasks:
            await asyncio.wait(list(self._popup_tasks), timeout=10)
        self.result.stats = self.coverage()
        self.session.db.set_meta("coverage", self.result.stats)
        return self.result

    async def _dismiss(self, dialog: Any) -> None:
        self._dialogs += 1
        try:
            await dialog.dismiss()
        except Exception:
            pass

    async def _phase(self, name: str, coro: Any, cand: Candidate) -> Any:
        """Run one phase of a page visit; an exception is recorded and the crawl continues (never aborts the scan)."""
        try:
            return await coro
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.errors.append({"phase": name, "url": self._safe_url(cand.url), "error": f"{type(exc).__name__}: {str(exc)[:160]}"})
            log.warning("phase failed", extra={"ctx": {"phase": name, "err": type(exc).__name__}})
            return None

    async def _ensure_page(self) -> Page:
        """Replace a closed/crashed page so one browser-side failure cannot end the scan."""
        pg = self.page
        if pg is not None and not pg.is_closed():
            return pg
        self._creating_page = True
        try:
            pg = await self._ctx.new_page()
            await self.session.arm_page(pg)
            pg.on("dialog", lambda d: asyncio.ensure_future(self._dismiss(d)))
            self.page = pg
            self.errors.append({"phase": "recovery", "url": "", "error": "page was closed/crashed; opened a new page"})
        finally:
            self._creating_page = False
        return pg

    async def _scroll_load(self, page: Page) -> None:
        """Read-only: scroll to the bottom a few times so lazy-loaded / infinite lists request their next pages."""
        last = -1
        for _ in range(self.lim.scroll_steps):
            try:
                h = await page.evaluate("() => { window.scrollTo(0, document.documentElement.scrollHeight); return document.documentElement.scrollHeight; }")
            except Exception:
                return
            await page.wait_for_timeout(350)
            if h == last:
                break
            last = h
        try:
            await page.evaluate("() => window.scrollTo(0, 0)")
        except Exception:
            pass

    async def _visit_safely(self, cand: Candidate) -> None:
        rec = PageRecord(page_id=f"pg-{uuid.uuid4().hex[:10]}", url=self._safe_url(cand.url), discovered_from=cand.discovered_from,
                         discovery_source=cand.source, depth=cand.depth, pattern=normalize_url(cand.url))
        page = await self._ensure_page()
        try:
            await asyncio.wait_for(self._visit(page, cand, rec), timeout=self.lim.max_page_seconds)
        except asyncio.TimeoutError:
            self.timeouts += 1
            rec.navigation_status = "timeout"
            rec.note = f"page watchdog: exceeded {self.lim.max_page_seconds}s; moved on"
            self.errors.append({"phase": "watchdog", "url": rec.url, "error": rec.note})
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if rec.navigation_status == "pending":
                rec.navigation_status = "failed"
            rec.note = f"{type(exc).__name__}: {str(exc)[:160]}"
            self.errors.append({"phase": "visit", "url": rec.url, "error": rec.note})
        if rec.navigation_status in ("ok", "http_error", "timeout", "failed"):
            self.visited += 1
        try:  # leave the page in a clean state for the next candidate (and recover from crashes)
            pg = self.page
            if pg is None or pg.is_closed():
                await self._ensure_page()
            elif rec.navigation_status in ("failed", "skipped_scope", "timeout") and "about:blank" not in pg.url:
                await pg.goto("about:blank", timeout=5000)
        except Exception:
            try:  # goto failed on a broken page: replace it
                try:
                    await self.page.close()  # type: ignore[union-attr]
                except Exception:
                    pass
                await self._ensure_page()
            except Exception:
                pass
        log.info("page", extra={"ctx": {"status": rec.navigation_status, "url": rec.url[:120]}})
        self._record(rec)

    async def _visit(self, page: Page, cand: Candidate, rec: PageRecord) -> None:
        await self._wait_writes(page)
        try:
            resp: Optional[Response] = await page.goto(cand.url, wait_until="load")
            rec.http_status = resp.status if resp else None
            rec.navigation_status = "ok" if resp is None or resp.status < 400 else "http_error"
        except PWTimeout:
            rec.navigation_status = "timeout"
        except Exception as exc:
            msg = str(exc)
            rec.navigation_status = "skipped_policy" if "Download is starting" in msg else (
                "skipped_scope" if "blockedbyclient" in msg.lower() or "ERR_BLOCKED_BY_CLIENT" in msg else "failed")
            rec.note = msg.splitlines()[0][:200]
        if rec.navigation_status in ("ok", "http_error"):
            final = page.url
            if not self.policy.check(final, apply_excludes=False):  # observe-mode safety net / unexpected escape
                rec.navigation_status = "skipped_scope"
                rec.note = f"navigation ended out of scope ({self.policy.check(final, apply_excludes=False).reason})"
                self.skipped["skipped_scope:post_navigation_escape"] += 1
                try:
                    await page.goto("about:blank")
                except Exception:
                    pass
            elif cand.depth > 0 and LOGIN_PATH.search(urlsplit(final).path) and not LOGIN_PATH.search(urlsplit(cand.url).path):
                # the session ended / we were bounced to a login page: never type credentials, stop the crawl
                rec.navigation_status = "skipped_policy"
                rec.note = "redirected to a login page (session lost?); crawl stopped, no credentials are ever entered"
                self.session_lost = True
                self._hit("session_lost")
                self.queue.clear()
            else:
                if final != cand.url:
                    rec.note = (rec.note or "") + "redirected in-scope"
                await page.wait_for_timeout(self.config.crawl.settle_ms)
                if self.session.cdp:
                    await self.session.cdp.attach_frames_of(page)
                try:
                    rec.title = (await page.title())[:200]
                except Exception:
                    pass
                await self._scroll_load(page)
                await self._phase("discover", self._discover(page, cand), cand)
                rec.interaction_summary = await self._phase("interact", self._interact(page, cand), cand) or {}
                if self.config.interaction_mode == "read_write" and not self.session_lost and cand.source != "read_back":
                    if rec.interaction_summary.get("clicked"):  # reset UI state left behind by exploratory clicks (open panels, filters)
                        try:
                            await page.goto(cand.url, wait_until="load")
                            await page.wait_for_timeout(self.config.crawl.settle_ms)
                        except Exception:
                            pass
                    rec.interaction_summary["writes"] = await self._phase("write", self._write_phase(page, cand), cand) or {}
                await self._phase("discover", self._discover(page, cand), cand)  # links revealed by interactions
    async def _discover(self, page: Page, cand: Candidate) -> None:
        try:
            links = await page.evaluate(LINK_JS)
        except Exception:
            return
        for l in links:
            href = l.get("href", "")
            if not href or l.get("download"):
                continue
            self._enqueue(href, cand.depth + 1, self._safe_url(cand.url), "nav" if l.get("nav") else "link")

    async def _close_overlays(self, page: Page) -> None:
        """A modal/overlay left open blocks every later click (the 'one button per page' failure). Escape first, then a Close/Cancel button."""
        for _ in range(3):
            try:
                if not await page.evaluate(OVERLAY_JS, OVERLAY_SELECTOR):
                    return
                await page.keyboard.press("Escape")
                await page.wait_for_timeout(250)
                if not await page.evaluate(OVERLAY_JS, OVERLAY_SELECTOR):
                    self.interactions["overlay_closed"] += 1
                    return
                for b in await page.query_selector_all(", ".join(f"{p} button" for p in OVERLAY_SELECTOR.split(", "))):
                    try:
                        lab = (await b.evaluate("e => (e.innerText || e.getAttribute('aria-label') || e.title || '').trim()"))[:30]
                        if CLOSE_LABEL.match(lab) and await b.evaluate("e => !!(e.offsetWidth || e.offsetHeight)"):
                            await b.click(timeout=1500)
                            await page.wait_for_timeout(250)
                            self.interactions["overlay_closed"] += 1
                            break
                    except Exception:
                        continue
            except Exception:
                return
        self.interactions["overlay_stuck"] += 1

    async def _interact(self, page: Page, cand: Candidate) -> dict[str, Any]:
        """Click safe controls. The control list is RE-QUERIED after every click (SPAs re-render, so handles go stale), overlays are
        closed first, and controls that repeat on every page (feedback/help widgets) stop being clicked after two pages."""
        summary: dict[str, Any] = {"clicked": [], "skipped_unsafe": [], "needs_approval": [], "skipped_form": 0, "approved": [],
                                   "skipped_repeated_widget": []}
        if self.lim.max_interactions_per_page == 0:
            return summary
        start_url = page.url
        tried: set[str] = set()
        clicks = 0
        rw = self.config.interaction_mode == "read_write"
        for _ in range(self.lim.max_interactions_per_page * 4 + 20):
            if clicks >= self.lim.max_interactions_per_page or not self._budget_ok():
                break
            await self._close_overlays(page)
            try:
                await page.evaluate(CLICKABLE_JS)
                handles = await page.query_selector_all(CONTROL_SELECTOR)
            except Exception:
                break
            picked = None
            for h in handles[:120]:
                try:
                    info = await h.evaluate(CONTROL_JS)
                except Exception:
                    continue
                key = f"{info['tag']}|{info['role']}|{info['text'][:40]}|{info['inForm']}"
                if key in tried or info["disabled"] or not info["visible"]:
                    continue
                tried.add(key)
                decision, reason = classify_control(info["text"], role=info["role"], tag=info["tag"], in_form=info["inForm"],
                                                    input_type=info["type"], has_expanded=info["expanded"])
                label = info["text"][:40]
                if decision == "skip":
                    summary["skipped_form"] += 1
                    self.interactions["skipped_form"] += 1
                    continue
                if decision == "unsafe":
                    summary["skipped_unsafe"].append(label)
                    self.interactions["skipped_unsafe"] += 1
                    continue
                if decision == "uncertain":
                    ok = False
                    if self.config.manual_approval and self.approve:
                        ok = await self.approve({"url": self._safe_url(page.url), "label": label, "reason": reason})
                    elif rw and label and not HARD_DENY_LABEL.search(label) and not ALWAYS_UNSAFE_LABEL.search(label):
                        ok = True  # auto-write mode: unclassified but not dangerous-sounding; the network deny-list still applies
                    if not ok:
                        summary["needs_approval"].append(label)
                        self.interactions["needs_approval"] += 1
                        continue
                    summary["approved"].append(label)
                if self._clicked_on_pages.get(label.lower(), 0) >= 2:
                    summary["skipped_repeated_widget"].append(label)
                    continue
                picked = (h, label)
                break
            if picked is None:
                break
            h, label = picked
            ok_click = False
            last_err = ""
            for attempt in range(2):
                try:
                    try:
                        await h.scroll_into_view_if_needed(timeout=1000)
                    except Exception:
                        pass
                    await h.click(timeout=2000)
                    ok_click = True
                    break
                except Exception as exc:
                    last_err = str(exc).splitlines()[0][:150] if str(exc) else type(exc).__name__
                    await self._close_overlays(page)  # something is covering it: clear and retry once
            if not ok_click:
                try:  # last resort for a control that is vetted as safe: fire its click handler without hit-testing (covered by a sticky banner, etc.)
                    await h.dispatch_event("click")
                    ok_click = True
                    self.interactions["click_fallback"] += 1
                except Exception:
                    pass
            if not ok_click:
                self.interactions["click_failed"] += 1
                if len(self.click_errors) < 40:
                    self.click_errors.append({"page": self._safe_url(page.url), "label": label[:40], "error": last_err})
                continue
            clicks += 1
            summary["clicked"].append(label)
            self.interactions["clicked"] += 1
            self._clicked_on_pages[label.lower()] = self._clicked_on_pages.get(label.lower(), 0) + 1
            await page.wait_for_timeout(self.config.crawl.settle_ms // 2)
            await self._wait_writes(page)
            if page.url != start_url:  # control navigated: treat like a discovered URL, then come back
                self._enqueue(page.url, cand.depth + 1, self._safe_url(cand.url), "interaction")
                try:
                    await page.goto(start_url, wait_until="load")
                except Exception:
                    break
        await self._close_overlays(page)
        return summary

    # ---- automatic writes (read_write mode only) -----------------------------------------------------------------
    def _next_marker(self) -> str:
        self._marker_n += 1
        return f"{self.marker_base}-{self._marker_n}"

    def _sample_for(self, accept: Optional[str], hint: str = "") -> Any:
        if self.samples is None:
            self.samples = SampleFiles(self.session.scan_dir / "test_files", self.marker_base)
        return self.samples.pick(accept, hint)

    def _text_for(self, hints: str, tag: str, marker: str) -> str:
        return sample_text(hints, tag, marker, self.config.write_sample_text)

    def _label_ok(self, label: str) -> bool:
        return label_allowed(label, self.config.write_allow_labels, self.config.write_uploads)

    def _req_started(self, req: Any) -> None:
        if req.method not in ("GET", "HEAD", "OPTIONS"):
            self._pending.add(id(req))
            self.nonget_count += 1

    def _req_done(self, req: Any) -> None:
        self._pending.discard(id(req))

    async def _wait_writes(self, page: Page, timeout: float = 25.0) -> None:
        """Never navigate away while a state-changing request is in flight (that cancels it: ERR_ABORTED = write not applied)."""
        end = time.monotonic() + timeout
        while self._pending and time.monotonic() < end:
            await asyncio.sleep(0.1)
        if self._pending:
            log.warning("write request still pending after wait", extra={"ctx": {"pending": len(self._pending)}})
        try:
            await page.wait_for_load_state("networkidle", timeout=1500)
        except Exception:
            pass

    async def _settle_after_write(self, page: Page) -> None:
        await page.wait_for_timeout(self.config.crawl.settle_ms)
        await self._wait_writes(page)

    async def _fill_empty_fields(self, page: Page) -> tuple[list[str], Optional[str]]:
        """Formless SPA editors: put the test marker/sample text into fields that are EMPTY (never overwrites existing values)."""
        marker, names = self._next_marker(), []
        try:
            for el in (await page.query_selector_all("input:not([type]), input[type=text], input[type=search], input[type=url], textarea"))[:6]:
                if not await el.evaluate("e => !!(e.offsetWidth || e.offsetHeight) && !e.disabled && !e.readOnly && !e.value"):
                    continue
                name = (await el.get_attribute("name")) or (await el.get_attribute("id")) or (await el.get_attribute("placeholder")) or "field"
                if SENSITIVE_FIELD.search(name + " " + (await el.get_attribute("autocomplete") or "")):
                    continue
                hints = " ".join([name, (await el.get_attribute("placeholder")) or "", (await el.get_attribute("aria-label")) or ""])
                await el.fill(self._text_for(hints, await el.evaluate("e => e.tagName.toLowerCase()"), marker))
                names.append(name[:30])
        except Exception:
            pass
        return names, (marker if names else None)

    def _can_write(self, per_page: int) -> bool:
        return (self.writes_done < self.lim.max_writes and per_page < self.lim.max_writes_per_page and self._budget_ok()
                and not self.session_lost)

    def _vet_form(self, f: dict[str, Any]) -> tuple[bool, str]:
        if not f["visible"]:
            return False, "not_visible"
        for fld in f["fields"]:
            if fld["type"] == "password" or SENSITIVE_FIELD.search(f"{fld['name']} {fld['auto']}"):
                return False, "sensitive_field"
            if fld["type"] == "file" and not self.config.write_uploads:
                return False, "sensitive_field"
        if f["method"] == "get":
            return False, "get_form_is_read_only"
        from urllib.parse import urlsplit as _us
        u = _us(f["action"] or "")
        why = write_denied(u.path or "", u.query or "", "POST", self.config.write_deny_patterns)
        if why:
            return False, f"action_denied:{why}"
        if not any(self._label_ok(b["text"]) for b in f["buttons"]):
            return False, "no_clearly_safe_submit_label"
        if not any((x["visible"] or x["type"] == "file") and not x["disabled"] and x["type"] not in ("hidden", "checkbox", "radio") for x in f["fields"]):
            return False, "nothing_to_fill"
        return True, "ok"

    async def _fill_form(self, handle: Any, f: dict[str, Any]) -> tuple[list[str], str]:
        marker = self._next_marker()
        filled: list[str] = []
        for el in await handle.query_selector_all("input,textarea,select"):
            try:
                tag = await el.evaluate("e => e.tagName.toLowerCase()")
                typ = (await el.get_attribute("type") or "text").lower()
                name = (await el.get_attribute("name")) or (await el.get_attribute("id")) or tag
                hints = " ".join([name, (await el.get_attribute("placeholder")) or "", (await el.get_attribute("aria-label")) or ""])
                if typ == "file" and self.config.write_uploads:
                    sample = self._sample_for(await el.get_attribute("accept"), hints)
                    await el.set_input_files(str(sample))
                    filled.append(f"{name}<-{sample.name}")
                    continue
                if await el.evaluate("e => e.disabled || !(e.offsetWidth || e.offsetHeight)") or typ in ("hidden", "submit", "button", "image", "reset", "file"):
                    continue
                if tag == "select":
                    opts = await el.evaluate("e => Array.from(e.options).map(o => o.value).filter(v => v)")
                    if opts:
                        await el.select_option(opts[0])
                        filled.append(name)
                elif typ in ("checkbox", "radio"):
                    if await el.evaluate("e => e.required") and not await el.is_checked():
                        await el.check()
                        filled.append(name)
                elif typ == "email":
                    await el.fill(f"{marker}@example.invalid")  # .invalid never resolves: nothing can be delivered
                    filled.append(name)
                elif typ == "url":
                    await el.fill("https://example.invalid/" + marker)
                    filled.append(name)
                elif typ == "number":
                    await el.fill("1")
                    filled.append(name)
                elif typ in ("text", "search", "textarea") or tag == "textarea":
                    await el.fill(self._text_for(hints, tag, marker))
                    filled.append(name)
            except Exception:
                continue
        return filled, marker

    async def _handle_forms(self, page: Page, cand: Candidate, out: dict[str, Any], per_page: list[int]) -> None:
        try:
            forms = await page.evaluate(FORMS_JS)
        except Exception:
            return
        handles = await page.query_selector_all("form")
        for f in forms:
            if not self._can_write(per_page[0]):
                return
            sig = f"{page.url.split('#')[0]}|{f['action']}|{','.join(sorted(x['name'] for x in f['fields']))}"
            if sig in self._done_forms:
                continue
            self._done_forms.add(sig)
            ok, why = self._vet_form(f)
            if not ok:
                out["forms_skipped"].append({"action": f["action"][:60], "reason": why})
                continue
            handle = handles[f["i"]] if f["i"] < len(handles) else None
            if handle is None:
                continue
            filled, marker = await self._fill_form(handle, f)
            btn = None
            for b in await handle.query_selector_all("button,input[type=submit]"):
                label = (await b.evaluate("e => (e.innerText || e.value || e.getAttribute('aria-label') || '').trim()"))[:40]
                if self._label_ok(label):
                    btn, blabel = b, label
                    break
            if btn is None or not filled:
                out["forms_skipped"].append({"action": f["action"][:60], "reason": "nothing_filled_or_no_button"})
                continue
            start_url = page.url
            try:
                await btn.click(timeout=3000)
            except Exception:
                out["forms_skipped"].append({"action": f["action"][:60], "reason": "click_failed"})
                continue
            self.writes_done += 1
            per_page[0] += 1
            act = {"kind": "form_submit", "page": self._safe_url(start_url), "button": blabel, "fields": filled, "marker": marker,
                   "action": f["action"][:80], "method": f["method"]}
            self.write_actions.append(act)
            out["forms_submitted"].append({"button": blabel, "fields": filled, "marker": marker})
            await self._settle_after_write(page)
            if page.url != start_url:
                self._enqueue(page.url, cand.depth + 1, self._safe_url(cand.url), "interaction")
                try:
                    await page.goto(start_url, wait_until="load")
                except Exception:
                    return
                return  # DOM replaced: handles are stale; remaining forms are picked up on a revisit if needed

    async def _dialog_flow(self, page: Page, cand: Candidate, out: dict[str, Any], per_page: list[int]) -> None:
        """Fields/buttons that appeared after a write-control click (SPA dialogs without <form>): fill with a marker, press a safe button."""
        if not self._can_write(per_page[0]):
            return
        try:
            fields = await page.query_selector_all("input:not([data-wa-seen]), textarea:not([data-wa-seen])")
        except Exception:
            return
        marker, filled = self._next_marker(), []
        if self.config.write_uploads:
            try:
                for fi in await page.query_selector_all("input[type=file]:not([data-wa-seen]):not([data-wa-uploaded])"):
                    sample = self._sample_for(await fi.get_attribute("accept"), (await fi.get_attribute("name")) or "")
                    await fi.set_input_files(str(sample))
                    filled.append(f"file<-{sample.name}")
            except Exception:
                pass
        for el in fields[:8]:
            try:
                typ = (await el.get_attribute("type") or "text").lower()
                name = (await el.get_attribute("name")) or (await el.get_attribute("id")) or (await el.get_attribute("placeholder")) or "field"
                hints = " ".join([name, (await el.get_attribute("placeholder")) or "", (await el.get_attribute("aria-label")) or ""])
                if (typ in ("password", "file", "hidden", "checkbox", "radio", "submit", "button", "email", "tel")
                        or SENSITIVE_FIELD.search(name + " " + (await el.get_attribute("autocomplete") or ""))
                        or not await el.evaluate("e => !!(e.offsetWidth || e.offsetHeight) && !e.disabled")):
                    continue
                await el.fill("1" if typ == "number" else self._text_for(hints, await el.evaluate("e => e.tagName.toLowerCase()"), marker))
                filled.append(name[:30])
            except Exception:
                continue
        if not filled:
            return
        for b in await page.query_selector_all("button:not([data-wa-seen])"):
            try:
                label = (await b.evaluate("e => (e.innerText || e.getAttribute('aria-label') || '').trim()"))[:40]
                if not self._label_ok(label) or not await b.evaluate("e => !!(e.offsetWidth || e.offsetHeight) && !e.disabled"):
                    continue
                url0 = page.url
                await b.click(timeout=3000)
                self.writes_done += 1
                per_page[0] += 1
                has_text = any("<-" not in f for f in filled)
                self.write_actions.append({"kind": "dialog_submit", "page": self._safe_url(url0), "button": label, "fields": filled,
                                           "marker": marker if has_text else None})
                out["forms_submitted"].append({"button": label, "fields": filled, "marker": marker if has_text else None})
                await self._settle_after_write(page)
                return
            except Exception:
                continue
        out["forms_skipped"].append({"action": "(dialog)", "reason": "no_safe_button_after_filling"})

    async def _press_safe_submit(self, page: Page) -> Optional[str]:
        """After attaching a file, many apps enable a Save/Upload/Add/Done button; press the first clearly safe one."""
        try:
            for b in await page.query_selector_all("button, [role=button], input[type=submit]"):
                label = (await b.evaluate("e => (e.innerText || e.value || e.getAttribute('aria-label') || '').trim()"))[:40]
                if (not label or UPLOAD_LABEL.match(label) or not self._label_ok(label)
                        or not await b.evaluate("e => !!(e.offsetWidth || e.offsetHeight) && !e.disabled")):
                    continue
                await b.click(timeout=2000)
                return label
        except Exception:
            pass
        return None

    async def _bare_file_inputs(self, page: Page, out: dict[str, Any], per_page: list[int]) -> None:
        """File inputs outside any <form> that no upload button reached (apps usually upload on change)."""
        if not self.config.write_uploads:
            return
        try:
            inputs = await page.query_selector_all("input[type=file]:not([data-wa-uploaded])")
            for fi in inputs[:2]:
                if not self._can_write(per_page[0]):
                    return
                if await fi.evaluate("e => !!e.closest('form') || e.disabled"):
                    continue
                name = (await fi.get_attribute("name")) or (await fi.get_attribute("id")) or "file"
                sample = self._sample_for(await fi.get_attribute("accept"), name)
                await fi.set_input_files(str(sample))
                await fi.evaluate("e => e.setAttribute('data-wa-uploaded', '1')")
                await page.wait_for_timeout(300)  # let the app enable its Save/Upload button
                submit = await self._press_safe_submit(page)
                self.writes_done += 1
                per_page[0] += 1
                self.write_actions.append({"kind": "file_upload", "page": self._safe_url(page.url), "button": f"input[{name}]", "file": sample.name,
                                           "marker": self.marker_base, **({"submit_button": submit} if submit else {})})
                out["controls_clicked"].append(f"input[{name}] -> uploaded {sample.name}" + (f", pressed '{submit}'" if submit else ""))
                await self._settle_after_write(page)
        except Exception:
            return

    async def _write_phase(self, page: Page, cand: Candidate) -> dict[str, Any]:
        out: dict[str, Any] = {"forms_submitted": [], "forms_skipped": [], "controls_clicked": [], "controls_denied": [], "controls_noop": []}
        per_page = [0]
        if not self._can_write(0):
            return out
        await self._close_overlays(page)
        await self._handle_forms(page, cand, out, per_page)
        start_url = page.url
        try:
            await page.evaluate(CLICKABLE_JS)
            await page.evaluate(SEEN_JS)
            handles = await page.query_selector_all(CONTROL_SELECTOR)
        except Exception:
            return out
        # collect eligible controls first; text/create flows are tried BEFORE uploads so uploads cannot starve them
        cands: list[tuple[int, Any, str]] = []
        for h in handles[:80]:
            try:
                info = await h.evaluate(CONTROL_JS)
            except Exception:
                continue
            if info["disabled"] or not info["visible"] or info["inForm"] or info["inDialog"] or info["type"] in ("file", "submit", "password", "reset"):
                continue
            if await h.get_attribute("data-wa-seen") is None:
                continue  # appeared after a click (a dialog): only _dialog_flow may touch it, after filling its fields
            label = info["text"][:40]
            if not self._label_ok(label):
                if label and UNSAFE_WORDS.search(label):
                    out["controls_denied"].append(label)
                continue
            cands.append((1 if (self.config.write_uploads and UPLOAD_LABEL.match(label.strip())) else 0, h, label))
        cands.sort(key=lambda c: c[0])
        upload_clicks = 0
        for prio, h, label in cands:
            if not self._can_write(per_page[0]):
                break
            if prio == 1 and upload_clicks >= 1:
                continue
            uploaded = None
            n0 = self.nonget_count
            filled_fields: list[str] = []
            fill_marker: Optional[str] = None
            if prio == 0 and re.match(r"^(save|update|apply|done)\b", label.strip(), re.I):
                filled_fields, fill_marker = await self._fill_empty_fields(page)
            try:
                await page.evaluate(SEEN_JS)  # only what is visible NOW counts as seen: anything that appears after the click is "new"
                if prio == 1:
                    upload_clicks += 1
                    try:
                        async with page.expect_file_chooser(timeout=2500) as fci:
                            await h.click(timeout=2000)
                        chooser = await fci.value
                        sample = self._sample_for(await chooser.element.get_attribute("accept"), label)
                        await chooser.element.evaluate("e => e.setAttribute('data-wa-uploaded', '1')")
                        await chooser.set_files(str(sample))
                        uploaded = sample.name
                    except Exception:
                        pass  # no file chooser opened: the click behaved like a normal control
                else:
                    await h.click(timeout=2000)
            except Exception:
                continue
            await self._settle_after_write(page)  # let any request this click started FINISH before anything else happens
            if uploaded:
                self.writes_done += 1
                per_page[0] += 1
                self.write_actions.append({"kind": "file_upload", "page": self._safe_url(start_url), "button": label, "file": uploaded,
                                           "marker": self.marker_base})
                out["controls_clicked"].append(f"{label} -> uploaded {uploaded}")
            elif self.nonget_count > n0:  # the click itself sent a state-changing request: a real write
                self.writes_done += 1
                per_page[0] += 1
                self.write_actions.append({"kind": "control_click", "page": self._safe_url(start_url), "button": label,
                                           **({"fields": filled_fields, "marker": fill_marker} if fill_marker else {})})
                out["controls_clicked"].append(label)
            else:
                out["controls_noop"].append(label)  # opened a menu/dialog or did nothing: not counted as a write
            await self._handle_forms(page, cand, out, per_page)  # a real <form> may have appeared
            await self._dialog_flow(page, cand, out, per_page)  # SPA dialogs without <form>
            if page.url != start_url:
                self._enqueue(page.url, cand.depth + 1, self._safe_url(cand.url), "interaction")
                try:
                    await self._wait_writes(page)
                    await page.goto(start_url, wait_until="load")
                except Exception:
                    pass
                break  # DOM replaced: remaining handles are stale
        await self._bare_file_inputs(page, out, per_page)
        return out

    def _on_new_page(self, popup: Page, opener: Page) -> None:
        if popup == opener or self._creating_page:
            return
        t = asyncio.ensure_future(self._handle_popup(popup))
        self._popup_tasks.add(t)
        t.add_done_callback(self._popup_tasks.discard)

    async def _handle_popup(self, popup: Page) -> None:
        try:
            await popup.wait_for_load_state("load", timeout=self.lim.page_timeout_ms)
        except Exception:
            pass
        url = popup.url
        d = self.policy.check(url, apply_excludes=False)
        rec = PageRecord(page_id=f"pg-{uuid.uuid4().hex[:10]}", url=self._safe_url(url), discovery_source="popup",
                         pattern=normalize_url(url))
        if d:
            rec.navigation_status = "ok"
            try:
                rec.title = (await popup.title())[:200]
            except Exception:
                pass
            self.popups.append(self._safe_url(url))
        else:
            rec.navigation_status = "skipped_scope"
            rec.note = d.reason
        self._record(rec)
        try:
            await popup.close()
        except Exception:
            pass

    def coverage(self) -> dict[str, Any]:
        by_status = Counter(p.navigation_status for p in self.result.pages)
        blocked = list(self.guard.blocked) if self.guard else []
        return {
            "pages_total_recorded": len(self.result.pages), "by_navigation_status": dict(by_status),
            "skipped": dict(self.skipped), "budgets_hit": self.budget_hit,
            "budgets": {"max_depth": self.lim.max_depth, "max_pages": self.lim.max_pages, "max_seconds": self.lim.max_seconds,
                        "max_requests": self.lim.max_requests, "max_pages_per_pattern": self.lim.max_pages_per_pattern},
            "errors": self.errors[:100], "errors_count": len(self.errors), "click_errors": self.click_errors, "page_timeouts": self.timeouts,
            "interaction_mode": self.config.interaction_mode, "writes_performed": self.writes_done, "write_actions": self.write_actions,
            "write_test_marker_prefix": self.marker_base if self.write_actions else None, "read_back_pages": self.readback_urls,
            "test_files_available": self.samples.listing() if self.samples else [], "session_lost": self.session_lost,
            "interactions": dict(self.interactions), "popups_observed": self.popups, "dialogs_dismissed": self._dialogs,
            "requests_observed_cdp": self._request_count(), "scope_guard_blocks": blocked,
            "url_patterns": dict(self.pattern_counts),
            "elapsed_s": round(time.monotonic() - self.started, 2),
            "note": "Discovery is best-effort: routes reachable only via unsafe/uncertain controls, forms, or deep state are NOT covered.",
        }
