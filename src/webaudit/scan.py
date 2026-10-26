"""Scan orchestration: login (uncollected) -> arm collectors -> guard -> crawl OR manual session -> flush -> export.

Output layout: ``<output_dir>/<N><host>/`` where N counts scans (1, 2, 3, ...), e.g. ``output/1example.com``.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import urlsplit

from playwright.async_api import BrowserContext, Page, Playwright, async_playwright

from . import exporter
from .browser import LoginPrompt, ScopeGuard, console_login_prompt, launch_context, manual_login
from .config import ScanConfig
from .crawler import ApproveFn, Crawler
from .instrumentation import CDP_VERSION, PW_VERSION
from .logging_setup import get_logger, setup_logging
from .models import PageRecord, ScanMetadata
from .redaction import redact_url
from .scope import ScopePolicy
from .session import CollectionSession
from .urlnorm import normalize_url

log = get_logger("scan")
FinishPrompt = Callable[[BrowserContext], Awaitable[None]]


def host_slug(url: str) -> str:
    host = urlsplit(url).hostname or "site"
    return re.sub(r"[^A-Za-z0-9.\-]", "_", host)


NUMBER_MARKER = ".scan_number"


def scan_number(d: Path) -> Optional[int]:
    """The scan's sequence number. A marker file is authoritative because ``<N><host>`` is ambiguous for hosts that start
    with digits (``3127.0.0.1`` is scan 3 of 127.0.0.1, not scan 3127). Unmarked legacy folders fall back to their leading digits."""
    try:
        return int((d / NUMBER_MARKER).read_text().strip())
    except (OSError, ValueError):
        m = re.match(r"(\d+)", d.name)
        return int(m.group(1)) if m else None


def next_scan_dir(output_dir: str | Path, url: str) -> Path:
    """``output/<N><host>`` with N = highest existing scan number + 1 (1, 2, 3, ...). Never reuses a number."""
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    nums = [n for d in root.iterdir() if d.is_dir() and (n := scan_number(d)) is not None]
    n = max(nums, default=0) + 1
    while True:
        d = root / f"{n}{host_slug(url)}"
        try:
            d.mkdir()
            (d / NUMBER_MARKER).write_text(str(n))
            return d
        except FileExistsError:
            n += 1


async def console_finish_prompt(context: BrowserContext) -> None:
    print("\nMANUAL SESSION: use the application normally in the browser window (login/logout, search, pagination, saves, uploads, ...).\n"
          "Everything you do is recorded passively. Press Enter here when you are finished...")
    await asyncio.to_thread(input)


async def run_scan(config: ScanConfig, *, login_prompt: LoginPrompt = console_login_prompt, approve: ApproveFn | None = None,
                   finish_prompt: FinishPrompt = console_finish_prompt, playwright: Optional[Playwright] = None,
                   export: bool = True) -> Path:
    config.require_authorization()
    scan_dir = next_scan_dir(config.output_dir, config.initial_url)
    scan_id = scan_dir.name
    setup_logging(config.log_level, str(scan_dir / "scan.log"))
    log.info("scan starting", extra={"ctx": {"scan_id": scan_id, "origins": config.allowed_origins, "mode": config.mode}})

    meta = ScanMetadata(scan_id=scan_id, started_at=datetime.now(timezone.utc).isoformat(), initial_url=config.initial_url,
                        allowed_origins=config.allowed_origins, configuration=config.public_dict(),
                        collector_versions={"cdp": CDP_VERSION, "playwright_events": PW_VERSION,
                                            "playwright": importlib.metadata.version("playwright"), "webaudit": "0.1.0"})
    session = CollectionSession(config, scan_dir, scan_id)
    session.db.set_meta("scan_metadata", meta.model_dump(mode="json"))
    (scan_dir / "scan_metadata.json").write_text(meta.model_dump_json(indent=2), encoding="utf-8")

    owns_pw = playwright is None
    pw = playwright if playwright is not None else await async_playwright().start()
    context = None
    status = "completed"
    try:
        context = await launch_context(pw, config)
        policy = ScopePolicy(config.allowed_origins, config.exclude_patterns, config.include_subdomains)
        guard = None
        if config.scope_enforcement == "guard":  # scope-only during login (credential POSTs must pass)
            guard = ScopeGuard(policy, session.sink, config)
            await guard.install(context)
        page = await manual_login(context, config.initial_url, login_prompt)  # login traffic is NOT collected
        await session.open(context)  # arms CDP on existing pages BEFORE the scan navigates
        await session.arm_page(page)
        if config.mode == "manual":
            # The human drives; the tool only observes. Method blocking stays off because the user decides which actions to perform.
            await _manual_session(config, session, context, finish_prompt)
        else:
            if guard:
                guard.enforce_methods = True
            crawler = Crawler(config, session, policy, approve=approve, guard=guard)
            await crawler.run(page)
        if session.cdp:
            meta.browser_version = (session.cdp.browser_info or {}).get("product")
            meta.protocol_version = (session.cdp.browser_info or {}).get("protocolVersion")
    except (KeyboardInterrupt, asyncio.CancelledError):
        status = "interrupted"
        log.warning("scan interrupted; flushing persisted data")
        raise
    except Exception as exc:
        status = "failed"
        meta.errors.append(repr(exc)[:500])
        log.exception("scan failed")
        raise
    finally:
        try:
            meta.completed_at = datetime.now(timezone.utc).isoformat()
            meta.completion_status = status  # type: ignore[assignment]
            if not session.closed:
                session.db.set_meta("scan_metadata", meta.model_dump(mode="json"))
            await asyncio.shield(session.close(status=status))
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
            if export:
                exporter.export_scan(scan_dir, completion_status=status)
        finally:
            if owns_pw:
                await pw.stop()
    return scan_dir


async def _manual_session(config: ScanConfig, session: CollectionSession, context: BrowserContext, finish_prompt: FinishPrompt) -> None:
    """Record pages the user visits (main-frame navigations) and wait until they finish."""
    seen: dict[str, PageRecord] = {}

    def on_nav(frame: Any) -> None:
        page = frame.page
        if frame != page.main_frame or not frame.url.startswith("http"):
            return
        url = redact_url(frame.url.split("#")[0])
        if url not in seen:
            seen[url] = PageRecord(page_id="pg-" + hashlib.sha1(url.encode()).hexdigest()[:10], url=url, discovery_source="manual",
                                   navigation_status="ok", pattern=normalize_url(url))
            session.db.upsert_page(seen[url].page_id, seen[url].model_dump_json())

    def hook(p: Page) -> None:
        p.on("framenavigated", on_nav)

    for p in context.pages:
        hook(p)
    context.on("page", hook)
    await finish_prompt(context)
    for p in context.pages:  # titles of the pages still open
        try:
            url = redact_url(p.url.split("#")[0])
            if url in seen:
                seen[url].title = (await p.title())[:200]
                session.db.upsert_page(seen[url].page_id, seen[url].model_dump_json())
        except Exception:
            pass
    session.db.set_meta("coverage", {
        "mode": "manual", "pages_total_recorded": len(seen), "by_navigation_status": {"ok": len(seen)}, "skipped": {}, "budgets_hit": [],
        "scope_guard_blocks": [], "interactions": {}, "url_patterns": {},
        "note": "Manual session: coverage is exactly what the human did in the browser. Nothing was clicked or submitted by the tool."})


def _all_scan_dirs(output_dir: str | Path) -> list[Path]:
    root = Path(output_dir)
    dirs: list[Path] = []
    if root.exists():
        dirs += [d for d in root.iterdir() if d.is_dir() and (d / "scan.sqlite").exists()]
        legacy = root / "scans"  # layout used by earlier versions
        if legacy.exists():
            dirs += [d for d in legacy.iterdir() if d.is_dir() and (d / "scan.sqlite").exists()]

    def key(d: Path) -> tuple[int, str]:
        n = scan_number(d)
        return (n if n is not None else 10**9, d.name)
    return sorted(dirs, key=key)


def resolve_scan(scan: str, output_dir: str | Path) -> Optional[Path]:
    """Accept a path, a folder name (``3example.com``), a bare number (``3``) or a legacy scan id."""
    p = Path(scan)
    if (p / "scan.sqlite").exists():
        return p
    dirs = _all_scan_dirs(output_dir)
    for d in dirs:
        if d.name == scan:
            return d
    if scan.isdigit():
        hits = [d for d in dirs if scan_number(d) == int(scan)]
        if len(hits) == 1:
            return hits[0]
    return None


def list_scans(output_dir: str | Path) -> list[dict[str, Any]]:
    out = []
    for d in _all_scan_dirs(output_dir):
        try:
            status = exporter.detect_status(d)
            meta_p = d / "scan_metadata.json"
            meta = json.loads(meta_p.read_text(encoding="utf-8")) if meta_p.exists() else {}
        except Exception as exc:
            out.append({"scan_id": d.name, "status": f"unreadable: {exc}"})
            continue
        cfg = meta.get("configuration", {})
        out.append({"scan_id": d.name, "status": status, "initial_url": meta.get("initial_url"), "started_at": meta.get("started_at"),
                    "exported": (d / "manifest.json").exists(), "mode": cfg.get("mode"), "session_label": cfg.get("session_label")})
    return out
