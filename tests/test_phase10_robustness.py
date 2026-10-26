"""Phase 10: robustness for arbitrary (and large) apps: error isolation, watchdog, crash recovery, lazy loading, scope options, presets."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from tests.test_phase4_crawl import jl
from webaudit import cli
from webaudit.config import BodyPolicy, CrawlLimits, ScanConfig
from webaudit.crawler import Crawler
from webaudit.scan import run_scan
from webaudit.scope import ScopePolicy, registrable_base


async def _settle(url: str) -> None:
    await asyncio.sleep(1.2)


def cfg(server: Any, tmp: Path, start: str, **kw: Any) -> ScanConfig:
    crawl = kw.pop("crawl", CrawlLimits(max_pages=6, max_depth=1, request_delay_ms=0, settle_ms=300, max_interactions_per_page=6))
    kw.setdefault("write_uploads", False)
    return ScanConfig(initial_url=server.main_url + start, confirm_authorized=True, allow_http_local=True, headless=True,
                      output_dir=str(tmp / "o"), profile_dir=str(tmp / "p"), crawl=crawl, **kw)


# ---- scope / config / presets (pure unit) ---------------------------------------------------------------

def test_include_subdomains_is_opt_in_and_https_only() -> None:
    off = ScopePolicy(["https://app.example.com"])
    on = ScopePolicy(["https://app.example.com"], include_subdomains=True)
    assert not off.check("https://docs.example.com/") and on.check("https://docs.example.com/x") and on.check("https://example.com/")
    assert not on.check("https://example.com.evil.com/") and not on.check("https://notexample.com/") and not on.check("http://docs.example.com/")
    assert not on.check("https://user@docs.example.com/")
    assert ScopePolicy(["http://127.0.0.1:8000"], include_subdomains=True).subdomain_bases == set()  # never for IPs/local
    assert registrable_base("a.b.example.co.uk") == "example.co.uk" and registrable_base("x.example.com") == "example.com"


def test_presets_and_defaults_scale_to_big_apps() -> None:
    assert CrawlLimits().max_requests >= 100_000 and ScanConfig(initial_url="https://a.example").network_buffer_mb >= 100
    p = cli.build_parser()
    t = cli._config_from_args(p.parse_args(["scan", "https://a.example", "--preset", "thorough"]))
    assert t.crawl.max_pages == 300 and t.crawl.max_seconds == 7200 and t.crawl.max_depth == 6
    q = cli._config_from_args(p.parse_args(["scan", "https://a.example", "--preset", "quick", "--max-pages", "9"]))
    assert q.crawl.max_pages == 9 and q.crawl.max_depth == 2  # explicit flag beats the preset
    assert cli._config_from_args(p.parse_args(["scan", "https://a.example", "--include-subdomains"])).include_subdomains is True


@pytest.mark.browser
async def test_cdp_buffer_comes_from_config(browser: Any, server: Any, tmp_path: Path) -> None:
    from webaudit.session import CollectionSession
    c = cfg(server, tmp_path, "/", network_buffer_mb=150)
    sess = CollectionSession(c, tmp_path / "s", "x")
    ctx = await browser.new_context()
    await sess.open(ctx)
    assert sess.cdp.max_total_buffer == 150_000_000 and sess.cdp.max_resource_buffer == 20_000_000  # type: ignore[union-attr]
    await sess.close()
    await ctx.close()


# ---- overlay detection: only real blockers --------------------------------------------------------------

@pytest.mark.browser
async def test_harmless_modal_looking_class_is_not_an_overlay_and_costs_no_time(server: Any, tmp_path: Path) -> None:
    scan_dir = await run_scan(cfg(server, tmp_path, "/ov3"), login_prompt=_settle)
    c = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert c["interactions"].get("overlay_stuck", 0) == 0 and c["interactions"].get("overlay_closed", 0) == 0
    clicked = next(p for p in jl(scan_dir / "pages.jsonl") if p["url"].endswith("/ov3"))["interaction_summary"]["clicked"]
    assert {"Zed", "Why"} <= set(clicked)


# ---- formless Save: fill only EMPTY fields, never overwrite -----------------------------------------------

@pytest.mark.browser
async def test_save_fills_only_empty_fields_and_marker_is_confirmed_on_readback(server: Any, tmp_path: Path) -> None:
    server.profile_saved = None
    scan_dir = await run_scan(cfg(server, tmp_path, "/prof", interaction_mode="read_write", body=BodyPolicy(mode="selected")), login_prompt=_settle)
    saved = server.profile_saved
    assert saved is not None and saved["name"] == "Existing Name"  # an existing value is never overwritten
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert saved["bio"].count("webaudit-test-") >= 1 and "automated test content" in saved["bio"]
    act = cov["write_actions"][0]
    assert act["kind"] == "control_click" and act["button"] == "Save" and act["fields"] == ["bio"] and act["marker"] in saved["bio"]
    assert cov["write_readback"]["write_requests"]["completed"] == 1


# ---- lazy loading ---------------------------------------------------------------------------------------

@pytest.mark.browser
async def test_scrolling_triggers_infinite_list_requests(server: Any, tmp_path: Path) -> None:
    h = len(server.hits)
    crawl = CrawlLimits(max_pages=2, max_depth=0, request_delay_ms=0, settle_ms=300, scroll_steps=6, max_interactions_per_page=0)
    await run_scan(cfg(server, tmp_path, "/inf", crawl=crawl), login_prompt=_settle)
    # the page itself loads page=1; scrolling must have pulled further pages
    pages_seen = [x for x in server.hits[h:] if x[1] == "/api/json"]
    assert len(pages_seen) >= 3


# ---- error isolation / watchdog / crash recovery --------------------------------------------------------

@pytest.mark.browser
async def test_exception_in_a_phase_is_isolated_and_the_scan_still_completes(server: Any, tmp_path: Path, monkeypatch: Any) -> None:
    orig = Crawler._interact
    calls = {"n": 0}

    async def flaky(self: Any, page: Any, cand: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom in interact")
        return await orig(self, page, cand)
    monkeypatch.setattr(Crawler, "_interact", flaky)
    scan_dir = await run_scan(cfg(server, tmp_path, "/page2"), login_prompt=_settle)
    manifest = json.loads((scan_dir / "manifest.json").read_text())
    c = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert manifest["completion_status"] == "completed" and c["errors_count"] == 1 and "boom in interact" in c["errors"][0]["error"]
    assert any("crawler interact" in e and "the scan continued" in e for e in manifest["collection_errors"])
    assert len([p for p in jl(scan_dir / "pages.jsonl") if p["navigation_status"] == "ok"]) >= 2  # later pages were still visited


@pytest.mark.browser
async def test_watchdog_moves_on_from_a_stuck_page(server: Any, tmp_path: Path, monkeypatch: Any) -> None:
    orig = Crawler._discover
    state = {"stuck": False}

    async def hang_once(self: Any, page: Any, cand: Any) -> None:
        if not state["stuck"] and cand.url.endswith("/page2"):
            state["stuck"] = True
            await asyncio.sleep(60)  # simulates a page that never settles
        await orig(self, page, cand)
    monkeypatch.setattr(Crawler, "_discover", hang_once)
    crawl = CrawlLimits(max_pages=6, max_depth=1, request_delay_ms=0, settle_ms=300, max_page_seconds=10, max_interactions_per_page=0)
    scan_dir = await run_scan(cfg(server, tmp_path, "/page2", crawl=crawl), login_prompt=_settle)
    c = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    pages = jl(scan_dir / "pages.jsonl")
    assert c["page_timeouts"] == 1 and any(p["navigation_status"] == "timeout" and "watchdog" in (p["note"] or "") for p in pages)
    assert json.loads((scan_dir / "manifest.json").read_text())["completion_status"] == "completed"


@pytest.mark.browser
async def test_closed_page_is_replaced_and_crawl_continues(server: Any, tmp_path: Path, monkeypatch: Any) -> None:
    orig = Crawler._interact
    state = {"closed": False}

    async def close_page(self: Any, page: Any, cand: Any) -> Any:
        if not state["closed"]:
            state["closed"] = True
            await page.close()  # simulates a crashed/closed tab
            raise RuntimeError("Target page, context or browser has been closed")
        return await orig(self, page, cand)
    monkeypatch.setattr(Crawler, "_interact", close_page)
    scan_dir = await run_scan(cfg(server, tmp_path, "/page2"), login_prompt=_settle)
    c = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert any(e["phase"] == "recovery" for e in c["errors"])
    assert len([p for p in jl(scan_dir / "pages.jsonl") if p["navigation_status"] == "ok"]) >= 2  # pages after the crash were visited on the new page
    assert json.loads((scan_dir / "manifest.json").read_text())["completion_status"] == "completed"
