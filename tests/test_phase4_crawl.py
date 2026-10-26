"""Phase 4: config validation, scope policy, persistent profile, manual login ordering, safe scoped crawling."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import pytest
from playwright.async_api import async_playwright

from webaudit.browser import ScopeGuard, launch_context, prepare_profile_dir
from webaudit.config import BodyPolicy, CrawlLimits, ScanConfig, load_config
from webaudit.crawler import classify_control
from webaudit.scan import list_scans, run_scan
from webaudit.scope import ScopePolicy, is_internal_host


# ---- config ------------------------------------------------------------------------------------

def test_config_requires_https_unless_local_opt_in() -> None:
    with pytest.raises(ValueError):
        ScanConfig(initial_url="http://app.example.com/")
    with pytest.raises(ValueError):
        ScanConfig(initial_url="http://app.example.com/", allow_http_local=True)  # not a local host
    with pytest.raises(ValueError):
        ScanConfig(initial_url="http://127.0.0.1:8000/")  # local but not opted in
    c = ScanConfig(initial_url="http://127.0.0.1:8000/", allow_http_local=True)
    assert c.allowed_origins == ["http://127.0.0.1:8000"]
    assert ScanConfig(initial_url="https://App.Example.com:443/dash").allowed_origins == ["https://app.example.com"]


def test_config_rejects_credentials_and_bad_origins() -> None:
    with pytest.raises(ValueError, match="credential-like"):
        ScanConfig.model_validate({"initial_url": "https://a.example", "password": "x"})
    with pytest.raises(ValueError):
        ScanConfig(initial_url="https://user:pw@a.example/")
    with pytest.raises(ValueError):
        ScanConfig(initial_url="https://a.example/", extra_allowed_origins=["https://*.example.com"])
    with pytest.raises(ValueError):
        ScanConfig(initial_url="https://a.example/", extra_allowed_origins=["https://b.example/path"])
    c = ScanConfig(initial_url="https://a.example/", extra_allowed_origins=["https://b.example"])
    assert c.allowed_origins == ["https://a.example", "https://b.example"]


def test_authorization_confirmation_is_required() -> None:
    with pytest.raises(PermissionError):
        ScanConfig(initial_url="https://a.example/").require_authorization()
    ScanConfig(initial_url="https://a.example/", confirm_authorized=True).require_authorization()


def test_load_config_toml(tmp_path: Path) -> None:
    p = tmp_path / "c.toml"
    p.write_text('initial_url = "https://a.example/dashboard"\n[crawl]\nmax_pages = 7\n[body]\nmode = "selected"\n', encoding="utf-8")
    c = load_config(p, confirm_authorized=True)
    assert c.crawl.max_pages == 7 and c.body.mode == "selected" and c.confirm_authorized


# ---- scope -----------------------------------------------------------------------------------

def test_scope_exact_origin_not_prefix() -> None:
    p = ScopePolicy(["https://app.example.com", "http://127.0.0.1:8000"], [r"logout"])
    assert p.check("https://app.example.com/a?b=1")
    assert p.check("https://APP.example.com:443/x")  # default port + case normalised
    for bad, why in [
        ("https://app.example.com.evil.com/", "origin_not_approved"),
        ("https://evilapp.example.com/", "origin_not_approved"),
        ("http://app.example.com/", "origin_not_approved"),  # scheme matters
        ("https://app.example.com:8443/", "origin_not_approved"),  # port matters
        ("https://app.example.com@evil.com/", "userinfo"),
        ("https://user:pw@app.example.com/", "userinfo"),
        ("http://127.0.0.1:8001/", "internal_target"),
        ("http://127.0.0.1.evil.com:8000/", "origin_not_approved"),
        ("http://169.254.169.254/latest/meta-data/", "metadata_endpoint"),
        ("http://10.0.0.5/", "internal_target"),
        ("http://[::1]:8000/", "internal_target"),
        ("javascript:alert(1)", "scheme"), ("file:///etc/passwd", "scheme"), ("data:text/html,x", "scheme"),
        ("https://app.example.com/logout", "excluded_pattern"),
    ]:
        d = p.check(bad)
        assert not d and d.reason == why, (bad, d)
    assert p.check("http://127.0.0.1:8000/ok")
    assert not p.request_blocked("http://169.254.169.254/")
    assert p.request_blocked("https://cdn.thirdparty.example/lib.js")  # public third party observed, not blocked
    assert is_internal_host("192.168.1.1") and not is_internal_host("8.8.8.8")


def test_control_classifier_is_conservative() -> None:
    assert classify_control("Tab One", role="tab")[0] == "safe"
    assert classify_control("More", tag="summary")[0] == "safe"
    assert classify_control("Next")[0] == "safe"
    assert classify_control("Delete account")[0] == "unsafe"
    assert classify_control("Save", in_form=True)[0] == "skip"
    assert classify_control("Invite user")[0] == "unsafe"
    assert classify_control("Pay now")[0] == "unsafe"
    assert classify_control("Log out")[0] == "unsafe"
    assert classify_control("Upload", input_type="file")[0] == "unsafe"
    assert classify_control("Do thing")[0] == "uncertain"
    assert classify_control("Show details", has_expanded=True)[0] == "safe"


# ---- profile ---------------------------------------------------------------------------------

def test_profile_refuses_ordinary_browser_profiles_and_foreign_dirs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ordinary browser profile"):
        prepare_profile_dir(tmp_path / "Google" / "Chrome" / "User Data")
    foreign = tmp_path / "docs"
    foreign.mkdir()
    (foreign / "file.txt").write_text("x")
    with pytest.raises(ValueError, match="not created by webaudit"):
        prepare_profile_dir(foreign)
    ok = prepare_profile_dir(tmp_path / "prof")
    assert (ok / ".webaudit_profile").exists()
    assert prepare_profile_dir(tmp_path / "prof") == ok  # idempotent for our own profile


@pytest.mark.browser
async def test_persistent_profile_keeps_authenticated_state(server: Any, tmp_path: Path) -> None:
    cfg = ScanConfig(initial_url=server.main_url + "/", allow_http_local=True, headless=True, profile_dir=str(tmp_path / "prof"))
    async with async_playwright() as pw:
        ctx = await launch_context(pw, cfg)
        await ctx.add_cookies([{"name": "auth_sim", "value": "v1", "url": server.main_url, "expires": time.time() + 3600}])
        page = await ctx.new_page()
        await page.goto(server.main_url + "/page2")
        await page.evaluate("localStorage.setItem('k', 'persisted')")
        await ctx.close()
        ctx2 = await launch_context(pw, cfg)
        cookies = await ctx2.cookies(server.main_url)
        assert any(c["name"] == "auth_sim" for c in cookies)
        p2 = ctx2.pages[0] if ctx2.pages else await ctx2.new_page()
        await p2.goto(server.main_url + "/page2")
        assert await p2.evaluate("localStorage.getItem('k')") == "persisted"
        await ctx2.close()


# ---- full scans against the fixture -------------------------------------------------------------

def scan_cfg(server: Any, tmp: Path, **kw: Any) -> ScanConfig:
    crawl = kw.pop("crawl", CrawlLimits(max_pages=30, request_delay_ms=0, settle_ms=300, max_seconds=120, page_timeout_ms=15000))
    return ScanConfig(initial_url=server.main_url + "/", confirm_authorized=True, allow_http_local=True, headless=True,
                      output_dir=str(tmp / "out"), profile_dir=str(tmp / "profile"), crawl=crawl, **kw)


async def _noop_prompt(url: str) -> None:
    return None


def jl(p: Path) -> list[dict[str, Any]]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


@pytest.mark.browser
async def test_full_scan_scope_safety_and_coverage(server: Any, tmp_path: Path) -> None:
    prompt_time: list[float] = []
    hits_at_prompt: list[int] = []

    async def prompt(url: str) -> None:
        await asyncio.sleep(1.5)  # a human takes seconds to log in; let login-phase page requests settle first
        prompt_time.append(time.time())
        hits_at_prompt.append(len(server.hits))  # page loads before this point are the (uncollected) login phase

    cfg = scan_cfg(server, tmp_path)
    scan_dir = await run_scan(cfg, login_prompt=prompt)
    new_hits = server.hits[hits_at_prompt[0]:]

    pages = jl(scan_dir / "pages.jsonl")
    by_path = {p["url"].replace(server.main_url, ""): p for p in pages if p["url"].startswith(server.main_url)}
    for ok in ("/", "/page2", "/page2/sub", "/users/1", "/users/2", "/danger"):
        assert by_path[ok]["navigation_status"] == "ok", (ok, by_path.get(ok))
    assert by_path["/page2"]["title"] == "Page 2"
    # excluded by policy and never requested
    assert by_path["/logout"]["navigation_status"] == "skipped_policy"
    assert ("GET", "/logout") not in new_hits
    # out-of-scope link recorded as a skipped coverage gap and never requested
    off = [p for p in pages if p["navigation_status"] == "skipped_scope"]
    assert off and any("origin_not_approved" in (p["note"] or "") or "internal_target" in (p["note"] or "") for p in off)
    assert ("GET", "API:/offsite") not in new_hits
    # no destructive request ever reached the server: not from click, form, nor page script
    assert [h for h in new_hits if h[0] == "POST"] == []
    # safe interactions happened (tabs), unsafe/uncertain did not
    p2 = by_path["/page2"]["interaction_summary"]
    assert {"Tab One", "Tab Two"} <= set(p2["clicked"]) and "More" in p2["clicked"]
    dz = by_path["/danger"]["interaction_summary"]
    assert "Delete account" in dz["skipped_unsafe"] and "Do thing" in dz["needs_approval"] and dz["clicked"] == []
    assert "Save" in dz["skipped_unsafe"]  # form submit button never clicked
    assert ("GET", "/api/json") in new_hits  # tab clicks fetched read-only data
    # popup registered
    assert any(p["discovery_source"] == "popup" and p["navigation_status"] == "ok" for p in pages)
    # /users/{id} deduplicated into one URL pattern
    cov = json.loads((scan_dir / "coverage.json").read_text())
    assert cov["crawl"]["url_patterns"][server.main_url + "/users/{id}"] == 2
    # guard blocked state-changing methods and cross-origin internal target subresources
    reasons = {b["reason"] for b in cov["crawl"]["scope_guard_blocks"]}
    assert "state_changing_method" in reasons
    # collectors were armed after login and before the scan navigated
    manifest = json.loads((scan_dir / "manifest.json").read_text())
    assert manifest["completion_status"] == "completed"
    events = jl(scan_dir / "network_events.jsonl")
    cdp_req_ts = [e["timestamp"] for e in events if e["event_type"] == "Network.requestWillBeSent"]
    assert cdp_req_ts and min(cdp_req_ts) > prompt_time[0]
    first_attach = next(e for e in events if e["event_type"] == "collector.cdp_attached")
    assert first_attach["timestamp"] >= prompt_time[0] and first_attach["raw_event"]["enabled"]
    assert list_scans(cfg.output_dir)[0]["status"] == "completed"


@pytest.mark.browser
async def test_budgets_and_pattern_limits_are_enforced_and_reported(server: Any, tmp_path: Path) -> None:
    crawl = CrawlLimits(max_pages=3, max_pages_per_pattern=1, request_delay_ms=0, settle_ms=200, max_interactions_per_page=0)
    scan_dir = await run_scan(scan_cfg(server, tmp_path, crawl=crawl), login_prompt=_noop_prompt)
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert "max_pages" in cov["budgets_hit"]
    ok = [p for p in jl(scan_dir / "pages.jsonl") if p["navigation_status"] == "ok"]
    assert len(ok) == 3
    assert any(k.startswith("skipped_budget:") for k in cov["skipped"])


@pytest.mark.browser
async def test_depth_limit(server: Any, tmp_path: Path) -> None:
    crawl = CrawlLimits(max_depth=0, request_delay_ms=0, settle_ms=200, max_interactions_per_page=0)
    scan_dir = await run_scan(scan_cfg(server, tmp_path, crawl=crawl), login_prompt=_noop_prompt)
    pages = jl(scan_dir / "pages.jsonl")
    assert [p["url"] for p in pages if p["navigation_status"] == "ok"] == [server.main_url + "/"]
    assert any(p["note"] == "max_depth" for p in pages)


@pytest.mark.browser
async def test_manual_approval_gate_for_uncertain_controls(server: Any, tmp_path: Path) -> None:
    asked: list[str] = []

    async def approve(info: dict[str, Any]) -> bool:
        asked.append(info["label"])
        return info["label"] == "Do thing"

    hits_before = [0]

    async def prompt(url: str) -> None:
        await asyncio.sleep(1.5)
        hits_before[0] = len(server.hits)

    cfg = ScanConfig(initial_url=server.main_url + "/danger", confirm_authorized=True, allow_http_local=True, headless=True,
                     manual_approval=True, output_dir=str(tmp_path / "out"), profile_dir=str(tmp_path / "p"),
                     crawl=CrawlLimits(max_depth=0, request_delay_ms=0, settle_ms=300))
    scan_dir = await run_scan(cfg, login_prompt=prompt, approve=approve)
    assert "Do thing" in asked and "Delete account" not in asked  # unsafe controls are never even offered
    assert ("GET", "/api/json") in server.hits[hits_before[0]:]
    assert [h for h in server.hits[hits_before[0]:] if h[0] == "POST"] == []


@pytest.mark.browser
async def test_guard_blocks_redirect_escape(server: Any, browser: Any, tmp_path: Path) -> None:
    """A same-origin URL that redirects off-scope must be stopped at the redirect hop (not just by URL pre-checks)."""
    from webaudit.event_store import EventSink
    cfg = scan_cfg(server, tmp_path)
    policy = ScopePolicy(cfg.allowed_origins, cfg.exclude_patterns)
    sink = EventSink(100)
    ctx = await browser.new_context()
    page = await ctx.new_page()
    guard = ScopeGuard(policy, sink, cfg)
    await guard.install(ctx)  # attaches the redirect guard to existing pages before they navigate
    n = len(server.hits)
    with pytest.raises(Exception, match="BLOCKED_BY_CLIENT"):
        await page.goto(server.main_url + "/redirect/offsite")
    assert ("GET", "/redirect/offsite") in server.hits[n:]  # the in-scope hop was allowed
    assert ("GET", "API:/offsite") not in server.hits[n:]  # the off-scope hop never reached the server
    assert any(b["reason"].startswith("redirect:") for b in guard.blocked)
    assert not page.url.startswith(server.api_url)
    await ctx.close()


@pytest.mark.browser
async def test_observe_mode_detects_escape_post_hoc(server: Any, tmp_path: Path) -> None:
    """Without routing, an escape cannot be prevented, only detected and recorded; verify honesty of that mode."""
    cfg = scan_cfg(server, tmp_path, scope_enforcement="observe",
                   crawl=CrawlLimits(max_depth=0, request_delay_ms=0, settle_ms=200, max_interactions_per_page=0))
    cfg = cfg.model_copy(update={"initial_url": server.main_url + "/redirect/offsite"})
    scan_dir = await run_scan(cfg, login_prompt=_noop_prompt)
    pages = jl(scan_dir / "pages.jsonl")
    assert pages[0]["navigation_status"] == "skipped_scope" and "out of scope" in pages[0]["note"]


async def test_run_scan_requires_authorization(server: Any, tmp_path: Path) -> None:
    cfg = ScanConfig(initial_url=server.main_url + "/", allow_http_local=True, output_dir=str(tmp_path))
    with pytest.raises(PermissionError):
        await run_scan(cfg, login_prompt=_noop_prompt)
    assert not (tmp_path / "scans").exists()
