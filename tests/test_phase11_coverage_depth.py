"""Phase 11: features that real SPAs need — custom clickables, verb-led create flows, upload-then-save, click fallback + diagnostics."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from tests.test_phase4_crawl import jl
from webaudit.config import CrawlLimits, ScanConfig
from webaudit.scan import run_scan
from webaudit.writeguard import label_allowed


async def _settle(url: str) -> None:
    await asyncio.sleep(1.2)


def cfg(server: Any, tmp: Path, start: str, **kw: Any) -> ScanConfig:
    kw.setdefault("interaction_mode", "read_write")
    kw.setdefault("write_uploads", True)
    return ScanConfig(initial_url=server.main_url + start, confirm_authorized=True, allow_http_local=True, headless=True,
                      output_dir=str(tmp / "o"), profile_dir=str(tmp / "p"),
                      crawl=CrawlLimits(max_pages=3, max_depth=0, request_delay_ms=0, settle_ms=300, max_interactions_per_page=8), **kw)


def test_verb_led_create_phrases_are_writes_but_dangerous_ones_are_not() -> None:
    for ok in ("Create a Memory", "Add child", "Add a new child", "Write entry", "Compose message", "Record moment", "Create new album", "Make a plan"):
        assert label_allowed(ok, [], True), ok
    for bad in ("Create invite", "Create account", "Add payment method", "Add email", "Remove", "Sign out", "Start free trial", "Export keepsake",
                "Create a Memory and share", "Delete memory", "Add a card"):
        assert not label_allowed(bad, [], True), bad


@pytest.mark.browser
async def test_div_and_li_navigation_is_discovered_and_destructive_custom_controls_are_not(server: Any, tmp_path: Path) -> None:
    h = len(server.hits)
    scan_dir = await run_scan(cfg(server, tmp_path, "/clk"), login_prompt=_settle)
    new = server.hits[h:]
    assert ("GET", "/api/json") in new
    page = next(p for p in jl(scan_dir / "pages.jsonl") if p["url"].endswith("/clk"))["interaction_summary"]
    assert {"Memories", "Children"} <= set(page["clicked"])  # cursor:pointer divs/li were found and clicked
    assert "Remove everything" not in page["clicked"] and not [x for x in new if x[0] == "DELETE"]


@pytest.mark.browser
async def test_create_a_memory_flow_fills_dialog_and_saves_but_create_invite_is_never_pressed(server: Any, tmp_path: Path) -> None:
    n, h = len(server.notes_store), len(server.hits)
    scan_dir = await run_scan(cfg(server, tmp_path, "/mem"), login_prompt=_settle)
    assert len(server.notes_store) == n + 1 and "automated test content" in server.notes_store[-1]
    assert ("POST", "/api/invite") not in server.hits[h:]
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert [a["kind"] for a in cov["write_actions"]] == ["dialog_submit"] and cov["write_actions"][0]["button"] == "Save memory"


@pytest.mark.browser
async def test_file_attach_is_followed_by_the_apps_own_save_button(server: Any, tmp_path: Path) -> None:
    n = len(server.uploads)
    scan_dir = await run_scan(cfg(server, tmp_path, "/img"), login_prompt=_settle)
    ups = server.uploads[n:]
    assert len(ups) == 1 and ups[0]["filename"] == "webaudit-test-sample.png" and ups[0]["has_png"]  # Save photo was enabled by the file and pressed
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert cov["write_actions"][0]["submit_button"] == "Save photo"
    assert cov["write_readback"]["write_requests"]["completed"] == 1


@pytest.mark.browser
async def test_covered_control_uses_fallback_and_failures_are_diagnosed(server: Any, tmp_path: Path) -> None:
    h = len(server.hits)
    scan_dir = await run_scan(cfg(server, tmp_path, "/cover", interaction_mode="read_only"), login_prompt=_settle)
    assert ("GET", "/api/json") in server.hits[h:]  # the covered tab still received its click
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert cov["interactions"].get("click_fallback", 0) >= 1 and "click_errors" in cov
