"""Phase 9: the interaction loop must survive overlays, re-rendering SPAs and repeated layout widgets (the 'one button per page' bug)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from tests.test_phase4_crawl import jl
from webaudit.config import CrawlLimits, ScanConfig
from webaudit.scan import run_scan


async def _settle(url: str) -> None:
    await asyncio.sleep(1.5)


def _cfg(server: Any, tmp: Path, mode: str) -> ScanConfig:
    return ScanConfig(initial_url=server.main_url + "/ov", confirm_authorized=True, allow_http_local=True, headless=True,
                      interaction_mode=mode, output_dir=str(tmp / "o"), profile_dir=str(tmp / "p"), write_uploads=False,
                      crawl=CrawlLimits(max_pages=4, max_depth=1, request_delay_ms=0, settle_ms=400, max_interactions_per_page=8))


@pytest.mark.browser
@pytest.mark.parametrize("mode", ["read_only", "read_write"])
async def test_overlay_and_rerendering_tabs_do_not_stop_the_crawl_after_one_click(server: Any, tmp_path: Path, mode: str) -> None:
    h = len(server.hits)
    scan_dir = await run_scan(_cfg(server, tmp_path / mode, mode), login_prompt=_settle)
    hits = [x for x in server.hits[h:] if x[0] == "GET" and x[1] == "/api/json"]
    pages = {p["url"].replace(server.main_url, ""): p for p in jl(scan_dir / "pages.jsonl") if p["navigation_status"] == "ok"}
    clicked = pages["/ov"]["interaction_summary"]["clicked"]
    # all three tabs were clicked although the first control opened a full-screen modal and every click re-renders the tab list
    assert {"Alpha", "Beta", "Gamma"} <= set(clicked), clicked
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert cov["interactions"].get("click_failed", 0) == 0 and cov["interactions"].get("overlay_stuck", 0) == 0
    if mode == "read_write":  # the unclassified floating widget is clicked, opens a full-screen modal, and the loop must close it and carry on
        assert "Report issue" in clicked and cov["interactions"].get("overlay_closed", 0) >= 1
    else:
        assert "Report issue" not in clicked
    # the layout widget repeated on /ov2 is not clicked over and over once it has been seen on two pages
    second = pages.get("/ov2")
    if second:
        assert second["interaction_summary"]["clicked"].count("Report issue") <= 1


@pytest.mark.browser
async def test_unclassified_controls_are_clicked_only_in_auto_write_mode(server: Any, tmp_path: Path) -> None:
    async def requests_for(mode: str) -> list[str]:
        h = len(server.hits)
        await run_scan(_cfg(server, tmp_path / ("m" + mode), mode), login_prompt=_settle)
        return [x[1] for x in server.hits[h:]]

    ro = await requests_for("read_only")
    assert "/api/json" in ro  # tabs are safe in any mode
    # 'Zoom thing' is unclassified: needs approval in read-only mode, clicked automatically in auto-write mode
    n_ro = len([1 for x in server.hits if x == ("GET", "/api/json")])
    cfg = _cfg(server, tmp_path / "chk", "read_only")
    s1 = await run_scan(cfg, login_prompt=_settle)
    ov = next(p for p in jl(s1 / "pages.jsonl") if p["url"].endswith("/ov"))["interaction_summary"]
    assert "Zoom thing" in ov["needs_approval"] and "Zoom thing" not in ov["clicked"]
    s2 = await run_scan(_cfg(server, tmp_path / "chk2", "read_write"), login_prompt=_settle)
    ov2 = next(p for p in jl(s2 / "pages.jsonl") if p["url"].endswith("/ov"))["interaction_summary"]
    assert "Zoom thing" in ov2["clicked"] and "Zoom thing" in ov2["approved"]
