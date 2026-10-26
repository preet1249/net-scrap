"""Phase 7: scan folders, manual sessions, initiator chains, body-reference integrity, failure/scope/channel diagnostics, comparison."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests import fixture_app as fx
from tests.test_phase3_storage import collect, read_jsonl
from webaudit import cli, exporter
from webaudit.compare import compare_scans, render_markdown
from webaudit.config import BodyPolicy, CrawlLimits, ScanConfig
from webaudit.correlation import initiator_chain
from webaudit.exporter import classify_failures, skipped_scope_origins
from webaudit.models import RequestRecord
from webaudit.scan import host_slug, list_scans, next_scan_dir, resolve_scan, run_scan


# ---- folder naming: output/<N><host> ---------------------------------------------------------------

def test_scan_folders_are_numbered_with_host(tmp_path: Path) -> None:
    out = tmp_path / "output"
    a = next_scan_dir(out, "https://example.com/dashboard")
    b = next_scan_dir(out, "https://app.example.com/x")
    c = next_scan_dir(out, "http://127.0.0.1:8000/")
    assert [a.name, b.name, c.name] == ["1example.com", "2app.example.com", "3127.0.0.1"]
    assert next_scan_dir(out, "http://127.0.0.1:9/").name == "4127.0.0.1"  # IP hosts: '3127.0.0.1' is scan 3, not scan 3127
    (out / "7old").mkdir()  # legacy/unmarked folder: leading digits are used
    assert next_scan_dir(out, "https://example.com").name == "8example.com"  # never reuses a number
    assert host_slug("https://User@Exa mple.com/") != ""


def test_scan_resolution_by_number_name_and_path(tmp_path: Path) -> None:
    out = tmp_path / "output"
    for n in ("1example.com", "2example.com", "12other.org"):
        (out / n).mkdir(parents=True)
        (out / n / "scan.sqlite").write_bytes(b"")
    (out / "3127.0.0.1").mkdir()
    (out / "3127.0.0.1" / "scan.sqlite").write_bytes(b"")
    (out / "3127.0.0.1" / ".scan_number").write_text("3")
    assert resolve_scan("3", out).name == "3127.0.0.1"
    assert resolve_scan("2", out).name == "2example.com"
    assert resolve_scan("12", out).name == "12other.org"
    assert resolve_scan("1example.com", out).name == "1example.com"
    assert resolve_scan(str(out / "2example.com"), out) == out / "2example.com"
    assert resolve_scan("5", out) is None


# ---- manual session: the human drives, the tool observes --------------------------------------------

async def _noop(url: str) -> None:
    return None


@pytest.mark.browser
async def test_manual_session_records_user_driven_write_payloads(server: Any, tmp_path: Path) -> None:
    posts_before = len([h for h in server.hits if h == ("POST", "/api/echo")])

    async def user_actions(context: Any) -> None:  # stands in for a person clicking "save" in the browser window
        page = context.pages[0]
        await page.goto(server.main_url + "/page2")
        await page.evaluate("fetch('/api/echo', {method: 'POST', headers: {'Content-Type': 'application/json'}, "
                            "body: JSON.stringify({title: 'My CV', password: '%s'})}).then(r => r.text())" % fx.SECRET_PASSWORD)
        await page.wait_for_timeout(500)

    cfg = ScanConfig(initial_url=server.main_url + "/page2", confirm_authorized=True, allow_http_local=True, headless=True, mode="manual",
                     session_label="userA-owner", output_dir=str(tmp_path / "output"), profile_dir=str(tmp_path / "p"),
                     body=BodyPolicy(mode="selected"))
    scan_dir = await run_scan(cfg, login_prompt=_noop, finish_prompt=user_actions)
    assert scan_dir.name == f"1{host_slug(server.main_url)}"  # e.g. 1127.0.0.1
    assert len([h for h in server.hits if h == ("POST", "/api/echo")]) == posts_before + 1  # exactly the user-driven POST reached the server
    reqs = read_jsonl(scan_dir / "requests.jsonl")
    post = next(r for r in reqs if r["method"] == "POST" and r["url"].endswith("/api/echo"))
    assert post["response_status"] == 200 and post["request_body_reference"].startswith("bodies/req-")
    payload = (scan_dir / post["request_body_reference"]).read_text()
    assert set(json.loads(payload)) == {"title", "password"} and "My CV" in payload and fx.SECRET_PASSWORD not in payload
    pages = read_jsonl(scan_dir / "pages.jsonl")
    assert pages and all(p["discovery_source"] == "manual" for p in pages) and any(p["title"] == "Page 2" for p in pages)
    cov = json.loads((scan_dir / "coverage.json").read_text())
    assert cov["mode"] == "manual" and cov["session_label"] == "userA-owner" and cov["crawl"]["scope_guard_blocks"] == []
    assert "userA-owner" in (scan_dir / "report.md").read_text(encoding="utf-8")
    row = list_scans(tmp_path / "output")[0]
    assert row["mode"] == "manual" and row["session_label"] == "userA-owner" and row["status"] == "completed"
    for p in scan_dir.rglob("*"):
        if p.is_file() and p.suffix in (".json", ".jsonl", ".txt", ".md"):
            assert fx.SECRET_PASSWORD not in p.read_text(encoding="utf-8", errors="replace"), p.name


def test_session_label_must_not_look_like_a_credential_field() -> None:
    with pytest.raises(ValueError):
        ScanConfig(initial_url="https://a.example", session_label="x" * 100)
    with pytest.raises(ValueError):
        ScanConfig(initial_url="https://a.example", session_label="bad;label")
    a = cli.build_parser().parse_args(["scan", "https://a.example", "--manual-session", "--session-label", "userB"])
    cfg = cli._config_from_args(a)
    assert cfg.mode == "manual" and cfg.session_label == "userB"


# ---- initiator chains --------------------------------------------------------------------------------

def test_initiator_chain_parsing() -> None:
    init = {"type": "script", "stack": {"callFrames": [{"functionName": "load", "url": "https://a/app.js", "lineNumber": 9, "columnNumber": 4},
                                                       {"functionName": "", "url": "https://a/vendor.js", "lineNumber": 0, "columnNumber": 0}],
                                        "parent": {"description": "await", "callFrames": [{"functionName": "init", "url": "https://a/main.js",
                                                                                           "lineNumber": 1, "columnNumber": 1}]}}}
    summary, frames = initiator_chain(init)
    assert summary == "script https://a/app.js:10:5"
    assert frames == ["load@https://a/app.js:10:5", "<anonymous>@https://a/vendor.js:1:1", "--- await ---", "init@https://a/main.js:2:2"]
    assert initiator_chain({"type": "parser", "url": "https://a/", "lineNumber": 3}) == ("parser https://a/:4", [])
    assert initiator_chain(None) == (None, [])


@pytest.mark.browser
async def test_initiators_in_requests_and_endpoints(browser: Any, server: Any, tmp_path: Path) -> None:
    d = tmp_path / "ini"
    await collect(browser, server, d)
    exporter.export_scan(d)
    reqs = {r["url"].replace(server.main_url, ""): r for r in read_jsonl(d / "requests.jsonl") if r["url"].startswith(server.main_url)}
    r = reqs["/api/json"]
    assert r["initiator_summary"].startswith("script ") and "/static/app.js" in r["initiator_summary"]
    assert any("/static/app.js" in f for f in r["initiator_frames"])
    assert reqs["/static/app.js"]["initiator_summary"].startswith("parser")  # the script tag in the HTML
    ep = next(e for e in read_jsonl(d / "endpoints.jsonl") if e["normalized_path"] == "/api/json")
    assert ep["initiators"] and "/static/app.js" in ep["initiators"][0]


# ---- every request keeps its own record and a resolvable body reference ------------------------------

@pytest.mark.browser
async def test_deduplicated_bodies_keep_per_request_association(browser: Any, server: Any, tmp_path: Path) -> None:
    d = tmp_path / "dup"
    await collect(browser, server, d, body_mode="selected", path="/dup")
    exporter.export_scan(d)
    recs = [r for r in read_jsonl(d / "requests.jsonl") if "/api/json?i=" in r["url"] or "/api/json?i" in r["url"]]
    assert len(recs) == 8  # one record per request even though the endpoint is identical
    assert len({r["request_id"] for r in recs}) == 8
    refs = [r["response_body_reference"] for r in recs]
    assert sum(1 for x in refs if x and x.startswith("bodies/body-")) == 5
    limited = [x for x in refs if x and x.startswith("endpoint_limit_see:bodies/body-")]
    assert len(limited) == 3 and all((d / x.split(":", 1)[1]).exists() for x in limited)  # points at a real captured body
    assert all(x is not None for x in refs)  # nothing silently without an explanation
    cov = json.loads((d / "coverage.json").read_text())
    assert cov["body_capture"]["capturer"]["duplicates_skipped"] >= 3


# ---- coverage explanations ----------------------------------------------------------------------------

@pytest.mark.browser
async def test_coverage_explains_failures_and_channels(browser: Any, server: Any, tmp_path: Path) -> None:
    d = tmp_path / "cov"
    await collect(browser, server, d)
    exporter.export_scan(d)
    cov = json.loads((d / "coverage.json").read_text())
    assert "connection_refused" in cov["failures_by_class"] and cov["failures_by_class"]["connection_refused"]["examples"]
    assert "cors_blocked" in cov["failures_by_class"]
    ch = cov["observed_channels"]
    assert ch["websockets_cdp"] >= 1 and ch["websockets_playwright"] >= 1 and "dedicated workers" in ch["not_instrumented"]
    assert any("Row Level Security" in l for l in cov["limitations"])
    report = (d / "report.md").read_text(encoding="utf-8")
    assert "Failed requests — connection_refused" in report and "NOT instrumented" in report


def test_failure_classification_unit() -> None:
    def f(reason: str, cors: Any = None) -> RequestRecord:
        return RequestRecord(record_id=reason, scan_id="s", request_id=reason, url="https://x/" + reason, state="failed", failure_reason=reason,
                             cors_error_status=cors)
    res = classify_failures([f("net::ERR_ABORTED"), f("net::ERR_BLOCKED_BY_CLIENT.Inspector"), f("net::ERR_NAME_NOT_RESOLVED"),
                             f("net::ERR_FAILED", {"corsError": "X"}), f("net::ERR_SOMETHING_NEW")])
    assert set(res) == {"aborted", "blocked_by_client", "dns_failure", "cors_blocked", "other"}
    assert "benign" in res["aborted"]["meaning"]


def test_skipped_scope_origins_flags_sibling_subdomains() -> None:
    pages = [{"navigation_status": "skipped_scope", "url": "https://docs.example.com/a"},
             {"navigation_status": "skipped_scope", "url": "https://docs.example.com/b"},
             {"navigation_status": "skipped_scope", "url": "https://twitter.com/x"},
             {"navigation_status": "ok", "url": "https://app.example.com/"}]
    res = skipped_scope_origins(pages, ["https://app.example.com"])
    by = {r["origin"]: r for r in res}
    assert by["https://docs.example.com"]["count"] == 2 and by["https://docs.example.com"]["same_site_as_target"] is True
    assert "--extra-origin https://docs.example.com" in by["https://docs.example.com"]["hint"]
    assert by["https://twitter.com"]["same_site_as_target"] is False and "correctly" in by["https://twitter.com"]["hint"]


def test_server_error_finding_links_captured_error_body() -> None:
    from tests.test_phase5_rules import ORIGIN, rec, run
    r = rec(1, ORIGIN + "/rest/v1/x?id=1", rtype="Fetch", status=500)
    f = next(f for f in run([r], {r.record_id: {"body_id": "body-000009", "status": "captured"}}) if f.rule_id == "API-5XX")
    assert "body:body-000009" in f.evidence_references


# ---- passive comparison of two sessions you control ---------------------------------------------------

def _scan_dir(base: Path, name: str, label: str, rows: list[tuple[str, str, int, str | None]]) -> Path:
    d = base / name
    (d / "bodies").mkdir(parents=True)
    (d / "scan_metadata.json").write_text(json.dumps({"configuration": {"session_label": label}}))
    reqs, eps, seen = [], [], {}
    for i, (method, url, status, body) in enumerate(rows):
        ref = None
        if body is not None:
            ref = f"bodies/body-{i:06d}.txt"
            (d / ref).write_text(body)
        reqs.append({"record_id": f"s/{i}#0", "method": method, "url": url, "response_status": status, "resource_type": "Fetch",
                     "is_preflight": False, "response_body_reference": ref})
        from urllib.parse import urlsplit
        from webaudit.urlnorm import normalize_path
        u = urlsplit(url)
        k = (method, f"{u.scheme}://{u.netloc}", normalize_path(u.path))
        seen.setdefault(k, set()).add(str(status))
    eps = [{"method": k[0], "origin": k[1], "normalized_path": k[2], "status_codes": {s: 1 for s in v}} for k, v in seen.items()]
    (d / "requests.jsonl").write_text("\n".join(json.dumps(r) for r in reqs))
    (d / "endpoints.jsonl").write_text("\n".join(json.dumps(e) for e in eps))
    return d


def test_compare_two_sessions_is_passive_and_flags_shared_objects(tmp_path: Path) -> None:
    api = "https://api.example.net/rest/v1"
    a = _scan_dir(tmp_path, "1a", "userA", [("GET", f"{api}/resumes?id=eq.11", 200, '{"o":"A"}'), ("GET", f"{api}/resumes?id=eq.99", 200, '{"o":"shared"}'),
                                              ("GET", f"{api}/admin_only", 200, None)])
    b = _scan_dir(tmp_path, "2b", "userB", [("GET", f"{api}/resumes?id=eq.22", 200, '{"o":"B"}'), ("GET", f"{api}/resumes?id=eq.99", 200, '{"o":"shared"}'),
                                              ("GET", f"{api}/admin_only", 403, None)])
    res = compare_scans(a, b)
    assert res["a"]["label"] == "userA" and res["b"]["label"] == "userB"
    shared = res["object_urls_both_sessions_read_successfully"]
    assert len(shared) == 1 and shared[0]["request"].endswith("id=eq.99") and shared[0]["body_identical"] is True
    assert res["status_differences"] == [{"endpoint": f"GET https://api.example.net/rest/v1/admin_only", "a": ["200"], "b": ["403"]}]
    md = render_markdown(res)
    assert "no requests were sent" in md and "review manually" in md and "userA" in md
    assert len(res["caveats"]) >= 3
