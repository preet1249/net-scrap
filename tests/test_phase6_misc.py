"""Phase 6: remaining spec scenarios (service worker, slow/large, popup), CLI, and core-module unit tests."""
from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests import fixture_app as fx
from tests.test_phase3_storage import collect, read_jsonl
from tests.test_phase4_crawl import _noop_prompt, scan_cfg
from webaudit import cli, exporter
from webaudit.logging_setup import JsonFormatter, _RedactFilter, setup_logging
from webaudit.redaction import (redact_body, redact_event, redact_header_value, redact_post_data, redact_url, scan_text_for_secrets,
                                sensitive_json_keys)
from webaudit.scan import run_scan
from webaudit.urlnorm import normalize_url, query_names

# ---- redaction ----------------------------------------------------------------------------------


def test_redact_headers_and_urls() -> None:
    assert redact_header_value("Authorization", "Bearer abcdefghijklmnop").startswith("Bearer [REDACTED")
    assert "secretvalue" not in redact_header_value("Cookie", "a=secretvalue; b=other")
    assert redact_header_value("Cookie", "a=secretvalue; b=other").startswith("a=[REDACTED")
    sc = redact_header_value("Set-Cookie", "sid=abc123; Path=/; HttpOnly\npref=zzz; Secure")
    assert "abc123" not in sc and "zzz" not in sc and "HttpOnly" in sc and "Secure" in sc
    assert redact_header_value("Content-Type", "text/html") == "text/html"
    assert redact_header_value("Access-Control-Allow-Credentials", "true") == "true"
    u = redact_url("https://user:pw@h.example/p?token=abc&page=2&sig=zz&x=" + "A" * 40)
    assert "user" not in u and "pw@" not in u and "token=[REDACTED" in u and "page=2" in u and "A" * 40 not in u
    assert redact_url("data:text/plain;base64,AAAA").startswith("data:[REDACTED")


def test_redact_event_deep_and_non_mutating() -> None:
    raw = {"request": {"url": "https://h/x?api_key=k123", "headers": {"Authorization": "Bearer tokentokentoken", "Accept": "*/*"},
                       "postData": '{"password": "p", "name": "n"}'},
           "associatedCookies": [{"cookie": {"name": "s", "value": "cookievalue"}}],
           "payloadData": "frame secret", "headersText": "GET / HTTP/1.1\r\nCookie: a=b\r\nHost: h\r\n"}
    out = redact_event(raw)
    blob = json.dumps(out)
    for s in ("k123", "tokentokentoken", "cookievalue", "frame secret", "a=b"):
        assert s not in blob
    assert json.loads(out["request"]["postData"]).keys() == {"password", "name"}  # names kept, values blanked
    assert raw["request"]["headers"]["Authorization"] == "Bearer tokentokentoken"  # input untouched
    assert redact_post_data("a=1&b=2").startswith("a=[REDACTED")


def test_body_redaction_and_detection() -> None:
    body = json.dumps({"email": fx.SECRET_EMAIL, "nested": {"ssn": fx.SECRET_SSN, "note": f"key {fx.SECRET_AWS}"}, "ok": "fine"})
    red = redact_body(body, "application/json")
    for s in (fx.SECRET_EMAIL, fx.SECRET_SSN, fx.SECRET_AWS):
        assert s not in red
    assert "fine" in red
    types = {c["type"] for c in scan_text_for_secrets(f"x = '{fx.SECRET_JWT}'; k='{fx.SECRET_AWS}'; -----BEGIN RSA PRIVATE KEY-----")}
    assert {"jwt", "aws_access_key_id", "private_key_block"} <= types
    assert sensitive_json_keys(body) == ["email", "ssn"]
    assert all("redacted_sample" in c and fx.SECRET_AWS not in json.dumps(c) for c in scan_text_for_secrets(fx.SECRET_AWS))


def test_urlnorm() -> None:
    assert normalize_url("https://h.example/api/users/42/orders/550e8400-e29b-41d4-a716-446655440000?token=x") == \
        "https://h.example/api/users/{id}/orders/{uuid}"
    assert normalize_url("https://h.example/a/deadbeefdeadbeefdead") == "https://h.example/a/{hex}"
    assert query_names("https://h/x?b=1&a=2&b=3") == ["a", "b"]


def test_logging_is_structured_and_redacts(capsys: Any) -> None:
    setup_logging("INFO")
    logging.getLogger("webaudit.test").info("Authorization: Bearer abc123 and password=hunter2", extra={"ctx": {"k": 1}})
    err = capsys.readouterr().err
    line = json.loads(err.strip().splitlines()[-1])
    assert line["level"] == "INFO" and line["k"] == 1
    assert "abc123" not in err and "hunter2" not in err and "[REDACTED]" in err


# ---- scenarios ----------------------------------------------------------------------------------

@pytest.mark.browser
async def test_slow_and_large_responses_are_observed(browser: Any, server: Any, tmp_path: Path) -> None:
    d = tmp_path / "sl"
    await collect(browser, server, d)
    exporter.export_scan(d)
    reqs = {r["url"].replace(server.main_url, ""): r for r in read_jsonl(d / "requests.jsonl") if r["url"].startswith(server.main_url)}
    assert reqs["/api/slow"]["timing"]["duration_ms"] >= 900
    assert reqs["/api/large"]["timing"]["encoded_data_length"] >= 2_000_000
    assert reqs["/api/large"]["state"] == "finished"
    ws = [json.loads(l) for l in (d / "network_events.jsonl").read_text().splitlines()]
    types = {e["event_type"] for e in ws}
    assert {"Network.webSocketCreated", "Network.webSocketFrameSent", "Network.webSocketFrameReceived", "Network.webSocketClosed",
            "pw.websocket_created"} <= types
    assert any(e["event_type"] == "Network.webSocketFrameSent" and "REDACTED" in json.dumps(e["raw_event"]) for e in ws)  # payloads redacted


@pytest.mark.browser
async def test_service_worker_scenario_and_documented_coverage_gap(browser: Any, server: Any, tmp_path: Path) -> None:
    from tests.test_phase3_storage import make_config
    from webaudit.config import BodyPolicy
    from webaudit.session import CollectionSession
    d = tmp_path / "sw"
    cfg = make_config(server, d, body=BodyPolicy(mode="none"))
    sess = CollectionSession(cfg, d, "scan-sw")
    ctx = await browser.new_context()
    await sess.open(ctx)
    page = await ctx.new_page()
    await sess.arm_page(page)
    await page.goto(server.main_url + "/sw-page")
    await page.wait_for_function("document.title.startsWith('SW ready')", timeout=20_000)
    title = await page.title()
    await sess.close()
    await ctx.close()
    assert title == "SW ready sw"  # response came from the service worker, not the network
    events = list(sess.db.iter_events()) if False else None
    from webaudit.event_store.sqlite import SqliteEventStore
    db = SqliteEventStore(d / "scan.sqlite")
    evs = list(db.iter_events())
    db.close()
    types = {e.event_type for e in evs}
    assert "pw.serviceworker" in types  # Playwright reports the worker target
    sw_resp = [e for e in evs if e.event_type == "Network.responseReceived" and e.raw_event["response"]["url"].endswith("/sw-data")]
    assert sw_resp and sw_resp[0].raw_event["response"].get("fromServiceWorker") is True
    # the worker's own network traffic (its script fetch) is not covered by the page-level CDP session: documented, not hidden
    diag = sess.cdp.diagnostics()  # type: ignore[union-attr]
    assert "workers" in diag["coverage_note"]
    manifest = exporter.export_scan(d)
    assert any("workers" in l for l in manifest["coverage_limitations"])


@pytest.mark.browser
async def test_popup_traffic_is_captured_after_arming(browser: Any, server: Any, tmp_path: Path) -> None:
    from tests.test_phase3_storage import make_config
    from webaudit.config import BodyPolicy
    from webaudit.event_store.sqlite import SqliteEventStore
    from webaudit.session import CollectionSession
    d = tmp_path / "pop"
    sess = CollectionSession(make_config(server, d, body=BodyPolicy(mode="none")), d, "scan-pop")
    ctx = await browser.new_context()
    await sess.open(ctx)
    page = await ctx.new_page()
    await sess.arm_page(page)
    await page.goto(server.main_url + "/popup-opener")
    await page.wait_for_timeout(1500)
    await sess.close()
    await ctx.close()
    db = SqliteEventStore(d / "scan.sqlite")
    evs = list(db.iter_events())
    db.close()
    assert any(e.event_type == "pw.popup" for e in evs) and any(e.event_type == "collector.late_attach" for e in evs)
    # Playwright (context-level) sees the popup's requests from the start...
    assert any(e.event_type == "pw.request" and e.raw_event["url"].endswith("/popup") for e in evs)
    # ...while the CDP session for the popup is attached only after the browser announces the page (documented gap):
    assert sum(1 for e in evs if e.event_type == "collector.cdp_attached") >= 2


# ---- CLI ----------------------------------------------------------------------------------------

def test_cli_requires_confirmation_non_interactive(tmp_path: Path) -> None:
    r = subprocess.run([sys.executable, "-W", "ignore", "-m", "webaudit", "scan", "https://app.example.com/dash",
                        "--output-dir", str(tmp_path)], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                       env={**__import__("os").environ, "PYTHONPATH": "src"})
    assert r.returncode != 0 and "authorization not confirmed" in r.stderr
    assert not (tmp_path / "scans").exists()


def test_cli_rejects_http_and_credential_args(tmp_path: Path) -> None:
    rc = cli.main(["scan", "http://app.example.com/", "--confirm-authorized", "--output-dir", str(tmp_path)])
    assert rc == 2
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["scan", "https://a.example", "--password", "x"])


@pytest.mark.browser
async def test_cli_list_export_diagnostics(server: Any, tmp_path: Path, capsys: Any) -> None:
    cfg = scan_cfg(server, tmp_path)
    scan_dir = await run_scan(cfg.model_copy(update={"crawl": cfg.crawl.model_copy(update={"max_pages": 2})}), login_prompt=_noop_prompt)
    out_dir = str(tmp_path / "out")
    assert cli.main(["list", "--output-dir", out_dir]) == 0
    assert scan_dir.name in capsys.readouterr().out
    (scan_dir / "report.md").unlink()
    assert cli.main(["export", scan_dir.name, "--output-dir", out_dir]) == 0
    assert (scan_dir / "report.md").exists()
    capsys.readouterr()
    assert cli.main(["diagnostics", scan_dir.name, "--output-dir", out_dir]) == 0
    diag = json.loads(capsys.readouterr().out)
    assert diag["status"] == "completed" and diag["events_persisted"] > 20
    assert diag["diagnostics"]["queue"]["dropped"] == 0
    assert "Authorization" not in json.dumps(diag)


def test_example_config_is_valid_and_cli_merges_overrides() -> None:
    from webaudit.config import load_config
    root = Path(__file__).resolve().parents[1]
    cfg = load_config(root / "config.example.toml")
    assert cfg.initial_url.startswith("https://") and cfg.body.mode == "none" and cfg.scope_enforcement == "guard"
    a = cli.build_parser().parse_args(["scan", "--config", str(root / "config.example.toml"), "--confirm-authorized", "--max-pages", "5",
                                       "--body-mode", "selected", "--allow-post-path", "/graphql"])
    merged = cli._config_from_args(a)
    assert merged.crawl.max_pages == 5 and merged.body.mode == "selected" and merged.allow_unsafe_method_paths == ["/graphql"]
    assert merged.confirm_authorized and merged.crawl.max_depth == 3  # untouched values come from the file
