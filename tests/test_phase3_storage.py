"""Phase 3: SQLite + JSONL persistence, schema validation, checksums, bounded opt-in body capture, interrupted-scan export."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from tests import fixture_app as fx
from webaudit import exporter
from webaudit.config import BodyPolicy, ScanConfig
from webaudit.event_store import EventSink
from webaudit.event_store.sqlite import SqliteEventStore
from webaudit.instrumentation.bodies import BodyCapturer, eligible
from webaudit.models import SCHEMA_VERSION, NetworkEvent, RequestRecord, ScanMetadata
from webaudit.session import CollectionSession


def make_config(server: Any, tmp: Path, **kw: Any) -> ScanConfig:
    return ScanConfig(initial_url=server.main_url + "/", confirm_authorized=True, allow_http_local=True,
                      output_dir=str(tmp), **kw)


def read_jsonl(p: Path) -> list[dict[str, Any]]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


async def collect(browser: Any, server: Any, scan_dir: Path, *, body_mode: str = "none", close: bool = True, path: str = "/",
                  **body_kw: Any) -> CollectionSession:
    cfg = make_config(server, scan_dir, body=BodyPolicy(mode=body_mode, **body_kw))
    sess = CollectionSession(cfg, scan_dir, "scan-p3")
    ctx = await browser.new_context()
    await sess.open(ctx)
    page = await ctx.new_page()
    await sess.arm_page(page)
    meta = ScanMetadata(scan_id="scan-p3", started_at="2026-01-01T00:00:00Z", initial_url=cfg.initial_url,
                        allowed_origins=cfg.allowed_origins, configuration=cfg.public_dict())
    sess.db.set_meta("scan_metadata", meta.model_dump(mode="json"))
    await page.goto(server.main_url + path)
    await page.wait_for_function("window.__scenarioDone === true", timeout=30_000)
    if close:
        await sess.close()
        await ctx.close()
    else:
        await sess.sink.queue.join()  # events persisted, but no graceful shutdown
        sess._ctx_for_cleanup = ctx  # type: ignore[attr-defined]
    return sess


# ---- sqlite unit -----------------------------------------------------------------------------

def _ev(i: int, t: str = "Network.requestWillBeSent") -> NetworkEvent:
    return NetworkEvent(event_id=f"evt-{i}", scan_id="s", seq=i, timestamp=float(i), source="cdp", target_id="T", session_id="cdp-1",
                        request_id=str(i), event_type=t, raw_event={"requestId": str(i), "n": i})


def test_sqlite_roundtrip_order_and_idempotent_insert(tmp_path: Path) -> None:
    db = SqliteEventStore(tmp_path / "scan.sqlite")
    db.append_events([_ev(3), _ev(1), _ev(2)])
    db.append_events([_ev(2)])  # duplicate ignored (immutable)
    assert db.event_count() == 3
    assert [e.seq for e in db.iter_events()] == [1, 2, 3]
    db.set_meta("k", {"a": 1})
    assert db.get_meta("k") == {"a": 1} and db.get_meta("missing", 5) == 5
    db.close()
    db2 = SqliteEventStore(tmp_path / "scan.sqlite")  # reopen: durable
    assert db2.event_count() == 3
    db2.close()


def test_schema_models_are_versioned_and_strict() -> None:
    assert _ev(1).schema_version == SCHEMA_VERSION
    with pytest.raises(Exception):
        NetworkEvent.model_validate({**_ev(1).model_dump(), "unexpected": 1})
    with pytest.raises(Exception):
        RequestRecord.model_validate({"record_id": "x", "scan_id": "s", "request_id": "1", "bogus": True})


# ---- body policy / capture units ---------------------------------------------------------------

def test_body_eligibility_rules() -> None:
    none, sel, allp = BodyPolicy(mode="none"), BodyPolicy(mode="selected"), BodyPolicy(mode="all_supported")
    assert eligible(none, "XHR", "application/json", 200)[0] is False
    assert eligible(sel, "Fetch", "application/json", 200)[0] is True
    assert eligible(sel, "Image", "image/png", 200) == (False, "skipped_binary_or_unknown_type")
    assert eligible(sel, "Stylesheet", "text/css", 200)[0] is False
    assert eligible(allp, "Stylesheet", "text/css", 200)[0] is True
    assert eligible(allp, "Fetch", "application/octet-stream", 200)[0] is False
    assert eligible(allp, "Font", "font/woff2", 200)[0] is False
    assert eligible(allp, "Fetch", "application/json", 204)[0] is False
    assert eligible(allp, "Document", "text/html", 302)[0] is False


class _Att:
    label, target_id = "cdp-1", "T"

    def __init__(self, behaviour: Any) -> None:
        self.session = self
        self.behaviour = behaviour
        self.calls: list[str] = []

    async def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(params["requestId"])
        res = self.behaviour(params["requestId"])
        if isinstance(res, Exception):
            raise res
        return res


def _drive(cap: BodyCapturer, att: _Att, rid: str, *, mime: str = "application/json", rtype: str = "Fetch", status: int = 200,
           fail: bool = False, finish: bool = True, clen: int | None = None) -> None:
    headers = {"Content-Length": str(clen)} if clen is not None else {}
    cap.observe("Network.responseReceived", {"requestId": rid, "type": rtype,
                                             "response": {"url": f"http://h/{rid}", "status": status, "mimeType": mime, "headers": headers}}, att)
    if fail:
        cap.observe("Network.loadingFailed", {"requestId": rid}, att)
    elif finish:
        cap.observe("Network.loadingFinished", {"requestId": rid, "encodedDataLength": clen or 10}, att)


async def _run_cap(policy: BodyPolicy, tmp: Path, drives: Any, behaviour: Any) -> tuple[list[dict[str, Any]], _Att]:
    sink = EventSink(100)
    cap = BodyCapturer(sink, tmp, policy)
    att = _Att(behaviour)
    cap.start()
    drives(cap, att)
    await cap.stop()
    out = []
    while not sink.queue.empty():
        item = sink.queue.get_nowait()
        if item is not None:
            out.append({"type": item.event_type, **item.raw_event})
    return out, att


async def test_body_retrieval_failure_is_recorded(tmp_path: Path) -> None:
    ev, att = await _run_cap(BodyPolicy(mode="all_supported"), tmp_path, lambda c, a: _drive(c, a, "1"),
                             lambda rid: RuntimeError("No resource with given identifier found"))
    assert [e["status"] for e in ev] == ["unavailable"] and "No resource" in ev[0]["error"]


async def test_no_body_fetch_for_failed_or_unfinished_or_policy_none(tmp_path: Path) -> None:
    def drives(c: BodyCapturer, a: _Att) -> None:
        _drive(c, a, "failed", fail=True)
        _drive(c, a, "unfinished", finish=False)
    ev, att = await _run_cap(BodyPolicy(mode="all_supported"), tmp_path, drives, lambda rid: {"body": "x", "base64Encoded": False})
    assert att.calls == [] and ev == []
    ev2, att2 = await _run_cap(BodyPolicy(mode="none"), tmp_path, lambda c, a: _drive(c, a, "1"), lambda rid: {"body": "x"})
    assert att2.calls == [] and ev2 == []  # nothing recorded, nothing fetched


async def test_truncation_counts_bytes_not_characters(tmp_path: Path) -> None:
    body = "é" * 100  # 100 chars, 200 bytes
    ev, _ = await _run_cap(BodyPolicy(mode="all_supported", max_body_bytes=50), tmp_path, lambda c, a: _drive(c, a, "1", mime="text/plain"),
                           lambda rid: {"body": body, "base64Encoded": False})
    assert ev[0]["status"] == "truncated" and ev[0]["size"] == 200 and ev[0]["stored_bytes"] <= 60


async def test_total_and_origin_budgets(tmp_path: Path) -> None:
    def drives(c: BodyCapturer, a: _Att) -> None:
        for i in range(4):
            _drive(c, a, str(i))
    ev, att = await _run_cap(BodyPolicy(mode="all_supported", max_total_bytes=30), tmp_path, drives,
                             lambda rid: {"body": json.dumps({"k": "v" * 20}), "base64Encoded": False})
    statuses = [e["status"] for e in ev]
    assert statuses[0] == "captured" and "skipped_total_budget" in statuses


async def test_secrets_redacted_in_stored_body_but_candidates_reported(tmp_path: Path) -> None:
    body = json.dumps({"user": {"email": fx.SECRET_EMAIL, "ssn": fx.SECRET_SSN}, "password": fx.SECRET_PASSWORD,
                       "note": f"key {fx.SECRET_AWS}", "token": fx.SECRET_JWT})
    ev, _ = await _run_cap(BodyPolicy(mode="selected"), tmp_path, lambda c, a: _drive(c, a, "1"),
                           lambda rid: {"body": body, "base64Encoded": False})
    stored = (tmp_path / ev[0]["path"]).read_text(encoding="utf-8")
    for s in (fx.SECRET_EMAIL, fx.SECRET_SSN, fx.SECRET_PASSWORD, fx.SECRET_AWS, fx.SECRET_JWT):
        assert s not in stored and s not in json.dumps(ev)
    assert "[REDACTED" in stored
    assert {"aws_access_key_id", "jwt"} <= {c["type"] for c in ev[0]["secret_candidates"]}
    assert {"email", "ssn", "password", "token"} <= set(ev[0]["sensitive_keys"])
    assert not (tmp_path / "bodies_raw").exists()  # raw only on explicit opt-in


async def test_raw_body_stored_only_on_opt_in(tmp_path: Path) -> None:
    ev, _ = await _run_cap(BodyPolicy(mode="selected", store_raw=True), tmp_path, lambda c, a: _drive(c, a, "1"),
                           lambda rid: {"body": '{"password": "abc"}', "base64Encoded": False})
    assert (tmp_path / ev[0]["raw_path"]).read_text() == '{"password": "abc"}'


# ---- integration: real browser -> sqlite/jsonl -> export bundle ----------------------------------

@pytest.mark.browser
async def test_session_persists_to_sqlite_and_live_jsonl(browser: Any, server: Any, tmp_path: Path) -> None:
    sess = await collect(browser, server, tmp_path / "s1")
    db = SqliteEventStore(tmp_path / "s1" / "scan.sqlite")
    n_db = db.event_count()
    db.close()
    live = read_jsonl(tmp_path / "s1" / "network_events.live.jsonl")
    assert n_db == len(live) > 50
    for line in live:
        NetworkEvent.model_validate(line)  # schema validation of every persisted line
    q = sess.worker.diagnostics()
    assert q["dropped"] == 0 and q["errors"] == [], q


@pytest.mark.browser
async def test_export_bundle_files_checksums_and_no_secrets(browser: Any, server: Any, tmp_path: Path) -> None:
    d = tmp_path / "s2"
    await collect(browser, server, d, body_mode="selected", max_body_bytes=100_000)
    manifest = exporter.export_scan(d)
    assert manifest["completion_status"] == "completed"
    for name in ("network_events.jsonl", "requests.jsonl", "endpoints.jsonl", "pages.jsonl", "coverage.json", "findings.json",
                 "scan_metadata.json"):
        assert name in manifest["files"], name
        p = d / name
        assert hashlib.sha256(p.read_bytes()).hexdigest() == manifest["files"][name]["sha256"]
        assert p.stat().st_size == manifest["files"][name]["bytes"]
    reqs = read_jsonl(d / "requests.jsonl")
    assert manifest["files"]["requests.jsonl"]["records"] == len(reqs)
    for r in reqs:
        RequestRecord.model_validate(r)
    # endpoint inventory has normalized paths and no query values
    eps = read_jsonl(d / "endpoints.jsonl")
    sens = next(e for e in eps if e["normalized_path"] == "/api/sensitive")
    assert sens["query_param_names"] == ["page", "token"]
    assert "FIXTURE-QUERY-TOKEN" not in json.dumps(eps)
    # bodies: JSON captured & redacted; binary/large skipped
    bodies = sorted((d / "bodies").glob("*.txt"))
    assert bodies
    blob = "".join(p.read_text(encoding="utf-8") for p in bodies)
    for s in (fx.SECRET_EMAIL, fx.SECRET_SSN, fx.SECRET_PASSWORD, fx.SECRET_AWS, fx.SECRET_JWT, fx.SECRET_API_KEY):
        assert s not in blob
    statuses = manifest and json.loads((d / "coverage.json").read_text())["body_capture"]["statuses"]
    assert statuses.get("captured", 0) >= 3
    large = next(r for r in reqs if r["url"].endswith("/api/large"))
    assert large["response_body_reference"] == "not_captured:skipped_binary_or_unknown_type"
    # nothing sensitive anywhere in the exported bundle
    for p in d.rglob("*"):
        if p.is_file() and p.suffix in (".json", ".jsonl", ".txt") and p.name != "scan.sqlite":
            t = p.read_text(encoding="utf-8", errors="replace")
            for s in (fx.SECRET_EMAIL, fx.SECRET_SSN, fx.SECRET_PASSWORD, fx.SECRET_AWS, fx.SECRET_JWT, fx.SECRET_API_KEY,
                      "FIXTURE-TOKEN-0123456789", "fixturesessionvalue123"):
                assert s not in t, f"{s} leaked into {p.name}"
    # body references attached to the right records
    sensitive = next(r for r in reqs if "/api/sensitive" in r["url"])
    assert sensitive["response_body_reference"].startswith("bodies/")


@pytest.mark.browser
async def test_body_mode_none_creates_no_body_artifacts(browser: Any, server: Any, tmp_path: Path) -> None:
    d = tmp_path / "s3"
    await collect(browser, server, d, body_mode="none")
    exporter.export_scan(d)
    assert not (d / "bodies").exists()
    assert all(r["response_body_reference"] is None for r in read_jsonl(d / "requests.jsonl"))


@pytest.mark.browser
async def test_interrupted_scan_is_identified_and_exportable(browser: Any, server: Any, tmp_path: Path, monkeypatch: Any) -> None:
    d = tmp_path / "s4"
    sess = await collect(browser, server, d, close=False)  # no graceful close: simulates a crash after flush
    monkeypatch.setattr(exporter, "STALE_AFTER_S", 0.0)
    await asyncio.sleep(0.05)
    assert exporter.detect_status(d) == "interrupted"
    manifest = exporter.export_scan(d)
    assert manifest["completion_status"] == "interrupted"
    reqs = read_jsonl(d / "requests.jsonl")
    assert len(reqs) > 20
    assert json.loads((d / "scan_metadata.json").read_text())["completion_status"] == "interrupted"
    await sess.close()  # tidy up
    await sess._ctx_for_cleanup.close()  # type: ignore[attr-defined]
    assert exporter.detect_status(d) == "completed"


# ---- request payloads, vendor JSON, dedupe, budgets ---------------------------------------------------

async def test_vendor_json_is_treated_as_text() -> None:
    from webaudit.instrumentation.bodies import _is_textual
    assert _is_textual("application/vnd.pgrst.object+json") and _is_textual("application/problem+json; charset=utf-8")
    assert not _is_textual("application/vnd.ms-excel") and not _is_textual("image/png")


async def test_static_assets_deduped_but_api_not_starved(tmp_path: Path) -> None:
    def drives(c: BodyCapturer, a: _Att) -> None:
        for i in range(6):  # same bundle fetched on 6 pages
            c.observe("Network.responseReceived", {"requestId": f"s{i}", "type": "Script", "response": {
                "url": "http://h/assets/app.js", "status": 200, "mimeType": "application/javascript", "headers": {}}}, a)
            c.observe("Network.loadingFinished", {"requestId": f"s{i}", "encodedDataLength": 10}, a)
        for i in range(8):  # same API endpoint, different ids -> normalized endpoint, limited to a few
            c.observe("Network.responseReceived", {"requestId": f"a{i}", "type": "Fetch", "response": {
                "url": f"http://h/api/items/{i}", "status": 200, "mimeType": "application/json", "headers": {}}}, a)
            c.observe("Network.loadingFinished", {"requestId": f"a{i}", "encodedDataLength": 10}, a)
    big = "x" * 400
    ev, att = await _run_cap(BodyPolicy(mode="selected", per_origin_bytes=300, max_body_bytes=1000), tmp_path, drives,
                             lambda rid: {"body": big if rid.startswith("s") else '{"k": "v"}', "base64Encoded": False})
    by = [(e["resource_type"], e["status"]) for e in ev]
    assert by.count(("Script", "captured")) == 1  # one capture per static URL
    assert by.count(("Fetch", "captured")) == 5  # API budget independent of the exhausted asset budget; per-endpoint cap
    assert len(att.calls) == 6


async def test_debug_indicators_not_scanned_in_scripts(tmp_path: Path) -> None:
    body = "function f(){ /* Traceback (most recent call last) */ var debug = true; }"
    ev, _ = await _run_cap(BodyPolicy(mode="selected"), tmp_path,
                           lambda c, a: _drive(c, a, "1", mime="application/javascript", rtype="Script"),
                           lambda rid: {"body": body, "base64Encoded": False})
    assert ev[0]["debug_indicators"] == []
    ev2, _ = await _run_cap(BodyPolicy(mode="selected"), tmp_path, lambda c, a: _drive(c, a, "1", mime="application/json", rtype="Fetch"),
                            lambda rid: {"body": '{"err": "Traceback (most recent call last)"}', "base64Encoded": False})
    assert ev2[0]["debug_indicators"] == ["python_traceback"]


async def test_request_payload_capture_unit(tmp_path: Path) -> None:
    def drives(c: BodyCapturer, a: _Att) -> None:
        c.observe("Network.requestWillBeSent", {"requestId": "p1", "type": "Fetch", "request": {
            "url": "http://h/api", "method": "POST", "headers": {"Content-Type": "application/json"},
            "postData": json.dumps({"email": fx.SECRET_EMAIL, "password": fx.SECRET_PASSWORD, "title": "ok"}), "hasPostData": True}}, a)
        c.observe("Network.requestWillBeSent", {"requestId": "p2", "type": "Fetch", "request": {  # large body: must be fetched via protocol
            "url": "http://h/api2", "method": "PUT", "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "hasPostData": True}}, a)
        c.observe("Network.requestWillBeSent", {"requestId": "p3", "type": "Fetch", "request": {
            "url": "http://h/up", "method": "POST", "headers": {"Content-Type": "image/png"}, "hasPostData": True}}, a)
        c.observe("Network.requestWillBeSent", {"requestId": "g1", "type": "Fetch", "request": {"url": "http://h/g", "method": "GET", "headers": {}}}, a)

    class Att2(_Att):
        async def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            assert method == "Network.getRequestPostData" and params["requestId"] == "p2"
            return {"postData": "token=" + "z" * 30 + "&q=search"}
    sink = EventSink(50)
    cap = BodyCapturer(sink, tmp_path, BodyPolicy(mode="selected"))
    att = Att2(lambda rid: {})
    cap.start()
    drives(cap, att)
    await cap.stop()
    evs = []
    while not sink.queue.empty():
        it = sink.queue.get_nowait()
        if it:
            evs.append((it.event_type, it.request_id, it.raw_event))
    assert [e[1] for e in evs] == ["p1", "p2", "p3"]  # GET without payload produces nothing
    assert all(e[0] == "collector.request_body" for e in evs)
    p1, p2, p3 = (e[2] for e in evs)
    stored = (tmp_path / p1["path"]).read_text()
    assert json.loads(stored).keys() == {"email", "password", "title"} and "ok" in stored
    assert fx.SECRET_EMAIL not in stored and fx.SECRET_PASSWORD not in stored
    assert p2["status"] == "captured" and "zzzz" not in (tmp_path / p2["path"]).read_text() and "q=" in (tmp_path / p2["path"]).read_text()
    assert p3["status"] == "skipped_binary_or_unknown_type"


@pytest.mark.browser
async def test_request_payload_and_vendor_json_end_to_end(browser: Any, server: Any, tmp_path: Path) -> None:
    d = tmp_path / "rb"
    await collect(browser, server, d, body_mode="selected")
    exporter.export_scan(d)
    reqs = {r["url"].replace(server.main_url, ""): r for r in read_jsonl(d / "requests.jsonl") if r["url"].startswith(server.main_url)}
    echo = reqs["/api/echo"]
    assert echo["request_body_reference"].startswith("bodies/req-")
    payload = json.loads((d / echo["request_body_reference"]).read_text())
    assert set(payload) == {"name", "password", "note"} and fx.SECRET_PASSWORD not in json.dumps(payload) and payload["name"] == "x"
    assert reqs["/api/vnd"]["response_body_reference"].startswith("bodies/body-")  # vnd+json captured, not skipped as binary
    cov = json.loads((d / "coverage.json").read_text())
    assert cov["body_capture"]["request_body_statuses"].get("captured", 0) >= 1
    assert "unsupported_or_partial_targets" in cov and cov["unsupported_or_partial_targets"]["cdp_sessions"] >= 1
    assert "capturer" in cov["body_capture"]
    for p in d.rglob("*"):
        if p.is_file() and p.suffix in (".json", ".jsonl", ".txt", ".md"):
            assert fx.SECRET_PASSWORD not in p.read_text(encoding="utf-8", errors="replace"), p.name
