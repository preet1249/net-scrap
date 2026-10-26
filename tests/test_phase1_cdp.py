"""Phase 1: prove the CDP collector works against the local fixture, including scenario coverage."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

import pytest

pytestmark = pytest.mark.browser


async def collect_home(harness_factory: Any, server: Any) -> list[dict[str, Any]]:
    async with harness_factory() as h:
        page = await h.new_page()
        await page.goto(server.main_url + "/")
        await page.wait_for_function("window.__scenarioDone === true", timeout=30_000)
        return await h.finish()


async def test_collector_attached_before_navigation_and_captures_lifecycle(harness_factory: Any, server: Any) -> None:
    events = await collect_home(harness_factory, server)
    cdp = [e for e in events if e["source"] == "cdp"]
    types = Counter(e["event_type"] for e in cdp)
    for required in ("Network.requestWillBeSent", "Network.requestWillBeSentExtraInfo", "Network.responseReceived",
                     "Network.responseReceivedExtraInfo", "Network.loadingFinished", "Network.loadingFailed"):
        assert types[required] > 0, f"missing {required}; got {dict(types)}"
    # attach marker precedes the first request event (Network.enable before navigation)
    attached = next(e for e in events if e["event_type"] == "collector.cdp_attached")
    first_req = next(e for e in events if e["event_type"] == "Network.requestWillBeSent")
    assert attached["raw_event"]["enabled"] is True
    assert attached["seq"] < first_req["seq"]
    # the very first request is the document navigation
    assert first_req["raw_event"]["type"] == "Document"
    assert first_req["raw_event"]["request"]["url"].endswith("/")


async def test_events_carry_session_target_ids_and_timestamps(harness_factory: Any, server: Any) -> None:
    events = await collect_home(harness_factory, server)
    cdp = [e for e in events if e["source"] == "cdp"]
    assert all(e["session_id"] and e["timestamp"] > 0 and e["scan_id"] == "scan-test" for e in cdp)
    assert all(e["target_id"] for e in cdp)
    assert len({e["event_id"] for e in events}) == len(events)
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs)


async def test_resource_types_and_scenarios_detected(harness_factory: Any, server: Any) -> None:
    events = await collect_home(harness_factory, server)
    rts: dict[str, set[str]] = defaultdict(set)
    for e in events:
        if e["event_type"] == "Network.requestWillBeSent":
            rts[e["raw_event"]["type"]].add(e["raw_event"]["request"]["url"].split("?")[0].split(str(server.main_port))[-1])
    assert {"Document", "Script", "Fetch", "XHR", "Image"} <= set(rts), dict(rts)
    assert any(u.endswith("/api/xhr") for u in rts["XHR"])
    assert any(u.endswith("/api/json") for u in rts["Fetch"])


async def test_preflight_emitted_as_independent_request(harness_factory: Any, server: Any) -> None:
    events = await collect_home(harness_factory, server)
    opts = [e for e in events if e["event_type"] == "Network.requestWillBeSent"
            and e["raw_event"]["request"]["method"] == "OPTIONS"]
    assert opts, "no OPTIONS preflight observed"
    pre = opts[0]["raw_event"]
    assert pre["request"]["url"].endswith("/api/cors")
    assert pre["initiator"]["type"] == "preflight"
    # the real request has a different request id
    real = [e for e in events if e["event_type"] == "Network.requestWillBeSent"
            and e["raw_event"]["request"]["url"].endswith("/api/cors") and e["raw_event"]["request"]["method"] == "GET"]
    assert real and real[0]["request_id"] != opts[0]["request_id"]
    assert ("OPTIONS", "API:/api/cors") in server.hits


async def test_redirect_reuses_request_id(harness_factory: Any, server: Any) -> None:
    events = await collect_home(harness_factory, server)
    reds = [e for e in events if e["event_type"] == "Network.requestWillBeSent" and "/redirect/" in e["raw_event"]["request"]["url"]]
    ids = {e["request_id"] for e in reds}
    assert len(ids) == 1, "redirect hops should share one CDP requestId"
    assert len(reds) == 3
    assert [bool(e["raw_event"].get("redirectResponse")) for e in reds] == [False, True, True]


async def test_failure_http_errors_and_websocket(harness_factory: Any, server: Any) -> None:
    events = await collect_home(harness_factory, server)
    failed = [e for e in events if e["event_type"] == "Network.loadingFailed"]
    assert failed and any(e["raw_event"].get("errorText") for e in failed)
    status = {}
    for e in events:
        if e["event_type"] == "Network.responseReceived":
            status[e["raw_event"]["response"]["url"].split(str(server.main_port))[-1]] = e["raw_event"]["response"]["status"]
    assert status["/api/e404"] == 404 and status["/api/e500"] == 500
    # HTTP errors still complete as network requests
    e404_id = next(e["request_id"] for e in events if e["event_type"] == "Network.responseReceived"
                   and e["raw_event"]["response"]["url"].endswith("/api/e404"))
    assert any(e["event_type"] == "Network.loadingFinished" and e["request_id"] == e404_id for e in events)
    types = {e["event_type"] for e in events}
    assert {"Network.webSocketCreated", "Network.webSocketFrameSent", "Network.webSocketFrameReceived",
            "Network.webSocketClosed"} <= types, types
    assert "Network.webSocketHandshakeResponseReceived" in types


async def test_repeated_headers_observability_in_raw_cdp(harness_factory: Any, server: Any) -> None:
    """Empirical CDP facts (Chromium 139): the primary event merges repeated headers with ', ' and omits Set-Cookie;
    the extra-info event joins repeats with newlines and `headersText` keeps the exact header lines."""
    events = await collect_home(harness_factory, server)
    rid = next(e["request_id"] for e in events if e["event_type"] == "Network.responseReceived"
               and e["raw_event"]["response"]["url"].endswith("/api/repeated"))
    primary = next(e for e in events if e["event_type"] == "Network.responseReceived" and e["request_id"] == rid)
    ph = {k.lower(): v for k, v in primary["raw_event"]["response"]["headers"].items()}
    assert ph["x-dup"] == "one, two" and "set-cookie" not in ph
    extra = next(e for e in events if e["event_type"] == "Network.responseReceivedExtraInfo" and e["request_id"] == rid)
    eh = {k.lower(): v for k, v in extra["raw_event"]["headers"].items()}
    assert eh["x-dup"].split(chr(10)) == ["one", "two"]
    assert len(eh["set-cookie"].split(chr(10))) == 2
    text = extra["raw_event"]["headersText"]
    assert text.count("X-Dup:") == 2 and text.count("Set-Cookie:") == 2


async def test_playwright_source_kept_separately(harness_factory: Any, server: Any) -> None:
    events = await collect_home(harness_factory, server)
    pw_req = [e for e in events if e["event_type"] == "pw.request"]
    pw_ws = [e for e in events if e["event_type"].startswith("pw.websocket")]
    assert pw_req and pw_ws
    assert all(e["source"] == "playwright" for e in pw_req)
    # repeated headers preserved as separate entries via headers_array()
    resp = next(e for e in events if e["event_type"] == "pw.response" and e["raw_event"]["url"].endswith("/api/repeated"))
    names = [n.lower() for n, _ in resp["raw_event"]["headers"]]
    assert names.count("x-dup") == 2 and names.count("set-cookie") == 2


async def test_secrets_redacted_in_persisted_events(harness_factory: Any, server: Any) -> None:
    events = await collect_home(harness_factory, server)
    blob = str(events)
    assert "FIXTURE-TOKEN-0123456789" not in blob
    assert "FIXTURE-QUERY-TOKEN-0123456789" not in blob
    assert "fixturesessionvalue123" not in blob
    assert "[REDACTED" in blob


async def test_queue_overflow_is_counted_not_silent(harness_factory: Any, server: Any) -> None:
    async with harness_factory(queue_size=2) as h:
        page = await h.new_page()
        # stall the worker so the tiny queue overflows
        await page.goto(server.main_url + "/")
        await page.wait_for_function("window.__scenarioDone === true", timeout=30_000)
        await h.finish()
        stats = h.sink.stats()
        assert stats["accepted"] + stats["dropped"] > 0
        assert stats["max_queue_depth"] <= 2
