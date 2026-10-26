"""Phase 2: correlation state machine — synthetic edge cases (offline, no browser) + integration against the fixture."""
from __future__ import annotations

import itertools
from typing import Any

import pytest

from webaudit.correlation import Correlator, correlate, link_playwright
from webaudit.models import NetworkEvent

_seq = itertools.count(1)


def ev(t: str, rid: str | None, raw: dict[str, Any], session: str = "cdp-1", source: str = "cdp") -> NetworkEvent:
    n = next(_seq)
    return NetworkEvent(event_id=f"e{n}", scan_id="s", seq=n, timestamp=float(n), source=source, target_id="T1",
                        session_id=session, request_id=rid, event_type=t, raw_event=raw)


def rws(rid: str, url: str, redirect: dict | None = None, method: str = "GET", ts: float = 1.0, **extra: Any) -> NetworkEvent:
    raw: dict[str, Any] = {"requestId": rid, "timestamp": ts, "type": "Fetch", "initiator": {"type": "script"},
                           "request": {"url": url, "method": method, "headers": {"A": "1"}}, **extra}
    if redirect:
        raw["redirectResponse"] = redirect
    return ev("Network.requestWillBeSent", rid, raw)


def resp(rid: str, url: str, status: int = 200, **r: Any) -> NetworkEvent:
    return ev("Network.responseReceived", rid, {"requestId": rid, "timestamp": 2.0, "response": {"url": url, "status": status, "headers": {"X": "p"}, **r}})


def fin(rid: str) -> NetworkEvent:
    return ev("Network.loadingFinished", rid, {"requestId": rid, "timestamp": 3.0, "encodedDataLength": 10})


def rx(rid: str, **kw: Any) -> NetworkEvent:
    return ev("Network.requestWillBeSentExtraInfo", rid, {"requestId": rid, "headers": {"Cookie": "[REDACTED]"}, **kw})


def sx(rid: str, status: int = 200, **kw: Any) -> NetworkEvent:
    return ev("Network.responseReceivedExtraInfo", rid, {"requestId": rid, "statusCode": status, "headers": {"Set-Cookie": "a=1\nb=2"}, **kw})


def run(events: list[NetworkEvent], **kw: Any) -> Correlator:
    return correlate(events, **kw)


def test_basic_lifecycle() -> None:
    c = run([rws("1", "http://x/a"), rx("1"), resp("1", "http://x/a"), sx("1"), fin("1")])
    (r,) = c.records
    assert (r.state, r.capture_status, r.response_status) == ("finished", "complete", 200)
    assert any(h.source == "extra_info" for h in r.request_headers)
    assert [h.value for h in r.response_headers if h.name == "Set-Cookie"] == ["a=1", "b=2"]  # repeated entries preserved


@pytest.mark.parametrize("order", [
    [0, 1, 2, 3, 4], [1, 0, 3, 2, 4], [3, 1, 0, 2, 4], [4, 3, 2, 1, 0], [2, 0, 4, 1, 3],
])
def test_out_of_order_arrival_is_equivalent(order: list[int]) -> None:
    base = [rws("1", "http://x/a"), rx("1"), resp("1", "http://x/a"), sx("1"), fin("1")]
    c = run([base[i] for i in order])
    (r,) = c.records
    assert r.response_status == 200 and r.state == "finished"
    assert {h.source for h in r.request_headers} == {"primary", "extra_info"}
    assert {h.source for h in r.response_headers} == {"primary", "extra_info"}
    assert all(l.status == "matched" for l in c.links.values())


def test_redirect_chain_hops_and_ordinal_extra_info() -> None:
    redir1 = {"url": "http://x/a", "status": 302, "headers": {"Location": "/b"}}
    redir2 = {"url": "http://x/b", "status": 301, "headers": {"Location": "/c"}}
    events = [
        rws("1", "http://x/a"), rx("1"), sx("1", 302, headers={"Location": "/b"}),
        rws("1", "http://x/b", redirect=redir1), rx("1"), sx("1", 301, headers={"Location": "/c"}),
        rws("1", "http://x/c", redirect=redir2), rx("1"), resp("1", "http://x/c"), sx("1", 200), fin("1"),
    ]
    c = run(events)
    assert [r.redirect_hop for r in c.records] == [0, 1, 2]
    assert [r.state for r in c.records] == ["redirected", "redirected", "finished"]
    assert [r.response_status for r in c.records] == [302, 301, 200]
    assert [len(r.redirect_chain) for r in c.records] == [0, 1, 2]
    assert c.records[0].redirect_chain == [] and c.records[2].redirect_chain[0].location == "/b"
    assert all(r.capture_status == "complete" for r in c.records)


def test_redirect_with_extra_info_arriving_early() -> None:
    redir1 = {"url": "http://x/a", "status": 302, "headers": {}}
    events = [rx("1"), sx("1", 302), rx("1"), rws("1", "http://x/a"), rws("1", "http://x/b", redirect=redir1),
              sx("1", 200), resp("1", "http://x/b"), fin("1")]
    c = run(events)
    assert [r.response_status for r in c.records] == [302, 200]
    assert all(l.status == "matched" for l in c.links.values())


def test_missing_response_failed_request() -> None:
    c = run([rws("1", "http://x/a"), ev("Network.loadingFailed", "1", {"requestId": "1", "timestamp": 2.0, "errorText": "net::ERR_CONNECTION_REFUSED", "canceled": False})])
    (r,) = c.records
    assert r.state == "failed" and r.response_status is None and r.failure_reason == "net::ERR_CONNECTION_REFUSED"
    assert r.capture_status == "complete"


def test_http_error_is_a_completed_request() -> None:
    c = run([rws("1", "http://x/a"), resp("1", "http://x/a", 503), fin("1")])
    assert c.records[0].state == "finished" and c.records[0].response_status == 503 and c.records[0].failure_reason is None


def test_incomplete_requests_are_preserved_not_dropped() -> None:
    c = run([rws("1", "http://x/a"), rws("2", "http://x/b"), resp("2", "http://x/b")])
    by = {r.request_id: r for r in c.records}
    assert by["1"].state == "requested" and by["1"].capture_status == "incomplete"
    assert by["2"].state == "response_received" and by["2"].capture_status == "incomplete"


def test_orphan_extra_info_kept() -> None:
    e1, e2 = rx("9"), sx("9")
    c = run([e1, e2])
    (r,) = c.records
    assert r.state == "incomplete" and "no requestWillBeSent" in r.notes[0]
    assert c.links[e1.event_id].status == "orphan_extra_info" and c.links[e2.event_id].status == "orphan_extra_info"
    assert c.stats["orphan_extra_info"] == 2


def test_extra_info_beyond_hops_is_orphan() -> None:
    e_extra = sx("1")
    c = run([rws("1", "http://x/a"), resp("1", "http://x/a"), sx("1"), e_extra, fin("1")])
    assert c.stats["orphan_extra_info"] == 1 and c.links[e_extra.event_id].status == "orphan_extra_info"


def test_status_mismatch_marks_ambiguous() -> None:
    c = run([rws("1", "http://x/a"), resp("1", "http://x/a", 200), sx("1", 404), fin("1")])
    assert c.records[0].capture_status == "ambiguous"


def test_same_request_id_in_different_sessions_not_mixed() -> None:
    a = [rws("1", "http://x/a"), resp("1", "http://x/a", 200), fin("1")]
    b = [ev("Network.requestWillBeSent", "1", {"requestId": "1", "timestamp": 1.0, "request": {"url": "http://y/b", "method": "POST", "headers": {}}}, session="cdp-2"),
         ev("Network.responseReceived", "1", {"requestId": "1", "timestamp": 2.0, "response": {"url": "http://y/b", "status": 201, "headers": {}}}, session="cdp-2"),
         ev("Network.loadingFinished", "1", {"requestId": "1", "timestamp": 3.0}, session="cdp-2")]
    c = run(a + b)
    assert {(r.session_id, r.method, r.response_status) for r in c.records} == {("cdp-1", "GET", 200), ("cdp-2", "POST", 201)}


def test_request_id_reuse_without_redirect_is_flagged() -> None:
    c = run([rws("1", "http://x/a"), resp("1", "http://x/a"), fin("1"), rws("1", "http://x/a")])
    assert [r.redirect_hop for r in c.records] == [0, 1]
    assert "request_id_reused_without_redirect" in c.records[1].notes and c.records[1].capture_status != "complete"


def test_preflight_is_separate_record() -> None:
    pre = ev("Network.requestWillBeSent", "P", {"requestId": "P", "timestamp": 1.0, "initiator": {"type": "preflight"},
                                                 "request": {"url": "http://api/c", "method": "OPTIONS", "headers": {"Access-Control-Request-Method": "GET"}}})
    c = run([rws("R", "http://api/c"), pre, resp("P", "http://api/c", 204), fin("P"), resp("R", "http://api/c"), fin("R")])
    by = {r.request_id: r for r in c.records}
    assert by["P"].is_preflight and by["P"].method == "OPTIONS" and not by["R"].is_preflight


def test_bounded_cache_evicts_terminal_first_and_marks_late_events() -> None:
    emitted: list[Any] = []
    c = Correlator(max_tracked=2, on_record=emitted.append)
    for e in [rws("1", "http://x/1"), resp("1", "http://x/1"), fin("1"), rws("2", "http://x/2"), rws("3", "http://x/3")]:
        c.ingest(e)
    assert [r.request_id for r in emitted] == ["1"]  # terminal request evicted first, complete
    late = sx("1")
    c.ingest(late)
    assert c.links[late.event_id].status == "late_after_eviction"
    c.finish()
    assert {r.request_id for r in emitted} == {"1", "2", "3"}


def test_websocket_and_playwright_events_are_observation_only() -> None:
    e = ev("Network.webSocketCreated", "W", {"requestId": "W", "url": "ws://x"})
    p = ev("pw.request", "pwreq-1", {"url": "http://x/a", "method": "GET", "headers": []}, source="playwright")
    c = run([e, p])
    assert c.records == [] and c.links[e.event_id].status == "observation_only" and c.links[p.event_id].status == "observation_only"


def test_playwright_linking_does_not_double_count() -> None:
    cdp = [rws("1", "http://x/a"), resp("1", "http://x/a"), fin("1")]
    pw = [ev("pw.request", "pwreq-1", {"url": "http://x/a", "method": "GET", "headers": [["Host", "x"]]}, source="playwright"),
          ev("pw.response", "pwreq-1", {"url": "http://x/a", "status": 200, "headers": [["X-Dup", "1"], ["X-Dup", "2"]]}, source="playwright")]
    c = run(cdp)
    n = link_playwright(c.records, pw)
    assert n == 1 and len(c.records) == 1 and c.records[0].playwright_seen
    assert [h.value for h in c.records[0].response_headers if h.source == "playwright" and h.name == "X-Dup"] == ["1", "2"]


# ---- integration with the real fixture ------------------------------------------------------

pytestmark_browser = pytest.mark.browser


@pytest.mark.browser
async def test_integration_fixture_correlation(harness_factory: Any, server: Any) -> None:
    from webaudit.models import NetworkEvent as NE
    async with harness_factory() as h:
        page = await h.new_page()
        await page.goto(server.main_url + "/")
        await page.wait_for_function("window.__scenarioDone === true", timeout=30_000)
        raw = await h.finish()
    events = [NE.model_validate(e) for e in raw]
    c = correlate(events)
    recs = c.records
    # redirect chain: 3 hops sharing one request id
    red = sorted([r for r in recs if "/redirect/" in r.url], key=lambda r: r.redirect_hop)
    assert [r.redirect_hop for r in red] == [0, 1, 2]
    assert [r.response_status for r in red] == [302, 301, 200]
    assert len({r.request_id for r in red}) == 1
    assert [r.capture_status for r in red] == ["complete"] * 3
    # preflight is an independent record
    pre = [r for r in recs if r.is_preflight]
    assert pre and pre[0].method == "OPTIONS" and pre[0].response_status == 204
    assert any(r.url.endswith("/api/cors") and r.method == "GET" and r.request_id != pre[0].request_id for r in recs)
    # failure + http errors
    assert any(r.state == "failed" and r.failure_reason for r in recs)
    by_url = {r.url.split(str(server.main_port))[-1]: r for r in recs if str(server.main_port) in r.url}
    assert by_url["/api/e404"].state == "finished" and by_url["/api/e404"].response_status == 404
    assert by_url["/api/e500"].response_status == 500
    # repeated headers from exact header lines
    rep = by_url["/api/repeated"]
    assert [h.value for h in rep.response_headers if h.source == "extra_info" and h.name.lower() == "x-dup"] == ["one", "two"]
    assert len([h for h in rep.response_headers if h.source == "extra_info" and h.name.lower() == "set-cookie"]) == 2
    # post data keys survive redaction, values do not
    echo = by_url["/api/echo"]
    assert echo.post_data_keys == ["name", "note", "password"]
    # nothing orphaned or ambiguous in a normal run; every cdp event has a link
    assert c.stats["orphan_extra_info"] == 0 and c.stats["ambiguous"] == 0
    cdp_ids = {e.event_id for e in events if e.source == "cdp"}
    assert cdp_ids <= set(c.links)
    assert all(l.status in ("matched", "observation_only") for l in c.links.values())
    # playwright linking
    assert link_playwright(recs, events) > 10
    assert not [r for r in recs if r.state in ("requested", "response_received") and r.url.startswith(server.main_url)]


def test_response_extra_info_without_response_received_kept_as_response_evidence() -> None:
    fail = ev("Network.loadingFailed", "1", {"requestId": "1", "timestamp": 2.0, "errorText": "net::ERR_FAILED",
                                            "corsErrorStatus": {"corsError": "MissingAllowOriginHeader"}})
    c = run([rws("1", "http://x/a"), rx("1"), sx("1", 200), fail])
    (r,) = c.records
    assert r.state == "failed" and r.response_status == 200 and r.cors_error_status["corsError"] == "MissingAllowOriginHeader"
    assert c.stats["orphan_extra_info"] == 0 and any("only via extra-info" in n for n in r.notes)


def test_orphan_with_pending_failure_keeps_failure_hint() -> None:
    fail = ev("Network.loadingFailed", "7", {"requestId": "7", "timestamp": 2.0, "errorText": "net::ERR_ABORTED"})
    c = run([rx("7"), sx("7"), fail])
    (r,) = c.records
    assert r.capture_status == "incomplete" and r.failure_reason == "net::ERR_ABORTED" and "before Network.enable" in r.notes[0]
