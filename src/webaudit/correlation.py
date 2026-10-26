"""Request correlation: state machine over persisted events, independent of arrival order.

Scope key: (scan_id, session_id [+ target_id], request_id). Redirect hops are modelled separately: CDP reuses the
requestId across a redirect chain and signals each hop via ``redirectResponse`` on the next ``requestWillBeSent``.

Extra-info matching
-------------------
``requestWillBeSentExtraInfo`` / ``responseReceivedExtraInfo`` carry only a requestId (no hop marker). They are
matched **by ordinal**: the k-th request-extra-info of a requestId belongs to hop k; the k-th response-extra-info
belongs to the k-th response (redirect responses included). Matching happens at emit time so arrival order of
primary vs. extra events is irrelevant. Response status codes are cross-checked; mismatches are marked ambiguous.
Extra-info without any primary event is kept as an orphan (never dropped).

Correlation is a pure function of the persisted event stream, so interrupted scans can be replayed from SQLite.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from .models import HeaderEntry, NetworkEvent, RedirectHop, RequestRecord, TimingInfo
from .urlnorm import normalize_url, query_names

PRIMARY_TYPES = {
    "Network.requestWillBeSent", "Network.responseReceived", "Network.loadingFinished", "Network.loadingFailed",
    "Network.requestServedFromCache",
}
REQ_EXTRA = "Network.requestWillBeSentExtraInfo"
RESP_EXTRA = "Network.responseReceivedExtraInfo"
WS_PREFIX = "Network.webSocket"


@dataclass
class _Hop:
    index: int
    rws: dict[str, Any]
    event_id: str
    redirect_response: Optional[dict[str, Any]] = None
    response: Optional[dict[str, Any]] = None
    response_event_id: Optional[str] = None
    finished: Optional[dict[str, Any]] = None
    failed: Optional[dict[str, Any]] = None
    from_cache: bool = False
    event_ids: list[str] = field(default_factory=list)
    response_ts: Optional[float] = None


@dataclass
class _Req:
    key: tuple[str, str, str]
    hops: list[_Hop] = field(default_factory=list)
    req_extra: list[tuple[str, dict[str, Any]]] = field(default_factory=list)  # (event_id, params)
    resp_extra: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    pending: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)  # primaries before the first rws
    notes: list[str] = field(default_factory=list)
    target_id: Optional[str] = None
    scan_id: str = ""
    last_seq: int = 0


@dataclass
class EventLink:
    event_id: str
    status: str  # matched | orphan_extra_info | ambiguous | late_after_eviction | observation_only | unlinked
    redirect_hop: Optional[int] = None


def _split_lines(v: str) -> list[str]:
    return v.split("\n") if "\n" in v else [v]


def entries_from(headers: dict[str, Any] | None, headers_text: str | None, source: str) -> list[HeaderEntry]:
    """Prefer exact header lines (headersText) for repeated-header fidelity; fall back to the dict ('\\n' joined)."""
    out: list[HeaderEntry] = []
    if headers_text:
        for line in headers_text.split("\r\n")[1:]:  # first line is the status/request line
            if not line:
                continue
            n, sep, v = line.partition(":")
            if sep:
                out.append(HeaderEntry(name=n.strip(), value=v.strip(), source=source))
        if out:
            return out
    for n, v in (headers or {}).items():
        for piece in _split_lines(str(v)):
            out.append(HeaderEntry(name=n, value=piece, source=source))
    return out


def _find_header(entries: list[HeaderEntry], name: str) -> Optional[str]:
    for e in entries:
        if e.name.lower() == name:
            return e.value
    return None


class Correlator:
    def __init__(self, *, max_tracked: int = 20_000, on_record: Callable[[RequestRecord], None] | None = None,
                 keep_links: bool = True, evicted_memory: int = 20_000) -> None:
        self.max_tracked = max_tracked
        self.on_record = on_record
        self.keep_links = keep_links
        self._active: "OrderedDict[tuple[str, str, str], _Req]" = OrderedDict()
        self._evicted: deque[tuple[str, str, str]] = deque(maxlen=evicted_memory)
        self._evicted_set: set[tuple[str, str, str]] = set()
        self.records: list[RequestRecord] = []
        self.links: dict[str, EventLink] = {}
        self.stats = {"events": 0, "requests": 0, "evicted_incomplete": 0, "orphan_extra_info": 0,
                      "late_after_eviction": 0, "ambiguous": 0, "ignored": 0}

    # ---- ingest -----------------------------------------------------------------------------
    def ingest(self, ev: NetworkEvent) -> None:
        self.stats["events"] += 1
        t = ev.event_type
        if ev.source != "cdp" or ev.request_id is None or not t.startswith("Network."):
            self._link(ev.event_id, "observation_only")
            return
        if t.startswith(WS_PREFIX):  # websocket lifecycle is accounted for but not a request/response record
            self._link(ev.event_id, "observation_only")
            return
        key = (ev.scan_id, ev.session_id or ev.target_id or "?", ev.request_id)
        if key in self._evicted_set:
            self.stats["late_after_eviction"] += 1
            self._link(ev.event_id, "late_after_eviction")
            return
        req = self._active.get(key)
        if req is None:
            req = _Req(key=key, target_id=ev.target_id, scan_id=ev.scan_id)
            self._active[key] = req
            self._evict_if_needed()
        req.last_seq = ev.seq
        raw = ev.raw_event
        if t == REQ_EXTRA:
            req.req_extra.append((ev.event_id, raw))
        elif t == RESP_EXTRA:
            req.resp_extra.append((ev.event_id, raw))
        elif t in PRIMARY_TYPES:
            self._primary(req, ev.event_id, t, raw)
        else:
            self.stats["ignored"] += 1
            self._link(ev.event_id, "observation_only")

    def _primary(self, req: _Req, eid: str, t: str, raw: dict[str, Any]) -> None:
        if t == "Network.requestWillBeSent":
            if raw.get("redirectResponse") and req.hops:
                prev = req.hops[-1]
                if prev.redirect_response is None:
                    prev.redirect_response = raw["redirectResponse"]
                else:
                    req.notes.append("duplicate redirectResponse")
            elif req.hops and (req.hops[-1].finished or req.hops[-1].failed or req.hops[-1].response):
                req.notes.append("request_id_reused_without_redirect")
            hop = _Hop(index=len(req.hops), rws=raw, event_id=eid)
            hop.event_ids.append(eid)
            req.hops.append(hop)
            if len(req.hops) == 1 and req.pending:  # replay primaries that arrived before the first requestWillBeSent
                for peid, pt, praw in req.pending:
                    self._apply(req, peid, pt, praw)
                req.pending.clear()
            return
        if not req.hops:
            req.pending.append((eid, t, raw))
            return
        self._apply(req, eid, t, raw)

    def _apply(self, req: _Req, eid: str, t: str, raw: dict[str, Any]) -> None:
        hop = req.hops[-1]
        hop.event_ids.append(eid)
        if t == "Network.responseReceived":
            if hop.response is not None:
                req.notes.append("multiple responseReceived for one hop")
            hop.response = raw.get("response") or {}
            hop.response_event_id = eid
            hop.response_ts = raw.get("timestamp")
            hop.from_cache = hop.from_cache or bool(hop.response.get("fromDiskCache") or hop.response.get("fromPrefetchCache"))
        elif t == "Network.loadingFinished":
            hop.finished = raw
        elif t == "Network.loadingFailed":
            hop.failed = raw
        elif t == "Network.requestServedFromCache":
            hop.from_cache = True

    # ---- eviction / finish ------------------------------------------------------------------
    def _is_terminal(self, r: _Req) -> bool:
        return bool(r.hops) and bool(r.hops[-1].finished or r.hops[-1].failed)

    def _evict_if_needed(self) -> None:
        while len(self._active) > self.max_tracked:
            victim = next((k for k, r in self._active.items() if self._is_terminal(r)), None)
            if victim is None:
                victim = next(iter(self._active))
                self.stats["evicted_incomplete"] += 1
            self._emit(self._active.pop(victim), evicted=True)
            if len(self._evicted) == self._evicted.maxlen:
                self._evicted_set.discard(self._evicted[0])
            self._evicted.append(victim)
            self._evicted_set.add(victim)

    def finish(self) -> list[RequestRecord]:
        """Finalize everything still tracked (also used after an interrupted scan)."""
        for key in list(self._active):
            self._emit(self._active.pop(key), evicted=False)
        return self.records

    def _link(self, event_id: str, status: str, hop: Optional[int] = None) -> None:
        if self.keep_links:
            self.links[event_id] = EventLink(event_id, status, hop)

    # ---- record building --------------------------------------------------------------------
    def _emit(self, req: _Req, *, evicted: bool) -> None:
        recs = self._build(req, evicted)
        self.stats["requests"] += len(recs)
        for r in recs:
            if self.on_record:
                self.on_record(r)
            else:
                self.records.append(r)

    def _build(self, req: _Req, evicted: bool) -> list[RequestRecord]:
        scan_id, session, rid = req.key
        recs: list[RequestRecord] = []
        if not req.hops:
            # Only extra-info and/or pending primaries: never drop silently.
            for eid, _ in req.req_extra + req.resp_extra:
                self._link(eid, "orphan_extra_info")
                self.stats["orphan_extra_info"] += 1
            for eid, _, _ in req.pending:
                self._link(eid, "unlinked")
            hint = next((raw for _, t, raw in req.pending if t == "Network.loadingFailed"), None)
            recs.append(RequestRecord(
                record_id=f"{session}/{rid}#0", scan_id=scan_id, target_id=req.target_id, session_id=session,
                request_id=rid, state="incomplete", capture_status="incomplete",
                failure_reason=(hint or {}).get("errorText"), blocked_reason=(hint or {}).get("blockedReason"),
                notes=["no requestWillBeSent observed (request began before Network.enable, or events were dropped)"] + req.notes,
                event_ids=[e for e, _ in req.req_extra + req.resp_extra] + [e for e, _, _ in req.pending]))
            return recs

        chain: list[RedirectHop] = []
        # responses in order: redirect responses of hops 0..n-2, plus final hop response
        resp_list: list[tuple[int, dict[str, Any]]] = []
        for h in req.hops:
            r = h.redirect_response or h.response
            if r is not None:
                resp_list.append((h.index, r))
        extra_only_hop: Optional[int] = None
        last = req.hops[-1]
        if len(req.resp_extra) > len(resp_list) and last.response is None and last.redirect_response is None:
            # e.g. CORS-blocked: browser reports response extra-info + loadingFailed but no responseReceived.
            resp_list.append((last.index, {}))
            extra_only_hop = last.index
        resp_extra_by_hop: dict[int, tuple[str, dict[str, Any]]] = {}
        ambiguous_hops: set[int] = set()
        for ordinal, (hop_idx, resp) in enumerate(resp_list):
            if ordinal < len(req.resp_extra):
                eid, extra = req.resp_extra[ordinal]
                st = extra.get("statusCode")
                if st is not None and resp.get("status") is not None and st != resp.get("status") and not req.hops[hop_idx].from_cache:
                    ambiguous_hops.add(hop_idx)
                    self.stats["ambiguous"] += 1
                resp_extra_by_hop[hop_idx] = (eid, extra)
        for eid, _ in req.resp_extra[len(resp_list):]:  # more extra-info than responses
            self._link(eid, "orphan_extra_info")
            self.stats["orphan_extra_info"] += 1
        for eid, _ in req.req_extra[len(req.hops):]:
            self._link(eid, "orphan_extra_info")
            self.stats["orphan_extra_info"] += 1

        for h in req.hops:
            rws = h.rws
            r = rws.get("request") or {}
            url = r.get("url", "")
            method = r.get("method", "GET")
            notes = list(req.notes)
            req_extra = req.req_extra[h.index] if h.index < len(req.req_extra) else None
            resp_extra = resp_extra_by_hop.get(h.index)
            req_headers = entries_from(r.get("headers"), None, "primary")
            if req_extra:
                req_headers += entries_from(req_extra[1].get("headers"), req_extra[1].get("headersText"), "extra_info")
            resp_obj = h.redirect_response or h.response
            resp_headers: list[HeaderEntry] = []
            status = None
            if resp_obj is not None:
                status = resp_obj.get("status")
                resp_headers = entries_from(resp_obj.get("headers"), None, "primary")
            if resp_extra:
                resp_headers += entries_from(resp_extra[1].get("headers"), resp_extra[1].get("headersText"), "extra_info")
                if status is None:
                    status = resp_extra[1].get("statusCode")
            if h.index == extra_only_hop:
                notes.append("response seen only via extra-info (no responseReceived; typical of browser-blocked CORS)")
            if resp_obj is not None and not resp_extra and not h.from_cache:
                notes.append("response extra-info not observed for this hop")
            if req_extra is None and not h.from_cache:
                notes.append("request extra-info not observed for this hop")

            if h.failed:
                state = "failed"
            elif h.redirect_response is not None:
                state = "redirected"
            elif h.finished:
                state = "finished"
            elif h.response is not None:
                state = "response_received"
            else:
                state = "requested"
            incomplete = state in ("requested", "response_received")
            if evicted and incomplete:
                capture = "evicted"
            elif incomplete:
                capture = "incomplete"
            elif h.index in ambiguous_hops or "request_id_reused_without_redirect" in notes:
                capture = "ambiguous"
            else:
                capture = "complete"

            loc = _find_header(resp_headers, "location")
            chain_snapshot = list(chain)
            chain.append(RedirectHop(hop=h.index, url=url, method=method, status=status if state == "redirected" else None,
                                     location=loc))
            ptime = rws.get("timestamp")
            end_ts = (h.finished or h.failed or {}).get("timestamp")
            dur = (end_ts - ptime) * 1000 if isinstance(end_ts, (int, float)) and isinstance(ptime, (int, float)) else None
            failed = h.failed or {}
            post = r.get("postData")
            keys: list[str] = []
            if isinstance(post, str):
                keys = _post_keys(post)
            rtype = rws.get("type")
            init = rws.get("initiator")
            init_summary, init_frames = initiator_chain(init)
            rec = RequestRecord(
                record_id=f"{session}/{rid}#{h.index}", scan_id=scan_id, target_id=req.target_id, session_id=session,
                request_id=rid, redirect_hop=h.index, method=method, url=url, normalized_url=normalize_url(url),
                resource_type=rtype, initiator=init, initiator_summary=init_summary, initiator_frames=init_frames,
                is_preflight=bool(isinstance(init, dict) and init.get("type") == "preflight"),
                request_headers=req_headers, has_post_data=bool(r.get("hasPostData") or post), post_data_keys=keys,
                query_param_names=query_names(url),
                response_status=status, response_status_text=(resp_obj or {}).get("statusText"),
                response_headers=resp_headers, response_mime_type=(h.response or {}).get("mimeType"),
                remote_address=_remote(resp_obj), protocol=(resp_obj or {}).get("protocol"),
                from_cache=h.from_cache, from_service_worker=bool((h.response or {}).get("fromServiceWorker")),
                mixed_content_type=r.get("mixedContentType"), document_url=rws.get("documentURL"),
                timing=TimingInfo(wall_time_start=rws.get("wallTime"), request_ts=ptime, response_ts=h.response_ts,
                                  finished_ts=end_ts, duration_ms=dur,
                                  encoded_data_length=(h.finished or {}).get("encodedDataLength")),
                redirect_chain=chain_snapshot, failure_reason=failed.get("errorText"),
                blocked_reason=failed.get("blockedReason"), cors_error_status=failed.get("corsErrorStatus"),
                state=state, capture_status=capture, notes=notes,
                event_ids=h.event_ids + ([req_extra[0]] if req_extra else []) + ([resp_extra[0]] if resp_extra else []),
            )
            recs.append(rec)
            # event links
            status_link = "ambiguous" if h.index in ambiguous_hops else "matched"
            for eid in h.event_ids:
                self._link(eid, "matched", h.index)
            if req_extra:
                self._link(req_extra[0], "matched", h.index)
            if resp_extra:
                self._link(resp_extra[0], status_link, h.index)
        return recs


def initiator_chain(init: Any) -> tuple[Optional[str], list[str]]:
    """Summarize a CDP initiator: type + origin of the call and the (async-joined) call stack, innermost first."""
    if not isinstance(init, dict):
        return None, []
    frames: list[str] = []
    stack = init.get("stack")
    depth = 0
    while isinstance(stack, dict) and depth < 6 and len(frames) < 12:
        desc = stack.get("description")
        if desc and depth:
            frames.append(f"--- {desc} ---")
        for f in stack.get("callFrames", [])[:8]:
            frames.append(f"{f.get('functionName') or '<anonymous>'}@{f.get('url', '')}:{f.get('lineNumber', 0) + 1}:{f.get('columnNumber', 0) + 1}")
        stack = stack.get("parent")
        depth += 1
    t = init.get("type")
    where = init.get("url") or (frames[0].split("@", 1)[1] if frames and "@" in frames[0] else "")
    if init.get("lineNumber") is not None and init.get("url"):
        where = f"{init['url']}:{init['lineNumber'] + 1}"
    return (f"{t} {where}".strip() if t else None), frames[:12]


def _post_keys(post: str) -> list[str]:
    import json
    from urllib.parse import parse_qsl
    try:
        obj = json.loads(post)
        if isinstance(obj, dict):
            return sorted(obj.keys())
    except ValueError:
        pass
    if "=" in post:
        return sorted({k for k, _ in parse_qsl(post, keep_blank_values=True)})
    return []


def _remote(resp: Optional[dict[str, Any]]) -> Optional[str]:
    if not resp or not resp.get("remoteIPAddress"):
        return None
    return f"{resp['remoteIPAddress']}:{resp.get('remotePort', '')}"


def correlate(events: Iterable[NetworkEvent], **kw: Any) -> Correlator:
    c = Correlator(**kw)
    for e in events:
        c.ingest(e)
    c.finish()
    return c


def link_playwright(records: list[RequestRecord], events: Iterable[NetworkEvent]) -> int:
    """Best-effort attach of Playwright observations (separate source) to CDP records by (method, url) in order.

    Not an identity guarantee: Playwright has no CDP request id. Matches only mark ``playwright_seen`` and add
    ``source='playwright'`` headers; they never create or merge requests (no double counting).
    """
    pw_reqs: list[NetworkEvent] = []
    pw_resp: dict[str, NetworkEvent] = {}
    for e in events:
        if e.event_type == "pw.request":
            pw_reqs.append(e)
        elif e.event_type == "pw.response" and e.request_id:
            pw_resp[e.request_id] = e
    used: set[str] = set()
    matched = 0
    by_key: dict[tuple[str, str], list[RequestRecord]] = {}
    for rec in sorted(records, key=lambda r: (r.timing.request_ts or 0)):
        by_key.setdefault((rec.method, rec.url), []).append(rec)
    for pe in sorted(pw_reqs, key=lambda e: e.seq):
        raw = pe.raw_event
        for rec in by_key.get((raw.get("method", ""), raw.get("url", "")), []):
            if rec.record_id in used:
                continue
            used.add(rec.record_id)
            rec.playwright_seen = True
            rec.request_headers += [HeaderEntry(name=n, value=v, source="playwright") for n, v in raw.get("headers", [])]
            pr = pw_resp.get(pe.request_id or "")
            if pr:
                rec.response_headers += [HeaderEntry(name=n, value=v, source="playwright") for n, v in pr.raw_event.get("headers", [])]
                if rec.response_status is None:
                    rec.response_status = pr.raw_event.get("status")
            rec.event_ids.append(pe.event_id)
            matched += 1
            break
    return matched
