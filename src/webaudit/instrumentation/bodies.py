"""Opt-in, bounded response-body capture via ``Network.getResponseBody``.

* Disabled by default (mode "none"): no jobs, no events, no files.
* Fetches only AFTER ``Network.loadingFinished`` for that request (never for incomplete/failed requests).
* The CDP callback (``observe``) only does dictionary bookkeeping and ``put_nowait`` on a bounded queue; the
  retrieval, analysis and file writes happen in a worker task.
* Every eligible-or-considered outcome is recorded as a ``collector.body_capture`` event with an explicit status.
* Stored bodies are redacted; raw bodies are written only when ``store_raw`` is explicitly enabled.
* URLs found inside bodies are never fetched.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from ..config import BodyPolicy
from ..event_store.sink import EventSink
from ..logging_setup import get_logger
from ..redaction import redact_body, redact_url, scan_debug_indicators, scan_text_for_secrets, sensitive_json_keys

log = get_logger("bodies")

BINARY_PREFIXES = ("image/", "video/", "audio/", "font/", "application/font", "application/x-font", "application/octet-stream",
                   "application/zip", "application/pdf", "application/gzip", "application/wasm", "application/x-protobuf",
                   "application/vnd.", "multipart/")
SELECTED_RESOURCE_TYPES = {"XHR", "Fetch", "Script", "Document"}


def _is_textual(mime: str) -> bool:
    m = (mime or "").split(";")[0].strip().lower()
    if not m:
        return False
    if m.endswith(("+json", "+xml")) or "json" in m:  # e.g. application/vnd.pgrst.object+json (PostgREST) is text
        return True
    if m.startswith(BINARY_PREFIXES):
        return False
    return (m.startswith("text/") or "json" in m or "javascript" in m or "xml" in m or "ecmascript" in m
            or m in ("application/x-www-form-urlencoded", "application/graphql"))


def eligible(policy: BodyPolicy, resource_type: Optional[str], mime: str, status: int) -> tuple[bool, str]:
    if policy.mode == "none":
        return False, "skipped_policy"
    if status in (204, 205, 304) or 300 <= status < 400:
        return False, "skipped_no_body_status"
    if not _is_textual(mime):
        return False, "skipped_binary_or_unknown_type"
    if policy.mode == "selected":
        if resource_type not in SELECTED_RESOURCE_TYPES:
            return False, "skipped_not_selected"
        if resource_type == "Document" and "html" not in mime:
            return False, "skipped_not_selected"
    return True, "eligible"


@dataclass
class _Meta:
    url: str
    status: int
    mime: str
    resource_type: Optional[str]
    declared_length: Optional[int]


@dataclass
class _Job:
    att: Any  # CDPAttachment (needs .session.send, .label, .target_id)
    request_id: str
    meta: _Meta
    encoded_length: Optional[float]
    kind: str = "response"  # response | request
    post_data: Optional[str] = None
    has_post: bool = False
    req_headers: Optional[dict[str, Any]] = None
    method: str = "POST"


STATIC_TYPES = {"Script", "Stylesheet", "Document"}
PER_ENDPOINT_LIMIT = 5  # distinct captures kept per normalized API endpoint (responses of the same URL differ per user/state)


class BodyCapturer:
    def __init__(self, sink: EventSink, out_dir: Path, policy: BodyPolicy, *, meta_cache: int = 5000) -> None:
        self.sink, self.policy = sink, policy
        self.redacted_dir = Path(out_dir) / "bodies"
        self.raw_dir = Path(out_dir) / "bodies_raw"
        self._meta: "OrderedDict[tuple[str, str], _Meta]" = OrderedDict()
        self._meta_cap = meta_cache
        self._queue: asyncio.Queue[_Job | None] = asyncio.Queue(maxsize=policy.queue_size)
        self._task: asyncio.Task[None] | None = None
        self.total_bytes = 0
        self.per_origin: dict[str, int] = {}
        self.status_counts: dict[str, int] = {}
        self._seen: dict[tuple[str, str], int] = {}  # dedupe: static assets once per URL, API responses a few per endpoint
        self.duplicates_skipped = 0
        self._n = 0

    # ---- scheduling (sync, called from CDP callbacks) ---------------------------------------
    def observe(self, name: str, params: dict[str, Any], att: Any) -> None:
        if self.policy.mode == "none":
            return
        rid = params.get("requestId")
        if not rid:
            return
        key = (att.label, rid)
        if name == "Network.requestWillBeSent":
            req = params.get("request") or {}
            if req.get("hasPostData") or req.get("postData"):
                meta = _Meta(req.get("url", ""), 0, "", params.get("type"), None)
                try:
                    self._queue.put_nowait(_Job(att, rid, meta, None, kind="request", post_data=req.get("postData"),
                                                has_post=bool(req.get("hasPostData")), req_headers=req.get("headers"),
                                                method=req.get("method", "POST")))
                except asyncio.QueueFull:
                    self._record(att, rid, meta, "skipped_queue_full", kind="request", method=req.get("method"))
            return
        if name == "Network.responseReceived":
            r = params.get("response", {})
            headers = {k.lower(): v for k, v in (r.get("headers") or {}).items()}
            try:
                declared = int(headers["content-length"]) if "content-length" in headers else None
            except ValueError:
                declared = None
            self._meta[key] = _Meta(r.get("url", ""), int(r.get("status", 0)), r.get("mimeType", ""), params.get("type"), declared)
            while len(self._meta) > self._meta_cap:
                self._meta.popitem(last=False)
        elif name == "Network.loadingFinished":
            meta = self._meta.pop(key, None)
            if meta is None:
                return
            ok, why = eligible(self.policy, meta.resource_type, meta.mime, meta.status)
            if not ok:
                if why != "skipped_policy":
                    self._record(att, rid, meta, why)
                return
            dup, dkey, dkind = self._is_duplicate(meta)
            if dup:
                self.duplicates_skipped += 1
                # no file, but an explicit record so the request keeps a resolvable reference (duplicate_of:<first capture>)
                self._record(att, rid, meta, "duplicate_static_url" if dkind == "static" else "skipped_endpoint_limit", dedupe_key=dkey)
                return
            try:
                self._queue.put_nowait(_Job(att, rid, meta, params.get("encodedDataLength")))
            except asyncio.QueueFull:
                self._record(att, rid, meta, "skipped_queue_full")
        elif name == "Network.loadingFailed":
            self._meta.pop(key, None)  # never fetch bodies for failed/incomplete requests

    @staticmethod
    def _dedupe_key(meta: _Meta) -> tuple[str, str]:
        from ..urlnorm import normalize_url
        static = meta.resource_type in STATIC_TYPES
        return ("static" if static else "api", meta.url.split("?")[0] if static else normalize_url(meta.url))

    def _is_duplicate(self, meta: _Meta) -> tuple[bool, str, str]:
        kind, key = self._dedupe_key(meta)
        n = self._seen.get((kind, key), 0)
        self._seen[(kind, key)] = n + 1
        return n >= (1 if kind == "static" else PER_ENDPOINT_LIMIT), f"{kind}:{key}", kind

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="body-capturer")

    async def stop(self, timeout: float = 15.0) -> None:
        await self._queue.put(None)
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout)
            except asyncio.TimeoutError:
                self._task.cancel()
                log.warning("body capturer timed out during shutdown")

    # ---- worker -----------------------------------------------------------------------------
    async def _run(self) -> None:
        while True:
            job = await self._queue.get()
            if job is None:
                return
            try:
                await (self._capture_request(job) if job.kind == "request" else self._capture(job))
            except Exception as exc:  # never let one body kill the worker
                self._record(job.att, job.request_id, job.meta, "error", error=repr(exc)[:300])

    async def _capture(self, job: _Job) -> None:
        meta, att = job.meta, job.att
        origin = urlsplit(meta.url)._replace(path="", query="", fragment="").geturl()
        origin = origin + ("#static" if meta.resource_type in STATIC_TYPES else "#api")  # API bodies are never starved by assets
        if self.total_bytes >= self.policy.max_total_bytes:
            return self._record(att, job.request_id, meta, "skipped_total_budget")
        if self.per_origin.get(origin, 0) >= self.policy.per_origin_bytes:
            return self._record(att, job.request_id, meta, "skipped_origin_budget")
        hint = meta.declared_length if meta.declared_length is not None else job.encoded_length
        if hint is not None and hint > self.policy.max_body_bytes * 20:
            return self._record(att, job.request_id, meta, "skipped_too_large", size=int(hint))
        try:
            res = await att.session.send("Network.getResponseBody", {"requestId": job.request_id})
        except Exception as exc:
            return self._record(att, job.request_id, meta, "unavailable", error=str(exc)[:300])
        body = res.get("body", "")
        if res.get("base64Encoded"):
            try:
                data = base64.b64decode(body)
            except Exception:
                return self._record(att, job.request_id, meta, "unavailable", error="invalid base64 from protocol")
        else:
            data = body.encode("utf-8", "replace")  # BYTES, not characters
        size = len(data)
        truncated = size > self.policy.max_body_bytes
        data = data[: self.policy.max_body_bytes]
        text = data.decode("utf-8", "replace")
        if "\x00" in text[:1024]:
            return self._record(att, job.request_id, meta, "skipped_binary_or_unknown_type", size=size)
        candidates = scan_text_for_secrets(text)
        keys = sensitive_json_keys(text) if "json" in meta.mime.lower() else []
        # library code legitimately contains stack-trace/path/debug strings: only look in non-script responses
        debug = [] if meta.resource_type in ("Script", "Stylesheet") else scan_debug_indicators(text)
        redacted = redact_body(text, meta.mime)
        self._n += 1
        bid = f"body-{self._n:06d}"
        self.redacted_dir.mkdir(parents=True, exist_ok=True)
        rel = f"bodies/{bid}.txt"
        stored = redacted.encode("utf-8")
        (Path(self.redacted_dir) / f"{bid}.txt").write_bytes(stored)
        raw_rel = None
        if self.policy.store_raw:
            self.raw_dir.mkdir(parents=True, exist_ok=True)
            rp = self.raw_dir / f"{bid}.raw"
            rp.write_bytes(data)
            try:
                os.chmod(rp, 0o600)
            except OSError:
                pass
            raw_rel = f"bodies_raw/{bid}.raw"
        self.total_bytes += len(data)
        self.per_origin[origin] = self.per_origin.get(origin, 0) + len(data)
        self._record(att, job.request_id, meta, "truncated" if truncated else "captured", size=size, stored_bytes=len(stored),
                     dedupe_key="%s:%s" % self._dedupe_key(meta), body_id=bid, path=rel, raw_path=raw_rel, sha256_redacted=hashlib.sha256(stored).hexdigest(),
                     secret_candidates=candidates, sensitive_keys=keys, debug_indicators=debug,
                     source_map_reference=("sourceMappingURL" in text[-500:]) or None)

    async def _capture_request(self, job: _Job) -> None:
        """Request payload (JSON / form / text). Stored redacted; raw only with store_raw. Never for binary uploads."""
        meta, att = job.meta, job.att
        hdrs = {k.lower(): v for k, v in (job.req_headers or {}).items()}
        ctype = str(hdrs.get("content-type", ""))
        if ctype and not _is_textual(ctype) and "x-www-form-urlencoded" not in ctype:
            return self._record(att, job.request_id, meta, "skipped_binary_or_unknown_type", kind="request", method=job.method, mime=ctype)
        text = job.post_data
        if text is None and job.has_post:
            try:
                res = await att.session.send("Network.getRequestPostData", {"requestId": job.request_id})
                text = res.get("postData", "")
            except Exception as exc:
                return self._record(att, job.request_id, meta, "unavailable", kind="request", method=job.method, error=str(exc)[:300])
        if text is None:
            return
        raw_bytes = text.encode("utf-8", "replace")
        size = len(raw_bytes)
        truncated = size > self.policy.max_body_bytes
        text = raw_bytes[: self.policy.max_body_bytes].decode("utf-8", "replace")
        if "form" in ctype and "=" in text and "{" not in text[:2]:
            from ..redaction import redact_post_data
            redacted = redact_post_data(text)
        else:
            redacted = redact_body(text, ctype or ("application/json" if text.lstrip().startswith(("{", "[")) else None))
        self._n += 1
        bid = f"req-{self._n:06d}"
        self.redacted_dir.mkdir(parents=True, exist_ok=True)
        stored = redacted.encode("utf-8")
        (self.redacted_dir / f"{bid}.txt").write_bytes(stored)
        raw_rel = None
        if self.policy.store_raw:
            self.raw_dir.mkdir(parents=True, exist_ok=True)
            rp = self.raw_dir / f"{bid}.raw"
            rp.write_bytes(text.encode("utf-8"))
            try:
                os.chmod(rp, 0o600)
            except OSError:
                pass
            raw_rel = f"bodies_raw/{bid}.raw"
        self._record(att, job.request_id, meta, "truncated" if truncated else "captured", kind="request", method=job.method, size=size,
                     stored_bytes=len(stored), body_id=bid, path=f"bodies/{bid}.txt", raw_path=raw_rel, mime=ctype,
                     sha256_redacted=hashlib.sha256(stored).hexdigest(), secret_candidates=scan_text_for_secrets(text),
                     sensitive_keys=sensitive_json_keys(text))

    def _record(self, att: Any, rid: str, meta: _Meta, status: str, **extra: Any) -> None:
        self.status_counts[status] = self.status_counts.get(status, 0) + 1
        et = "collector.request_body" if extra.get("kind") == "request" else "collector.body_capture"
        payload = {"status": status, "request_id": rid, "url": redact_url(meta.url), "mime": meta.mime,
                   "resource_type": meta.resource_type, "http_status": meta.status,
                   "policy": {"mode": self.policy.mode, "max_body_bytes": self.policy.max_body_bytes}, **extra}
        self.sink.offer("collector", et, payload, target_id=att.target_id, session_id=att.label, request_id=rid)

    def diagnostics(self) -> dict[str, Any]:
        return {"mode": self.policy.mode, "total_bytes": self.total_bytes, "per_origin": dict(self.per_origin),
                "status_counts": dict(self.status_counts), "duplicates_skipped": self.duplicates_skipped,
                "dedupe_policy": f"static assets captured once per URL; API responses up to {PER_ENDPOINT_LIMIT} per normalized endpoint"}
