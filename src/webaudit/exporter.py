"""Export an evidence bundle from a scan directory. Works on interrupted scans because everything is replayed
from the SQLite event store (the source of truth)."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Iterator

from . import __version__
from .correlation import Correlator, link_playwright
from .event_store.sqlite import SqliteEventStore
from .inventory import build_inventory
from .logging_setup import get_logger
from .models import SCHEMA_VERSION, NetworkEvent, RequestRecord
from .report import render_report
from .security_rules import analyze
from .security_rules.base import RuleContext

log = get_logger("exporter")
STALE_AFTER_S = 30.0

NOT_INSTRUMENTED = ["dedicated workers", "shared workers", "service-worker own network traffic", "browser-level targets other than attached pages/frames"]

FAILURE_CLASSES = [  # (substring in failure_reason, class, meaning)
    ("ERR_BLOCKED_BY_CLIENT", "blocked_by_client", "blocked by the scan's scope/method guard (or a browser extension); see scope_guard_blocks"),
    ("ERR_ABORTED", "aborted", "cancelled by the page/browser (navigation away, superseded request, preload); usually benign"),
    ("NAME_NOT_RESOLVED", "dns_failure", "hostname did not resolve"),
    ("CONNECTION_REFUSED", "connection_refused", "nothing listening / port closed"),
    ("CONNECTION_RESET", "connection_reset", "connection reset by peer"),
    ("TIMED_OUT", "timeout", "request timed out"),
    ("NETWORK_CHANGED", "network_change", "local network changed during the request"),
    ("INTERNET_DISCONNECTED", "network_change", "local network changed during the request"),
    ("CERT", "tls_certificate", "TLS certificate problem"),
    ("ERR_FAILED", "generic_failure", "unspecified browser failure (often CORS, mixed content or policy); check cors_error_status"),
]


def classify_failures(records: list[RequestRecord]) -> dict[str, Any]:
    out: dict[str, dict[str, Any]] = {}
    for r in records:
        if r.state != "failed":
            continue
        if r.cors_error_status:
            cls, why = "cors_blocked", "browser enforced CORS policy; not a server failure"
        else:
            cls, why = "other", "unclassified"
            for sub_, c, w in FAILURE_CLASSES:
                if sub_ in (r.failure_reason or ""):
                    cls, why = c, w
                    break
        d = out.setdefault(cls, {"count": 0, "meaning": why, "examples": []})
        d["count"] += 1
        if len(d["examples"]) < 3:
            d["examples"].append(r.url[:140])
    return out


def skipped_scope_origins(pages: list[dict[str, Any]], allowed: list[str]) -> list[dict[str, Any]]:
    """Which origins were refused as out of scope, and are any siblings of the target (same registrable-looking domain)?"""
    from urllib.parse import urlsplit
    target_host = urlsplit(allowed[0]).hostname or "" if allowed else ""
    base = ".".join(target_host.split(".")[-2:])
    counts: dict[str, int] = {}
    for p in pages:
        if p.get("navigation_status") == "skipped_scope":
            u = urlsplit(p.get("url", ""))
            o = f"{u.scheme}://{u.netloc}" if u.scheme in ("http", "https") and u.netloc else f"{u.scheme or '?'}: (non-web link)"
            counts[o] = counts.get(o, 0) + 1
    res = []
    for o, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        host = urlsplit(o).hostname or ""
        same = bool(base) and (host == base or host.endswith("." + base))
        if "non-web link" in o:
            res.append({"origin": o, "count": n, "same_site_as_target": False, "hint": "mailto:/tel:/javascript: links are not navigable pages"})
            continue
        res.append({"origin": o, "count": n, "same_site_as_target": same,
                    "hint": ("sibling subdomain of the target: if it is part of your application, approve it with --extra-origin "
                             f"{o}" if same else "external origin: correctly not visited")})
    return res


STATIC_LIMITATIONS = [
    "Passive observation of browser-visible traffic only; the endpoint inventory is NOT a complete list of the application's endpoints.",
    "CDP data is structured browser instrumentation, not a byte-for-byte packet capture.",
    "Page/frame-level CDP sessions do not cover service/shared/dedicated workers; popups' earliest requests may be missed.",
    "Redaction is best-effort pattern matching and is not guaranteed to remove every sensitive value.",
    "Passive findings are indicators; authorization/access-control weaknesses cannot be proven without separate, authorized active testing.",
    "Browser-side evidence cannot show server-side SQL, database policy decisions (e.g. Row Level Security) or backend authorization logic; "
    "use server/database audit logs or tracing, and tests with separate accounts you control.",
    "Workflows are covered only if they were exercised: the crawler never performs writes; use a manual session to record login/logout, saves, uploads, etc.",
    "Not instrumented: " + ", ".join(NOT_INSTRUMENTED) + ".",
]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_jsonl(path: Path, rows: Iterator[dict[str, Any]]) -> int:
    n = 0
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
            n += 1
    return n


def detect_status(scan_dir: Path) -> str:
    """completed/failed if the scan closed cleanly; 'running' if the heartbeat is fresh; otherwise 'interrupted'."""
    db = SqliteEventStore(scan_dir / "scan.sqlite")
    try:
        final = db.get_meta("final_status")
        if final:
            return final
        with db._lock:  # heartbeat is a bare float string written by append_events
            row = db._conn.execute("SELECT value FROM meta WHERE key='heartbeat'").fetchone()
        if row and time.time() - float(row[0]) < STALE_AFTER_S:
            return "running"
        return "interrupted"
    finally:
        db.close()


REPLAY_EXTRAS: dict[str, Any] = {}


def replay(db: SqliteEventStore) -> tuple[Correlator, dict[str, dict[str, Any]]]:
    """Correlate all persisted events. Returns (correlator with records, body-capture info keyed by record_id).

    Side information (unsupported targets, unavailable bodies, request-body statuses) is left in ``REPLAY_EXTRAS``."""
    corr = Correlator()
    side: list[NetworkEvent] = []
    body_events: list[NetworkEvent] = []
    req_body_events: list[NetworkEvent] = []
    targets: dict[str, int] = {"cdp_sessions": 0, "frames_without_own_session": 0, "service_workers_reported": 0, "late_attached_pages": 0,
                               "redirect_guard_unavailable": 0}
    channels: dict[str, Any] = {"websockets_cdp": 0, "websockets_playwright": 0, "popups": 0, "pages_announced": 0}
    for ev in db.iter_events():
        corr.ingest(ev)
        t = ev.event_type
        if t in ("pw.request", "pw.response"):
            side.append(ev)
        elif t == "collector.body_capture":
            body_events.append(ev)
        elif t == "collector.request_body":
            req_body_events.append(ev)
        elif t == "collector.cdp_attached":
            targets["cdp_sessions"] += 1
        elif t == "collector.frame_attach_skipped":
            targets["frames_without_own_session"] += 1
        elif t == "pw.serviceworker":
            targets["service_workers_reported"] += 1
        elif t == "collector.late_attach":
            targets["late_attached_pages"] += 1
        elif t == "collector.redirect_guard_unavailable":
            targets["redirect_guard_unavailable"] += 1
        elif t == "Network.webSocketCreated":
            channels["websockets_cdp"] += 1
        elif t == "pw.websocket_created":
            channels["websockets_playwright"] += 1
        elif t == "pw.popup":
            channels["popups"] += 1
        elif t == "pw.page":
            channels["pages_announced"] += 1
    recs = corr.finish()
    link_playwright(recs, side)
    last_hop: dict[tuple[str, str], RequestRecord] = {}
    for r in recs:
        k = (r.session_id or "", r.request_id)
        if k not in last_hop or r.redirect_hop > last_hop[k].redirect_hop:
            last_hop[k] = r
    for qe in req_body_events:
        raw = qe.raw_event
        for r in recs:
            if r.session_id == qe.session_id and r.request_id == qe.request_id and r.url == raw.get("url") and r.method == raw.get("method"):
                r.request_body_reference = raw.get("path") or f"unavailable:{raw.get('status')}"
                break
    unavailable = [{"url": b.raw_event.get("url"), "status": b.raw_event.get("status"), "error": b.raw_event.get("error")}
                   for b in body_events + req_body_events if b.raw_event.get("status") in ("unavailable", "skipped_too_large", "skipped_queue_full")]
    REPLAY_EXTRAS.clear()
    REPLAY_EXTRAS.update({
        "unsupported_or_partial_targets": targets, "bodies_unavailable": unavailable[:50], "bodies_unavailable_count": len(unavailable),
        "request_body_statuses": _count(b.raw_event.get("status") for b in req_body_events),
        "response_body_statuses": _count(b.raw_event.get("status") for b in body_events)})
    channels["service_workers_reported"] = targets["service_workers_reported"]
    channels["not_instrumented"] = NOT_INSTRUMENTED
    REPLAY_EXTRAS["observed_channels"] = channels
    first_path: dict[str, str] = {}
    for be in body_events:  # first capture per dedupe key
        if be.raw_event.get("path") and be.raw_event.get("dedupe_key"):
            first_path.setdefault(be.raw_event["dedupe_key"], be.raw_event["path"])
    bodies: dict[str, dict[str, Any]] = {}
    for be in body_events:
        r = last_hop.get((be.session_id or "", be.request_id or ""))
        raw = dict(be.raw_event)
        raw["event_id"] = be.event_id
        if r is None:
            continue
        st = raw.get("status")
        if st in ("duplicate_static_url", "skipped_endpoint_limit"):
            src = first_path.get(raw.get("dedupe_key", ""))
            tag = "duplicate_of" if st == "duplicate_static_url" else "endpoint_limit_see"
            r.response_body_reference = f"{tag}:{src}" if src else st
            continue  # no body of its own; findings come from the original capture
        r.response_body_reference = raw.get("path") or (f"not_captured:{st}" if str(st).startswith("skipped") else f"unavailable:{st}")
        bodies[r.record_id] = raw
    return corr, bodies


def export_scan(scan_dir: Path, *, completion_status: str | None = None) -> dict[str, Any]:
    scan_dir = Path(scan_dir)
    status = completion_status or detect_status(scan_dir)
    db = SqliteEventStore(scan_dir / "scan.sqlite")
    try:
        meta: dict[str, Any] = db.get_meta("scan_metadata", {}) or {}
        meta["completion_status"] = status
        corr, bodies = replay(db)
        records = corr.records
        files: dict[str, dict[str, Any]] = {}

        def events_rows() -> Iterator[dict[str, Any]]:
            for ev in db.iter_events():
                d = ev.model_dump(mode="json")
                link = corr.links.get(ev.event_id)
                if link:
                    d["correlation_status"] = link.status
                    d["redirect_hop"] = link.redirect_hop
                yield d

        files["network_events.jsonl"] = {"records": _write_jsonl(scan_dir / "network_events.jsonl", events_rows())}
        files["requests.jsonl"] = {"records": _write_jsonl(scan_dir / "requests.jsonl", (r.model_dump(mode="json") for r in records))}
        endpoints = build_inventory(records, bodies)
        files["endpoints.jsonl"] = {"records": _write_jsonl(scan_dir / "endpoints.jsonl", iter(endpoints))}
        pages = db.load_json("pages")
        files["pages.jsonl"] = {"records": _write_jsonl(scan_dir / "pages.jsonl", iter(pages))}
        db.replace_table("requests", "record_id", [(r.record_id, r.model_dump_json()) for r in records])

        crawl_cov = dict(db.get_meta("coverage", {}) or {})
        crawl_cov["write_readback"] = _write_readback(scan_dir, crawl_cov, records, bodies)
        diag = db.get_meta("diagnostics", {}) or {}
        findings, rule_errors = analyze(RuleContext(records=records, bodies=bodies, allowed_origins=meta.get("allowed_origins", []),
                                                    endpoints=endpoints))
        coverage = {
            "schema_version": SCHEMA_VERSION,
            "allowed_origins": meta.get("allowed_origins", []),
            "crawl": crawl_cov,
            "collector_diagnostics": diag,
            "correlation": corr.stats,
            "incomplete_requests": sum(1 for r in records if r.capture_status in ("incomplete", "evicted")),
            "body_capture": {"statuses": REPLAY_EXTRAS.get("response_body_statuses", {}),
                             "request_body_statuses": REPLAY_EXTRAS.get("request_body_statuses", {}),
                             "unavailable_count": REPLAY_EXTRAS.get("bodies_unavailable_count", 0),
                             "unavailable_examples": REPLAY_EXTRAS.get("bodies_unavailable", [])[:10],
                             "capturer": (diag.get("bodies") or {})},
            "unsupported_or_partial_targets": REPLAY_EXTRAS.get("unsupported_or_partial_targets", {}),
            "observed_channels": REPLAY_EXTRAS.get("observed_channels", {}),
            "failures_by_class": classify_failures(records),
            "skipped_scope_origins": skipped_scope_origins(pages, meta.get("allowed_origins", [])),
            "session_label": (meta.get("configuration") or {}).get("session_label"),
            "mode": (meta.get("configuration") or {}).get("mode", "crawl"),
            "pages_failed_or_timeout": [{"url": p["url"], "status": p["navigation_status"], "note": p.get("note")}
                                        for p in pages if p["navigation_status"] in ("failed", "timeout")][:25],
            "rule_errors": rule_errors,
            "limitations": STATIC_LIMITATIONS,
        }
        (scan_dir / "coverage.json").write_text(json.dumps(coverage, indent=2, default=str), encoding="utf-8")
        files["coverage.json"] = {}
        (scan_dir / "findings.json").write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8")
        files["findings.json"] = {"records": len(findings)}
        db.replace_table("findings", "finding_id", [(f.finding_id, f.model_dump_json()) for f in findings])
        # report.md lists file checksums, so hash the data files first (report/manifest are listed in manifest.json itself)
        (scan_dir / "scan_metadata.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
        files["scan_metadata.json"] = {}
        pre = {n: {"bytes": (scan_dir / n).stat().st_size, "sha256": _sha256(scan_dir / n)} for n in files if (scan_dir / n).exists()}
        (scan_dir / "report.md").write_text(render_report(meta, findings, records, endpoints, pages, coverage, pre), encoding="utf-8")
        files["report.md"] = {}

        manifest = _manifest(scan_dir, meta, files, diag, coverage, status)
        (scan_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest
    finally:
        db.close()


def _write_readback(scan_dir: Path, crawl: dict[str, Any], records: list[RequestRecord], bodies: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Evidence about writes: (1) every state-changing request actually observed and whether it COMPLETED, (2) did our text markers come back
    in response bodies, (3) uploaded file names (file contents cannot be confirmed from JSON responses)."""
    actions = crawl.get("write_actions", [])
    write_reqs = [r for r in records if r.method not in ("GET", "HEAD", "OPTIONS") and not r.is_preflight]
    summary = {"observed": len(write_reqs), "completed": sum(1 for r in write_reqs if r.state == "finished" and r.response_status and r.response_status < 400),
               "http_error": sum(1 for r in write_reqs if r.response_status and r.response_status >= 400),
               "failed_or_aborted": sum(1 for r in write_reqs if r.state in ("failed", "incomplete", "requested", "response_received")),
               "requests": [{"method": r.method, "url": r.normalized_url, "status": r.response_status, "state": r.state, "failure": r.failure_reason,
                             "payload": r.request_body_reference, "record": r.record_id} for r in write_reqs[:60]]}
    out: dict[str, Any] = {"write_requests": summary}
    markers = sorted({a["marker"] for a in actions if a.get("marker") and a["kind"] in ("form_submit", "dialog_submit", "control_click")})
    files = [{"file": a["file"], "page": a["page"], "button": a.get("button")} for a in actions if a["kind"] == "file_upload"]
    for a in actions:  # file fields filled inside a form/dialog ("name<-file")
        for f in a.get("fields", []) or []:
            if "<-" in f and a["kind"] in ("form_submit", "dialog_submit"):
                files.append({"file": f.split("<-", 1)[1], "page": a["page"], "button": a.get("button")})
    out["file_uploads_attempted"] = files
    if files:
        out["file_upload_note"] = ("file contents are not returned inline by JSON APIs; confirm uploads via the matching write request status above "
                                   "and by checking the application (look for files named webaudit-test-sample.*)")
    if not markers:
        out.update({"checked": False, "note": "no automatic text writes with a marker were performed" + (" (only file uploads)" if files else "")})
        return out
    if not bodies:
        out.update({"checked": False, "markers": markers, "note": "response bodies were not captured; re-run with --body-mode selected to confirm read-back"})
        return out
    by_id = {r.record_id: r for r in records}
    found: dict[str, list[dict[str, str]]] = {}
    for rid, b in bodies.items():
        path = b.get("path")
        r = by_id.get(rid)
        if not path or not r or not path.startswith("bodies/body-"):
            continue
        try:
            text = (scan_dir / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in markers:
            if m in text:
                found.setdefault(m, []).append({"method": r.method, "url": r.url[:140], "body": path})
    out.update({"checked": True, "markers": markers, "confirmed": {m: found[m][:8] for m in found},
                "unconfirmed": [m for m in markers if m not in found],
                "note": "marker found in response bodies = the written data was returned by the application when read back (GET) or echoed (POST)"})
    return out


def _count(it: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for x in it:
        out[str(x)] = out.get(str(x), 0) + 1
    return out


def _manifest(scan_dir: Path, meta: dict[str, Any], files: dict[str, dict[str, Any]], diag: dict[str, Any],
              coverage: dict[str, Any], status: str) -> dict[str, Any]:
    entries = {}
    for name, info in files.items():
        p = scan_dir / name
        if p.exists():
            entries[name] = {"bytes": p.stat().st_size, "sha256": _sha256(p), **info}
    body_files = {}
    bdir = scan_dir / "bodies"
    if bdir.exists():
        for p in sorted(bdir.glob("*.txt")):
            body_files[f"bodies/{p.name}"] = {"bytes": p.stat().st_size, "sha256": _sha256(p)}
    queue = (diag or {}).get("queue", {})
    errors = list(queue.get("errors", [])) + list((diag.get("cdp", {}) or {}).get("failures", [])) \
        + list((diag.get("playwright", {}) or {}).get("errors", []))
    if queue.get("dropped"):
        errors.append(f"{queue['dropped']} events dropped due to a full queue: {queue.get('dropped_by_type')}")
    for e in ((coverage.get("crawl") or {}).get("errors") or [])[:50]:
        errors.append(f"crawler {e.get('phase')} on {e.get('url')}: {e.get('error')} (the scan continued)")
    if queue.get("late_after_close"):
        errors.append(f"{queue['late_after_close']} events arrived after collection was finalized (shutdown race, not stored)")
    cfg = meta.get("configuration", {})
    return {
        "manifest_version": "1.0", "schema_version": SCHEMA_VERSION, "tool_version": __version__,
        "scan_id": meta.get("scan_id"), "completion_status": status,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": entries, "body_artifacts": body_files,
        "capture_settings": {"body": cfg.get("body"), "scope_enforcement": cfg.get("scope_enforcement"),
                             "block_unsafe_methods": cfg.get("block_unsafe_methods"), "crawl": cfg.get("crawl")},
        "redaction": {"headers": "sensitive header values replaced", "urls": "sensitive query values replaced",
                      "bodies": "redacted by default", "raw_bodies_exported": False, "perfect": False},
        "collection_errors": errors, "coverage_limitations": coverage.get("limitations", []),
    }
