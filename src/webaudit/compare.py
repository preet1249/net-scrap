"""Passive comparison of two existing scans (e.g. two test accounts YOU control). Sends no requests.

It highlights where two sessions saw the same object-specific URL or different results for the same endpoint. That is a pointer for manual
verification; it cannot prove or disprove an authorization flaw (shared/public data is legitimate and a block may be applied elsewhere).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .urlnorm import normalize_path

OBJECT_TYPES = {"Fetch", "XHR", "Document"}


def _jl(p: Path) -> list[dict[str, Any]]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []


def _label(d: Path) -> str:
    try:
        m = json.loads((d / "scan_metadata.json").read_text(encoding="utf-8"))
        return (m.get("configuration") or {}).get("session_label") or d.name
    except Exception:
        return d.name


def _body_hash(d: Path, ref: str | None) -> str | None:
    if not ref or not ref.startswith("bodies/"):
        return None
    p = d / ref
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16] if p.exists() else None


def _is_object_url(url: str) -> bool:
    u = urlsplit(url)
    return normalize_path(u.path) != u.path or any(k.lower().endswith(("id", "_id")) for k, _ in
                                                  (kv.partition("=")[::2] for kv in u.query.split("&") if kv))


def compare_scans(dir_a: Path, dir_b: Path) -> dict[str, Any]:
    ra, rb = _jl(dir_a / "requests.jsonl"), _jl(dir_b / "requests.jsonl")
    ea, eb = _jl(dir_a / "endpoints.jsonl"), _jl(dir_b / "endpoints.jsonl")
    key = lambda e: (e["method"], e["origin"], e["normalized_path"])  # noqa: E731
    ma, mb = {key(e): e for e in ea}, {key(e): e for e in eb}
    only_a = sorted("%s %s%s" % k for k in ma.keys() - mb.keys())
    only_b = sorted("%s %s%s" % k for k in mb.keys() - ma.keys())
    status_diff = [{"endpoint": "%s %s%s" % k, "a": sorted(ma[k]["status_codes"]), "b": sorted(mb[k]["status_codes"])}
                   for k in sorted(ma.keys() & mb.keys()) if set(ma[k]["status_codes"]) != set(mb[k]["status_codes"])]

    def ok_objects(rs: list[dict[str, Any]], d: Path) -> dict[tuple[str, str], dict[str, Any]]:
        out = {}
        for r in rs:
            if (r["resource_type"] in OBJECT_TYPES and not r["is_preflight"] and r["response_status"] and 200 <= r["response_status"] < 300
                    and _is_object_url(r["url"])):
                out[(r["method"], r["url"])] = {"hash": _body_hash(d, r.get("response_body_reference")), "ref": r["record_id"]}
        return out

    oa, ob = ok_objects(ra, dir_a), ok_objects(rb, dir_b)
    shared = []
    for k in sorted(oa.keys() & ob.keys()):
        ha, hb = oa[k]["hash"], ob[k]["hash"]
        shared.append({"request": f"{k[0]} {k[1]}", "both_succeeded": True,
                       "body_identical": (ha == hb) if (ha and hb) else None, "evidence": [f"A:{oa[k]['ref']}", f"B:{ob[k]['ref']}"]})
    return {"a": {"scan": dir_a.name, "label": _label(dir_a), "requests": len(ra), "endpoints": len(ea)},
            "b": {"scan": dir_b.name, "label": _label(dir_b), "requests": len(rb), "endpoints": len(eb)},
            "endpoints_only_in_a": only_a, "endpoints_only_in_b": only_b, "status_differences": status_diff,
            "object_urls_both_sessions_read_successfully": shared,
            "caveats": ["Passive comparison of existing evidence; no requests were sent.",
                        "An object URL fetched successfully by both sessions may be legitimately shared/public data; verify ownership manually.",
                        "Absence of overlap does not prove isolation; only URLs actually visited by each session are compared.",
                        "Verify with controlled tests on accounts and records you own, and review server-side policies (e.g. RLS) directly."]}


def render_markdown(c: dict[str, Any]) -> str:
    a, b = c["a"], c["b"]
    out = [f"# Session comparison: `{a['label']}` (scan {a['scan']}) vs `{b['label']}` (scan {b['scan']})\n",
           *[f"> {x}" for x in c["caveats"]], "",
           f"- Requests: {a['requests']} vs {b['requests']}  |  Endpoints: {a['endpoints']} vs {b['endpoints']}",
           f"- Endpoints only in A: {len(c['endpoints_only_in_a'])}  |  only in B: {len(c['endpoints_only_in_b'])}",
           f"- Same endpoint, different status codes: {len(c['status_differences'])}",
           f"- Object-specific URLs both sessions read successfully: {len(c['object_urls_both_sessions_read_successfully'])}\n"]
    if c["object_urls_both_sessions_read_successfully"]:
        out += ["## Object URLs read successfully by both sessions (review manually)\n", "| Request | Body identical | Evidence |", "|---|---|---|"]
        out += [f"| `{s['request'][:120]}` | {s['body_identical']} | {', '.join(s['evidence'])} |"
                for s in c["object_urls_both_sessions_read_successfully"][:100]]
    if c["status_differences"]:
        out += ["", "## Status differences per endpoint\n", "| Endpoint | A | B |", "|---|---|---|"]
        out += [f"| `{s['endpoint']}` | {s['a']} | {s['b']} |" for s in c["status_differences"][:100]]
    for title, items in (("Only in A", c["endpoints_only_in_a"]), ("Only in B", c["endpoints_only_in_b"])):
        if items:
            out += ["", f"## Endpoints {title}\n"] + [f"- `{i}`" for i in items[:100]]
    return "\n".join(out) + "\n"
