"""Endpoint inventory built from correlated request records (observed traffic only — NOT a complete API surface)."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable
from urllib.parse import urlsplit

from .models import HeaderEntry, RequestRecord
from .urlnorm import normalize_path


def header_values(entries: Iterable[HeaderEntry], name: str) -> list[str]:
    """Distinct values for a header across sources (primary/extra_info/playwright report the same header)."""
    seen: list[str] = []
    for e in entries:
        if e.name.lower() == name and e.value not in seen:
            seen.append(e.value)
    return seen


def build_inventory(records: list[RequestRecord], bodies: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for r in records:
        p = urlsplit(r.url)
        if not p.scheme.startswith("http"):
            continue
        origin = f"{p.scheme}://{p.netloc}"
        key = (r.method, origin, normalize_path(p.path))
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "method": r.method, "origin": origin, "normalized_path": key[2], "count": 0, "status_codes": defaultdict(int),
                "content_types": set(), "resource_types": set(), "query_param_names": set(), "payload_field_names": set(),
                "auth_indicators": set(), "redirect_responses": 0, "failures": 0, "preflight": False,
                "cache_control": set(), "cors": {"allow_origin": set(), "allow_credentials": set()},
                "evidence": [], "from_service_worker": False, "initiators": set(),
            }
        g["count"] += 1
        if r.response_status is not None:
            g["status_codes"][str(r.response_status)] += 1
        if r.response_mime_type:
            g["content_types"].add(r.response_mime_type)
        for ct in header_values(r.response_headers, "content-type"):
            g["content_types"].add(ct.split(";")[0].strip().lower())
        if r.resource_type:
            g["resource_types"].add(r.resource_type)
        g["query_param_names"].update(r.query_param_names)
        g["payload_field_names"].update(r.post_data_keys)
        if header_values(r.request_headers, "authorization"):
            g["auth_indicators"].add("authorization_header")
        if header_values(r.request_headers, "cookie"):
            g["auth_indicators"].add("cookie_sent")
        if r.response_status in (401, 403):
            g["auth_indicators"].add(f"http_{r.response_status}")
        if header_values(r.response_headers, "www-authenticate"):
            g["auth_indicators"].add("www_authenticate")
        if r.state == "redirected":
            g["redirect_responses"] += 1
        if r.state == "failed":
            g["failures"] += 1
        if r.is_preflight:
            g["preflight"] = True
        g["cache_control"].update(header_values(r.response_headers, "cache-control"))
        g["cors"]["allow_origin"].update(header_values(r.response_headers, "access-control-allow-origin"))
        g["cors"]["allow_credentials"].update(header_values(r.response_headers, "access-control-allow-credentials"))
        g["from_service_worker"] = g["from_service_worker"] or r.from_service_worker
        if r.initiator_summary and len(g["initiators"]) < 8:
            g["initiators"].add(r.initiator_summary)
        if len(g["evidence"]) < 5:
            g["evidence"].append(f"request:{r.record_id}")
    out = []
    for g in groups.values():
        d = dict(g)
        d["status_codes"] = dict(g["status_codes"])
        for k in ("content_types", "resource_types", "query_param_names", "payload_field_names", "auth_indicators", "cache_control", "initiators"):
            d[k] = sorted(g[k])
        d["cors"] = {k: sorted(v) for k, v in g["cors"].items()}
        d["response_variants"] = len(g["status_codes"]) > 1 or len(g["content_types"]) > 1
        out.append(d)
    out.sort(key=lambda d: (d["origin"], d["normalized_path"], d["method"]))
    return out
