"""URL normalisation for endpoint identity. Query strings are never part of the identifier."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NUM = re.compile(r"^\d+$")
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{24,}$")


def normalize_segment(seg: str) -> str:
    if _NUM.match(seg):
        return "{id}"
    if _UUID.match(seg):
        return "{uuid}"
    if _HEX.match(seg):
        return "{hex}"
    if _TOKEN.match(seg) and any(c.isdigit() for c in seg):
        return "{token}"
    return seg


def normalize_path(path: str) -> str:
    segs = [normalize_segment(s) for s in path.split("/")]
    return "/".join(segs) or "/"


def normalize_url(url: str) -> str:
    try:
        p = urlsplit(url)
    except ValueError:
        return url
    if not p.scheme or p.scheme in ("data", "blob"):
        return f"{p.scheme}:"
    return f"{p.scheme}://{p.netloc}{normalize_path(p.path)}"


def query_names(url: str) -> list[str]:
    try:
        return sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})
    except ValueError:
        return []


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""
