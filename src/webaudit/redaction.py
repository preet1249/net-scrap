"""Best-effort redaction. This reduces accidental exposure; it is NOT guaranteed to catch every secret."""
from __future__ import annotations

import json
import re
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit, urlunsplit, quote

REDACTED = "[REDACTED"

SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token", "x-amz-security-token", "x-access-token", "x-session-id",
}
SENSITIVE_NAME_RE = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|apikey|auth|session|sess|credential|signature|sig|"
    r"private|bearer|jwt|csrf|xsrf|otp|code|ssn|card|cvv)", re.I)
PII_KEY_RE = re.compile(r"(e-?mail|phone|ssn|social|dob|birth|address|iban|passport|card|salary)", re.I)

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt", JWT_RE),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_secret_key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("generic_assigned_secret", re.compile(
        r"""(?ix)(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token|client[_-]?secret)
        ["']?\s*[:=]\s*["']([A-Za-z0-9_\-/+=.]{12,})["']""")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*")),
]
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def mark(value: str) -> str:
    return f"{REDACTED}:{len(value)}chars]"


def sample(value: str) -> str:
    """Short redacted sample safe for reports: first 2 chars + length."""
    return f"{value[:2]}…[{len(value)} chars]" if len(value) > 4 else "…[short]"


SAFE_HEADER_PREFIXES = ("access-control-", "content-security-policy", "cross-origin-")
SAFE_HEADERS = {":authority", "x-content-type-options", "x-frame-options", "strict-transport-security", "referrer-policy",
                "cache-control", "content-type", "content-length", "content-encoding", "host", "origin", "vary", "permissions-policy",
                "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-websocket-accept", "sec-websocket-extensions"}
URL_HEADERS = {"location", "referer", "content-location"}


def redact_header_value(name: str, value: str) -> str:
    lname = name.lower()
    if lname == "set-cookie":
        out = []
        for line in value.split("\n"):  # CDP joins repeated Set-Cookie headers with newlines
            first, _, attrs = line.partition(";")
            cname, eq, cval = first.partition("=")
            out.append(f"{cname}{eq}{mark(cval)}" + (";" + attrs if attrs else ""))
        return "\n".join(out)
    if lname == "cookie":
        parts = []
        for piece in value.split(";"):
            n, eq, v = piece.strip().partition("=")
            parts.append(f"{n}{eq}{mark(v)}" if eq else n)
        return "; ".join(parts)
    if lname in URL_HEADERS:
        return redact_url(value)
    if lname.startswith(SAFE_HEADER_PREFIXES) or lname in SAFE_HEADERS:
        return value  # security-relevant policy headers must stay readable as evidence
    if lname in SENSITIVE_HEADERS or SENSITIVE_NAME_RE.search(lname):
        scheme, _, rest = value.partition(" ")
        if lname in ("authorization", "proxy-authorization") and rest:
            return f"{scheme} {mark(rest)}"
        return mark(value)
    return value


def redact_headers(headers: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(headers, dict):
        return headers
    return {k: redact_header_value(k, v) if isinstance(v, str) else v for k, v in headers.items()}


def redact_url(url: str) -> str:
    """Redact query-parameter values that look sensitive, userinfo, and JWT-like path/query pieces."""
    if not isinstance(url, str):
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if parts.scheme in ("data", "blob", "javascript"):
        return f"{parts.scheme}:{REDACTED}:omitted]"
    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        out = []
        for k, v in pairs:
            if SENSITIVE_NAME_RE.search(k) or JWT_RE.search(v) or len(v) >= 32 and re.fullmatch(r"[A-Za-z0-9_\-+/=]+", v):
                v = mark(v)
            out.append(f"{quote(k, safe='')}={v}")
        query = "&".join(out)
    path = JWT_RE.sub(lambda m: mark(m.group(0)), parts.path)
    fragment = REDACTED + ":fragment]" if parts.fragment and SENSITIVE_NAME_RE.search(parts.fragment) else parts.fragment
    return urlunsplit((parts.scheme, netloc, path, query, fragment))


_URL_KEYS = {"url", "documentURL", "urlFragment", "origin", "initiator_url", "redirectUrl", "wallTime_url"}
_HEADER_KEYS = {"headers", "requestHeaders", "responseHeaders"}


def redact_event(obj: Any, *, _key: str = "") -> Any:
    """Recursively redact a raw protocol event (deep copy; input untouched)."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k in _HEADER_KEYS and isinstance(v, dict):
                out[k] = redact_headers(v)
            elif k in _HEADER_KEYS and isinstance(v, list):  # Playwright headers_array: [[name, value], ...]
                out[k] = [[p[0], redact_header_value(p[0], p[1])] if isinstance(p, (list, tuple)) and len(p) == 2
                          and isinstance(p[0], str) and isinstance(p[1], str) else p for p in v]
            elif k.lower().endswith("headerstext") and isinstance(v, str):
                out[k] = _redact_headers_text(v)
            elif k == "postData" and isinstance(v, str):
                out[k] = redact_post_data(v)
            elif k == "postDataEntries" and isinstance(v, list):
                out[k] = [{"bytes": mark(e.get("bytes", ""))} if isinstance(e, dict) else e for e in v]
            elif k == "payloadData" and isinstance(v, str):  # websocket frame payload
                out[k] = mark(v)
            elif k == "associatedCookies" and isinstance(v, list):
                out[k] = [_redact_cookie_assoc(c) for c in v]
            elif k in ("url", "documentURL", "redirectUrl", "frame_url", "page_url_at_attach", "initiator_url") and isinstance(v, str):
                out[k] = redact_url(v)
            else:
                out[k] = redact_event(v, _key=k)
        return out
    if isinstance(obj, list):
        return [redact_event(i, _key=_key) for i in obj]
    if isinstance(obj, str):
        return JWT_RE.sub(lambda m: mark(m.group(0)), obj) if "eyJ" in obj else obj
    return obj


def redact_post_data(text: str) -> str:
    """Keep field NAMES (useful for the API inventory) but never values."""
    try:
        def blank(o: Any) -> Any:
            if isinstance(o, dict):
                return {k: blank(v) for k, v in o.items()}
            if isinstance(o, list):
                return [blank(v) for v in o[:50]]
            return f"{REDACTED}:value]"
        obj = json.loads(text)
        if isinstance(obj, (dict, list)):
            return json.dumps(blank(obj))
    except ValueError:
        pass
    if "=" in text and "\n" not in text and len(text) < 100_000:
        return "&".join(f"{quote(k, safe='')}={REDACTED}:value]" for k, _ in parse_qsl(text, keep_blank_values=True))
    return mark(text)


def _redact_cookie_assoc(c: Any) -> Any:
    if isinstance(c, dict):
        out = dict(c)
        ck = out.get("cookie")
        if isinstance(ck, dict):
            ck = dict(ck)
            if isinstance(ck.get("value"), str):
                ck["value"] = mark(ck["value"])
            out["cookie"] = ck
        return out
    return c


def _redact_headers_text(text: str) -> str:
    lines = []
    for line in text.split("\r\n"):
        n, sep, v = line.partition(":")
        lines.append(f"{n}:{' ' + redact_header_value(n, v.strip())}" if sep else line)
    return "\r\n".join(lines)


def redact_header_entries(entries: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(n, redact_header_value(n, v)) for n, v in entries]


# ---- bodies -----------------------------------------------------------------------------------

def _jwt_meta(token: str) -> dict[str, Any]:
    """Non-secret JWT facts used to tell public anon keys from privileged tokens: header alg and the payload 'role' claim only."""
    import base64
    out: dict[str, Any] = {}
    try:
        h, p, _ = token.split(".")
        pad = lambda x: x + "=" * (-len(x) % 4)
        alg = json.loads(base64.urlsafe_b64decode(pad(h))).get("alg")
        role = json.loads(base64.urlsafe_b64decode(pad(p))).get("role")
        if isinstance(alg, str) and len(alg) < 20:
            out["jwt_alg"] = alg
        if isinstance(role, str) and len(role) < 40:
            out["jwt_role"] = role
    except Exception:
        pass
    return out


def scan_text_for_secrets(text: str) -> list[dict[str, Any]]:
    """Return candidate secret locations with redacted samples only (never raw values)."""
    cands: list[dict[str, Any]] = []
    for kind, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            if kind == "generic_assigned_secret" and not (re.search(r"\d", val) and re.search(r"[A-Za-z]", val)):
                continue
            if kind == "generic_assigned_secret" and JWT_RE.fullmatch(val):
                continue  # already reported (with role classification) by the dedicated jwt pattern  # identifier-like words (e.g. 'accessToken') are overwhelmingly code, not credentials
            line = text.count("\n", 0, m.start()) + 1
            c: dict[str, Any] = {"type": kind, "offset": m.start(), "line": line, "redacted_sample": sample(val)}
            if kind == "jwt":
                c.update(_jwt_meta(val))
            cands.append(c)
            if len(cands) >= 50:
                return cands
    return cands


def redact_text(text: str) -> str:
    def rep(m: re.Match[str]) -> str:
        val = m.group(1) if m.groups() else m.group(0)
        return m.group(0).replace(val, mark(val)) if m.groups() else mark(val)

    for _, rx in SECRET_PATTERNS:
        text = rx.sub(rep, text)
    text = SSN_RE.sub(lambda m: mark(m.group(0)), text)
    text = EMAIL_RE.sub(lambda m: mark(m.group(0)), text)
    return text


def redact_json_value(obj: Any, key: str = "") -> Any:
    if isinstance(obj, dict):
        return {k: redact_json_value(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_json_value(v, key) for v in obj]
    if isinstance(obj, str):
        if SENSITIVE_NAME_RE.search(key) or PII_KEY_RE.search(key):
            return mark(obj)
        return redact_text(obj)
    if isinstance(obj, (int, float)) and not isinstance(obj, bool) and PII_KEY_RE.search(key):
        return f"{REDACTED}:number]"
    return obj


def redact_body(text: str, mime: str | None) -> str:
    """Redact a captured text body. JSON is key-aware; anything else uses pattern redaction."""
    if mime and "json" in mime.lower():
        try:
            return json.dumps(redact_json_value(json.loads(text)), ensure_ascii=False)
        except ValueError:
            pass
    return redact_text(text)


def sensitive_json_keys(text: str) -> list[str]:
    """Names (not values) of PII/credential-like keys in a JSON body."""
    found: set[str] = set()

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if PII_KEY_RE.search(k) or SENSITIVE_NAME_RE.search(k):
                    found.add(k)
                walk(v)
        elif isinstance(o, list):
            for v in o[:200]:
                walk(v)

    try:
        walk(json.loads(text))
    except ValueError:
        pass
    return sorted(found)


DEBUG_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("python_traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("java_stack_trace", re.compile(r"\bat [\w.$]+\([\w.]+\.java:\d+\)")),
    ("js_stack_trace", re.compile(r"\bat .{1,80}\(.{1,200}:\d+:\d+\)")),
    ("sql_error", re.compile(r"(?i)\b(SQLSTATE\[|SQL syntax.*MySQL|ORA-\d{5}|PG::\w+Error|sqlite3\.OperationalError)")),
    ("debug_flag", re.compile(r"(?i)[\"']?(debug|stack_?trace|trace)[\"']?\s*[:=]\s*(true|[\"'])")),
    ("internal_path", re.compile(r"(?:[A-Za-z]:\\\\|/)(?:home|var|usr|srv|opt|app|Users)/[\w./-]{4,}")),
]


def scan_debug_indicators(text: str) -> list[str]:
    """Names of debug/diagnostic indicator classes present (no matched text is returned)."""
    return sorted({name for name, rx in DEBUG_PATTERNS if rx.search(text)})
