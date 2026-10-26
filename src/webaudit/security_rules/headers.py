"""Response-header, mixed-content and cookie rules."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional
from urllib.parse import urlsplit

from ..inventory import header_values
from ..models import Finding, RequestRecord
from .base import RuleContext, make_finding, ref

HSTS_MIN_AGE = 15_552_000  # 180 days


def parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if toks and toks[0].lower() not in out:
            out[toks[0].lower()] = toks[1:]
    return out


def csp_script_issues(policy: dict[str, list[str]]) -> list[str]:
    src = policy.get("script-src") or policy.get("script-src-elem") or policy.get("default-src")
    if src is None:
        return ["no script-src/default-src: script sources are unrestricted"]
    low = [s.lower() for s in src]
    issues = []
    has_nonce = any(s.startswith("'nonce-") or s.startswith("'sha") for s in low)
    if "'unsafe-inline'" in low and not (has_nonce or "'strict-dynamic'" in low):
        issues.append("'unsafe-inline' allows inline scripts")
    if "'unsafe-eval'" in low:
        issues.append("'unsafe-eval' allows eval-like APIs")
    for s in low:
        if s in ("*", "https:", "http:", "data:", "blob:") or s.startswith("*."):
            issues.append(f"broad script source '{s}'")
    return issues


def _by_origin(ctx: RuleContext, docs: list[RequestRecord]) -> dict[str, list[RequestRecord]]:
    d: dict[str, list[RequestRecord]] = defaultdict(list)
    for r in docs:
        d[ctx.origin(r)].append(r)
    return d


def rule_headers(ctx: RuleContext) -> list[Finding]:
    out: list[Finding] = []
    lim_doc = ("Evaluated on in-scope HTML document responses actually observed; other pages/routes may differ. A header set by a CDN/proxy "
               "only for some paths, or removed before the browser saw it, is outside what this check can establish.")
    for origin, docs in _by_origin(ctx, ctx.documents()).items():
        https = origin.startswith("https://")
        ev = [ref(r) for r in docs[:5]]
        n = len(docs)

        # HSTS
        if https:
            missing = [r for r in docs if not header_values(r.response_headers, "strict-transport-security")]
            if missing:
                out.append(make_finding("HDR-HSTS", origin, title="Strict-Transport-Security header not observed", severity="low",
                    confidence="high", status="observed",
                    description=f"{len(missing)} of {n} HTML document response(s) from {origin} had no Strict-Transport-Security header.",
                    evidence=[ref(r) for r in missing[:5]], impact="Browsers may be downgraded to HTTP on first visit or after expiry (SSL stripping).",
                    limitations=lim_doc + " HSTS is only honoured over HTTPS and preload-list membership is not checked.",
                    remediation="Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses once HTTPS is fully deployed.",
                    verification=["Fetch the origin with a header-aware client and confirm the header on the main document."]))
            else:
                for r in docs:
                    v = header_values(r.response_headers, "strict-transport-security")[0]
                    m = re.search(r"max-age\s*=\s*(\d+)", v, re.I)
                    if not m or int(m.group(1)) < HSTS_MIN_AGE:
                        out.append(make_finding("HDR-HSTS-WEAK", origin, title="Strict-Transport-Security max-age is short or invalid", severity="low",
                            confidence="high", status="observed", description=f"Observed HSTS value: {v!r}.", evidence=[ref(r)],
                            limitations=lim_doc, remediation="Use max-age of at least 15552000 (180 days), ideally 31536000."))
                        break
        else:
            out.append(make_finding("HDR-NOTLS", origin, title="Document served over HTTP", severity="medium" if not _is_local(origin) else "info",
                confidence="high", status="observed", description=f"{origin} served HTML documents without TLS; HSTS is not applicable.",
                evidence=ev, limitations="Local development origins are expected to use HTTP.",
                remediation="Serve the application over HTTPS only and redirect HTTP to HTTPS."))

        # CSP
        enforced = [(r, header_values(r.response_headers, "content-security-policy")) for r in docs]
        no_csp = [r for r, v in enforced if not v]
        if no_csp:
            report_only = any(header_values(r.response_headers, "content-security-policy-report-only") for r in no_csp)
            out.append(make_finding("HDR-CSP-MISSING", origin, title="Content-Security-Policy not enforced" + (" (report-only observed)" if report_only else ""),
                severity="medium" if not report_only else "low", confidence="high", status="observed",
                description=f"{len(no_csp)} of {n} HTML document response(s) from {origin} lacked an enforced Content-Security-Policy header.",
                evidence=[ref(r) for r in no_csp[:5]], impact="Reduces defence-in-depth against XSS and data injection; absence alone is not a vulnerability.",
                limitations=lim_doc + " CSP delivered via <meta http-equiv> is not examined.",
                remediation="Deploy a restrictive CSP (nonce/hash-based script-src, object-src 'none', base-uri 'self', frame-ancestors).",
                verification=["Confirm in DevTools > Network that no CSP header exists on the document response."]))
        for r, vals in enforced:
            if not vals:
                continue
            pols = [parse_csp(v) for v in vals]
            issue_sets = [csp_script_issues(p) for p in pols]
            if all(issue_sets):  # every enforced policy is permissive for scripts
                issues = sorted({i for s in issue_sets for i in s})
                out.append(make_finding("HDR-CSP-PERMISSIVE", origin, title="Content-Security-Policy has permissive script directives",
                    severity="medium", confidence="high", status="observed",
                    description="; ".join(issues) + ".", evidence=[ref(r)],
                    impact="A permissive script policy weakens CSP's ability to contain XSS.",
                    limitations="Policy semantics were evaluated statically; nonce-based policies and browser-specific fallbacks may behave differently.",
                    remediation="Remove 'unsafe-inline'/'unsafe-eval' and wildcard/scheme sources; use nonces or hashes.",
                    verification=["Review the full policy text in the evidence record and test with a CSP evaluator."]))
                break
            if all("object-src" not in p and "default-src" not in p for p in pols):
                out.append(make_finding("HDR-CSP-OBJECT", origin, title="CSP does not restrict object-src", severity="low", confidence="medium",
                    status="observed", description="No object-src or default-src directive was present.", evidence=[ref(r)],
                    limitations=lim_doc, remediation="Add object-src 'none'."))
                break

        # nosniff
        bad = [r for r in docs if "nosniff" not in [v.lower() for v in header_values(r.response_headers, "x-content-type-options")]]
        if bad:
            out.append(make_finding("HDR-XCTO", origin, title="X-Content-Type-Options: nosniff not observed", severity="low", confidence="high",
                status="observed", description=f"{len(bad)} of {n} document response(s) lacked 'X-Content-Type-Options: nosniff'.",
                evidence=[ref(r) for r in bad[:5]], impact="MIME-sniffing can reinterpret content types in older/edge cases.", limitations=lim_doc,
                remediation="Send 'X-Content-Type-Options: nosniff' on all responses."))

        # framing
        def framed(r: RequestRecord) -> bool:
            csps = [parse_csp(v) for v in header_values(r.response_headers, "content-security-policy")]
            return any("frame-ancestors" in p for p in csps) or bool(header_values(r.response_headers, "x-frame-options"))
        unframed = [r for r in docs if not framed(r)]
        if unframed:
            out.append(make_finding("HDR-FRAME", origin, title="No frame-protection policy observed (frame-ancestors / X-Frame-Options)",
                severity="medium", confidence="medium", status="observed",
                description=f"{len(unframed)} of {n} document response(s) had neither CSP frame-ancestors nor X-Frame-Options.",
                evidence=[ref(r) for r in unframed[:5]], impact="Pages may be embeddable by other origins, enabling clickjacking where sensitive actions exist.",
                limitations=lim_doc + " Impact depends on whether the page contains state-changing UI and relies on cookies for auth.",
                remediation="Add 'Content-Security-Policy: frame-ancestors 'none'' (or 'self') and/or 'X-Frame-Options: DENY'.",
                verification=["Attempt to embed an authenticated page in an iframe from a test origin you control."]))

        # referrer
        refs = [(r, header_values(r.response_headers, "referrer-policy")) for r in docs]
        weak = [r for r, v in refs if v and v[-1].lower().split(",")[-1].strip() in ("unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin")]
        if weak:
            out.append(make_finding("HDR-REFERRER", origin, title="Referrer-Policy may leak full URLs", severity="low", confidence="high",
                status="observed", description="Referrer-Policy permits sending full URLs cross-origin.", evidence=[ref(r) for r in weak[:5]],
                limitations=lim_doc, remediation="Use 'strict-origin-when-cross-origin' or 'no-referrer'."))
        elif all(not v for _, v in refs):
            out.append(make_finding("HDR-REFERRER-MISSING", origin, title="Referrer-Policy header not set", severity="info", confidence="high",
                status="observed", description="No Referrer-Policy header; browsers apply their default (typically strict-origin-when-cross-origin).",
                evidence=ev, limitations=lim_doc, remediation="Set an explicit Referrer-Policy."))

    out.extend(_mixed_content(ctx))
    out.extend(_info_headers(ctx))
    return out


def _is_local(origin: str) -> bool:
    from ..config import is_local_host
    return is_local_host(urlsplit(origin).hostname)


def _mixed_content(ctx: RuleContext) -> list[Finding]:
    hits = [r for r in ctx.records if r.url.startswith("http://") and not _is_local(r.url) and
            (r.mixed_content_type or (r.document_url or "").startswith("https://"))]
    if not hits:
        return []
    blockable = [r for r in hits if r.mixed_content_type == "blockable" or r.resource_type in ("Script", "Stylesheet", "XHR", "Fetch", "Document")]
    return [make_finding("HDR-MIXED", "mixed", title="Mixed content indicators", severity="medium" if blockable else "low",
        confidence="medium", status="observed",
        description=f"{len(hits)} request(s) used http:// from an https:// document context (Chromium mixedContentType / document URL).",
        evidence=[ref(r) for r in hits[:8]], impact="Insecure subresources can be tampered with by a network attacker.",
        limitations="Chromium may auto-upgrade or block such requests; an observed request does not prove it succeeded. Evidence reflects the document URL at request time.",
        remediation="Load all subresources over HTTPS.")]


def _info_headers(ctx: RuleContext) -> list[Finding]:
    hits = [r for r in ctx.records if ctx.in_scope(r) and (header_values(r.response_headers, "x-powered-by") or
            re.search(r"/\d", " ".join(header_values(r.response_headers, "server")) or ""))]
    if not hits:
        return []
    vals = sorted({v for r in hits for v in header_values(r.response_headers, "x-powered-by") + header_values(r.response_headers, "server")})
    return [make_finding("HDR-BANNER", "banner", title="Server technology/version disclosure headers", severity="info", confidence="high",
        status="observed", description=f"Headers disclose technology/version information: {', '.join(vals[:5])}.",
        evidence=[ref(r) for r in hits[:5]], limitations="Disclosure is informational; it aids fingerprinting but is not itself exploitable.",
        remediation="Remove or generalize Server/X-Powered-By headers.")]


# ---- cookies ------------------------------------------------------------------------------------

SESSION_NAME_RE = re.compile(r"(sess|sid|auth|token|jwt|login|remember|csrf|xsrf)", re.I)


def parse_set_cookie(line: str) -> dict:
    first, *attrs = [p.strip() for p in line.split(";")]
    name, _, _ = first.partition("=")
    d = {"name": name.strip(), "secure": False, "httponly": False, "samesite": None, "domain": None, "path": None}
    for a in attrs:
        k, _, v = a.partition("=")
        k = k.lower()
        if k == "secure":
            d["secure"] = True
        elif k == "httponly":
            d["httponly"] = True
        elif k == "samesite":
            d["samesite"] = v.strip().lower()
        elif k in ("domain", "path"):
            d[k] = v.strip()
    return d


def rule_cookies(ctx: RuleContext) -> list[Finding]:
    issues: dict[tuple[str, str], list[str]] = defaultdict(list)
    names: dict[tuple[str, str], set[str]] = defaultdict(set)
    for r in ctx.records:
        if not ctx.in_scope(r):
            continue
        https = r.url.startswith("https://")
        seen: set[str] = set()
        for e in r.response_headers:
            if e.name.lower() != "set-cookie" or e.value in seen:
                continue
            seen.add(e.value)
            c = parse_set_cookie(e.value)
            sess = bool(SESSION_NAME_RE.search(c["name"]))
            def add(code: str) -> None:
                issues[(code, ctx.origin(r))].append(ref(r))
                names[(code, ctx.origin(r))].add(c["name"])
            if https and not c["secure"]:
                add("COOKIE-SECURE")
            if not c["httponly"] and sess:
                add("COOKIE-HTTPONLY")
            if c["samesite"] is None:
                add("COOKIE-SAMESITE")
            if c["samesite"] == "none" and not c["secure"]:
                add("COOKIE-SAMESITE-NONE-INSECURE")
            if c["name"].startswith("__Host-") and (not c["secure"] or c["path"] != "/" or c["domain"]):
                add("COOKIE-PREFIX")
    meta = {
        "COOKIE-SECURE": ("Cookie set without Secure attribute over HTTPS", "medium", "The cookie may be sent over plain HTTP if the browser ever requests an http:// URL of the site."),
        "COOKIE-HTTPONLY": ("Session-like cookie without HttpOnly", "medium", "Script running on the page (e.g., via XSS) can read the cookie."),
        "COOKIE-SAMESITE": ("Cookie without explicit SameSite attribute", "low", "Browsers default to Lax for such cookies; behaviour differs across browsers/versions."),
        "COOKIE-SAMESITE-NONE-INSECURE": ("SameSite=None cookie without Secure", "medium", "Browsers reject such cookies; indicates misconfiguration."),
        "COOKIE-PREFIX": ("__Host- cookie prefix requirements not met", "low", "Browsers will reject the cookie."),
    }
    out = []
    for (code, origin), evs in issues.items():
        title, sev, impact = meta[code]
        nm = sorted(names[(code, origin)])
        heuristic = code == "COOKIE-HTTPONLY"
        out.append(make_finding(code, origin, title=title, severity=sev, confidence="high" if not heuristic else "medium",  # type: ignore[arg-type]
            status="heuristic" if heuristic else "observed",
            description=f"Cookie name(s) {', '.join(nm[:6])} set by {origin} (values redacted).", evidence=evs[:8], impact=impact,
            limitations="Based on Set-Cookie headers visible to the browser instrumentation; cookie purpose is inferred from its name"
                        + (" (HttpOnly relevance is a heuristic)." if heuristic else "."),
            remediation="Set Secure, HttpOnly (for session cookies) and an explicit SameSite attribute.",
            verification=["Inspect the cookie in DevTools > Application > Cookies and confirm which cookie carries the session."]))
    return out
