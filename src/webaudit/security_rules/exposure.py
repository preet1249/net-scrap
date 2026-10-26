"""Client-side exposure, sensitive data, third-party destinations, authorization candidates, caching."""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import parse_qsl, urlsplit

from ..inventory import header_values
from ..models import Finding
from ..urlnorm import normalize_path
from .base import RuleContext, make_finding, ref

HIGH_SPECIFICITY = {"aws_access_key_id", "private_key_block", "github_token", "slack_token", "stripe_secret_key"}
SECRET_LIM = ("Pattern-based detection of a candidate secret in a captured body; it can be a public identifier, a test/placeholder value or "
              "a false positive, and validity was NOT checked. The value is deliberately not shown.")


PRIVILEGED_ROLES = {"service_role", "supabase_admin", "admin", "superuser", "root"}


def rule_secrets(ctx: RuleContext) -> list[Finding]:
    """One finding per (asset URL, pattern, offset): the same script fetched several times is a single location."""
    grouped: dict[tuple[str, str, int], dict[str, Any]] = {}
    for rid, b in ctx.bodies.items():
        for c in b.get("secret_candidates") or []:
            k = (b.get("url") or "", c["type"], int(c.get("offset", 0)))
            g = grouped.setdefault(k, {"b": b, "c": c, "ev": []})
            g["ev"] += [f"request:{rid}", f"body:{b.get('body_id')}", f"event:{b.get('event_id')}"]
    out: list[Finding] = []
    for (url, kind, offset), g in grouped.items():
        b, c = g["b"], g["c"]
        hi = kind in HIGH_SPECIFICITY
        sev, conf = ("high" if hi else "medium"), ("medium" if hi else "low")
        title = f"Secret-looking value in client-visible response ({kind})"
        extra_lim = ""
        remediation = "Rotate the credential if valid, remove it from client-delivered assets, and use server-side secrets or short-lived tokens."
        steps = ["Locate the value in the original asset using the location below.",
                 "Determine whether it is a public identifier or a real secret, and rotate if secret."]
        if kind == "jwt":
            role = c.get("jwt_role")
            if role == "anon":
                sev, conf = "info", "medium"
                title = "Public-by-design JWT (role claim 'anon') embedded in client asset"
                extra_lim = (" The decoded 'role' claim is 'anon', which backends such as Supabase issue as a publishable key. It is harmless only if "
                             "authorization (e.g., row-level security) is enforced for that role; that was NOT tested.")
                remediation = "Confirm the key is the intended public/anon key and that backend policies restrict what the anon role can read or write."
                steps = ["Confirm the key is your project's public/anon key.", "In an authorized test, review RLS/authorization policies for the anon role."]
            elif role in PRIVILEGED_ROLES:
                sev, conf = "critical", "medium"
                title = f"Privileged-role JWT (role claim '{role}') embedded in client asset"
                extra_lim = " The 'role' claim was decoded from the token payload; token validity/expiry was NOT checked."
                remediation = "Treat as compromised: rotate the key immediately and keep privileged keys server-side only."
        elif kind == "google_api_key":
            extra_lim = " Google API keys are often public by design and restricted by referrer/API in the Google console."
        loc = f"{url} line {c.get('line')} offset {offset}"
        out.append(make_finding("EXP-SECRET", f"{url}|{kind}|{offset}", title=title, severity=sev, confidence=conf, status="heuristic",
            description=f"A {kind} pattern matched in a {b.get('mime')} response body ({b.get('resource_type')})"
                        + (f"; decoded role claim: {c['jwt_role']}" if c.get("jwt_role") else "") + ".",
            evidence=g["ev"], impact="If valid and sensitive, anyone who can load this resource obtains the credential.",
            limitations=SECRET_LIM + extra_lim, remediation=remediation, verification=steps,
            sample=c.get("redacted_sample"), location=loc))
    return out


def rule_sourcemaps_debug(ctx: RuleContext) -> list[Finding]:
    out: list[Finding] = []
    maps = [r for r in ctx.records if ctx.in_scope(r) and urlsplit(r.url).path.endswith(".map") and r.response_status and 200 <= r.response_status < 300]
    if maps:
        out.append(make_finding("EXP-SOURCEMAP", "maps", title="Source map files are publicly retrievable", severity="low", confidence="high",
            status="observed", description=f"{len(maps)} source map file(s) returned HTTP 2xx to the authenticated browser session.",
            evidence=[ref(r) for r in maps[:8]], impact="Source maps expose original source structure, comments and internal names, easing analysis of the application.",
            limitations="Observed with the scanned session only; the maps may be restricted for anonymous users. Contents were not analysed unless body capture was enabled.",
            remediation="Do not deploy source maps to production, or restrict them to authenticated developers.",
            verification=["Request the .map URL without a session and compare."]))
    refs = [(rid, b) for rid, b in ctx.bodies.items() if b.get("source_map_reference")]
    if refs and not maps:
        out.append(make_finding("EXP-SOURCEMAP-REF", "refs", title="Scripts reference source maps (retrieval not observed)", severity="info", confidence="medium",
            status="heuristic", description=f"{len(refs)} script(s) end with a sourceMappingURL comment; the map was not requested during the scan.",
            evidence=[f"request:{rid}" for rid, _ in refs[:6]], limitations="Browsers only fetch maps when DevTools is open; whether the map is retrievable is untested.",
            remediation="Verify that .map files are not publicly served."))
    dbg = [(rid, b) for rid, b in ctx.bodies.items() if b.get("debug_indicators")]
    if dbg:
        kinds = sorted({k for _, b in dbg for k in b["debug_indicators"]})
        strong = bool(set(kinds) & {"python_traceback", "java_stack_trace", "sql_error", "js_stack_trace"})
        out.append(make_finding("EXP-DEBUG", "debug", title="Debug or diagnostic information in responses", severity="medium" if strong else "low", confidence="low",
            status="heuristic", description=f"Response bodies contained indicators: {', '.join(kinds)}.", evidence=[f"request:{rid}" for rid, _ in dbg[:8]] + [f"body:{b.get('body_id')}" for _, b in dbg[:4]],
            impact="Stack traces and internal paths aid attackers and can disclose implementation details.",
            limitations="Regex indicators (matched text not retained) can match benign content such as documentation or client bundles.",
            remediation="Disable verbose errors in production and return generic error bodies."))
    return out


def rule_sensitive_data(ctx: RuleContext) -> list[Finding]:
    by_rec = {r.record_id: r for r in ctx.records}
    items = [(rid, b) for rid, b in ctx.bodies.items() if rid in by_rec and b.get("sensitive_keys") and ctx.in_scope(by_rec[rid])]
    out = []
    for rid, b in items:
        r = by_rec[rid]
        keys = sorted(b["sensitive_keys"])
        cc = " ".join(header_values(r.response_headers, "cache-control")).lower()
        out.append(make_finding("EXP-PII", f"{r.method}|{r.normalized_url}", title="API response contains sensitive-looking fields",
            severity="low", confidence="low", status="heuristic",
            description=f"{r.method} {r.normalized_url} returned JSON with field names suggesting personal or credential data: {', '.join(keys[:10])}.",
            evidence=[ref(r), f"body:{b.get('body_id')}"], impact="Over-exposure of fields (data minimisation issue) or credential fields returned to clients.",
            limitations="Based on key names only; values were redacted and never inspected. Returning a user's own data to that user may be intended. "
                        + ("Cache-Control does not include no-store/private. " if cc and "no-store" not in cc and "private" not in cc else ""),
            remediation="Return only fields the client needs; never return credential/secret fields.",
            verification=["Confirm each listed field is required by the UI and belongs to the authenticated user."]))
    return out


def rule_server_errors(ctx: RuleContext) -> list[Finding]:
    """Observed 5xx responses on API calls: a fact worth reviewing (stability, error-detail leakage), not a vulnerability."""
    groups: dict[tuple[str, str], list] = defaultdict(list)
    for r in ctx.records:
        if r.response_status and r.response_status >= 500 and r.resource_type in ("XHR", "Fetch", "Document"):
            groups[(r.method, r.normalized_url)].append(r)
    return [make_finding("API-5XX", f"{m}|{u}", title=f"Server error responses observed: {m} {u.split('//', 1)[-1]}", severity="info", confidence="high",
            status="observed", description=f"{len(rs)} request(s) returned HTTP {', '.join(sorted({str(r.response_status) for r in rs}))}.",
            evidence=[ref(r) for r in rs[:6]] + [f"body:{ctx.bodies[r.record_id]['body_id']}" for r in rs[:6]
                                                  if r.record_id in ctx.bodies and ctx.bodies[r.record_id].get("body_id")],
            impact="Indicates a server-side fault (possibly triggered by the scanned account's data/permissions); error bodies can leak details.",
            limitations="Cause unknown from the client side; may be an application bug, a policy rejection or a transient error.",
            remediation="Investigate server logs for these requests; return generic error bodies.")
            for (m, u), rs in groups.items()]


def rule_third_parties(ctx: RuleContext) -> list[Finding]:
    dests: dict[str, set[str]] = defaultdict(set)
    ev: dict[str, list[str]] = defaultdict(list)
    for r in ctx.records:
        p = urlsplit(r.url)
        if p.scheme not in ("http", "https") or ctx.in_scope(r):
            continue
        o = f"{p.scheme}://{p.netloc}"
        dests[o].add(r.resource_type or "?")
        if len(ev[o]) < 2:
            ev[o].append(ref(r))
    if not dests:
        return []
    desc = "; ".join(f"{o} ({', '.join(sorted(t))})" for o, t in sorted(dests.items())[:15])
    return [make_finding("EXP-THIRDPARTY", "dest", title=f"{len(dests)} third-party destination(s) contacted", severity="info", confidence="high",
        status="observed", description=desc, evidence=[e for v in ev.values() for e in v][:12],
        limitations="Destinations are listed from observed traffic only. Whether each is expected/approved must be judged by the application owner.",
        remediation="Review third parties for necessity, privacy impact and Subresource Integrity/CSP coverage.")]


ID_PARAM_RE = re.compile(r"(^|_)(id|uid|owner|[a-z]+_?id)$", re.I)  # also PostgREST-style filters: user_id=eq.<value>


def rule_authz_candidates(ctx: RuleContext) -> list[Finding]:
    """Passive pointers only. Nothing here demonstrates an access-control flaw."""
    groups: dict[tuple[str, str, str], list] = defaultdict(list)
    for r in ctx.records:
        credentialed = bool(header_values(r.request_headers, "authorization") or header_values(r.request_headers, "cookie"))
        # the app's own backend is often a different origin (e.g. a hosted API): include any API call that carried credentials
        if r.is_preflight or not (ctx.in_scope(r) or credentialed) or not r.response_status or not (200 <= r.response_status < 300):
            continue
        if r.resource_type not in ("XHR", "Fetch"):
            continue
        path = urlsplit(r.url).path
        norm = normalize_path(path)
        has_id_seg = any(s in ("{id}", "{uuid}", "{hex}") for s in norm.split("/"))
        has_id_q = any(ID_PARAM_RE.search(k) for k, _ in parse_qsl(urlsplit(r.url).query))
        if has_id_seg or has_id_q:
            groups[(r.method, ctx.origin(r), norm)].append(r)
    out = []
    for (method, origin, norm), recs in groups.items():
        qn = sorted({k for r in recs for k, _ in parse_qsl(urlsplit(r.url).query) if ID_PARAM_RE.search(k)})
        statuses = sorted({str(r.response_status) for r in recs})
        out.append(make_finding("AUTHZ-CANDIDATE", f"{method}|{origin}|{norm}", title=f"Object-identifier endpoint (authorization candidate): {method} {norm}",
            severity="info", confidence="low", status="untested_hypothesis",
            description=f"{method} {origin}{norm} takes an object identifier"
                        + (f" (parameters: {', '.join(qn)})" if qn else " in its path") + f" and returned HTTP {', '.join(statuses)} to the scanned session "
                        f"({len(recs)} request(s)). Whether other users' objects are protected was NOT tested.",
            evidence=[ref(r) for r in recs[:5]], impact="If server-side ownership checks are missing, users could access other users' objects (IDOR/BOLA).",
            limitations="Passive traffic cannot show an access-control weakness. This is a pointer for authorized manual testing with designated test accounts.",
            remediation="Enforce object-level authorization server-side on every request.",
            verification=["With two authorized test accounts you own, request account A's object using account B's session and expect 403/404.",
                          "Use only known test resources; do not enumerate real customers' records."]))
    return out
