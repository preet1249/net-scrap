"""CORS rules. A CORS header is a policy statement, never a vulnerability on its own: each finding states the
browser origin, credentials context, response kind (preflight / actual / browser-generated failure) and what is unproven."""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from ..inventory import header_values
from ..models import Finding, RequestRecord
from .base import RuleContext, make_finding, ref


def _req_origin(r: RequestRecord) -> str | None:
    v = header_values(r.request_headers, "origin")
    return v[0] if v else None


def _kind(r: RequestRecord) -> str:
    return "preflight (OPTIONS)" if r.is_preflight else "actual response"


def _sent_credentials(r: RequestRecord) -> bool:
    return bool(header_values(r.request_headers, "cookie") or header_values(r.request_headers, "authorization"))


def rule_cors(ctx: RuleContext) -> list[Finding]:
    out: list[Finding] = []
    groups: dict[tuple[str, str], list[RequestRecord]] = defaultdict(list)
    for r in ctx.records:
        if r.response_status is None and not r.cors_error_status:
            continue
        acao = header_values(r.response_headers, "access-control-allow-origin")
        if acao:
            p = urlsplit(r.url)
            groups[(acao[0], f"{p.scheme}://{p.netloc}")].append(r)
    lim = ("One observation from the browser origin(s) used during the scan. It cannot show how the server treats other Origin values "
           "unless they were actually sent, and CORS only governs what browsers expose to scripts; it does not authenticate callers.")
    for (acao, target), recs in groups.items():
        acac = {v.lower() for r in recs for v in header_values(r.response_headers, "access-control-allow-credentials")}
        kinds = sorted({_kind(r) for r in recs})
        ev = [ref(r) for r in recs[:6]]
        origins = {_req_origin(r) for r in recs} - {None}
        creds = "true" in acac
        if acao == "*" and creds:
            out.append(make_finding("CORS-WILDCARD-CREDS", f"{target}", title="Access-Control-Allow-Origin '*' combined with Allow-Credentials: true",
                severity="low", confidence="high", status="observed",
                description=f"{target} returned ACAO '*' together with ACAC 'true' ({', '.join(kinds)}). Browsers reject credentialed responses with a wildcard origin.",
                evidence=ev, impact="Indicates a misconfigured CORS policy; the browser blocks it, so direct impact is unlikely.", limitations=lim,
                remediation="Return a specific allowed origin (from a server-side allowlist) when credentials are permitted."))
        elif acao == "null":
            out.append(make_finding("CORS-NULL", target, title="CORS allows the 'null' origin", severity="medium", confidence="medium",
                status="heuristic", description=f"{target} returned ACAO 'null' ({', '.join(kinds)}). Sandboxed iframes and data: URLs send Origin 'null'.",
                evidence=ev, impact="Untrusted contexts could read responses if credentials are also allowed.", limitations=lim + f" Credentials allowed: {creds}.",
                remediation="Do not allow 'null'; use an explicit origin allowlist.", verification=["With authorization, send Origin: null and observe whether ACAO/ACAC are returned."]))
        elif acao not in ("*",) and origins and acao in origins and not _same_origin(acao, target):
            # reflecting the origin we sent is normal for allowlists; flag only the risky combination as an indicator
            if creds:
                out.append(make_finding("CORS-REFLECT-CREDS", target, title="Cross-origin response echoes the request Origin with credentials allowed",
                    severity="medium", confidence="low", status="heuristic",
                    description=f"Request Origin {acao} was echoed in ACAO by {target} together with ACAC true ({', '.join(kinds)}). "
                                "This is expected for an allowlisted trusted origin and risky if the server reflects ANY origin.",
                    evidence=ev, impact="If origin reflection is unconditional, any website could read authenticated responses from this endpoint.",
                    limitations=lim + " Only the origin(s) actually sent were observed: " + ", ".join(sorted(origins)) + ". Reflection of arbitrary origins is UNTESTED.",
                    remediation="Validate Origin against an exact allowlist; never reflect arbitrary values with credentials.",
                    verification=["In an authorized test, request the endpoint with a controlled unrelated Origin header and check whether ACAO echoes it with ACAC true."]))
        elif acao == "*" and any(_sent_credentials(r) for r in recs):
            out.append(make_finding("CORS-WILDCARD-AUTHED", target, title="Wildcard CORS on a request that carried credentials",
                severity="info", confidence="medium", status="observed",
                description=f"{target} answered requests that included cookies/Authorization with ACAO '*' (credentialed reads are blocked by browsers).",
                evidence=ev, limitations=lim, remediation="Confirm the endpoint is intended to be public; otherwise restrict ACAO."))
    # preflight policy breadth
    for r in ctx.records:
        if r.is_preflight and r.response_status is not None:
            ah = header_values(r.response_headers, "access-control-allow-headers")
            am = header_values(r.response_headers, "access-control-allow-methods")
            acac = [v.lower() for v in header_values(r.response_headers, "access-control-allow-credentials")]
            if any(v.strip() == "*" for v in ah + am) and "true" in acac:
                out.append(make_finding("CORS-PREFLIGHT-BROAD", r.url.split("?")[0], title="Preflight allows wildcard methods/headers with credentials",
                    severity="low", confidence="medium", status="observed", description="Preflight response (OPTIONS) uses '*' in Allow-Methods/Headers together with Allow-Credentials.",
                    evidence=[ref(r)], limitations=lim, remediation="List exact methods and headers."))
    # browser-generated CORS failures
    fails = [r for r in ctx.records if r.cors_error_status]
    if fails:
        errs = sorted({str(r.cors_error_status.get("corsError")) for r in fails if isinstance(r.cors_error_status, dict)})
        out.append(make_finding("CORS-BLOCKED", "blocked", title="Browser blocked cross-origin requests (CORS failures)", severity="info", confidence="high",
            status="observed", description=f"{len(fails)} request(s) failed with a browser-generated CORS error ({', '.join(errs)}). "
                                           "This is the browser enforcing policy, not a server vulnerability.",
            evidence=[ref(r) for r in fails[:8]], limitations="A failure here may mean the application is broken for this origin rather than insecure.",
            remediation="If these calls are intended, add the required CORS headers; otherwise remove the calls."))
    return out


def _same_origin(a: str, b: str) -> bool:
    return a.lower().rstrip("/") == b.lower().rstrip("/")
