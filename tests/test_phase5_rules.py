"""Phase 5: passive security rules (synthetic unit cases) and an end-to-end audit of the fixture's known configurations."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests import fixture_app as fx
from tests.test_phase4_crawl import _noop_prompt, jl, scan_cfg
from webaudit.config import BodyPolicy, CrawlLimits
from webaudit.models import Finding, HeaderEntry, RequestRecord
from webaudit.scan import run_scan
from webaudit.security_rules import analyze
from webaudit.security_rules.base import RuleContext
from webaudit.security_rules.headers import csp_script_issues, parse_csp, parse_set_cookie

ORIGIN = "https://app.example.com"


def H(**kw: str) -> list[HeaderEntry]:
    return [HeaderEntry(name=k.replace("_", "-"), value=v, source="extra_info") for k, v in kw.items()]


def rec(i: int, url: str = ORIGIN + "/", *, rtype: str = "Document", status: int | None = 200, req_h: list[HeaderEntry] | None = None,
        resp_h: list[HeaderEntry] | None = None, method: str = "GET", **kw: Any) -> RequestRecord:
    return RequestRecord(record_id=f"s/{i}#0", scan_id="s", request_id=str(i), url=url, normalized_url=url, method=method,
                         resource_type=rtype, response_status=status, state=kw.pop("state", "finished"),
                         request_headers=req_h or [], response_headers=resp_h or [], **kw)


def run(records: list[RequestRecord], bodies: dict[str, dict[str, Any]] | None = None, origins: list[str] | None = None) -> list[Finding]:
    f, errs = analyze(RuleContext(records, bodies or {}, origins or [ORIGIN]))
    assert errs == []
    return f


def ids(fs: list[Finding]) -> set[str]:
    return {f.rule_id for f in fs}


GOOD = dict(Strict_Transport_Security="max-age=31536000; includeSubDomains",
            Content_Security_Policy="default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            X_Content_Type_Options="nosniff", Referrer_Policy="strict-origin-when-cross-origin")


def test_good_headers_produce_no_header_findings() -> None:
    fs = run([rec(1, resp_h=H(**GOOD))])
    assert not [f for f in fs if f.rule_id.startswith("HDR-")], [f.rule_id for f in fs]


def test_missing_headers_detected_with_evidence_and_limitations() -> None:
    fs = run([rec(1)])
    assert {"HDR-HSTS", "HDR-CSP-MISSING", "HDR-XCTO", "HDR-FRAME", "HDR-REFERRER-MISSING"} <= ids(fs)
    for f in fs:
        assert f.evidence_references and f.limitations and f.status in ("observed", "heuristic", "untested_hypothesis")


def test_hsts_not_applicable_over_http_local_and_weak_max_age() -> None:
    fs = run([rec(1, "http://127.0.0.1:8000/")], origins=["http://127.0.0.1:8000"])
    assert "HDR-HSTS" not in ids(fs) and "HDR-NOTLS" in ids(fs)
    assert next(f for f in fs if f.rule_id == "HDR-NOTLS").severity == "info"
    fs2 = run([rec(1, resp_h=H(**{**GOOD, "Strict_Transport_Security": "max-age=300"}))])
    assert "HDR-HSTS-WEAK" in ids(fs2)
    fs3 = run([rec(1, "http://app.example.com/")], origins=["http://app.example.com"])
    assert next(f for f in fs3 if f.rule_id == "HDR-NOTLS").severity == "medium"


def test_csp_parsing_and_permissive_detection() -> None:
    assert csp_script_issues(parse_csp("default-src 'self'")) == []
    assert any("unsafe-inline" in i for i in csp_script_issues(parse_csp("script-src 'self' 'unsafe-inline'")))
    assert csp_script_issues(parse_csp("script-src 'nonce-abc' 'unsafe-inline'")) == []  # nonce neutralises unsafe-inline
    assert any("'*'" in i for i in csp_script_issues(parse_csp("default-src *")))
    assert csp_script_issues(parse_csp("img-src 'self'"))  # no script restriction
    fs = run([rec(1, resp_h=H(**{**GOOD, "Content_Security_Policy": "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' data:"}))])
    f = next(f for f in fs if f.rule_id == "HDR-CSP-PERMISSIVE")
    assert "unsafe-eval" in f.description and "unsafe-inline" in f.description


def test_frame_protection_via_csp_or_xfo() -> None:
    no_ancestors = {**GOOD, "Content_Security_Policy": "default-src 'self'; object-src 'none'"}
    assert "HDR-FRAME" in ids(run([rec(1, resp_h=H(**no_ancestors))]))
    assert "HDR-FRAME" not in ids(run([rec(1, resp_h=H(**no_ancestors, X_Frame_Options="DENY"))]))


def test_mixed_content_indicator() -> None:
    fs = run([rec(1, resp_h=H(**GOOD)), rec(2, "http://cdn.example.net/a.js", rtype="Script", mixed_content_type="blockable",
                                           document_url=ORIGIN + "/")])
    assert "HDR-MIXED" in ids(fs)
    assert "HDR-MIXED" not in ids(run([rec(1, "http://127.0.0.1:9/a.js", rtype="Script", document_url="http://127.0.0.1:9/")]))


def test_cookie_parsing_and_findings() -> None:
    c = parse_set_cookie("sid=[REDACTED:5chars]; Path=/; HttpOnly; Secure; SameSite=Lax")
    assert c["name"] == "sid" and c["secure"] and c["httponly"] and c["samesite"] == "lax"
    fs = run([rec(1, resp_h=H(**GOOD) + [HeaderEntry(name="Set-Cookie", value="session=[REDACTED:9chars]; Path=/", source="extra_info"),
                                          HeaderEntry(name="Set-Cookie", value="theme=dark; Path=/; Secure; SameSite=None", source="extra_info")])])
    got = ids(fs)
    assert {"COOKIE-SECURE", "COOKIE-HTTPONLY", "COOKIE-SAMESITE"} <= got
    hp = next(f for f in fs if f.rule_id == "COOKIE-HTTPONLY")
    assert hp.status == "heuristic" and "session" in hp.description and "REDACTED" not in hp.description.replace("(values redacted)", "")
    assert "COOKIE-SAMESITE-NONE-INSECURE" not in got


def _cors(i: int, acao: str, *, acac: str | None = None, origin: str | None = ORIGIN, preflight: bool = False,
          url: str = "https://api.example.com/x") -> RequestRecord:
    rh = H(Access_Control_Allow_Origin=acao) + (H(Access_Control_Allow_Credentials=acac) if acac else [])
    return rec(i, url, rtype="Fetch", resp_h=rh, req_h=H(Origin=origin) if origin else [],
               method="OPTIONS" if preflight else "GET", is_preflight=preflight)


def test_cors_rules_are_cautious_and_labelled() -> None:
    fs = run([_cors(1, "*", acac="true")])
    f = next(f for f in fs if f.rule_id == "CORS-WILDCARD-CREDS")
    assert f.status == "observed" and "actual response" in f.description and "browsers reject" in f.description.lower()
    fs = run([_cors(2, ORIGIN, acac="true", preflight=True)])
    f = next(f for f in fs if f.rule_id == "CORS-REFLECT-CREDS")
    assert f.status == "heuristic" and f.confidence == "low" and "preflight" in f.description
    assert "UNTESTED" in f.limitations and f.verification_steps
    assert not [f for f in run([_cors(3, ORIGIN)]) if f.rule_id.startswith("CORS-REFLECT")]  # no credentials -> no indicator
    assert "CORS-NULL" in ids(run([_cors(4, "null")]))
    blocked = rec(5, "https://api.example.com/y", rtype="Fetch", state="failed", status=None,
                  cors_error_status={"corsError": "MissingAllowOriginHeader"}, failure_reason="net::ERR_FAILED")  # noqa
    f = next(f for f in run([blocked]) if f.rule_id == "CORS-BLOCKED")
    assert f.severity == "info" and "not a server vulnerability" in f.description


def _body(rid: str, **kw: Any) -> dict[str, Any]:
    return {"status": "captured", "body_id": "body-000001", "event_id": "evt-1", "url": ORIGIN + "/a.js", "mime": "application/javascript",
            "resource_type": "Script", **kw}


def test_secret_candidates_are_heuristic_redacted_and_never_contain_values() -> None:
    r = rec(1, ORIGIN + "/a.js", rtype="Script")
    b = _body(r.record_id, secret_candidates=[{"type": "aws_access_key_id", "offset": 10, "line": 2, "redacted_sample": "AK…[20 chars]"},
                                              {"type": "jwt", "offset": 99, "line": 3, "redacted_sample": "ey…[60 chars]"}])
    fs = run([r], {r.record_id: b})
    sec = [f for f in fs if f.rule_id == "EXP-SECRET"]
    assert len(sec) == 2 and all(f.status == "heuristic" for f in sec)
    assert next(f for f in sec if "aws" in f.title).severity == "high"
    assert all(f.redacted_sample and f.location and f.evidence_references for f in sec)
    assert fx.SECRET_AWS not in json.dumps([f.model_dump() for f in fs])


def test_sourcemap_debug_pii_thirdparty_and_authz_candidate() -> None:
    m = rec(1, ORIGIN + "/static/app.js.map", rtype="Fetch")
    api = rec(2, ORIGIN + "/api/users/42", rtype="XHR", resp_h=H(Content_Type="application/json"))
    api2 = rec(3, ORIGIN + "/api/orders?account_id=7", rtype="Fetch")
    tp = rec(4, "https://cdn.thirdparty.example/lib.js", rtype="Script")
    bodies = {api.record_id: _body(api.record_id, mime="application/json", resource_type="XHR", sensitive_keys=["email", "ssn"],
                                   debug_indicators=["python_traceback"])}
    fs = run([m, api, api2, tp], bodies)
    assert {"EXP-SOURCEMAP", "EXP-DEBUG", "EXP-PII", "EXP-THIRDPARTY", "AUTHZ-CANDIDATE"} <= ids(fs)
    az = [f for f in fs if f.rule_id == "AUTHZ-CANDIDATE"]
    assert len(az) == 2 and all(f.status == "untested_hypothesis" and "NOT tested" in f.description for f in az)
    pii = next(f for f in fs if f.rule_id == "EXP-PII")
    assert "email" in pii.description and pii.status == "heuristic"


def test_rule_failure_is_reported_not_raised(monkeypatch: Any) -> None:
    import webaudit.security_rules as sr

    def boom(ctx: Any) -> list[Finding]:
        raise RuntimeError("bug")
    monkeypatch.setattr(sr, "RULES", [boom, sr.rule_third_parties])
    f, errs = sr.analyze(RuleContext([rec(1, "https://x.example/a.js", rtype="Script")], {}, [ORIGIN]))
    assert errs and "boom" in errs[0] and any(x.rule_id == "EXP-THIRDPARTY" for x in f)


# ---- end to end -----------------------------------------------------------------------------------

@pytest.mark.browser
async def test_end_to_end_audit_of_fixture(server: Any, tmp_path: Path) -> None:
    cfg = scan_cfg(server, tmp_path, body=BodyPolicy(mode="selected", max_body_bytes=200_000),
                   extra_allowed_origins=[server.api_url],
                   crawl=CrawlLimits(max_pages=12, request_delay_ms=0, settle_ms=400, max_depth=2, max_interactions_per_page=2))
    cfg = cfg.model_copy(update={"initial_url": server.main_url + "/sec"})
    scan_dir = await run_scan(cfg, login_prompt=_noop_prompt)

    findings = [Finding.model_validate(f) for f in json.loads((scan_dir / "findings.json").read_text())]
    got = ids(findings)
    expected = {"HDR-CSP-PERMISSIVE", "HDR-XCTO", "HDR-FRAME", "HDR-REFERRER", "HDR-NOTLS", "COOKIE-HTTPONLY", "COOKIE-SAMESITE",
                "CORS-REFLECT-CREDS", "EXP-SECRET", "EXP-SOURCEMAP", "EXP-PII", "EXP-DEBUG", "AUTHZ-CANDIDATE", "CORS-WILDCARD-AUTHED" if False else "HDR-CSP-MISSING"}
    assert expected <= got, expected - got
    # the good-header page contributes nothing negative for CSP-permissive; the bad page does
    perm = next(f for f in findings if f.rule_id == "HDR-CSP-PERMISSIVE")
    reqs = {r["record_id"]: r for r in jl(scan_dir / "requests.jsonl")}
    assert reqs[perm.evidence_references[0].split(":", 1)[1]]["url"].endswith("/h/bad")
    # evidence references resolve; limitations present; statuses valid
    bodies_dir = scan_dir / "bodies"
    for f in findings:
        assert f.evidence_references and f.limitations
        for e in f.evidence_references:
            kind, _, val = e.partition(":")
            if kind == "request":
                assert val in reqs, e
            elif kind == "body":
                assert (bodies_dir / f"{val}.txt").exists(), e
    # secrets: types found, none of the values anywhere in the bundle
    sec_types = {f.title for f in findings if f.rule_id == "EXP-SECRET"}
    assert any("aws_access_key_id" in t for t in sec_types) and any("stripe_secret_key" in t for t in sec_types) and any("jwt" in t for t in sec_types)
    for p in scan_dir.rglob("*"):
        if p.is_file() and p.name != "scan.sqlite" and not p.name.endswith((".sqlite-wal", ".sqlite-shm", ".log")):
            t = p.read_text(encoding="utf-8", errors="replace")
            for s in (fx.SECRET_AWS, fx.SECRET_JWT, fx.SECRET_API_KEY, fx.SECRET_PASSWORD, fx.SECRET_EMAIL, fx.SECRET_SSN):
                assert s not in t, f"{s} in {p.name}"
    # report structure
    report = (scan_dir / "report.md").read_text(encoding="utf-8")
    for heading in ("## 1. Observed facts", "## 2. Heuristic findings", "## 3. Untested hypotheses", "## 4. Coverage gaps and limitations"):
        assert heading in report
    assert report.index("## 1. Observed facts") < report.index("## 2. Heuristic") < report.index("## 3. Untested") < report.index("## 4. Coverage")
    az_pos = report.index("AUTHZ-CANDIDATE")
    assert az_pos > report.index("## 3. Untested hypotheses")
    assert "does not claim to have discovered every endpoint" in report
    manifest = json.loads((scan_dir / "manifest.json").read_text())
    assert "report.md" in manifest["files"] and manifest["files"]["findings.json"]["records"] == len(findings)
    assert manifest["redaction"]["perfect"] is False


def _jwt(role: str) -> str:
    import base64
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{b({'alg': 'HS256'})}.{b({'role': role})}.c2lnbmF0dXJlc2lnbmF0dXJl"


def test_jwt_role_classification_and_dedup() -> None:
    from webaudit.redaction import scan_text_for_secrets
    anon, priv = scan_text_for_secrets(f"a='{_jwt('anon')}';p='{_jwt('service_role')}'")
    assert anon["jwt_role"] == "anon" and priv["jwt_role"] == "service_role"
    r1, r2 = rec(1, ORIGIN + "/index.js", rtype="Script"), rec(2, ORIGIN + "/index.js", rtype="Script")  # same asset fetched twice
    bodies = {r.record_id: _body(r.record_id, url=ORIGIN + "/index.js", secret_candidates=[anon, priv]) for r in (r1, r2)}
    fs = [f for f in run([r1, r2], bodies) if f.rule_id == "EXP-SECRET"]
    assert len(fs) == 2  # not 4: duplicates merged by (asset, type, offset)
    a = next(f for f in fs if "anon" in f.title)
    p = next(f for f in fs if "service_role" in f.title)
    assert (a.severity, a.status) == ("info", "heuristic") and "NOT tested" in a.limitations
    assert p.severity == "critical" and p.status == "heuristic" and len(p.evidence_references) >= 4
    dumped = json.dumps([f.model_dump() for f in fs])
    assert "c2lnbmF0dXJl" not in dumped  # no token material in findings


def test_generic_secret_filter_ignores_identifier_words() -> None:
    from webaudit.redaction import scan_text_for_secrets
    assert scan_text_for_secrets("accessToken = 'refreshTokenName'") == []
    assert [c["type"] for c in scan_text_for_secrets("apiKey = 'abcd1234efgh5678'")] == ["generic_assigned_secret"]


def test_authz_candidates_for_cross_origin_credentialed_api_and_postgrest_filters() -> None:
    api = "https://backend.example.net"
    auth = H(Authorization="Bearer [REDACTED:10chars]", Apikey="[REDACTED:5chars]")
    recs = [rec(1, f"{api}/rest/v1/resumes?select=basics&user_id=eq.46dcd662", rtype="Fetch", req_h=auth),
            rec(2, f"{api}/rest/v1/notifications?recipient_user_id=eq.7&limit=5", rtype="Fetch", req_h=auth),
            rec(3, f"{api}/rest/v1/public?select=a", rtype="Fetch", req_h=auth),  # no id-like parameter
            rec(4, "https://other.example.org/x?user_id=1", rtype="Fetch")]  # not credentialed, not in scope
    fs = [f for f in run(recs) if f.rule_id == "AUTHZ-CANDIDATE"]
    titles = " ".join(f.title for f in fs)
    assert len(fs) == 2 and "/rest/v1/resumes" in titles and "/rest/v1/notifications" in titles
    assert all(f.status == "untested_hypothesis" for f in fs)
    assert "user_id" in next(f for f in fs if "resumes" in f.title).description


def test_server_error_finding_is_observed_fact() -> None:
    r = rec(1, ORIGIN + "/rest/v1/x?id=1", rtype="Fetch", status=500)
    f = next(f for f in run([r]) if f.rule_id == "API-5XX")
    assert f.status == "observed" and f.severity == "info" and f.limitations


def test_generic_pattern_does_not_duplicate_jwt_and_weak_debug_is_low() -> None:
    from webaudit.redaction import scan_text_for_secrets
    types = [c["type"] for c in scan_text_for_secrets(f"var cfg = {{ apiKey: '{_jwt('anon')}' }}")]
    assert types == ["jwt"]
    r = rec(1, ORIGIN + "/api/x", rtype="Fetch")
    weak = run([r], {r.record_id: _body(r.record_id, mime="application/json", resource_type="Fetch", debug_indicators=["debug_flag"])})
    strong = run([r], {r.record_id: _body(r.record_id, mime="application/json", resource_type="Fetch", debug_indicators=["python_traceback"])})
    assert next(f for f in weak if f.rule_id == "EXP-DEBUG").severity == "low"
    assert next(f for f in strong if f.rule_id == "EXP-DEBUG").severity == "medium"
