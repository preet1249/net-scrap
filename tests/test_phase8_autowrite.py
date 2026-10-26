"""Phase 8: automatic read/write mode inside the logged-in account, with a hard deny-list."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from tests.test_phase4_crawl import jl
from webaudit import cli
from webaudit.config import CrawlLimits, ScanConfig
from webaudit.scan import run_scan
from webaudit.writeguard import label_allowed, label_allows_write, write_denied


def test_write_deny_list_covers_signout_account_switch_destructive_and_billing() -> None:
    deny = lambda p, m="POST", q="": write_denied(p, q, m)  # noqa: E731
    assert deny("/auth/v1/logout") == "signout" and deny("/api/signout") == "signout" and deny("/logout") == "signout"
    assert deny("/auth/v1/token", q="grant_type=password") == "account_switch_or_creation"
    assert deny("/auth/v1/signup") == "account_switch_or_creation" and deny("/login") == "account_switch_or_creation"
    assert deny("/auth/v1/token", q="grant_type=refresh_token") is None  # keeps the CURRENT session alive
    assert deny("/auth/v1/user", "PUT") == "credentials_or_identity_change" and deny("/account/password") == "credentials_or_identity_change"
    assert deny("/rest/v1/resumes", "DELETE") == "delete_method" and deny("/rest/v1/rpc/delete_resume") == "destructive_name"
    assert deny("/api/checkout") == "payments_billing" and deny("/api/invite") == "invites_sharing_permissions"
    assert deny("/api/upload") == "upload_or_export" and deny("/api/team/members") == "invites_sharing_permissions"
    # ordinary create/edit inside the account is allowed; ?order= must not look like an order/payment
    assert deny("/rest/v1/resumes") is None and deny("/rest/v1/resumes", "PATCH", "id=eq.5") is None and deny("/rest/v1/profiles", "PATCH", "order=a") is None
    assert write_denied("/x/secret-admin-thing", "", "POST", [r"secret-admin"]) == "custom_deny_pattern" or write_denied("/x/admin", "", "POST")


def test_ui_label_policy() -> None:
    for ok in ("Paste Text", "Paste LaTeX CV", "Save", "Save note", "New item", "Add", "Create resume", "Update profile", "Rename", "Save changes", "Duplicate"):
        assert label_allows_write(ok), ok
    for bad in ("Delete", "Remove item", "Sign out", "Log out", "Invite teammate", "Pay now", "Upgrade", "Publish", "Update password",
                "Send", "Export", "Add email", "Create account", "Save payment method", "Switch account", ""):
        assert not label_allows_write(bad), bad


def test_read_write_requires_guard_and_cli_flag() -> None:
    with pytest.raises(ValueError, match="requires scope_enforcement=guard"):
        ScanConfig(initial_url="https://a.example", interaction_mode="read_write", scope_enforcement="observe")
    a = cli.build_parser().parse_args(["scan", "https://a.example", "--auto-write", "--max-writes", "5"])
    cfg = cli._config_from_args(a)
    assert cfg.interaction_mode == "read_write" and cfg.crawl.max_writes == 5
    assert ScanConfig(initial_url="https://a.example").interaction_mode == "read_only"  # default stays read-only


async def _login_settle(url: str) -> None:
    await asyncio.sleep(1.5)  # the (unguarded) login-phase page load settles, as it would while a human logs in


def _cfg(server: Any, tmp: Path, start: str, **kw: Any) -> ScanConfig:
    kw.setdefault("write_uploads", False)
    return ScanConfig(initial_url=server.main_url + start, confirm_authorized=True, allow_http_local=True, headless=True,
                      interaction_mode="read_write", output_dir=str(tmp / "output"), profile_dir=str(tmp / "p"),
                      crawl=CrawlLimits(max_pages=8, max_depth=1, request_delay_ms=0, settle_ms=400, max_writes=10), **kw)


@pytest.mark.browser
async def test_auto_write_creates_test_data_but_never_signs_out_or_does_anything_destructive(server: Any, tmp_path: Path) -> None:
    marks: list[int] = []

    async def prompt(url: str) -> None:
        await asyncio.sleep(1.5)
        marks.append(len(server.hits))
        marks.append(len(server.bodies))

    from webaudit.config import BodyPolicy
    cfg = _cfg(server, tmp_path, "/app", body=BodyPolicy(mode="selected"))
    scan_dir = await run_scan(cfg, login_prompt=prompt)
    hits, bodies = server.hits[marks[0]:], server.bodies[marks[1]:]

    # --- writes that SHOULD happen (inside the logged-in account) ---
    assert ("POST", "/notes") in hits and ("POST", "/api/items") in hits
    note = next(b for b in bodies if b[1] == "/notes")
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    prefix = cov["write_test_marker_prefix"]
    assert prefix.startswith("webaudit-test-") and f"title={prefix}-" in note[2] and f"{prefix}-" in note[2].split("body=")[1]  # test-marked data
    assert "WebAudit+automated+test+content" in note[2]  # pre-written sample text for the textarea
    assert json.loads(next(b for b in bodies if b[1] == "/api/items")[2]) == {"name": "from-new-button"}

    # --- everything dangerous must NOT reach the server ---
    for forbidden in (("DELETE", "/api/items/1"), ("POST", "/auth/v1/logout"), ("POST", "/account/password"), ("POST", "/upload"),
                      ("POST", "/api/invite"), ("GET", "/logout")):
        assert forbidden not in hits, forbidden
    # hostile page-load requests were blocked at the network layer, with reasons
    reasons = {b["reason"] for b in cov["scope_guard_blocks"]}
    assert {"write_denied:delete_method", "write_denied:signout"} <= reasons

    # --- UI layer: forms skipped for the right reasons, destructive controls never clicked ---
    summary = next(p for p in jl(scan_dir / "pages.jsonl") if p["url"].endswith("/app"))["interaction_summary"]["writes"]
    skipped = {s["reason"] for s in summary["forms_skipped"]}
    assert "sensitive_field" in skipped  # password form and file-upload form
    assert [f["button"] for f in summary["forms_submitted"]] == ["Save note"] and summary["controls_clicked"] == ["New item"]
    assert {"Remove item", "Sign out", "Invite teammate"} <= set(summary["controls_denied"])

    # --- the evidence: payloads captured, writes disclosed in report and coverage ---
    reqs = jl(scan_dir / "requests.jsonl")
    post_items = next(r for r in reqs if r["method"] == "POST" and r["url"].endswith("/api/items"))
    assert post_items["request_body_reference"].startswith("bodies/req-") and post_items["response_status"] == 200
    assert json.loads((scan_dir / post_items["request_body_reference"]).read_text()) == {"name": "from-new-button"}
    post_notes = next(r for r in reqs if r["method"] == "POST" and r["url"].endswith("/notes"))
    assert post_notes["has_post_data"] and post_notes["request_body_reference"]
    assert cov["writes_performed"] == 2 and len(cov["write_actions"]) == 2 and cov["interaction_mode"] == "read_write"
    report = (scan_dir / "report.md").read_text(encoding="utf-8")
    assert "Automatic writes performed: 2" in report and prefix in report
    assert (scan_dir.name == "1" + server.main_url.split("//")[1].split(":")[0])


@pytest.mark.browser
async def test_write_budget_is_respected(server: Any, tmp_path: Path) -> None:
    cfg = _cfg(server, tmp_path, "/app")
    cfg = cfg.model_copy(update={"crawl": cfg.crawl.model_copy(update={"max_writes": 1})})
    before = len(server.bodies)
    scan_dir = await run_scan(cfg, login_prompt=_login_settle)
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert cov["writes_performed"] == 1
    assert len([b for b in server.bodies[before:] if b[1] in ("/notes", "/api/items")]) == 1


@pytest.mark.browser
async def test_session_loss_stops_crawl_and_never_enters_credentials(server: Any, tmp_path: Path) -> None:
    cfg = _cfg(server, tmp_path, "/page2")
    cfg = cfg.model_copy(update={"crawl": cfg.crawl.model_copy(update={"max_depth": 2})})
    # a link on the seed leads to a page that bounces to /login
    from urllib.parse import quote
    cfg2 = cfg.model_copy(update={"initial_url": server.main_url + "/page2"})
    from webaudit.crawler import Crawler
    from webaudit.scope import ScopePolicy
    orig = Crawler._discover

    async def discover(self: Any, page: Any, cand: Any) -> None:
        if cand.depth == 0:
            self._enqueue(server.main_url + "/session-expired", 1, None, "link")
            self._enqueue(server.main_url + "/page2/sub", 1, None, "link")
        await orig(self, page, cand)
    Crawler._discover = discover  # type: ignore[method-assign]
    try:
        scan_dir = await run_scan(cfg2, login_prompt=_login_settle)
    finally:
        Crawler._discover = orig  # type: ignore[method-assign]
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert cov["session_lost"] is True and "session_lost" in cov["budgets_hit"]
    pages = jl(scan_dir / "pages.jsonl")
    assert any("login page" in (p["note"] or "") for p in pages)
    assert not any(h[0] == "POST" and h[1] == "/login" for h in server.hits)
    assert "Session appeared to end" in (scan_dir / "report.md").read_text(encoding="utf-8")


@pytest.mark.browser
async def test_formless_spa_dialog_needs_user_allowlisted_label_then_is_filled_and_submitted(server: Any, tmp_path: Path) -> None:
    from webaudit.writeguard import label_allowed
    assert not label_allowed("Spark Joy", []) and label_allowed("Spark Joy", ["spark joy"])
    assert not label_allowed("Delete note", ["delete note"]) and not label_allowed("Sign out", ["sign out"])  # hard deny beats the allow-list

    # 1) without the allow-list nothing is written (the label is not in the safe vocabulary)
    n0 = len(server.bodies)
    s1 = await run_scan(_cfg(server, tmp_path / "a", "/spa"), login_prompt=_login_settle)
    assert not [b for b in server.bodies[n0:] if b[1] == "/api/notes"]
    assert json.loads((s1 / "coverage.json").read_text())["crawl"]["writes_performed"] == 0

    # 2) with it, the dialog's textarea is filled with a marker and 'Create' is pressed; password field and Delete are untouched
    n1 = len(server.bodies)
    h1 = len(server.hits)
    cfg = _cfg(server, tmp_path / "b", "/spa", write_allow_labels=["Spark Joy"])
    s2 = await run_scan(cfg, login_prompt=_login_settle)
    new = server.bodies[n1:]
    note = next(b for b in new if b[1] == "/api/notes")
    cov = json.loads((s2 / "coverage.json").read_text())["crawl"]
    assert cov["write_test_marker_prefix"] in json.loads(note[2])["text"] and "automated test content" in json.loads(note[2])["text"]
    assert not [h for h in server.hits[h1:] if h[0] == "DELETE"]
    kinds = [a["kind"] for a in cov["write_actions"]]
    assert kinds == ["dialog_submit"] and cov["write_actions"][0]["fields"] == ["t"]  # merely OPENING the dialog sent nothing: not counted as a write  # password input never filled


# ---- uploads, pre-written text and read-back --------------------------------------------------------------

def test_upload_policy_unit() -> None:
    from webaudit.samplefiles import SampleFiles
    assert write_denied("/api/upload", "", "POST") == "upload_or_export"  # off by default at the policy level
    assert write_denied("/api/upload", "", "POST", None, True) is None and write_denied("/storage/v1/object/avatars/x", "", "POST", None, True) is None
    assert write_denied("/api/export", "", "POST", None, True) == "upload_or_export"  # exports stay denied
    assert write_denied("/storage/v1/object/avatars/x", "", "DELETE", None, True) == "delete_method"
    assert label_allowed("Upload Resume", [], True) and not label_allowed("Upload Resume", [], False)
    assert label_allowed("Change photo", [], True) and not label_allowed("Remove photo", [], True) and not label_allowed("Download PDF", [], True)


@pytest.mark.browser
async def test_uploads_use_generated_files_matching_accept_and_never_delete(server: Any, tmp_path: Path) -> None:
    n = len(server.uploads)
    h = len(server.hits)
    scan_dir = await run_scan(_cfg(server, tmp_path / "u", "/upl", write_uploads=True), login_prompt=_login_settle)
    ups = server.uploads[n:]
    by_path = {u["path"]: u for u in ups}
    assert by_path["/api/upload"]["filename"] == "webaudit-test-sample.pdf" and by_path["/api/upload"]["starts_pdf"]  # accept=".pdf,.docx" -> PDF
    assert by_path["/api/avatar"]["filename"] == "webaudit-test-sample.png" and by_path["/api/avatar"]["has_png"]  # accept="image/*" -> blank PNG
    assert not [x for x in server.hits[h:] if x[0] == "DELETE"]
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert {a["kind"] for a in cov["write_actions"]} == {"file_upload"} and len(cov["write_actions"]) == 2
    # the slow uploads were allowed to FINISH (not cancelled by the next navigation) and are reported as completed writes
    posts = [r for r in jl(scan_dir / "requests.jsonl") if r["method"] == "POST" and "/api/" in r["url"]]
    assert len(posts) == 2 and all(r["state"] == "finished" and r["response_status"] == 200 for r in posts), [(r["url"], r["state"], r["failure_reason"]) for r in posts]
    wr = cov["write_readback"]
    assert wr["write_requests"]["observed"] == 2 and wr["write_requests"]["completed"] == 2 and wr["write_requests"]["failed_or_aborted"] == 0
    assert wr["checked"] is False and len(wr["file_uploads_attempted"]) == 2 and "only file uploads" in wr["note"]
    assert "Write requests actually sent: 2" in (scan_dir / "report.md").read_text(encoding="utf-8")
    assert "webaudit-test-sample.pdf" in cov["test_files_available"]
    assert (scan_dir / "test_files" / "webaudit-test-sample.pdf").read_bytes().startswith(b"%PDF")
    # generated material only; and uploads can be switched off
    n2 = len(server.uploads)
    await run_scan(_cfg(server, tmp_path / "u2", "/upl", write_uploads=False), login_prompt=_login_settle)
    assert len(server.uploads) == n2


@pytest.mark.browser
async def test_prewritten_resume_text_and_read_back_confirmation(server: Any, tmp_path: Path) -> None:
    from webaudit.config import BodyPolicy
    before = len(server.notes_store)
    cfg = _cfg(server, tmp_path / "t", "/spa2", write_allow_labels=["Paste Text"], body=BodyPolicy(mode="selected"))
    scan_dir = await run_scan(cfg, login_prompt=_login_settle)
    written = server.notes_store[before:]
    assert len(written) == 1 and "Software Engineer" in written[0] and "Alex Test (webaudit-test-" in written[0]  # resume-like pre-written text
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert cov["read_back_pages"]  # pages were revisited after writing
    # read-back proof needs a page that lists the data: /spa lists notes via GET /api/notes
    before2 = len(server.notes_store)
    cfg2 = _cfg(server, tmp_path / "r", "/spa", write_allow_labels=["Spark Joy"], body=BodyPolicy(mode="selected"))
    scan2 = await run_scan(cfg2, login_prompt=_login_settle)
    assert len(server.notes_store) == before2 + 1
    rb = json.loads((scan2 / "coverage.json").read_text())["crawl"]["write_readback"]
    assert rb["checked"] is True and rb["unconfirmed"] == [] and len(rb["confirmed"]) == 1
    hits = next(iter(rb["confirmed"].values()))
    assert any(h["method"] == "GET" and h["url"].endswith("/api/notes") for h in hits)  # the app returned our data when read back
    assert "Read-back after writes:** confirmed 1 of 1" in (scan2 / "report.md").read_text(encoding="utf-8")


@pytest.mark.browser
async def test_noop_clicks_and_status_text_do_not_consume_write_budget_or_get_clicked(server: Any, tmp_path: Path) -> None:
    from webaudit.writeguard import label_allowed
    assert label_allowed("Upload A", [], True) and not label_allowed("Resume A\nUploaded", [], True) and not label_allowed("Uploaded 3 days ago", [], True)
    h = len(server.hits)
    cfg = _cfg(server, tmp_path / "n", "/upl2", write_uploads=True)
    cfg = cfg.model_copy(update={"crawl": cfg.crawl.model_copy(update={"max_writes": 1, "max_writes_per_page": 1})})  # budget of ONE real write
    scan_dir = await run_scan(cfg, login_prompt=_login_settle)
    new = server.hits[h:]
    assert ("POST", "/api/items") in new  # the real create flow was reached even though upload-looking buttons come first
    assert ("POST", "/api/card") not in new  # status text "Resume A / Uploaded" is not an upload button
    cov = json.loads((scan_dir / "coverage.json").read_text())["crawl"]
    assert cov["writes_performed"] == 1 and [a["button"] for a in cov["write_actions"]] == ["New item"]
    summary = next(p for p in jl(scan_dir / "pages.jsonl") if p["url"].endswith("/upl2"))["interaction_summary"]["writes"]
    assert len(summary["controls_noop"]) <= 1  # at most one upload-looking button was tried; it sent nothing and was not counted
