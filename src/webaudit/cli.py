"""Command-line interface: scan | list | export | diagnostics. Never prints header values, cookies, tokens or bodies."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Optional

from pydantic import ValidationError

from . import __version__, exporter
from .config import ScanConfig, load_config
from .compare import compare_scans, render_markdown
from .scan import list_scans, resolve_scan, run_scan

CONFIRM_PHRASE = "I AM AUTHORIZED"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="webaudit", description="Passive, local-first authenticated web security auditor.")
    p.add_argument("--version", action="version", version=f"webaudit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="open a dedicated browser, log in manually, then crawl and collect evidence")
    s.add_argument("url", nargs="?", help="dashboard URL you own or are authorized to assess")
    s.add_argument("--config", help="TOML/JSON config file (see config.example.toml)")
    s.add_argument("--confirm-authorized", action="store_true", help="confirm you own / are authorized to assess the target")
    s.add_argument("--allow-http-local", action="store_true", help="allow http:// for localhost development targets")
    s.add_argument("--extra-origin", action="append", default=None, help="additional approved origin (exact scheme://host[:port])")
    s.add_argument("--output-dir")
    s.add_argument("--profile-dir", help="dedicated automation profile directory (never your normal browser profile)")
    s.add_argument("--headless", action="store_true", default=None)
    s.add_argument("--body-mode", choices=["none", "selected", "all_supported"], help="response-body capture (default none)")
    s.add_argument("--store-raw-bodies", action="store_true", help="ALSO store raw (unredacted) bodies in a separate local directory")
    s.add_argument("--preset", choices=["quick", "standard", "thorough"],
                   help="crawl size: quick (15 pages), standard (default, 50), thorough (300 pages, depth 6, up to 2h, more interactions/writes)")
    s.add_argument("--include-subdomains", action="store_true", help="approve every https subdomain of the target's domain (explicit scope widening)")
    s.add_argument("--max-pages", type=int)
    s.add_argument("--max-depth", type=int)
    s.add_argument("--max-seconds", type=int)
    s.add_argument("--scope-enforcement", choices=["guard", "observe"])
    s.add_argument("--manual-approval", action="store_true", default=None, help="ask before clicking uncertain controls")
    s.add_argument("--allow-post-path", action="append", default=None, metavar="PREFIX",
                   help="allow state-changing HTTP methods to this path prefix (e.g. /graphql, /rest/v1/rpc/); use only for read-only query endpoints")
    s.add_argument("--log-level", default=None)
    s.add_argument("--auto-write", action="store_true",
                   help="let the scraper create/edit/save data AUTOMATICALLY inside the already logged-in account (test-marked data; never signs out, "
                        "switches accounts, deletes, pays, invites, shares, uploads or changes credentials)")
    s.add_argument("--write-label", action="append", default=None, metavar="LABEL",
                   help="extra control label you consider safe in --auto-write mode, e.g. \"Paste Text\" (repeatable; hard deny-list still wins)")
    s.add_argument("--no-test-uploads", action="store_true", help="with --auto-write: do NOT upload generated sample images/documents")
    s.add_argument("--max-writes", type=int, help="cap on automatic write actions (default 20)")
    s.add_argument("--manual-session", action="store_true",
                   help="YOU drive the app (logins, saves, uploads, ...); the tool only observes passively and never clicks or submits anything")
    s.add_argument("--session-label", help="label for the account/role used, e.g. userA-owner (never a credential); shown in the report")
    s.add_argument("--skip-login", action="store_true",
                   help="do not pause for manual login: scan only what the (possibly unauthenticated) profile can reach")

    l = sub.add_parser("list", help="list scans (flags interrupted ones)")
    l.add_argument("--output-dir", default="output")

    e = sub.add_parser("export", help="(re-)export a scan's evidence bundle; works for interrupted scans")
    e.add_argument("scan", help="scan id or path to a scan directory")
    e.add_argument("--output-dir", default="output")

    c = sub.add_parser("compare", help="passively compare two existing scans (e.g. two test accounts you control); sends no requests")
    c.add_argument("scan_a")
    c.add_argument("scan_b")
    c.add_argument("--output-dir", default="output")

    d = sub.add_parser("diagnostics", help="show collector diagnostics for a scan")
    d.add_argument("scan")
    d.add_argument("--output-dir", default="output")
    return p


def resolve_scan_dir(scan: str, output_dir: str) -> Path:
    d = resolve_scan(scan, output_dir)
    if d is None:
        raise SystemExit(f"error: scan not found: {scan} (use a number like 3, a folder name like 3example.com, or a path)")
    return d


def _config_from_args(a: argparse.Namespace) -> ScanConfig:
    over: dict[str, Any] = {"initial_url": a.url, "output_dir": a.output_dir, "profile_dir": a.profile_dir,
                            "headless": a.headless, "scope_enforcement": a.scope_enforcement,
                            "manual_approval": a.manual_approval, "log_level": a.log_level}
    if a.allow_http_local:
        over["allow_http_local"] = True
    if a.confirm_authorized:
        over["confirm_authorized"] = True
    if a.extra_origin:
        over["extra_allowed_origins"] = a.extra_origin
    if a.allow_post_path:
        over["allow_unsafe_method_paths"] = a.allow_post_path
    if a.manual_session:
        over["mode"] = "manual"
    if a.auto_write:
        over["interaction_mode"] = "read_write"
    if a.no_test_uploads:
        over["write_uploads"] = False
    if a.write_label:
        over["write_allow_labels"] = a.write_label
    if a.session_label:
        over["session_label"] = a.session_label
    base: dict[str, Any] = {}
    if a.config:
        path = Path(a.config)
        import tomllib
        base = tomllib.loads(path.read_text(encoding="utf-8")) if path.suffix == ".toml" else json.loads(path.read_text(encoding="utf-8"))
    base.update({k: v for k, v in over.items() if v is not None})
    if a.preset:
        PRESETS = {"quick": {"max_pages": 15, "max_depth": 2, "max_seconds": 300, "max_interactions_per_page": 5, "max_writes": 5},
                   "standard": {},
                   "thorough": {"max_pages": 300, "max_depth": 6, "max_seconds": 7200, "max_interactions_per_page": 25, "max_writes": 40,
                                "max_pages_per_pattern": 8, "page_timeout_ms": 45000}}
        for k, v in PRESETS[a.preset].items():
            base.setdefault("crawl", {}).setdefault(k, v)  # explicit flags/config below still win
    if a.include_subdomains:
        over["include_subdomains"] = True
        base["include_subdomains"] = True
    for key, field in (("max_pages", "max_pages"), ("max_depth", "max_depth"), ("max_seconds", "max_seconds"), ("max_writes", "max_writes")):
        v = getattr(a, key)
        if v is not None:
            base.setdefault("crawl", {})[field] = v
    if a.body_mode:
        base.setdefault("body", {})["mode"] = a.body_mode
    if a.store_raw_bodies:
        base.setdefault("body", {})["store_raw"] = True
    if "initial_url" not in base:
        raise SystemExit("error: a URL (argument) or initial_url in --config is required")
    return ScanConfig.model_validate(base)


def _ensure_confirmed(cfg: ScanConfig) -> ScanConfig:
    if cfg.confirm_authorized:
        return cfg
    if not sys.stdin.isatty():
        raise SystemExit("error: authorization not confirmed. Pass --confirm-authorized if you own or are authorized to assess "
                         f"{cfg.allowed_origins[0]}.")
    print(f"You are about to scan: {', '.join(cfg.allowed_origins)}")
    try:
        ans = input(f"Type '{CONFIRM_PHRASE}' to confirm you own or are authorized to assess this target: ").strip()
    except EOFError:  # e.g. stdin is NUL on Windows, where isatty() can still be True
        raise SystemExit("error: authorization not confirmed (no interactive input). Pass --confirm-authorized.")
    if ans != CONFIRM_PHRASE:
        raise SystemExit("authorization not confirmed; aborting.")
    return cfg.model_copy(update={"confirm_authorized": True})


async def _approve(info: dict[str, Any]) -> bool:
    ans = await asyncio.to_thread(input, f"Click uncertain control '{info['label']}' on {info['url']}? [y/N] ")
    return ans.strip().lower() == "y"


def cmd_scan(a: argparse.Namespace) -> int:
    try:
        cfg = _ensure_confirmed(_config_from_args(a))
    except (ValidationError, ValueError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    print(f"Approved origins: {', '.join(cfg.allowed_origins)} | body capture: {cfg.body.mode} | scope enforcement: {cfg.scope_enforcement}")
    try:
        kw: dict[str, Any] = {"approve": _approve if cfg.manual_approval else None}
        if a.skip_login:
            async def _no_wait(url: str) -> None:
                print("Skipping manual login pause (--skip-login): only content reachable without further login will be covered.")
            kw["login_prompt"] = _no_wait
        scan_dir = asyncio.run(run_scan(cfg, **kw))
    except KeyboardInterrupt:
        print("\nInterrupted. Persisted data is kept; export it with: webaudit export <scan-id>", file=sys.stderr)
        return 130
    m = json.loads((scan_dir / "manifest.json").read_text(encoding="utf-8"))
    print(f"\nScan {m['scan_id']} {m['completion_status']}. Bundle: {scan_dir}")
    cov = json.loads((scan_dir / "coverage.json").read_text(encoding="utf-8")).get("crawl", {})
    if cov.get("write_actions"):
        print(f"\nAUTO-WRITE: {len(cov['write_actions'])} write action(s) were performed in the logged-in account. Test data is marked with "
              f"'{cov.get('write_test_marker_prefix')}-N' - review/delete it in the app. Details: coverage.json -> crawl.write_actions")
    blocked = [b for b in cov.get("scope_guard_blocks", []) if b["reason"] == "state_changing_method"]
    if blocked:
        uniq = sorted({f"{b['method']} {b['origin']}{b['path']}" for b in blocked})[:8]
        print(f"Note: {len(blocked)} state-changing request(s) were blocked by the safety guard (coverage gap), e.g.:")
        for u in uniq:
            print(f"  - {u}")
        print("If these are read-only queries (GraphQL/RPC), re-run with --allow-post-path <prefix> after reviewing them.")
    print(f"Report: {scan_dir / 'report.md'}  |  findings: {m['files']['findings.json'].get('records', 0)}  |  "
          f"collection errors: {len(m['collection_errors'])}")
    return 0


def cmd_list(a: argparse.Namespace) -> int:
    rows = list_scans(a.output_dir)
    if not rows:
        print("no scans found")
        return 0
    for r in rows:
        extra = " ".join(x for x in (r.get("mode"), r.get("session_label")) if x)
        print(f"{r['scan_id']:<32} {r['status']:<12} exported={r.get('exported')}  {extra}  {r.get('initial_url') or ''}")
    return 0


def cmd_export(a: argparse.Namespace) -> int:
    d = resolve_scan_dir(a.scan, a.output_dir)
    m = exporter.export_scan(d)
    print(f"exported {m['scan_id']} status={m['completion_status']} -> {d}")
    if m["completion_status"] == "interrupted":
        print("note: scan was interrupted; the bundle contains only data persisted before the interruption.")
    return 0


def cmd_compare(a: argparse.Namespace) -> int:
    da, db_ = resolve_scan_dir(a.scan_a, a.output_dir), resolve_scan_dir(a.scan_b, a.output_dir)
    res = compare_scans(da, db_)
    out = Path(a.output_dir) / f"comparison_{da.name}_vs_{db_.name}.md"
    out.write_text(render_markdown(res), encoding="utf-8")
    print(f"compared {da.name} vs {db_.name}: only-A {len(res['endpoints_only_in_a'])}, only-B {len(res['endpoints_only_in_b'])}, "
          f"status differences {len(res['status_differences'])}, shared object URLs {len(res['object_urls_both_sessions_read_successfully'])}")
    print(f"written: {out}")
    return 0


def cmd_diagnostics(a: argparse.Namespace) -> int:
    d = resolve_scan_dir(a.scan, a.output_dir)
    from .event_store.sqlite import SqliteEventStore
    db = SqliteEventStore(d / "scan.sqlite")
    try:
        out = {"status": exporter.detect_status(d), "events_persisted": db.event_count(), "diagnostics": db.get_meta("diagnostics", {}),
               "coverage": db.get_meta("coverage", {})}
    finally:
        db.close()
    print(json.dumps(out, indent=2, default=str))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    a = build_parser().parse_args(argv)
    return {"scan": cmd_scan, "list": cmd_list, "export": cmd_export, "diagnostics": cmd_diagnostics,
                                                                   "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
