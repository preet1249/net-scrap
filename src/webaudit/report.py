"""Markdown report. Distinguishes observed facts, heuristic findings, untested hypotheses and coverage gaps."""
from __future__ import annotations

from collections import Counter
from typing import Any

from .models import Finding, RequestRecord
from .redaction import redact_url

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _finding_md(f: Finding) -> str:
    lines = [f"#### {f.finding_id} — {f.title}", "",
             f"- **Severity:** {f.severity}  |  **Confidence:** {f.confidence}  |  **Status:** {f.status}  |  **Rule:** `{f.rule_id}`",
             f"- **What was seen:** {f.description}"]
    if f.location:
        lines.append(f"- **Location:** {f.location}")
    if f.redacted_sample:
        lines.append(f"- **Redacted sample:** `{f.redacted_sample}`")
    if f.impact:
        lines.append(f"- **Potential impact:** {f.impact}")
    lines.append(f"- **Limitations / uncertainty:** {f.limitations or 'None recorded.'}")
    if f.remediation:
        lines.append(f"- **Remediation:** {f.remediation}")
    if f.verification_steps:
        lines.append("- **How to verify:**")
        lines += [f"  {i}. {s}" for i, s in enumerate(f.verification_steps, 1)]
    lines.append("- **Evidence:** " + (", ".join(f"`{e}`" for e in f.evidence_references) or "none"))
    return "\n".join(lines) + "\n"


def render_report(meta: dict[str, Any], findings: list[Finding], records: list[RequestRecord], endpoints: list[dict[str, Any]],
                  pages: list[dict[str, Any]], coverage: dict[str, Any], manifest_files: dict[str, Any]) -> str:
    out: list[str] = []
    w = out.append
    w(f"# Security Audit Report — `{meta.get('scan_id')}`\n")
    w("> Passive, browser-observed evidence only. This report does not prove the absence of vulnerabilities and does not claim to have "
      "discovered every endpoint. Secret values and personal data are never printed; samples are redacted.\n")
    w("## Scan summary\n")
    w(f"- **Initial URL:** {redact_url(str(meta.get('initial_url')))}")
    w(f"- **Approved origins:** {', '.join(meta.get('allowed_origins', []))}")
    w(f"- **Started:** {meta.get('started_at')}  |  **Completed:** {meta.get('completed_at') or 'n/a'}")
    cfg_ = meta.get("configuration") or {}
    w(f"- **Mode:** {cfg_.get('mode', 'crawl')}" + (f"  |  **Session label:** {cfg_['session_label']}" if cfg_.get("session_label") else ""))
    w(f"- **Completion status:** `{meta.get('completion_status')}`" + (
        "  — **interrupted scan: data is partial**" if meta.get("completion_status") == "interrupted" else ""))
    w(f"- **Browser:** {meta.get('browser_version') or 'unknown'}  |  **CDP protocol:** {meta.get('protocol_version') or 'unknown'}")
    w(f"- **Requests recorded (per redirect hop):** {len(records)}  |  **Endpoints observed:** {len(endpoints)}  |  **Pages recorded:** {len(pages)}\n")

    by_status = {s: [f for f in findings if f.status == s] for s in ("observed", "heuristic", "untested_hypothesis")}
    w("### Findings overview\n")
    w("| Severity | Observed | Heuristic | Untested hypothesis |\n|---|---|---|---|")
    for sev in SEV_ORDER:
        c = [sum(1 for f in by_status[s] if f.severity == sev) for s in by_status]
        if any(c):
            w(f"| {sev} | {c[0]} | {c[1]} | {c[2]} |")
    if not findings:
        w("| _none_ | 0 | 0 | 0 |")
    w("")

    w("## 1. Observed facts\n")
    w("Directly observed in captured traffic. Each can be re-checked against the referenced evidence records.\n")
    st = Counter(str(r.response_status) for r in records if r.response_status is not None)
    w(f"- HTTP status distribution: {', '.join(f'{k}×{v}' for k, v in sorted(st.items())) or 'none'}")
    failed = [r for r in records if r.state == "failed"]
    w(f"- Failed requests: {len(failed)}" + (f" (reasons: {', '.join(sorted({r.failure_reason or '?' for r in failed}))})" if failed else ""))
    w(f"- Preflight (OPTIONS) requests: {sum(1 for r in records if r.is_preflight)}")
    w(f"- Redirect responses: {sum(1 for r in records if r.state == 'redirected')}")
    w("\n**Endpoint inventory (observed only; first 40):**\n")
    w("| Method | Origin | Path | Count | Statuses | Types | Auth indicators |\n|---|---|---|---|---|---|---|")
    for e in endpoints[:40]:
        w(f"| {e['method']} | {e['origin']} | `{e['normalized_path']}` | {e['count']} | {','.join(e['status_codes']) or '-'} | "
          f"{','.join(e['resource_types']) or '-'} | {','.join(e['auth_indicators']) or '-'} |")
    if len(endpoints) > 40:
        w(f"\n_…{len(endpoints) - 40} more in `endpoints.jsonl`._")
    w("")
    for f in by_status["observed"]:
        w(_finding_md(f))

    w("## 2. Heuristic findings\n")
    w("Pattern- or inference-based indicators. They are **candidates requiring manual verification**, not confirmed vulnerabilities.\n")
    for f in by_status["heuristic"]:
        w(_finding_md(f))
    if not by_status["heuristic"]:
        w("_None._\n")

    w("## 3. Untested hypotheses\n")
    w("Pointers for authorized, manual follow-up testing. **Nothing in this section was tested.**\n")
    for f in by_status["untested_hypothesis"]:
        w(_finding_md(f))
    if not by_status["untested_hypothesis"]:
        w("_None._\n")

    w("## 4. Coverage gaps and limitations\n")
    crawl = coverage.get("crawl") or {}
    if crawl.get("write_actions"):
        w(f"- **Automatic writes performed: {len(crawl['write_actions'])}** (mode read_write). Test data carries the marker "
          f"`{crawl.get('write_test_marker_prefix')}-N`; review and delete it in the application:")
        for a in crawl["write_actions"][:20]:
            w(f"  - {a['kind']} on `{a['page']}` — button \"{a.get('button')}\"" + (f", {('file ' + a['file']) if a.get('file') else 'fields ' + str(a.get('fields'))}, marker `{a['marker']}`" if a.get("marker") else ""))
    rb = crawl.get("write_readback") or {}
    wr = rb.get("write_requests") or {}
    if wr.get("observed") is not None and crawl.get("write_actions"):
        w(f"- **Write requests actually sent: {wr['observed']}** — completed {wr['completed']}, HTTP errors {wr['http_error']}, "
          f"failed/aborted {wr['failed_or_aborted']} (an aborted write may NOT have been applied)")
        for q in wr.get("requests", [])[:10]:
            w(f"  - {q['method']} `{q['url'][:100]}` → {q['status'] or q['failure'] or q['state']}" + (f", payload `{q['payload']}`" if q.get("payload") else ""))
    if rb.get("file_uploads_attempted"):
        w(f"- File uploads attempted: {', '.join(sorted({f['file'] for f in rb['file_uploads_attempted']}))}. {rb.get('file_upload_note', '')}")
    if rb.get("checked"):
        w(f"- **Read-back after writes:** confirmed {len(rb.get('confirmed', {}))} of {len(rb.get('markers', []))} written marker(s) in response bodies"
          + (f"; NOT seen: {rb.get('unconfirmed')}" if rb.get("unconfirmed") else "") + ".")
        for m, hits in list(rb.get("confirmed", {}).items())[:6]:
            w(f"  - `{m}` returned by {', '.join(sorted({h['method'] for h in hits}))} {hits[0]['url']}")
    elif rb.get("note"):
        w(f"- Read-back after writes: not checked — {rb['note']}")
    if crawl.get("read_back_pages"):
        w(f"- Read-back pages revisited: {len(crawl['read_back_pages'])}")
    if crawl.get("session_lost"):
        w("- **Session appeared to end during the crawl (redirected to a login page); the crawl stopped and no credentials were entered.**")
    w(f"- Pages by navigation status: {crawl.get('by_navigation_status', {})}")
    if crawl.get("budgets_hit"):
        w(f"- **Budgets exhausted (coverage is incomplete):** {', '.join(crawl['budgets_hit'])}")
    skipped = crawl.get("skipped", {})
    if skipped:
        w("- Skipped (not visited): " + "; ".join(f"{k}×{v}" for k, v in sorted(skipped.items())))
    inter = crawl.get("interactions", {})
    if inter:
        w(f"- UI interactions: {inter}  (controls classed unsafe/uncertain were intentionally not clicked)")
    blocks = crawl.get("scope_guard_blocks") or []
    if blocks:
        c = Counter(b["reason"] for b in blocks)
        w("- Requests blocked by the scope guard: " + ", ".join(f"{k}×{v}" for k, v in c.items()))
        uniq = sorted({f"{b['method']} {b['origin']}{b['path']} ({b['reason']})" for b in blocks})[:15]
        for u in uniq:
            w(f"  - blocked: `{u}` — not observed; pages depending on it may be incomplete. If it is a read-only query, allow it with "
              "`--allow-post-path` (reviewing it first).")
    w(f"- Incomplete/evicted request records: {coverage.get('incomplete_requests', 0)}")
    corr = coverage.get("correlation", {})
    if corr.get("orphan_extra_info") or corr.get("ambiguous"):
        w(f"- Correlation anomalies: orphan extra-info={corr.get('orphan_extra_info', 0)}, ambiguous={corr.get('ambiguous', 0)}")
    bc = coverage.get("body_capture") or {}
    w(f"- Response-body capture: {bc.get('statuses') or 'disabled/none captured'}")
    if bc.get("request_body_statuses"):
        w(f"- Request-payload capture: {bc['request_body_statuses']}")
    if bc.get("unavailable_count"):
        w(f"- Bodies unavailable/not fetched: {bc['unavailable_count']} (e.g. {[x.get('url') for x in bc.get('unavailable_examples', [])[:3]]})")
    dd = (bc.get("capturer") or {}).get("duplicates_skipped")
    if dd:
        w(f"- Duplicate bodies not re-captured: {dd} ({(bc.get('capturer') or {}).get('dedupe_policy')})")
    tg = coverage.get("unsupported_or_partial_targets") or {}
    if tg:
        w(f"- Targets: {tg} (workers are not instrumented; frames without their own session share the parent's coverage)")
    for cls, d in (coverage.get("failures_by_class") or {}).items():
        w(f"- Failed requests — {cls} ×{d['count']}: {d['meaning']} (e.g. `{d['examples'][0]}`)")
    for o in (coverage.get("skipped_scope_origins") or [])[:12]:
        w(f"- Off-scope origin not visited: `{o['origin']}` ×{o['count']} — {o['hint']}")
    ch = coverage.get("observed_channels") or {}
    if ch:
        w(f"- Channels: WebSockets (CDP/Playwright) {ch.get('websockets_cdp', 0)}/{ch.get('websockets_playwright', 0)}, popups {ch.get('popups', 0)}, "
          f"service workers reported {ch.get('service_workers_reported', 0)}; NOT instrumented: {', '.join(ch.get('not_instrumented', []))}")
    pf = coverage.get("pages_failed_or_timeout") or []
    if pf:
        w("- Pages that failed/timed out: " + "; ".join(f"{p['status']} {p['url']}" for p in pf[:8]))
    if coverage.get("rule_errors"):
        w(f"- **Rule errors (some checks did not run):** {coverage['rule_errors']}")
    q = (coverage.get("collector_diagnostics") or {}).get("queue", {})
    if q.get("dropped"):
        w(f"- **Events dropped (queue overflow): {q['dropped']}** {q.get('dropped_by_type')}")
    w("\n**Standing limitations:**\n")
    for l in coverage.get("limitations", []):
        w(f"- {l}")
    w("\n## 5. Evidence bundle\n")
    w("| File | Bytes | SHA-256 |\n|---|---|---|")
    for name, info in manifest_files.items():
        w(f"| `{name}` | {info.get('bytes', '')} | `{str(info.get('sha256', ''))[:16]}…` |")
    w("\nFull checksums and record counts are in `manifest.json`. Evidence references use the form `request:<record_id>`, "
      "`body:<body_id>` and `event:<event_id>`.\n")
    return "\n".join(out)
