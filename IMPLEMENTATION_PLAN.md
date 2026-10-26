# Implementation Plan

Environment (verified): Windows 11, Python 3.13.5, Playwright 1.54.0 (Chromium 139.0.7258.5, CDP protocol 1.3),
pydantic 2.10.4, pytest 8.4.2, pytest-asyncio 1.3.0, aiohttp 3.13.2 (test fixture server only).
No `uv` available -> reproducible pins in `pyproject.toml` + `requirements.lock` (pip-freeze equivalent).

Package: `src/webaudit/`. Run: `python -m webaudit ...`. Tests: `python -m pytest`.

## Modules

| Module | Responsibility | Phase |
|---|---|---|
| `models.py` | Versioned pydantic schemas (NetworkEvent, RequestRecord, PageRecord, Finding, ScanMetadata) | 1 |
| `redaction.py` | Header/URL/body redaction (never claimed perfect) | 1, 3 |
| `logging_setup.py` | Structured JSON logging with redaction filter | 1 |
| `event_store/sink.py` | Bounded queue (`EventSink`), drop accounting, backpressure | 1 |
| `event_store/jsonl.py`, `sqlite.py`, `worker.py` | Incremental JSONL, SQLite, persistence worker | 1 / 3 |
| `instrumentation/cdp.py` | `CDPNetworkCollector` (per page/frame CDP sessions, enable before navigation) | 1 |
| `instrumentation/playwright_events.py` | `NetworkCollector` (request/response/popup/websocket/service worker, source-attributed) | 1/2 |
| `instrumentation/bodies.py` | Opt-in `Network.getResponseBody` after loadingFinished, bounded | 3 |
| `correlation.py` | Request state machine, redirect hops, out-of-order extra-info, bounded cache | 2 |
| `config.py` | Validated scan config, origin scope | 4 |
| `scope.py` | URL/IP/origin policy, redirect revalidation | 4 |
| `browser.py` | Persistent profile, manual login, page registration, arm collectors | 4 |
| `crawler.py` | Budgeted, scoped, read-only discovery, coverage | 4 |
| `security_rules/` | Passive rules -> `Finding` with evidence refs and limitations | 5 |
| `exporter.py` | JSONL/JSON/Markdown/manifest bundle | 3/5 |
| `cli.py` | `scan`, `list`, `export`, `diagnostics` | 4/6 |
| `tests/fixture_app.py` | Local aiohttp app (two origins) covering all scenarios | 1 |

## Design decisions
- CDP callbacks are synchronous and only call `EventSink.offer()` (non-blocking `put_nowait`). If the queue is full the event is
  **dropped and counted** (callbacks cannot await); drops are reported in diagnostics/manifest. Async producers (Playwright source) use
  `await sink.put()` = true backpressure.
- Persisted events are redacted by default. Correlation is a deterministic function of the persisted event stream, so it is run live
  for diagnostics and **replayed** from SQLite on export — this is what makes interrupted scans exportable.
- Correlation scope: scan + target/session + requestId; redirect hops split on `redirectResponse`; extra-info events are matched by
  ordinal per requestId (k-th request extra-info <-> k-th hop; k-th response extra-info <-> k-th response) and kept as unmatched when no primary exists.
- Page-level CDP sessions are *not* browser-wide: popups' earliest requests, workers and OOPIFs may be partially covered; recorded as coverage gaps.
- Scope guard (crawler only) uses `context.route`, which Playwright documents as disabling the HTTP cache; the passive collector installs no routes.

## Acceptance criteria (spec §12) — each marked only because an executed test passed

| # | Criterion | Status | Evidence (test file::test) |
|---|---|---|---|
| 1 | Collector attaches before initial navigation | verified | phase1 `test_collector_attached_before_navigation...`; phase4 `test_full_scan...` (attach after login prompt, before first request) |
| 2 | Each resource type and lifecycle event detected | verified | phase1 `test_resource_types_and_scenarios_detected`, `...failure_http_errors_and_websocket` |
| 3 | Preflight preserved as independent record | verified | phase1 `test_preflight_emitted_as_independent_request`; phase2 `test_preflight_is_separate_record` |
| 4 | Redirect hops/request IDs correlated | verified | phase2 `test_redirect_chain_hops_and_ordinal_extra_info`, integration test |
| 5 | Extra-info preserved when out of order | verified | phase2 `test_out_of_order_arrival_is_equivalent` (5 orders), `...early`, orphan tests |
| 6 | Failed/incomplete request does not crash | verified | phase2 failed/incomplete/orphan tests; phase1 failure scenario |
| 7 | Body retrieval failure recorded | verified | phase3 `test_body_retrieval_failure_is_recorded` (stubbed CDP error; real-browser path covered by happy-path + skip statuses) |
| 8 | Crawler never leaves scope without approval | verified for `guard` mode | phase4 scope unit test, `test_guard_blocks_redirect_escape`, `test_full_scan...`; `observe` mode only *detects* (`test_observe_mode_detects_escape_post_hoc`) |
| 9 | No automatic destructive submission | verified | phase4 `test_full_scan...` (zero POST reach server; delete/form/unsafe controls skipped), `test_manual_approval_gate...` |
| 10 | Fixture secrets redacted from default output | verified | phase1/3/5/6 leak scans over whole bundle |
| 11 | Interrupted scans identifiable and exportable | verified | phase3 `test_interrupted_scan_is_identified_and_exportable` (simulated by skipping graceful close; not a real process kill) |
| 12 | Report separates facts / heuristics / hypotheses / gaps | verified | phase5 `test_end_to_end_audit_of_fixture` |
| 13 | Test suite runs offline against local fixtures | verified | tests only contact 127.0.0.1/localhost servers (Chromium must be installed) |
| 14 | Core modules have tests and structured logging | verified | phases 1–6; logging redaction test |

## Phase results (executed)
| Phase | Tests | Result |
|---|---|---|
| 1 CDP proof | tests/test_phase1_cdp.py | 10 passed (one test initially failed and revealed real CDP header semantics; a second exposed a header-redaction leak — both fixed) |
| 2 Correlation | tests/test_phase2_correlation.py | 23 passed (real-browser run revealed CORS-blocked requests have no `responseReceived`; handled) |
| 3 Persistence/evidence/bodies | tests/test_phase3_storage.py | 13 passed |
| 4 Browser/crawler/scope | tests/test_phase4_crawl.py | 15 passed (revealed that Playwright `route` is not invoked on redirect hops → CDP `Fetch` layer added) |
| 5 Security rules | tests/test_phase5_rules.py | 14 passed (revealed `Access-Control-Allow-Credentials` was wrongly redacted → fixed) |
| 6 CLI/docs/misc | tests/test_phase6_misc.py | 12 passed |
| Full suite | `python -m pytest` | **87 passed** (run repeatedly; one timing flake in a test's login-phase snapshot was fixed) |

Live smoke test (not part of the suite): unauthenticated, headless, passive scan of the user-authorized dashboard of the project owner
completed; it led to fixes (duplicate secret findings, Supabase anon-JWT classification, POST-read blocking disclosure, orphan notes).
An *authenticated* run was not performed (needs the user's manual login).

## Known gaps / not implemented (honest list)
* Worker (service/shared/dedicated) network traffic is not instrumented; popup first requests can be missed (tested + documented).
* Raw body storage is not encrypted (documented); no automatic retention enforcement.
* No active/authorization testing mode (by design). No HTML report, Rich UI or Jinja2 (optional in spec). No `uv.lock` (uv unavailable) — `requirements.lock` instead.
* Interruption was simulated, not tested with a hard process kill; CDP `Fetch` guard layer was verified on Chromium 139 only.
