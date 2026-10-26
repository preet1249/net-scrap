# Architecture

```
 Chromium (persistent dedicated profile)
   │  CDP Network.* events (per page/frame session)        Playwright request/response/page/websocket/serviceworker events
   ▼                                                        ▼
 CDPNetworkCollector ───────────── EventSink (bounded asyncio.Queue) ◄──────── NetworkCollector
   │ on_event (cheap)                       │
   ▼                                        ▼
 BodyCapturer (opt-in, bounded)      PersistenceWorker ── redact ──► SQLite (scan.sqlite) + live JSONL (fsync per batch)
                                            ▲
 Crawler + ScopeGuard (route + CDP Fetch)   │ replay at export time
                                            ▼
                         Correlator → RequestRecords → inventory + security_rules → exporter (bundle, report, manifest)
```

| Module | Responsibility |
|---|---|
| `config` | Pydantic-validated configuration; exact-origin scope; rejects credential-like keys; authorization confirmation |
| `browser` | Dedicated persistent profile (refuses ordinary profiles), manual login, `ScopeGuard` |
| `instrumentation/cdp.py` | Per-page/frame CDP session; handlers registered **before** `Network.enable`; callbacks only enqueue |
| `instrumentation/playwright_events.py` | Separate, source-attributed Playwright observations (never merged into request counts) |
| `instrumentation/bodies.py` | `Network.getResponseBody` only after `loadingFinished`; byte/origin/total budgets; explicit status per body |
| `event_store/` | `EventSink` (bounded queue, drop accounting), `PersistenceWorker` (validate → redact → write), SQLite, JSONL |
| `correlation` | Request state machine; redirect hops; ordinal extra-info matching; bounded cache; orphan preservation |
| `session` | Wires collectors/worker/stores; graceful shutdown (quiesce → bodies → flush → detach) |
| `scope` | Exact origin matching, userinfo/scheme checks, metadata/private-target protection |
| `crawler` | BFS with depth/page/time/request budgets, URL-pattern dedup, safe-control classifier, popups, coverage |
| `security_rules/` | Deterministic passive rules → `Finding` (status observed / heuristic / untested_hypothesis) |
| `exporter`, `report`, `inventory` | Replay → bundle; Markdown report; endpoint inventory |
| `cli`, `scan` | Commands and the orchestration (login uncollected → arm → guard → crawl → flush → export) |

## Key design decisions (verified empirically, Chromium 139 / Playwright 1.54)

* **Events are the source of truth.** Derived data (request records, findings) is a pure function of the persisted events, so
  `export` can rebuild everything after a crash.
* **Callbacks never block.** CDP handlers call `EventSink.offer()` (`put_nowait`). On overflow the event is dropped **and counted**
  (`dropped`, `dropped_by_type`), surfaced in the manifest. Async producers use `await put()` (true backpressure). Events arriving
  after finalization are counted separately (`late_after_close`).
* **Correlation scope** = scan + CDP session + requestId; redirect hops split on `redirectResponse`. Extra-info events are matched by
  *ordinal* per requestId (k-th request extra-info ↔ hop k; k-th response extra-info ↔ k-th response), independent of arrival order,
  with status-code cross-checks (`ambiguous`) and orphan retention.
* **Observed CDP facts** (tested): the primary `response.headers` merges repeated headers with `", "` and omits `Set-Cookie`;
  `responseReceivedExtraInfo.headers` joins repeats with `\n`; `headersText` keeps exact lines (used for header-entry fidelity).
  A CORS-blocked request produces `responseReceivedExtraInfo` + `loadingFailed(corsErrorStatus)` but **no** `responseReceived`.
  Preflights are separate requestIds with `initiator.type = "preflight"`.
* **Scope guard**: Playwright `context.route` is *not* invoked for redirect hops, so a second layer uses per-page CDP `Fetch`
  interception at the response stage of Document requests and fails off-scope redirects before the browser follows them.
* **Login phase is intentionally uncollected and method-unguarded** (credentials are POSTed there). Requests that were in flight when
  collectors armed appear as incomplete/orphan records (`no requestWillBeSent observed`).
* **Header provenance**: header entries carry `source` = `primary` | `extra_info` | `playwright`, so the same header may appear up to
  three times; consumers de-duplicate (`inventory.header_values`).

## Data model
Versioned pydantic models in `models.py` (`SCHEMA_VERSION = "1.0"`, `extra="forbid"`): `NetworkEvent`, `RequestRecord`, `PageRecord`,
`Finding`, `ScanMetadata`, `HeaderEntry`.
