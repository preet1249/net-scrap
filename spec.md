# Authenticated Web Security Auditor
## Engineering Specification and Claude Code Implementation Brief

### 1. Project objective

Build a local-first Python application that accepts a URL for a web application I own or am authorized to assess, opens a Chromium browser, lets me authenticate manually, explores accessible application pages, captures browser network traffic, evaluates passive security indicators, and exports a portable evidence bundle for manual analysis with an AI model.

The scanner must be reliable, auditable, modular, and honest about its coverage. It must never claim to have discovered every endpoint or proven security solely from browser traffic.

### 2. Technology stack

Required:
- Python 3.11 or newer.
- Playwright Python async API for browser lifecycle, navigation, page discovery, interactions, and browser events.
- Chromium DevTools Protocol through Playwright's `context.new_cdp_session(page)` for lower-level network events.
- Python asyncio for asynchronous collection and concurrency control.
- SQLite through the built-in `sqlite3` module for structured scan data.
- Pydantic for validated data models.
- Standard-library JSON and JSON Lines for event serialization and exports.
- Pytest and pytest-asyncio for automated testing.
- A Markdown report generator and a command-line interface.

Optional:
- Rich for terminal progress and summaries.
- Jinja2 for an HTML report.
- Beautiful Soup only if HTML parsing is actually needed; it is not a network capture library.

Pin compatible dependency versions in `pyproject.toml` and `uv.lock` or an equivalent reproducible lock file. Do not invent APIs: consult installed package documentation and inspect method signatures when necessary.

### 3. Architecture

Implement these independent modules:

1. `config`
   - Validated scan configuration.
   - URL validation, allowed origins, exclusions, crawl limits, body-capture policy, and storage paths.

2. `browser`
   - Launch Chromium using Playwright.
   - Create and manage a dedicated persistent browser profile.
   - Support manual login, including MFA.
   - Keep authenticated browser state local.
   - Create pages and register newly opened tabs/popups.
   - Register network instrumentation before navigating.

3. `instrumentation`
   - Implement a `NetworkCollector` for Playwright events.
   - Implement a separate `CDPNetworkCollector` for Chromium CDP events.
   - Make instrumentation reusable for each page/target.
   - Keep CDP sessions alive until collection is finalized.
   - Do not use browser request interception by default.

4. `event_store`
   - Persist immutable event records to SQLite.
   - Write JSONL exports incrementally.
   - Handle partial scans, process interruption, and recovery.
   - Preserve repeated header entries when available.
   - Prevent unbounded in-memory event queues.

5. `correlation`
   - Correlate request events, response events, extra-info events, redirects, completion, failures, and optional body retrieval.
   - Scope correlation by scan, CDP session/target and request ID.
   - Preserve original events as well as derived request summaries.
   - Represent incomplete correlation explicitly instead of silently dropping data.

6. `crawler`
   - Discover internal links and accessible routes.
   - Record page titles, URLs, navigation outcomes and discovery source.
   - Explore same-origin links and safe, read-only UI interactions.
   - Use configurable depth, page, time, and request budgets.
   - Detect repeated routes and normalized URL patterns.
   - Avoid automatic destructive actions, purchases, account changes, invitations, deletions and external form submissions.
   - Allow manual approval for uncertain actions.
   - Record skipped pages and coverage gaps.

7. `security_rules`
   - Run deterministic, passive checks over captured evidence.
   - Return structured findings with severity, confidence, evidence references, rationale, limitations and remediation.
   - Never present a heuristic as a confirmed vulnerability.

8. `exporter`
   - Export JSONL network events.
   - Export endpoint and page inventories.
   - Export findings and scan metadata as JSON.
   - Generate a Markdown report.
   - Produce a manifest with record counts, artifact paths, capture settings, errors and coverage limitations.

9. `cli`
   - Provide commands for starting a scan, listing scans, exporting a scan, and inspecting collector diagnostics.
   - Show progress without exposing sensitive header values or payloads.

### 4. Browser and authentication lifecycle

The initial workflow must be:

1. User supplies the dashboard URL.
2. Validate the URL and require HTTPS by default; allow HTTP only for explicitly configured local development environments.
3. Require explicit confirmation that the target is owned by the user or authorized for assessment.
4. Resolve and confirm the permitted origin scope.
5. Launch a dedicated Chromium profile. Do not attach to the user's ordinary browser profile or read unrelated browser credentials.
6. Allow the user to authenticate manually.
7. After authentication, arm or verify the collectors before navigating into the scan.
8. Explore only the configured scope.
9. Flush pending events and close sessions cleanly.
10. Export the report and evidence bundle.

Never ask the user to paste passwords, session cookies, bearer tokens or MFA codes into command-line arguments or configuration files.

### 5. CDP instrumentation requirements

Use Playwright's documented API:

- `context.new_cdp_session(page)`
- `CDPSession.send("Network.enable", ...)`
- `CDPSession.on(event_name, handler)`

Enable Network collection before the first target navigation. Use a configurable buffer size if supported and appropriate. Do not clear cookies, caches, or local storage as part of a normal scan.

Register handlers for the following protocol events where supported by the installed Chromium version:

- `Network.requestWillBeSent`
- `Network.requestWillBeSentExtraInfo`
- `Network.responseReceived`
- `Network.responseReceivedExtraInfo`
- `Network.loadingFinished`
- `Network.loadingFailed`
- `Network.requestServedFromCache`
- `Network.webSocketCreated`
- `Network.webSocketHandshakeResponseReceived`
- `Network.webSocketFrameSent`
- `Network.webSocketFrameReceived`
- `Network.webSocketClosed`

Handle optional or unsupported events without crashing the scan. Verify event availability using the protocol version and Chromium version.

CDP callbacks should perform minimal work. They should enqueue immutable event data into a bounded asynchronous queue. A dedicated persistence worker should write records. Define backpressure behavior, queue limits, error reporting, and graceful shutdown.

Do not assume events arrive in a convenient order. In particular:

- Extra-info events may arrive before or after the corresponding primary event.
- Redirects can reuse a request ID and may generate multiple request/response stages.
- A response may be absent for a failed request.
- A response can complete with an HTTP error status and still be a successfully completed network request.
- Cached and service-worker-mediated responses can have different observability.
- Browser targets and worker targets may require separate instrumentation.
- A page-level CDP session must not be described as complete browser-wide coverage.

Maintain a request state machine and bounded correlation cache. Preserve unmatched extra-info events and incomplete requests for diagnostics. Use scan ID + target/session ID + request ID as the correlation scope, and model redirect hops separately.

For Playwright, also observe `request`, `response`, `requestfinished`, `requestfailed`, `page`, `popup`, and `websocket` events. Do not double-count these independent observation sources as separate HTTP requests. Preserve source attribution.

Do not install route handlers or modify outgoing requests in the passive collector. If a future active testing mode is implemented, isolate it behind a separate explicit opt-in.

### 6. Header fidelity

Use `Network.requestWillBeSent` and the corresponding extra-info events for CDP network evidence. Preserve raw protocol event fields in a versioned event envelope.

Use Playwright's `request.all_headers()` and `response.all_headers()` as complementary sources. Where exact repeated header entries matter, use `headers_array()` when available.

Store header names and values without silently overwriting repeated entries. Record whether a value came from a primary event, an extra-info event, or Playwright.

Do not claim that serialized CDP data is a byte-for-byte packet capture. It is structured browser instrumentation, not a raw network packet trace.

### 7. Response-body capture

Make body capture disabled by default.

Provide a configurable mode:

- `none`: metadata and headers only.
- `selected`: capture eligible API responses such as JSON with strict size limits.
- `all_supported`: attempt all supported body types subject to strict limits and exclusions.

For each eligible response, wait for the relevant loading-completed event and then attempt `Network.getResponseBody` using the appropriate session and request ID.

Requirements:

- Do not retrieve bodies for requests that have not completed.
- Handle body-not-found, evicted-body, unsupported target and protocol errors.
- Set maximum body bytes, total scan storage, and per-origin limits.
- Record truncation, retrieval failures, content type, and capture status.
- Avoid treating a character count as an exact byte count.
- Do not automatically store binary, media, image, font or large download bodies.
- Do not export sensitive data by default.
- Do not fetch additional URLs discovered inside response bodies automatically.

Store a redacted representation by default. If raw evidence is explicitly enabled for an authorized assessment, store it separately with restrictive local permissions, encryption where appropriate, and a documented retention policy. Redaction must not be described as perfect.

### 8. Scope and safe crawling

Default scope is the exact configured origin: scheme, hostname and port.

Allow additional origins only through explicit configuration and confirmation. Do not infer authorization from a redirect, CORS response or link.

Block or require explicit approval for:
- Navigation to an unapproved origin.
- State-changing actions and destructive controls.
- File uploads.
- Payment and checkout flows.
- Account deletion, invitations and permission changes.
- Arbitrary form submission.
- Automated payload injection.
- Requests to cloud metadata endpoints, localhost, private network targets or other infrastructure outside the approved target scope.

Revalidate navigation and redirect destinations. Avoid relying solely on string prefix checks for hostnames. Validate normalized URLs and IP addresses, and prevent redirect-based scope escape.

Discover internal links, navigation elements, tabs, pagination and safe read-only controls. Avoid blindly clicking every button. Use page and request budgets, repeated-state detection, depth limits, rate limits and configurable timeouts.

Provide a manual approval mechanism for actions that cannot confidently be classified as read-only.

### 9. Security checks

Implement passive rules with explicit limitations.

A. Response headers:
- HSTS applicability and configuration.
- Content Security Policy presence and suspiciously permissive directives.
- `X-Content-Type-Options`.
- Frame-protection policy using CSP and/or `X-Frame-Options`.
- Referrer policy.
- Mixed-content indicators where evidence permits.
- Insecure cookie attributes when visible in `Set-Cookie`.

B. CORS:
- `Access-Control-Allow-Origin`.
- `Access-Control-Allow-Credentials`.
- Allowed methods and headers.
- Suspicious wildcard/credential combinations.
- Origin reflection indicators, when observed.
- Whether evidence comes from a real preflight response, a normal response, or a browser-generated failure.

Do not claim a CORS vulnerability from one header alone. Explain the browser origin, credentials context, response accessibility and evidence limitations.

C. Client-side exposure:
- Secret-looking values in selected JavaScript, JSON, HTML and source-map content.
- Public configuration versus plausible secret credentials.
- Internal endpoint names, debug information and exposed source maps.
- Sensitive personal or account data returned in API responses.
- Unexpected third-party destinations.

Never print discovered secret values in terminal output or the default report. Report the location, type, redacted sample and evidence reference. Treat heuristic secret detection as a candidate finding requiring verification.

D. API inventory:
- Methods, normalized paths, status codes, content types and resource types.
- Authentication-related indicators and observed response differences.
- Query and payload parameter names, with sensitive values redacted.
- Redirect chains, errors, caching indicators and observed CORS metadata.

E. Authorization:
- Passive observations can identify candidates but cannot prove access-control weaknesses.
- Any active authorization checks must be a separate opt-in mode.
- Only use explicitly configured test accounts and known test resources.
- Never enumerate or access unrelated customers' records.
- Record evidence and clearly distinguish confirmed results from untested candidates.

### 10. Data models

Define versioned Pydantic schemas for:

`ScanMetadata`
- scan_id, started_at, completed_at, initial_url, allowed_origins, browser_version, protocol_version, collector_versions, configuration, completion_status.

`NetworkEvent`
- event_id, scan_id, timestamp, source, target_id, session_id, request_id, redirect_hop, event_type, raw_event, correlation_status.

`RequestRecord`
- request_id, method, URL, normalized_url, resource_type, initiator, request_headers, request_body_reference, response_status, response_headers, response_body_reference, timing, redirect_chain, failure_reason, capture_status.

`PageRecord`
- page_id, URL, title, discovered_from, navigation_status, interaction_summary.

`Finding`
- finding_id, rule_id, title, severity, confidence, status, description, evidence_references, impact, limitations, remediation, verification_steps.

Preserve timestamps and source metadata. Avoid placing unredacted query parameters, cookies, or payloads in normalized endpoint identifiers.

### 11. Output structure

Create one directory per scan:

`output/scans/<scan_id>/`

Include:

- `scan_metadata.json`
- `pages.jsonl`
- `endpoints.jsonl`
- `network_events.jsonl`
- `requests.jsonl`
- `findings.json`
- `coverage.json`
- `report.md`
- `manifest.json`

Optional body artifacts should be stored separately from metadata and excluded from the default bundle when sensitive.

The manifest should include file sizes, record counts, schema versions, checksums, redaction settings, and collection errors.

### 12. Testing and acceptance criteria

Build tests using a local test application that the project itself controls. Do not use an unrelated production application as a test target.

The test application must include:
- HTML document and JavaScript.
- Fetch and XHR endpoints.
- JSON and non-JSON responses.
- A real browser-generated CORS preflight scenario.
- Redirect chains.
- HTTP 4xx and 5xx responses.
- Failed requests.
- Repeated headers.
- A slow response and a large response.
- A WebSocket endpoint.
- A popup or second page.
- A service worker test scenario.
- A response with sensitive test values that must be redacted.
- Known security-header configurations for rule verification.

Acceptance criteria:

1. The collector attaches before initial navigation.
2. Tests demonstrate detection of each supported resource type and lifecycle event.
3. Preflight requests are preserved as independent records when emitted.
4. Redirect hops and request IDs are correlated correctly.
5. Extra-info events are preserved even when they arrive out of order.
6. A failed or incomplete request does not crash the scan.
7. A body retrieval failure is recorded rather than silently discarded.
8. The crawler never leaves the configured origin scope without explicit approval.
9. The scanner does not automatically submit destructive actions.
10. Secrets in test fixtures are redacted from the default output.
11. Interrupted scans can be identified and their persisted data exported.
12. The final report distinguishes observed facts, heuristic findings, untested hypotheses, and coverage gaps.
13. The test suite runs offline against local fixtures.
14. All core modules have automated tests and structured logging.

### 13. Implementation milestones

Milestone 1: Minimal CDP proof of concept.
- Launch Chromium.
- Create a page and CDP session.
- Enable Network before navigation.
- Capture and export raw CDP events.
- Verify document, script, fetch, XHR, OPTIONS, response and failure events against a local fixture.
- Do not proceed until tests pass.

Milestone 2: Request correlation.
- Implement event state machines, redirect handling, extra-info correlation and lifecycle finalization.
- Add tests for out-of-order events, missing responses and repeated request IDs.

Milestone 3: Persistent storage and exports.
- Add SQLite, JSONL, schema validation and crash-safe flushing.

Milestone 4: Authenticated browser and page discovery.
- Add persistent dedicated browser profile, manual authentication, safe navigation, popup handling and crawler budgets.

Milestone 5: Security analysis.
- Implement deterministic passive rules, evidence references and false-positive limitations.

Milestone 6: Body capture and advanced targets.
- Add opt-in body retrieval, service-worker diagnostics and additional target coverage where supported.

Milestone 7: Hardening and documentation.
- Run the full local test suite.
- Add installation, configuration, troubleshooting, data handling, security and limitations documentation.
- Produce a reproducible setup with pinned dependencies.

### 14. Required deliverables

Deliver working source code, a dependency lock file, test fixtures, automated tests, an example configuration, CLI documentation, a security model, a troubleshooting guide, a sample sanitized audit bundle and an architecture document.

Do not merely output code snippets or pseudocode. Implement modules in the repository, run tests, inspect failures and fix them. Never report a test as passing unless it was actually run.

If an implementation detail is uncertain, investigate the installed Playwright and CDP APIs, document the limitation, and create a reproducible test rather than guessing.

### 15. Mandatory scope of the first release

The first release is a passive, local-first scanner for explicitly authorized web applications. It collects evidence and identifies security concerns. It does not exploit vulnerabilities, bypass authentication, modify production data, or automatically run intrusive security tests.

The primary objective is reliable observation, complete event accounting within declared coverage, safe storage, useful evidence, and reproducible findings.