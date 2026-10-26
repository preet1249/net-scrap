# webaudit — Authenticated Web Security Auditor

A passive, local-first Python tool for web applications **you own or are authorized to assess**. It opens a dedicated Chromium
profile, lets you log in manually (MFA included), explores accessible pages within an approved origin scope, records browser
network traffic through the Chrome DevTools Protocol (CDP), evaluates passive security indicators and exports a portable,
redacted evidence bundle (JSONL/JSON/Markdown) for manual review or analysis with an AI model.

It does **not** exploit anything, bypass authentication, submit forms, or claim to have found every endpoint. See
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) and [Limitations](#limitations).

## Setup

Requirements: Python ≥ 3.11 (developed on 3.13, Windows 11), Chromium via Playwright.

```powershell
python -m pip install -r requirements.lock     # pinned versions that the test suite was run with
python -m pip install -e . --no-deps           # installs the `webaudit` package
python -m playwright install chromium          # one-time browser download (Playwright 1.54 -> Chromium 139)
```

`requirements.lock` is a `pip freeze`-style pin file (the `uv` tool was not available when this was built, so there is no `uv.lock`).
Direct dependencies are also pinned in `pyproject.toml`.

## Quick start

```powershell
python -m webaudit scan https://app.example.com/dashboard --confirm-authorized
```

1. A dedicated Chromium window opens (profile in `.profiles/default`, never your everyday profile).
2. Log in manually. Login traffic is **not** collected. Press Enter in the terminal when the dashboard is visible.
3. Collectors are armed (CDP `Network.enable` happens before the scan navigates), then the crawler explores in scope.
4. Results land in `output/<N><host>/` — scan number then host, e.g. `output/1app.example.com`, `output/2app.example.com` (see below). Open `report.md` first.

### Automatic read + write inside your logged-in account (`--auto-write`)
```powershell
python -m webaudit scan https://app.example.com/dashboard --confirm-authorized --auto-write --body-mode selected --max-writes 20
```
After you log in, the scraper itself clicks safe controls AND creates/edits data in that account (forms with clear "Save/Create/Add/Update/New ..." buttons,
"New x" buttons), filling text fields with test-marked values (`webaudit-test-<id>-N`, e-mails `...@example.invalid`). Every write is listed in
`coverage.json` → `crawl.write_actions` and in the report so you can find and delete the test data. Request payloads are captured (values redacted).

If a flow needs a file or text, the scraper supplies its own generated, harmless material (no files from your machine): blank PNG/JPG/GIF images and small
PDF/DOCX/TXT/MD/CSV/JSON/TeX documents (chosen to match each upload field's `accept` type, via the file chooser or hidden file inputs) and pre-written text
(sample paragraph, sample resume, LaTeX snippet — or your own via `write_sample_text`), all containing the test marker. Disable uploads with `--no-test-uploads`.
After writing, it **reloads the seed page and the pages it wrote on** and checks whether the marker comes back in the captured responses; `coverage.json` →
`crawl.write_readback` and the report say which written items were confirmed (needs `--body-mode selected`). Extra safe button labels can be added with
`--write-label "Paste Text"` (the hard deny-list still wins).

Hard limits, enforced twice (network guard + UI classifier) — the scraper will **never**: sign out; log in as / create another account (password grants, sign-up,
recover, OTP); change e-mail/password/MFA; delete anything (any DELETE, or names containing delete/remove/destroy/...); pay, bill, subscribe, upgrade; invite, share or
change permissions; export/download; upload anything except its own generated blank/sample test files (and only with uploads enabled); submit forms containing password/card/OTP fields. If the app bounces to a login page the crawl stops
(`session_lost`) and no credentials are ever entered. Add your own regexes with `write_deny_patterns` in the config. Writes are capped by `--max-writes` / `max_writes_per_page`.

### Optional: recording workflows yourself (`--manual-session`)
If you prefer to perform some workflows by hand (uploads, deletions, anything on the deny-list), use a manual session — you click, the tool only observes:

```powershell
python -m webaudit scan https://app.example.com/dashboard --confirm-authorized --manual-session --session-label userA-owner --body-mode selected
```

Compare two sessions of two test accounts **you control** (run once per account, then):

```powershell
python -m webaudit compare 1 2     # passive: reads the two bundles, sends nothing; writes output/comparison_*.md
```


Useful options: `--body-mode selected` (opt-in response bodies, redacted), `--max-pages 30 --max-depth 2`,
`--extra-origin https://api.example.com`, `--manual-approval`, `--allow-post-path /graphql` (read-only query endpoints only),
`--skip-login` (unattended run of whatever the profile can reach), `--config config.example.toml`.

Other commands: `webaudit list`, `webaudit export <number|folder>` (also for interrupted scans), `webaudit diagnostics <number|folder>`, `webaudit compare <a> <b>`. A scan can be referenced by its number (`3`), its folder name (`3example.com`) or a path.
Details: [docs/CLI.md](docs/CLI.md).

## Large and complex apps

Scans of big dashboards are slow but built not to die:
* `--preset quick|standard|thorough` (thorough: 300 pages, depth 6, up to 2 h, 25 interactions/page, 40 writes). Explicit flags override the preset.
* Every page visit is isolated: an exception in discovery/interaction/write is recorded (`coverage.json` → `crawl.errors`, and the manifest) and the crawl continues.
  A per-page watchdog (`max_page_seconds`, default 240) moves on from a stuck page; a closed/crashed tab is replaced automatically.
* The control list is re-read after every click (SPAs re-render), blocking overlays/modals are closed, and widgets that repeat on every page are not re-clicked.
* Each page is scrolled to the bottom a few times to trigger lazy-loaded lists (`scroll_steps`).
* Request cap defaults to 100 000 (pages and time are the real budgets); Chromium's body buffer is 100 MB (`network_buffer_mb`) so large pages don't evict bodies.
* `--include-subdomains` approves every https subdomain of the target's domain (e.g. `*.example.com`); otherwise only exact origins are visited.
* Scans are persisted incrementally; if one is interrupted, `webaudit export <n>` still produces the bundle (a scan cannot yet be *resumed*).

## What data you get (and where)

| # | Data | File / field | Notes |
|---|---|---|---|
| 1 | Page inventory (URLs, titles, discovery source, depth, nav status) | `pages.jsonl` | skipped pages are listed with the reason |
| 2 | API endpoint inventory (methods, normalized paths, query/payload field names) | `endpoints.jsonl` | observed traffic only; backend origins on other hosts included |
| 3 | Request headers (Authorization, Content-Type, Origin, Cookie, ...) | `requests.jsonl` → `request_headers` | each entry has `source` (primary / extra_info / playwright); sensitive values `[REDACTED:n chars]` |
| 4 | Response headers (Set-Cookie, CSP, CORS, cache, ...) | `requests.jsonl` → `response_headers` | repeated headers kept as separate entries |
| 5 | Request payloads | `bodies/req-*.txt` via `request_body_reference`; field names in `post_data_keys`; `query_param_names` | needs `--body-mode selected\|all_supported`; values redacted, binary uploads skipped |
| 6 | Response bodies (JSON, HTML, JS, config) | `bodies/body-*.txt` via `response_body_reference` | opt-in, byte-bounded, redacted; static assets once per URL, API responses up to 5 per endpoint |
| 7 | HTTP status codes | `requests.jsonl` → `response_status` | HTTP errors are completed requests; failures have `failure_reason` |
| 8 | Lifecycle (timestamps, durations, redirects, failures, correlation ids) + **initiator chains** | `requests.jsonl` → `timing`, `redirect_chain`, `redirect_hop`, `request_id`, `event_ids`, `capture_status`, `initiator_summary`, `initiator_frames`; `endpoints.jsonl` → `initiators` | one record per request and per redirect hop, even when bodies are identical; failures are classified in `coverage.json` → `failures_by_class` |
| 9 | Resource types incl. preflight | `requests.jsonl` → `resource_type`, `is_preflight` | |
| 10 | JS exposure (secret candidates, source maps, debug info, third parties) | `findings.json` (`EXP-*`) | secret values are never printed; location + redacted sample only |
| 11 | Security-header findings | `findings.json` (`HDR-*`) | |
| 12 | CORS findings | `findings.json` (`CORS-*`) | |
| 13 | Cookie indicators | `findings.json` (`COOKIE-*`) | only when `Set-Cookie` is observed (token-in-localStorage apps have none) |
| 14 | Access-control test candidates | `findings.json` (`AUTHZ-CANDIDATE`, status `untested_hypothesis`) | includes credentialed calls to a separate backend origin, e.g. `user_id=eq.<id>` filters |
| 15 | Coverage and errors | `coverage.json`, `manifest.json` | pages, skips, budgets, guard blocks, unsupported/partial targets, unavailable bodies, drops |

## Output bundle (`output/<N><host>/`)

| File | Content |
|---|---|
| `report.md` | Observed facts / heuristic findings / untested hypotheses / coverage gaps |
| `findings.json` | Structured findings with evidence references, limitations, remediation, verification steps |
| `requests.jsonl` | One correlated record per request **hop** (redirects, preflights, failures, header entries with provenance) |
| `network_events.jsonl` | Every persisted raw event (redacted) with derived hop and correlation status |
| `endpoints.jsonl`, `pages.jsonl` | Observed endpoint inventory (normalized paths) and crawled/skipped pages |
| `coverage.json`, `scan_metadata.json`, `manifest.json` | Coverage/diagnostics, scan metadata, checksums + counts + errors |
| `bodies/` | Redacted response bodies (only when `--body-mode` is not `none`) |
| `scan.sqlite`, `scan.log` | Source of truth for replay/export; structured log |

A sanitized example generated from the project's own fixture app is in [examples/sample_bundle/](examples/sample_bundle/).

## Tests

```powershell
python -m pytest            # 135 tests; offline, against local fixture servers; needs Chromium installed
python scripts/make_sample_bundle.py   # regenerate the sample bundle
```

## Limitations

* Observation is **page/frame-level CDP + Playwright events**. Service/shared/dedicated worker traffic, other targets and a popup's
  very first requests are not fully covered (recorded in `coverage.json`).
* The endpoint inventory contains only what the browser did during the scan.
* With `scope_enforcement = "guard"` Playwright routing disables the HTTP cache and state-changing requests (POST/PUT/PATCH/DELETE)
  are blocked after login — apps that read data via POST (GraphQL, RPC) need `--allow-post-path` for full coverage.
* Redaction is best-effort and is not guaranteed to remove every sensitive value. Raw body storage (`store_raw`) is **not encrypted**.
* Passive findings are indicators; access-control flaws cannot be proven without separate authorized testing (not implemented).

More: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) · [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
