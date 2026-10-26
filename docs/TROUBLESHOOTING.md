# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `BrowserType.launch: Executable doesn't exist ...chromium...-1181` | Playwright 1.54 needs its own Chromium build: `python -m playwright install chromium` |
| `configuration error: HTTPS is required` | Use an `https://` URL; for local development add `--allow-http-local` (localhost/127.0.0.1/::1 only) |
| `authorization not confirmed` | Pass `--confirm-authorized` (non-interactive runs cannot answer the prompt) |
| `refusing to use what looks like an ordinary browser profile` / `not created by webaudit` | `--profile-dir` must be a new or webaudit-created directory (contains `.webaudit_profile`) |
| Browser window opens but nothing is scanned | The scan starts only after you press Enter in the terminal following login |
| App shows errors / data missing during the scan; report lists `state_changing_method` blocks | The guard blocks POST/PUT/PATCH/DELETE after login. If the blocked calls are read-only queries (GraphQL, RPC), re-run with `--allow-post-path /graphql` (review them first) |
| `crawl.errors` in coverage / manifest | A phase failed on some page and was skipped; the scan continued. Check `phase`/`url`; `page_timeouts` counts watchdog stops |
| One click per page, `click_failed` high, `overlay_stuck` high | A modal covers the page or the app re-renders after each click; update to the current version (overlays are closed, controls re-queried) and check `interactions` in `coverage.json` |
| Bodies `unavailable` | Chromium evicted them; raise `network_buffer_mb` |
| Many `skipped_scope` pages | Links to other origins are recorded, not visited. Add trusted origins with `--extra-origin` |
| `budgets_hit` in coverage | Raise `--max-pages/--max-depth/--max-seconds` or accept partial coverage |
| Findings mention `no requestWillBeSent observed` | Requests already in flight when collectors armed (login-phase page load) or events dropped; check `queue.dropped` in `diagnostics` |
| `events dropped due to a full queue` in the manifest | Raise `queue_size`; slow disks/AV scanning of the output directory are the usual cause |
| `events arrived after collection was finalized` | Shutdown race with still-pending third-party requests; harmless but listed for honesty |
| Scan killed / laptop slept | Run `webaudit list` (status `interrupted`) then `webaudit export <id>`; data persisted before the interruption is exported |
| `ERR_BLOCKED_BY_CLIENT` in failed requests | The scope guard blocked the request (see `scope_guard_blocks` in `coverage.json`) |
| No `Set-Cookie` in `response.headers` of raw events | Expected: Chromium exposes it only in `responseReceivedExtraInfo`; `requests.jsonl` merges both with provenance |
| Tests hang or fail to start on Windows | Make sure no stale `chrome.exe` automation processes hold the profile; run `python -m pytest -x -q` |
| `RequestsDependencyWarning` | Unrelated warning from an environment-level `requests` package; harmless |

Inspect collector health: `python -m webaudit diagnostics <scan_id>` (per-session CDP event counts, queue depth/drops, body-capture status counts).
