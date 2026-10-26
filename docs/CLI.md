# CLI reference

`python -m webaudit <command>` (or `webaudit <command>` after `pip install -e .`). Output never includes header values, cookies,
tokens or bodies; progress is structured JSON logging on stderr (`scan.log` in the scan directory as well).

## `scan [URL]`

Starts a scan. The URL (or `initial_url` in `--config`) must be `https://` (HTTP only for localhost with `--allow-http-local`).
Authorization must be confirmed with `--confirm-authorized`, or by typing `I AM AUTHORIZED` at the interactive prompt; in
non-interactive use the scan refuses to start without the flag.

| Option | Meaning |
|---|---|
| `--config FILE` | TOML/JSON configuration ([config.example.toml](../config.example.toml)); command-line options override it |
| `--extra-origin ORIGIN` | Additional **exact** approved origin (repeatable). Nothing is inferred from links/redirects/CORS |
| `--output-dir`, `--profile-dir` | Where bundles go / the dedicated browser profile (ordinary browser profiles are refused) |
| `--headless` | No visible window (manual login impossible; combine with `--skip-login` or an already-authenticated profile) |
| `--skip-login` | Do not pause for manual login |
| `--body-mode none\|selected\|all_supported` | Opt-in, size-bounded, redacted response bodies |
| `--store-raw-bodies` | Also store raw bodies in `bodies_raw/` (unencrypted, sensitive) |
| `--max-pages N`, `--max-depth N`, `--max-seconds N` | Crawl budgets (budgets hit are reported as coverage gaps) |
| `--scope-enforcement guard\|observe` | `guard` blocks off-scope navigations/redirects and internal targets; `observe` never intercepts |
| `--allow-post-path PREFIX` | Permit state-changing methods to a path prefix, for read-only query endpoints you reviewed |
| `--manual-approval` | Ask before clicking controls that cannot be classified as read-only |
| `--preset quick\|standard\|thorough` | Crawl size preset (explicit `--max-*` flags override it) |
| `--include-subdomains` | Approve every https subdomain of the target's registrable domain (explicit scope widening) |
| `--auto-write` | Scraper creates/edits data automatically inside the logged-in account (test-marked, capped, deny-listed; never signs out/switches accounts/deletes/pays/invites/uploads) |
| `--no-test-uploads` | With `--auto-write`: do not upload the generated blank images / sample documents |
| `--write-label LABEL` | Extra control label you consider safe in auto-write mode (repeatable); the hard deny-list still wins |
| `--max-writes N` | Cap on automatic write actions (default 20) |
| `--manual-session` | You drive the app (writes, uploads, logout, ...); the tool only observes — nothing is clicked or submitted by the tool |
| `--session-label LABEL` | Label of the account/role (e.g. `userA-owner`); never put credentials here |

Scans are written to `output/<N><host>/` (N = 1, 2, 3, ...; e.g. `output/2example.com`). Any command that takes a scan accepts the number, the folder name or a path.

Exit codes: 0 ok · 2 configuration error · 130 interrupted (persisted data kept; run `export`).

## `list [--output-dir DIR]`
Lists scans with status `completed`, `failed`, `running` (fresh heartbeat) or `interrupted` (no clean shutdown).

## `export SCAN [--output-dir DIR]`
Replays the persisted events from `scan.sqlite`, re-correlates, re-runs the rules and rewrites the whole bundle including
`manifest.json`. Works for interrupted scans (the manifest says `interrupted`; data is partial).

## `compare SCAN_A SCAN_B`
Passive comparison of two existing scans (two accounts you control): endpoints only seen by one session, status differences per endpoint, and object-specific URLs both sessions read successfully (with whether the redacted bodies are identical). Writes `output/comparison_<A>_vs_<B>.md`. It sends no requests and cannot prove an authorization flaw.

## `diagnostics SCAN [--output-dir DIR]`
Prints status, persisted event count, collector/queue/body-capture diagnostics (drops, late events, sessions, event counts) and crawl coverage as JSON.
