# Security model and data handling

## Intended use and non-goals
For applications you own or are explicitly authorized to assess. The first release is **passive**: it does not exploit,
fuzz, inject payloads, bypass authentication, test other tenants' data or submit forms. Active authorization testing is
deliberately not implemented; it would have to be a separate opt-in mode with configured test accounts and known test resources.

## Controls
| Risk | Control | Verified by |
|---|---|---|
| Scanning without permission | Authorization confirmation required (flag or typed phrase); refuses non-interactive start without flag | `test_phase4`, `test_phase6` |
| Scope escape | Exact origin match (scheme+host+port), userinfo/scheme rejection, redirect revalidation (CDP `Fetch`), metadata/private-IP protection | `test_scope_exact_origin_not_prefix`, `test_guard_blocks_redirect_escape` |
| Destructive actions | Control classifier (unsafe/uncertain/form controls never clicked), default exclusion patterns, state-changing methods blocked after login, manual approval option | `test_full_scan_scope_safety_and_coverage` (no POST reaches the server) |
| Credential handling | Config rejects password/cookie/token keys; login is manual; login traffic is not collected; dedicated profile; ordinary browser profiles refused | `test_config_rejects_credentials...`, `test_profile_refuses...` |
| Sensitive data in evidence | Headers, cookies, query values, post data, WebSocket payloads redacted *before persistence*; bodies stored redacted; secrets never appear in findings (type, location, redacted sample only) | `test_secrets_redacted_in_persisted_events`, `test_export_bundle_files_checksums_and_no_secrets`, `test_end_to_end_audit_of_fixture` |
| Silent data loss | Bounded queue with counted drops; late-event accounting; incomplete/orphan requests kept; every body outcome has a status | `test_queue_overflow_is_counted_not_silent`, correlation tests |
| Over-claiming | Findings carry status (observed/heuristic/untested), confidence, limitations; report separates the four categories | `test_phase5_rules` |

## What the evidence contains
* Redacted request/response metadata of all browser traffic after login, including third-party destinations.
* Header **names** and non-sensitive values (policy headers such as CORS/CSP are intentionally readable); sensitive header values are replaced by `[REDACTED:<n>chars]`.
* Optional (opt-in) redacted text bodies. Binary, media, font and large bodies are never stored.
* The `scan.sqlite` store contains the same redacted events. `bodies_raw/` exists **only** with `store_raw = true` and holds unredacted data.

## Redaction is not perfect
Redaction uses header-name rules, query-parameter-name rules, JSON key rules and regular expressions (JWTs, cloud keys, private key
blocks, e-mail, SSN-like values, …). Novel secret formats or secrets embedded in free text can be missed. Review a bundle before
sharing it — especially before giving it to a third-party AI service. Findings only carry short redacted samples (first two characters + length).

## Raw evidence retention (when `store_raw = true`)
* Files are written with mode 0600 where the OS supports it (on Windows, POSIX modes are largely ignored — rely on NTFS ACLs of the output directory).
* **Not encrypted** by this release. Use an encrypted volume or delete `bodies_raw/` promptly.
* Suggested retention: delete raw bodies when the assessment ends (≤ 30 days); keep redacted bundles only as long as needed.
* Never commit `output/`, `.profiles/` (authenticated session data) or `bodies_raw/`; `.gitignore` excludes them.

## Writes, accounts and the backend
* By default the tool performs no state-changing actions. With `--auto-write` it may create/edit data **only inside the logged-in account**, test-marked and capped, under a hard deny-list (`writeguard.py`): no sign-out, no account switching/creation, no credential/e-mail changes, no DELETE or delete-like names, no payments, invites/sharing/permissions, exports/downloads; uploads only of generated blank/sample files and only while `write_uploads` is on. The deny-list is enforced at the network layer (guard) and the UI layer (control/form classifier). Test data it creates must be cleaned up by you (listed in the report).
* Residual risk: uploads and form submissions can trigger costly or visible backend work (e.g. AI parsing, notifications, public profile images) and may replace existing items such as an avatar; use a test account when in doubt. An app may perform a harmful action through an endpoint whose name the deny-list does not recognise; use `write_deny_patterns`, a staging copy or a throw-away account when in doubt.
* Authorization is verified by YOU with accounts and records you own; `compare` only reads two existing bundles.
* Browser data cannot show what the backend executed (SQL, RLS decisions). Use server/database audit logs or tracing for that.

## Residual risks and gaps
* Page-level CDP does not cover workers; early popup requests can be missed; in-flight requests at arming are incomplete.
* The scope guard (routing) changes caching behaviour; `observe` mode cannot prevent escapes, only detect them after the fact.
* The login phase is unguarded for methods by design; the landing/dashboard page's own scripts may issue requests there.
* Apps that read via POST need `--allow-post-path`; allowing a path trusts that it is read-only.
