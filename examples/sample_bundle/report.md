# Security Audit Report — `1127.0.0.1`

> Passive, browser-observed evidence only. This report does not prove the absence of vulnerabilities and does not claim to have discovered every endpoint. Secret values and personal data are never printed; samples are redacted.

## Scan summary

- **Initial URL:** http://127.0.0.1:55489/sec
- **Approved origins:** http://127.0.0.1:55489, http://localhost:55490
- **Started:** 2026-10-26T19:42:10.721879+00:00  |  **Completed:** 2026-10-26T19:42:20.658103+00:00
- **Mode:** crawl
- **Completion status:** `completed`
- **Browser:** HeadlessChrome/139.0.7258.5  |  **CDP protocol:** 1.3
- **Requests recorded (per redirect hop):** 14  |  **Endpoints observed:** 13  |  **Pages recorded:** 4

### Findings overview

| Severity | Observed | Heuristic | Untested hypothesis |
|---|---|---|---|
| high | 0 | 4 | 0 |
| medium | 3 | 8 | 0 |
| low | 4 | 1 | 0 |
| info | 3 | 0 | 1 |

## 1. Observed facts

Directly observed in captured traffic. Each can be re-checked against the referenced evidence records.

- HTTP status distribution: 200×12, 204×1
- Failed requests: 1 (reasons: net::ERR_FAILED)
- Preflight (OPTIONS) requests: 1
- Redirect responses: 0

**Endpoint inventory (observed only; first 40):**

| Method | Origin | Path | Count | Statuses | Types | Auth indicators |
|---|---|---|---|---|---|---|
| GET | http://127.0.0.1:55489 | `/api/sensitive` | 1 | 200 | Fetch | - |
| GET | http://127.0.0.1:55489 | `/api/users/{id}` | 1 | 200 | Fetch | cookie_sent |
| GET | http://127.0.0.1:55489 | `/h/bad` | 1 | 200 | Document | - |
| GET | http://127.0.0.1:55489 | `/h/good` | 1 | 200 | Document | - |
| GET | http://127.0.0.1:55489 | `/leaky.js` | 1 | 200 | Script | - |
| GET | http://127.0.0.1:55489 | `/sec` | 1 | 200 | Document | - |
| GET | http://127.0.0.1:55489 | `/static/app.js.map` | 1 | 200 | Fetch | - |
| GET | http://127.0.0.1:55489 | `/users/{id}` | 1 | 200 | Document | cookie_sent |
| GET | http://localhost:55490 | `/api/cors` | 1 | 200 | Fetch | - |
| OPTIONS | http://localhost:55490 | `/api/cors` | 1 | 204 | Other | - |
| GET | http://localhost:55490 | `/api/cors-nopolicy` | 1 | 200 | Fetch | - |
| GET | http://localhost:55490 | `/api/cors-reflect` | 1 | 200 | Fetch | - |
| GET | http://localhost:55490 | `/api/cors-simple` | 1 | 200 | Fetch | - |

#### F-HDR-CSP-MISSING-1132bc61 — Content-Security-Policy not enforced

- **Severity:** medium  |  **Confidence:** high  |  **Status:** observed  |  **Rule:** `HDR-CSP-MISSING`
- **What was seen:** 2 of 4 HTML document response(s) from http://127.0.0.1:55489 lacked an enforced Content-Security-Policy header.
- **Potential impact:** Reduces defence-in-depth against XSS and data injection; absence alone is not a vulnerability.
- **Limitations / uncertainty:** Evaluated on in-scope HTML document responses actually observed; other pages/routes may differ. A header set by a CDN/proxy only for some paths, or removed before the browser saw it, is outside what this check can establish. CSP delivered via <meta http-equiv> is not examined.
- **Remediation:** Deploy a restrictive CSP (nonce/hash-based script-src, object-src 'none', base-uri 'self', frame-ancestors).
- **How to verify:**
  1. Confirm in DevTools > Network that no CSP header exists on the document response.
- **Evidence:** `request:cdp-1/4F10C79CE930CEA9D15173EC34FAC2FE#0`, `request:cdp-1/D954EB009F4834A1957AB74830F5584B#0`

#### F-HDR-CSP-PERMISSIVE-b8d8e9ec — Content-Security-Policy has permissive script directives

- **Severity:** medium  |  **Confidence:** high  |  **Status:** observed  |  **Rule:** `HDR-CSP-PERMISSIVE`
- **What was seen:** 'unsafe-eval' allows eval-like APIs; 'unsafe-inline' allows inline scripts; broad script source 'data:'.
- **Potential impact:** A permissive script policy weakens CSP's ability to contain XSS.
- **Limitations / uncertainty:** Policy semantics were evaluated statically; nonce-based policies and browser-specific fallbacks may behave differently.
- **Remediation:** Remove 'unsafe-inline'/'unsafe-eval' and wildcard/scheme sources; use nonces or hashes.
- **How to verify:**
  1. Review the full policy text in the evidence record and test with a CSP evaluator.
- **Evidence:** `request:cdp-1/C4B8856239C89406115317ABA7CC23A4#0`

#### F-HDR-FRAME-365a2dc8 — No frame-protection policy observed (frame-ancestors / X-Frame-Options)

- **Severity:** medium  |  **Confidence:** medium  |  **Status:** observed  |  **Rule:** `HDR-FRAME`
- **What was seen:** 3 of 4 document response(s) had neither CSP frame-ancestors nor X-Frame-Options.
- **Potential impact:** Pages may be embeddable by other origins, enabling clickjacking where sensitive actions exist.
- **Limitations / uncertainty:** Evaluated on in-scope HTML document responses actually observed; other pages/routes may differ. A header set by a CDN/proxy only for some paths, or removed before the browser saw it, is outside what this check can establish. Impact depends on whether the page contains state-changing UI and relies on cookies for auth.
- **Remediation:** Add 'Content-Security-Policy: frame-ancestors 'none'' (or 'self') and/or 'X-Frame-Options: DENY'.
- **How to verify:**
  1. Attempt to embed an authenticated page in an iframe from a test origin you control.
- **Evidence:** `request:cdp-1/4F10C79CE930CEA9D15173EC34FAC2FE#0`, `request:cdp-1/C4B8856239C89406115317ABA7CC23A4#0`, `request:cdp-1/D954EB009F4834A1957AB74830F5584B#0`

#### F-COOKIE-SAMESITE-6062e0f4 — Cookie without explicit SameSite attribute

- **Severity:** low  |  **Confidence:** high  |  **Status:** observed  |  **Rule:** `COOKIE-SAMESITE`
- **What was seen:** Cookie name(s) sid set by http://127.0.0.1:55489 (values redacted).
- **Potential impact:** Browsers default to Lax for such cookies; behaviour differs across browsers/versions.
- **Limitations / uncertainty:** Based on Set-Cookie headers visible to the browser instrumentation; cookie purpose is inferred from its name.
- **Remediation:** Set Secure, HttpOnly (for session cookies) and an explicit SameSite attribute.
- **How to verify:**
  1. Inspect the cookie in DevTools > Application > Cookies and confirm which cookie carries the session.
- **Evidence:** `request:cdp-1/C4B8856239C89406115317ABA7CC23A4#0`

#### F-EXP-SOURCEMAP-611dc9cf — Source map files are publicly retrievable

- **Severity:** low  |  **Confidence:** high  |  **Status:** observed  |  **Rule:** `EXP-SOURCEMAP`
- **What was seen:** 1 source map file(s) returned HTTP 2xx to the authenticated browser session.
- **Potential impact:** Source maps expose original source structure, comments and internal names, easing analysis of the application.
- **Limitations / uncertainty:** Observed with the scanned session only; the maps may be restricted for anonymous users. Contents were not analysed unless body capture was enabled.
- **Remediation:** Do not deploy source maps to production, or restrict them to authenticated developers.
- **How to verify:**
  1. Request the .map URL without a session and compare.
- **Evidence:** `request:cdp-1/10752.14#0`

#### F-HDR-REFERRER-805abfb6 — Referrer-Policy may leak full URLs

- **Severity:** low  |  **Confidence:** high  |  **Status:** observed  |  **Rule:** `HDR-REFERRER`
- **What was seen:** Referrer-Policy permits sending full URLs cross-origin.
- **Limitations / uncertainty:** Evaluated on in-scope HTML document responses actually observed; other pages/routes may differ. A header set by a CDN/proxy only for some paths, or removed before the browser saw it, is outside what this check can establish.
- **Remediation:** Use 'strict-origin-when-cross-origin' or 'no-referrer'.
- **Evidence:** `request:cdp-1/C4B8856239C89406115317ABA7CC23A4#0`

#### F-HDR-XCTO-76fa0e0c — X-Content-Type-Options: nosniff not observed

- **Severity:** low  |  **Confidence:** high  |  **Status:** observed  |  **Rule:** `HDR-XCTO`
- **What was seen:** 3 of 4 document response(s) lacked 'X-Content-Type-Options: nosniff'.
- **Potential impact:** MIME-sniffing can reinterpret content types in older/edge cases.
- **Limitations / uncertainty:** Evaluated on in-scope HTML document responses actually observed; other pages/routes may differ. A header set by a CDN/proxy only for some paths, or removed before the browser saw it, is outside what this check can establish.
- **Remediation:** Send 'X-Content-Type-Options: nosniff' on all responses.
- **Evidence:** `request:cdp-1/4F10C79CE930CEA9D15173EC34FAC2FE#0`, `request:cdp-1/C4B8856239C89406115317ABA7CC23A4#0`, `request:cdp-1/D954EB009F4834A1957AB74830F5584B#0`

#### F-CORS-BLOCKED-2dee8817 — Browser blocked cross-origin requests (CORS failures)

- **Severity:** info  |  **Confidence:** high  |  **Status:** observed  |  **Rule:** `CORS-BLOCKED`
- **What was seen:** 1 request(s) failed with a browser-generated CORS error (MissingAllowOriginHeader). This is the browser enforcing policy, not a server vulnerability.
- **Limitations / uncertainty:** A failure here may mean the application is broken for this origin rather than insecure.
- **Remediation:** If these calls are intended, add the required CORS headers; otherwise remove the calls.
- **Evidence:** `request:cdp-1/10752.18#0`

#### F-HDR-BANNER-196e234a — Server technology/version disclosure headers

- **Severity:** info  |  **Confidence:** high  |  **Status:** observed  |  **Rule:** `HDR-BANNER`
- **What was seen:** Headers disclose technology/version information: Python/3.13 aiohttp/3.13.2.
- **Limitations / uncertainty:** Disclosure is informational; it aids fingerprinting but is not itself exploitable.
- **Remediation:** Remove or generalize Server/X-Powered-By headers.
- **Evidence:** `request:cdp-1/4F10C79CE930CEA9D15173EC34FAC2FE#0`, `request:cdp-1/10752.11#0`, `request:cdp-1/10752.13#0`, `request:cdp-1/10752.14#0`, `request:cdp-1/10752.15#0`

#### F-HDR-NOTLS-698a8914 — Document served over HTTP

- **Severity:** info  |  **Confidence:** high  |  **Status:** observed  |  **Rule:** `HDR-NOTLS`
- **What was seen:** http://127.0.0.1:55489 served HTML documents without TLS; HSTS is not applicable.
- **Limitations / uncertainty:** Local development origins are expected to use HTTP.
- **Remediation:** Serve the application over HTTPS only and redirect HTTP to HTTPS.
- **Evidence:** `request:cdp-1/4F10C79CE930CEA9D15173EC34FAC2FE#0`, `request:cdp-1/C04BA6C84E478FC7B7CEF8073D71B97A#0`, `request:cdp-1/C4B8856239C89406115317ABA7CC23A4#0`, `request:cdp-1/D954EB009F4834A1957AB74830F5584B#0`

## 2. Heuristic findings

Pattern- or inference-based indicators. They are **candidates requiring manual verification**, not confirmed vulnerabilities.

#### F-EXP-SECRET-026d0f80 — Secret-looking value in client-visible response (aws_access_key_id)

- **Severity:** high  |  **Confidence:** medium  |  **Status:** heuristic  |  **Rule:** `EXP-SECRET`
- **What was seen:** A aws_access_key_id pattern matched in a application/javascript response body (Script).
- **Location:** http://127.0.0.1:55489/leaky.js line 1 offset 69
- **Redacted sample:** `…[short]`
- **Potential impact:** If valid and sensitive, anyone who can load this resource obtains the credential.
- **Limitations / uncertainty:** Pattern-based detection of a candidate secret in a captured body; it can be a public identifier, a test/placeholder value or a false positive, and validity was NOT checked. The value is deliberately not shown.
- **Remediation:** Rotate the credential if valid, remove it from client-delivered assets, and use server-side secrets or short-lived tokens.
- **How to verify:**
  1. Locate the value in the original asset using the location below.
  2. Determine whether it is a public identifier or a real secret, and rotate if secret.
- **Evidence:** `request:cdp-1/10752.11#0`, `body:body-000002`, `event:evt-41`

#### F-EXP-SECRET-4f1f6cbc — Secret-looking value in client-visible response (aws_access_key_id)

- **Severity:** high  |  **Confidence:** medium  |  **Status:** heuristic  |  **Rule:** `EXP-SECRET`
- **What was seen:** A aws_access_key_id pattern matched in a application/json response body (Fetch).
- **Location:** http://127.0.0.1:55489/api/sensitive line 1 offset 194
- **Redacted sample:** `…[short]`
- **Potential impact:** If valid and sensitive, anyone who can load this resource obtains the credential.
- **Limitations / uncertainty:** Pattern-based detection of a candidate secret in a captured body; it can be a public identifier, a test/placeholder value or a false positive, and validity was NOT checked. The value is deliberately not shown.
- **Remediation:** Rotate the credential if valid, remove it from client-delivered assets, and use server-side secrets or short-lived tokens.
- **How to verify:**
  1. Locate the value in the original asset using the location below.
  2. Determine whether it is a public identifier or a real secret, and rotate if secret.
- **Evidence:** `request:cdp-1/10752.13#0`, `body:body-000003`, `event:evt-79`

#### F-EXP-SECRET-76d33d77 — Secret-looking value in client-visible response (stripe_secret_key)

- **Severity:** high  |  **Confidence:** medium  |  **Status:** heuristic  |  **Rule:** `EXP-SECRET`
- **What was seen:** A stripe_secret_key pattern matched in a application/json response body (Fetch).
- **Location:** http://127.0.0.1:55489/api/sensitive line 1 offset 150
- **Redacted sample:** `sk…[33 chars]`
- **Potential impact:** If valid and sensitive, anyone who can load this resource obtains the credential.
- **Limitations / uncertainty:** Pattern-based detection of a candidate secret in a captured body; it can be a public identifier, a test/placeholder value or a false positive, and validity was NOT checked. The value is deliberately not shown.
- **Remediation:** Rotate the credential if valid, remove it from client-delivered assets, and use server-side secrets or short-lived tokens.
- **How to verify:**
  1. Locate the value in the original asset using the location below.
  2. Determine whether it is a public identifier or a real secret, and rotate if secret.
- **Evidence:** `request:cdp-1/10752.13#0`, `body:body-000003`, `event:evt-79`

#### F-EXP-SECRET-ecbb9171 — Secret-looking value in client-visible response (stripe_secret_key)

- **Severity:** high  |  **Confidence:** medium  |  **Status:** heuristic  |  **Rule:** `EXP-SECRET`
- **What was seen:** A stripe_secret_key pattern matched in a application/javascript response body (Script).
- **Location:** http://127.0.0.1:55489/leaky.js line 1 offset 24
- **Redacted sample:** `sk…[33 chars]`
- **Potential impact:** If valid and sensitive, anyone who can load this resource obtains the credential.
- **Limitations / uncertainty:** Pattern-based detection of a candidate secret in a captured body; it can be a public identifier, a test/placeholder value or a false positive, and validity was NOT checked. The value is deliberately not shown.
- **Remediation:** Rotate the credential if valid, remove it from client-delivered assets, and use server-side secrets or short-lived tokens.
- **How to verify:**
  1. Locate the value in the original asset using the location below.
  2. Determine whether it is a public identifier or a real secret, and rotate if secret.
- **Evidence:** `request:cdp-1/10752.11#0`, `body:body-000002`, `event:evt-41`

#### F-COOKIE-HTTPONLY-243b6310 — Session-like cookie without HttpOnly

- **Severity:** medium  |  **Confidence:** medium  |  **Status:** heuristic  |  **Rule:** `COOKIE-HTTPONLY`
- **What was seen:** Cookie name(s) sid set by http://127.0.0.1:55489 (values redacted).
- **Potential impact:** Script running on the page (e.g., via XSS) can read the cookie.
- **Limitations / uncertainty:** Based on Set-Cookie headers visible to the browser instrumentation; cookie purpose is inferred from its name (HttpOnly relevance is a heuristic).
- **Remediation:** Set Secure, HttpOnly (for session cookies) and an explicit SameSite attribute.
- **How to verify:**
  1. Inspect the cookie in DevTools > Application > Cookies and confirm which cookie carries the session.
- **Evidence:** `request:cdp-1/C4B8856239C89406115317ABA7CC23A4#0`

#### F-CORS-REFLECT-CREDS-e88f8674 — Cross-origin response echoes the request Origin with credentials allowed

- **Severity:** medium  |  **Confidence:** low  |  **Status:** heuristic  |  **Rule:** `CORS-REFLECT-CREDS`
- **What was seen:** Request Origin http://127.0.0.1:55489 was echoed in ACAO by http://localhost:55490 together with ACAC true (actual response, preflight (OPTIONS)). This is expected for an allowlisted trusted origin and risky if the server reflects ANY origin.
- **Potential impact:** If origin reflection is unconditional, any website could read authenticated responses from this endpoint.
- **Limitations / uncertainty:** One observation from the browser origin(s) used during the scan. It cannot show how the server treats other Origin values unless they were actually sent, and CORS only governs what browsers expose to scripts; it does not authenticate callers. Only the origin(s) actually sent were observed: http://127.0.0.1:55489. Reflection of arbitrary origins is UNTESTED.
- **Remediation:** Validate Origin against an exact allowlist; never reflect arbitrary values with credentials.
- **How to verify:**
  1. In an authorized test, request the endpoint with a controlled unrelated Origin header and check whether ACAO echoes it with ACAC true.
- **Evidence:** `request:cdp-1/22FFA0AF5DF5A21858E1230D7A75764F#0`, `request:cdp-1/10752.15#0`, `request:cdp-1/10752.17#0`

#### F-EXP-DEBUG-1a6c451e — Debug or diagnostic information in responses

- **Severity:** medium  |  **Confidence:** low  |  **Status:** heuristic  |  **Rule:** `EXP-DEBUG`
- **What was seen:** Response bodies contained indicators: debug_flag, python_traceback.
- **Potential impact:** Stack traces and internal paths aid attackers and can disclose implementation details.
- **Limitations / uncertainty:** Regex indicators (matched text not retained) can match benign content such as documentation or client bundles.
- **Remediation:** Disable verbose errors in production and return generic error bodies.
- **Evidence:** `request:cdp-1/10752.13#0`, `body:body-000003`

#### F-EXP-SECRET-0ca54ecc — Secret-looking value in client-visible response (generic_assigned_secret)

- **Severity:** medium  |  **Confidence:** low  |  **Status:** heuristic  |  **Rule:** `EXP-SECRET`
- **What was seen:** A generic_assigned_secret pattern matched in a application/javascript response body (Script).
- **Location:** http://127.0.0.1:55489/leaky.js line 1 offset 15
- **Redacted sample:** `sk…[33 chars]`
- **Potential impact:** If valid and sensitive, anyone who can load this resource obtains the credential.
- **Limitations / uncertainty:** Pattern-based detection of a candidate secret in a captured body; it can be a public identifier, a test/placeholder value or a false positive, and validity was NOT checked. The value is deliberately not shown.
- **Remediation:** Rotate the credential if valid, remove it from client-delivered assets, and use server-side secrets or short-lived tokens.
- **How to verify:**
  1. Locate the value in the original asset using the location below.
  2. Determine whether it is a public identifier or a real secret, and rotate if secret.
- **Evidence:** `request:cdp-1/10752.11#0`, `body:body-000002`, `event:evt-41`

#### F-EXP-SECRET-18f3400c — Secret-looking value in client-visible response (generic_assigned_secret)

- **Severity:** medium  |  **Confidence:** low  |  **Status:** heuristic  |  **Rule:** `EXP-SECRET`
- **What was seen:** A generic_assigned_secret pattern matched in a application/json response body (Fetch).
- **Location:** http://127.0.0.1:55489/api/sensitive line 1 offset 99
- **Redacted sample:** `hu…[24 chars]`
- **Potential impact:** If valid and sensitive, anyone who can load this resource obtains the credential.
- **Limitations / uncertainty:** Pattern-based detection of a candidate secret in a captured body; it can be a public identifier, a test/placeholder value or a false positive, and validity was NOT checked. The value is deliberately not shown.
- **Remediation:** Rotate the credential if valid, remove it from client-delivered assets, and use server-side secrets or short-lived tokens.
- **How to verify:**
  1. Locate the value in the original asset using the location below.
  2. Determine whether it is a public identifier or a real secret, and rotate if secret.
- **Evidence:** `request:cdp-1/10752.13#0`, `body:body-000003`, `event:evt-79`

#### F-EXP-SECRET-24957b56 — Secret-looking value in client-visible response (generic_assigned_secret)

- **Severity:** medium  |  **Confidence:** low  |  **Status:** heuristic  |  **Rule:** `EXP-SECRET`
- **What was seen:** A generic_assigned_secret pattern matched in a application/json response body (Fetch).
- **Location:** http://127.0.0.1:55489/api/sensitive line 1 offset 139
- **Redacted sample:** `sk…[33 chars]`
- **Potential impact:** If valid and sensitive, anyone who can load this resource obtains the credential.
- **Limitations / uncertainty:** Pattern-based detection of a candidate secret in a captured body; it can be a public identifier, a test/placeholder value or a false positive, and validity was NOT checked. The value is deliberately not shown.
- **Remediation:** Rotate the credential if valid, remove it from client-delivered assets, and use server-side secrets or short-lived tokens.
- **How to verify:**
  1. Locate the value in the original asset using the location below.
  2. Determine whether it is a public identifier or a real secret, and rotate if secret.
- **Evidence:** `request:cdp-1/10752.13#0`, `body:body-000003`, `event:evt-79`

#### F-EXP-SECRET-be3bc9d0 — Secret-looking value in client-visible response (jwt)

- **Severity:** medium  |  **Confidence:** low  |  **Status:** heuristic  |  **Rule:** `EXP-SECRET`
- **What was seen:** A jwt pattern matched in a application/json response body (Fetch).
- **Location:** http://127.0.0.1:55489/api/sensitive line 1 offset 227
- **Redacted sample:** `ey…[67 chars]`
- **Potential impact:** If valid and sensitive, anyone who can load this resource obtains the credential.
- **Limitations / uncertainty:** Pattern-based detection of a candidate secret in a captured body; it can be a public identifier, a test/placeholder value or a false positive, and validity was NOT checked. The value is deliberately not shown.
- **Remediation:** Rotate the credential if valid, remove it from client-delivered assets, and use server-side secrets or short-lived tokens.
- **How to verify:**
  1. Locate the value in the original asset using the location below.
  2. Determine whether it is a public identifier or a real secret, and rotate if secret.
- **Evidence:** `request:cdp-1/10752.13#0`, `body:body-000003`, `event:evt-79`

#### F-EXP-SECRET-f7615c95 — Secret-looking value in client-visible response (jwt)

- **Severity:** medium  |  **Confidence:** low  |  **Status:** heuristic  |  **Rule:** `EXP-SECRET`
- **What was seen:** A jwt pattern matched in a application/javascript response body (Script).
- **Location:** http://127.0.0.1:55489/leaky.js line 2 offset 121
- **Redacted sample:** `ey…[67 chars]`
- **Potential impact:** If valid and sensitive, anyone who can load this resource obtains the credential.
- **Limitations / uncertainty:** Pattern-based detection of a candidate secret in a captured body; it can be a public identifier, a test/placeholder value or a false positive, and validity was NOT checked. The value is deliberately not shown.
- **Remediation:** Rotate the credential if valid, remove it from client-delivered assets, and use server-side secrets or short-lived tokens.
- **How to verify:**
  1. Locate the value in the original asset using the location below.
  2. Determine whether it is a public identifier or a real secret, and rotate if secret.
- **Evidence:** `request:cdp-1/10752.11#0`, `body:body-000002`, `event:evt-41`

#### F-EXP-PII-fa031010 — API response contains sensitive-looking fields

- **Severity:** low  |  **Confidence:** low  |  **Status:** heuristic  |  **Rule:** `EXP-PII`
- **What was seen:** GET http://127.0.0.1:55489/api/sensitive returned JSON with field names suggesting personal or credential data: api_key, email, password, ssn, token.
- **Potential impact:** Over-exposure of fields (data minimisation issue) or credential fields returned to clients.
- **Limitations / uncertainty:** Based on key names only; values were redacted and never inspected. Returning a user's own data to that user may be intended. 
- **Remediation:** Return only fields the client needs; never return credential/secret fields.
- **How to verify:**
  1. Confirm each listed field is required by the UI and belongs to the authenticated user.
- **Evidence:** `request:cdp-1/10752.13#0`, `body:body-000003`

## 3. Untested hypotheses

Pointers for authorized, manual follow-up testing. **Nothing in this section was tested.**

#### F-AUTHZ-CANDIDATE-2998b0f7 — Object-identifier endpoint (authorization candidate): GET /api/users/{id}

- **Severity:** info  |  **Confidence:** low  |  **Status:** untested_hypothesis  |  **Rule:** `AUTHZ-CANDIDATE`
- **What was seen:** GET http://127.0.0.1:55489/api/users/{id} takes an object identifier in its path and returned HTTP 200 to the scanned session (1 request(s)). Whether other users' objects are protected was NOT tested.
- **Potential impact:** If server-side ownership checks are missing, users could access other users' objects (IDOR/BOLA).
- **Limitations / uncertainty:** Passive traffic cannot show an access-control weakness. This is a pointer for authorized manual testing with designated test accounts.
- **Remediation:** Enforce object-level authorization server-side on every request.
- **How to verify:**
  1. With two authorized test accounts you own, request account A's object using account B's session and expect 403/404.
  2. Use only known test resources; do not enumerate real customers' records.
- **Evidence:** `request:cdp-1/10752.22#0`

## 4. Coverage gaps and limitations

- Read-back after writes: not checked — no automatic text writes with a marker were performed
- Pages by navigation status: {'ok': 4}
- Incomplete/evicted request records: 1
- Response-body capture: {'captured': 11, 'skipped_no_body_status': 1}
- Targets: {'cdp_sessions': 1, 'frames_without_own_session': 0, 'service_workers_reported': 0, 'late_attached_pages': 0, 'redirect_guard_unavailable': 0} (workers are not instrumented; frames without their own session share the parent's coverage)
- Failed requests — cors_blocked ×1: browser enforced CORS policy; not a server failure (e.g. `http://localhost:55490/api/cors-nopolicy`)
- Channels: WebSockets (CDP/Playwright) 0/0, popups 0, service workers reported 0; NOT instrumented: dedicated workers, shared workers, service-worker own network traffic, browser-level targets other than attached pages/frames

**Standing limitations:**

- Passive observation of browser-visible traffic only; the endpoint inventory is NOT a complete list of the application's endpoints.
- CDP data is structured browser instrumentation, not a byte-for-byte packet capture.
- Page/frame-level CDP sessions do not cover service/shared/dedicated workers; popups' earliest requests may be missed.
- Redaction is best-effort pattern matching and is not guaranteed to remove every sensitive value.
- Passive findings are indicators; authorization/access-control weaknesses cannot be proven without separate, authorized active testing.
- Browser-side evidence cannot show server-side SQL, database policy decisions (e.g. Row Level Security) or backend authorization logic; use server/database audit logs or tracing, and tests with separate accounts you control.
- Workflows are covered only if they were exercised: the crawler never performs writes; use a manual session to record login/logout, saves, uploads, etc.
- Not instrumented: dedicated workers, shared workers, service-worker own network traffic, browser-level targets other than attached pages/frames.

## 5. Evidence bundle

| File | Bytes | SHA-256 |
|---|---|---|
| `network_events.jsonl` | 117355 | `8416a39f942ca3d8…` |
| `requests.jsonl` | 67505 | `e6cb571fabb1d41a…` |
| `endpoints.jsonl` | 7430 | `3898bb1a337086f8…` |
| `pages.jsonl` | 1823 | `6b9de344344198f6…` |
| `coverage.json` | 6314 | `fc3f269d48615664…` |
| `findings.json` | 27696 | `b56a4783ec360018…` |
| `scan_metadata.json` | 2390 | `225b1336b4b4454e…` |

Full checksums and record counts are in `manifest.json`. Evidence references use the form `request:<record_id>`, `body:<body_id>` and `event:<event_id>`.
