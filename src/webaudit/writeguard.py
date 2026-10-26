"""Hard deny-list for automatic write mode (``interaction_mode = "read_write"``).

Writes are permitted ONLY inside the already-logged-in account, and never for: signing out, signing in as/creating other accounts,
credential/e-mail/password changes, payments/billing, invitations/sharing/permissions, destructive operations (any DELETE, or names
that say delete/remove/destroy/...), uploads/exports. This applies to the guard (network layer) AND to the crawler (UI layer).
"""
from __future__ import annotations

import re
from typing import Optional

# (reason, regex on the URL *path*, lower-cased).  Query strings are only used for the auth grant check below.
PATH_DENY: list[tuple[str, re.Pattern[str]]] = [
    ("signout", re.compile(r"(log|sign)[-_]?out|/auth/v\d+/logout|/auth/logout|/session/(end|destroy)")),
    ("account_switch_or_creation", re.compile(
        r"/(sign[-_]?in|log[-_]?in|sign[-_]?up|register|signup|recover|forgot|otp|magiclink|callback)\b|/auth/v\d+/(signup|recover|otp|magiclink|invite|admin|verify)")),
    ("credentials_or_identity_change", re.compile(r"/auth/v\d+/user$|passw|credential|\bmfa\b|2fa|email[-_]?change|change[-_]?email|\bphone\b")),
    ("payments_billing", re.compile(r"checkout|payment|billing|subscri|invoice|stripe|paypal|purchase|\borders?\b|\bcart\b|\bcard\b|\bplan\b|upgrade")),
    ("invites_sharing_permissions", re.compile(r"invit|\bshare\b|sharing|permission|\bmembers?\b|\broles?\b|collaborat|transfer|\badmin\b|\bsudo\b")),
    ("destructive_name", re.compile(r"delet|remov|destroy|purge|erase|deactivat|terminat|revoke|wipe|close[-_]?account|\bdrop\b")),
    ("upload_or_export", re.compile(r"export|download")),
]
# only denied when test uploads are NOT enabled (`write_uploads=false`); generated blank/sample files are then allowed
UPLOAD_PATH = re.compile(r"upload|import|\bfiles?\b|\bstorage\b|/object/|\bavatars?\b|\bimages?\b|\bmedia\b|attachment")
GRANT_RE = re.compile(r"grant_type=(?!refresh_token)", re.I)  # password/other grants = logging in as someone; refresh_token keeps the session alive


def write_denied(path: str, query: str, method: str, extra: Optional[list[str]] = None, allow_uploads: bool = False) -> Optional[str]:
    """Reason a state-changing request must NOT be allowed, or None if it is permitted in write mode."""
    m = method.upper()
    if m == "DELETE":
        return "delete_method"
    p = path.lower()
    if not allow_uploads and UPLOAD_PATH.search(p):
        return "upload_or_export"
    for reason, rx in PATH_DENY:
        if rx.search(p):
            return reason
    if p.endswith(("/token", "/auth/v1/token")) and GRANT_RE.search(query or ""):
        return "account_switch_or_creation"
    for pat in extra or []:
        if re.search(pat, p + ("?" + query if query else ""), re.I):
            return "custom_deny_pattern"
    return None


# UI layer ------------------------------------------------------------------------------------------------------
ALWAYS_UNSAFE_LABEL = re.compile(
    r"\b(delete|remove|destroy|erase|drop|purge|revoke|deactivate|disable|terminate|cancel|unsubscribe|close account|log ?out|sign ?out|sign ?in|"
    r"log ?in|sign ?up|pay|purchase|buy|order|checkout|subscribe|upgrade|invite|share|send|upload|import|export|download|reset|transfer|"
    r"withdraw|grant|permission|role|password|publish|unpublish|restore|clear|archive|run|execute|deploy|start|stop|restart|install|"
    r"confirm|approve|reject|account|billing|payment|email|delete account|switch|impersonate|"
    r"cards?|bank|credit|debit|iban|wallet|coupon|promo|gift|donat\w*|phone|mfa|2fa|api key|secret|tokens?|webhook|domain|seats?|licen[sc]e)\b", re.I)
WRITE_OK_LABEL = re.compile(r"^(create|add|new|save|update|edit|rename|duplicate|apply|done|add new|create new|save changes|save draft|"
                            r"new \w+|add \w+|create \w+|save \w+|update \w+|rename \w+|duplicate \w+|paste( [\w\-]+){0,3}|"
                            r"(create|add|new|write|compose|record|capture|make|plan|schedule|start a|log a)( (a|an|my|new|another|your))?( [\w\-']+){1,3})$", re.I)
SENSITIVE_FIELD = re.compile(r"pass|pwd|card|cc-|cvv|cvc|iban|ssn|otp|token|secret|captcha|pin\b|routing|account[-_ ]?number", re.I)
LOGIN_PATH = re.compile(r"/(log[-_]?in|sign[-_]?in|auth|sso|oauth)\b", re.I)


HARD_DENY_LABEL = re.compile(
    r"sign ?out|log ?out|delete|remove|destroy|erase|password|payment|billing|upgrade|subscribe|invite|share|export|download|"
    r"deactivate|close account|cancel|unsubscribe|switch account|impersonate|checkout|purchase|buy\b|pay\b|"
    r"\bcards?\b|\bbank\b|credit|debit|\biban\b|wallet|donat|\bmfa\b|\b2fa\b|api key|secret|\btokens?\b", re.I)
UPLOAD_LABEL = re.compile(r"^(upload|attach|choose file|browse|import|add (an? )?(image|photo|picture|file|document|logo|avatar)|change (photo|picture|image|avatar|logo))\b[^\n]{0,24}$", re.I)  # a verb-led button, NOT status text such as "Uploaded 3 days ago"


def label_allowed(label: str, allow: list[str], uploads: bool = False) -> bool:
    """Default vocabulary OR an explicit user allow-list entry (exact label, case-insensitive) OR (uploads enabled) an upload-type label.
    The hard deny list always wins."""
    t = (label or "").strip()
    if not t or HARD_DENY_LABEL.search(t):
        return False
    if uploads and UPLOAD_LABEL.match(t):
        return True
    return label_allows_write(t) or t.lower() in {a.strip().lower() for a in allow}


def label_allows_write(label: str) -> bool:
    t = (label or "").strip()
    return bool(t) and not ALWAYS_UNSAFE_LABEL.search(t) and bool(WRITE_OK_LABEL.match(t))
