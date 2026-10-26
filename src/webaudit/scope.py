"""Scope policy: exact-origin allowlist, exclusions, and internal-target protection. No string-prefix matching."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urldefrag, urlsplit

from .config import origin_of

METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata", "100.100.100.200", "fd00:ec2::254"}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str  # ok | scheme | no_host | userinfo | origin_not_approved | excluded_pattern | metadata_endpoint | internal_target

    def __bool__(self) -> bool:
        return self.allowed


def is_internal_host(host: str | None) -> bool:
    """Loopback, private, link-local or cloud-metadata style hosts."""
    if not host:
        return False
    h = host.strip("[]").lower().rstrip(".")
    if h in METADATA_HOSTS:
        return True
    if h == "localhost" or h.endswith(".localhost") or h.endswith(".internal") or h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified


SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


def registrable_base(host: str) -> str:
    """Heuristic registrable domain (no public-suffix list): example.com, example.co.uk."""
    parts = host.lower().rstrip(".").split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class ScopePolicy:
    def __init__(self, allowed_origins: list[str], exclude_patterns: list[str] | None = None, include_subdomains: bool = False) -> None:
        self.allowed = {o.lower() for o in allowed_origins}
        self.subdomain_bases: set[str] = set()
        if include_subdomains:  # explicit opt-in only; https only; never IPs/localhost
            for o in allowed_origins:
                u = urlsplit(o)
                if u.scheme == "https" and u.hostname and not is_internal_host(u.hostname) and u.hostname.count(".") >= 1 \
                        and not u.hostname.replace(".", "").isdigit():
                    self.subdomain_bases.add(registrable_base(u.hostname))
        self.excludes = [re.compile(p, re.I) for p in (exclude_patterns or [])]

    @staticmethod
    def strip_fragment(url: str) -> str:
        return urldefrag(url)[0]

    def origin_allowed(self, url: str) -> bool:
        try:
            if origin_of(url).lower() in self.allowed:
                return True
            if self.subdomain_bases:
                u = urlsplit(url)
                h = (u.hostname or "").lower().rstrip(".")
                return u.scheme == "https" and any(h == b or h.endswith("." + b) for b in self.subdomain_bases) and not u.username
            return False
        except ValueError:
            return False

    def check(self, url: str, *, apply_excludes: bool = True) -> Decision:
        try:
            p = urlsplit(url)
            host = p.hostname
            _ = p.port  # validates port
        except ValueError:
            return Decision(False, "scheme")
        if p.scheme not in ("http", "https"):
            return Decision(False, "scheme")
        if not host:
            return Decision(False, "no_host")
        if p.username or p.password:
            return Decision(False, "userinfo")
        if not self.origin_allowed(url):
            h = host.lower().rstrip(".")
            if h in METADATA_HOSTS:
                return Decision(False, "metadata_endpoint")
            if is_internal_host(h):
                return Decision(False, "internal_target")
            return Decision(False, "origin_not_approved")
        if apply_excludes:
            target = p.path + ("?" + p.query if p.query else "")
            for rx in self.excludes:
                if rx.search(target):
                    return Decision(False, "excluded_pattern")
        return Decision(True, "ok")

    def request_blocked(self, url: str) -> Decision:
        """For subresource/XHR requests: only metadata/internal targets outside the approved origins are refused.
        Third-party public origins are observed (reported as destinations), not blocked."""
        try:
            host = urlsplit(url).hostname
        except ValueError:
            return Decision(False, "scheme")
        if self.origin_allowed(url):
            return Decision(True, "ok")
        if host and host.lower().rstrip(".") in METADATA_HOSTS:
            return Decision(False, "metadata_endpoint")
        if is_internal_host(host):
            return Decision(False, "internal_target")
        return Decision(True, "ok")
