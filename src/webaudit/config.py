"""Validated scan configuration. Credentials/cookies/tokens are never accepted here (log in manually in the browser)."""
from __future__ import annotations

import ipaddress
import json
import tomllib
from pathlib import Path
from typing import Any, Literal, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
FORBIDDEN_KEYS = {"password", "cookie", "cookies", "token", "bearer", "mfa", "otp", "session"}


def origin_of(url: str) -> str:
    p = urlsplit(url)
    host = p.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    default = {"http": 80, "https": 443}.get(p.scheme)
    port = f":{p.port}" if p.port and p.port != default else ""
    return f"{p.scheme}://{host.lower()}{port}"


def is_local_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() in LOCAL_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CrawlLimits(_M):
    max_depth: int = Field(3, ge=0, le=20)
    max_pages: int = Field(50, ge=1, le=5000)
    max_seconds: int = Field(600, ge=5)
    max_requests: int = Field(100_000, ge=10)  # real dashboards issue thousands of requests per few pages; pages/time are the real budgets
    max_pages_per_pattern: int = Field(5, ge=1)
    request_delay_ms: int = Field(250, ge=0)
    page_timeout_ms: int = Field(30_000, ge=1000)
    settle_ms: int = Field(800, ge=0)
    max_interactions_per_page: int = Field(10, ge=0)
    max_page_seconds: int = Field(240, ge=10)  # watchdog: one stuck page can never stall the whole scan
    scroll_steps: int = Field(4, ge=0, le=30)  # scroll-to-bottom steps per page to trigger lazy loading / infinite lists
    max_writes: int = Field(20, ge=0)  # total automatic write actions (read_write mode)
    max_writes_per_page: int = Field(3, ge=0)


class BodyPolicy(_M):
    mode: Literal["none", "selected", "all_supported"] = "none"
    max_body_bytes: int = Field(262_144, ge=1)
    max_total_bytes: int = Field(20_000_000, ge=1)
    per_origin_bytes: int = Field(5_000_000, ge=1)
    store_raw: bool = False  # explicit opt-in; raw bodies go to a separate restricted directory
    queue_size: int = Field(500, ge=1)


class ScanConfig(_M):
    initial_url: str
    confirm_authorized: bool = False
    allow_http_local: bool = False
    extra_allowed_origins: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=lambda: [
        r"logout", r"signout", r"sign-out", r"delete", r"remove", r"unsubscribe", r"checkout", r"payment", r"billing",
        r"invite", r"deactivate", r"/admin/danger"])
    crawl: CrawlLimits = Field(default_factory=CrawlLimits)
    body: BodyPolicy = Field(default_factory=BodyPolicy)
    output_dir: str = "output"
    profile_dir: str = ".profiles/default"
    headless: bool = False
    queue_size: int = Field(10_000, ge=10)
    network_buffer_mb: int = Field(100, ge=10, le=1000)  # Chromium's per-session buffer for response bodies; too small = bodies evicted ('No resource')
    include_subdomains: bool = False  # opt-in: approve every https subdomain of the target's registrable domain
    scope_enforcement: Literal["guard", "observe"] = "guard"
    block_unsafe_methods: bool = True
    allow_unsafe_method_paths: list[str] = Field(default_factory=list)
    manual_approval: bool = False
    interaction_mode: Literal["read_only", "read_write"] = "read_only"  # read_write: create/edit/save inside the logged-in account only
    write_deny_patterns: list[str] = Field(default_factory=list)  # extra regexes (path[?query]) that must never be written to
    write_allow_labels: list[str] = Field(default_factory=list)  # extra control labels YOU consider safe to click (hard deny-list still wins)
    write_uploads: bool = True  # in read_write mode: upload generated blank images / sample documents when a flow needs a file
    write_sample_text: Optional[str] = Field(None, max_length=2000)  # your own pre-written text for long text fields ("{marker}" is substituted)
    write_test_prefix: str = Field("webaudit-test", max_length=30, pattern=r"^[A-Za-z0-9_-]+$")
    mode: Literal["crawl", "manual"] = "crawl"  # manual: human drives the browser, the tool only observes
    session_label: Optional[str] = Field(None, max_length=60, pattern=r"^[A-Za-z0-9 _.\-]+$")  # e.g. "userA-owner"; never a credential
    log_level: str = "INFO"

    @model_validator(mode="before")
    @classmethod
    def _no_secrets(cls, data: Any) -> Any:
        if isinstance(data, dict):
            bad = [k for k in data if k.lower() in FORBIDDEN_KEYS]
            if bad:
                raise ValueError(f"credential-like keys are not accepted in configuration: {bad}; authenticate manually in the browser")
        return data

    @field_validator("initial_url")
    @classmethod
    def _url(cls, v: str) -> str:
        p = urlsplit(v)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("initial_url must be an absolute http(s) URL")
        if p.username or p.password:
            raise ValueError("credentials in URLs are not allowed")
        return v

    @model_validator(mode="after")
    def _scope(self) -> "ScanConfig":
        p = urlsplit(self.initial_url)
        if p.scheme == "http" and not (self.allow_http_local and is_local_host(p.hostname)):
            raise ValueError("HTTPS is required (HTTP only for local hosts with allow_http_local=true)")
        if self.interaction_mode == "read_write" and self.scope_enforcement != "guard":
            raise ValueError("interaction_mode=read_write requires scope_enforcement=guard (the deny-list is enforced by the guard)")
        for o in self.extra_allowed_origins:
            op = urlsplit(o)
            if "*" in o or op.scheme not in ("http", "https") or not op.hostname or op.path not in ("", "/"):
                raise ValueError(f"extra origin must be an exact scheme://host[:port] origin, got {o!r}")
            if op.scheme == "http" and not (self.allow_http_local and is_local_host(op.hostname)):
                raise ValueError(f"HTTP origin not allowed: {o}")
        return self

    @property
    def allowed_origins(self) -> list[str]:
        out = [origin_of(self.initial_url)]
        for o in self.extra_allowed_origins:
            n = origin_of(o)
            if n not in out:
                out.append(n)
        return out

    def require_authorization(self) -> None:
        if not self.confirm_authorized:
            raise PermissionError("Explicit confirmation that you own or are authorized to assess the target is required "
                                  "(--confirm-authorized or confirm_authorized=true).")

    def public_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def load_config(path: str | Path, **overrides: Any) -> ScanConfig:
    p = Path(path)
    data = tomllib.loads(p.read_text(encoding="utf-8")) if p.suffix == ".toml" else json.loads(p.read_text(encoding="utf-8"))
    data.update({k: v for k, v in overrides.items() if v is not None})
    return ScanConfig.model_validate(data)
