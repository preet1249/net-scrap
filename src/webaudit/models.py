"""Versioned pydantic schemas. Bump SCHEMA_VERSION on any incompatible change."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"

EventSource = Literal["cdp", "playwright", "collector", "crawler"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HeaderEntry(_Model):
    """One header line. Repeated headers are separate entries; `source` records provenance."""

    name: str
    value: str
    source: str  # primary | extra_info | playwright


class NetworkEvent(_Model):
    """Immutable, versioned envelope around one observed protocol/Playwright event."""

    schema_version: str = SCHEMA_VERSION
    event_id: str
    scan_id: str
    seq: int
    timestamp: float  # collector wall clock, epoch seconds
    source: EventSource
    target_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    redirect_hop: Optional[int] = None  # derived by correlation, never by the collector
    event_type: str
    raw_event: dict[str, Any]
    correlation_status: str = "unprocessed"


class TimingInfo(_Model):
    wall_time_start: Optional[float] = None
    request_ts: Optional[float] = None  # CDP monotonic seconds
    response_ts: Optional[float] = None
    finished_ts: Optional[float] = None
    duration_ms: Optional[float] = None
    encoded_data_length: Optional[float] = None


class RedirectHop(_Model):
    hop: int
    url: str
    method: str
    status: Optional[int] = None
    location: Optional[str] = None


class RequestRecord(_Model):
    """Derived summary of one request id (one record per hop, hop 0 = original request)."""

    schema_version: str = SCHEMA_VERSION
    record_id: str  # "<session>/<request_id>#<hop>"
    scan_id: str
    target_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: str
    redirect_hop: int = 0
    method: str = "GET"
    url: str = ""  # redacted
    normalized_url: str = ""
    resource_type: Optional[str] = None
    initiator: Optional[dict[str, Any]] = None
    initiator_summary: Optional[str] = None  # e.g. 'script https://app/x.js:10:5'
    initiator_frames: list[str] = Field(default_factory=list)  # call stack, innermost first, 'fn@url:line:col'
    is_preflight: bool = False
    request_headers: list[HeaderEntry] = Field(default_factory=list)
    request_body_reference: Optional[str] = None
    has_post_data: bool = False
    post_data_keys: list[str] = Field(default_factory=list)
    query_param_names: list[str] = Field(default_factory=list)
    response_status: Optional[int] = None
    response_status_text: Optional[str] = None
    response_headers: list[HeaderEntry] = Field(default_factory=list)
    response_mime_type: Optional[str] = None
    response_body_reference: Optional[str] = None
    remote_address: Optional[str] = None
    protocol: Optional[str] = None
    from_cache: bool = False
    from_service_worker: bool = False
    mixed_content_type: Optional[str] = None
    document_url: Optional[str] = None
    timing: TimingInfo = Field(default_factory=TimingInfo)
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    failure_reason: Optional[str] = None
    blocked_reason: Optional[str] = None
    cors_error_status: Optional[dict[str, Any]] = None
    state: str = "new"  # new|requested|response_received|finished|failed|redirected|incomplete
    capture_status: str = "complete"  # complete|incomplete|extra_info_missing|ambiguous|evicted
    notes: list[str] = Field(default_factory=list)
    playwright_seen: bool = False
    event_ids: list[str] = Field(default_factory=list)


class PageRecord(_Model):
    schema_version: str = SCHEMA_VERSION
    page_id: str
    url: str
    title: Optional[str] = None
    discovered_from: Optional[str] = None
    discovery_source: str = "seed"  # seed|link|nav|tab|popup|redirect
    navigation_status: str = "pending"  # pending|ok|http_error|failed|skipped_scope|skipped_budget|skipped_policy|timeout
    http_status: Optional[int] = None
    depth: int = 0
    pattern: Optional[str] = None
    interaction_summary: dict[str, Any] = Field(default_factory=dict)
    note: Optional[str] = None


class Finding(_Model):
    schema_version: str = SCHEMA_VERSION
    finding_id: str
    rule_id: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    status: Literal["observed", "heuristic", "untested_hypothesis"]
    description: str
    evidence_references: list[str] = Field(default_factory=list)
    impact: str = ""
    limitations: str = ""
    remediation: str = ""
    verification_steps: list[str] = Field(default_factory=list)
    redacted_sample: Optional[str] = None
    location: Optional[str] = None


class ScanMetadata(_Model):
    schema_version: str = SCHEMA_VERSION
    scan_id: str
    started_at: str
    completed_at: Optional[str] = None
    initial_url: str
    allowed_origins: list[str]
    browser_version: Optional[str] = None
    protocol_version: Optional[str] = None
    collector_versions: dict[str, str] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    completion_status: Literal["running", "completed", "interrupted", "failed"] = "running"
    errors: list[str] = Field(default_factory=list)
