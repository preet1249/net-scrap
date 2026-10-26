"""Shared types for passive rules. Every finding cites evidence and states what it cannot prove."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Literal, Optional
from urllib.parse import urlsplit

from ..models import Finding, RequestRecord

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
Status = Literal["observed", "heuristic", "untested_hypothesis"]


@dataclass
class RuleContext:
    records: list[RequestRecord]
    bodies: dict[str, dict[str, Any]]  # record_id -> body_capture event payload
    allowed_origins: list[str]
    endpoints: list[dict[str, Any]] = field(default_factory=list)

    def origin(self, r: RequestRecord) -> str:
        p = urlsplit(r.url)
        return f"{p.scheme}://{p.netloc}".lower() if p.scheme else ""

    def in_scope(self, r: RequestRecord) -> bool:
        from ..config import origin_of
        try:
            return origin_of(r.url).lower() in {o.lower() for o in self.allowed_origins}
        except ValueError:
            return False

    def documents(self) -> list[RequestRecord]:
        return [r for r in self.records if r.resource_type == "Document" and r.response_status is not None
                and 200 <= r.response_status < 300 and r.state == "finished" and self.in_scope(r)]


def ref(r: RequestRecord) -> str:
    return f"request:{r.record_id}"


def make_finding(rule_id: str, key: str, *, title: str, severity: Severity, confidence: Confidence, status: Status,
                 description: str, evidence: Iterable[str], impact: str = "", limitations: str = "", remediation: str = "",
                 verification: Optional[list[str]] = None, sample: Optional[str] = None, location: Optional[str] = None) -> Finding:
    ev = list(dict.fromkeys(evidence))[:12]
    fid = "F-" + rule_id + "-" + hashlib.sha1(f"{rule_id}|{key}".encode()).hexdigest()[:8]
    return Finding(finding_id=fid, rule_id=rule_id, title=title, severity=severity, confidence=confidence, status=status,
                   description=description, evidence_references=ev, impact=impact, limitations=limitations,
                   remediation=remediation, verification_steps=verification or [], redacted_sample=sample, location=location)


Rule = Callable[[RuleContext], list[Finding]]
